// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"maps"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/ternimal/tern/internal/mcpserver"
	tern "github.com/ternimal/tern/internal/tern"
)

// cmdMCP serves the Model Context Protocol over stdio so an AI client (Claude
// Code, Claude Desktop, Cursor, ...) can use agents through tern. stdout is the
// protocol channel: everything else goes to stderr.
//
// One target comes from the usual connection flags; several targets with
// their own profiles come from a --config file.
func cmdMCP(args []string) {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	cf := addConnFlags(fs)
	configPath := fs.String("config", "", "JSON config with named targets and profiles (instead of connection flags)")
	profile := fs.String("profile", "readonly", "policy profile for a single target from connection flags (readonly; others need --config)")
	workspace := fs.String("workspace", "", "local directory upload and download may use; without one those tools are off")
	auditLog := fs.String("audit-log", defaultAuditPath(), "append JSON lines, at least one per tool call, to this file")
	recordDir := fs.String("record-dir", "", "record each terminal the AI opens as an asciicast (.cast) file in this directory")
	persistPTYs := fs.Bool("persist-ptys", false, "leave the AI's terminals running when tern mcp exits and reattach them when it starts again with the same targets")
	maxOutput := fs.Int("max-output", 256<<10, "default bytes of output or file content one call returns, at most 16 MiB (16777216)")
	maxTimeout := fs.Duration("max-timeout", 5*time.Minute, "default cap on how long a run or job_start command may run, pty_run may wait, and a file write or transfer may take")
	allowInsecure := fs.Bool("allow-insecure-transport", false, "DANGEROUS: permit the --insecure-* connection flags in mcp mode, where a man in the middle could inject instructions into command output")
	verbose := addVerbose(fs)
	tern.SetUsage(fs, "tern mcp [conn | --config FILE] [flags] - MCP server over stdio for AI clients")
	conn, args := splitLeadingConn(args)
	fs.Parse(args)
	rejectArgs(fs)
	cf.applyConn(conn)
	tern.SetVerbose(*verbose)
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if err := checkLimits(*maxOutput, *maxTimeout); err != nil {
		log.Fatal(err)
	}

	if set["config"] && *configPath == "" {
		log.Fatal("--config needs the path of a config file")
	}
	// An MCP client starts tern mcp without a shell, in a directory of its
	// choosing, so every path flag is made absolute here, as the config
	// file's paths are (see resolvePaths).
	for _, f := range []struct {
		name string
		p    *string
	}{
		{"config", configPath}, {"workspace", workspace}, {"audit-log", auditLog}, {"record-dir", recordDir},
		{"to-file", cf.toFile}, {"token-file", cf.tokenFile}, {"relay-token-file", cf.relayTokFile}, {"key", cf.key},
	} {
		p, err := mcpPathFlag(f.name, *f.p)
		if err != nil {
			log.Fatal(err)
		}
		*f.p = p
	}

	cfg := mcpserver.Config{Version: version, MaxOutput: *maxOutput, MaxTimeout: *maxTimeout}
	audit, persist, cfgFile, wsRelative := "", false, "", ""
	// The files that hold a target's login or say which agent to trust:
	// the workspace tools never send them anywhere, whatever their names.
	logins := []string{*cf.toFile, *cf.tokenFile, *cf.relayTokFile, *cf.key}
	if *configPath != "" {
		if conn != "" || connFlagsSet(cf) || set["profile"] {
			log.Fatal("--config replaces the connection flags and --profile; use one or the other")
		}
		cfgFile = *configPath
		c, err := loadMCPConfig(cfgFile)
		if err != nil {
			log.Fatalf("config: %v", err)
		}
		policies, err := mcpserver.BuildPolicies(c.Profiles)
		if err != nil {
			log.Fatalf("config: %v", err)
		}
		for _, name := range slices.Sorted(maps.Keys(c.Targets)) {
			tc := c.Targets[name]
			logins = append(logins, tc.ToFile, tc.TokenFile, tc.RelayTokenFile, tc.Key)
			t, err := tc.build()
			if err == nil {
				err = checkFingerprints(t)
			}
			if err != nil {
				log.Fatalf("config: target %s: %v", name, err)
			}
			prof := tc.Profile
			if prof == "" {
				prof = "readonly"
			}
			pol := policies[prof]
			if pol == nil {
				log.Fatalf("config: target %s: unknown profile %q", name, prof)
			}
			cfg.Targets = append(cfg.Targets, mcpserver.TargetSpec{
				Target: t.info(name),
				Policy: pol,
				Dial:   func(ctx context.Context) (*tern.Client, error) { return t.dial(ctx, "") },
			})
		}
		cfg.DefaultTarget, cfg.Workspace, audit = c.DefaultTarget, expandHome(c.Workspace), expandHome(c.AuditLog)
		cfg.RecordDir = expandHome(c.RecordDir)
		persist, wsRelative = c.PersistPTYs, c.wsRelative
	} else {
		// An AI client acts on what commands print, so a connection an attacker
		// can intercept lets them inject instructions. Refuse the insecure
		// transport flags unless the operator explicitly accepts that.
		if (*cf.insecure || *cf.skipEnc || *cf.dangerous) && !*allowInsecure {
			log.Fatal("refusing --insecure-* connection flags in mcp mode: a man in the middle could inject instructions into command output. Pass --allow-insecure-transport to override")
		}
		if *cf.key != "" {
			if err := checkKeyUsable(*cf.key); err != nil {
				log.Fatal(err)
			}
		}
		pol, err := mcpserver.NewPolicy(*profile)
		if err != nil {
			log.Fatal(err)
		}
		if conn == "" && !connFlagsSet(cf) && os.Getenv("TERN_TO") == "" {
			log.Fatal("tern mcp needs a target: a tern1: connection string (argument, --to-file or TERN_TO) or --addr/--relay with --fingerprint, plus a token or key; or --config FILE for several targets")
		}
		t := mustTarget(cf)
		// Fail now, not on every call: an MCP client would show a server
		// that starts as healthy.
		if t.token == "" && t.key == "" {
			log.Fatal("tern mcp needs credentials: --key, --token-file or TERN_TOKEN")
		}
		if err := checkFingerprints(t); err != nil {
			log.Fatal(err)
		}
		cfg.Targets = []mcpserver.TargetSpec{{
			Target: t.info("default"),
			Policy: pol,
			Dial:   func(ctx context.Context) (*tern.Client, error) { return t.dial(ctx, "") },
		}}
	}
	if set["workspace"] {
		cfg.Workspace, wsRelative = *workspace, ""
	}
	if set["record-dir"] {
		cfg.RecordDir = *recordDir
	}
	if set["persist-ptys"] {
		persist = *persistPTYs
	}
	if persist {
		if cfg.PTYState = ptyStatePath(cfg.Targets); cfg.PTYState == "" {
			log.Fatal(noStateDir("the state file that keeps terminals"))
		}
	}
	cfg.AuditPath = *auditLog
	if !set["audit-log"] && audit != "" {
		cfg.AuditPath = audit
	}
	switch {
	case cfg.AuditPath != "":
	case set["audit-log"]:
		log.Fatal("--audit-log needs the path of a file")
	default:
		log.Fatal(noStateDir("the audit log") + ", or name the log with --audit-log or audit_log")
	}
	// The files of this run are tern's own too: the workspace tools never
	// send the recordings, the audit log, the config file or the files that
	// hold a target's login anywhere.
	cfg.TernDirs = ternDirs()
	for _, p := range append([]string{cfg.RecordDir, cfg.AuditPath, cfgFile}, logins...) {
		if abs, err := filepath.Abs(p); p != "" && err == nil && !slices.Contains(cfg.TernDirs, abs) {
			cfg.TernDirs = append(cfg.TernDirs, abs)
		}
	}
	// A relative workspace in the config file is taken from the file's
	// directory, which for the usual ~/.config/tern/mcp.json is tern's own:
	// say so, rather than that every file in it is tern's.
	if wsRelative != "" {
		if i := slices.IndexFunc(cfg.TernDirs, func(d string) bool { return pathWithin(cfg.Workspace, d) }); i >= 0 {
			log.Fatalf("config: workspace %q is a relative path, taken from the config file's directory, so it names %s, inside tern's own directory %s, where the workspace tools never upload or create anything; give it as an absolute or ~/ path, such as %q",
				wsRelative, cfg.Workspace, cfg.TernDirs[i], "~/"+filepath.ToSlash(wsRelative))
		}
	}

	srv, err := mcpserver.New(cfg)
	if err != nil {
		log.Fatalf("mcp: %v", err)
	}
	defer srv.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := srv.RunStdio(ctx); err != nil && ctx.Err() == nil {
		log.Printf("mcp: %v", err)
	}
}

// checkFingerprints catches a mistyped fingerprint at startup instead of on
// every call: a pinned fingerprint is the SHA-256 of the certificate in hex,
// in either case and with or without colons, as every command accepts it.
func checkFingerprints(t *target) error {
	for _, fp := range []struct{ name, v string }{{"fingerprint", t.fp}, {"relay fingerprint", t.relayFP}} {
		if fp.v == "" {
			continue
		}
		if b, err := hex.DecodeString(strings.ReplaceAll(fp.v, ":", "")); err != nil || len(b) != 32 {
			return fmt.Errorf("the %s %q is not a SHA-256 fingerprint (64 hex characters); copy it from the line ternd or ternr prints", fp.name, fp.v)
		}
	}
	return nil
}

// connFlagsSet reports whether any connection flag carries a value.
func connFlagsSet(cf *connFlags) bool {
	for _, s := range []*string{cf.to, cf.addr, cf.fp, cf.relay, cf.relayFP, cf.relayTok, cf.id, cf.key, cf.token, cf.tokenFile, cf.relayTokFile, cf.toFile} {
		if *s != "" {
			return true
		}
	}
	return *cf.insecure || *cf.skipEnc || *cf.dangerous
}

// info describes the target for agent_info, list_targets and the audit log,
// without secrets. Its connect flags reach the agent but carry no token, so
// the person watching a terminal adds their own credentials.
func (t *target) info(name string) mcpserver.Target {
	ti := mcpserver.Target{Name: name, Mode: t.mode, Fingerprint: t.fp, Transport: "tls-pinned", Endpoint: t.addr}
	if t.mode == "relay" {
		ti.Endpoint = t.relay + "#" + t.id
		ti.ConnectArgs = []string{"--relay", t.relay}
		if t.relayFP != "" {
			ti.ConnectArgs = append(ti.ConnectArgs, "--relay-fingerprint", t.relayFP)
		}
		ti.ConnectArgs = append(ti.ConnectArgs, "--id", t.id)
	} else {
		ti.ConnectArgs = []string{"--addr", t.addr}
	}
	if t.fp != "" {
		ti.ConnectArgs = append(ti.ConnectArgs, "--fingerprint", t.fp)
	}
	switch {
	case t.skipEnc && t.insecure:
		ti.Transport = "plaintext"
		ti.ConnectArgs = append(ti.ConnectArgs, "--insecure-dangerous")
	case t.skipEnc:
		ti.Transport = "plaintext"
		ti.ConnectArgs = append(ti.ConnectArgs, "--insecure-skip-encryption")
	case t.insecure:
		ti.Transport = "tls-unverified"
		ti.ConnectArgs = append(ti.ConnectArgs, "--insecure-skip-fingerprint")
	}
	return ti
}

// maxOutputCap bounds --max-output, as a profile's limits.output_bytes is
// bounded: the offsets redaction keeps for each byte of a result are 32
// bits, and one call's result has no reason to be larger.
const maxOutputCap = 16 << 20

// checkLimits checks --max-output and --max-timeout.
func checkLimits(maxOutput int, maxTimeout time.Duration) error {
	if maxOutput <= 0 || maxOutput > maxOutputCap {
		return fmt.Errorf("--max-output must be from 1 to %d (16 MiB)", maxOutputCap)
	}
	if maxTimeout <= 0 {
		return errors.New("--max-timeout must be greater than zero")
	}
	return nil
}

// defaultAuditPath is <state dir>/tern/mcp-audit.jsonl, or "" without a
// state directory.
func defaultAuditPath() string { return statePath("mcp-audit.jsonl") }

// mcpPathFlag returns p, the value of the path flag --name, as an absolute
// path: ~ is the home directory, as is a leading ~/ (or ~\ on Windows),
// refused when that is not known, as with HOME unset. Any other relative path
// is refused: it would resolve in the directory tern mcp was started in,
// which an MCP client chooses, often the project it has open, whose files
// would then decide the key, token or agent tern mcp uses, or receive its
// audit log and recordings.
func mcpPathFlag(name, p string) (string, error) {
	switch {
	case p == "" || filepath.IsAbs(p):
		return p, nil
	case homePath(p):
		home, err := homeDir()
		if err != nil {
			return "", fmt.Errorf("--%s %q starts with ~, the home directory, which is not known (%v); set it, or give the path in full", name, p, err)
		}
		return filepath.Join(home, p[1:]), nil
	}
	return "", fmt.Errorf("--%s %q is a relative path, which tern mcp would take from the directory it was started in, for an MCP client often the project it has open; give an absolute or ~/ path, or use --config, whose relative paths are taken from the config file's directory", name, p)
}

// homePath reports whether p names the home directory, or a path under it,
// as ~, ~/... or, on Windows, ~\....
func homePath(p string) bool {
	return p == "~" || strings.HasPrefix(p, "~/") || runtime.GOOS == "windows" && strings.HasPrefix(p, `~\`)
}

// pathWithin reports whether p is dir or a path under it, both absolute.
func pathWithin(p, dir string) bool {
	rel, err := filepath.Rel(dir, p)
	return err == nil && filepath.IsLocal(rel)
}

// homeDir is the user's home directory, which must be an absolute path.
func homeDir() (string, error) {
	home, err := os.UserHomeDir()
	if err == nil && !filepath.IsAbs(home) {
		err = fmt.Errorf("the home directory %q is not an absolute path", home)
	}
	return home, err
}

// noStateDir says that tern mcp has no state directory for what.
func noStateDir(what string) string {
	return fmt.Sprintf(`tern mcp has no place for %s: it keeps it in its state directory, $XDG_STATE_HOME/tern or ~/.local/state/tern (%%LocalAppData%%\tern on Windows), and neither is known; set XDG_STATE_HOME or HOME (LOCALAPPDATA on Windows)`, what)
}

// ptyStatePath names the file that keeps terminals across restarts, one per
// set of targets, so two configs never reattach each other's terminals; ""
// without a state directory.
func ptyStatePath(targets []mcpserver.TargetSpec) string {
	h := sha256.New()
	for _, t := range targets {
		fmt.Fprintf(h, "%s=%s\n", t.Name, t.Endpoint)
	}
	return statePath(fmt.Sprintf("mcp-ptys-%x.json", h.Sum(nil)[:6]))
}

// ternDirs lists the directories where tern keeps its own state and
// configuration on this machine, whichever of them a run uses: the state
// directory in use and its default places (~/.local/state/tern, and
// %LocalAppData%\tern on Windows), and ~/.config/tern and the user's
// configuration directory, the usual places for token files and the config
// file. The workspace tools never upload a file in them nor create one there.
func ternDirs() []string {
	var dirs []string
	add := func(d string) {
		if filepath.IsAbs(d) && !slices.Contains(dirs, d) {
			dirs = append(dirs, d)
		}
	}
	if p := statePath("x"); p != "" {
		add(filepath.Dir(p))
	}
	if home, err := homeDir(); err == nil {
		add(filepath.Join(home, ".local", "state", "tern"))
		add(filepath.Join(home, ".config", "tern"))
	}
	if runtime.GOOS == "windows" {
		if d, err := os.UserCacheDir(); err == nil {
			add(filepath.Join(d, "tern"))
		}
	}
	if d, err := os.UserConfigDir(); err == nil {
		add(filepath.Join(d, "tern"))
	}
	return dirs
}

// statePath is name in <state dir>/tern: $XDG_STATE_HOME or ~/.local/state on
// Unix, %LocalAppData% on Windows. Without one, as with HOME unset, it is "":
// a relative path would put the file wherever tern mcp was started. A
// relative $XDG_STATE_HOME is ignored, as the XDG specification says.
func statePath(name string) string {
	dir := os.Getenv("XDG_STATE_HOME")
	if !filepath.IsAbs(dir) {
		dir = ""
		if runtime.GOOS == "windows" {
			if d, err := os.UserCacheDir(); err == nil && filepath.IsAbs(d) {
				dir = d
			}
		} else if home, err := homeDir(); err == nil {
			dir = filepath.Join(home, ".local", "state")
		}
	}
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "tern", name)
}
