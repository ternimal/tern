// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ternimal/tern/internal/mcpserver"
	tern "github.com/ternimal/tern/internal/tern"
	"golang.org/x/term"
)

// mcpConfig is the tern mcp config file: named targets, the profiles they
// use, and where the workspace and audit log live. Secrets are never written
// in it, only referenced through *_env or *_file fields.
type mcpConfig struct {
	Targets       map[string]targetConfig            `json:"targets"`
	Profiles      map[string]mcpserver.ProfileConfig `json:"profiles"`
	DefaultTarget string                             `json:"default_target"`
	Workspace     string                             `json:"workspace"`
	AuditLog      string                             `json:"audit_log"`
	RecordDir     string                             `json:"record_dir"`
	PersistPTYs   bool                               `json:"persist_ptys"`
	// ConfirmWait is how long a call waits for the client to answer an
	// approval form asked inside it, such as "30s"; empty means the
	// default. A client that answers by itself or never shows the form
	// cannot approve anything, so a short wait refuses sooner.
	ConfirmWait string `json:"confirm_wait"`

	// wsRelative is the workspace as written, when that is a relative path,
	// which resolvePaths takes from the config file's directory.
	wsRelative string
}

// targetConfig names one agent. Either to_env or to_file supplies a tern1:
// string, or the fields describe a direct (addr) or relay (relay, id)
// connection; the agent fingerprint is always required.
type targetConfig struct {
	ToEnv            string `json:"to_env"`
	ToFile           string `json:"to_file"`
	Addr             string `json:"addr"`
	Fingerprint      string `json:"fingerprint"`
	Relay            string `json:"relay"`
	RelayFingerprint string `json:"relay_fingerprint"`
	RelayTokenEnv    string `json:"relay_token_env"`
	RelayTokenFile   string `json:"relay_token_file"`
	ID               string `json:"id"`
	TokenEnv         string `json:"token_env"`
	TokenFile        string `json:"token_file"`
	Key              string `json:"key"`
	Profile          string `json:"profile"`
}

// confirmWait is confirm_wait as a duration; 0 when the file leaves it out,
// which means the server's default.
func (c *mcpConfig) confirmWait() (time.Duration, error) {
	if c.ConfirmWait == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(c.ConfirmWait)
	if err != nil {
		return 0, fmt.Errorf("confirm_wait %q is not a duration such as %q", c.ConfirmWait, "30s")
	}
	if d < mcpserver.ConfirmWaitMin || d > mcpserver.ConfirmWaitMax {
		return 0, fmt.Errorf("confirm_wait %s is outside %s to %s", d, mcpserver.ConfirmWaitMin, mcpserver.ConfirmWaitMax)
	}
	return d, nil
}

// loadMCPConfig reads path strictly: an unknown field is an error, which
// catches typos and refuses secrets pasted inline. The file decides which
// agents tern mcp trusts and what its profiles allow there, so one another
// local user could change is refused (see tern.ReadConfigFile). Its paths
// are made absolute (see resolvePaths).
func loadMCPConfig(path string) (*mcpConfig, error) {
	data, err := tern.ReadConfigFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var c mcpConfig
	if err := dec.Decode(&c); err != nil {
		if strings.Contains(err.Error(), "unknown field") && looksSecret(err.Error()) {
			return nil, fmt.Errorf("%s: %w (secrets are referenced with *_env or *_file fields, never written inline)", path, err)
		}
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%s: unexpected data after the config object", path)
	}
	if len(c.Targets) == 0 {
		return nil, fmt.Errorf("%s: no targets", path)
	}
	if err := c.resolvePaths(path); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

// resolvePaths makes the paths in c, the config read from file, absolute: a
// leading ~/ is the home directory, and any other relative path is taken
// from the directory file is in. The working directory would not do: an MCP
// client starts tern mcp in the project it has open, whose files are those
// of whoever wrote the project, and a tern1: file there would choose the
// agent and the fingerprint to trust.
func (c *mcpConfig) resolvePaths(file string) error {
	abs, err := filepath.Abs(file)
	if err != nil {
		return err
	}
	dir := filepath.Dir(abs)
	type field struct {
		name string
		p    *string
	}
	resolve := func(fields []field) error {
		for _, f := range fields {
			p, err := configPath(dir, *f.p)
			if err != nil {
				return fmt.Errorf("%s: %w", f.name, err)
			}
			*f.p = p
		}
		return nil
	}
	if c.Workspace != "" && !homePath(c.Workspace) && !filepath.IsAbs(c.Workspace) {
		c.wsRelative = c.Workspace
	}
	if err := resolve([]field{{"workspace", &c.Workspace}, {"audit_log", &c.AuditLog}, {"record_dir", &c.RecordDir}}); err != nil {
		return err
	}
	for name, tc := range c.Targets {
		if err := resolve([]field{{"to_file", &tc.ToFile}, {"token_file", &tc.TokenFile}, {"relay_token_file", &tc.RelayTokenFile}, {"key", &tc.Key}}); err != nil {
			return fmt.Errorf("target %s: %w", name, err)
		}
		c.Targets[name] = tc
	}
	return nil
}

// configPath resolves p, a path in a config file in the directory dir (see
// resolvePaths). A path relative to a drive's own working directory, as
// C:name is on Windows, is refused; one from the root of the drive, \name,
// is taken on the drive dir is on.
func configPath(dir, p string) (string, error) {
	if p == "" {
		return "", nil
	}
	p = expandHome(p)
	switch {
	case filepath.IsAbs(p):
		return p, nil
	case homePath(p):
		return "", fmt.Errorf("%q starts with ~, the home directory, which is not known", p)
	case filepath.VolumeName(p) != "":
		return "", fmt.Errorf("%q is relative to the working directory of drive %s; give the whole path", p, filepath.VolumeName(p))
	case os.IsPathSeparator(p[0]):
		return filepath.Join(filepath.VolumeName(dir), p), nil
	}
	return filepath.Join(dir, p), nil
}

// looksSecret reports whether an unknown-field error names what looks like a
// secret, such as "token" or "password", so the hint about secrets helps.
func looksSecret(msg string) bool {
	msg = strings.ToLower(msg)
	for _, w := range []string{"token", "secret", "pass", "key", "cred"} {
		if strings.Contains(msg, w) {
			return true
		}
	}
	return false
}

// build turns a target entry into a dialable target, reading its secrets.
func (tc targetConfig) build() (*target, error) {
	t := &target{}
	var cs string
	switch {
	case tc.ToEnv != "" && tc.ToFile != "":
		return nil, fmt.Errorf("set to_env or to_file, not both")
	case tc.ToEnv != "":
		if cs = strings.TrimSpace(os.Getenv(tc.ToEnv)); cs == "" {
			return nil, fmt.Errorf("environment variable %s is empty", tc.ToEnv)
		}
	case tc.ToFile != "":
		s, err := tern.ReadConnStringFile(expandHome(tc.ToFile))
		if err != nil {
			return nil, fmt.Errorf("to_file: %w", err)
		}
		cs = s
	}
	if cs != "" {
		if tc.Addr != "" || tc.Relay != "" || tc.Fingerprint != "" || tc.ID != "" {
			return nil, fmt.Errorf("a tern1: string (to_env or to_file) cannot be combined with addr, relay, fingerprint or id")
		}
		c, err := tern.DecodeConnString(cs)
		if err != nil {
			return nil, err
		}
		t.mode, t.addr, t.fp = c.Mode, c.Addr, c.FP
		t.relay, t.relayFP, t.relayToken, t.id = c.Relay, c.RelayFP, c.RelayToken, c.ID
		if t.mode == "relay" && t.relayToken == "" { // as ternd prints it
			if t.relayToken, err = targetSecret("relay_token", tc.RelayTokenFile, tc.RelayTokenEnv); err != nil {
				return nil, err
			}
		}
	} else if tc.Relay != "" {
		rt, err := targetSecret("relay_token", tc.RelayTokenFile, tc.RelayTokenEnv)
		if err != nil {
			return nil, err
		}
		t.mode, t.relay, t.relayFP, t.relayToken, t.id, t.fp = "relay", tc.Relay, tc.RelayFingerprint, rt, tc.ID, tc.Fingerprint
	} else {
		t.mode, t.addr, t.fp = "direct", tc.Addr, tc.Fingerprint
	}
	token, err := targetSecret("token", tc.TokenFile, tc.TokenEnv)
	if err != nil {
		return nil, err
	}
	if token == "" && tc.TokenEnv != "" && tc.TokenFile == "" && tc.Key == "" {
		return nil, fmt.Errorf("environment variable %s is empty", tc.TokenEnv)
	}
	t.token, t.key = token, expandHome(tc.Key)
	switch {
	case t.fp == "":
		return nil, fmt.Errorf("the agent fingerprint is required")
	case t.mode == "relay" && (t.relay == "" || t.relayFP == "" || t.relayToken == "" || t.id == ""):
		return nil, fmt.Errorf("a relay target needs relay, relay_fingerprint, a relay token and id")
	case t.mode == "direct" && t.addr == "":
		return nil, fmt.Errorf("a direct target needs addr")
	case t.token == "" && t.key == "":
		return nil, fmt.Errorf("set token_env, token_file or key to authenticate")
	}
	if t.key != "" {
		if err := checkKeyUsable(t.key); err != nil {
			return nil, err
		}
		if err := tern.PreloadKey(t.key); err != nil {
			return nil, err
		}
	}
	return t, nil
}

// targetSecret reads a target's secret from the file its <field>_file names,
// held to the rules of a token file (see tern.ReadSecretFile), or else from
// the environment variable its <field>_env names.
func targetSecret(field, file, env string) (string, error) {
	if file != "" {
		s, err := tern.ReadSecretFile(expandHome(file))
		if err != nil {
			return "", fmt.Errorf("%s_file: %w", field, err)
		}
		return s, nil
	}
	if env == "" {
		return "", nil
	}
	return os.Getenv(env), nil
}

// checkKeyUsable refuses an encrypted key when stdin is not a terminal: in tern
// mcp stdin carries the protocol, so there is no way to ask for a passphrase.
func checkKeyUsable(key string) error {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		return nil
	}
	if enc, err := tern.KeyNeedsPassphrase(key); err == nil && enc {
		return fmt.Errorf("key %s is encrypted and tern mcp cannot ask for its passphrase because stdin carries the MCP protocol; use an unencrypted key or token auth", key)
	}
	return nil
}

// expandHome expands ~, and a leading ~/ (or ~\ on Windows), to the home
// directory, when that is known.
func expandHome(p string) string {
	if homePath(p) {
		if home, err := homeDir(); err == nil {
			return filepath.Join(home, p[1:])
		}
	}
	return p
}
