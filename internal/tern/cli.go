// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
)

// ResolveVersion returns v when the build set it (-ldflags "-X main.version=...",
// as the Makefile and release builds do). Otherwise, for a plain
// `go install github.com/ternimal/tern/cmd/tern@latest` or a `go build` from a
// tagged checkout, it returns the module version Go recorded in the binary.
func ResolveVersion(v string) string {
	if v != "dev" {
		return v
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return v
}

// ResolveSecret resolves a secret from, in order: the --<name> flag value, a
// file named by --<name>-file (see ReadSecretFile, which refuses a file other
// local users could read or change), or the environment variable env.
// fromFlag reports that it came from the flag, i.e. from argv, which
// /proc/<pid>/cmdline exposes to every local user; callers pass fromFlag to
// WarnSecretOnArgv. flagName is only used in error messages.
func ResolveSecret(flagName, flagVal, fileVal, env string) (secret string, fromFlag bool, err error) {
	if flagVal != "" {
		if fileVal != "" {
			return "", false, fmt.Errorf("set only one of --%s or --%s-file", flagName, flagName)
		}
		return flagVal, true, nil
	}
	if fileVal != "" {
		// An explicit but empty file is a configuration mistake, not a request to
		// run without a secret: ReadSecretFile fails instead of letting a command
		// mint an ephemeral one.
		s, rerr := ReadSecretFile(fileVal)
		if rerr != nil {
			return "", false, fmt.Errorf("--%s-file: %w", flagName, rerr)
		}
		return s, false, nil
	}
	return os.Getenv(env), false, nil
}

// argvPublicNote names where argv is exposed, for the secret-on-command-line
// warning. /proc is Linux; other systems expose argv through their own process
// listings.
var argvPublicNote = func() string {
	if runtime.GOOS == "linux" {
		return "readable by other local users via /proc"
	}
	return "visible to other local users in the process list"
}()

// WarnSecretOnArgv logs a hint when a secret was passed on the command line,
// since argv is world-readable to other local users. envName and flagName name
// the safer alternatives.
func WarnSecretOnArgv(fromFlag bool, flagName, envName string) {
	if fromFlag {
		slog.Warn("a secret on the command line is "+argvPublicNote+"; prefer "+
			envName+" or --"+flagName+"-file", "flag", "--"+flagName)
	}
}

// CleanText removes control bytes (C0 controls, DEL and C1) from s, keeping tab,
// so text that came from a peer (a session name, an agent's error message)
// cannot inject terminal escape sequences when it is printed. It is the client's
// defense; agents also reject control characters in session names at the source.
func CleanText(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' {
			return r
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return -1
		}
		return r
	}, s)
}

// ShellQuote renders s as one argument for a POSIX shell: as is when it
// holds only characters no shell gives a meaning to there, else in single
// quotes, so a printed command means the same when it is pasted. An "=" is
// plain after the first character (--read-only=false); a leading one is
// quoted, since zsh expands =name to a command's path.
func ShellQuote(s string) string {
	plain := s != ""
	for i := 0; i < len(s) && plain; i++ {
		plain = isAlnum(s[i]) || strings.IndexByte("@%+:,./_-", s[i]) >= 0 || s[i] == '=' && i > 0
	}
	if plain {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// ValidSessionName reports whether a client-supplied session name is safe to
// store and later print: non-empty names must be printable (no control bytes)
// and reasonably short.
func ValidSessionName(name string) error {
	if len(name) > 128 {
		return fmt.Errorf("session name too long (max 128 bytes)")
	}
	if name != CleanText(name) {
		return fmt.Errorf("session name must not contain control characters")
	}
	return nil
}

// Banner renders the tern logo as a boxed, plain-ASCII startup banner, so it
// shows the same on any Windows console. version, when non-empty, is placed on
// the last line; the frame grows to fit.
func Banner(version string) string {
	lines := []string{
		` \\\_\`,
		` \\\( ^>     t e r n`,
		`  \\\=/      A minimal, portable, secure remote terminal with MCP`,
		"  ~~~~~",
	}
	if version != "" {
		lines[3] = "  ~~~~~      " + version
	}
	w := 0
	for _, l := range lines {
		if len(l) > w {
			w = len(l)
		}
	}
	w++ // one trailing space of padding
	bar := "+" + strings.Repeat("-", w) + "+"
	var b strings.Builder
	b.WriteString(bar + "\n")
	for _, l := range lines {
		b.WriteString("|" + l + strings.Repeat(" ", w-len(l)) + "|\n")
	}
	b.WriteString(bar)
	return b.String()
}

// Alias registers short as an additional name for an existing flag (long) on fs,
// sharing its value so either spelling works. The alias carries no usage text of
// its own; SetUsage merges the two spellings onto one help line.
func Alias(fs *flag.FlagSet, long, short string) {
	f := fs.Lookup(long)
	if f == nil {
		panic("tern.Alias: no flag --" + long)
	}
	fs.Var(f.Value, short, "")
}

// Aliases registers several short aliases at once (long -> short).
func Aliases(fs *flag.FlagSet, m map[string]string) {
	for long, short := range m {
		Alias(fs, long, short)
	}
}

// ResolveWriteMode maps the parsed --read-only flag to the (write, coDrive) pair
// shared by `tern connect` and `rtern`:
//
//	--read-only not given  -> write=true,  coDrive=false (single-writer: the first
//	                          client writes, later joiners attach read-only)
//	--read-only            -> write=false, coDrive=false (viewer; it can only
//	                          join an existing session, never create one)
//	--read-only=false      -> write=true,  coDrive=true  (force co-driving)
//
// The short alias (-V, -V=false) behaves the same as the long flag.
func ResolveWriteMode(fs *flag.FlagSet, readOnly bool) (write, coDrive bool) {
	if readOnly {
		return false, false
	}
	ro := fs.Lookup("read-only")
	fs.Visit(func(f *flag.Flag) {
		// The alias shares the flag's Value, so this matches either spelling
		// given explicitly as false.
		if ro != nil && f.Value == ro.Value {
			coDrive = true
		}
	})
	return true, coDrive
}

// SetUsage installs a usage function that prints header then one line per flag,
// merging aliases: "  -a, --addr value   agent address (default ...)".
func SetUsage(fs *flag.FlagSet, header string) {
	fs.Usage = func() {
		out := fs.Output()
		if header != "" {
			fmt.Fprintf(out, "%s\n\n", header)
		}
		type group struct {
			names  []string
			usage  string
			def    string
			isBool bool
		}
		groups := map[flag.Value]*group{}
		var order []*group
		fs.VisitAll(func(f *flag.Flag) {
			g := groups[f.Value]
			if g == nil {
				g = &group{}
				groups[f.Value] = g
				order = append(order, g)
			}
			g.names = append(g.names, f.Name)
			if f.Usage != "" { // the canonical (long) flag carries the usage + default
				g.usage = f.Usage
				g.def = f.DefValue
				if b, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && b.IsBoolFlag() {
					g.isBool = true
				}
			}
		})
		if len(order) > 0 {
			fmt.Fprintln(out, "Flags:")
		}
		for _, g := range order {
			sort.Slice(g.names, func(i, j int) bool {
				if len(g.names[i]) != len(g.names[j]) {
					return len(g.names[i]) < len(g.names[j]) // short form first
				}
				return g.names[i] < g.names[j]
			})
			parts := make([]string, 0, len(g.names))
			for _, n := range g.names {
				if len(n) == 1 {
					parts = append(parts, "-"+n)
				} else {
					parts = append(parts, "--"+n)
				}
			}
			head := "  " + strings.Join(parts, ", ")
			if !g.isBool {
				head += " value"
			}
			fmt.Fprintf(out, "%-32s %s", head, g.usage)
			if g.def != "" && g.def != "false" && g.def != "0" && g.def != "0s" {
				fmt.Fprintf(out, " (default %s)", g.def)
			}
			fmt.Fprintln(out)
		}
	}
}
