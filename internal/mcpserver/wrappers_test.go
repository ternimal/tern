// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Programs that load a library named on their command line, which runs as
// code, or run a program they are given, are wrappers: p11tool and certtool
// (--provider), p11-kit, every JDK tool (a -J-agentpath: option anywhere,
// jcmd's agent loading), redis-server, valkey-server and keydb-server
// (--loadmodule), nginx and Apache (a module named by -g or -C), insmod and
// modprobe, gpg (--photo-viewer), gpg-agent, gpg-connect-agent (--exec),
// openvpn (--up) and stunnel (exec). confirm_unlisted never offers them, and
// a pattern with a slot names one only with allow_wrappers.
func TestLibraryLoadersAreWrappers(t *testing.T) {
	cu := mustPol(t, ProfileConfig{Run: RunConfig{ConfirmUnlisted: true}})
	for _, name := range []string{"p11tool", "certtool", "p11-kit", "keytool", "keytool.exe", "jarsigner", "jcmd", "jps",
		"jstat", "jstack", "jmap", "jinfo", "jdb", "javac", "javadoc", "jar", "jlink", "jshell", "jwebserver", "rmiregistry",
		"redis-server", "valkey-server", "keydb-server", "nginx", "nginx-debug", "openresty", "apache2", "httpd", "httpd.worker",
		"apachectl", "apache2ctl", "insmod", "modprobe", "gpg", "gpg2", "gpg-agent", "gpg-connect-agent", "openvpn", "stunnel",
		"stunnel4", "ldd", "postgres", "postmaster", "pg_ctl", "pg_ctlcluster", "mysqld", "mariadbd", "mysqld_safe",
		"mariadbd-safe"} {
		if !isWrapper(name) {
			t.Errorf("%s is not a wrapper", name)
			continue
		}
		if d, _ := cu.RunDecision([]string{name, "x"}, false); d != Deny {
			t.Errorf("confirm_unlisted offers %s", name)
		}
		if _, err := BuildPolicies(map[string]ProfileConfig{"p": {Run: RunConfig{Allow: [][]string{{name, "-list", "*"}}}}}); err == nil {
			t.Errorf("a pattern with a slot names %s without allow_wrappers", name)
		}
	}
	for _, name := range []string{"redis-cli", "valkey-cli", "nginx-exporter", "jq", "keyctl", "certbot", "modinfo", "lsmod"} {
		if isWrapper(name) {
			t.Errorf("%s taken for a wrapper", name)
		}
	}
}

// A pattern with no slot names one command line, whose arguments the model
// cannot choose, so it may name a wrapper without allow_wrappers: exactly
// that command runs (or asks first, where run is confirmed), and any other
// is refused as a wrapper's, confirm_unlisted or not. A pattern with a slot
// (* or a final **) still needs allow_wrappers.
func TestLiteralWrapperPatterns(t *testing.T) {
	literal := [][]string{{"openssl", "version"}, {"ssh-keygen", "-l", "-f", "/etc/ssh/ssh_host_ed25519_key.pub"},
		{"nginx", "-t"}, {"keytool", "-list", "-keystore", "/etc/app/trust.jks", "-storepass:file", "/etc/app/pass"}}
	pols, err := BuildPolicies(map[string]ProfileConfig{"p": {Run: RunConfig{Allow: literal}},
		"c": {Run: RunConfig{Allow: literal}, Confirm: []string{"run"}}, "u": {Run: RunConfig{Allow: literal, ConfirmUnlisted: true}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, argv := range literal {
		if d, why := pols["p"].RunDecision(argv, false); d != Allow {
			t.Errorf("%q: %v %s", argv, d, why)
		}
		if d, why := pols["c"].RunDecision(argv, false); d != Confirm {
			t.Errorf("%q under confirm: %v %s", argv, d, why)
		}
	}
	for _, argv := range [][]string{{"openssl", "version", "-a"}, {"openssl", "engine", "-t", "/tmp/x.so"},
		{"nginx", "-t", "-g", "load_module /tmp/x.so;"}, {"keytool", "-list", "-J-agentpath:/tmp/x.so"}} {
		for _, p := range []*Policy{pols["p"], pols["u"]} {
			if d, why := p.RunDecision(argv, false); d != Deny || !strings.Contains(why, "can run arbitrary commands") {
				t.Errorf("%q in %s: %v %s", argv, p.Profile, d, why)
			}
		}
	}
	for _, pat := range [][]string{{"openssl", "x509", "-in", "*"}, {"keytool", "-list", "-keystore", "*"}, {"nginx", "**"},
		{"redis-server", "/etc/redis/redis.conf", "**"}} {
		if _, err := BuildPolicies(map[string]ProfileConfig{"p": {Run: RunConfig{Allow: [][]string{pat}}}}); err == nil ||
			!strings.Contains(err.Error(), "allow_wrappers") || !strings.Contains(err.Error(), "argument the model chooses") {
			t.Errorf("pattern %q: %v", pat, err)
		}
	}
	if _, err := BuildPolicies(map[string]ProfileConfig{"p": {Run: RunConfig{AllowWrappers: true, Allow: [][]string{{"openssl", "x509", "-in", "*"}}}}}); err != nil {
		t.Errorf("allow_wrappers with a slot: %v", err)
	}
}

// A shell, interpreter or wrapper that only a pattern with no slot lets run
// takes no standard input: run ["sh"] fed a command line would run it. With
// run.allow_wrappers, and for any other program, input goes through.
func TestLiteralWrapperTakesNoStdin(t *testing.T) {
	pols, err := BuildPolicies(map[string]ProfileConfig{"p": {Run: RunConfig{Allow: [][]string{{"sh"}, {"cat"}}}},
		"w": {Run: RunConfig{Allow: [][]string{{"sh"}}, AllowWrappers: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if why := pols["p"].StdinProblem([]string{"sh"}, false); !strings.Contains(why, "takes no stdin") {
		t.Errorf("sh in p: %q", why)
	}
	for _, c := range []struct {
		p    *Policy
		argv []string
	}{{pols["w"], []string{"sh"}}, {pols["p"], []string{"cat"}}} {
		if why := c.p.StdinProblem(c.argv, false); why != "" {
			t.Errorf("%q in %s: %q", c.argv, c.p.Profile, why)
		}
	}
	if runtime.GOOS == "windows" {
		return
	}
	a := newStackAgent(t)
	srv, _ := stackServer(t, a, ProfileConfig{Run: RunConfig{Allow: [][]string{{"sh"}}}}, nil)
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	marker := filepath.Join(t.TempDir(), "ran")
	for _, tool := range []string{"run", "job_start"} {
		why := call(t, cs, tool, map[string]any{"argv": []string{"sh"}, "stdin": "touch " + marker + "\n"}, nil, true)
		if !strings.Contains(why, "takes no stdin") {
			t.Errorf("%s of sh with stdin: %s", tool, why)
		}
	}
	if _, err := os.Lstat(marker); err == nil {
		t.Error("sh ran the command it was fed")
	}
	call(t, cs, "run", map[string]any{"argv": []string{"sh"}}, nil, false)
}

// A command a human is asked to approve is named in the reason with its
// secrets redacted, as the reason is written to the audit log.
func TestConfirmReasonRedacted(t *testing.T) {
	pols, err := BuildPolicies(map[string]ProfileConfig{"u": {Run: RunConfig{ConfirmUnlisted: true}}})
	if err != nil {
		t.Fatal(err)
	}
	d, why := pols["u"].RunDecision([]string{"redis-cli", "-a", "S3cr3t!x", "ping"}, false)
	if d != Confirm || strings.Contains(why, "S3cr3t") || !strings.Contains(why, "redis-cli") {
		t.Errorf("%v %q", d, why)
	}
}
