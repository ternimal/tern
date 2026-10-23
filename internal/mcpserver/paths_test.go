// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"strings"
	"testing"
)

func TestMatchPath(t *testing.T) {
	cases := []struct {
		pat, p string
		want   bool
	}{
		{"/etc/**", "/etc/os-release", true},
		{"/etc/**", "/etc/nginx/conf.d/site.conf", true},
		{"/etc/**", "/etc", true}, // ** matches zero segments
		{"/etc/**", "/var/etc/x", false},
		{"/etc/ssh/*_key", "/etc/ssh/ssh_host_ed25519_key", true},
		{"/etc/ssh/*_key", "/etc/ssh/ssh_host_ed25519_key.pub", false},
		{"**/.ssh/**", "/home/u/.ssh/id_ed25519", true},
		{"**/.ssh/**", "/root/.ssh", true},
		{"**/*.key", "/srv/tls/site.key", true},
		{"**/*.key", "/srv/tls/site.key.bak", false},
		{"/proc/*/status", "/proc/1/status", true},
		{"/proc/*/status", "/proc/1/task/1/status", false},
		{"/proc/loadavg", "/proc/loadavg", true},
		{"/[", "/[", false}, // malformed pattern never matches
	}
	for _, c := range cases {
		if got := matchPath(c.pat, c.p); got != c.want {
			t.Errorf("matchPath(%q, %q) = %v, want %v", c.pat, c.p, got, c.want)
		}
	}
}

func TestCheckRead(t *testing.T) {
	p, _ := NewPolicy("readonly")
	for _, path := range []string{"/etc/os-release", "/etc/nginx/nginx.conf", "/var/log/syslog", "/proc/1/status", "/proc/loadavg"} {
		if _, ok, why := p.CheckRead(path); !ok {
			t.Errorf("%s should be readable: %s", path, why)
		}
	}
	denied := []struct{ path, cleaned, want string }{
		{"/etc/shadow", "/etc/shadow", "secret-path rule"},
		{"/var/log/../../etc/shadow", "/etc/shadow", "secret-path rule"}, // .. cannot walk around a rule
		{"/etc//sudoers", "/etc/sudoers", "secret-path rule"},
		{"/home/u/.ssh/id_ed25519", "/home/u/.ssh/id_ed25519", "secret-path rule"},
		{"/etc/ssl/private/server.key", "/etc/ssl/private/server.key", "secret-path rule"},
		{"/srv/app/.env", "/srv/app/.env", "secret-path rule"},
		{"/etc/app/api-token.txt", "/etc/app/api-token.txt", "secret-path rule"},
		{"/proc/1/environ", "/proc/1/environ", "secret-path rule"},
		{"/etc/apt/auth.conf", "/etc/apt/auth.conf", "secret-path rule"},
		{"/etc/apt/auth.conf.d/esm.conf", "/etc/apt/auth.conf.d/esm.conf", "secret-path rule"},
		{"/etc/postfix/sasl_passwd", "/etc/postfix/sasl_passwd", "secret-path rule"},
		{"/etc/mysql/debian.cnf", "/etc/mysql/debian.cnf", "secret-path rule"},
		{"/etc/ceph/ceph.client.admin.keyring", "/etc/ceph/ceph.client.admin.keyring", "secret-path rule"},
		{"/etc/dropbear/dropbear_ed25519_host_key", "/etc/dropbear/dropbear_ed25519_host_key", "secret-path rule"},
		{"/root/notes.txt", "/root/notes.txt", "outside the paths"},
		{"/var/log/../../root/x", "/root/x", "outside the paths"},
		{"etc/passwd", "etc/passwd", "absolute"},
		{"", "", "empty"},
		{"/etc/os-release\x00.png", "/etc/os-release\x00.png", "NUL"},
	}
	for _, c := range denied {
		clean, ok, why := p.CheckRead(c.path)
		if ok {
			t.Errorf("%q should be denied", c.path)
			continue
		}
		if clean != c.cleaned || !strings.Contains(why, c.want) {
			t.Errorf("CheckRead(%q) = %q, %q; want cleaned %q and reason containing %q", c.path, clean, why, c.cleaned, c.want)
		}
	}
}

// A Windows agent opens "x.key." as x.key, SSH~1 as .ssh and "x::$DATA" as x,
// so such aliases must not walk around a secret-path rule.
func TestWindowsAliasesRefused(t *testing.T) {
	ps, err := BuildPolicies(map[string]ProfileConfig{"home": {ReadPaths: []string{"/c:/users/**", "/c:/srv/**", "/c:/programdata/**", "/srv/**", "/windows/**"}}})
	if err != nil {
		t.Fatal(err)
	}
	p := ps["home"]
	for _, raw := range []string{
		`C:\Users\me\SSH~1\id_ed25519`,
		`C:\Users\me\.ssh.\id_ed25519`,
		`C:\Users\me\.ssh\id_ed25519.`,
		`C:\srv\site.key.`,
		`C:\srv\site.key `,
		`C:\srv\site.key.. .`,
		`C:\srv\API_TO~1.TXT`,
		`C:\ProgramData\ssh\ssh_host_ed25519_key`,
		`C:\ProgramData\ssh\administrators_authorized_keys`,
		`/srv/site.key::$DATA`,
		`/srv/site.key.`,
		`/Users/me/SSH~1/id_ed25519`,
		`/Windows/System32/config/SAM`,
		`/srv/.ssh:$I30:$INDEX_ALLOCATION/id_ed25519`,
	} {
		if _, ok, _ := p.CheckRead(raw); ok {
			t.Errorf("CheckRead(%q) allowed", raw)
		}
		if _, ok, _ := p.CheckWrite(raw); ok {
			t.Errorf("CheckWrite(%q) allowed", raw)
		}
	}
	for _, raw := range []string{`C:\Users\me\notes~draft.txt`, `C:\srv\v1.2\app.log`, `/srv/backup~/a.txt`, `/srv/x~1y`,
		`/srv/pkg_1.0~20230101.1_amd64.deb`, `/srv/longername~1.txt`} {
		if _, ok, why := p.CheckRead(raw); !ok {
			t.Errorf("CheckRead(%q) refused: %s", raw, why)
		}
	}
}

// The credential stores of package and container registries, databases,
// sync tools, browsers and shell histories, and Windows system secrets, are
// secret paths, wherever a profile lets the model read.
func TestMatchSecretCredentialStores(t *testing.T) {
	for _, key := range []string{
		"/home/u/.dockercfg", "/home/u/.config/containers/auth.json", "/run/user/1000/containers/auth.json",
		"/home/u/.npmrc", "/home/u/.pypirc", "/home/u/.my.cnf", "/home/u/.config/rclone/rclone.conf",
		"/home/u/.config/sops/age/keys.txt", "/home/u/.bash_history", "/root/.mysql_history",
		"/home/u/.mozilla/firefox/x.default/logins.json", "/home/u/.mozilla/firefox/x.default/key4.db",
		"/home/u/.config/google-chrome/default/login data", "/home/u/.config/google-chrome/local state",
		"/c:/users/u/_netrc", "/c:/users/u/keys/srv.ppk", "/c:/users/u/ntuser.dat",
		"/c:/users/u/appdata/roaming/microsoft/windows/powershell/psreadline/consolehost_history.txt",
		"/c:/users/u/appdata/roaming/filezilla/sitemanager.xml",
		"/c:/windows/system32/microsoft/protect/s-1-5-18/user/key", "/c:/programdata/microsoft/vault/x",
		"/c:/programdata/microsoft/wlansvc/profiles/interfaces/x/y.xml", "/c:/windows/memory.dmp",
		"/c:/windows/system32/inetsrv/config/applicationhost.config",
	} {
		if matchSecret(key) == "" {
			t.Errorf("%s is not a secret path", key)
		}
	}
	for _, key := range []string{"/etc/os-release", "/var/log/syslog", "/home/u/notes.txt", "/c:/windows/logs/cbs/cbs.log"} {
		if pat := matchSecret(key); pat != "" {
			t.Errorf("%s matched secret rule %q", key, pat)
		}
	}
}

// A slash path keeps its backslashes, which a Windows agent takes for
// separators, so a ".." between them would leave the allowed prefix and walk
// around the secret rules: such a path is refused.
func TestSlashPathRefusesBackslash(t *testing.T) {
	ro, _ := NewPolicy("readonly")
	for _, p := range []string{
		`/etc/..\..\Users\Administrator\.ssh\id_ed25519`,
		`/var/log/..\..\Windows\System32\config\SAM`,
	} {
		if ap, ok, _ := ro.CheckRead(p); ok {
			t.Errorf("readonly may read %q (sent to agent as %q)", p, ap)
		}
	}
	w := mustPol(t, ProfileConfig{WritePaths: []string{"/tmp/**"}})
	if ap, ok, _ := w.CheckWrite(`/tmp/..\..\Windows\System32\evil.dll`); ok {
		t.Errorf("write allowed to %q", ap)
	}
}

// Windows strips trailing dots and spaces from the final component, where
// the lexical secret rules would not see them: such names are refused.
func TestWindowsTrailingDotRefused(t *testing.T) {
	p := mustPol(t, ProfileConfig{ReadPaths: []string{"/c:/users/**"}})
	for _, s := range []string{`C:\Users\bob\.git-credentials.`, `C:\Users\bob\id.pem.`, `C:\Users\bob\.netrc `, `C:\Users\bob\vault.kdbx.`} {
		if _, ok, _ := p.CheckRead(s); ok {
			t.Errorf("secret rule evaded by %q", s)
		}
	}
	for _, s := range []string{`C:\Users\bob\.git-credentials`, `C:\Users\bob\id.pem`} {
		if _, ok, _ := p.CheckRead(s); ok {
			t.Fatalf("control %q should be denied", s)
		}
	}
}

// /proc/<pid>/root and /proc/<pid>/cwd are magic links to the real tree,
// which would walk around every anchored secret rule (/etc/shadow,
// /etc/ssh/*_key, ...): they are secret paths themselves.
func TestProcLinksAreSecret(t *testing.T) {
	p := mustPol(t, ProfileConfig{ReadPaths: []string{"/**"}})
	if _, ok, _ := p.CheckRead("/etc/shadow"); ok {
		t.Fatal("control")
	}
	for _, s := range []string{"/proc/self/root/etc/shadow", "/proc/1/root/etc/ssh/ssh_host_ed25519_key", "/proc/1/root/etc/sudoers", "/proc/self/root/proc/kcore"} {
		if _, ok, _ := p.CheckRead(s); ok {
			t.Errorf("%s readable", s)
		}
	}
}
