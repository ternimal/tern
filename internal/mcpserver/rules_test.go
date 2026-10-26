// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// A case-insensitive file system opens a protected name under spellings that
// strings.ToLower does not produce: Linux casefold and APFS fold Unicode case
// fully (the long s is s, the sharp s ss, the fi ligature fi), and Linux also
// ignores default-ignorable characters such as zero-width joiners. Each such
// spelling meets the rules of the plain name, on the path asked for and on the
// path the agent reports.
func TestCaseFoldAliasesRefused(t *testing.T) {
	p := mustPol(t, ProfileConfig{
		ReadPaths:  []string{"/home/**", "/Users/**", "/etc/**", "/srv/**"},
		WritePaths: []string{"/home/**", "/Users/**", "/srv/**"},
	})
	for _, alias := range []string{
		"/home/u/.\u017fsh/id_ed25519", // long s
		"/home/u/.\u00dfh/id_ed25519",  // sharp s
		"/home/u/.\u1e9eh/id_ed25519",  // capital sharp s
		"/home/u/.SSH/id_ed25519",
		"/home/u/.s\u200dsh/id_ed25519",       // zero-width joiner
		"/home/u/.s\u00adsh/id_ed25519",       // soft hyphen
		"/home/u/.ss\ufe0fh/id_ed25519",       // variation selector
		"/home/u/.ss\u034fh/id_ed25519",       // combining grapheme joiner
		"/home/u/.aw\u017f/config",            // .aws
		"/home/u/.con\ufb01g/gcloud/adc.json", // fi ligature
		"/home/u/.pgpa\u017fs",
		"/home/u/.kube/kubecon\ufb01g",
		"/srv/kubecon\ufb01g",
		"/srv/tls.\u212aey", // Kelvin sign
		"/home/u/app/db_\u017fecret",
		"/home/u/.bash_hi\u017ftory",
		"/home/u/.git-credential\u017f",
		"/Users/u/.\u017fsh/id_ed25519",
		"/etc/\u017fudoers",
		"/etc/\u017fsh/ssh_host_ed25519_key",
		"C:\\Users\\u\\.\u017fsh\\id_ed25519",
	} {
		if _, ok, why := p.CheckRead(alias); ok || !strings.Contains(why, "secret-path rule") {
			t.Errorf("CheckRead(%q) = %v, %q", alias, ok, why)
		}
		if _, ok, _ := p.CheckWrite(alias); ok {
			t.Errorf("CheckWrite(%q) allowed", alias)
		}
		if err := p.CheckReal(alias); err == nil {
			t.Errorf("CheckReal(%q) allowed", alias)
		}
	}
	// Persistence points: authorized_keys anywhere, a login script, git hooks.
	for _, alias := range []string{"/home/u/srv/authorized_key\u017f", "/Users/u/.ba\u017fhrc", "/srv/app/.git/hook\u017f/pre-commit", "/home/u/.pro\ufb01le"} {
		if _, ok, why := p.CheckWrite(alias); ok || !strings.Contains(why, "persistence-point rule") {
			t.Errorf("CheckWrite(%q) = %v, %q", alias, ok, why)
		}
		if err := p.CheckRealWrite(alias); err == nil {
			t.Errorf("CheckRealWrite(%q) allowed", alias)
		}
	}
	// Names that merely hold such characters are ordinary files.
	for _, name := range []string{"/home/u/stra\u00dfe.txt", "/srv/\ufb01le.txt", "/srv/caf\u00e9.md", "/srv/\U0001f469\u200d\U0001f4bb.png"} {
		if _, ok, why := p.CheckRead(name); !ok {
			t.Errorf("CheckRead(%q) refused: %s", name, why)
		}
	}
}

// Linux casefold may take a name of dots and ignorable characters for "." or
// "..", which path.Clean does not resolve, so the rules would see a path
// inside an allowed directory that leaves it.
func TestDotAliasRefused(t *testing.T) {
	p := mustPol(t, ProfileConfig{ReadPaths: []string{"/srv/app/**", "/c:/srv/app/**"}, WritePaths: []string{"/srv/app/**"}})
	for _, raw := range []string{"/srv/app/..\u200d/etc/passwd", "/srv/app/.\u200d.\u200d/x", "/srv/app/\u00ad..\u200b/x", "/srv/app/sub/.\u200b", "C:\\srv\\app\\..\u2060\\x"} {
		if _, ok, why := p.CheckRead(raw); ok || !strings.Contains(why, "case-insensitive") {
			t.Errorf("CheckRead(%q) = %v, %q", raw, ok, why)
		}
		if _, ok, _ := p.CheckWrite(raw); ok {
			t.Errorf("CheckWrite(%q) allowed", raw)
		}
	}
	for _, raw := range []string{"/srv/app/..x/y", "/srv/app/a..b", "/srv/app/...txt"} {
		if _, ok, why := p.CheckRead(raw); !ok {
			t.Errorf("CheckRead(%q) refused: %s", raw, why)
		}
	}
}

// Programs that start others or run code given to them are wrappers under
// every name a host runs them by: versioned, alternative, static and
// cross-compiler names, Windows names, and spellings a case-insensitive file
// system folds. Neither confirm_unlisted nor a pattern lets one through
// without allow_wrappers.
func TestWrapperSpellings(t *testing.T) {
	cu := mustPol(t, ProfileConfig{Run: RunConfig{ConfirmUnlisted: true}})
	for _, name := range []string{
		// coreutils, util-linux, systemd and OpenSSH
		"split", "sort", "setarch", "linux64", "linux32", "x86_64", "i386", "prlimit", "choom", "uclampset",
		"runcon", "systemd-cat", "systemd-inhibit", "systemd-socket-activate", "machinectl", "dbus-run-session",
		"ssh-agent", "sftp", "slogin", "ssh-copy-id", "ip",
		// alternative and versioned names
		"ex", "view", "vimdiff", "vim.basic", "vim.tiny", "vim.nox", "editor", "sensible-editor",
		"perl5.40-x86_64-linux-gnu", "python3.13-dbg", "pypy3", "php-cgi", "php8.3-cgi", "luajit",
		"nc.openbsd", "nc.traditional", "netcat", "bash-static", "zsh-static", "busybox.static", "lksh", "rksh",
		"bsd-csh", "gtar", "bsdtar", "x86_64-linux-gnu-gcc-13", "aarch64-linux-gnu-gcc", "git-cmd.exe",
		// interpreters and REPLs
		"m4", "dc", "gnuplot", "R", "irb", "erb", "ipython", "ipython3", "jshell", "jrunscript", "groovy", "scala",
		"guile", "racket", "sbcl", "erl", "elixir", "swipl", "ghci", "octave", "calc", "csi", "fsi", "dotnet",
		// build and package tools
		"npm", "pnpm", "yarn", "corepack", "pip", "pip3", "pipx", "uv", "uvx", "poetry", "pipenv", "conda",
		"bundle", "rake", "gem", "composer", "cargo", "go", "mvn", "gradle", "cmake", "gcc", "cc", "g++", "clang",
		"clang-17", "rpm", "apt-get", "dpkg",
		// clients with a command escape
		"psql", "mysql", "ftp", "lftp", "hg", "svn",
		// other programs that run what they are given
		"fd", "fdfind", "rg", "entr", "watchexec", "batch", "unbuffer", "fakeroot", "proot", "faketime",
		"proxychains4", "torsocks", "xvfb-run", "valgrind", "perf", "lldb", "rclone", "restic", "borg",
		"pdflatex", "luatex", "groff", "gs", "convert", "magick",
		// Windows
		"explorer.exe", "runas.exe", "wt.exe", "mintty.exe", "git-bash.exe", "cdb.exe", "psexec.exe",
		"syncappvpublishingserver.exe", "scriptrunner.exe", "odbcconf.exe", "cmstp.exe", "control.exe",
		"msedge.exe", "chrome.exe", "ubuntu.exe", "ubuntu2204.exe", "ftp.exe", "diskshadow.exe", "netsh.exe",
		"reg.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe", "wmic.exe", "cscript.exe", "wscript.exe",
		"msiexec.exe", "installutil.exe", "msbuild.exe", "bitsadmin.exe", "certutil.exe", "schtasks.exe",
		"at.exe", "forfiles.exe", "presentationhost.exe", "CMD.EXE",
		// folded spellings
		"\u017fh", "ba\u017fh", "pyth\u200don", "per\u00adl",
	} {
		if !isWrapper(name) {
			t.Errorf("isWrapper(%q) = false", name)
		}
		if d, why := cu.RunDecision([]string{name, "x"}, false); d != Deny {
			t.Errorf("confirm_unlisted decision for %q = %v (%s), want a refusal", name, d, why)
		}
		if _, err := BuildPolicies(map[string]ProfileConfig{"p": {Run: RunConfig{Allow: [][]string{{name, "**"}}}}}); err == nil {
			t.Errorf("pattern %q ** accepted without allow_wrappers", name)
		}
	}
	for _, name := range []string{"uptime", "df", "systemctl", "journalctl", "whoami", "hostname", "ssh-keyscan",
		"git-lfs", "python3-config", "ip6tables", "update-ca-certificates", "sha256sum", "pg_dump", "kubeadm"} {
		if isWrapper(name) {
			t.Errorf("isWrapper(%q) = true", name)
		}
	}
}

// On Windows a name with a ':' is a path relative to that drive's current
// directory (C:cmd runs cmd.exe from System32 for a service) or names a data
// stream, and a "~" with a digit is an 8.3 short name for a long one. Neither
// is a bare command name, even where wrappers are allowed, and the agent's
// check of batch-file arguments would not see C:deploy as deploy.bat.
func TestCommandNamePathForms(t *testing.T) {
	cu := mustPol(t, ProfileConfig{Run: RunConfig{ConfirmUnlisted: true}})
	aw := mustPol(t, ProfileConfig{Run: RunConfig{ConfirmUnlisted: true, AllowWrappers: true}})
	if d, why := cu.RunDecision([]string{"cmd", "/c", "echo"}, false); d != Deny {
		t.Fatalf("control: cmd should be refused, got %v %s", d, why)
	}
	for _, name := range []string{"C:cmd", "c:powershell.exe", "C:forfiles", "D:rundll32", "C:deploy", "C:cmd.exe",
		"cmd.exe::$DATA", "powershell.exe::$DATA", "POWERS~1", "POWERS~1.EXE", "INSTAL~1.EXE", "BITSAD~1.EXE", "DEPLOY~1"} {
		for _, p := range []*Policy{cu, aw} {
			if d, why := p.RunDecision([]string{name, "/c", "echo"}, false); d != Deny || !strings.Contains(why, "bare command name") {
				t.Errorf("%q with allow_wrappers=%v: decision %v (%s)", name, p.allowWrappers, d, why)
			}
		}
		_, err := BuildPolicies(map[string]ProfileConfig{"p": {Run: RunConfig{AllowWrappers: true, Allow: [][]string{{name, "**"}}}}})
		if err == nil || !strings.Contains(err.Error(), "bare name") {
			t.Errorf("pattern %q: %v", name, err)
		}
	}
	for _, name := range []string{"C:cmd", "c:powershell.exe", "C:forfiles", "D:rundll32", "cmd.exe::$DATA"} {
		if !isWrapper(name) {
			t.Errorf("isWrapper(%q) = false; a Windows agent runs it as the wrapper", name)
		}
	}
	for _, name := range []string{"deploy", "backup~", "x~y"} {
		if why := commandNameProblem(name); why != "" {
			t.Errorf("commandNameProblem(%q) = %q", name, why)
		}
	}
}

// The *secret*, *credential* and *token* rules cover directories too: a
// Kubernetes secret volume (mounted at /etc/secret-volume in the documented
// example), Docker's /run/secrets and systemd's credentials hold secrets under
// file names of their own.
func TestSecretDirectories(t *testing.T) {
	ro, _ := NewPolicy("readonly")
	for _, p := range []string{"/etc/secret-volume/password", "/etc/secret-volume/username", "/etc/secrets/db_password",
		"/etc/app/credentials/password", "/etc/tokens/github", "/etc/foo/.dockerconfigjson"} {
		if _, ok, why := ro.CheckRead(p); ok || !strings.Contains(why, "secret-path rule") {
			t.Errorf("readonly CheckRead(%q) = %v, %q", p, ok, why)
		}
	}
	all := mustPol(t, ProfileConfig{ReadPaths: []string{"/**"}})
	for _, p := range []string{"/run/secrets/db_password", "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
		"/srv/app/secrets/prod.yaml", "/run/credentials/app.service/db", "/home/u/.cache/tokens/x"} {
		if _, ok, why := all.CheckRead(p); ok || !strings.Contains(why, "secret-path rule") {
			t.Errorf("CheckRead(%q) = %v, %q", p, ok, why)
		}
	}
	// What readonly is for still reads.
	for _, p := range []string{"/etc/os-release", "/etc/nginx/conf.d/site.conf", "/var/log/syslog", "/var/log/nginx/error.log",
		"/proc/cpuinfo", "/proc/meminfo", "/proc/1/status", "/proc/self/status", `C:\Windows\System32\drivers\etc\hosts`,
		`C:\Windows\Logs\CBS\CBS.log`} {
		if _, ok, why := ro.CheckRead(p); !ok {
			t.Errorf("readonly CheckRead(%q) refused: %s", p, why)
		}
	}
}

// Credential files of common services under /etc are secret paths, so no
// profile reads them, whatever their mode.
func TestEtcCredentialFiles(t *testing.T) {
	ro, _ := NewPolicy("readonly")
	for _, p := range []string{
		"/etc/sssd/sssd.conf", "/etc/sssd/conf.d/ldap.conf", "/etc/nslcd.conf", "/etc/ldap.conf",
		"/etc/krb5kdc/stash", "/etc/krb5kdc/.k5.EXAMPLE.COM", "/etc/samba/smbpasswd", "/etc/redis/redis.conf",
		"/etc/redis.conf", "/etc/wpa_supplicant/wpa_supplicant.conf", "/etc/wpa_supplicant/wpa_supplicant-wlan0.conf",
		"/etc/openvpn/client/auth.txt", "/etc/openvpn/auth.txt", "/etc/apache2/.htpasswd", "/etc/nginx/.htpasswd",
		"/etc/ssmtp/ssmtp.conf", "/etc/msmtprc", "/etc/pgbouncer/userlist.txt", "/etc/dovecot/users",
		"/etc/webmin/miniserv.users", "/etc/gitlab/gitlab.rb", "/etc/gitlab/gitlab-secrets.json",
		"/etc/gitlab-runner/config.toml", "/etc/snmp/snmpd.conf", "/etc/chrony/chrony.keys", "/etc/kcpassword",
		"/etc/master.passwd", "/etc/spwd.db", "/etc/openldap/certs/password", "/etc/ldap/slapd.d/cn=config.ldif",
		"/etc/ipsec.secrets", "/etc/ppp/chap-secrets",
	} {
		if _, ok, why := ro.CheckRead(p); ok || !strings.Contains(why, "secret-path rule") {
			t.Errorf("readonly CheckRead(%q) = %v, %q", p, ok, why)
		}
	}
	for _, key := range []string{"/var/lib/samba/private/passdb.tdb", "/private/etc/kcpassword", "/home/u/.msmtprc",
		"/var/kerberos/krb5kdc/.k5.EXAMPLE.COM", "/var/lib/iwd/home.psk"} {
		if matchSecret(key) == "" {
			t.Errorf("%s is not a secret path", key)
		}
	}
}

// Under /etc, readonly reads only files every user may read: the others are
// mostly credentials of a service, which a root ternd would hand over.
// Logs are readable by design, and a profile that lists a path itself reads
// it whatever its mode.
func TestReadCheckEtcModes(t *testing.T) {
	ro, _ := NewPolicy("readonly")
	for _, c := range []struct {
		path string
		perm os.FileMode
		ok   bool
	}{
		{"/etc/nginx/nginx.conf", 0o644, true},
		{"/etc/os-release", 0o444, true},
		{"/etc/gophish/config.json", 0o640, false},
		{"/etc/default/iodine", 0o600, false},
		{"/etc/postgresql/18/main/pg_hba.conf", 0o640, false},
		{"/etc/ppp/peers/provider", 0o640, false},
		{"/etc/odd", 0, false}, // also a reply that carries no mode
		{"/var/log/nginx/access.log", 0o640, true},
		{"/var/log/boot.log", 0o600, true},
		{"/proc/1/status", 0o444, true},
		{"C:/Windows/System32/drivers/etc/hosts", 0o666, true}, // Windows reports 0666 or 0444
	} {
		err := ro.ReadCheck(c.path)(c.path, c.perm, true)
		if (err == nil) != c.ok {
			t.Errorf("%s mode %04o: %v", c.path, c.perm, err)
		}
		if err != nil && !strings.Contains(err.Error(), "not readable by every user") {
			t.Errorf("%s: %v", c.path, err)
		}
	}
	// On macOS the agent reports /private/etc; the path asked for decides.
	if err := ro.ReadCheck("/etc/gophish/config.json")("/private/etc/gophish/config.json", 0o640, true); err == nil {
		t.Error("a /private/etc path passed")
	}
	own := mustPol(t, ProfileConfig{ReadPaths: []string{"/etc/postgresql/**"}})
	if err := own.ReadCheck("/etc/postgresql/18/main/pg_hba.conf")("/etc/postgresql/18/main/pg_hba.conf", 0o640, true); err != nil {
		t.Errorf("a path the profile lists: %v", err)
	}
	if err := own.ReadCheck("/etc/gophish/config.json")("/etc/gophish/config.json", 0o640, true); err == nil {
		t.Error("a path the profile does not list passed")
	}
	// The secret-path rules come first, on the real path.
	if err := ro.ReadCheck("/etc/nginx/key")("/etc/ssl/private/site.key", 0o644, true); err == nil || !strings.Contains(err.Error(), "secret-path rule") {
		t.Errorf("a link to a secret path: %v", err)
	}
	if err := ro.ReadCheck("/etc/hostname")("", 0o644, true); err == nil {
		t.Error("an agent that reports no real path passed")
	}
}

// The agent's reply carries the mode, and the check refuses the file before
// any of its content moves: read_file returns nothing of it, and download
// leaves nothing in the workspace, not even a partial file.
func TestReadCheckModeEndToEnd(t *testing.T) {
	a := newStackAgent(t)
	dir, ws := openTempDir(t), t.TempDir() // dir and those above it open to all, as /etc is
	conf, bind := filepath.Join(dir, "app.conf"), filepath.Join(dir, "bind.conf")
	os.WriteFile(conf, []byte("listen 80\n"), 0o644)
	os.WriteFile(bind, []byte("bindpw not-a-real-one\n"), 0o600)
	os.Chmod(conf, 0o644) // whatever the umask
	builtIn := func(c *Config) {
		// dir stands in for /etc: readable through a built-in rule that
		// reaches only files every user may read.
		p := c.Targets[0].Policy
		p.readAllow = append(slices.Clone(p.readAllow), dir+"/**")
		p.worldOnly = []string{dir + "/**"}
		c.Workspace = ws
	}
	srv, _ := stackServer(t, a, ProfileConfig{}, builtIn)
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	var r ReadOutput
	call(t, cs, "read_file", map[string]any{"path": conf}, &r, false)
	if r.Content != "listen 80\n" {
		t.Fatalf("read_file of a world-readable file = %q", r.Content)
	}
	if why := call(t, cs, "read_file", map[string]any{"path": bind}, nil, true); !strings.Contains(why, "not readable by every user") || strings.Contains(why, "not-a-real-one") {
		t.Errorf("read_file of an owner-only file: %s", why)
	}
	if why := call(t, cs, "download", map[string]any{"remote": bind, "local": "bind.conf"}, nil, true); !strings.Contains(why, "not readable by every user") {
		t.Errorf("download of an owner-only file: %s", why)
	}
	if names, _ := os.ReadDir(ws); len(names) != 0 {
		t.Errorf("a refused download left %v in the workspace", names)
	}
	// Listed by the profile itself, the same file reads.
	srv2, _ := stackServer(t, a, ProfileConfig{ReadPaths: []string{dir + "/**"}}, func(c *Config) {
		c.Targets[0].Policy.worldOnly = []string{dir + "/**"}
	})
	defer srv2.Close()
	call(t, stackClient(t, srv2, "", nil), "read_file", map[string]any{"path": bind}, &r, false)
	if r.Content != "bindpw not-a-real-one\n" {
		t.Errorf("read_file of a listed path = %q", r.Content)
	}
}

// Persistence points are never writable, however broad the write grant, and
// stay readable where reads are allowed.
func TestPersistencePointsNeverWritable(t *testing.T) {
	root := mustPol(t, ProfileConfig{WritePaths: []string{"/**"}, ReadPaths: []string{"/**"}})
	home := mustPol(t, ProfileConfig{WritePaths: []string{"/home/**", "/Users/**", "/c:/users/**", "/c:/programdata/**", "/c:/windows/**"}})
	for _, c := range []struct {
		p    *Policy
		path string
	}{
		{root, "/etc/ld.so.preload"}, {root, "/etc/passwd"}, {root, "/etc/group"}, {root, "/etc/cron.d/x"},
		{root, "/etc/crontab"}, {root, "/etc/cron.daily/x"}, {root, "/var/spool/cron/crontabs/root"},
		{root, "/etc/systemd/system/x.service"}, {root, "/usr/lib/systemd/system/x.service"}, {root, "/etc/profile"},
		{root, "/etc/profile.d/x.sh"}, {root, "/etc/pam.d/sshd"}, {root, "/etc/environment"}, {root, "/etc/rc.local"},
		{root, "/etc/apt/apt.conf.d/99x"}, {root, "/etc/udev/rules.d/99-x.rules"}, {root, "/etc/ssh/sshd_config"},
		{root, "/Library/LaunchDaemons/x.plist"}, {root, "/private/etc/periodic/daily/x"},
		{root, "/srv/app/.git/hooks/pre-commit"}, {root, "/srv/app/.git/config"}, {root, "/opt/tern/agent_authorized_keys"},
		{root, "/root/.ssh/authorized_keys2"},
		{home, "/home/u/.bashrc"}, {home, "/home/u/.bash_profile"}, {home, "/home/u/.profile"}, {home, "/home/u/.zshrc"},
		{home, "/home/u/.zprofile"}, {home, "/home/u/.zshenv"}, {home, "/home/u/.config/fish/config.fish"},
		{home, "/home/u/.config/systemd/user/x.service"}, {home, "/home/u/.config/autostart/x.desktop"},
		{home, "/home/u/.local/bin/ls"}, {home, "/home/u/project/.git/hooks/pre-commit"}, {home, "/home/u/.gitconfig"},
		{home, "/Users/u/Library/LaunchAgents/x.plist"}, {home, "/home/u/authorized_keys"},
		{home, `C:\Users\u\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.bat`},
		{home, `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\x.lnk`},
		{home, `C:\Users\u\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1`},
		{home, `C:\Windows\System32\Tasks\x`},
	} {
		if _, ok, why := c.p.CheckWrite(c.path); ok || !strings.Contains(why, "rule") {
			t.Errorf("CheckWrite(%q) = %v, %q", c.path, ok, why)
		}
	}
	for _, p := range []string{"/etc/passwd", "/etc/crontab", "/home/u/.bashrc", "/srv/app/.git/config", "/home/u/.ssh-keys/authorized_keys"} {
		if _, ok, why := root.CheckRead(p); !ok {
			t.Errorf("CheckRead(%q) refused: %s", p, why)
		}
	}
	// Through a link, on the path the agent reports, macOS's /private included.
	for _, real := range []string{"/etc/cron.d/x", "/private/etc/cron.d/x", "/home/u/.git/hooks/post-checkout", `C:\Users\u\.bashrc`} {
		if err := root.CheckRealWrite(real); err == nil || !strings.Contains(err.Error(), "persistence-point rule") {
			t.Errorf("CheckRealWrite(%q) = %v", real, err)
		}
		if err := root.CheckReal(real); err != nil {
			t.Errorf("CheckReal(%q), for a read: %v", real, err)
		}
	}
	if _, ok, why := root.CheckWrite("/srv/app/hooks/x"); !ok {
		t.Errorf("an ordinary hooks directory: %s", why)
	}
}

// A write through a link into a persistence point is refused on the path the
// agent reports, before any content lands.
func TestPersistencePointThroughLink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks needs a privilege on Windows")
	}
	a := newStackAgent(t)
	dir := t.TempDir()
	hooks := filepath.Join(dir, "project", ".git", "hooks")
	os.MkdirAll(hooks, 0o700)
	os.MkdirAll(filepath.Join(dir, "pub"), 0o700)
	os.Symlink(hooks, filepath.Join(dir, "pub", "h"))
	ws := t.TempDir()
	os.WriteFile(filepath.Join(ws, "hook"), []byte("#!/bin/sh\necho hi\n"), 0o755)
	srv, _ := stackServer(t, a, ProfileConfig{WritePaths: []string{dir + "/pub/**"}}, func(c *Config) { c.Workspace = ws })
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	if why := call(t, cs, "write_file", map[string]any{"path": dir + "/pub/h/pre-commit", "content": "#!/bin/sh\n"}, nil, true); !strings.Contains(why, "persistence-point rule") {
		t.Errorf("write_file through a link into .git/hooks: %s", why)
	}
	if why := call(t, cs, "upload", map[string]any{"local": "hook", "remote": dir + "/pub/h/post-merge"}, nil, true); !strings.Contains(why, "persistence-point rule") {
		t.Errorf("upload through a link into .git/hooks: %s", why)
	}
	// The agent drops its temporary file once it sees the refusal, a moment
	// after the call returns; nothing else may be left.
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		names, _ := os.ReadDir(hooks)
		if len(names) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("a refused write left %v in %s", names, hooks)
		}
	}
}

// write_file and upload reach the same remote files, and read_file and
// download read them, so a confirm entry for one of a pair covers both.
func TestConfirmPairs(t *testing.T) {
	for _, c := range []struct{ named, other string }{
		{"write_file", "upload"}, {"upload", "write_file"}, {"read_file", "download"}, {"download", "read_file"},
	} {
		p := mustPol(t, ProfileConfig{ReadPaths: []string{"/srv/**"}, WritePaths: []string{"/srv/**"}, Confirm: []string{c.named}})
		if d, _ := fileDecision(p, c.other); d != Confirm {
			t.Errorf("confirm %s: %s decision %v", c.named, c.other, d)
		}
		if !slices.Contains(p.ConfirmActions(), c.other) {
			t.Errorf("confirm %s: confirm_actions %v", c.named, p.ConfirmActions())
		}
	}
	// The documented ops profile confirms write_file, so its uploads ask too.
	pols, err := BuildPolicies(map[string]ProfileConfig{
		"ops":   {Run: RunConfig{Shell: true}, PTY: true, WritePaths: []string{"/srv/app/**"}, Confirm: []string{"run:shell", "write_file"}},
		"child": {Extends: "ops"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ops", "child"} {
		if d, _ := fileDecision(pols[name], "upload"); d != Confirm {
			t.Errorf("%s: upload decision %v", name, d)
		}
		if d, _ := fileDecision(pols[name], "read_file"); d != Allow {
			t.Errorf("%s: read_file decision %v, a write confirmation must not ask for reads", name, d)
		}
	}
}

// An upload's approval is bound to the bytes the form showed: a file changed
// between the question and the approved retry, even to the same size and
// mtime, is a different action and is not sent.
func TestUploadApprovalBindsContent(t *testing.T) {
	for _, version := range []string{"2026-07-28", "2025-11-25"} {
		t.Run(version, func(t *testing.T) { testUploadApprovalBindsContent(t, version) })
	}
}

func testUploadApprovalBindsContent(t *testing.T, version string) {
	a := newStackAgent(t)
	ws, remote := t.TempDir(), t.TempDir()
	const v1 = "echo approved-content-v1\n"
	const v2 = "echo SWAPPEDX-content-v2\n"
	local := filepath.Join(ws, "deploy.sh")
	os.WriteFile(local, []byte(v1), 0o644)
	os.Chmod(local, 0o644) // whatever the umask
	st0, _ := os.Stat(local)
	srv, _ := stackServer(t, a, ProfileConfig{WritePaths: []string{remote + "/**"}, Confirm: []string{"upload"}},
		func(c *Config) { c.Workspace = ws })
	defer srv.Close()
	swap := true
	var asked []string
	handler := func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		asked = append(asked, req.Params.Message)
		if swap {
			// While the user reads the form and approves, something else
			// with access to the workspace swaps the file.
			os.WriteFile(local, []byte(v2), 0o644)
			os.Chtimes(local, st0.ModTime(), st0.ModTime())
		}
		return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approve": true}}, nil
	}
	cs := stackClient(t, srv, version, &mcp.ClientOptions{ElicitationHandler: handler})
	args := map[string]any{"local": "deploy.sh", "remote": remote + "/deploy.sh"}
	if why := call(t, cs, "upload", args, nil, true); !strings.Contains(why, "does not match this action") {
		t.Errorf("upload of a file swapped after approval: %s", why)
	}
	if len(asked) != 1 || !strings.Contains(asked[0], "  | echo approved-content-v1") || !strings.Contains(asked[0], "mode 0644 if new") {
		t.Fatalf("the form must show the content: %q", asked)
	}
	if b, err := os.ReadFile(filepath.Join(remote, "deploy.sh")); err == nil {
		t.Fatalf("uploaded %q, which the user never saw", b)
	}
	// Left alone, the file the user sees is the file that arrives.
	swap = false
	var out TransferOutput
	call(t, cs, "upload", args, &out, false)
	if b, _ := os.ReadFile(filepath.Join(remote, "deploy.sh")); string(b) != v2 || !strings.Contains(asked[1], "  | echo SWAPPEDX-content-v2") || out.SHA256 != sha(v2) {
		t.Errorf("approved upload = %q (sha256 %s), form %q", b, out.SHA256, asked[1])
	}
}

// A path the agent reports comes back to the model in error text, escaped as
// the confirmation form escapes it: nothing invisible reaches the model.
func TestRealPathErrorsEscaped(t *testing.T) {
	p := mustPol(t, ProfileConfig{ReadPaths: []string{"/**"}, WritePaths: []string{"/**"}})
	for _, err := range []error{
		p.CheckReal("/home/u/.ssh/id\U000e0049\U000e0047\U000e004e"),
		p.CheckReal("/srv/x\u202e."),
		p.CheckReal("/srv/A\u200bPI~1/x"),
		p.CheckReal("unresolved: lstat /srv/\u2066x\u2069: no such file or directory"),
		p.CheckRealWrite("/etc/cron.d/x\ufe0f"),
	} {
		if err == nil {
			t.Error("a path passed")
		} else if strings.ContainsFunc(err.Error(), invisible) {
			t.Errorf("an error shows invisible characters raw: %q", err)
		}
	}
	if runtime.GOOS == "windows" {
		return
	}
	a := newStackAgent(t)
	dir := t.TempDir()
	hidden := "\U000E0049\U000E0047\U000E004E\U000E004F\U000E0052\U000E0045" // tag letters
	secret := filepath.Join(dir, "home", ".ssh")
	logs := filepath.Join(dir, "logs")
	os.MkdirAll(secret, 0o700)
	os.MkdirAll(logs, 0o700)
	os.WriteFile(filepath.Join(secret, "id"+hidden), []byte("x"), 0o600)
	os.Symlink(filepath.Join(secret, "id"+hidden), filepath.Join(logs, "app.log"))
	srv, _ := stackServer(t, a, ProfileConfig{ReadPaths: []string{logs + "/**"}}, nil)
	defer srv.Close()
	msg := call(t, stackClient(t, srv, "", nil), "read_file", map[string]any{"path": filepath.Join(logs, "app.log")}, nil, true)
	if !strings.Contains(msg, "secret-path rule") || strings.ContainsFunc(msg, invisible) || !strings.Contains(msg, `\U000e0049`) {
		t.Errorf("error the model reads: %q", msg)
	}
}

// The "Why you are asked" line of a confirmation form renders the command as
// the action line does, so invisible characters show escaped there too.
func TestConfirmWhyEscaped(t *testing.T) {
	pol := mustPol(t, ProfileConfig{Run: RunConfig{ConfirmUnlisted: true}})
	argv := []string{"rm", "-r", "/srv/app\ufe0f\u3164\ufe0e"}
	d, why := pol.RunDecision(argv, false)
	msg, err := confirmMessage("box", pol.Profile, why, commandView("run a command", argv, false, ""))
	if d != Confirm || err != nil {
		t.Fatalf("%v %v", d, err)
	}
	if strings.ContainsFunc(msg, invisible) || strings.Count(msg, `rm -r "/srv/app\ufe0f\u3164\ufe0e"`) != 2 {
		t.Errorf("form: %q", msg)
	}
	if _, why := pol.RunDecision([]string{"pyth\u200bon3"}, false); strings.ContainsFunc(why, invisible) {
		t.Errorf("refusal: %q", why)
	}
}

// readonly (the default) must not read well-known credential files.
func TestReadonlyCredentialFiles(t *testing.T) {
	ro, _ := NewPolicy("readonly")
	for _, s := range []string{"/etc/kubernetes/admin.conf", "/etc/kubernetes/super-admin.conf", "/etc/rancher/k3s/k3s.yaml",
		"/etc/krb5.keytab", "/etc/security/opasswd", "/etc/NetworkManager/system-connections/wifi.nmconnection"} {
		if _, ok, _ := ro.CheckRead(s); ok {
			t.Errorf("readonly may read %s", s)
		}
	}
	out, _ := redact("users:\n- name: kubernetes-admin\n  user:\n    client-key-data: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFBS0NBUUVB\n")
	if strings.Contains(out, "LS0tLS1CRUdJTi") {
		t.Errorf("kubeconfig client-key-data not redacted: %s", out)
	}
	out, _ = redact(`{"db": {"password": "hunter2"}}`)
	if strings.Contains(out, "hunter2") {
		t.Errorf("JSON password not redacted: %s", out)
	}
}

// The wrapper denylist must also catch ".exe" and versioned names.
func TestWrapperAliases(t *testing.T) {
	p := mustPol(t, ProfileConfig{Run: RunConfig{ConfirmUnlisted: true}})
	if d, _ := p.RunDecision([]string{"python", "-c", "x"}, false); d != Deny {
		t.Fatal("control")
	}
	for _, a0 := range []string{"python.exe", "bash.exe", "node.exe", "curl.exe", "wsl.exe", "python3.12", "rundll32.exe", "mshta.exe",
		"cmd.exe ", "rundll32.exe.", "powershell.exe ", "bash.exe.", "cmd.exe. ."} {
		if d, _ := p.RunDecision([]string{a0, "-c", "x"}, false); d != Deny {
			t.Errorf("wrapper %s not refused (decision %d)", a0, d)
		}
	}
	if _, err := BuildPolicies(map[string]ProfileConfig{"p": {Run: RunConfig{Allow: [][]string{{"bash.exe", "**"}}}}}); err == nil {
		t.Errorf("pattern bash.exe ** accepted without allow_wrappers")
	}
}

// On macOS /etc is a link to /private/etc, so the path an agent reports for a
// read or write there must still meet the /etc secret rules.
func TestCheckRealMacOSPrivate(t *testing.T) {
	p := mustPol(t, ProfileConfig{ReadPaths: []string{"/**"}})
	for _, real := range []string{"/private/etc/sudoers", "/private/etc/ssh/ssh_host_ed25519_key", "/private/etc/sudoers.d/admin"} {
		if err := p.CheckReal(real); err == nil {
			t.Errorf("CheckReal(%q) allowed a secret path", real)
		}
	}
	if err := p.CheckReal("/private/var/log/system.log"); err != nil {
		t.Errorf("CheckReal refused an ordinary log: %v", err)
	}
}

// MCP clients', AI coding tools' and editors' configuration is never
// writable on an agent, whatever write_paths say, on Linux, macOS and
// Windows, in a home directory and in a project: the hooks, MCP servers,
// tasks and extensions it names run code. The parts that hold logins or the
// environment MCP servers get are never readable either; instruction files
// and editor settings stay readable.
func TestClientConfigNeverWritable(t *testing.T) {
	p := mustPol(t, ProfileConfig{ReadPaths: []string{"/**", "/c:/**"}, WritePaths: []string{"/**", "/c:/**"}})
	secret := []string{
		"/home/u/.claude/settings.json", "/home/u/.claude/.credentials.json", "/srv/app/.claude/settings.local.json",
		"/srv/app/.claude/commands/deploy.md", "/Users/u/.claude/settings.json", `C:\Users\u\.claude\settings.json`,
		"/home/u/.claude.json", "/home/u/.claude.json.backup", `C:\Users\u\.claude.json`,
		"/Users/u/Library/Application Support/Claude/claude_desktop_config.json",
		`C:\Users\u\AppData\Roaming\Claude\claude_desktop_config.json`, "/home/u/.cursor/mcp.json", "/srv/app/.vscode/mcp.json",
		"/srv/app/.mcp.json", "/home/u/.config/Code/User/mcp.json", "/home/u/.codeium/windsurf/mcp_config.json",
		"/home/u/.copilot/mcp-config.json", "/home/u/.config/anthropic/configs/default.json",
		`C:\Users\u\AppData\Roaming\Anthropic\configs\default.json`, "/home/u/.codex/auth.json", "/home/u/.codex/config.toml",
		"/home/u/.gemini/oauth_creds.json", "/srv/app/.gemini/settings.json",
		"/home/u/.config/zed/settings.json", "/srv/app/.zed/settings.json", `C:\Users\u\AppData\Roaming\Zed\settings.json`,
		"/home/u/.continue/config.yaml", "/srv/app/.continue/mcpServers/tern.yaml", "/home/u/.config/goose/config.yaml",
		`C:\Users\u\AppData\Roaming\Block\goose\config\config.yaml`, "/srv/app/opencode.json", "/srv/app/opencode.jsonc",
		"/home/u/.config/opencode/opencode.json", "/srv/app/crush.json", "/srv/app/.crush.json",
		"/home/u/.config/crush/crush.json", `C:\Users\u\AppData\Local\crush\crush.json`, "/home/u/.qwen/settings.json",
		"/srv/app/.qwen/settings.json",
	}
	noWrite := []string{
		"/home/u/CLAUDE.md", "/srv/app/CLAUDE.local.md", "/srv/app/AGENTS.md", "/srv/app/GEMINI.md", "/srv/app/.cursorrules",
		"/srv/app/.windsurfrules", "/srv/app/.clinerules", "/etc/claude-code/managed-settings.json",
		"/Library/Application Support/ClaudeCode/managed-settings.json", `C:\Program Files\ClaudeCode\managed-settings.json`,
		"/home/u/.config/Claude/extensions/x/index.js", "/Users/u/Library/Application Support/Claude/Claude Extensions/x/a.js",
		`C:\Users\u\AppData\Local\Packages\Claude_x\LocalCache\Roaming\Claude\extensions\x.js`, "/home/u/.cursor/hooks.json",
		"/srv/app/.vscode/tasks.json", "/srv/app/.vscode/settings.json", "/home/u/.vscode/extensions/x/extension.js",
		"/home/u/.vscode-server/data/Machine/settings.json", "/home/u/.cursor-server/extensions/x/a.js",
		"/home/u/.config/Code/User/settings.json", "/home/u/.config/Cursor/User/settings.json",
		"/Users/u/Library/Application Support/Code/User/tasks.json", `C:\Users\u\AppData\Roaming\Code\User\settings.json`,
		`C:\Users\u\AppData\Roaming\Windsurf\User\settings.json`, "/home/u/.windsurf/extensions/x/a.js",
		"/home/u/.config/zed/keymap.json", "/srv/app/.zed/tasks.json", `C:\Users\u\AppData\Roaming\Zed\tasks.json`,
		"/srv/app/.amazonq/cli-agents/x.json", "/srv/app/.opencode/plugin/x.js",
		"/srv/app/AGENTS.override.md", "/home/u/notes/AGENTS.override.md", "/srv/app/.github/copilot-instructions.md",
		"/srv/app/.github/instructions/api.instructions.md", "/srv/app/.goosehints", "/srv/app/.rules",
		"/etc/gemini-cli/settings.json", "/etc/gemini-cli/system-defaults.json",
		"/Library/Application Support/GeminiCli/settings.json", `C:\ProgramData\gemini-cli\settings.json`,
		"/etc/cursor/hooks.json", `C:\ProgramData\Cursor\hooks.json`, "/Library/Application Support/Cursor/hooks.json",
		"/etc/codex/requirements.toml", "/etc/codex/managed_config.toml",
	}
	for _, path := range secret {
		if _, ok, why := p.CheckWrite(path); ok || !strings.Contains(why, "secret-path rule") {
			t.Errorf("CheckWrite(%q) = %v, %q", path, ok, why)
		}
		if _, ok, why := p.CheckRead(path); ok || !strings.Contains(why, "secret-path rule") {
			t.Errorf("CheckRead(%q) = %v, %q", path, ok, why)
		}
	}
	for _, path := range noWrite {
		if _, ok, why := p.CheckWrite(path); ok || !strings.Contains(why, "persistence-point rule") {
			t.Errorf("CheckWrite(%q) = %v, %q", path, ok, why)
		}
		if _, ok, why := p.CheckRead(path); !ok {
			t.Errorf("CheckRead(%q) refused: %s", path, why)
		}
	}
	for _, path := range []string{"/srv/app/src/main.go", "/srv/app/docs/claude-notes.md", "/srv/app/vscode-ext/package.json",
		"/home/u/.config/codex-notes.txt", `C:\Users\u\AppData\Roaming\Codecs\x.ini`, "/srv/app/.github/workflows/ci.yml",
		"/srv/app/docs/rules.md", "/etc/udev-notes/99-x.rules", "/etc/cursors/x.conf"} {
		if _, ok, why := p.CheckWrite(path); !ok {
			t.Errorf("CheckWrite(%q) refused: %s", path, why)
		}
	}
}

// The per-user program folders of Windows are never writable, in either
// spelling a Windows agent opens and in any case: the programs there run as
// the user and many are on the user's PATH. The data folders beside them
// stay writable.
func TestWindowsUserProgramFolders(t *testing.T) {
	p := mustPol(t, ProfileConfig{WritePaths: []string{"/c:/users/**", "/Users/**"}})
	for _, path := range []string{
		`C:\Users\u\AppData\Local\Programs\Microsoft VS Code\Code.exe`, `C:\Users\u\AppData\Local\Programs\Python\Python313\python.exe`,
		`C:\Users\u\AppData\Local\Programs\cursor\resources\app\out\main.js`, `c:\users\u\appdata\local\PROGRAMS\x\x.exe`,
		`C:\Users\u\AppData\Local\AnthropicClaude\claude.exe`, `C:\Users\u\AppData\Local\AnthropicClaude\app-1.2.3\claude.exe`,
		`C:\Users\u\AppData\Local\AnthropicClaude\Update.exe`, `C:\Users\u\AppData\Local\Discord\app-1.0.9187\Discord.exe`,
		`C:\Users\u\AppData\Local\slack\Update.exe`, `C:\Users\u\AppData\Local\Microsoft\WindowsApps\python.exe`,
		`C:\Users\u\AppData\Local\Microsoft\WinGet\Links\rg.exe`, `C:\Users\u\AppData\Local\Microsoft\WinGet\Packages\x\x.exe`,
		`C:\Users\u\AppData\Roaming\Python\Python313\Scripts\black.exe`, "/Users/u/AppData/Local/Programs/x/x.exe",
	} {
		if _, ok, why := p.CheckWrite(path); ok || !strings.Contains(why, "persistence-point rule") {
			t.Errorf("CheckWrite(%q) = %v, %q", path, ok, why)
		}
	}
	for _, path := range []string{`C:\Users\u\AppData\Local\Temp\x.txt`, `C:\Users\u\AppData\Local\Discord\settings.json`,
		`C:\Users\u\AppData\Local\MyApp\data\app.db`, `C:\Users\u\AppData\Roaming\Python\notes.txt`, `C:\Users\u\Documents\Programs\x.txt`} {
		if _, ok, why := p.CheckWrite(path); !ok {
			t.Errorf("CheckWrite(%q) refused: %s", path, why)
		}
	}
}

// tern's own keys, under the names tern keygen and the docs give them, and
// its configuration and state directories on every system, are secret paths:
// an agent hands none of them over, and none is written there.
func TestTernOwnFilesSecret(t *testing.T) {
	p := mustPol(t, ProfileConfig{ReadPaths: []string{"/**", "/c:/**"}, WritePaths: []string{"/**", "/c:/**"}})
	for _, path := range []string{
		"/home/u/.config/tern/id_tern", "/home/u/.config/tern/web1.token", "/home/u/.config/tern/mcp.json",
		"/srv/deploy/tern_id_ed25519", "/srv/deploy/tern_id_ed25519.pub", "/srv/app/id_tern", "/root/id_tern_old",
		"/home/u/.local/state/tern/mcp-audit.jsonl", "/home/u/.local/state/tern/recordings/x.cast",
		"/home/u/.local/state/tern/mcp-ptys-0123456789ab.json", `C:\Users\u\AppData\Local\tern\mcp-ptys-0123456789ab.json`,
		`C:\Users\u\AppData\Roaming\tern\web1.token`, "/Users/u/Library/Application Support/tern/mcp.json",
	} {
		if _, ok, why := p.CheckRead(path); ok || !strings.Contains(why, "secret-path rule") {
			t.Errorf("CheckRead(%q) = %v, %q", path, ok, why)
		}
		if _, ok, why := p.CheckWrite(path); ok || !strings.Contains(why, "secret-path rule") {
			t.Errorf("CheckWrite(%q) = %v, %q", path, ok, why)
		}
	}
	for _, path := range []string{"/srv/app/internal/tern/client.go", "/home/u/src/tern/README.md", "/srv/pattern_id.txt"} {
		if _, ok, why := p.CheckRead(path); !ok {
			t.Errorf("CheckRead(%q) refused: %s", path, why)
		}
	}
}

// Registry and package-manager logins are secret paths: Composer's, Maven's
// server passwords, Gradle's and Yarn's tokens, Poetry's, NuGet's, pip's
// index URLs, Bundler's, Helm's, JFrog's, Terraform's CLI tokens, rclone's,
// hub's, and the registry logins of root's container tools under
// /run/containers/0. The projects' own build files stay readable.
func TestPackageManagerCredentials(t *testing.T) {
	p := mustPol(t, ProfileConfig{ReadPaths: []string{"/**", "/c:/**"}})
	for _, path := range []string{
		"/home/u/.config/composer/auth.json", "/home/u/.composer/auth.json", `C:\Users\u\AppData\Roaming\Composer\auth.json`,
		"/home/u/.m2/settings.xml", "/home/u/.gradle/gradle.properties", "/home/u/.yarnrc.yml", "/srv/app/.yarnrc.yml",
		"/home/u/.config/pypoetry/auth.toml", "/Users/u/Library/Application Support/pypoetry/auth.toml",
		"/home/u/.nuget/NuGet/NuGet.Config", `C:\Users\u\AppData\Roaming\NuGet\NuGet.Config`, "/home/u/.config/pip/pip.conf",
		"/home/u/.pip/pip.conf", "/etc/pip.conf", `C:\Users\u\AppData\Roaming\pip\pip.ini`, "/home/u/.bundle/config",
		"/home/u/.config/helm/registry/config.json", "/home/u/.config/helm/repositories.yaml",
		"/home/u/.jfrog/jfrog-cli.conf.v6", "/home/u/.terraformrc", `C:\Users\u\AppData\Roaming\terraform.rc`,
		"/home/u/.config/rclone/rclone.conf", `C:\Users\u\AppData\Roaming\rclone\rclone.conf`, "/home/u/.config/hub",
		"/run/containers/0/auth.json", "/run/user/1000/containers/auth.json", "/home/u/.config/containers/auth.json",
		"/home/u/.cargo/credentials.toml", "/home/u/.gem/credentials", "/home/u/.terraform.d/credentials.tfrc.json",
		"/home/u/.config/gh/hosts.yml",
	} {
		if _, ok, why := p.CheckRead(path); ok || !strings.Contains(why, "secret-path rule") {
			t.Errorf("CheckRead(%q) = %v, %q", path, ok, why)
		}
	}
	for _, path := range []string{"/srv/app/composer.json", "/srv/app/pom.xml", "/srv/app/build.gradle", "/srv/app/gradle.properties",
		"/srv/app/package.json", "/srv/app/pyproject.toml", "/srv/app/requirements.txt", "/home/u/.m2/repository/x/x.pom",
		"/srv/app/Gemfile", "/srv/app/Chart.yaml", "/run/containers/0/overlay/x"} {
		if _, ok, why := p.CheckRead(path); !ok {
			t.Errorf("CheckRead(%q) refused: %s", path, why)
		}
	}
}
