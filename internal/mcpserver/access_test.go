// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	tern "github.com/ternimal/tern/internal/tern"
)

// openTempDir returns a new directory that every user may search, as may
// every directory above it, so a world-readable file in it is readable by
// every user, as the files under /etc are. t.TempDir makes 0700 directories,
// and TMPDIR may sit in a private home directory, so it looks for a base
// that is open all the way up.
func openTempDir(t *testing.T) string {
	t.Helper()
	for _, base := range []string{os.TempDir(), "/tmp", "/var/tmp", "/dev/shm"} {
		real, err := filepath.EvalSymlinks(base)
		if err != nil || !searchableByAll(real) {
			continue
		}
		dir, err := os.MkdirTemp(real, "tern-test-")
		if err != nil {
			continue
		}
		t.Cleanup(func() { os.RemoveAll(dir) })
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	t.Skip("no directory that every user may search to make test files in")
	return ""
}

// searchableByAll reports whether dir and every directory above it let every
// user search them.
func searchableByAll(dir string) bool {
	for d := dir; ; d = filepath.Dir(d) {
		fi, err := os.Stat(d)
		if err != nil || fi.Mode().Perm()&0o001 == 0 {
			return false
		}
		if filepath.Dir(d) == d {
			return true
		}
	}
}

// approveAll answers every confirmation form with an approval and keeps the
// forms it was shown.
func approveAll(asked *[]string) *mcp.ClientOptions {
	return &mcp.ClientOptions{ElicitationHandler: func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		*asked = append(*asked, req.Params.Message)
		return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approve": true}}, nil
	}}
}

// Under /etc, readonly reads only what every user may read. A file whose own
// mode lets everyone read it is still private when a directory above it keeps
// other users out, as systemd's credential store keeps 0644 files in a 0700
// directory. Logs are read whatever their mode, and a profile that names a
// path itself reads it anyway.
func TestReadCheckClosedDirectory(t *testing.T) {
	ro, _ := NewPolicy("readonly")
	for _, c := range []struct {
		path string
		perm os.FileMode
		open bool
		ok   bool
	}{
		{"/etc/nginx/nginx.conf", 0o644, true, true},
		{"/etc/app/settings.conf", 0o644, false, false},
		{"/etc/app/settings.conf", 0o640, false, false},
		{"/var/log/private/app.log", 0o600, false, true},
		{"C:/Windows/System32/drivers/etc/hosts", 0o666, true, true},
	} {
		err := ro.ReadCheck(c.path)(c.path, c.perm, c.open)
		if (err == nil) != c.ok {
			t.Errorf("%s mode %04o, directories open %v: %v", c.path, c.perm, c.open, err)
		}
		if err != nil && !strings.Contains(err.Error(), "not readable by every user") {
			t.Errorf("%s: %v", c.path, err)
		}
	}
	err := ro.ReadCheck("/etc/app/settings.conf")("/etc/app/settings.conf", 0o644, false)
	if err == nil || !strings.Contains(err.Error(), "a directory above it keeps other users out") {
		t.Errorf("the refusal should say why: %v", err)
	}
	own := mustPol(t, ProfileConfig{ReadPaths: []string{"/etc/app/**"}})
	if err := own.ReadCheck("/etc/app/settings.conf")("/etc/app/settings.conf", 0o644, false); err != nil {
		t.Errorf("a path the profile names: %v", err)
	}
}

// A path the built-in rules read whatever its mode, such as a log, is also
// judged where a link leads: a link from /var/log to a file under /etc
// reaches only what /etc itself would show, also through the names macOS
// gives /etc. A path the profile names itself reads its link's target
// whatever its mode only where the profile names the target too.
func TestReadCheckLinkIntoEtc(t *testing.T) {
	ro, _ := NewPolicy("readonly")
	for _, real := range []string{"/etc/app/config.json", "/private/etc/app/config.json", "/System/Volumes/Data/private/etc/app/config.json"} {
		if err := ro.ReadCheck("/var/log/app.log")(real, 0o640, true); err == nil || !strings.Contains(err.Error(), "not readable by every user") {
			t.Errorf("a log linked to an owner-only %s: %v", real, err)
		}
		if err := ro.ReadCheck("/var/log/app.log")(real, 0o644, false); err == nil {
			t.Errorf("a log linked to %s in a closed directory passed", real)
		}
		if err := ro.ReadCheck("/var/log/app.log")(real, 0o644, true); err != nil {
			t.Errorf("a log linked to a world-readable %s: %v", real, err)
		}
	}
	if err := ro.ReadCheck("/var/log/app.log")("/var/log/old/app.log.1", 0o600, false); err != nil {
		t.Errorf("a log linked to another log: %v", err)
	}
	own := mustPol(t, ProfileConfig{ReadPaths: []string{"/srv/app/**"}})
	if err := own.ReadCheck("/srv/app/config.json")("/etc/app/config.json", 0o640, true); err == nil || !strings.Contains(err.Error(), "not readable by every user") {
		t.Errorf("a path the profile names, linked to an owner-only file under /etc: %v", err)
	}
	if err := own.ReadCheck("/srv/app/config.json")("/etc/app/config.json", 0o644, true); err != nil {
		t.Errorf("a path the profile names, linked to a world-readable file under /etc: %v", err)
	}
	if err := own.ReadCheck("/srv/app/config.json")("/srv/app/shared/config.json", 0o600, false); err != nil {
		t.Errorf("a path the profile names, linked to another it names: %v", err)
	}
	both := mustPol(t, ProfileConfig{ReadPaths: []string{"/srv/app/**", "/etc/app/**"}})
	if err := both.ReadCheck("/srv/app/config.json")("/etc/app/config.json", 0o640, true); err != nil {
		t.Errorf("a path the profile names, linked to an owner-only file it names too: %v", err)
	}
}

// A link under a readable tree that leads out of every path the profile may
// read reaches only a file every user may read: a log a service account
// links to /root reads nothing private. A profile that lists /var/log again
// does not lift the check on a log that links into /etc, and macOS's names
// for /var/log, where the agent resolves it, are still inside it.
func TestReadCheckLinkLeavingReadablePaths(t *testing.T) {
	ro, _ := NewPolicy("readonly")
	for _, c := range []struct {
		real string
		perm os.FileMode
		open bool
		ok   bool
	}{
		{"/root/notes.txt", 0o600, false, false},
		{"/home/alice/private/plan.txt", 0o644, false, false},
		{"/var/lib/app/state.db", 0o640, true, false},
		{"/srv/app/config.yml", 0o644, true, true},
		{"/var/log/app/app.log.1", 0o600, false, true},
		{"/private/var/log/app/app.log", 0o600, false, true},
		{"/System/Volumes/Data/private/var/log/app/app.log", 0o600, false, true},
		{"/private/var/root/notes.txt", 0o600, false, false},
	} {
		err := ro.ReadCheck("/var/log/app/link.log")(c.real, c.perm, c.open)
		if (err == nil) != c.ok {
			t.Errorf("/var/log/app/link.log -> %s mode %04o, directories open %v: %v", c.real, c.perm, c.open, err)
		}
		if err != nil && !strings.Contains(err.Error(), "not readable by every user") {
			t.Errorf("%s: %v", c.real, err)
		}
	}
	if err := ro.ReadCheck("/var/log/app/link.log")("/root/notes.txt", 0o600, true); err == nil || !strings.Contains(err.Error(), "leads out of the paths") {
		t.Errorf("the refusal should say the link leads out: %v", err)
	}
	// On macOS the agent reports /var/log as /private/var/log.
	if err := ro.ReadCheck("/var/log/system.log")("/private/var/log/system.log", 0o640, true); err != nil {
		t.Errorf("a log under the name macOS resolves it to: %v", err)
	}
	relisted := mustPol(t, ProfileConfig{ReadPaths: []string{"/var/log/**", "/srv/app/**"}})
	if err := relisted.ReadCheck("/var/log/app/x.log")("/etc/app/owner.conf", 0o600, true); err == nil {
		t.Error("a profile that lists /var/log again read a log linked to an owner-only file under /etc")
	}
	if err := relisted.ReadCheck("/var/log/app/x.log")("/var/log/app/x.log", 0o600, false); err != nil {
		t.Errorf("a log the profile lists: %v", err)
	}
}

// End to end, a log linked to an owner-only file outside every readable path
// reads nothing of it, while one linked to a file every user may read reads.
func TestLogLinkLeavingReadablePathsEndToEnd(t *testing.T) {
	a := newStackAgent(t)
	base := openTempDir(t)
	logs, private, public := filepath.Join(base, "log"), filepath.Join(base, "private"), filepath.Join(base, "public")
	for _, d := range []string{logs, private, public} {
		os.MkdirAll(d, 0o755)
		os.Chmod(d, 0o755)
	}
	os.WriteFile(filepath.Join(private, "notes.txt"), []byte("owner-only note: not-a-real-value\n"), 0o600)
	os.WriteFile(filepath.Join(public, "motd"), []byte("hello\n"), 0o644)
	os.Chmod(filepath.Join(public, "motd"), 0o644)
	os.Chmod(private, 0o700) // as /root is
	os.Symlink(filepath.Join(private, "notes.txt"), filepath.Join(logs, "svc.log"))
	os.Symlink(filepath.Join(public, "motd"), filepath.Join(logs, "motd.log"))
	srv, _ := stackServer(t, a, ProfileConfig{}, func(c *Config) {
		// logs stands in for /var/log: a built-in tree read whatever the mode.
		p := c.Targets[0].Policy
		p.readAllow = append(slices.Clone(p.readAllow), logs+"/**")
	})
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	if why := call(t, cs, "read_file", map[string]any{"path": filepath.Join(logs, "svc.log")}, nil, true); !strings.Contains(why, "not readable by every user") || strings.Contains(why, "not-a-real-value") {
		t.Errorf("a log linked to an owner-only file outside: %s", why)
	}
	var r ReadOutput
	call(t, cs, "read_file", map[string]any{"path": filepath.Join(logs, "motd.log")}, &r, false)
	if r.Content != "hello\n" {
		t.Errorf("a log linked to a world-readable file outside = %q", r.Content)
	}
}

// End to end, the agent reports whether every directory above a file lets
// every user search it, and read_file and download refuse a world-readable
// file in a closed directory before any of it moves, as they refuse a link
// from a log into a file only its owner may read.
func TestReadCheckClosedDirectoryEndToEnd(t *testing.T) {
	a := newStackAgent(t)
	base := openTempDir(t)
	etc, logs, ws := filepath.Join(base, "etc"), filepath.Join(base, "log"), t.TempDir()
	closed := filepath.Join(etc, "private")
	os.MkdirAll(closed, 0o755)
	os.MkdirAll(logs, 0o755)
	os.Chmod(etc, 0o755) // whatever the umask
	os.Chmod(logs, 0o755)
	write := func(p, content string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		os.Chmod(p, mode)
	}
	write(filepath.Join(etc, "app.conf"), "listen 80\n", 0o644)
	write(filepath.Join(closed, "db.conf"), "dbpass not-a-real-one\n", 0o644)
	write(filepath.Join(etc, "owner.conf"), "bindpw not-a-real-one\n", 0o640)
	write(filepath.Join(logs, "plain.log"), "started\n", 0o600)
	os.Symlink(filepath.Join(etc, "owner.conf"), filepath.Join(logs, "app.log"))
	os.Chmod(closed, 0o700) // as systemd asks of its credential store
	srv, _ := stackServer(t, a, ProfileConfig{}, func(c *Config) {
		// etc and log stand in for /etc and /var/log under readonly.
		p := c.Targets[0].Policy
		p.readAllow = append(slices.Clone(p.readAllow), etc+"/**", logs+"/**")
		p.worldOnly = []string{etc + "/**"}
		c.Workspace = ws
	})
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	var r ReadOutput
	call(t, cs, "read_file", map[string]any{"path": filepath.Join(etc, "app.conf")}, &r, false)
	if r.Content != "listen 80\n" {
		t.Errorf("read_file of a file every user may read = %q", r.Content)
	}
	call(t, cs, "read_file", map[string]any{"path": filepath.Join(logs, "plain.log")}, &r, false)
	if r.Content != "started\n" {
		t.Errorf("read_file of an owner-only log = %q", r.Content)
	}
	db := filepath.Join(closed, "db.conf")
	if why := call(t, cs, "read_file", map[string]any{"path": db}, nil, true); !strings.Contains(why, "keeps other users out") || strings.Contains(why, "not-a-real-one") {
		t.Errorf("read_file of a 0644 file in a 0700 directory: %s", why)
	}
	if why := call(t, cs, "download", map[string]any{"remote": db, "local": "db.conf"}, nil, true); !strings.Contains(why, "keeps other users out") {
		t.Errorf("download of a 0644 file in a 0700 directory: %s", why)
	}
	if names, _ := os.ReadDir(ws); len(names) != 0 {
		t.Errorf("a refused download left %v in the workspace", names)
	}
	if why := call(t, cs, "read_file", map[string]any{"path": filepath.Join(logs, "app.log")}, nil, true); !strings.Contains(why, "not readable by every user") || strings.Contains(why, "not-a-real-one") {
		t.Errorf("read_file of a log linked to an owner-only file: %s", why)
	}
	// The directory decides: opened to all, the same file reads.
	os.Chmod(closed, 0o755)
	call(t, cs, "read_file", map[string]any{"path": db}, &r, false)
	if !strings.Contains(r.Content, "dbpass") {
		t.Errorf("read_file once the directory is open = %q", r.Content)
	}
}

// systemd's credential stores, in each directory LoadCredential= searches and
// their .encrypted twins, are secret paths, as its runtime credentials are,
// so readonly on a root ternd does not read them whatever their mode.
func TestSystemdCredentialStoresSecret(t *testing.T) {
	ro, _ := NewPolicy("readonly")
	all := mustPol(t, ProfileConfig{ReadPaths: []string{"/**"}, WritePaths: []string{"/**"}})
	for _, p := range []string{"/etc/credstore/mysql.password", "/etc/credstore.encrypted/db", "/run/credstore/token",
		"/run/credstore.encrypted/x", "/usr/lib/credstore/x", "/usr/lib/credstore.encrypted/x",
		"/usr/local/lib/credstore/x", "/run/credentials/app.service/db", "/var/lib/systemd/credential.secret"} {
		if _, ok, why := all.CheckRead(p); ok || !strings.Contains(why, "secret-path rule") {
			t.Errorf("CheckRead(%q) = %v, %q", p, ok, why)
		}
		if _, ok, _ := all.CheckWrite(p); ok {
			t.Errorf("CheckWrite(%q) passed", p)
		}
	}
	if _, ok, _ := ro.CheckRead("/etc/credstore/mysql.password"); ok {
		t.Error("readonly reads /etc/credstore")
	}
	if err := ro.CheckReal("/etc/credstore/mysql.password"); err == nil {
		t.Error("a link into /etc/credstore passed")
	}
}

// macOS mounts its Data volume at /System/Volumes/Data and firmlinks it into
// the root, so /System/Volumes/Data/private/etc/sudoers is /etc/sudoers and
// /System/Volumes/Data/Library/LaunchDaemons is /Library/LaunchDaemons. A
// firmlink is not a symbolic link, so the agent may report either spelling:
// the rules anchored at /etc, /var, /Library or /usr/local hold under both,
// in any case. /.vol paths, which open a file by inode number, are refused.
func TestMacDataVolumeNames(t *testing.T) {
	p := mustPol(t, ProfileConfig{ReadPaths: []string{"/**"}, WritePaths: []string{"/**"}})
	reads := []string{"/private/etc/master.passwd", "/private/etc/kcpassword", "/private/etc/sudoers",
		"/private/etc/ssh/ssh_host_ed25519_key", "/private/etc/sudoers.d/admin", "/private/etc/postfix/sasl_passwd"}
	writes := []string{"/Library/LaunchDaemons/com.x.plist", "/Library/StartupItems/x/x", "/private/etc/sudoers.d/x",
		"/private/etc/pam.d/sudo", "/private/etc/periodic/daily/999.x", "/private/var/at/tabs/root", "/private/etc/zshrc",
		"/private/etc/paths.d/x", "/private/etc/ssh/sshd_config", "/private/etc/profile", "/usr/local/etc/doas.conf"}
	for _, d := range []string{"/System/Volumes/Data", "/system/volumes/data", "/SYSTEM/Volumes/DATA"} {
		for _, s := range reads {
			alias := d + s
			if _, ok, why := p.CheckRead(alias); ok || !strings.Contains(why, "secret-path rule") {
				t.Errorf("CheckRead(%q) = %v, %q", alias, ok, why)
			}
			if err := p.CheckReal(alias); err == nil {
				t.Errorf("CheckReal(%q) passed", alias)
			}
		}
		for _, s := range writes {
			alias := d + s
			if _, ok, why := p.CheckWrite(alias); ok || !strings.Contains(why, "rule") {
				t.Errorf("CheckWrite(%q) = %v, %q", alias, ok, why)
			}
			if err := p.CheckRealWrite(alias); err == nil {
				t.Errorf("CheckRealWrite(%q) passed", alias)
			}
		}
	}
	// The worldOnly rule for /etc sees through the Data volume too.
	ro, _ := NewPolicy("readonly")
	if err := ro.ReadCheck("/etc/app.conf")("/System/Volumes/Data/private/etc/app.conf", 0o640, true); err == nil {
		t.Error("an owner-only /etc file reported under the Data volume passed")
	}
	// Ordinary files on the Data volume stay writable, and a directory whose
	// name only starts like the mount point is not taken for it.
	for _, s := range []string{"/System/Volumes/Data/Users/u/project/main.go", "/System/Volumes/Datastore/private/etc/sudoers.d/x"} {
		if _, ok, why := p.CheckWrite(s); !ok {
			t.Errorf("CheckWrite(%q) refused: %s", s, why)
		}
	}
	for _, v := range []string{"/.vol/16777231/1234567", "/.VOL/16777231/2", "/private/../.vol/1/2"} {
		if _, ok, why := p.CheckRead(v); ok || !strings.Contains(why, "inode") {
			t.Errorf("CheckRead(%q) = %v, %q", v, ok, why)
		}
		if err := p.CheckReal(v); err == nil {
			t.Errorf("CheckReal(%q) passed", v)
		}
	}
}

// An approval is used once for its whole life, its last second included: a
// spent nonce is kept until its state has expired by the same whole-second
// test that refuses an expired state, and is forgotten after that.
func TestConfirmUsedOnceToTheEnd(t *testing.T) {
	c := newConfirmer()
	cur := time.Unix(1_800_000_000, 400_000_000) // part way into a second, as a real clock is
	c.now = func() time.Time { return cur }
	act := actionKey("run", "web1", map[string]any{"argv": []string{"systemctl", "restart", "nginx"}})
	state := c.request(act, "msg").RequestState
	if st, why := c.check(act, retry(state, "accept", true)); st != confirmApproved {
		t.Fatalf("first use: %v %s", st, why)
	}
	exp := cur.Add(confirmTTL).Unix()
	for _, at := range []time.Time{time.Unix(exp-1, 900_000_000), time.Unix(exp, 0), time.Unix(exp, 500_000_000),
		time.Unix(exp, 999_999_999), time.Unix(exp+1, 0)} {
		cur = at
		if st, why := c.check(act, retry(state, "accept", true)); st != confirmRejected {
			t.Errorf("used again at %s, %d ns into the second of its expiry %d: %q", at.UTC().Format(time.TimeOnly), at.Nanosecond(), exp, why)
		}
	}
	// Past its expiry the spent nonce is dropped at the next answer.
	cur = time.Unix(exp+60, 0)
	if st, why := c.check(act, retry(c.request(act, "msg").RequestState, "accept", true)); st != confirmApproved {
		t.Fatalf("a fresh approval: %v %s", st, why)
	}
	c.mu.Lock()
	n := len(c.used)
	c.mu.Unlock()
	if n != 1 {
		t.Errorf("%d spent nonces kept, want only the fresh one", n)
	}
}

// A mode of 0 is refused: the agent takes a zero mode as none given and
// creates the file 0644, the opposite of the 0000 a form would show.
func TestWriteModeZeroRefused(t *testing.T) {
	for _, m := range []string{"0", "00", "000", "0000"} {
		if mode, why := parseMode(m); !strings.Contains(why, "mode 0000") {
			t.Errorf("parseMode(%q) = %04o, %q", m, mode, why)
		}
	}
	for m, want := range map[string]os.FileMode{"": 0o644, "0600": 0o600, "1": 0o001, "0777": 0o777} {
		if mode, why := parseMode(m); mode != want || why != "" {
			t.Errorf("parseMode(%q) = %04o, %q", m, mode, why)
		}
	}
	a := newStackAgent(t)
	ws, remote := t.TempDir(), t.TempDir()
	srv, _ := stackServer(t, a, ProfileConfig{WritePaths: []string{remote + "/**"}, Confirm: []string{"write_file"}},
		func(c *Config) { c.Workspace = ws })
	defer srv.Close()
	var asked []string
	cs := stackClient(t, srv, "", approveAll(&asked))
	for _, m := range []string{"0", "0000"} {
		p := filepath.Join(remote, "private"+m)
		if why := call(t, cs, "write_file", map[string]any{"path": p, "content": "fake-key\n", "mode": m}, nil, true); !strings.Contains(why, "mode 0000") {
			t.Errorf("write_file with mode %q: %s", m, why)
		}
		if _, err := os.Stat(p); err == nil {
			t.Errorf("mode %q created %s", m, p)
		}
	}
	if len(asked) != 0 {
		t.Errorf("the user was asked about a write that cannot happen as shown: %q", asked)
	}
	// A local file with no permission bits is refused the same way, where
	// tern mcp can read it at all (as root).
	locked := filepath.Join(ws, "locked")
	os.WriteFile(locked, []byte("fake-key\n"), 0o600)
	os.Chmod(locked, 0)
	why := call(t, cs, "upload", map[string]any{"local": "locked", "remote": remote + "/locked"}, nil, true)
	if os.Geteuid() == 0 && !strings.Contains(why, "mode 0000") {
		t.Errorf("upload of a mode 0000 file: %s", why)
	}
	if _, err := os.Stat(filepath.Join(remote, "locked")); err == nil {
		t.Error("a mode 0000 file was uploaded")
	}
}

// Content that is not UTF-8 is previewed as text all the same, each byte that
// is not part of a character as \xNN, and the form says it is binary: one
// stray byte in a comment cannot hide what a script will run.
func TestBinaryContentPreviewed(t *testing.T) {
	script := "#!/bin/sh\necho hidden-payload-would-run\n# \xff\n"
	got := preview("Content", []byte(script))
	for _, want := range []string{fmt.Sprintf("all %d bytes, BINARY", len(script)), "  | #!/bin/sh\n", "  | echo hidden-payload-would-run\n", `  | # \xff` + "\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("the preview lacks %q:\n%s", want, got)
		}
	}
	big := bytes.Repeat([]byte{0x80}, 2*maxPreview)
	got = preview("Content", big)
	if !strings.Contains(got, fmt.Sprintf("ONLY THE FIRST %d OF %d BYTES, BINARY", maxPreview, len(big))) || strings.Count(got, `\x80`) != maxPreview {
		t.Errorf("a long binary preview:\n%s", got)
	}
	// A character cut by the preview's end is left out whole, not shown in bytes.
	odd := append(bytes.Repeat([]byte("a"), maxPreview-1), "é\xff"...)
	if got := preview("Content", odd); strings.Contains(got, `\xc3`) || !strings.Contains(got, fmt.Sprintf("FIRST %d OF", maxPreview-1)) {
		t.Errorf("a preview ending inside a character:\n%s", got)
	}

	a := newStackAgent(t)
	remote := t.TempDir()
	srv, _ := stackServer(t, a, ProfileConfig{WritePaths: []string{remote + "/**"}, Confirm: []string{"write_file"}}, nil)
	defer srv.Close()
	var asked []string
	cs := stackClient(t, srv, "", approveAll(&asked))
	call(t, cs, "write_file", map[string]any{"path": remote + "/deploy.sh", "content": base64.StdEncoding.EncodeToString([]byte(script)),
		"encoding": "base64", "mode": "0755"}, nil, false)
	if len(asked) != 1 || !strings.Contains(asked[0], "  | echo hidden-payload-would-run") || !strings.Contains(asked[0], "BINARY") {
		t.Errorf("the form the user approved: %q", asked)
	}
}

// The workspace side of upload and download has the agent side's rules: a
// local key is never uploaded, and a download never creates a local login
// file, SSH file or autostart entry, also through a link inside the
// workspace. Ordinary files still move both ways.
func TestWorkspaceSideRules(t *testing.T) {
	a := newStackAgent(t)
	home, remote := t.TempDir(), t.TempDir()
	os.MkdirAll(filepath.Join(home, ".ssh"), 0o700)
	os.MkdirAll(filepath.Join(home, ".config"), 0o700)
	const key = "-----FAKE OPENSSH PRIVATE KEY for a test-----\n"
	os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519"), []byte(key), 0o600)
	os.Symlink(".ssh", filepath.Join(home, "keys"))
	os.Symlink(".config", filepath.Join(home, "conf"))
	os.WriteFile(filepath.Join(home, "notes.txt"), []byte("notes\n"), 0o644)
	os.WriteFile(filepath.Join(remote, "payload"), []byte("echo a-login-hook\n"), 0o644)
	srv, _ := stackServer(t, a, ProfileConfig{ReadPaths: []string{remote + "/**"}, WritePaths: []string{remote + "/**"}},
		func(c *Config) { c.Workspace = home })
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	for _, local := range []string{".ssh/id_ed25519", "keys/id_ed25519", ".SSH/id_ed25519"} {
		if why := call(t, cs, "upload", map[string]any{"local": local, "remote": remote + "/exfil"}, nil, true); !strings.Contains(why, "secret-path rule") {
			t.Errorf("upload of %s: %s", local, why)
		}
	}
	if _, err := os.Stat(filepath.Join(remote, "exfil")); err == nil {
		t.Error("a local key reached the agent")
	}
	for _, local := range []string{".zshenv", ".ssh/authorized_keys", ".config/autostart/x.desktop", "conf/autostart/y.desktop",
		".local/bin/ls", "project/.git/hooks/pre-commit"} {
		if why := call(t, cs, "download", map[string]any{"remote": remote + "/payload", "local": local}, nil, true); !strings.Contains(why, "rule") || !strings.Contains(why, "never creates") {
			t.Errorf("download to %s: %s", local, why)
		}
		if _, err := os.Lstat(filepath.Join(home, local)); err == nil {
			t.Errorf("download created %s", local)
		}
	}
	if _, err := os.Stat(filepath.Join(home, ".config", "autostart")); err == nil {
		t.Error("a refused download made its directory")
	}
	call(t, cs, "upload", map[string]any{"local": "notes.txt", "remote": remote + "/notes.txt"}, nil, false)
	call(t, cs, "download", map[string]any{"remote": remote + "/payload", "local": "work/payload.sh"}, nil, false)
	if b, _ := os.ReadFile(filepath.Join(home, "work", "payload.sh")); string(b) != "echo a-login-hook\n" {
		t.Errorf("an ordinary download = %q", b)
	}
}

// A workspace that a rule holding in it matches as a whole is refused at
// startup with the rule named: in a credential store such as ~/.ssh, a
// directory named for tokens, or tern's own state directory, every file is a
// secret the model must never upload; in a place such as ~/.config/autostart
// every file it downloaded would run code. Through a link into such a place
// too, before anything is created.
func TestWorkspaceMatchedByARuleRefused(t *testing.T) {
	a := newStackAgent(t)
	base := t.TempDir()
	state := filepath.Join(base, "xdg-state", "tern")
	os.MkdirAll(filepath.Join(base, "home", ".ssh"), 0o700)
	os.Symlink(filepath.Join(base, "home", ".ssh"), filepath.Join(base, "keys"))
	newServer := func(ws string) error {
		pols, _ := BuildPolicies(nil)
		srv, err := New(Config{Version: "test", AuditPath: filepath.Join(t.TempDir(), "audit.jsonl"), Workspace: ws,
			TernDirs: []string{state}, Targets: []TargetSpec{{Target: Target{Name: "box"}, Policy: pols["readonly"], Dial: a.dial}}})
		if err == nil {
			srv.Close()
		}
		return err
	}
	for _, c := range []struct{ ws, rule string }{
		{filepath.Join(base, "home", ".ssh"), `secret-path rule "**/.ssh/**"`},
		{filepath.Join(base, "home", ".ssh", "work"), `secret-path rule "**/.ssh/**"`},
		{filepath.Join(base, "keys"), `secret-path rule "**/.ssh/**"`},
		{filepath.Join(base, "keys", "new"), `secret-path rule "**/.ssh/**"`},
		{filepath.Join(base, "tokenizer-work"), `secret-path rule "**/*token*/**"`},
		{filepath.Join(base, "home", ".config", "autostart"), `persistence-point rule "**/.config/autostart/**"`},
		{filepath.Join(base, "home", ".local", "state", "tern"), `secret-path rule "**/.local/state/tern/**"`},
		{filepath.Join(base, "home", ".claude", "work"), `secret-path rule "**/.claude/**"`},
		{filepath.Join(base, "home", "src", ".vscode"), `persistence-point rule "**/.vscode/**"`},
		{filepath.Join(state, "work"), "for tern's own files"},
	} {
		err := newServer(c.ws)
		if err == nil || !strings.Contains(err.Error(), c.rule) || !strings.Contains(err.Error(), "choose another directory") {
			t.Errorf("workspace %s: %v", c.ws, err)
		}
	}
	for _, d := range []string{filepath.Join(base, "home", ".ssh", "work"), filepath.Join(base, "home", ".ssh", "new"),
		filepath.Join(base, "home", ".config"), filepath.Join(state, "work")} {
		if _, err := os.Lstat(d); err == nil {
			t.Errorf("a refused workspace made %s", d)
		}
	}
	for _, ws := range []string{filepath.Join(base, "home"), filepath.Join(base, "home", "tern-work"), filepath.Join(base, "xdg-state")} {
		if err := newServer(ws); err != nil {
			t.Errorf("workspace %s: %v", ws, err)
		}
	}
}

// A download creates nothing through a link that leads to no directory yet:
// the rules judged the link's own name, so a link named innocently that
// points at a ~/.config not made yet would otherwise let a download make
// ~/.config/autostart/x.desktop. A link at the new file's own name is a name
// that exists, which a download never replaces, and a link to a directory
// that exists still takes a download where the rules saw it land.
func TestDownloadThroughDanglingLink(t *testing.T) {
	a := newStackAgent(t)
	remote := t.TempDir()
	os.WriteFile(filepath.Join(remote, "payload"), []byte("[Desktop Entry]\nExec=sh -c 'echo planted'\n"), 0o644)
	for _, c := range []struct{ link, target, local, lands string }{
		{"cfg", ".config", "cfg/autostart/evil.desktop", ".config/autostart/evil.desktop"},
		{"vimfiles", ".vim", "vimfiles/plugin/evil.vim", ".vim/plugin/evil.vim"},
		{"units", ".config/systemd", "units/user/evil.service", ".config/systemd/user/evil.service"},
		{"lnk", "sub/../.config/autostart", "lnk/evil.desktop", ".config/autostart/evil.desktop"},
		{"out", "build/out", "out/file.txt", "build/out/file.txt"},
		{"rc", ".bashrc", "rc", ".bashrc"},
	} {
		home := t.TempDir()
		if err := os.Symlink(c.target, filepath.Join(home, c.link)); err != nil {
			t.Fatal(err)
		}
		srv, _ := stackServer(t, a, ProfileConfig{ReadPaths: []string{remote + "/**"}}, func(cf *Config) { cf.Workspace = home })
		cs := stackClient(t, srv, "", nil)
		why := call(t, cs, "download", map[string]any{"remote": remote + "/payload", "local": c.local}, nil, true)
		if _, err := os.Lstat(filepath.Join(home, c.lands)); err == nil {
			t.Errorf("download to %s (link %s -> %s) created %s", c.local, c.link, c.target, c.lands)
		}
		if target, err := os.Readlink(filepath.Join(home, c.link)); err != nil || target != c.target {
			t.Errorf("download to %s changed the link %s: %q, %v", c.local, c.link, target, err)
		}
		t.Logf("download to %s: %s", c.local, why)
		srv.Close()
	}
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, "data", "in"), 0o700)
	os.Symlink(filepath.Join("data", "in"), filepath.Join(home, "inbox"))
	os.Symlink(filepath.Join("data", "in"), filepath.Join(home, "drop"))
	srv, _ := stackServer(t, a, ProfileConfig{ReadPaths: []string{remote + "/**"}}, func(cf *Config) { cf.Workspace = home })
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	call(t, cs, "download", map[string]any{"remote": remote + "/payload", "local": "inbox/new/x.txt"}, nil, false)
	if _, err := os.Stat(filepath.Join(home, "data", "in", "new", "x.txt")); err != nil {
		t.Errorf("a download through a link to a directory that exists: %v", err)
	}
	if why := call(t, cs, "download", map[string]any{"remote": remote + "/payload", "local": "drop"}, nil, true); !strings.Contains(why, "already exists") {
		t.Errorf("a download onto a link to a directory: %s", why)
	}
}

// tern's own directories match as the names they are, wildcard characters
// in them included, and under the name their links resolve to.
func TestTernDirRulesMatchLiterally(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix path names")
	}
	base := t.TempDir()
	odd := filepath.Join(base, `st*te[1]?\x`, "tern")
	os.MkdirAll(filepath.Join(base, "real"), 0o700)
	os.Symlink(filepath.Join(base, "real"), filepath.Join(base, "lnk"))
	rules := treeRules([]string{odd, filepath.Join(base, "lnk", "tern"), "relative/tern"})
	for _, p := range []string{filepath.Join(odd, "mcp-ptys-x.json"), filepath.Join(odd, "a", "b"),
		filepath.Join(base, "lnk", "tern", "x"), filepath.Join(base, "real", "tern", "x")} {
		if matchRule(rules, localKey(p)) == "" {
			t.Errorf("%s matches none of %q", p, rules)
		}
	}
	for _, p := range []string{filepath.Join(base, "stXte1Y\\x", "tern", "x"), filepath.Join(base, "stte1x", "tern", "x"),
		filepath.Join(base, "real", "terns", "x"), filepath.Join(base, "relative", "tern", "x")} {
		if r := matchRule(rules, localKey(p)); r != "" {
			t.Errorf("%s matches %q", p, r)
		}
	}
}

// A workspace in a credential store would hand the model its keys: the
// server never starts, so nothing in it is uploaded.
func TestWorkspaceInsideSSHDirectoryUploadsNothing(t *testing.T) {
	a := newStackAgent(t)
	remote := t.TempDir()
	ws := filepath.Join(t.TempDir(), "home", ".ssh")
	os.MkdirAll(ws, 0o700)
	os.WriteFile(filepath.Join(ws, "id_ed25519"), []byte("-----FAKE OPENSSH PRIVATE KEY for a test-----\n"), 0o600)
	pols, _ := BuildPolicies(map[string]ProfileConfig{"p": {WritePaths: []string{remote + "/**"}}})
	srv, err := New(Config{Version: "test", AuditPath: filepath.Join(t.TempDir(), "audit.jsonl"), Workspace: ws,
		Targets: []TargetSpec{{Target: Target{Name: "box"}, Policy: pols["p"], Dial: a.dial}}})
	if err == nil {
		defer srv.Close()
		cs := stackClient(t, srv, "", nil)
		res, _ := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "upload", Arguments: map[string]any{"local": "id_ed25519", "remote": remote + "/id_ed25519"}})
		t.Errorf("a server with its workspace in ~/.ssh started; upload: %v", res)
	}
	if b, err := os.ReadFile(filepath.Join(remote, "id_ed25519")); err == nil {
		t.Errorf("the key reached the agent: %q", b)
	}
}

// Persistence points: directories on PATH, Python's startup files, editors'
// and multiplexers' startup files, git hooks and config in bare
// repositories, submodules and hooksPath directories,
// package-manager, boot-loader and network hooks, and on Windows the per-user
// WindowsApps directory on PATH, Office's startup folders and templates, and
// PowerShell's module directories, also in Program Files. Ordinary files
// beside them stay writable.
func TestPathAndHookPersistencePoints(t *testing.T) {
	home := mustPol(t, ProfileConfig{WritePaths: []string{"/home/**", "/srv/**", "/Users/**", "/c:/users/**", "/c:/program files/**", "/c:/windows/**"}})
	root := mustPol(t, ProfileConfig{WritePaths: []string{"/**"}})
	for _, c := range []struct {
		p    *Policy
		path string
	}{
		{home, "/home/u/bin/sudo"}, {home, "/home/u/.cargo/bin/git"}, {home, "/home/u/.local/lib/python3.12/site-packages/x.pth"},
		{home, "/home/u/.local/lib/python3.12/site-packages/usercustomize.py"}, {home, "/home/u/.gitconfig.local"},
		{home, "/srv/git/site.git/hooks/post-receive"}, {home, "/srv/git/site.git/config"},
		{home, "/srv/app/.git/modules/lib/hooks/post-checkout"}, {home, "/srv/app/.git/modules/lib/config"},
		{home, "/srv/app/.husky/pre-commit"}, {home, "/srv/app/.githooks/pre-commit"},
		{home, "/home/u/.local/share/applications/firefox.desktop"}, {home, "/home/u/.config/plasma-workspace/env/x.sh"},
		{home, "/home/u/.forward"}, {home, "/home/u/.oh-my-zsh/custom/x.zsh"}, {home, "/home/u/.p10k.zsh"},
		{home, "/home/u/.config/starship.toml"}, {home, "/home/u/.vimrc"}, {home, "/home/u/.vim/plugin/x.vim"},
		{home, "/home/u/.config/nvim/init.lua"}, {home, "/home/u/.emacs.d/init.el"}, {home, "/home/u/.tmux.conf"},
		{home, "/home/u/.gradle/init.d/x.gradle"}, {home, "/home/u/.cargo/config.toml"}, {home, "/Users/u/bin/git"},
		{home, `C:\Users\u\AppData\Local\Microsoft\WindowsApps\python.exe`},
		{home, `C:\Users\u\AppData\Local\Microsoft\WindowsApps\code.cmd`},
		{home, `C:\Users\u\AppData\Roaming\Microsoft\Templates\Normal.dotm`},
		{home, `C:\Users\u\AppData\Roaming\Microsoft\Excel\XLSTART\book.xlsm`},
		{home, `C:\Users\u\AppData\Roaming\Microsoft\Word\STARTUP\macros.dotm`},
		{home, `C:\Users\u\Documents\WindowsPowerShell\Modules\Evil\Evil.psm1`},
		{home, `C:\Users\u\Documents\PowerShell\Modules\Evil\Evil.psm1`},
		{home, `C:\Program Files\WindowsPowerShell\Modules\Evil\Evil.psm1`},
		{home, `C:\Program Files\PowerShell\7\Modules\Evil\Evil.psm1`},
		{home, `C:\Windows\System32\WindowsPowerShell\v1.0\Modules\Evil\Evil.psm1`},
		{home, `C:\Program Files\Microsoft Office\root\Office16\XLSTART\book.xlsm`},
		{home, `C:\Program Files\Microsoft Office\root\Office16\STARTUP\macros.dotm`},
		{root, "/usr/local/bin/sudo"}, {root, "/opt/homebrew/bin/sudo"}, {root, "/usr/bin/sudo"}, {root, "/sbin/init"},
		{root, "/usr/lib/python3/dist-packages/x.pth"}, {root, "/etc/gitconfig"}, {root, "/usr/local/etc/gitconfig"},
		{root, "/etc/dpkg/dpkg.cfg.d/x"}, {root, "/etc/needrestart/conf.d/x.conf"}, {root, "/etc/pacman.d/hooks/x.hook"},
		{root, "/etc/apk/commit_hooks.d/x"}, {root, "/etc/network/if-up.d/x"}, {root, "/etc/grub.d/99_x"},
		{root, "/etc/default/grub"}, {root, "/boot/grub/grub.cfg"}, {root, "/etc/tmpfiles.d/x.conf"}, {root, "/etc/subuid"},
		{root, "/usr/share/polkit-1/rules.d/x.rules"}, {root, "/etc/xdg/systemd/user/pipewire.service"},
		{root, "/etc/rsyslog.d/x.conf"}, {root, "/etc/daily.local"}, {root, "/usr/local/etc/sudoers.d/x"},
	} {
		if _, ok, why := c.p.CheckWrite(c.path); ok || !strings.Contains(why, "rule") {
			t.Errorf("CheckWrite(%q) = %v, %q", c.path, ok, why)
		}
	}
	// Through a junction or link, on the path the agent reports.
	for _, real := range []string{`C:\Users\u\AppData\Local\Microsoft\WindowsApps\kubectl.bat`, "/usr/local/bin/git"} {
		if err := root.CheckRealWrite(real); err == nil || !strings.Contains(err.Error(), "persistence-point rule") {
			t.Errorf("CheckRealWrite(%q) = %v", real, err)
		}
	}
	for _, p := range []string{"/srv/app/hooks/x", "/home/u/project/bin/tool", "/srv/app/src/main.py", "/home/u/.config/app/settings.toml",
		"/srv/app/startup/x", `C:\Users\u\Documents\report.docx`, `C:\Users\u\AppData\Local\tool\config.json`} {
		if _, ok, why := home.CheckWrite(p); !ok {
			t.Errorf("CheckWrite(%q) refused: %s", p, why)
		}
	}
}

// Credential stores: installer answers, macOS's local directory and
// keychains, desktop keyrings, command-line tools' tokens and shell
// histories, SSSD's cache, VPN logins, WordPress's database password,
// Terraform state and env files.
func TestKeychainAndAppCredentialStores(t *testing.T) {
	ro, _ := NewPolicy("readonly")
	all := mustPol(t, ProfileConfig{ReadPaths: []string{"/**"}})
	for _, c := range []struct {
		p    *Policy
		path string
	}{
		{ro, "/var/log/installer/autoinstall-user-data"}, {all, "/var/lib/cloud/instances/i-1/user-data.txt"},
		{all, "/var/db/dslocal/nodes/Default/users/admin.plist"}, {all, "/private/var/db/dslocal/nodes/Default/users/admin.plist"},
		{all, "/Library/Keychains/System.keychain"}, {all, "/private/var/db/SystemKey"},
		{all, "/Users/u/Library/Keychains/login.keychain-db"}, {all, "/home/u/.local/share/keyrings/login.keyring"},
		{all, "/home/u/.local/share/kwalletd/kdewallet.kwl"}, {all, "/home/u/.config/gh/hosts.yml"},
		{all, "/home/u/.config/glab-cli/config.yml"}, {all, "/home/u/.s3cfg"}, {all, "/home/u/.boto"},
		{all, "/home/u/.config/doctl/config.yaml"}, {all, "/home/u/.local/share/fish/fish_history"}, {all, "/home/u/.histfile"},
		{all, "/home/u/.zhistory"}, {all, "/home/u/.local/share/atuin/history.db"}, {all, "/var/lib/sss/db/cache_example.com.ldb"},
		{all, "/etc/vpnc/work.conf"}, {all, "/var/www/html/wp-config.php"}, {all, "/srv/infra/terraform.tfstate"},
		{all, "/srv/infra/terraform.tfstate.backup"}, {all, "/srv/infra/prod.tfvars"}, {all, "/srv/app/production.env"},
		{all, "/srv/app/.envrc"}, {all, "/usr/local/etc/sudoers"},
	} {
		if _, ok, why := c.p.CheckRead(c.path); ok || !strings.Contains(why, "secret-path rule") {
			t.Errorf("%s CheckRead(%q) = %v, %q", c.p.Profile, c.path, ok, why)
		}
	}
	for _, p := range []string{"/var/log/installer/syslog", "/srv/app/environment.yml", "/srv/app/README.md", "/var/www/html/index.php"} {
		if _, ok, why := all.CheckRead(p); !ok {
			t.Errorf("CheckRead(%q) refused: %s", p, why)
		}
	}
}

// Programs that run code or other programs are wrappers, which a pattern
// names only with allow_wrappers and confirm_unlisted never offers:
// interpreters and shells, other names of listed ones, programs that run the
// command they are given, version and deployment managers, and Windows
// programs known to run code, also as a variant such as gdb-multiarch.
func TestInterpreterAndManagerWrapperNames(t *testing.T) {
	cu := mustPol(t, ProfileConfig{Run: RunConfig{ConfirmUnlisted: true}})
	for _, name := range []string{
		"gdb-multiarch", "emacs-gtk", "emacs-lucid", "emacs-nox", "scala-cli", "jupyter-console", "pwsh-preview", "lxc-attach",
		"lxc-execute", "kotlinc-jvm", "texlua", "luahbtex", "yarnpkg", "pnpx", "pdb3", "java", "ghc", "raku", "crystal", "bb",
		"mix", "ocaml", "micropython", "bpython", "xonsh", "nu", "elvish", "oksh", "sash", "toybox", "swift", "mlr", "duckdb",
		"sqlcmd", "mysqlsh", "mycli", "usql", "spatialite", "fennel", "resty", "ecl", "rhino", "jbang", "plackup", "rackup",
		"latexmk", "etex", "xetex", "mpost", "eatmydata", "rlwrap", "chronic", "ifne", "pee", "zrun", "lckdo", "mispipe",
		"hyperfine", "rr", "catchsegv", "datefudge", "trickle", "nocache", "zellij", "abduco", "nodemon", "pm2", "foreman",
		"coredumpctl", "busctl", "kak", "nvi", "mise", "asdf", "direnv", "pyenv", "rbenv", "opam", "volta", "fnm", "pixi",
		"rye", "carton", "perlbrew", "nx", "lerna", "concurrently", "prove", "perldoc", "cpan", "cpanm", "gh", "glab", "jj",
		"repo", "ansible", "ansible-playbook", "salt-call", "puppet", "chef-apply", "knife", "helm", "kustomize", "buildah",
		"runc", "crun", "multipass", "vagrant", "limactl", "colima", "minikube", "wp", "drush", "dbclient", "plink",
		"wlrmdr.exe", "tttracer.exe", "winget.exe", "choco.exe", "fsianycpu.exe", "rcsi.exe", "tracker.exe", "mftrace.exe",
		"appvlp.exe", "sqlps.exe", "javaw.exe", "python3-console",
	} {
		if !isWrapper(name) {
			t.Errorf("%s is not a wrapper", name)
			continue
		}
		if d, _ := cu.RunDecision([]string{name, "x"}, false); d != Deny {
			t.Errorf("confirm_unlisted offers %s", name)
		}
		if _, err := BuildPolicies(map[string]ProfileConfig{"p": {Run: RunConfig{Allow: [][]string{{name, "**"}}}}}); err == nil {
			t.Errorf("a pattern names %s without allow_wrappers", name)
		}
	}
	// Variant suffixes make a wrapper only of a wrapper.
	for _, name := range []string{"redis-cli", "aws-cli", "fwupd-console", "gtk-preview", "uptime", "df"} {
		if isWrapper(name) {
			t.Errorf("%s taken for a wrapper", name)
		}
	}
}

// Persistence points: bash's drop-ins and completions, the startup files of
// debuggers, database shells, REPLs and window managers, Kerberos login
// lists, the directories on PATH that language tools add, Outlook's and
// Windows Terminal's code, kubelet's static pods, PAM and NSS modules,
// D-Bus, the initramfs, acpid, display managers, Docker's daemon settings
// and Apache's and nginx's configuration; and on Windows the files directly
// in the system folders on PATH and PowerShell 7's folder. Their subfolders
// that hold data stay writable.
func TestStartupAndSystemPersistencePoints(t *testing.T) {
	home := mustPol(t, ProfileConfig{WritePaths: []string{"/home/**", "/root/**", "/Users/**", "/c:/users/**"}})
	root := mustPol(t, ProfileConfig{WritePaths: []string{"/**", "/c:/**"}})
	for _, c := range []struct {
		p    *Policy
		path string
	}{
		{home, "/home/u/.bashrc.d/x.sh"}, {home, "/home/u/.bash_completion"}, {home, "/home/u/.local/share/bash-completion/completions/git"},
		{home, "/home/u/.config/autostart-scripts/x.sh"}, {home, "/home/u/.gdbinit"}, {home, "/home/u/.config/gdb/gdbinit"},
		{home, "/home/u/.psqlrc"}, {home, "/home/u/.psqlrc-16"}, {home, "/home/u/.sqliterc"}, {home, "/home/u/.irbrc"},
		{home, "/home/u/.ipython/profile_default/startup/00-x.py"}, {home, "/home/u/.jupyter/jupyter_server_config.py"},
		{home, "/home/u/.mavenrc"}, {home, "/home/u/.config/i3/config"}, {home, "/home/u/.config/sway/config"},
		{home, "/home/u/.wezterm.lua"}, {home, "/home/u/.config/wezterm/wezterm.lua"}, {home, "/home/u/.k5login"},
		{home, "/home/u/go/bin/kubectl"}, {home, "/root/go/bin/kubectl"}, {home, "/home/linuxbrew/.linuxbrew/bin/git"},
		{home, "/home/u/.npm-global/bin/git"}, {home, "/home/u/.deno/bin/git"}, {home, "/home/u/.bun/bin/git"},
		{home, `C:\Users\u\AppData\Roaming\npm\git.cmd`}, {home, `C:\Users\u\scoop\shims\git.exe`}, {home, `C:\Users\u\go\bin\x.exe`},
		{home, `C:\Users\u\.dotnet\tools\x.exe`}, {home, `C:\Users\u\AppData\Roaming\Microsoft\Outlook\VbaProject.OTM`},
		{home, `C:\Users\u\AppData\Local\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json`},
		{root, "/etc/apache2/conf-enabled/x.conf"}, {root, "/etc/apache2/sites-available/000-default.conf"},
		{root, "/etc/apache2/envvars"}, {root, "/etc/httpd/conf.d/x.conf"}, {root, "/usr/local/etc/apache24/httpd.conf"},
		{root, "/etc/kubernetes/manifests/x.yaml"}, {root, "/usr/lib/x86_64-linux-gnu/security/pam_unix.so"},
		{root, "/lib/x86_64-linux-gnu/security/pam_unix.so"}, {root, "/usr/lib64/security/pam_unix.so"}, {root, "/etc/nsswitch.conf"},
		{root, "/usr/share/dbus-1/system-services/x.service"}, {root, "/etc/dbus-1/system.d/x.conf"},
		{root, "/etc/initramfs-tools/scripts/init-top/x"}, {root, "/usr/lib/dracut/modules.d/99x/module-setup.sh"},
		{root, "/etc/acpi/events/x"}, {root, "/etc/lightdm/lightdm.conf"}, {root, "/etc/gdm3/PostLogin/Default"},
		{root, "/etc/docker/daemon.json"}, {root, "/usr/share/bash-completion/completions/git"},
		{root, `C:\Windows\System32\git.exe`}, {root, `C:\Windows\git.exe`}, {root, `C:\Windows\System32\version.dll`},
		{root, `C:\Windows\SysWOW64\git.exe`}, {root, `C:\Windows\System32\Wbem\git.exe`},
		{root, `C:\Windows\System32\WindowsPowerShell\v1.0\git.exe`}, {root, `C:\Program Files\PowerShell\7\pwsh.exe`},
		{root, "/Windows/System32/git.exe"}, {root, "/etc/nginx/nginx.conf"}, {root, "/etc/nginx/sites-available/shop"},
		{root, "/etc/nginx/modules-enabled/50-mod-x.conf"}, {root, "/usr/local/etc/nginx/nginx.conf"},
		{root, "/opt/homebrew/etc/nginx/servers/x.conf"}, {root, "/usr/local/nginx/conf/nginx.conf"},
	} {
		if _, ok, why := c.p.CheckWrite(c.path); ok || !strings.Contains(why, "persistence-point rule") {
			t.Errorf("CheckWrite(%q) = %v, %q", c.path, ok, why)
		}
	}
	for _, p := range []string{`C:\Windows\Temp\x.txt`, `C:\Windows\System32\drivers\etc\hosts`, `C:\Windows\Logs\app\x.log`,
		"/home/u/go/src/app/main.go", "/home/u/.config/app/settings.toml", "/etc/myapp/app.conf", "/etc/docker/certs.d/x/ca.crt",
		"/home/u/project/bin/tool"} {
		if _, ok, why := root.CheckWrite(p); !ok {
			t.Errorf("CheckWrite(%q) refused: %s", p, why)
		}
	}
}

// Credential stores: backups of the password hashes, OpenSSH keys under
// their default names anywhere, Kerberos ticket caches, the Erlang cookie,
// Tailscale's keys, etcd's data, Ceph keyrings, and the password files of
// fetchmail, MySQL login paths, Maven and Ansible vault; vim's history.
func TestKeyAndServiceCredentialStores(t *testing.T) {
	all := mustPol(t, ProfileConfig{ReadPaths: []string{"/**"}})
	for _, p := range []string{
		"/var/backups/shadow.bak", "/var/backups/gshadow.bak", "/etc/shadow-", "/etc/gshadow", "/etc/shadow.old",
		"/var/lib/rabbitmq/.erlang.cookie", "/var/lib/tailscale/tailscaled.state", `C:\ProgramData\Tailscale\server-state.conf`,
		"/var/lib/etcd/member/snap/db", "/data/etcd/member/wal/0000000000000000-0000000000000000.wal",
		"/var/lib/ceph/osd/ceph-0/keyring", "/etc/ceph/ceph.client.admin.keyring", "/tmp/krb5cc_1000",
		"/run/user/1000/krb5cc/tkt", "/home/u/.m2/settings-security.xml", "/home/u/.fetchmailrc", "/home/u/.mylogin.cnf",
		"/home/u/.vault_pass.txt", "/srv/ansible/vault-password", "/home/u/.vaultpass", "/srv/deploy/id_ed25519",
		"/root/keys/id_rsa", "/home/u/backup/id_ecdsa_old", "/home/u/.viminfo", "/home/u/.local/state/nvim/shada/main.shada",
	} {
		if _, ok, why := all.CheckRead(p); ok || !strings.Contains(why, "secret-path rule") {
			t.Errorf("CheckRead(%q) = %v, %q", p, ok, why)
		}
	}
	for _, p := range []string{"/var/backups/passwd.bak", "/etc/passwd", "/var/lib/etcd-docs/README.md", "/srv/ansible/vault.yml.example",
		"/home/u/.vim/vimrc.local", "/etc/krb5.conf"} {
		if _, ok, why := all.CheckRead(p); !ok {
			t.Errorf("CheckRead(%q) refused: %s", p, why)
		}
	}
}

// Programs that run the command or code they are given are wrappers:
// confirm_unlisted never offers them and a pattern names them only with
// allow_wrappers.
func TestSandboxAndTaskRunnerWrapperNames(t *testing.T) {
	cu := mustPol(t, ProfileConfig{Run: RunConfig{ConfirmUnlisted: true}})
	for _, name := range []string{
		"aa-exec", "logsave", "cpulimit", "pidstat", "setlock", "msgfilter", "openvt", "ksu", "uftrace", "hwloc-bind",
		"minijail0", "nsjail", "distrobox", "distrobox-enter", "toolbox", "flatpak-spawn", "oc", "xdotool", "service",
		"rc-service", "mail", "mailx", "run-mailcap", "distcc", "just", "pre-commit", "tsx", "ts-node", "electron", "gosh",
		"nim", "zig", "pdksh", "osh", "ysh", "runonce.exe", "msdeploy.exe", "ttdinject.exe", "vsjitdebugger.exe", "csc.exe",
		"vbc.exe", "jsc.exe", "openssl", "openssl.exe", "ssh-keygen", "ssh-keygen.exe", "pkcs11-tool",
	} {
		if !isWrapper(name) {
			t.Errorf("%s is not a wrapper", name)
			continue
		}
		if d, _ := cu.RunDecision([]string{name, "x"}, false); d != Deny {
			t.Errorf("confirm_unlisted offers %s", name)
		}
		if _, err := BuildPolicies(map[string]ProfileConfig{"p": {Run: RunConfig{Allow: [][]string{{name, "**"}}}}}); err == nil {
			t.Errorf("a pattern names %s without allow_wrappers", name)
		}
	}
	for _, name := range []string{"systemctl", "journalctl", "ssh-keyscan", "mailq", "postqueue", "ocsp"} {
		if isWrapper(name) {
			t.Errorf("%s taken for a wrapper", name)
		}
	}
}

// Background jobs are offered only where some target's profile runs more
// than the built-in read-only diagnostics, which are quick and gain nothing
// from running in the background.
func TestJobToolsNeedARunProfile(t *testing.T) {
	tools := func(prof ProfileConfig) []string {
		t.Helper()
		pol := mustPol(t, prof)
		srv, err := New(Config{Version: "test", AuditPath: filepath.Join(t.TempDir(), "audit.jsonl"), Targets: []TargetSpec{{
			Target: Target{Name: "box", Mode: "direct", Endpoint: "loopback", Transport: "tls-pinned"},
			Policy: pol,
			Dial:   func(context.Context) (*tern.Client, error) { return nil, errors.New("no agent in this test") },
		}}})
		if err != nil {
			t.Fatal(err)
		}
		defer srv.Close()
		list, err := stackClient(t, srv, "", nil).ListTools(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, tl := range list.Tools {
			names = append(names, tl.Name)
		}
		return names
	}
	for _, prof := range []ProfileConfig{{}, {ReadPaths: []string{"/srv/**"}}, {WritePaths: []string{"/srv/**"}}} {
		if names := tools(prof); slices.ContainsFunc(names, func(n string) bool { return strings.HasPrefix(n, "job_") }) {
			t.Errorf("profile %+v offers %v", prof, names)
		}
	}
	for _, prof := range []ProfileConfig{{Run: RunConfig{Allow: [][]string{{"systemctl", "restart", "nginx"}}}},
		{Run: RunConfig{Shell: true}}, {Run: RunConfig{ConfirmUnlisted: true}}} {
		if names := tools(prof); !slices.Contains(names, "job_start") || !slices.Contains(names, "job_poll") ||
			!slices.Contains(names, "job_cancel") || !slices.Contains(names, "job_list") {
			t.Errorf("profile %+v offers %v", prof, names)
		}
	}
}

// Writes follow a symlinked directory on the agent: where the lexical secret
// rule sees /<allowed>/link/config, the file would land in .ssh, so the
// path the agent reports is held to the rules too.
func TestPathRulesFollowLinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks needs a privilege on Windows")
	}
	a := newStackAgent(t)
	dir := t.TempDir()
	sshDir := filepath.Join(dir, "home", ".ssh")
	os.MkdirAll(sshDir, 0o700)
	os.MkdirAll(filepath.Join(dir, "pub"), 0o700)
	os.Symlink(sshDir, filepath.Join(dir, "pub", "link"))
	srv, _ := stackServer(t, a, ProfileConfig{WritePaths: []string{dir + "/pub/**"}, ReadPaths: []string{dir + "/pub/**"}}, nil)
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	if why := call(t, cs, "write_file", map[string]any{"path": dir + "/pub/link/config", "content": "ProxyCommand evil\n"}, nil, true); !strings.Contains(why, "secret-path rule") {
		t.Errorf("write through a link: %s", why)
	}
	if b, err := os.ReadFile(filepath.Join(sshDir, "config")); err == nil {
		t.Errorf("wrote into a secret path through a symlink: %q", b)
	}
	// An empty write is refused before the agent touches the file: there is
	// no content to hold it back.
	conf := filepath.Join(sshDir, "config")
	os.WriteFile(conf, []byte("Host *\n"), 0o600)
	if why := call(t, cs, "write_file", map[string]any{"path": dir + "/pub/link/config", "content": ""}, nil, true); !strings.Contains(why, "secret-path rule") {
		t.Errorf("empty write through a link: %s", why)
	}
	if b, _ := os.ReadFile(conf); string(b) != "Host *\n" {
		t.Errorf("a refused empty write changed %s: %q", conf, b)
	}
	// authorized_keys is a persistence point wherever it is, link or not.
	if why := call(t, cs, "write_file", map[string]any{"path": dir + "/pub/link/authorized_keys", "content": "ssh-ed25519 AAAA attacker\n"}, nil, true); !strings.Contains(why, "persistence-point rule") {
		t.Errorf("write of authorized_keys: %s", why)
	}
	os.WriteFile(filepath.Join(sshDir, "id_ed25519"), []byte("PRIVATE-MATERIAL\n"), 0o600)
	var r ReadOutput
	if why := call(t, cs, "read_file", map[string]any{"path": dir + "/pub/link/id_ed25519"}, &r, true); !strings.Contains(why, "secret-path rule") {
		t.Errorf("read through a link: %s", why)
	}
	// A link to an ordinary file outside what the profile reads reads it
	// when every user may, and a write lands in the real directory.
	os.WriteFile(filepath.Join(dir, "home", "notes.txt"), []byte("hello\n"), 0o600)
	os.Symlink(filepath.Join(dir, "home"), filepath.Join(dir, "pub", "home"))
	if why := call(t, cs, "read_file", map[string]any{"path": dir + "/pub/home/notes.txt"}, nil, true); !strings.Contains(why, "not readable by every user") {
		t.Errorf("read through a link to an owner-only file outside: %s", why)
	}
	open := openTempDir(t)
	os.WriteFile(filepath.Join(open, "notes.txt"), []byte("hello\n"), 0o644)
	os.Chmod(filepath.Join(open, "notes.txt"), 0o644)
	os.Symlink(open, filepath.Join(dir, "pub", "open"))
	call(t, cs, "read_file", map[string]any{"path": dir + "/pub/open/notes.txt"}, &r, false)
	if r.Content != "hello\n" {
		t.Errorf("read through an ordinary link = %q", r.Content)
	}
	call(t, cs, "write_file", map[string]any{"path": dir + "/pub/home/new.txt", "content": "x"}, nil, false)
	if b, _ := os.ReadFile(filepath.Join(dir, "home", "new.txt")); string(b) != "x" {
		t.Errorf("write through an ordinary link = %q", b)
	}
	if strings.Contains(r.Content, "PRIVATE-MATERIAL") {
		t.Errorf("read a secret path through a symlink: %q", r.Content)
	}
}

// End to end, nothing is read through /proc/self/root, and /proc
// pseudo-files, which report size 0, read with their content.
func TestProcFilesHaveContent(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("uses /proc")
	}
	a := newStackAgent(t)
	srv, _ := stackServer(t, a, ProfileConfig{ReadPaths: []string{"/proc/**"}}, nil)
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	var r ReadOutput
	call(t, cs, "read_file", map[string]any{"path": "/proc/self/root/etc/os-release"}, &r, true)
	call(t, cs, "read_file", map[string]any{"path": "/proc/cpuinfo"}, &r, false)
	if r.Content == "" {
		t.Errorf("/proc/cpuinfo (readonly-allowed) reads as empty, size %d", r.Size)
	}
}
