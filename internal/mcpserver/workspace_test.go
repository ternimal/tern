// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	tern "github.com/ternimal/tern/internal/tern"
)

// A download never creates the configuration an MCP client, an AI coding
// tool or an editor runs code from, nor the instruction files they load into
// every session: the hooks of a Claude Code settings file run at its next
// start, VS Code runs a folder's tasks when it opens, and each of these
// clients starts the MCP servers its lists name.
func TestDownloadNeverCreatesMCPClientConfig(t *testing.T) {
	a := newStackAgent(t)
	home, remote := t.TempDir(), t.TempDir()
	payload := `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"echo planted"}]}]}}` + "\n"
	os.WriteFile(filepath.Join(remote, "app.json"), []byte(payload), 0o644)
	srv, _ := stackServer(t, a, ProfileConfig{ReadPaths: []string{remote + "/**"}}, func(c *Config) { c.Workspace = home })
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	for _, local := range []string{
		".claude/settings.json", ".claude/agents/x.md", ".claude.json", "projects/app/.claude/settings.local.json",
		"projects/app/.claude/settings.json", "projects/app/.claude/commands/deploy.md", "projects/app/.mcp.json",
		"CLAUDE.md", "projects/app/CLAUDE.local.md", "projects/app/AGENTS.md", "projects/app/GEMINI.md",
		"Library/Application Support/Claude/claude_desktop_config.json", ".config/Claude/extensions/x/index.js",
		".cursor/mcp.json", "projects/app/.cursor/hooks.json", "projects/app/.cursorrules", "projects/app/.vscode/tasks.json",
		"projects/app/.vscode/settings.json", ".vscode/extensions/x/extension.js", ".vscode-server/data/Machine/settings.json",
		".config/Code/User/settings.json", ".config/Code/User/mcp.json", "projects/app/.windsurfrules", ".codeium/windsurf/mcp_config.json",
		".gemini/settings.json", "projects/app/.gemini/commands/x.toml", ".codex/config.toml", ".config/zed/settings.json",
		"projects/app/.zed/tasks.json", ".continue/config.yaml", ".copilot/mcp-config.json", "projects/app/.amazonq/mcp.json",
		".config/goose/config.yaml", "projects/app/opencode.json", "projects/app/.opencode/plugin/x.js",
	} {
		why := call(t, cs, "download", map[string]any{"remote": remote + "/app.json", "local": local}, nil, true)
		if !strings.Contains(why, "rule") || !strings.Contains(why, "never creates") {
			t.Errorf("download to %s: %s", local, why)
		}
		if _, err := os.Lstat(filepath.Join(home, local)); err == nil {
			t.Errorf("a download created %s", local)
		}
	}
	call(t, cs, "download", map[string]any{"remote": remote + "/app.json", "local": "projects/app/config/app.json"}, nil, false)
}

// The workspace tools never send tern's own logins anywhere: keys under the
// names tern keygen and the docs give them, the MCP client configuration
// that holds TERN_TOKEN, tern's state and configuration directories with
// their recordings, and this run's own files: its recordings directory, audit
// log and config file wherever they are.
func TestTernOwnFilesNeverUploaded(t *testing.T) {
	a := newStackAgent(t)
	home, remote := t.TempDir(), t.TempDir()
	for _, k := range []string{".config/tern/id_tern", "tern_id_ed25519", "projects/app/id_tern"} {
		p := filepath.Join(home, k)
		os.MkdirAll(filepath.Dir(p), 0o700)
		if _, err := tern.GenerateKeyFiles(p, "test"); err != nil {
			t.Fatal(err)
		}
	}
	login := `{"mcpServers":{"tern":{"command":"tern","args":["mcp"],"env":{"TERN_TOKEN":"FakeAgentToken0123456789"}}}}` + "\n"
	files := []string{
		".claude.json", ".claude/settings.json", "Library/Application Support/Claude/claude_desktop_config.json",
		"AppData/Roaming/Claude/claude_desktop_config.json", ".cursor/mcp.json", "projects/app/.vscode/mcp.json",
		"projects/app/.mcp.json", ".codeium/windsurf/mcp_config.json", ".codex/config.toml", ".gemini/settings.json",
		".config/anthropic/configs/default.json", ".local/state/tern/recordings/box-mcp-abcdefghijkl-1.cast",
		"AppData/Local/tern/mcp-audit.jsonl", "work/rec/box-mcp-abcdefghijkl-1.cast", "work/audit.jsonl", "work/tern.json",
	}
	for _, f := range files {
		p := filepath.Join(home, f)
		os.MkdirAll(filepath.Dir(p), 0o700)
		os.WriteFile(p, []byte(login), 0o600)
	}
	os.WriteFile(filepath.Join(home, "work", "notes.txt"), []byte("notes\n"), 0o600)
	own := []string{filepath.Join(home, "work", "rec"), filepath.Join(home, "work", "audit.jsonl"), filepath.Join(home, "work", "tern.json")}
	srv, _ := stackServer(t, a, ProfileConfig{WritePaths: []string{remote + "/**"}}, func(c *Config) { c.Workspace, c.TernDirs = home, own })
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	for i, local := range append([]string{".config/tern/id_tern", ".config/tern/id_tern.pub", "tern_id_ed25519", "projects/app/id_tern"}, files...) {
		dst := filepath.Join(remote, fmt.Sprintf("sent-%d", i))
		why := call(t, cs, "upload", map[string]any{"local": local, "remote": dst}, nil, true)
		if !strings.Contains(why, "rule") || !strings.Contains(why, "never uploaded") {
			t.Errorf("upload of %s: %s", local, why)
		}
		if _, err := os.Lstat(dst); err == nil {
			t.Errorf("%s reached the agent", local)
		}
	}
	call(t, cs, "upload", map[string]any{"local": "work/notes.txt", "remote": remote + "/notes.txt"}, nil, false)
}

// A private key never travels under another name either: upload and
// download look at a file's first keyCheckBytes for the line a key starts
// with, in a PEM block, a PuTTY key file or an age identity, after a
// preamble such as openssl's "Bag Attributes" or kilobytes of other text
// too, and in UTF-16 text with a byte-order mark, in either byte order. A
// download holds those bytes back until they are checked, so nothing of the
// key lands in the workspace. Certificates, public keys and a key line past
// the bytes looked at go through.
func TestPrivateKeyNeverTravelsUnderAnotherName(t *testing.T) {
	a := newStackAgent(t)
	ws, remote := t.TempDir(), t.TempDir()
	keyFile := filepath.Join(t.TempDir(), "k")
	if _, err := tern.GenerateKeyFiles(keyFile, "test"); err != nil {
		t.Fatal(err)
	}
	openssh, _ := os.ReadFile(keyFile)
	pub, _ := os.ReadFile(keyFile + ".pub")
	utf16le, utf16be := []byte{0xff, 0xfe}, []byte{0xfe, 0xff}
	for _, u := range utf16.Encode([]rune(string(openssh))) {
		utf16le = append(utf16le, byte(u), byte(u>>8))
		utf16be = append(utf16be, byte(u>>8), byte(u))
	}
	// A key line well inside the bytes looked at, past the first KiB.
	mid := append(bytes.Repeat([]byte("# notes before the key\n"), keyCheckBytes/2/23), openssh...)
	keys := map[string][]byte{
		"openssh":  openssh,
		"pkcs8":    []byte("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n-----END PRIVATE KEY-----\n"),
		"bag":      []byte("Bag Attributes\n    localKeyID: 01 00 00 00\nKey Attributes: <No Attributes>\n-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFHzBJBgkq\n-----END ENCRYPTED PRIVATE KEY-----\n"),
		"rsa-crlf": []byte("\r\n  -----BEGIN RSA PRIVATE KEY-----\r\nMIIEpAIBAAKCAQEA\r\n-----END RSA PRIVATE KEY-----\r\n"),
		"pgp":      []byte("-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nlQVYBGVb\n-----END PGP PRIVATE KEY BLOCK-----\n"),
		"putty":    []byte("PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: test\n"),
		"age":      []byte("# created: 2026-01-01T00:00:00Z\n# public key: age1qqqq\nAGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ\n"),
		"utf16":    utf16le,
		"utf16be":  utf16be,
		"mid":      mid,
		"big":      append(append([]byte{}, openssh...), bytes.Repeat([]byte("x"), 3*keyCheckBytes)...),
	}
	if n := bytes.Index(mid, []byte("-----BEGIN")); n < 4<<10 || n+40 > keyCheckBytes {
		t.Fatalf("the mid key line starts at byte %d", n)
	}
	for name, b := range keys {
		os.WriteFile(filepath.Join(ws, name+".txt"), b, 0o600)
		os.WriteFile(filepath.Join(remote, name+".txt"), b, 0o600)
	}
	plain := map[string][]byte{
		"cert.txt":  []byte("-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIU\n-----END CERTIFICATE-----\n"),
		"pub.txt":   pub,
		"doc.txt":   []byte("Keys look like this: -----BEGIN OPENSSH PRIVATE KEY----- (an example)\n"),
		"late.txt":  append(bytes.Repeat([]byte("y"), keyCheckBytes), openssh...),
		"large.bin": bytes.Repeat([]byte{0, 1, 2, 3, 0xff}, 40<<10),
	}
	for name, b := range plain {
		os.WriteFile(filepath.Join(ws, name), b, 0o600)
		os.WriteFile(filepath.Join(remote, name), b, 0o600)
	}
	srv, _ := stackServer(t, a, ProfileConfig{ReadPaths: []string{remote + "/**"}, WritePaths: []string{remote + "/**"}},
		func(c *Config) { c.Workspace = ws })
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	for name := range keys {
		if why := call(t, cs, "upload", map[string]any{"local": name + ".txt", "remote": remote + "/up-" + name}, nil, true); !strings.Contains(why, "holds a private key") {
			t.Errorf("upload of %s: %s", name, why)
		}
		if _, err := os.Lstat(filepath.Join(remote, "up-"+name)); err == nil {
			t.Errorf("the %s key reached the agent", name)
		}
		if why := call(t, cs, "download", map[string]any{"remote": remote + "/" + name + ".txt", "local": "dl/" + name}, nil, true); !strings.Contains(why, "holds a private key") {
			t.Errorf("download of %s: %s", name, why)
		}
	}
	if ents, _ := os.ReadDir(filepath.Join(ws, "dl")); len(ents) != 0 {
		t.Errorf("refused downloads left %d files in the workspace", len(ents))
	}
	for name, b := range plain {
		call(t, cs, "upload", map[string]any{"local": name, "remote": remote + "/up-" + name}, nil, false)
		var out TransferOutput
		call(t, cs, "download", map[string]any{"remote": remote + "/" + name, "local": "ok/" + name}, &out, false)
		got, _ := os.ReadFile(filepath.Join(ws, "ok", name))
		sum := sha256.Sum256(b)
		if !bytes.Equal(got, b) || out.SHA256 != hex.EncodeToString(sum[:]) || out.Bytes != int64(len(b)) {
			t.Errorf("download of %s: %d bytes, sha256 %s, want %d and %x", name, len(got), out.SHA256, len(b), sum)
		}
	}
}

// A persistence point or credential store that is a link into the workspace,
// as dotfiles setups make ~/.config/nvim, ~/.vim, ~/.local/bin or ~/.kube,
// holds its rule where the link leads too: no download creates a file there,
// and a credential store's files are never uploaded. Links that lead nowhere
// yet count, since a download would make what they name; and so do the names
// under the home directory a rule names, which can be links into the
// workspace from outside it. A link that leads to the whole workspace makes
// New refuse it.
func TestLinkedRuleDirectoriesIntoWorkspace(t *testing.T) {
	a := newStackAgent(t)
	home, remote := t.TempDir(), t.TempDir()
	t.Setenv("HOME", t.TempDir()) // a home outside the workspace, set up below
	link := func(target, name string) {
		t.Helper()
		os.MkdirAll(filepath.Dir(filepath.Join(home, name)), 0o700)
		if err := os.Symlink(target, filepath.Join(home, name)); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{"dotfiles/nvim/plugin", "dotfiles/vim/plugin", "dotfiles/bin", "dotfiles/kube"} {
		os.MkdirAll(filepath.Join(home, d), 0o700)
	}
	link("../dotfiles/nvim", ".config/nvim")
	link("dotfiles/vim", ".vim")
	link("../dotfiles/bin", ".local/bin")
	link("dotfiles/kube", ".kube")
	link("dotfiles/emacs", ".emacs.d")         // leads to nothing yet
	link("../../dotfiles/netrc", "a/b/.netrc") // a file that does not exist yet
	os.WriteFile(filepath.Join(home, "dotfiles/kube/config"), []byte("users:\n- user:\n    token: fake-kube-token-0123456789\n"), 0o600)
	os.WriteFile(filepath.Join(home, "dotfiles/notes.txt"), []byte("notes\n"), 0o600)
	// Outside the workspace: the home directory's ~/.tmux.conf and
	// ~/.config/systemd lead into it.
	os.MkdirAll(filepath.Join(os.Getenv("HOME"), ".config"), 0o700)
	os.Symlink(filepath.Join(home, "dotfiles", "tmux.conf"), filepath.Join(os.Getenv("HOME"), ".tmux.conf"))
	os.Symlink(filepath.Join(home, "dotfiles", "systemd"), filepath.Join(os.Getenv("HOME"), ".config", "systemd"))
	os.WriteFile(filepath.Join(remote, "payload"), []byte("os.execute('echo planted')\n"), 0o644)
	srv, _ := stackServer(t, a, ProfileConfig{ReadPaths: []string{remote + "/**"}, WritePaths: []string{remote + "/**"}},
		func(c *Config) { c.Workspace = home })
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	for _, c := range []struct{ local, link string }{
		{"dotfiles/nvim/plugin/x.lua", ".config/nvim"}, {"dotfiles/vim/plugin/x.vim", ".vim"}, {"dotfiles/bin/ls", ".local/bin"},
		{"dotfiles/emacs/init.el", ".emacs.d"}, {"dotfiles/netrc", ".netrc"}, {"dotfiles/tmux.conf", ".tmux.conf"},
		{"dotfiles/systemd/user/x.service", "systemd"},
	} {
		why := call(t, cs, "download", map[string]any{"remote": remote + "/payload", "local": c.local}, nil, true)
		if !strings.Contains(why, "lies where") || !strings.Contains(why, c.link) || !strings.Contains(why, "never creates") {
			t.Errorf("download to %s: %s", c.local, why)
		}
		if _, err := os.Lstat(filepath.Join(home, c.local)); err == nil {
			t.Errorf("a download created %s", c.local)
		}
	}
	if _, err := os.Lstat(filepath.Join(home, "dotfiles", "emacs")); err == nil {
		t.Error("a refused download made the directory a dangling link leads to")
	}
	why := call(t, cs, "upload", map[string]any{"local": "dotfiles/kube/config", "remote": remote + "/k"}, nil, true)
	if !strings.Contains(why, "lies where .kube leads") || !strings.Contains(why, "never uploaded") {
		t.Errorf("upload of dotfiles/kube/config: %s", why)
	}
	// A persistence point's files are still read and sent; only what a
	// download creates there is refused.
	os.WriteFile(filepath.Join(home, "dotfiles/vim/plugin/mine.vim"), []byte("set nu\n"), 0o600)
	call(t, cs, "upload", map[string]any{"local": "dotfiles/vim/plugin/mine.vim", "remote": remote + "/mine.vim"}, nil, false)
	call(t, cs, "upload", map[string]any{"local": "dotfiles/notes.txt", "remote": remote + "/notes.txt"}, nil, false)
	call(t, cs, "download", map[string]any{"remote": remote + "/payload", "local": "dotfiles/other/x.lua"}, nil, false)

	// A link under a persistence point's name to the whole workspace, as
	// ~/.local/bin to a scripts directory, leaves it for uploads; every
	// download is refused. One under a credential store's name refuses the
	// workspace at startup.
	scripts := t.TempDir()
	os.WriteFile(filepath.Join(scripts, "deploy.sh"), []byte("#!/bin/sh\necho deploy\n"), 0o700)
	os.MkdirAll(filepath.Join(os.Getenv("HOME"), ".local"), 0o700)
	os.Symlink(scripts, filepath.Join(os.Getenv("HOME"), ".local", "bin"))
	srv2, _ := stackServer(t, a, ProfileConfig{ReadPaths: []string{remote + "/**"}, WritePaths: []string{remote + "/**"}},
		func(c *Config) { c.Workspace = scripts })
	defer srv2.Close()
	cs2 := stackClient(t, srv2, "", nil)
	call(t, cs2, "upload", map[string]any{"local": "deploy.sh", "remote": remote + "/deploy.sh"}, nil, false)
	why = call(t, cs2, "download", map[string]any{"remote": remote + "/payload", "local": "new.sh"}, nil, true)
	if !strings.Contains(why, "lies where") || !strings.Contains(why, ".local/bin") || !strings.Contains(why, "never creates") {
		t.Errorf("download into a workspace ~/.local/bin leads to: %s", why)
	}
	keys := t.TempDir()
	os.Symlink(keys, filepath.Join(os.Getenv("HOME"), ".kube"))
	pols, _ := BuildPolicies(nil)
	_, err := New(Config{Version: "test", AuditPath: filepath.Join(t.TempDir(), "audit.jsonl"), Workspace: keys,
		Targets: []TargetSpec{{Target: Target{Name: "box"}, Policy: pols["readonly"], Dial: a.dial}}})
	if err == nil || !strings.Contains(err.Error(), "through a link") || !strings.Contains(err.Error(), "choose another directory") {
		t.Errorf("a workspace a ~/.kube link leads to: %v", err)
	}
}

// The look for links is bounded: once it has read aliasEntries directories
// or judged aliasLinks links it stops short, which refuses downloads for the
// run (see TestDownloadsRefusedWhenTheLookStopsShort), so a workspace with
// many directories or links costs a bounded time at startup and hides no
// link where a download could land. Plain files cost only their reading: a
// directory of many of them read first keeps the look from no link beside
// it. Links deeper than aliasDepth directories are not looked at, which is
// not stopping short. It reads breadth first, dot directories first, so
// links near the top, where dotfiles setups put theirs, come first.
func TestLinkLookIsBounded(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks needs a privilege on Windows")
	}
	t.Setenv("HOME", t.TempDir())
	look := func(dir string) ([]ruleList, string) {
		t.Helper()
		start := time.Now()
		out, cut := (&Server{wsReal: dir}).newLook().run()
		t.Logf("%s: %d places in %v, stopped short: %q", dir, len(out), time.Since(start), cut)
		return out, cut
	}
	files := t.TempDir()
	for i := range aliasEntries + 1 {
		os.WriteFile(filepath.Join(files, fmt.Sprintf("f%05d", i)), nil, 0o600)
	}
	os.MkdirAll(filepath.Join(files, "sub", "dotfiles", "vim"), 0o700)
	os.Symlink("dotfiles/vim", filepath.Join(files, "sub", ".vim"))
	if got, cut := look(files); len(got) != 1 || cut != "" {
		t.Errorf("a link beside %d files: %+v, %q", aliasEntries+1, got, cut)
	}
	dirs := t.TempDir()
	for i := range aliasEntries {
		os.Mkdir(filepath.Join(dirs, fmt.Sprintf("d%05d", i)), 0o700)
	}
	if _, cut := look(dirs); !strings.Contains(cut, fmt.Sprintf("reading %d directories", aliasEntries)) {
		t.Errorf("%d directories: stopped short %q", aliasEntries+1, cut)
	}
	links := t.TempDir()
	for i := range aliasLinks + 1 {
		os.Symlink("target", filepath.Join(links, fmt.Sprintf("l%04d", i)))
	}
	if _, cut := look(links); !strings.Contains(cut, fmt.Sprintf("judging %d links", aliasLinks)) {
		t.Errorf("%d links: stopped short %q", aliasLinks+1, cut)
	}
	deep := t.TempDir()
	os.MkdirAll(filepath.Join(deep, "a", "b", "c", "vim"), 0o700)
	os.Symlink("vim", filepath.Join(deep, "a", "b", "c", ".vim"))
	if got, cut := look(deep); len(got) != 0 || cut != "" {
		t.Errorf("a link %d directories down: %+v, %q", aliasDepth+1, got, cut)
	}
	shallow := t.TempDir()
	os.MkdirAll(filepath.Join(shallow, "a", "b", "vim"), 0o700)
	os.Symlink("vim", filepath.Join(shallow, "a", "b", ".vim"))
	if got, cut := look(shallow); len(got) != 1 || got[0].link != filepath.Join("a", "b", ".vim") || cut != "" {
		t.Errorf("a link %d directories down: %+v, %q", aliasDepth, got, cut)
	}
}

// mkdirAll never makes a directory a link points to: each link on the way
// must lead to a directory that exists. A link to one is followed, and a file
// in the way is refused.
func TestMkdirAllRefusesDanglingLinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks needs a privilege on Windows")
	}
	ws := t.TempDir()
	root, err := os.OpenRoot(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	os.Symlink(".config", filepath.Join(ws, "cfg"))
	os.MkdirAll(filepath.Join(ws, "data", "in"), 0o700)
	os.Symlink(filepath.Join("data", "in"), filepath.Join(ws, "inbox"))
	os.WriteFile(filepath.Join(ws, "file"), nil, 0o600)
	if err := mkdirAll(root, filepath.Join("cfg", "autostart")); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("through a dangling link: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(ws, ".config")); err == nil {
		t.Error("mkdirAll made the directory a dangling link leads to")
	}
	if err := mkdirAll(root, filepath.Join("inbox", "new", "deeper")); err != nil {
		t.Errorf("through a link to a directory: %v", err)
	}
	if fi, err := os.Stat(filepath.Join(ws, "data", "in", "new", "deeper")); err != nil || !fi.IsDir() {
		t.Errorf("the directories made through inbox: %v", err)
	}
	if err := mkdirAll(root, filepath.Join("file", "x")); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("a file in the way: %v", err)
	}
}

// A download that a link on its path would refuse is refused before a human
// is asked to approve it. And the workspace may change while one is asked: a
// link planted on the path then, which leads to no directory yet, makes the
// approved call fail, as it meets the checks again, and nothing is made where
// the link leads, though the check before asking passed.
func TestDownloadRechecksLinksAfterApproval(t *testing.T) {
	for _, version := range []string{"2026-07-28", "2025-11-25"} {
		t.Run(version, func(t *testing.T) { testDownloadRechecksLinksAfterApproval(t, version) })
	}
}

func testDownloadRechecksLinksAfterApproval(t *testing.T, version string) {
	a := newStackAgent(t)
	ws, remote := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(remote, "x.desktop"), []byte("[Desktop Entry]\nExec=sh -c 'echo planted'\n"), 0o644)
	srv, _ := stackServer(t, a, ProfileConfig{ReadPaths: []string{remote + "/**"}, Confirm: []string{"download"}},
		func(c *Config) { c.Workspace = ws })
	defer srv.Close()
	asked := 0
	cs := stackClient(t, srv, version, &mcp.ClientOptions{ElicitationHandler: func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		asked++
		if err := os.Symlink(".config", filepath.Join(ws, "cfg")); err != nil {
			t.Error(err)
		}
		return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approve": true}}, nil
	}})
	os.Symlink(".local/share", filepath.Join(ws, "data"))
	why := call(t, cs, "download", map[string]any{"remote": remote + "/x.desktop", "local": "data/applications/x.desktop"}, nil, true)
	if asked != 0 || !strings.Contains(why, "does not exist") {
		t.Errorf("through a link that leads nowhere: asked %d times; download: %s", asked, why)
	}
	why = call(t, cs, "download", map[string]any{"remote": remote + "/x.desktop", "local": "cfg/autostart/x.desktop"}, nil, true)
	if asked != 1 || !strings.Contains(why, "does not exist") {
		t.Errorf("asked %d times; download: %s", asked, why)
	}
	if _, err := os.Lstat(filepath.Join(ws, ".config")); err == nil {
		t.Error("the download made a directory where the link planted while asking leads")
	}
}

// TestDownloadNoOverwriteWhileAsking: a file that appears at the download's
// target while the form is open is not replaced: the approved call meets the
// check that nothing is there again, with both protocols.
func TestDownloadNoOverwriteWhileAsking(t *testing.T) {
	for _, version := range []string{"2026-07-28", "2025-11-25"} {
		t.Run(version, func(t *testing.T) {
			a := newStackAgent(t)
			ws, remote := t.TempDir(), t.TempDir()
			os.WriteFile(filepath.Join(remote, "r.txt"), []byte("from the host"), 0o644)
			srv, _ := stackServer(t, a, ProfileConfig{ReadPaths: []string{remote + "/**"}, Confirm: []string{"download"}},
				func(c *Config) { c.Workspace = ws })
			defer srv.Close()
			mine := filepath.Join(ws, "notes.txt")
			cs := stackClient(t, srv, version, &mcp.ClientOptions{ElicitationHandler: func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
				if err := os.WriteFile(mine, []byte("the user's notes"), 0o600); err != nil {
					t.Error(err)
				}
				return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approve": true}}, nil
			}})
			why := call(t, cs, "download", map[string]any{"remote": remote + "/r.txt", "local": "notes.txt"}, nil, true)
			if b, _ := os.ReadFile(mine); !strings.Contains(why, "already exists") || string(b) != "the user's notes" {
				t.Errorf("download: %s; the file now holds %q", why, b)
			}
		})
	}
}

// A terminal state file is named by an absolute path: a relative one would
// land wherever tern mcp was started, outside tern's own directories.
func TestPTYStateNeedsAbsolutePath(t *testing.T) {
	t.Chdir(t.TempDir())
	if _, _, err := openPTYStore("mcp-ptys-0123456789ab.json"); err == nil || !strings.Contains(err.Error(), "not an absolute path") {
		t.Errorf("a relative state file: %v", err)
	}
	if ents, _ := os.ReadDir("."); len(ents) != 0 {
		t.Errorf("a refused state file left %d files", len(ents))
	}
}
