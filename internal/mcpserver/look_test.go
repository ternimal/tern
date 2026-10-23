// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// stuckDir is a directory that does not answer, as one on a dead network
// mount does, until release is closed.
type stuckDir struct{ release chan struct{} }

func (d stuckDir) ReadDir(int) ([]os.DirEntry, error) { <-d.release; return nil, errors.New("gone") }
func (d stuckDir) Close() error                       { return nil }

// A directory in the workspace that never answers cannot hold startup: New
// waits for the look at most aliasTime and aliasGrace, then starts with the
// look stopped short, which refuses downloads and uploads, since a link the
// look did not see could lead where one lands, or make a file a secret under
// another name. The look left behind finishes once the directory answers.
func TestLookTimeBoundHoldsStartup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks needs a privilege on Windows")
	}
	a := newStackAgent(t)
	ws, remote := t.TempDir(), t.TempDir()
	t.Setenv("HOME", t.TempDir())
	os.MkdirAll(filepath.Join(ws, "mnt", "nas"), 0o700)
	os.WriteFile(filepath.Join(ws, "notes.txt"), []byte("notes\n"), 0o600)
	os.WriteFile(filepath.Join(remote, "payload"), []byte("x\n"), 0o644)
	release := make(chan struct{})
	defer func(open func(string) (lookDir, error), budget time.Duration) {
		close(release)
		openLookDir, aliasTime = open, budget
	}(openLookDir, aliasTime)
	stuck := filepath.Join(ws, "mnt", "nas")
	var reached atomic.Bool
	openLookDir = func(p string) (lookDir, error) {
		if p == stuck {
			reached.Store(true)
			return stuckDir{release}, nil
		}
		return os.Open(p)
	}
	aliasTime = 200 * time.Millisecond
	start := time.Now()
	srv, _ := stackServer(t, a, ProfileConfig{ReadPaths: []string{remote + "/**"}, WritePaths: []string{remote + "/**"}},
		func(c *Config) { c.Workspace = ws })
	defer srv.Close()
	took := time.Since(start)
	t.Logf("New took %v; the look: %q", took, srv.lookCut)
	if !reached.Load() {
		t.Fatal("the look never read the directory that does not answer")
	}
	if took > aliasTime+aliasGrace+time.Second || !strings.Contains(srv.lookCut, "did not finish within") {
		t.Errorf("New took %v with a directory that never answers; the look: %q", took, srv.lookCut)
	}
	cs := stackClient(t, srv, "", nil)
	why := call(t, cs, "download", map[string]any{"remote": remote + "/payload", "local": "new.txt"}, nil, true)
	if !strings.Contains(why, "downloads into this workspace are refused") || !strings.Contains(why, "did not finish") {
		t.Errorf("download after the look stopped short: %s", why)
	}
	if _, err := os.Lstat(filepath.Join(ws, "new.txt")); err == nil {
		t.Error("a download landed though the look stopped short")
	}
	why = call(t, cs, "upload", map[string]any{"local": "notes.txt", "remote": remote + "/notes.txt"}, nil, true)
	if !strings.Contains(why, "uploads from this workspace are refused") {
		t.Errorf("upload after the look stopped short: %s", why)
	}
}

// A look that reaches one of its bounds stops short, and downloads and
// uploads are refused for the run, with what stopped it; a look that
// finishes leaves them as they are.
func TestDownloadsRefusedWhenTheLookStopsShort(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks needs a privilege on Windows")
	}
	a := newStackAgent(t)
	ws, remote := t.TempDir(), t.TempDir()
	t.Setenv("HOME", t.TempDir())
	for i := range aliasLinks + 1 {
		os.Symlink("nowhere", filepath.Join(ws, fmt.Sprintf("l%04d", i)))
	}
	os.WriteFile(filepath.Join(remote, "payload"), []byte("x\n"), 0o644)
	srv, _ := stackServer(t, a, ProfileConfig{ReadPaths: []string{remote + "/**"}, WritePaths: []string{remote + "/**"}},
		func(c *Config) { c.Workspace = ws })
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	why := call(t, cs, "download", map[string]any{"remote": remote + "/payload", "local": "new.txt"}, nil, true)
	if !strings.Contains(why, fmt.Sprintf("stopped after judging %d links", aliasLinks)) || !strings.Contains(why, "a directory of its own") {
		t.Errorf("download: %s", why)
	}
	// Uploads too: a link the look did not see could make a file in the
	// workspace a secret under another name.
	os.WriteFile(filepath.Join(ws, "notes.txt"), []byte("n\n"), 0o600)
	why = call(t, cs, "upload", map[string]any{"local": "notes.txt", "remote": remote + "/sent"}, nil, true)
	if !strings.Contains(why, "uploads from this workspace are refused") {
		t.Errorf("upload: %s", why)
	}
	os.Remove(filepath.Join(ws, "l0000"))
	srv2, _ := stackServer(t, a, ProfileConfig{ReadPaths: []string{remote + "/**"}}, func(c *Config) { c.Workspace = ws })
	defer srv2.Close()
	call(t, stackClient(t, srv2, "", nil), "download", map[string]any{"remote": remote + "/payload", "local": "new.txt"}, nil, false)
}

// The look never steps onto another file system: it does not read a mount
// point in the workspace, so a dead network mount there cannot stop it, and a
// link a rule names that leads onto one is placed where it leads, as written,
// without looking inside the mount.
func TestLookStaysOffOtherFileSystems(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks needs a privilege on Windows")
	}
	ws, home := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	nas := filepath.Join(ws, "mnt", "nas")
	os.MkdirAll(filepath.Join(nas, "sub"), 0o700)
	os.Symlink("mnt/nas/vim", filepath.Join(ws, ".vim"))
	os.MkdirAll(filepath.Join(home, ".config"), 0o700)
	os.Symlink(filepath.Join(nas, "nvim"), filepath.Join(home, ".config", "nvim"))
	defer func(open func(string) (lookDir, error), lstat func(string) (os.FileInfo, error), mounts func() []string) {
		openLookDir, lookLstat, mountPoints = open, lstat, mounts
	}(openLookDir, lookLstat, mountPoints)
	mountPoints = func() []string { return []string{"/", nas, filepath.Dir(ws)} }
	var opened []string
	openLookDir = func(p string) (lookDir, error) {
		opened = append(opened, p)
		return os.Open(p)
	}
	lookLstat = func(p string) (os.FileInfo, error) {
		opened = append(opened, p)
		return os.Lstat(p)
	}
	out, cut := (&Server{wsReal: ws}).newLook().run()
	if cut != "" || slices.ContainsFunc(opened, func(p string) bool { return within(p, nas) }) {
		t.Errorf("the look touched %q (stopped short: %q)", opened, cut)
	}
	var rules []string
	for _, l := range out {
		rules = append(rules, l.rules...)
	}
	for _, want := range []string{treeRule(filepath.Join(nas, "vim")), treeRule(filepath.Join(nas, "nvim"))} {
		if !slices.Contains(rules, want) {
			t.Errorf("no place %s among %q", want, rules)
		}
	}
}

// Each link is followed once, through at most maxLinkHops links, as Linux
// follows them: links named like a rule into a long chain, deep in the
// workspace, cost the chain once, and a chain longer than a program could
// open leads nowhere. A shorter one is followed to its end.
func TestLinkChainsFollowedOnce(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks needs a privilege on Windows")
	}
	t.Setenv("HOME", t.TempDir())
	ws := t.TempDir()
	var segs []string
	for i := range 60 {
		segs = append(segs, fmt.Sprintf("d%d", i))
	}
	deep := filepath.Join(append([]string{ws, "c"}, segs...)...)
	os.MkdirAll(deep, 0o700)
	up := strings.Repeat("../", 60)
	for i := range 250 {
		os.Symlink(up+strings.Join(segs, "/")+fmt.Sprintf("/l%d", i+1), filepath.Join(deep, fmt.Sprintf("l%d", i)))
	}
	for i := range 500 {
		os.Symlink("c/"+strings.Join(segs, "/")+"/l0", filepath.Join(ws, fmt.Sprintf("token-%04d", i)))
	}
	start := time.Now()
	l := (&Server{wsReal: ws}).newLook()
	out, cut := l.run()
	took := time.Since(start)
	t.Logf("500 links into a 250-link chain 61 directories deep: %d places, stopped short %q, %d steps, in %v", len(out), cut, l.steps, took)
	// Each name is looked up once and each link read once: some 70
	// directories, 290 links of the chain, 500 links into it.
	if len(out) != 0 || cut != "" || took > aliasTime/3 || l.steps > 2000 {
		t.Errorf("%d places %+v, stopped short %q, %d steps, in %v", len(out), out, cut, l.steps, took)
	}
	for _, c := range []struct {
		hops  int
		found bool
	}{{maxLinkHops - 1, true}, {maxLinkHops, false}} {
		ws := t.TempDir()
		os.MkdirAll(filepath.Join(ws, "dotfiles", "vim"), 0o700)
		for i := range c.hops - 1 {
			os.Symlink(fmt.Sprintf("h%d", i+1), filepath.Join(ws, fmt.Sprintf("h%d", i)))
		}
		os.Symlink(filepath.Join("dotfiles", "vim"), filepath.Join(ws, fmt.Sprintf("h%d", c.hops-1)))
		os.Symlink("h0", filepath.Join(ws, ".vim")) // .vim, then c.hops links more
		out, cut := (&Server{wsReal: ws}).newLook().run()
		if found := slices.ContainsFunc(out, func(l ruleList) bool { return l.link == ".vim" }); found != c.found || cut != "" {
			t.Errorf(".vim through %d more links: found %v (%+v), stopped short %q", c.hops, found, out, cut)
		}
	}
}

// A link whose target is outside the workspace is not followed: what it
// leads to is not in the workspace, unless through a further link out there,
// which the look does not follow.
func TestLinkThroughOneOutsideFollowed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks needs a privilege on Windows")
	}
	t.Setenv("HOME", t.TempDir())
	ws, out := t.TempDir(), t.TempDir()
	os.MkdirAll(filepath.Join(ws, "plugins"), 0o700)
	os.MkdirAll(filepath.Join(ws, "dotfiles", "nvim"), 0o700)
	os.Symlink(filepath.Join(ws, "plugins"), filepath.Join(out, "back"))
	os.Symlink(filepath.Join(out, "back"), filepath.Join(ws, ".vim"))
	os.MkdirAll(filepath.Join(ws, ".config"), 0o700)
	os.Symlink(filepath.Join(ws, "dotfiles", "nvim"), filepath.Join(ws, ".config", "nvim"))
	got, cut := (&Server{wsReal: ws}).newLook().run()
	links := map[string]bool{}
	for _, p := range got {
		links[p.link] = true
	}
	if cut != "" || len(got) != 2 || !links[".vim"] || !links[filepath.Join(".config", "nvim")] {
		t.Errorf("places %+v, stopped short %q", got, cut)
	}
}

// The names under the home directory that a rule names are found under
// every spelling the rule matches, as rules match without case: on a
// case-sensitive file system ~/.config/Code, ~/.config/Cursor and
// ~/.config/Claude are VS Code's, Cursor's and Claude Desktop's, linked into
// the workspace by a dotfiles setup.
func TestHomeNamesInAnyCase(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks needs a privilege on Windows")
	}
	ws, home := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	os.MkdirAll(filepath.Join(home, ".config"), 0o700)
	names := map[string]string{".config/Code": "vscode", ".config/Cursor": "cursor", ".config/Claude": "claude",
		".config/Windsurf": "windsurf", ".config/VSCodium": "codium", ".config/Code - Insiders": "insiders", ".config/nvim": "nvim"}
	for name, target := range names {
		os.MkdirAll(filepath.Join(ws, target), 0o700)
		if err := os.Symlink(filepath.Join(ws, target), filepath.Join(home, filepath.FromSlash(name))); err != nil {
			t.Fatal(err)
		}
	}
	got, cut := (&Server{wsReal: ws}).newLook().run()
	for name, target := range names {
		if !slices.ContainsFunc(got, func(l ruleList) bool { return slices.Contains(l.rules, treeRule(filepath.Join(ws, target))) }) {
			t.Errorf("~/%s, a link to %s: not seen among %+v (stopped short %q)", name, target, got, cut)
		}
	}
}

// The look reads dot directories before the others at each depth, and plain
// files cost it only their reading: a picture folder of more files than
// aliasEntries, read first, keeps it from no link in ~/.config.
func TestLookReadsDotDirectoriesFirst(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks needs a privilege on Windows")
	}
	ws := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	for _, d := range []string{"dotfiles/nvim", "Pictures", ".config"} {
		os.MkdirAll(filepath.Join(ws, d), 0o700)
	}
	os.Symlink("../dotfiles/nvim", filepath.Join(ws, ".config", "nvim"))
	for i := range aliasEntries + 100 {
		os.WriteFile(filepath.Join(ws, "Pictures", fmt.Sprintf("IMG_%05d.jpg", i)), nil, 0o600)
	}
	defer func(open func(string) (lookDir, error)) { openLookDir = open }(openLookDir)
	var opened []string
	openLookDir = func(p string) (lookDir, error) {
		opened = append(opened, p)
		return os.Open(p)
	}
	got, cut := (&Server{wsReal: ws}).newLook().run()
	if len(got) != 1 || got[0].link != filepath.Join(".config", "nvim") || cut != "" {
		t.Errorf("places %+v, stopped short %q", got, cut)
	}
	if i, j := slices.Index(opened, filepath.Join(ws, ".config")), slices.Index(opened, filepath.Join(ws, "Pictures")); i < 0 || j < 0 || i > j {
		t.Errorf("the look read %q", opened)
	}
}

// On macOS the system asks the user before a program reads the home
// directory's Desktop, Documents and Downloads, and iCloud Drive's or other
// apps' data: with the home directory as the workspace, the look reads none
// of them, nor the media folders, and so never makes it ask. It still reads
// ~/Library's LaunchAgents, where a link to a file the workspace holds would
// run at the next login. A workspace inside such a folder is read as usual.
func TestLookSkipsFoldersMacOSAsksAbout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks needs a privilege on Windows")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, d := range []string{"Desktop/proj", "Documents/proj", "Downloads", "Pictures", "Movies", "Music",
		"Library/Mobile Documents/com~apple~CloudDocs", "Library/Containers/x", "Library/Group Containers/x",
		"Library/LaunchAgents", "dotfiles", "src/app"} {
		os.MkdirAll(filepath.Join(home, filepath.FromSlash(d)), 0o700)
	}
	os.Symlink("../../dotfiles/agent.plist", filepath.Join(home, "Library", "LaunchAgents", "x.plist"))
	defer func(open func(string) (lookDir, error), asks bool) { openLookDir, macAsks = open, asks }(openLookDir, macAsks)
	macAsks = true
	var opened []string
	openLookDir = func(p string) (lookDir, error) {
		opened = append(opened, p)
		return os.Open(p)
	}
	got, _ := (&Server{wsReal: home}).newLook().run()
	for _, d := range []string{"Desktop", "Documents", "Downloads", "Pictures", "Movies", "Music", "Library/Mobile Documents",
		"Library/Containers", "Library/Group Containers"} {
		if slices.ContainsFunc(opened, func(p string) bool { return within(p, filepath.Join(home, filepath.FromSlash(d))) }) {
			t.Errorf("the look read ~/%s", d)
		}
	}
	if !slices.ContainsFunc(got, func(l ruleList) bool {
		return slices.Contains(l.rules, treeRule(filepath.Join(home, "dotfiles", "agent.plist")))
	}) {
		t.Errorf("the LaunchAgents link was not seen: %+v", got)
	}
	opened = nil
	docs := filepath.Join(home, "Documents", "proj")
	(&Server{wsReal: docs}).newLook().run()
	if !slices.Contains(opened, docs) {
		t.Errorf("a workspace in ~/Documents was not read: %q", opened)
	}
}
