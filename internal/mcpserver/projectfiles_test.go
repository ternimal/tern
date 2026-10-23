// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	tern "github.com/ternimal/tern/internal/tern"
)

// newFileAgent is newStackAgent for tests that only move files, which run
// on Windows too.
func newFileAgent(t *testing.T) *stackAgent {
	t.Helper()
	shell := "/bin/sh"
	if runtime.GOOS == "windows" {
		shell = "cmd.exe"
	}
	cert, err := tern.LoadOrCreateCert(filepath.Join(t.TempDir(), "agent"))
	if err != nil {
		t.Fatal(err)
	}
	return &stackAgent{
		agent: tern.NewAgent(tern.ServerTLSConfig(cert), &tern.AuthConfig{Token: stackToken}, shell, time.Minute, ""),
		fp:    tern.CertFingerprint(cert),
	}
}

// pathRule is the rule for every path under dir, an absolute local path, as
// a profile writes it: /c:/... on Windows.
func pathRule(dir string) string {
	if v := filepath.VolumeName(dir); len(v) == 2 && v[1] == ':' {
		return "/" + strings.ToLower(filepath.ToSlash(dir)) + "/**"
	}
	return filepath.ToSlash(dir) + "/**"
}

// A repository's .git, a directory or a file that names one, is never made
// nor written, nor anything in it: git takes its config and hooks from
// where those files say (a gitdir file, commondir), so downloads that put a
// .git/commondir in a project, or a .git file in a directory that is not a
// repository yet, and a config elsewhere, would make the next git command
// there, which shells' prompts and editors run, run a command. The same in
// bare repositories (commondir), and for Mercurial, Jujutsu and Sapling.
// .gitignore and .gitattributes stay writable.
func TestRepositoryMetadataNeverWritten(t *testing.T) {
	p := mustPol(t, ProfileConfig{WritePaths: []string{"/**", "/c:/**"}})
	for _, path := range []string{"/srv/app/.git/commondir", "/srv/app/sub/.git", "/srv/app/.git", "/srv/app/.git/info/exclude",
		"/srv/app/.git/objects/info/alternates", "/srv/app/.git/worktrees/w/commondir", "/srv/git/site.git/commondir",
		"/srv/app/.gitmodules", "/srv/app/.hg/hgrc", "/srv/app/.hg", "/srv/app/.hg/sharedpath", "/srv/app/.jj/repo/config.toml",
		"/srv/app/.sl/config", `C:\src\app\.git\commondir`, `C:\src\app\.GIT\config`, "/srv/cache/HEAD",
		"/srv/cache/head", `C:\src\cache\HEAD`, "/home/u/.cfg/commondir"} {
		if _, ok, why := p.CheckWrite(path); ok || !strings.Contains(why, "persistence-point rule") {
			t.Errorf("CheckWrite(%q) = %v, %q", path, ok, why)
		}
	}
	for _, path := range []string{"/srv/app/.gitignore", "/srv/app/.gitattributes", "/srv/app/src/x.git.txt", "/srv/app/gitdir/x",
		"/srv/app/.github/workflows/ci.yml"} {
		if _, ok, why := p.CheckWrite(path); !ok {
			t.Errorf("CheckWrite(%q) refused: %s", path, why)
		}
	}
	a := newStackAgent(t)
	ws, remote := t.TempDir(), t.TempDir()
	marker := filepath.Join(t.TempDir(), "planted")
	proj, other := filepath.Join(ws, "proj"), filepath.Join(ws, "other")
	os.MkdirAll(other, 0o700)
	git, err := exec.LookPath("git")
	if err == nil {
		for _, args := range [][]string{{"init", "-q", proj}, {"-C", proj, "-c", "user.email=a@b", "-c", "user.name=a", "commit", "-q", "--allow-empty", "-m", "x"}} {
			if out, err := exec.Command(git, args...).CombinedOutput(); err != nil {
				t.Fatalf("git %v: %v %s", args, err, out)
			}
		}
	}
	for name, body := range map[string]string{"commondir": "../.cache-x\n", "gitfile": "gitdir: .cache-x\n", "head": "ref: refs/heads/main\n",
		"config": "[core]\n\trepositoryformatversion = 0\n\tfsmonitor = \"touch " + marker + "\"\n", "empty": "", "hgrc": "[hooks]\nprecommit = touch " + marker + "\n"} {
		os.WriteFile(filepath.Join(remote, name), []byte(body), 0o644)
	}
	srv, _ := stackServer(t, a, ProfileConfig{ReadPaths: []string{remote + "/**"}}, func(c *Config) { c.Workspace = ws })
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	for _, d := range []struct{ remote, local string }{
		{"commondir", "proj/.git/commondir"}, {"gitfile", "other/.git"}, {"config", "other/.git/config"}, {"hgrc", "other/.hg/hgrc"},
		{"commondir", "bare.git/commondir"}, {"head", "other/.cache-x/HEAD"}, {"head", "plant/HEAD"},
	} {
		why := call(t, cs, "download", map[string]any{"remote": remote + "/" + d.remote, "local": d.local}, nil, true)
		if !strings.Contains(why, "persistence-point rule") || !strings.Contains(why, "never creates") {
			t.Errorf("download to %s: %s", d.local, why)
		}
	}
	// What the rest of such a redirection would need lands, as ordinary files.
	for _, d := range []struct{ remote, local string }{
		{"config", "proj/.cache-x/config"}, {"empty", "proj/.cache-x/objects/.keep"}, {"empty", "proj/.cache-x/refs/.keep"},
		{"config", "other/.cache-x/config"}, {"empty", "other/.cache-x/objects/.keep"},
		{"empty", "other/.cache-x/refs/.keep"}, {"config", "plant/config"}, {"empty", "plant/objects/.keep"},
		{"empty", "plant/refs/.keep"},
	} {
		call(t, cs, "download", map[string]any{"remote": remote + "/" + d.remote, "local": d.local}, nil, false)
	}
	if git == "" {
		return
	}
	// A directory with a config, objects/ and refs/ but no HEAD is no bare
	// repository to git.
	for _, dir := range []string{proj, other, filepath.Join(ws, "plant")} {
		out, _ := exec.Command(git, "-C", dir, "status", "--short").CombinedOutput()
		if _, err := os.Stat(marker); err == nil {
			t.Errorf("git status in %s ran the downloaded config's command: %s", filepath.Base(dir), out)
		}
	}
}

// The project files that a tool runs code from at its next run are never
// written nor created by a download: Yarn's yarn-path and plugins, pnpm's
// and Bun's hooks, pre-commit's hooks, the Gradle and Maven wrappers and
// Maven's extensions, dev containers, JetBrains' run configurations,
// bazelisk's URL, husky's hooks, Cargo's config and ripgrep's. The files the
// same tools only read stay writable.
func TestProjectToolFilesNeverWritten(t *testing.T) {
	files := []string{".yarnrc", ".yarn/plugins/x.cjs", ".yarn/releases/yarn-4.cjs", ".pnpmfile.cjs", ".pnpmfile.mjs",
		"bunfig.toml", ".bunfig.toml", ".pre-commit-config.yaml", ".pre-commit-config.yml", "gradle/wrapper/gradle-wrapper.properties",
		"gradle/wrapper/gradle-wrapper.jar", ".mvn/extensions.xml", ".mvn/wrapper/maven-wrapper.properties", ".mvn/jvm.config",
		".devcontainer/devcontainer.json", ".devcontainer.json", ".idea/workspace.xml", ".idea/runConfigurations/x.xml",
		".bazeliskrc", ".husky/pre-commit", ".cargo/config.toml", ".ripgreprc", ".gitmodules"}
	p := mustPol(t, ProfileConfig{WritePaths: []string{"/**"}})
	for _, f := range files {
		if _, ok, why := p.CheckWrite("/srv/app/" + f); ok || !strings.Contains(why, "persistence-point rule") {
			t.Errorf("CheckWrite(/srv/app/%s) = %v, %q", f, ok, why)
		}
	}
	plain := []string{"package.json", "yarn.lock", "pnpm-lock.yaml", "gradle/libs.versions.toml", "pom.xml", "src/idea.txt",
		"docs/devcontainer.md", "Cargo.toml"}
	for _, f := range plain {
		if _, ok, why := p.CheckWrite("/srv/app/" + f); !ok {
			t.Errorf("CheckWrite(/srv/app/%s) refused: %s", f, why)
		}
	}
	a := newStackAgent(t)
	ws, remote := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(remote, "payload"), []byte("x\n"), 0o644)
	srv, _ := stackServer(t, a, ProfileConfig{ReadPaths: []string{remote + "/**"}}, func(c *Config) { c.Workspace = ws })
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	for _, f := range files {
		why := call(t, cs, "download", map[string]any{"remote": remote + "/payload", "local": "proj/" + f}, nil, true)
		if !strings.Contains(why, "never creates") {
			t.Errorf("download to proj/%s: %s", f, why)
		}
	}
	for _, f := range plain {
		call(t, cs, "download", map[string]any{"remote": remote + "/payload", "local": "proj/" + f}, nil, false)
	}
}

// A local name that a system may open as another is refused before anything
// is read or made, on every system, since a workspace may be on any file
// system: Windows drops trailing dots and spaces, so on a Windows workspace
// ".claude.\settings.local.json" would land in .claude, which the rules do
// not see under that name, and an upload of ".claude.\settings.json" would
// send Claude Code's settings; Windows takes CLAUDE~1 for the short name of
// .claude, a ':' for a data stream; a case-insensitive file system may take
// "..\u200d" for "..".
func TestLocalNamesOpenedAsOthersRefused(t *testing.T) {
	a := newFileAgent(t)
	ws, remote := t.TempDir(), longTempDir(t)
	os.WriteFile(filepath.Join(remote, "payload"), []byte(`{"hooks":{}}`+"\n"), 0o644)
	os.MkdirAll(filepath.Join(ws, ".claude"), 0o700)
	os.WriteFile(filepath.Join(ws, ".claude", "settings.json"), []byte(`{"env":{"TERN_TOKEN":"FakeToken0123456789"}}`+"\n"), 0o600)
	os.WriteFile(filepath.Join(ws, "CLAUDE.md"), []byte("notes\n"), 0o600)
	srv, _ := stackServer(t, a, ProfileConfig{ReadPaths: []string{pathRule(remote)}, WritePaths: []string{pathRule(remote)}},
		func(c *Config) { c.Workspace = ws })
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	names := []string{filepath.Join("x", "..\u200d", "y")}
	if runtime.GOOS == "windows" {
		names = append(names, filepath.Join(".claude.", "settings.local.json"), filepath.Join(".claude ", "settings.local.json"),
			"CLAUDE.md.", ".mcp.json ", filepath.Join("CLAUDE~1", "settings.local.json"), "notes.txt::$DATA",
			"notes.txt:hidden", "nul", filepath.Join("logs", "con.txt"))
	}
	for _, local := range names {
		why := call(t, cs, "download", map[string]any{"remote": filepath.Join(remote, "payload"), "local": local}, nil, true)
		if !strings.Contains(why, "local path") {
			t.Errorf("download to %q: %s", local, why)
		}
	}
	if runtime.GOOS == "windows" {
		for _, local := range []string{filepath.Join(".claude.", "settings.json"), "CLAUDE.md "} {
			why := call(t, cs, "upload", map[string]any{"local": local, "remote": filepath.Join(remote, "sent")}, nil, true)
			if !strings.Contains(why, "local path") {
				t.Errorf("upload of %q: %s", local, why)
			}
		}
	} else {
		// Elsewhere such names are names of their own, as Perl's man pages
		// and plenty of other files have them.
		for _, local := range []string{filepath.Join("blib", "man3", "JSON::PP.3pm"), "a~1.txt", "notes."} {
			call(t, cs, "download", map[string]any{"remote": filepath.Join(remote, "payload"), "local": local}, nil, false)
		}
	}
	if _, err := os.Lstat(filepath.Join(remote, "sent")); err == nil {
		t.Error("an upload under another name reached the agent")
	}
	for _, p := range []string{filepath.Join(ws, ".claude", "settings.local.json"), filepath.Join(ws, ".mcp.json")} {
		if _, err := os.Lstat(p); err == nil {
			t.Errorf("a download made %s", p)
		}
	}
	call(t, cs, "download", map[string]any{"remote": filepath.Join(remote, "payload"), "local": filepath.Join("notes", "payload.json")}, nil, false)
}
