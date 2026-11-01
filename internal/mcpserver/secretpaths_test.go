// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A secret-path stem names a file for what it holds, at the ends of a name
// and next to a separator, never as a word inside a longer one: a sweep
// someone called host-credential-sweep.txt, or a source file called
// tokenizer.py, is not a credential store.
func TestSecretStemsMatchStoresNotWords(t *testing.T) {
	all := mustPol(t, ProfileConfig{ReadPaths: []string{"/**"}})
	for _, p := range []string{
		"/srv/credentials", "/srv/credentials.json", "/srv/.credentials", "/srv/aws_credentials",
		"/srv/credentials-prod.json", "/srv/client_secret.json", "/srv/secrets.yaml", "/srv/.secrets",
		"/srv/token", "/srv/token.json", "/srv/access_token", "/srv/token-cache.json", "/srv/app.token",
		"/srv/app/secrets/prod.yaml", "/etc/secret-volume/password", "/run/credentials/app.service/db",
	} {
		if _, ok, why := all.CheckRead(p); ok || !strings.Contains(why, "secret-path rule") {
			t.Errorf("CheckRead(%q) = %v, %q, want a secret-path refusal", p, ok, why)
		}
	}
	for _, p := range []string{
		"/srv/host-credential-sweep.txt", "/srv/tokenizer.py", "/srv/secretary-notes.txt",
		"/srv/credentialing.md", "/srv/notes/secretariat.txt", "/srv/cs/host-credential-sweep.txt",
	} {
		if _, ok, why := all.CheckRead(p); !ok {
			t.Errorf("CheckRead(%q) refused: %q", p, why)
		}
	}
}

// A name says what a file is called, not what it holds, so a download may
// create one the name rules match, in a workspace of its own. What the rules
// name a place for, and the configuration an AI client loads by name, it
// still may not create, and an upload still reads nothing the rules match.
func TestNameRulesDoNotStopADownload(t *testing.T) {
	a := newStackAgent(t)
	home, remote := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(remote, "sweep.txt"), []byte("findings\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	srv, _ := stackServer(t, a, ProfileConfig{ReadPaths: []string{remote + "/**"}, WritePaths: []string{remote + "/**"}},
		func(c *Config) { c.Workspace = home })
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)

	for _, local := range []string{"host-credential-sweep.txt", "cs/credentials.json", "keys/server.pem", ".netrc"} {
		call(t, cs, "download", map[string]any{"remote": remote + "/sweep.txt", "local": local}, nil, false)
		if _, err := os.Stat(filepath.Join(home, local)); err != nil {
			t.Errorf("download to %s: %v", local, err)
		}
	}
	for _, local := range []string{".ssh/id_ed25519", ".mcp.json", "projects/app/mcp.json"} {
		why := call(t, cs, "download", map[string]any{"remote": remote + "/sweep.txt", "local": local}, nil, true)
		if !strings.Contains(why, "rule") {
			t.Errorf("download to %s: %s", local, why)
		}
	}
	// Reading a local file to upload is matched against every rule, so a
	// key in the workspace is still never sent to an agent.
	if err := os.WriteFile(filepath.Join(home, "id_rsa"), []byte("-----BEGIN PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	why := call(t, cs, "upload", map[string]any{"local": "id_rsa", "remote": remote + "/x"}, nil, true)
	if !strings.Contains(why, "secret-path rule") || !strings.Contains(why, "never uploaded") {
		t.Errorf("upload of a key: %s", why)
	}
	// The one the download just created is a plain file, and uploading it
	// back is refused only because of its name, which is the point: the
	// rule still holds for what a local file holds.
	if why := call(t, cs, "upload", map[string]any{"local": "cs/credentials.json", "remote": remote + "/y"}, nil, true); !strings.Contains(why, "secret-path rule") {
		t.Errorf("upload of credentials.json: %s", why)
	}
}

// The config file can name more secret paths and lift the rules for paths of
// its own, server-wide or per profile, and agent_info reports both.
func TestSecretPathsConfig(t *testing.T) {
	pols, err := BuildPolicies(map[string]ProfileConfig{
		"ops": {
			ReadPaths:   []string{"/srv/**"},
			SecretPaths: SecretPathsConfig{Add: []string{"/srv/vault/**"}, Except: []string{"/srv/app/credentials.json", "/srv/app/.mcp.json"}},
		},
		"plain": {ReadPaths: []string{"/srv/**"}},
	}, SecretPathsConfig{Add: []string{"/srv/boxes/**"}, Except: []string{"/srv/sweeps/**"}})
	if err != nil {
		t.Fatal(err)
	}
	ops, plain := pols["ops"], pols["plain"]
	for _, c := range []struct {
		p     *Policy
		path  string
		allow bool
	}{
		{ops, "/srv/vault/db.txt", false},           // added by the profile
		{ops, "/srv/boxes/host.txt", false},         // added server-wide
		{ops, "/srv/app/credentials.json", true},    // the profile's exception
		{ops, "/srv/sweeps/credentials.json", true}, // the server-wide exception
		{ops, "/srv/other/credentials.json", false},
		{plain, "/srv/vault/db.txt", true},    // the profile's addition is its own
		{plain, "/srv/boxes/host.txt", false}, // the server-wide one is not
		{plain, "/srv/app/credentials.json", false},
		{plain, "/srv/sweeps/credentials.json", true},
	} {
		if _, ok, why := c.p.CheckRead(c.path); ok != c.allow {
			t.Errorf("%s CheckRead(%q) = %v, want %v (%s)", c.p.Profile, c.path, ok, c.allow, why)
		}
	}
	// An exception lifts the secret-path rules only: an MCP server list it
	// names is no longer secret, yet stays unwritable as a persistence
	// point, and a path outside the profile's own read paths stays
	// unreadable.
	if _, ok, why := ops.CheckWrite("/srv/app/.mcp.json"); ok || !strings.Contains(why, "persistence-point rule") {
		t.Errorf("CheckWrite of an MCP server list = %v, %q", ok, why)
	}
	if _, ok, _ := ops.CheckRead("/etc/app/credentials.json"); ok {
		t.Error("an exception must not widen the profile's read paths")
	}
	// agent_info says what holds, additions and exceptions included.
	if n := ops.NeverReadable(); !slices.Contains(n, "/srv/vault/**") || !slices.Contains(n, "/srv/boxes/**") {
		t.Errorf("never_readable lacks the added paths: %v", n[len(n)-4:])
	}
	if e := ops.SecretExceptions(); !slices.Contains(e, "/srv/app/credentials.json") || !slices.Contains(e, "/srv/sweeps/**") {
		t.Errorf("secret_exceptions = %v", e)
	}
}

// A pattern that matches every path would lift every secret-path rule, and a
// malformed one is refused as any path pattern is.
func TestSecretPathsConfigRefused(t *testing.T) {
	for _, c := range []struct {
		cfg  SecretPathsConfig
		base SecretPathsConfig
		want string
	}{
		{cfg: SecretPathsConfig{Except: []string{"**"}}, want: "matches every path"},
		{cfg: SecretPathsConfig{Except: []string{"/**"}}, want: "matches every path"},
		{cfg: SecretPathsConfig{Except: []string{"**/*"}}, want: "matches every path"},
		{cfg: SecretPathsConfig{Except: []string{"srv/x"}}, want: "must be absolute"},
		{cfg: SecretPathsConfig{Add: []string{"/srv/../etc/**"}}, want: ".. segment"},
		{base: SecretPathsConfig{Except: []string{"**"}}, want: "matches every path"},
		{base: SecretPathsConfig{Add: []string{"relative/**"}}, want: "must be absolute"},
	} {
		_, err := BuildPolicies(map[string]ProfileConfig{"p": {SecretPaths: c.cfg}}, c.base)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v %+v: %v, want %q", c.cfg, c.base, err, c.want)
		}
	}
	// A profile may still name a credential store of its own to protect.
	if _, err := BuildPolicies(map[string]ProfileConfig{"p": {SecretPaths: SecretPathsConfig{Add: []string{"**/*.myvault"}}}}, SecretPathsConfig{}); err != nil {
		t.Errorf("an added pattern was refused: %v", err)
	}
}

// A server-wide exception holds in the workspace too, where the same rules
// decide what an upload may read.
func TestSecretPathsConfigInWorkspace(t *testing.T) {
	a := newStackAgent(t)
	home, remote := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "credentials.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, _ := stackServer(t, a, ProfileConfig{WritePaths: []string{remote + "/**"}}, func(c *Config) {
		c.Workspace = home
		c.SecretPaths = SecretPathsConfig{Except: []string{"**/credentials.json"}, Add: []string{"**/*.myvault"}}
	})
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	call(t, cs, "upload", map[string]any{"local": "credentials.json", "remote": remote + "/c.json"}, nil, false)

	if err := os.WriteFile(filepath.Join(home, "box.myvault"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if why := call(t, cs, "upload", map[string]any{"local": "box.myvault", "remote": remote + "/v"}, nil, true); !strings.Contains(why, "secret-path rule") {
		t.Errorf("upload of an added secret path: %s", why)
	}
}
