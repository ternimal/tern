// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"archive/zip"
	"bytes"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"
)

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, text := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEscapeSpellsUpperCaseAsTheModuleCacheDoes(t *testing.T) {
	for in, want := range map[string]string{
		"golang.org/x/sys":           "golang.org/x/sys",
		"github.com/BurntSushi/toml": "github.com/!burnt!sushi/toml",
		"v1.0.0-RC1":                 "v1.0.0-!r!c1",
	} {
		if got, err := escape(in); err != nil || got != want {
			t.Errorf("escape(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"a!b", "caf\u00e9", "a\nb"} {
		if got, err := escape(bad); err == nil {
			t.Errorf("escape(%q) = %q, want an error", bad, got)
		}
	}
}

func TestLicenseFilesComeFirstThenNoticesPatentsAuthors(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"AUTHORS": "a", "PATENTS": "p", "NOTICE.txt": "n", "LICENSE.md": "l",
		"COPYING": "c", "license-mit": "m", "README.md": "r", "go.mod": "g",
		"LICENSES/MIT.txt": "a directory is not a license file",
	})
	got, err := licenseFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range got {
		names = append(names, filepath.Base(p))
	}
	want := []string{"COPYING", "LICENSE.md", "license-mit", "NOTICE.txt", "PATENTS", "AUTHORS"}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("got %q, want %q", names, want)
	}
}

func TestModuleWithoutALicenseFileIsAnError(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"NOTICE": "n", "README.md": "MIT licensed"})
	if _, err := licenseFiles(dir); err == nil || !strings.Contains(err.Error(), "no license file") {
		t.Errorf("got %v, want a no-license error", err)
	}
	cache := t.TempDir()
	writeFiles(t, cache, map[string]string{"example.com/bare@v1.0.0/README.md": "no license"})
	goroot := t.TempDir()
	writeFiles(t, goroot, map[string]string{"LICENSE": "go"})
	mods, err := locate([]*debug.Module{{Path: "example.com/bare", Version: "v1.0.0"}}, cache)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := noticesText([]string{"tern"}, "linux/amd64", "go1.26.9", goroot, mods, nil); err == nil || !strings.Contains(err.Error(), "example.com/bare v1.0.0") {
		t.Errorf("got %v, want an error naming the module", err)
	}
}

func TestNoticesListEveryModuleAndCarryItsLicenseTexts(t *testing.T) {
	goroot := t.TempDir()
	writeFiles(t, goroot, map[string]string{"LICENSE": "Go license\r\nline two\r\n", "PATENTS": "Go patents\n", "README.md": "not a license"})
	cache := t.TempDir()
	writeFiles(t, cache, map[string]string{
		"github.com/b/two@v1.0.0/LICENSE":         "two license\n\n",
		"github.com/!a/one@v0.1.0/LICENSE":        "\none license\n",
		"github.com/!a/one@v0.1.0/NOTICE":         "one notice\n",
		"example.com/new@v1.2.0/COPYING":          "new copying\n",
		"example.com/old@v1.0.0/LICENSE":          "the replaced module's own license must not appear\n",
		"github.com/b/two@v1.0.0/sub/LICENSE":     "a nested license is not read\n",
		"github.com/!a/one@v0.1.0/doc/LICENSE.md": "neither is this one\n",
	})
	extra := t.TempDir()
	writeFiles(t, extra, map[string]string{"NOTICE": "C start files notice\n"})

	// Deliberately unsorted, as several binaries' build information can give them.
	deps := []*debug.Module{
		{Path: "github.com/b/two", Version: "v1.0.0"},
		{Path: "github.com/A/one", Version: "v0.1.0"},
		{Path: "example.com/old", Version: "v1.0.0", Replace: &debug.Module{Path: "example.com/new", Version: "v1.2.0"}},
	}
	mods, err := locate(deps, cache)
	if err != nil {
		t.Fatal(err)
	}
	got, err := noticesText([]string{"tern", "ternd"}, "linux/amd64", "go1.26.9", goroot, mods,
		notices{{"C start files", filepath.Join(extra, "NOTICE")}})
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)

	for _, want := range []string{
		"Binaries: tern, ternd (built for linux/amd64)",
		"  Go standard library  go1.26.9\n  example.com/old      v1.0.0\n  github.com/A/one     v0.1.0\n  github.com/b/two     v1.0.0\n  C start files\n",
		rule + "\nGo standard library go1.26.9\nSource: https://go.dev/dl/go1.26.9.src.tar.gz\n\n--- LICENSE ---\n\nGo license\nline two\n\n--- PATENTS ---\n\nGo patents\n",
		rule + "\nexample.com/old v1.0.0, replaced by example.com/new v1.2.0\nSource: https://proxy.golang.org/example.com/new/@v/v1.2.0.zip\n\n--- COPYING ---\n\nnew copying\n",
		rule + "\ngithub.com/A/one v0.1.0\nSource: https://proxy.golang.org/github.com/!a/one/@v/v0.1.0.zip\n\n--- LICENSE ---\n\none license\n\n--- NOTICE ---\n\none notice\n",
		rule + "\ngithub.com/b/two v1.0.0\nSource: https://proxy.golang.org/github.com/b/two/@v/v1.0.0.zip\n\n--- LICENSE ---\n\ntwo license\n",
		rule + "\nC start files\n\n--- NOTICE ---\n\nC start files notice\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("notices lack %q:\n%s", want, text)
		}
	}
	for _, unwanted := range []string{"\r", "must not appear", "nested", "neither", "not a license"} {
		if strings.Contains(text, unwanted) {
			t.Errorf("notices hold %q:\n%s", unwanted, text)
		}
	}
	if i, j := strings.Index(text, "\ngithub.com/A/one v0.1.0\n"), strings.Index(text, "\ngithub.com/b/two v1.0.0\n"); i < 0 || j < i {
		t.Errorf("sections are not in path order:\n%s", text)
	}
	if !strings.HasSuffix(text, "notice\n") || strings.HasSuffix(text, "\n\n") {
		t.Errorf("notices should end with one line break:\n%q", text[max(0, len(text)-40):])
	}
}

func TestZipIsTheSameForTheSameInputs(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"tern": "binary one", "ternd": "binary two", "LICENSE": "license text"})
	entries := []entry{
		{name: "tern", mode: 0o755, src: filepath.Join(dir, "tern")},
		{name: "ternd", mode: 0o755, src: filepath.Join(dir, "ternd")},
		{name: "LICENSE", mode: 0o644, src: filepath.Join(dir, "LICENSE")},
		{name: noticesName, mode: 0o644, data: []byte("notices")},
	}
	when := time.Unix(1760000000, 0).UTC()
	first := filepath.Join(dir, "first.zip")
	if err := writeZip(first, when, entries); err != nil {
		t.Fatal(err)
	}

	// What a rebuild changes on disk must not reach the zip: file times, modes.
	later := time.Now().Add(time.Hour)
	for _, n := range []string{"tern", "ternd", "LICENSE"} {
		p := filepath.Join(dir, n)
		if err := os.Chtimes(p, later, later); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	second := filepath.Join(dir, "second.zip")
	if err := writeZip(second, when, entries); err != nil {
		t.Fatal(err)
	}
	a, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("the same entries packed to different bytes")
	}

	zr, err := zip.NewReader(bytes.NewReader(a), int64(len(a)))
	if err != nil {
		t.Fatal(err)
	}
	if len(zr.File) != len(entries) {
		t.Fatalf("zip holds %d files, want %d", len(zr.File), len(entries))
	}
	for i, f := range zr.File {
		e := entries[i]
		if f.Name != e.name {
			t.Errorf("file %d is %s, want %s", i, f.Name, e.name)
		}
		if runtime.GOOS != "windows" && f.Mode() != e.mode {
			t.Errorf("%s has mode %v, want %v", f.Name, f.Mode(), e.mode)
		}
		if !f.Modified.Equal(when) {
			t.Errorf("%s is dated %v, want %v", f.Name, f.Modified, when)
		}
		if f.Method != zip.Deflate {
			t.Errorf("%s is not deflated", f.Name)
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		want := e.data
		if e.src != "" {
			if want, err = os.ReadFile(e.src); err != nil {
				t.Fatal(err)
			}
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s holds %q, want %q", f.Name, got, want)
		}
	}
}

func TestZipRefusesTwoFilesOfOneNameAndLeavesNothing(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "x.zip")
	err := writeZip(out, time.Unix(zipEpoch, 0).UTC(), []entry{{name: "a", mode: 0o644, data: []byte("1")}, {name: "a", mode: 0o644, data: []byte("2")}})
	if err == nil {
		t.Fatal("two files named a were packed")
	}
	left, _ := os.ReadDir(dir)
	if len(left) != 0 {
		t.Errorf("left %v behind", left)
	}
}

func TestPackReadsTheBinaryBuildInformation(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	gover, platform, _, err := linked([]string{exe})
	if err != nil {
		t.Fatal(err)
	}
	if gover != runtime.Version() || platform != runtime.GOOS+"/"+runtime.GOARCH {
		t.Errorf("got %s for %s, want %s for %s/%s", gover, platform, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	}

	dir := t.TempDir()
	goroot := filepath.Join(dir, "goroot")
	writeFiles(t, goroot, map[string]string{"LICENSE": "Go license\n"})
	writeFiles(t, dir, map[string]string{"LICENSE": "AGPL\n", "NOTICE": "Ternimal notice\n"})
	out := filepath.Join(dir, "out.zip")
	err = pack(out, time.Unix(zipEpoch, 0).UTC(), goroot, filepath.Join(dir, "modcache"), []string{exe},
		[]string{filepath.Join(dir, "LICENSE"), filepath.Join(dir, "NOTICE")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.OpenReader(out)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	var names []string
	for _, f := range zr.File {
		names = append(names, f.Name)
	}
	want := []string{filepath.Base(exe), "LICENSE", "NOTICE", noticesName}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("zip holds %q, want %q", names, want)
	}
	if runtime.GOOS != "windows" && zr.File[0].Mode() != fs.FileMode(0o755) {
		t.Errorf("the binary has mode %v", zr.File[0].Mode())
	}

	if _, _, _, err := linked([]string{filepath.Join(dir, "LICENSE")}); err == nil {
		t.Error("a text file was read as a Go binary")
	}
}
