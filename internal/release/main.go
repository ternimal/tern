// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

// Command release packs one platform's zip for `make release`: the binaries,
// text files such as LICENSE and NOTICE, and a THIRD_PARTY_NOTICES.txt written
// from the build information in the binaries. That file holds the license
// files of the Go standard library and of every module linked into any of the
// binaries, read from GOROOT and the module cache, so nothing is downloaded.
// The entries go in the order given, with fixed modes and one fixed time, so
// the same inputs always pack to the same bytes.
//
//	go run ./internal/release -o ZIP -goroot DIR -modcache DIR [-mtime SECONDS]
//	    [-text FILE,...] [-notice TITLE=FILE]... BINARY...
package main

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"debug/buildinfo"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"time"
)

// zipEpoch is the earliest time a zip entry can carry: MS-DOS dates start at
// 1980-01-01.
const zipEpoch = 315532800

const noticesName = "THIRD_PARTY_NOTICES.txt"

const rule = "================================================================================"

const preamble = `Besides Ternimal's own code (AGPL-3.0-only, see LICENSE and NOTICE), these
binaries contain code from the projects listed below, each under its own
license, reproduced in full further down. The source of the Go standard
library is at https://go.dev/dl/, and that of each Go module at the
proxy.golang.org address given with it.
`

// A module is a Go module linked into a binary.
type module struct {
	path, version string // as the build information names it
	replaced      string // what go.mod replaced it with, or ""
	dir           string // where its files are
	source        string // where to download its source, or ""
}

// A notice is a file of license terms for code the build information does not
// list, such as C files a cgo build links in.
type notice struct{ title, file string }

type notices []notice

func (n *notices) String() string { return fmt.Sprint(*n) }

func (n *notices) Set(s string) error {
	title, file, ok := strings.Cut(s, "=")
	if !ok || title == "" || file == "" {
		return fmt.Errorf("want TITLE=FILE, got %q", s)
	}
	*n = append(*n, notice{title, file})
	return nil
}

// An entry is a file in the zip: copied from src, or holding data.
type entry struct {
	name string
	mode fs.FileMode
	src  string
	data []byte
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("release: ")
	out := flag.String("o", "", "the zip file to write")
	mtime := flag.Int64("mtime", 0, "time of every entry, in seconds since 1970; a time before 1980 means 1980-01-01")
	goroot := flag.String("goroot", "", "GOROOT of the toolchain that built the binaries (go env GOROOT)")
	modcache := flag.String("modcache", "", "module cache the binaries were built from (go env GOMODCACHE)")
	text := flag.String("text", "", "comma-separated files to add as they are, such as LICENSE,NOTICE")
	var extra notices
	flag.Var(&extra, "notice", "TITLE=FILE: add FILE to the notices under TITLE, for code the build information does not list (repeatable)")
	flag.Usage = func() {
		fmt.Fprintln(flag.CommandLine.Output(), "usage: go run ./internal/release -o ZIP -goroot DIR -modcache DIR [flags] BINARY...")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *out == "" || *goroot == "" || *modcache == "" || flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}
	var texts []string
	for _, t := range strings.Split(*text, ",") {
		if t = strings.TrimSpace(t); t != "" {
			texts = append(texts, t)
		}
	}
	t := time.Unix(max(*mtime, zipEpoch), 0).UTC()
	if err := pack(*out, t, *goroot, *modcache, flag.Args(), texts, extra); err != nil {
		log.Fatal(err)
	}
}

// pack writes the zip: the binaries, then the text files, then the notices.
func pack(out string, t time.Time, goroot, modcache string, bins, texts []string, extra notices) error {
	gover, platform, deps, err := linked(bins)
	if err != nil {
		return err
	}
	mods, err := locate(deps, modcache)
	if err != nil {
		return err
	}
	var names []string
	var entries []entry
	for _, b := range bins {
		names = append(names, filepath.Base(b))
		entries = append(entries, entry{name: filepath.Base(b), mode: 0o755, src: b})
	}
	for _, f := range texts {
		entries = append(entries, entry{name: filepath.Base(f), mode: 0o644, src: f})
	}
	text, err := noticesText(names, platform, gover, goroot, mods, extra)
	if err != nil {
		return err
	}
	entries = append(entries, entry{name: noticesName, mode: 0o644, data: text})
	return writeZip(out, t, entries)
}

// linked reads the build information of the binaries: the Go version and the
// platform they were built with, the same for all of them, and every module
// linked into any of them, once.
func linked(bins []string) (gover, platform string, deps []*debug.Module, err error) {
	seen := map[string]bool{}
	for i, b := range bins {
		bi, err := buildinfo.ReadFile(b)
		if err != nil {
			return "", "", nil, err
		}
		var goos, goarch string
		for _, s := range bi.Settings {
			switch s.Key {
			case "GOOS":
				goos = s.Value
			case "GOARCH":
				goarch = s.Value
			}
		}
		p := goos + "/" + goarch
		if i == 0 {
			gover, platform = bi.GoVersion, p
		} else if bi.GoVersion != gover || p != platform {
			return "", "", nil, fmt.Errorf("%s was built with %s for %s, but %s with %s for %s", b, bi.GoVersion, p, bins[0], gover, platform)
		}
		for _, d := range bi.Deps {
			k := d.Path + "@" + d.Version
			if d.Replace != nil {
				k += "=>" + d.Replace.Path + "@" + d.Replace.Version
			}
			if !seen[k] {
				seen[k] = true
				deps = append(deps, d)
			}
		}
	}
	return gover, platform, deps, nil
}

// locate finds the files of each module: in the module cache, or for a module
// that go.mod replaced with a directory, in that directory.
func locate(deps []*debug.Module, modcache string) ([]module, error) {
	var mods []module
	for _, d := range deps {
		m := module{path: d.Path, version: d.Version}
		from := d
		if r := d.Replace; r != nil {
			if r.Version == "" {
				m.replaced = "the directory " + r.Path
				m.dir = filepath.FromSlash(r.Path)
				mods = append(mods, m)
				continue
			}
			m.replaced = r.Path + " " + r.Version
			from = r
		}
		path, err := escape(from.Path)
		if err != nil {
			return nil, err
		}
		version, err := escape(from.Version)
		if err != nil {
			return nil, err
		}
		m.dir = filepath.Join(modcache, filepath.FromSlash(path)+"@"+version)
		m.source = "https://proxy.golang.org/" + path + "/@v/" + version + ".zip"
		mods = append(mods, m)
	}
	return mods, nil
}

// escape spells a module path or version the way the module cache and the
// module proxy do: each upper-case letter becomes '!' and its lower case.
func escape(s string) (string, error) {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '!' || r > '~' || r < ' ':
			return "", fmt.Errorf("%q is not a module path or version", s)
		case 'A' <= r && r <= 'Z':
			b.WriteByte('!')
			b.WriteRune(r - 'A' + 'a')
		default:
			b.WriteRune(r)
		}
	}
	return b.String(), nil
}

// A section of the notices: one project and its license files.
type section struct {
	name, version string   // in the list
	head          []string // the lines that open the section
	files         []string // the files whose text the section holds
}

// noticesText writes THIRD_PARTY_NOTICES.txt: a list of the Go standard
// library, the modules sorted by path and the extra notices, then a section
// for each with the full text of its license files.
func noticesText(bins []string, platform, gover, goroot string, mods []module, extra notices) ([]byte, error) {
	src := "https://go.dev/dl/"
	if v := strings.Fields(gover); len(v) > 0 && strings.HasPrefix(v[0], "go1.") {
		src += v[0] + ".src.tar.gz"
	}
	files, err := licenseFiles(goroot)
	if err != nil {
		return nil, fmt.Errorf("the Go standard library: %v", err)
	}
	secs := []section{{
		name:    "Go standard library",
		version: gover,
		head:    []string{"Go standard library " + gover, "Source: " + src},
		files:   files,
	}}

	mods = append([]module(nil), mods...)
	sort.Slice(mods, func(i, j int) bool {
		if mods[i].path != mods[j].path {
			return mods[i].path < mods[j].path
		}
		return mods[i].version < mods[j].version
	})
	for _, m := range mods {
		files, err := licenseFiles(m.dir)
		if err != nil {
			return nil, fmt.Errorf("module %s %s: %v", m.path, m.version, err)
		}
		head := m.path + " " + m.version
		if m.replaced != "" {
			head += ", replaced by " + m.replaced
		}
		s := section{name: m.path, version: m.version, head: []string{head}, files: files}
		if m.source != "" {
			s.head = append(s.head, "Source: "+m.source)
		}
		secs = append(secs, s)
	}
	for _, n := range extra {
		secs = append(secs, section{name: n.title, head: []string{n.title}, files: []string{n.file}})
	}

	width := 0
	for _, s := range secs {
		if s.version != "" {
			width = max(width, len(s.name))
		}
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "THIRD-PARTY NOTICES\n\nBinaries: %s (built for %s)\n\n%s\n", strings.Join(bins, ", "), platform, preamble)
	for _, s := range secs {
		if s.version == "" {
			fmt.Fprintf(&b, "  %s\n", s.name)
		} else {
			fmt.Fprintf(&b, "  %-*s  %s\n", width, s.name, s.version)
		}
	}
	for _, s := range secs {
		fmt.Fprintf(&b, "\n%s\n%s\n", rule, strings.Join(s.head, "\n"))
		for _, f := range s.files {
			data, err := os.ReadFile(f)
			if err != nil {
				return nil, err
			}
			data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
			data = bytes.TrimRight(bytes.TrimLeft(data, "\n"), " \t\n")
			fmt.Fprintf(&b, "\n--- %s ---\n\n%s\n", filepath.Base(f), data)
		}
	}
	return b.Bytes(), nil
}

// licenseFiles lists the files in dir that carry license terms, licenses first
// (LICENSE, LICENCE or COPYING, also with a suffix such as .md or -MIT), then
// NOTICE, PATENTS and AUTHORS files. A directory with no license is an error.
func licenseFiles(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range ents {
		if e.Type().IsRegular() && licenseRank(e.Name()) >= 0 {
			names = append(names, e.Name())
		}
	}
	sort.Slice(names, func(i, j int) bool {
		if ri, rj := licenseRank(names[i]), licenseRank(names[j]); ri != rj {
			return ri < rj
		}
		return names[i] < names[j]
	})
	if len(names) == 0 || licenseRank(names[0]) != 0 {
		return nil, fmt.Errorf("no license file in %s", dir)
	}
	for i, n := range names {
		names[i] = filepath.Join(dir, n)
	}
	return names, nil
}

// licenseRank orders the names of files with license terms: 0 for a license,
// then NOTICE, PATENTS and AUTHORS; -1 for any other name.
func licenseRank(name string) int {
	stem, _, _ := strings.Cut(strings.ToUpper(name), ".")
	stem, _, _ = strings.Cut(stem, "-")
	stem, _, _ = strings.Cut(stem, "_")
	switch stem {
	case "LICENSE", "LICENCE", "COPYING":
		return 0
	case "NOTICE":
		return 1
	case "PATENTS":
		return 2
	case "AUTHORS":
		return 3
	}
	return -1
}

// writeZip writes the entries to path in the order given, each with its mode
// and the time t, deflated at the best level: the same entries give the same
// bytes. The zip appears at path only once it is complete.
func writeZip(path string, t time.Time, entries []entry) (err error) {
	f, err := os.CreateTemp(filepath.Dir(path), ".release-*.zip")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(f.Name())
		}
	}()
	zw := zip.NewWriter(f)
	zw.RegisterCompressor(zip.Deflate, func(w io.Writer) (io.WriteCloser, error) {
		return flate.NewWriter(w, flate.BestCompression)
	})
	seen := map[string]bool{}
	for _, e := range entries {
		if seen[e.name] {
			return fmt.Errorf("two files named %s", e.name)
		}
		seen[e.name] = true
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate, Modified: t}
		h.SetMode(e.mode)
		w, err := zw.CreateHeader(h)
		if err != nil {
			return err
		}
		if e.src == "" {
			_, err = w.Write(e.data)
		} else {
			err = copyFile(w, e.src)
		}
		if err != nil {
			return err
		}
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if err := f.Chmod(0o644); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func copyFile(w io.Writer, name string) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(w, f)
	return err
}
