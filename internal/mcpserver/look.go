// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"
)

// The bounds of the look for links that New takes (see lookAsync): links
// at most aliasDepth directories below the workspace, in at most
// aliasEntries directories read, of which at most aliasLinks symbolic links
// are judged, and at most aliasSteps names looked up and links read while
// following the links whose names a rule matches, each path through at most
// maxLinkHops links, as Linux follows them; all within aliasTime. A look
// that reaches one of these bounds stops short, and downloads and uploads
// are refused for the run: a link it did not see could lead where one lands,
// or make a file a secret under another name. Plain files
// cost only the time it takes to read their names.
const (
	aliasDepth   = 3
	aliasEntries = 20000
	aliasLinks   = 1000
	aliasSteps   = 100000
	maxLinkHops  = 40
)

// aliasTime bounds the whole look, which New never waits for longer than
// aliasTime and aliasGrace: a look stuck in a file system that does not
// answer is left behind and counts as stopped short. Tests shorten them.
var (
	aliasTime  = 3 * time.Second
	aliasGrace = 250 * time.Millisecond
)

// openLookDir opens a directory for the look to read, lookLstat looks a name
// up, and mountPoints lists the mount points the system has; tests replace
// them, to make a directory that never answers, see what the look touches,
// and make a mount point anywhere.
var (
	openLookDir = func(p string) (lookDir, error) { return os.Open(p) }
	lookLstat   = os.Lstat
	mountPoints = systemMounts
)

type lookDir interface {
	ReadDir(n int) ([]os.DirEntry, error)
	Close() error
}

// linkLook is one look for links: what it is given, what it found so far,
// and what it has looked up, so that each name is looked up and each link
// read once.
type linkLook struct {
	wsNames   []string // the workspace as configured and with its links resolved
	ternRules []string // rules for tern's own files
	budget    time.Duration
	deadline  time.Time
	open      func(string) (lookDir, error)
	lstatFn   func(string) (fs.FileInfo, error)
	mountList func() []string
	asks      bool // see macAsks

	inside []string        // rules matching every path in the workspace, under each of its names
	home   string          // the home directory, its links resolved; "" when not known
	mounts map[string]bool // mount points the look never steps onto
	steps  int
	stats  map[string]fs.FileMode // the type of each name looked up, or modeMissing
	links  map[string]linkEnd
	found  map[string]bool
	out    []ruleList
	cut    string // why the look stopped short; "" when it did not
}

// modeMissing marks a name that does not exist or cannot be looked up.
const modeMissing = fs.ModeIrregular | fs.ModeTemporary

// linkEnd is where a link leads (dest) and how many links that took, the
// link itself included; or, with ok false, the most links left with which it
// led through too many links or out of the workspace.
type linkEnd struct {
	dest string
	hops int
	ok   bool
}

// lookAsync finds the places in the workspace that a link reaches under a
// name a rule matches, as a dotfiles setup makes ~/.config/nvim, ~/.vim,
// ~/.local/bin or ~/.kube links into a dotfiles directory: a file there runs,
// or is read, as one under the link's name, so the rule holds there too. It
// looks once, at startup: first at the names under the home directory that
// a rule names as a whole, which may be links into the workspace from outside
// it, each under every spelling the rule matches; then at the links in the
// workspace down to aliasDepth directories, breadth first and dot
// directories first, never on another file system. A link is followed
// wherever it leads, out of the workspace and back too, through at most
// maxLinkHops links. A link made later, a deeper one, or one past the bounds
// is not seen, and past the bounds the look stops short.
//
// It runs the look in the background and waits for it at most
// aliasTime and aliasGrace, so that a directory that never answers, such as
// one on a dead network mount, cannot hold startup. It returns the places
// found and why the look stopped short, or "" when it did not.
func (s *Server) lookAsync() ([]ruleList, string) {
	l := s.newLook()
	type result struct {
		out []ruleList
		cut string
	}
	done := make(chan result, 1) // a look left behind never blocks on its result
	go func() {
		out, cut := l.run()
		done <- result{out, cut}
	}()
	t := time.NewTimer(l.budget + aliasGrace)
	defer t.Stop()
	select {
	case r := <-done:
		return r.out, r.cut
	case <-t.C:
		return nil, fmt.Sprintf("did not finish within %v: a directory there, or one a link leads to, did not answer, as an unresponsive network mount does", l.budget)
	}
}

// newLook captures what the look needs from s, touching no file.
func (s *Server) newLook() *linkLook {
	l := &linkLook{ternRules: s.ternDirs, budget: aliasTime, deadline: time.Now().Add(aliasTime), open: openLookDir,
		lstatFn: lookLstat, mountList: mountPoints, asks: macAsks, stats: map[string]fs.FileMode{},
		links: map[string]linkEnd{}, found: map[string]bool{}, mounts: map[string]bool{}}
	for _, n := range []string{s.wsReal, s.wsAbs} {
		if n != "" && !slices.Contains(l.wsNames, n) {
			l.wsNames = append(l.wsNames, n)
		}
	}
	return l
}

// run looks for the places, first under the home directory and then in the
// workspace.
func (l *linkLook) run() ([]ruleList, string) {
	if len(l.wsNames) == 0 {
		return nil, ""
	}
	l.inside = treeRules(l.wsNames)
	if home, err := os.UserHomeDir(); err == nil && filepath.IsAbs(home) {
		if r, err := filepath.EvalSymlinks(home); err == nil {
			home = r
		}
		l.home = home
	}
	for _, m := range l.mountList() {
		// The file systems the workspace and the home directory are on are
		// stepped onto anyway; the look stays off the others.
		if !slices.ContainsFunc(append([]string{l.home}, l.wsNames...), func(p string) bool { return within(p, m) }) {
			l.mounts[m] = true
		}
	}
	l.lookHome()
	if l.cut == "" {
		l.walk(l.wsNames[0])
	}
	return l.out, l.cut
}

// within reports whether p is dir or a path under it.
func within(p, dir string) bool {
	if p == "" || dir == "" {
		return false
	}
	rel, err := filepath.Rel(dir, p)
	return err == nil && !filepath.IsAbs(rel) && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// stop ends the look short for the reason why, the first one given.
func (l *linkLook) stop(why string) {
	if l.cut == "" {
		l.cut = why
	}
}

// alive reports whether the look may go on: it has not stopped short, and
// its time is not up.
func (l *linkLook) alive() bool {
	if l.cut == "" && time.Now().After(l.deadline) {
		l.stop(fmt.Sprintf("did not finish within %v", l.budget))
	}
	return l.cut == ""
}

// step counts a name looked up or a link read, and reports whether the look
// may go on.
func (l *linkLook) step() bool {
	if l.steps >= aliasSteps {
		l.stop(fmt.Sprintf("stopped after %d steps following links", aliasSteps))
	}
	l.steps++
	return l.alive()
}

// lstat returns the type of the name p, an absolute path, looking it up
// once; ok is false when the look may not go on.
func (l *linkLook) lstat(p string) (fs.FileMode, bool) {
	if m, ok := l.stats[p]; ok {
		return m, true
	}
	if !l.step() {
		return 0, false
	}
	m := modeMissing
	if fi, err := l.lstatFn(p); err == nil {
		m = fi.Mode().Type()
	}
	l.stats[p] = m
	return m, true
}

// isLinkMode reports a symbolic link, or on Windows a junction, which Go
// reports as irregular, and not a directory, and which every program
// follows. Other irregular names there, such as a cloud file's placeholder,
// count too; the link they cannot be read as leads to themselves.
func isLinkMode(m fs.FileMode) bool {
	return m&fs.ModeSymlink != 0 ||
		runtime.GOOS == "windows" && m&fs.ModeIrregular != 0 && m&fs.ModeDir == 0 && m != modeMissing
}

// leadsTo returns where p, an absolute local path, leads: the part of it
// that exists with its links followed as the kernel follows them, and the
// rest as written, so that a link that leads to nothing yet leads to where a
// file made under the link's name would land once its target is made. ok is
// false when p passes through more than maxLinkHops links or through a link
// whose target is outside the workspace, or when the look stops short. A
// mount point the look stays off ends the part looked at.
func (l *linkLook) leadsTo(p string) (string, bool) {
	dest, _, ok := l.resolve(p, maxLinkHops)
	return dest, ok
}

// resolve is leadsTo with hops links left to pass through; it also returns
// how many are left. It walks p a name at a time in one buffer, the path so
// far, which holds no link; a string is made only for a name not looked up
// before, which the look keeps.
func (l *linkLook) resolve(p string, hops int) (string, int, bool) {
	vol := filepath.VolumeName(p)
	buf := append(make([]byte, 0, len(p)+64), vol...)
	buf = append(buf, filepath.Separator)
	root := len(buf) // the volume's root ends here
	for rest := p[len(vol):]; ; {
		for rest != "" && os.IsPathSeparator(rest[0]) {
			rest = rest[1:]
		}
		if rest == "" {
			return string(buf), hops, true
		}
		n := 0
		for n < len(rest) && !os.IsPathSeparator(rest[n]) {
			n++
		}
		part := rest[:n]
		rest = rest[n:]
		switch part {
		case ".":
			continue
		case "..":
			i := len(buf) - 1
			for i >= root && !os.IsPathSeparator(buf[i]) {
				i--
			}
			buf = buf[:max(i, root)]
			continue
		}
		if len(buf) > root {
			buf = append(buf, filepath.Separator)
		}
		buf = append(buf, part...)
		m, known := l.stats[string(buf)]
		switch {
		case l.mounts[string(buf)]:
			m = modeMissing
		case !known:
			var ok bool
			if m, ok = l.lstat(string(buf)); !ok {
				return "", 0, false
			}
		}
		switch {
		case m == modeMissing:
			return filepath.Join(string(buf), rest), hops, true
		case !isLinkMode(m):
			continue
		}
		d, left, ok := l.follow(string(buf), hops)
		if !ok {
			return "", 0, false
		}
		buf = append(buf[:0], d...)
		root = len(filepath.VolumeName(d)) + 1
		if len(d) < root { // d is a volume's root, ending in its separator
			root = len(d)
		}
		hops = left
	}
}

// follow returns where the link at link, a path with no link above it,
// leads, with hops links left to pass through, link itself included.
func (l *linkLook) follow(link string, hops int) (string, int, bool) {
	if e, ok := l.links[link]; ok {
		switch {
		case e.ok && e.hops <= hops:
			return e.dest, hops - e.hops, true
		case !e.ok && hops <= e.hops:
			return "", 0, false
		}
	}
	fail := func(left int) (string, int, bool) {
		if e, ok := l.links[link]; !ok || !e.ok && e.hops < left {
			l.links[link] = linkEnd{hops: left}
		}
		return "", 0, false
	}
	if hops == 0 {
		return fail(0)
	}
	if !l.step() {
		return "", 0, false
	}
	target, err := os.Readlink(link)
	if err != nil {
		return link, hops, true // a name that is not a link after all
	}
	target = localTarget(link, target)
	// A target out of the workspace is followed too: through a link there,
	// such as ~/dotfiles to a directory in the workspace, it can lead back.
	d, left, ok := l.resolve(target, hops-1)
	switch {
	case !ok && l.cut != "":
		return "", 0, false
	case !ok:
		return fail(hops)
	}
	l.links[link] = linkEnd{dest: d, hops: hops - left, ok: true}
	return d, left, true
}

// localTarget makes target, what the link at link holds, an absolute path:
// relative to the link's directory, or on Windows, starting with a
// separator, to the root of the link's drive.
func localTarget(link, target string) string {
	switch {
	case filepath.IsAbs(target):
		return target
	case filepath.VolumeName(target) == "" && target != "" && os.IsPathSeparator(target[0]):
		return filepath.VolumeName(link) + target
	}
	return filepath.Dir(link) + string(filepath.Separator) + target
}

// splitLocal splits a local path at its separators, dropping empty parts.
func splitLocal(p string) []string {
	return strings.FieldsFunc(p, func(r rune) bool { return r < 0x80 && os.IsPathSeparator(byte(r)) })
}

// place records where name, a link or a path through one, leads, if that is
// in the workspace, for the rule pat of the given kind that the link's name
// matches; link names the link in messages.
func (l *linkLook) place(link, name, pat, kind string) {
	to, ok := l.leadsTo(name)
	if !ok || to == name {
		return
	}
	keys := ruleKeys(localKey(to))
	if l.found[kind+"\x00"+to] || !slices.ContainsFunc(l.inside, func(r string) bool { return ruleMatches(r, keys) }) {
		return
	}
	l.found[kind+"\x00"+to] = true
	l.out = append(l.out, ruleList{rules: []string{treeRule(to)}, kind: kind, link: link, rule: pat})
}

// homeNode is a name under the home directory on the way to one a rule names
// as a whole (see homeNames), with the rules that name it.
type homeNode struct {
	seg   string               // the name as the rule spells it
	kids  map[string]*homeNode // by folded name
	rules [][2]string          // pattern and kind
}

// lookHome looks at the names under the home directory that a secret-path or
// persistence-point rule names as a whole, which may be links into the
// workspace from outside it. Rules match without case, so each name is
// found under every spelling a rule matches (~/.config/Code for the rule
// **/.config/code/**) by reading the directories on the way to it, each
// once, and only those.
func (l *linkLook) lookHome() {
	if l.home == "" {
		return
	}
	root := &homeNode{kids: map[string]*homeNode{}}
	for _, list := range []struct {
		rules []string
		kind  string
	}{{secretPaths, secretKind}, {noWritePaths, persistKind}} {
		for _, pat := range list.rules {
			for _, name := range homeNames(pat, l.home) {
				rel, err := filepath.Rel(l.home, name)
				if err != nil || rel == "." || !filepath.IsLocal(rel) {
					continue
				}
				n := root
				for _, seg := range splitLocal(rel) {
					k := n.kids[fold(seg)]
					if k == nil {
						k = &homeNode{seg: seg, kids: map[string]*homeNode{}}
						n.kids[fold(seg)] = k
					}
					n = k
				}
				n.rules = append(n.rules, [2]string{pat, list.kind})
			}
		}
	}
	var visit func(dir string, n *homeNode, exists bool)
	visit = func(dir string, n *homeNode, exists bool) {
		for _, r := range n.rules {
			l.place(dir, dir, r[0], r[1])
		}
		if len(n.kids) == 0 || !l.alive() {
			return
		}
		seen := map[*homeNode]bool{}
		if exists {
			for _, name := range l.namesIn(dir, n.kids) {
				k := n.kids[fold(name)]
				seen[k] = true
				visit(filepath.Join(dir, name), k, true)
			}
		}
		// A name that is not there under any spelling may still lead
		// somewhere through a link above it, as a file made under it would.
		for _, k := range n.kids {
			if !seen[k] && l.alive() {
				visit(filepath.Join(dir, k.seg), k, false)
			}
		}
	}
	visit(l.home, root, true)
}

// namesIn returns the names in the directory dir whose folded form is a key
// of want, reading dir once, a chunk at a time; none when it cannot be read.
func (l *linkLook) namesIn(dir string, want map[string]*homeNode) []string {
	var out []string
	if l.mounts[dir] {
		return nil
	}
	l.readDir(dir, func(e os.DirEntry) bool {
		if want[fold(e.Name())] != nil {
			out = append(out, e.Name())
		}
		return true
	})
	return out
}

// homeNames returns the paths under home, a clean absolute local path with
// its links resolved, that the rule pat names as a whole: what follows a part
// of pat that matches home, when that holds no wildcard. A rule for every
// path below a directory names the directory.
func homeNames(pat, home string) []string {
	segs := splitPath(strings.TrimSuffix(pat, "/**"))
	key := strings.ToLower(localKey(home))
	var out []string
	for k := 1; k < len(segs); k++ {
		rest := segs[k:]
		if slices.ContainsFunc(rest, func(s string) bool { return strings.ContainsAny(s, `*?[\`) }) {
			continue
		}
		if matchPath(strings.ToLower("/"+strings.Join(segs[:k], "/")), key) {
			out = append(out, filepath.Join(home, filepath.FromSlash(strings.Join(rest, "/"))))
		}
	}
	return out
}

// splitRule is a rule split once for the look, with what a path it matches
// must hold: its segments that hold no wildcard, as they are, and a last
// segment its own last one matches, unless that is **. Most rules are passed
// over by those alone, so judging a link costs little more than reading its
// name.
type splitRule struct {
	segs, lits      []string
	last, pat, kind string
}

func splitRules(lists []ruleList) []splitRule {
	var split []splitRule
	for _, l := range lists {
		for _, pat := range l.rules {
			r := splitRule{segs: splitPath(strings.ToLower(pat)), pat: pat, kind: l.kind}
			for _, seg := range r.segs {
				if seg != "**" && !strings.ContainsAny(seg, `*?[\`) {
					r.lits = append(r.lits, seg)
				}
			}
			if n := len(r.segs); n > 0 && r.segs[n-1] != "**" {
				r.last = r.segs[n-1]
			}
			split = append(split, r)
		}
	}
	return split
}

// walk reads the workspace ws breadth first, dot directories before the
// others at each depth, and judges each link in it by its name: one a rule
// matches, as the directory it names or as itself, is placed. It reads no
// directory on another file system, nor on macOS the home directory's
// folders the system asks the user about before a program may read them.
func (l *linkLook) walk(ws string) {
	split := splitRules([]ruleList{{rules: secretPaths, kind: secretKind}, {rules: l.ternRules, kind: ownKind},
		{rules: noWritePaths, kind: persistKind}})
	match := func(name string) (string, string) {
		var keys [][]string
		for _, k := range append(ruleKeys(localKey(filepath.Join(name, "x"))), ruleKeys(localKey(name))...) {
			if segs := splitPath(k); len(segs) > 0 {
				keys = append(keys, segs)
			}
		}
		for _, r := range split {
			for _, k := range keys {
				if r.last != "" {
					if ok, _ := path.Match(r.last, k[len(k)-1]); !ok {
						continue
					}
				}
				if !slices.ContainsFunc(r.lits, func(lit string) bool { return !slices.Contains(k, lit) }) && matchSegs(r.segs, k) {
					return r.pat, r.kind
				}
			}
		}
		return "", ""
	}
	level := [2][]string{nil, {ws}} // dot directories, then the others
	read, links := 0, 0
	for depth := 0; depth < aliasDepth && l.alive(); depth++ {
		var next [2][]string
		for _, dir := range slices.Concat(level[0], level[1]) {
			if read == aliasEntries {
				l.stop(fmt.Sprintf("stopped after reading %d directories", aliasEntries))
				return
			}
			read++
			l.readDir(dir, func(e os.DirEntry) bool {
				p := filepath.Join(dir, e.Name())
				switch {
				case isLinkMode(e.Type()):
					if e.Type()&fs.ModeSymlink != 0 {
						if links == aliasLinks {
							l.stop(fmt.Sprintf("stopped after judging %d links", aliasLinks))
							return false
						}
						links++
					}
					if pat, kind := match(p); pat != "" {
						rel, _ := filepath.Rel(ws, p)
						l.place(rel, p, pat, kind)
					}
				case e.IsDir() && depth+1 < aliasDepth && !l.mounts[p] && !l.asksFirst(dir, e.Name()):
					i := 1
					if strings.HasPrefix(e.Name(), ".") {
						i = 0
					}
					next[i] = append(next[i], p)
				}
				return l.cut == ""
			})
			if l.cut != "" {
				return
			}
		}
		level = next
	}
}

// readDir passes each entry of the directory dir to f, a chunk at a time,
// until f returns false, the entries end, or the look's time is up.
func (l *linkLook) readDir(dir string, f func(os.DirEntry) bool) {
	if !l.alive() {
		return
	}
	d, err := l.open(dir)
	if err != nil {
		return
	}
	defer d.Close()
	for {
		ents, err := d.ReadDir(256)
		for _, e := range ents {
			if !f(e) {
				return
			}
		}
		if err != nil || !l.alive() {
			return
		}
	}
}

// macAsks reports whether the look runs where the system asks the user
// before a program reads some folders of the home directory: macOS. Tests
// set it.
var macAsks = runtime.GOOS == "darwin"

// asksFirst reports whether name, in the directory dir, is one of the home
// directory's folders that macOS asks the user about before a program reads
// them (Desktop, Documents, Downloads, iCloud Drive's and other apps' data),
// or that hold the user's media; the look does not read them, so it never
// makes the system ask. A workspace inside one is read as usual.
func (l *linkLook) asksFirst(dir, name string) bool {
	if !l.asks || l.home == "" {
		return false
	}
	var names []string
	switch {
	case strings.EqualFold(dir, l.home):
		names = []string{"Desktop", "Documents", "Downloads", "Movies", "Music", "Pictures"}
	case strings.EqualFold(dir, filepath.Join(l.home, "Library")):
		names = []string{"Mobile Documents", "Containers", "Group Containers"}
	}
	return slices.ContainsFunc(names, func(n string) bool { return strings.EqualFold(n, name) })
}
