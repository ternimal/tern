// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"fmt"
	"math/rand/v2"
	"net"
	"slices"
	"testing"
	"time"
)

func TestAddrPath(t *testing.T) {
	for _, c := range []struct {
		addr string
		want []string
	}{
		{"192.0.2.1:80", []string{"192.0.0.0/16", "192.0.2.0/24", "192.0.2.1"}},
		{"[::ffff:192.0.2.1]:80", []string{"192.0.0.0/16", "192.0.2.0/24", "192.0.2.1"}},
		{"[2001:db8:1:2:3::1]:80", []string{"2001:db8::/32", "2001:db8::/40", "2001:db8:1::/48", "2001:db8:1::/56", "2001:db8:1:2::/64"}},
		{"[fe80::1%eth0]:80", []string{"fe80::/32", "fe80::/40", "fe80::/48", "fe80::/56", "fe80::/64"}},
	} {
		if got := addrPath(testAddr(c.addr)); !slices.Equal(got, c.want) {
			t.Errorf("%s: %q, want %q", c.addr, got, c.want)
		}
	}
	if got := addrPath(pipeAddr{}); !slices.Equal(got, []string{"pipe"}) {
		t.Errorf("a non-IP address: %q", got)
	}
	if got := capKeys(addrPath(testAddr("[2001:db8:1:2:3::1]:80"))); !slices.Equal(got, []string{"2001:db8:1:2::/64", "2001:db8:1::/56", "2001:db8:1::/48"}) {
		t.Errorf("IPv6 cap groups: %q", got)
	}
	if got := partyKey(addrPath(testAddr("[2001:db8:1:2:3::1]:80"))); got != "2001:db8:1::/48" {
		t.Errorf("an IPv6 party: %q", got)
	}
	if got := partyKey(addrPath(testAddr("192.0.2.1:80"))); got != "192.0.2.1" {
		t.Errorf("an IPv4 party: %q", got)
	}
}

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

func testAddr(s string) net.Addr {
	a, err := net.ResolveTCPAddr("tcp", s)
	if err != nil {
		panic(err)
	}
	return a
}

// modelEntry is an entry of the brute-force model a partyTree is checked
// against.
type modelEntry struct {
	e     *partyEntry[int]
	path  []string
	seq   uint64
	since time.Time
}

// modelPick picks as partyTree documents, by brute force: at each level the
// block holding the most of entries, ties going to the block whose oldest
// entry is oldest, and in the last block the oldest entry.
func modelPick(entries []*modelEntry, level int) *modelEntry {
	if len(entries) == 0 {
		return nil
	}
	if level == len(entries[0].path) {
		return slices.MinFunc(entries, func(a, b *modelEntry) int { return int(a.seq) - int(b.seq) })
	}
	blocks := map[string][]*modelEntry{}
	for _, m := range entries {
		blocks[m.path[level]] = append(blocks[m.path[level]], m)
	}
	var best []*modelEntry
	oldest := func(es []*modelEntry) uint64 {
		return slices.MinFunc(es, func(a, b *modelEntry) int { return int(a.seq) - int(b.seq) }).seq
	}
	for _, es := range blocks {
		if best == nil || len(es) > len(best) || len(es) == len(best) && oldest(es) < oldest(best) {
			best = es
		}
	}
	return modelPick(best, level+1)
}

// modelDisplace is partyTree.displace by brute force.
func modelDisplace(entries []*modelEntry, path []string, level int) *modelEntry {
	if len(entries) == 0 || level == len(path) {
		return nil
	}
	top := modelPick(entries, level)
	if top.path[level] == path[level] {
		var within []*modelEntry
		for _, m := range entries {
			if m.path[level] == path[level] {
				within = append(within, m)
			}
		}
		return modelDisplace(within, path, level+1)
	}
	topN, own := 0, 0
	for _, m := range entries {
		switch m.path[level] {
		case top.path[level]:
			topN++
		case path[level]:
			own++
		}
	}
	if topN < own+2 {
		return nil
	}
	return top
}

// modelVictim is partyTree.victim by brute force, over the entries in the
// block at level holding key, or over all of them for no key.
func modelVictim(entries []*modelEntry, key string, level int, grace time.Duration, now time.Time) *modelEntry {
	var in []*modelEntry
	for _, m := range entries {
		if key == "" || level < len(m.path) && m.path[level] == key {
			in = append(in, m)
		}
	}
	var quiet *modelEntry
	for _, m := range in {
		if m.e.quiet && (quiet == nil || m.seq < quiet.seq) {
			quiet = m
		}
	}
	if quiet == nil || now.Sub(quiet.since) < grace {
		return modelPick(in, 0)
	}
	// The quiet one goes first unless, where its path and the heaviest
	// blocks' part, a block outweighs its own.
	cur, from := in, 0
	if key != "" {
		from = level + 1
	}
	for lv := from; lv < len(quiet.path); lv++ {
		top, n := modelHeaviest(cur, lv)
		var within []*modelEntry
		own := 0
		for _, m := range cur {
			if m.path[lv] == quiet.path[lv] {
				within = append(within, m)
				own++
			}
		}
		if top == quiet.path[lv] {
			cur = within
			continue
		}
		if own < n {
			return modelPick(in, 0)
		}
		break
	}
	return quiet
}

// modelHeaviest returns the block at level holding the most of entries, ties
// going to the block whose oldest entry is oldest, and how many it holds.
func modelHeaviest(entries []*modelEntry, level int) (string, int) {
	blocks := map[string][]*modelEntry{}
	for _, m := range entries {
		blocks[m.path[level]] = append(blocks[m.path[level]], m)
	}
	oldest := func(es []*modelEntry) uint64 {
		return slices.MinFunc(es, func(a, b *modelEntry) int { return int(a.seq) - int(b.seq) }).seq
	}
	var key string
	var best []*modelEntry
	for k, es := range blocks {
		if best == nil || len(es) > len(best) || len(es) == len(best) && oldest(es) < oldest(best) {
			key, best = k, es
		}
	}
	return key, len(best)
}

// A partyTree picks, displaces, counts and chooses its victims as the
// brute-force model does, through random additions, removals and quiet
// entries heard from, over addresses that share blocks at every level.
func TestPartyTreeMatchesModel(t *testing.T) {
	var addrs []string
	for a := range 3 {
		for b := range 3 {
			for c := range 2 {
				addrs = append(addrs, fmt.Sprintf("10.%d.%d.%d:1", a, b, c+1))
			}
		}
	}
	for p32 := range 3 {
		for p48 := range 3 {
			for p64 := range 3 {
				addrs = append(addrs, fmt.Sprintf("[2001:%x:%x::%x:0:0:1]:1", 0xdb8+p32, p48, p64))
				addrs = append(addrs, fmt.Sprintf("[2001:%x:%x:%x00::1]:1", 0xdb8+p32, p48, p64))
			}
		}
	}
	r := rand.New(rand.NewPCG(1, 2))
	var tree partyTree[int]
	var model []*modelEntry
	var seq uint64
	start := time.Now()
	for step := range 20000 {
		now := start.Add(time.Duration(step) * time.Millisecond)
		switch op := r.IntN(10); {
		case len(model) > 0 && (op < 4 || len(model) > 300):
			i := r.IntN(len(model))
			tree.remove(model[i].e)
			model = slices.Delete(model, i, i+1)
		case len(model) > 0 && op < 6:
			tree.heard(model[r.IntN(len(model))].e)
		default:
			seq++
			m := &modelEntry{e: &partyEntry[int]{val: step}, path: addrPath(testAddr(addrs[r.IntN(len(addrs))])), seq: seq, since: now}
			tree.add(m.e, m.path, seq, r.IntN(2) == 0, now)
			model = append(model, m)
		}
		if tree.root.n != len(model) {
			t.Fatalf("step %d: the tree holds %d, the model %d", step, tree.root.n, len(model))
		}
		want := modelPick(model, 0)
		got := tree.root.pick()
		if (want == nil) != (got == nil) || want != nil && got != want.e {
			t.Fatalf("step %d: the tree picked a different entry from the model", step)
		}
		grace := time.Duration(r.IntN(200)) * time.Millisecond
		wantV, gotV := modelVictim(model, "", 0, grace, now), tree.victim(&tree.root, grace, now)
		if (wantV == nil) != (gotV == nil) || wantV != nil && gotV != wantV.e {
			t.Fatalf("step %d: the tree's victim differs from the model's", step)
		}
		if len(model) > 0 {
			m := model[r.IntN(len(model))]
			level := r.IntN(len(m.path))
			wantV := modelVictim(model, m.path[level], level, grace, now)
			if gotV := tree.victim(tree.nodes[m.path[level]], grace, now); gotV != wantV.e {
				t.Fatalf("step %d: the tree's victim in block %s differs from the model's", step, m.path[level])
			}
		}
		probe := addrPath(testAddr(addrs[r.IntN(len(addrs))]))
		wantD := modelDisplace(model, probe, 0)
		gotD := tree.displace(probe)
		if (wantD == nil) != (gotD == nil) || wantD != nil && gotD != wantD.e {
			t.Fatalf("step %d: for a newcomer from %v the tree would displace a different entry from the model", step, probe)
		}
		if step%97 == 0 {
			for _, key := range probe {
				n := 0
				for _, m := range model {
					if slices.Contains(m.path, key) {
						n++
					}
				}
				if c := tree.count(key); c != n {
					t.Fatalf("step %d: block %s holds %d, the model %d", step, key, c, n)
				}
			}
		}
	}
	for _, m := range model {
		tree.remove(m.e)
	}
	if tree.root.n != 0 || len(tree.nodes) != 0 || len(tree.root.kids) != 0 {
		t.Fatalf("an emptied tree still holds %d entries, %d blocks", tree.root.n, len(tree.nodes))
	}
}
