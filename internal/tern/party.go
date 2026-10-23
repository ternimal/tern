// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"container/heap"
	"net"
	"net/netip"
	"time"
)

// The address blocks a peer's address is weighed in, widest first, as prefix
// lengths. A peer that holds many addresses almost always holds them within
// one block of whoever gave them out: an IPv6 /32 is a typical provider's,
// a /48 a site's and a /64 a host's, and an IPv4 /16 or /24 a provider's
// range. Weighing the blocks at every level, not only the addresses, keeps a
// peer with thousands of addresses in one block from passing for thousands
// of peers.
var (
	ipv4Blocks = [...]int{16, 24, 32}
	ipv6Blocks = [...]int{32, 40, 48, 56, 64}
)

// maxBlocks is the longest an addrPath gets.
const maxBlocks = len(ipv6Blocks)

// addrPath names the address blocks a peer at a belongs to, widest first.
// The last names its source, an IPv4 address or an IPv6 /64, which a single
// host often has whole. An address that is not IP is a block of its own.
func addrPath(a net.Addr) []string {
	if a == nil {
		return []string{""}
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return []string{a.String()}
	}
	ip := ap.Addr().Unmap()
	bits := ipv6Blocks[:]
	if ip.Is4() {
		bits = ipv4Blocks[:]
	}
	path := make([]string, 0, len(bits))
	for _, b := range bits {
		p, err := ip.Prefix(b)
		if err != nil {
			return []string{ip.String()}
		}
		path = append(path, p.String())
	}
	if ip.Is4() {
		path[len(path)-1] = ip.String()
	}
	return path
}

// capKeys names the groups an address with blocks path counts in for the
// handshake caps: its source, then for IPv6 its /56 and /48.
func capKeys(path []string) []string {
	if len(path) == len(ipv6Blocks) {
		return []string{path[4], path[3], path[2]}
	}
	return path[len(path)-1:]
}

// partyKey names the party a relay holds to its caps per party: an IPv4
// address or an IPv6 /48.
func partyKey(path []string) string {
	return path[min(2, len(path)-1)]
}

// partyTree holds entries, such as handshakes in flight or relay bridges, by
// the address blocks of the peer each came from, so that a full listener can
// tell which entry to let go: the oldest entry of the source holding the
// most, within the block holding the most at every level above it, ties
// going to the block whose oldest entry is oldest. Every operation costs a
// heap step or two per level, however many entries and blocks it holds.
//
// An entry may be added quiet, for a peer that has sent nothing yet, until
// heard says it has. One that stays quiet a while goes before the rest (see
// victim): a real client speaks as soon as it connects, while a connection
// that never does costs a flood nothing to open.
type partyTree[T any] struct {
	root        partyNode[T]
	nodes       map[string]*partyNode[T] // the blocks holding any entry
	quiet, last *partyEntry[T]           // the quiet entries, oldest first
}

// partyNode is an address block in a partyTree, or the tree's root.
type partyNode[T any] struct {
	key         string
	parent      *partyNode[T]
	level       int            // its index in a path; -1 for the root
	n           int            // entries held in the block
	first, last *partyEntry[T] // the same, oldest first (none kept for the root)
	kids        partyHeap[T]   // the blocks within it holding any, heaviest first
	at          int            // its index in parent.kids
}

// partyEntry is what a partyTree holds; the owner of an entry embeds it, and
// val points back at the owner.
type partyEntry[T any] struct {
	val        T
	seq        uint64 // order of arrival: the smaller, the older
	depth      int    // the number of blocks it is in; 0 while out of a tree
	nodes      [maxBlocks]*partyNode[T]
	prev, next [maxBlocks]*partyEntry[T] // its neighbours in each block's list

	quiet        bool      // its peer has sent nothing yet
	since        time.Time // when it was added, for a quiet one
	qprev, qnext *partyEntry[T]
}

// add puts e in t under the blocks of path as their youngest entry: seq must
// be larger than that of any entry in t. quiet marks an entry whose peer has
// sent nothing yet, as of now.
func (t *partyTree[T]) add(e *partyEntry[T], path []string, seq uint64, quiet bool, now time.Time) {
	if t.nodes == nil {
		t.nodes = make(map[string]*partyNode[T])
		t.root.level = -1
	}
	e.seq, e.depth = seq, len(path)
	if quiet {
		e.quiet, e.since, e.qprev, e.qnext = true, now, t.last, nil
		if t.last != nil {
			t.last.qnext = e
		} else {
			t.quiet = e
		}
		t.last = e
	}
	parent := &t.root
	for i, key := range path {
		nd := t.nodes[key]
		if nd == nil {
			nd = &partyNode[T]{key: key, parent: parent, level: i, at: -1}
			t.nodes[key] = nd
		}
		e.nodes[i], e.prev[i], e.next[i] = nd, nd.last, nil
		if nd.last != nil {
			nd.last.next[i] = e
		} else {
			nd.first = e
		}
		nd.last = e
		nd.n++
		if nd.at < 0 {
			heap.Push(&parent.kids, nd)
		} else {
			heap.Fix(&parent.kids, nd.at)
		}
		parent = nd
	}
	t.root.n++
}

// heard records that e's peer has sent something: e is quiet no more.
func (t *partyTree[T]) heard(e *partyEntry[T]) {
	if !e.quiet {
		return
	}
	if e.qprev != nil {
		e.qprev.qnext = e.qnext
	} else {
		t.quiet = e.qnext
	}
	if e.qnext != nil {
		e.qnext.qprev = e.qprev
	} else {
		t.last = e.qprev
	}
	e.quiet, e.qprev, e.qnext = false, nil, nil
}

// remove takes e, which add put in t, out of it.
func (t *partyTree[T]) remove(e *partyEntry[T]) {
	t.heard(e)
	for i := range e.depth {
		nd := e.nodes[i]
		prev, next := e.prev[i], e.next[i]
		if prev != nil {
			prev.next[i] = next
		} else {
			nd.first = next
		}
		if next != nil {
			next.prev[i] = prev
		} else {
			nd.last = prev
		}
		e.nodes[i], e.prev[i], e.next[i] = nil, nil, nil
		nd.n--
		if nd.n == 0 {
			heap.Remove(&nd.parent.kids, nd.at)
			delete(t.nodes, nd.key)
		} else {
			heap.Fix(&nd.parent.kids, nd.at)
		}
	}
	e.depth = 0
	t.root.n--
}

// count is how many entries t holds in the block key.
func (t *partyTree[T]) count(key string) int {
	if nd := t.nodes[key]; nd != nil {
		return nd.n
	}
	return 0
}

// pick returns the entry to let go first of those in nd's block: the oldest
// of the block holding the most at every level below it, or nil if it holds
// none.
func (nd *partyNode[T]) pick() *partyEntry[T] {
	for len(nd.kids) > 0 {
		nd = nd.kids[0]
	}
	return nd.first
}

// victim returns the entry to let go first of those in nd's block, which is
// t's root for all of t, or nil if it holds none: the one nd picks, unless
// the oldest quiet entry has been quiet for grace and no block outweighs its
// own, where their paths part, which then goes first. So a peer with many
// addresses in one block always gives way first, and among blocks that weigh
// the same, such as many parties holding one each, the ones that have sent
// nothing go before a client getting on with its handshake. An entry quiet
// for less than grace is no likelier to go than any other, so a client the
// moment before its first bytes are read loses nothing by it. For a block
// other than the root, the oldest quiet entry is looked up by walking the
// block's list, which the caps keep short.
func (t *partyTree[T]) victim(nd *partyNode[T], grace time.Duration, now time.Time) *partyEntry[T] {
	q := t.quiet
	if nd != &t.root {
		for q = nd.first; q != nil && !q.quiet; q = q.next[nd.level] {
		}
	}
	if q == nil || now.Sub(q.since) < grace {
		return nd.pick()
	}
	for cur := nd; len(cur.kids) > 0; {
		top := cur.kids[0]
		own := q.nodes[top.level]
		if own == top {
			cur = top
			continue
		}
		if own.n < top.n {
			return nd.pick() // a heavier block gives way first
		}
		break
	}
	return q
}

// displace returns the entry a newcomer with address blocks path may push
// out of a full t: the one t's root would pick, but only from a block that
// holds at least two more entries than the newcomer's own block where their
// paths part. A newcomer so takes places from a heavier party only, and
// never trades places with an equal one, which would close an entry to no
// one's gain. It returns nil when there is none: the newcomer is the one to
// turn away.
func (t *partyTree[T]) displace(path []string) *partyEntry[T] {
	nd := &t.root
	for i := 0; len(nd.kids) > 0; i++ {
		top := nd.kids[0]
		if i < len(path) && top.key == path[i] {
			nd = top // the newcomer's own block holds the most: look within it
			continue
		}
		own := 0
		if i < len(path) {
			own = t.count(path[i])
		}
		if top.n < own+2 {
			return nil
		}
		return top.pick()
	}
	return nil
}

// partyHeap orders the blocks within one block: the one holding the most
// first, ties going to the one whose oldest entry is oldest.
type partyHeap[T any] []*partyNode[T]

func (h partyHeap[T]) Len() int { return len(h) }

func (h partyHeap[T]) Less(i, j int) bool {
	if h[i].n != h[j].n {
		return h[i].n > h[j].n
	}
	return h[i].first.seq < h[j].first.seq
}

func (h partyHeap[T]) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].at, h[j].at = i, j
}

func (h *partyHeap[T]) Push(x any) {
	nd := x.(*partyNode[T])
	nd.at = len(*h)
	*h = append(*h, nd)
}

func (h *partyHeap[T]) Pop() any {
	old := *h
	nd := old[len(old)-1]
	old[len(old)-1] = nil
	*h = old[:len(old)-1]
	nd.at = -1
	return nd
}
