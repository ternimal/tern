// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"errors"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// procInfo is what /proc/<pid>/stat says of a process.
type procInfo struct {
	state byte   // R, S, D, Z, T, ...
	ppid  int    // parent
	sid   int    // session
	start uint64 // start time, in clock ticks since boot: with the pid, it names one process
}

// parseStat parses the contents of /proc/<pid>/stat.
func parseStat(b []byte) (procInfo, bool) {
	s := string(b)
	// The command name, in parentheses, may itself hold spaces and ")".
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return procInfo{}, false
	}
	// After it: state ppid pgrp session tty_nr tpgid flags minflt cminflt
	// majflt cmajflt utime stime cutime cstime priority nice num_threads
	// itrealvalue starttime ...
	f := strings.Fields(s[i+1:])
	if len(f) < 20 || len(f[0]) != 1 {
		return procInfo{}, false
	}
	ppid, err1 := strconv.Atoi(f[1])
	sid, err2 := strconv.Atoi(f[3])
	start, err3 := strconv.ParseUint(f[19], 10, 64)
	if err1 != nil || err2 != nil || err3 != nil {
		return procInfo{}, false
	}
	return procInfo{state: f[0][0], ppid: ppid, sid: sid, start: start}, true
}

// readProc reads one process's stat line.
func readProc(pid int) (procInfo, bool) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return procInfo{}, false
	}
	return parseStat(b)
}

// ownProc reports whether /proc is that of this process's PID namespace, so
// that the pids it lists are the numbers signals from here reach. A /proc of
// another namespace, as a process in a namespace of its own sees when no
// /proc of that namespace is mounted (unshare -p without --mount-proc, a
// sandbox that keeps the host's), lists other processes, whose numbers here
// name unrelated processes or none.
func ownProc() bool {
	self, err := os.Readlink("/proc/self")
	return err == nil && self == strconv.Itoa(os.Getpid())
}

// readProcs reads every process /proc shows, as pid -> procInfo. A process
// that ends while the table is read is just missing from it.
func readProcs() (map[int]procInfo, error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	procs := make(map[int]procInfo, len(ents))
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		if pr, ok := readProc(pid); ok {
			procs[pid] = pr
		}
	}
	return procs, nil
}

// signalProc sends sig to the process pid, but only while pid still names
// the process that started at start, as a table read moments ago showed: a
// process that ended since, its pid taken by another, is never signalled.
// Where the kernel has pidfds the signal goes through one opened before the
// check, which then names that process however soon its pid is reused.
// It reports whether the signal was sent.
func signalProc(pid int, start uint64, sig unix.Signal) bool {
	fd, err := unix.PidfdOpen(pid, 0)
	switch {
	case err == nil:
		defer unix.Close(fd)
		if pr, ok := readProc(pid); !ok || pr.start != start {
			return false
		}
		return unix.PidfdSendSignal(fd, sig, nil, 0) == nil
	case errors.Is(err, unix.ESRCH): // gone
		return false
	default:
		// No pidfd (before Linux 5.3, a seccomp filter that hides them, no
		// descriptor left, or pid is a thread's id): a signal by number.
		return killByNumber(pid, start, sig)
	}
}

// killByNumber sends sig to pid by number, right after the check signalProc
// makes, and only when pid is a process's own id: a thread's id, which
// /proc/<tid> answers to as well, would take the signal to the whole
// process the thread is in.
func killByNumber(pid int, start uint64, sig unix.Signal) bool {
	if pr, ok := readProc(pid); !ok || pr.start != start || !isProcessID(pid) {
		return false
	}
	return unix.Kill(pid, sig) == nil
}

// isProcessID reports whether pid is the id of a process, the leader of its
// thread group, rather than of one of its other threads.
func isProcessID(pid int) bool {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return false
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "Tgid:"); ok {
			tgid, err := strconv.Atoi(strings.TrimSpace(v))
			return err == nil && tgid == pid
		}
	}
	return false
}
