// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package e2e

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// pidsWithCmdline lists the processes whose command line is argv exactly.
func pidsWithCmdline(argv ...string) []int {
	want := []byte(strings.Join(argv, "\x00") + "\x00")
	ents, _ := os.ReadDir("/proc")
	var pids []int
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if b, err := os.ReadFile("/proc/" + e.Name() + "/cmdline"); err == nil && bytes.Equal(b, want) {
			pids = append(pids, pid)
		}
	}
	return pids
}

// procState is a process's state letter from /proc/<pid>/stat (T when
// stopped), or 0 once it is gone.
func procState(pid int) byte {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b[bytes.LastIndexByte(b, ')')+1:]))
	if len(f) == 0 || len(f[0]) != 1 {
		return 0
	}
	return f[0][0]
}

// ternd shutting down while it kills a cancelled command lets the kill
// finish: the processes the kill stops on its way, before it kills them
// all, are not left stopped for good when ternd exits.
func TestShutdownDuringKillLeavesNothingStopped(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("needs bash")
	}
	tok := genToken(t)
	port := freePort(t)
	d := start(t, "ternd", nil, "--addr", addr(port), "--token", tok, "--cert", filepath.Join(t.TempDir(), "agent"), "--shell", "/bin/sh")
	fp := d.waitFor(t, reFingerprint, 15*time.Second)
	waitListen(t, addr(port), 10*time.Second)

	mark := strconv.Itoa(4000000 + os.Getpid()) // a sleep no other process runs
	cl := exec.Command(bin["tern"], "run", "--addr", addr(port), "--fingerprint", fp, "--token", tok, "--",
		"bash", "-c", "for i in $(seq 60); do sleep "+mark+" & done; echo ready; wait")
	out, err := cl.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cl.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, pid := range pidsWithCmdline("sleep", mark) {
			syscall.Kill(pid, syscall.SIGKILL)
		}
		cl.Process.Kill()
		cl.Wait()
	}()
	if line, err := bufio.NewReader(out).ReadString('\n'); err != nil || strings.TrimSpace(line) != "ready" {
		t.Fatalf("the command printed %q, %v", line, err)
	}
	// "ready" can come before the last children have become sleep.
	var pids []int
	for deadline := time.Now().Add(5 * time.Second); len(pids) < 60 && time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		pids = pidsWithCmdline("sleep", mark)
	}
	if len(pids) != 60 {
		t.Fatalf("found %d of the command's 60 processes", len(pids))
	}
	cl.Process.Kill() // the client goes: ternd cancels its command

	// SIGTERM the moment the kill is seen under way, one of its processes
	// stopped.
	seen := false
	for deadline := time.Now().Add(10 * time.Second); !seen && time.Now().Before(deadline); {
		for _, pid := range pids {
			if procState(pid) == 'T' {
				seen = true
				break
			}
		}
	}
	d.cmd.Process.Signal(syscall.SIGTERM)
	exited := make(chan struct{})
	go func() {
		d.cmd.Wait()
		close(exited)
	}()
	select {
	case <-exited:
	case <-time.After(15 * time.Second):
		t.Fatal("ternd did not exit after SIGTERM")
	}
	stopped := 0
	for _, pid := range pids {
		if procState(pid) == 'T' {
			stopped++
		}
	}
	if stopped > 0 {
		t.Errorf("ternd exited leaving %d of the command's processes stopped", stopped)
	}
	if !seen {
		t.Log("the kill was over before it could be seen under way")
	}
}
