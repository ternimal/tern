// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package tern

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A client that sent more input than its command reads can still cancel the
// command: it is killed when the client goes away, as it is with no input.
func TestExecCancelWithUnreadStdin(t *testing.T) {
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	marker := filepath.Join(t.TempDir(), "still-ran")
	stdin := bytes.NewReader(bytes.Repeat([]byte("A"), 1<<20)) // far more than a pipe holds; sleep reads none
	done := make(chan struct{})
	go func() {
		cl.Run([]string{"sh", "-c", "sleep 1; touch " + marker}, stdin, io.Discard)
		close(done)
	}()
	time.Sleep(300 * time.Millisecond)
	cl.Close() // what an MCP timeout, job_cancel, a REST cancel and Ctrl-C do
	<-done
	time.Sleep(1500 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the command outlived its client")
	}
}

// A client can end a command whose input is backed up and keep its
// connection: the end request comes on the control stream, so it does not
// wait for the command to take the input sent before it, which it never
// does.
func TestExecEndWithInputBackedUp(t *testing.T) {
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	marker := filepath.Join(t.TempDir(), "still-ran")
	st, err := cl.sess.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	writeHeader(st, streamHeader{Kind: kindExec, Cmd: []string{"sh", "-c", "sleep 1; touch " + marker}})
	if rep, err := readReply(st); err != nil || !rep.OK {
		t.Fatalf("reply %+v %v", rep, err)
	}
	go func() { // input sleep never reads: blocks once the stream's window is full
		chunk := make([]byte, 32<<10)
		for i := 0; i < 128; i++ {
			if writeFrame(st, frameData, chunk) != nil {
				return
			}
		}
	}()
	time.Sleep(300 * time.Millisecond)
	within(t, time.Second, "the end request", func() error { return cl.control(st, frameEnd, nil) })
	time.Sleep(1500 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the command ran on after its end request")
	}
	if code, err := cl.Run([]string{"true"}, nil, io.Discard); err != nil || code != 0 {
		t.Fatalf("the connection no longer serves: exit %d, %v", code, err)
	}
}

// Input far larger than the agent queues arrives whole and in order: the
// queue slows the client down, it does not drop or reorder.
func TestExecStdinArrivesWhole(t *testing.T) {
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	in := make([]byte, 3<<20)
	for i := range in {
		in[i] = byte(i % 251)
	}
	var out bytes.Buffer
	code, err := cl.Run([]string{"cat"}, bytes.NewReader(in), &out)
	if err != nil || code != 0 {
		t.Fatalf("cat: exit %d, %v", code, err)
	}
	if !bytes.Equal(out.Bytes(), in) {
		t.Fatalf("cat returned %d bytes, not the %d sent", out.Len(), len(in))
	}
}

// A command's background jobs end with it, once its output has ended.
func TestExecBackgroundJobEndsWithCommand(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("elsewhere the leader is reaped before its group can be killed")
	}
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	var out bytes.Buffer
	if _, err := cl.Run([]string{"sh", "-c", "sleep 30 >/dev/null 2>&1 & echo $!"}, nil, &out); err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(out.String()))
	if err != nil {
		t.Fatalf("output %q", out.String())
	}
	for i := 0; syscall.Kill(pid, 0) == nil; i++ {
		if i == 100 {
			syscall.Kill(pid, syscall.SIGKILL)
			t.Fatal("the background job outlived its command")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Killing a command's process group when its client leaves never reaches a
// process that took the pid of the command's leader. The leader exits while
// a process it started, outside its group, keeps the output open, so the
// command goes on; the leader's pid must stay taken until the agent is done
// signalling its group. A private PID namespace, where ns_last_pid steers
// which pid the next process gets, puts an unrelated process right where the
// leader's pid would be reused.
func TestExecKillSparesReusedPID(t *testing.T) {
	if os.Getenv("TERN_TEST_PIDNS") == "" {
		runInPIDNamespace(t)
		return
	}
	for _, leader := range []bool{false, true} {
		t.Run(fmt.Sprintf("leader=%v", leader), func(t *testing.T) { killSparesReusedPID(t, leader) })
	}
}

// runInPIDNamespace runs the calling test again as process 1 of a PID
// namespace of its own (and a user namespace, so no privilege is needed),
// skipping where unshare(1) or user namespaces are not available.
func runInPIDNamespace(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("needs Linux namespaces")
	}
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skip("needs unshare(1)")
	}
	cmd := exec.Command(unshare, "-Urpf", "--mount-proc", os.Args[0], "-test.run=^"+t.Name()+"$", "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), "TERN_TEST_PIDNS=1")
	out, err := cmd.CombinedOutput()
	switch {
	case bytes.Contains(out, []byte("--- FAIL")):
		t.Fatalf("in a PID namespace:\n%s", out)
	case bytes.Contains(out, []byte("--- SKIP")):
		t.Skipf("in a PID namespace:\n%s", out)
	case bytes.Contains(out, []byte("--- PASS: "+t.Name())):
		t.Logf("in a PID namespace:\n%s", out)
	default:
		t.Skipf("no PID namespace here (%v):\n%s", err, out)
	}
}

func killSparesReusedPID(t *testing.T, leader bool) {
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	pr, pw := io.Pipe()
	go func() {
		// sh prints its pid and exits; setsid sleep leaves sh's process
		// group but keeps the output open, so the command goes on.
		cl.Run([]string{"sh", "-c", "echo $$; setsid sleep 3 & exit 0"}, nil, pw)
		pw.Close()
	}()
	br := bufio.NewReader(pr)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	go io.Copy(io.Discard, br)
	pid, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		t.Fatal(err)
	}
	stat := func() string { b, _ := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); return string(b) }
	for i := 0; ; i++ {
		// gone (reaped), or a zombie: ") Z " after the command's name
		if s := stat(); s == "" || strings.Contains(s, ") Z ") {
			break
		}
		if i == 200 {
			t.Fatalf("sh did not exit: %s", stat())
		}
		time.Sleep(10 * time.Millisecond)
	}
	// An unrelated process takes the leader's pid if it is free, as any
	// process may once the pid counter wraps.
	var victim *exec.Cmd
	for try := 0; try < 5; try++ {
		if err := os.WriteFile("/proc/sys/kernel/ns_last_pid", []byte(strconv.Itoa(pid-1)), 0); err != nil {
			t.Skipf("ns_last_pid: %v", err)
		}
		v := exec.Command("sleep", "30")
		if leader {
			v.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		}
		if err := v.Start(); err != nil {
			t.Fatal(err)
		}
		if victim != nil {
			victim.Process.Kill()
			victim.Wait()
		}
		victim = v
		if v.Process.Pid == pid {
			break
		}
	}
	t.Logf("the command's leader had pid %d; an unrelated process has pid %d", pid, victim.Process.Pid)
	exited := make(chan error, 1)
	go func() { exited <- victim.Wait() }()

	cl.Close() // the client leaves: the agent kills the command's group
	select {
	case err := <-exited:
		t.Fatalf("the agent killed process %d, which is not the command's: %v", victim.Process.Pid, err)
	case <-time.After(time.Second):
		victim.Process.Kill()
		<-exited
	}
	for i := 0; stat() != ""; i++ {
		if i == 200 {
			t.Fatalf("the command's leader was never reaped: %s", stat())
		}
		time.Sleep(10 * time.Millisecond)
	}
}
