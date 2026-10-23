// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/aymanbagabas/go-pty"
	"golang.org/x/sys/unix"
)

// A process's stat line is read past a command name that holds spaces and
// parentheses, which any process can give itself.
func TestParseStatOddNames(t *testing.T) {
	line := "4242 (a) b (c) d) S 1 4242 4242 0 -1 4194560 100 0 0 0 0 0 0 0 20 0 1 0 98765 0 0\n"
	pr, ok := parseStat([]byte(line))
	if !ok || pr.state != 'S' || pr.ppid != 1 || pr.sid != 4242 || pr.start != 98765 {
		t.Fatalf("parseStat = %+v, %v", pr, ok)
	}
	if _, ok := parseStat([]byte("4242 (x) S 1 4242")); ok {
		t.Fatal("a cut-short stat line parsed")
	}
}

// gone reports whether pid has ended: no such process, or a zombie.
func gone(pid int) bool {
	pr, ok := readProc(pid)
	return !ok || pr.state == 'Z' || pr.state == 'X'
}

// waitGone waits up to two seconds for pid to end.
func waitGone(pid int) bool {
	for i := 0; i < 100; i++ {
		if gone(pid) {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// waitExec waits for each of pids to run sleep: by then it has left its
// shell's process group or session, as it was told to.
func waitExec(t *testing.T, pids []int) {
	t.Helper()
	for _, pid := range pids {
		for i := 0; ; i++ {
			if b, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm"); string(b) == "sleep\n" {
				break
			}
			if i == 200 {
				t.Fatalf("process %d never ran sleep", pid)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// bash returns bash's path, skipping the test without it: a job-control
// shell that, unlike dash, moves background jobs to process groups of their
// own without a terminal.
func bash(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("needs bash")
	}
	return p
}

// startReporting runs line with bash, a shell line that prints the pids of
// the processes it leaves running, one per line, then keeps running, and
// returns those pids once the line holding "ready" is read. The command's
// output goes on being drained.
func startReporting(t *testing.T, cl *Client, line string) []int {
	t.Helper()
	sh := bash(t)
	pr, pw := io.Pipe()
	go func() {
		cl.Run([]string{sh, "-c", line}, nil, pw)
		pw.Close()
	}()
	br := bufio.NewReader(pr)
	var pids []int
	for {
		s, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("reading the command's pids: %v (got %v)", err, pids)
		}
		s = strings.TrimSpace(s)
		if s == "ready" {
			break
		}
		pid, err := strconv.Atoi(s)
		if err != nil {
			t.Fatalf("output %q", s)
		}
		pids = append(pids, pid)
	}
	go io.Copy(io.Discard, br)
	return pids
}

// Cancelling a command kills what it started that left its process group:
// a job moved to a group of its own, and a process that started a session of
// its own while its parent still runs.
func TestCancelKillsDetachedDescendants(t *testing.T) {
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	// "set -m" puts each background job in a process group of its own, as
	// an interactive shell does; setsid gives sleep a session of its own.
	pids := startReporting(t, cl, `set -m; sleep 31 >/dev/null 2>&1 & echo $!; set +m; setsid sleep 32 >/dev/null 2>&1 & echo $!; echo ready; wait`)
	defer func() {
		for _, pid := range pids {
			syscall.Kill(pid, syscall.SIGKILL)
		}
	}()
	waitExec(t, pids)
	for _, pid := range pids {
		if gone(pid) {
			t.Fatalf("process %d ended before the cancel", pid)
		}
	}
	cl.Close() // a cancel: job_cancel, a REST DELETE, a client that leaves
	for i, pid := range pids {
		if !waitGone(pid) {
			t.Errorf("%s (pid %d) outlived the cancelled command", []string{"the job in a group of its own", "the process in a session of its own"}[i], pid)
		}
	}
}

// A command that ends leaves no background job running in its session, even
// one in a process group of its own.
func TestCommandEndKillsJobControlJobs(t *testing.T) {
	sh := bash(t)
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	var out bytes.Buffer
	if _, err := cl.Run([]string{sh, "-c", "set -m; sleep 33 >/dev/null 2>&1 & echo $!"}, nil, &out); err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(out.String()))
	if err != nil {
		t.Fatalf("output %q", out.String())
	}
	if !waitGone(pid) {
		syscall.Kill(pid, syscall.SIGKILL)
		t.Fatal("a background job in a group of its own outlived its command")
	}
}

// Killing a command reaches only processes it started: another session, a
// process the agent's host runs beside it, is left alone.
func TestCancelSparesOtherSessions(t *testing.T) {
	other := exec.Command("sleep", "34")
	other.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := other.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		other.Process.Kill()
		other.Wait()
	}()
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	pids := startReporting(t, cl, `setsid sleep 35 >/dev/null 2>&1 & echo $!; echo ready; wait`)
	defer syscall.Kill(pids[0], syscall.SIGKILL)
	waitExec(t, pids)
	cl.Close()
	if !waitGone(pids[0]) {
		t.Error("the command's own process outlived the cancel")
	}
	if gone(other.Process.Pid) {
		t.Error("a process outside the command was killed with it")
	}
}

// As process 1 of a PID namespace, as in a container without an init, the
// agent reaps the processes its commands leave behind, and still sees the
// exit status of each of its own commands and shells.
func TestOrphansReapedAsProcessOne(t *testing.T) {
	if os.Getenv("TERN_TEST_PIDNS") == "" {
		runInPIDNamespace(t)
		return
	}
	if os.Getpid() != 1 {
		t.Skip("not process 1")
	}
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	for i := 0; i < 5; i++ {
		// sh ends at once and its job becomes the agent's child; killed
		// with sh's process group, it is a zombie for the agent to reap.
		if _, err := cl.Run([]string{"sh", "-c", "sleep 30 >/dev/null 2>&1 &"}, nil, io.Discard); err != nil {
			t.Fatal(err)
		}
	}
	// Meanwhile commands and shells start and end, and orphans keep coming:
	// the reaper never takes one of the agent's own children.
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Go(func() {
			code, err := cl.Run([]string{"sh", "-c", "(sleep 0.01 &); exit 7"}, nil, io.Discard)
			if err != nil || code != 7 {
				t.Errorf("exit status %d, %v; want 7", code, err)
			}
		})
	}
	wg.Go(func() {
		sh, err := cl.OpenShell(ShellOptions{Session: "reap", Mode: modeNew, Write: true, Cols: 80, Rows: 24})
		if err != nil {
			t.Error(err)
			return
		}
		sh.Write([]byte("exit 3\n"))
		if !sh.CopyOutput(io.Discard) {
			t.Error("the shell's end was not reported")
		}
	})
	wg.Wait()
	var zs []int
	for i := 0; i < 100; i++ {
		zs = zs[:0]
		procs, _ := readProcs()
		for pid, pr := range procs {
			if pr.ppid == 1 && pr.state == 'Z' {
				zs = append(zs, pid)
			}
		}
		if len(zs) == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("zombie children of the agent left: %v", zs)
}

// An exec'd command has no controlling terminal, even when ternd runs on
// one: it cannot open /dev/tty, read from it or take it over.
func TestExecHasNoControllingTerminal(t *testing.T) {
	if os.Getenv("TERN_TEST_CTTY") == "" {
		runOnTerminal(t)
		return
	}
	if _, err := os.Open("/dev/tty"); err != nil {
		t.Skipf("the test has no controlling terminal: %v", err)
	}
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	var out bytes.Buffer
	// Field 7 of /proc/self/stat is the controlling terminal's device, 0 for none.
	if _, err := cl.Run([]string{"sh", "-c", "cut -d' ' -f7 /proc/self/stat; (exec 3</dev/tty) 2>/dev/null && echo opened-the-terminal"}, nil, &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Fields(out.String())
	if len(lines) == 0 || lines[0] != "0" || strings.Contains(out.String(), "opened-the-terminal") {
		t.Errorf("the command shares ternd's controlling terminal: %q", out.String())
	}
}

// runOnTerminal runs the calling test again in a process whose controlling
// terminal is a new pseudo-terminal.
func runOnTerminal(t *testing.T) {
	p, err := pty.New()
	if err != nil {
		t.Skipf("no pseudo-terminal: %v", err)
	}
	defer p.Close()
	c := p.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.v", "-test.count=1")
	c.Env = append(os.Environ(), "TERN_TEST_CTTY=1")
	if err := c.Start(); err != nil {
		t.Skipf("start on a terminal: %v", err)
	}
	var out bytes.Buffer
	read := make(chan struct{})
	go func() {
		io.Copy(&out, p) // until the terminal's last user is gone
		close(read)
	}()
	c.Wait()
	p.Close()
	<-read
	switch s := out.String(); {
	case strings.Contains(s, "--- FAIL"):
		t.Fatalf("on a terminal:\n%s", s)
	case strings.Contains(s, "--- SKIP"):
		t.Skipf("on a terminal:\n%s", s)
	case strings.Contains(s, "--- PASS: "+t.Name()):
		t.Logf("on a terminal:\n%s", s)
	default:
		t.Fatalf("on a terminal, no result:\n%s", s)
	}
}

// ternd's shutdown wait, giving up on a kill pass still under way, kills the
// processes that pass has stopped: none is left stopped for good once ternd
// exits.
func TestClosingWaitLeavesNoProcessStopped(t *testing.T) {
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	exited := make(chan struct{})
	go func() {
		cmd.Wait()
		close(exited)
	}()
	defer func() {
		unix.Kill(pid, unix.SIGKILL)
		<-exited
	}()
	pr, ok := readProc(pid)
	if !ok {
		t.Fatal("no stat line for the process")
	}
	p := beginKill(func(pid int, start uint64) { signalProc(pid, start, unix.SIGKILL) })
	if p == nil {
		t.Fatal("a kill pass did not begin")
	}
	defer p.end()
	if !p.stopping(pid, pr.start) || !signalProc(pid, pr.start, unix.SIGSTOP) {
		t.Fatal("the pass could not stop the process")
	}
	reopenKills(t)
	if waitKills(50*time.Millisecond, true) {
		t.Fatal("the closing wait did not give up on the pass")
	}
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		st, _ := readProc(pid)
		t.Fatalf("the process the pass stopped is left in state %c after the closing wait", st.state)
	}
}

// A signal by number never goes out by a thread's id, which /proc/<tid>
// answers to as a process's id does: it would reach the whole process the
// thread is in. The process's own id still takes it.
func TestSignalByNumberSparesThreadIDs(t *testing.T) {
	if os.Getenv("TERN_TEST_THREADS") != "" {
		// A process with threads of its own, for the test that started it.
		for range 4 {
			go func() {
				runtime.LockOSThread()
				select {}
			}()
		}
		time.Sleep(time.Minute)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), "TERN_TEST_THREADS=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	defer func() {
		unix.Kill(pid, unix.SIGKILL)
		cmd.Wait()
	}()
	tid := 0
	for deadline := time.Now().Add(5 * time.Second); tid == 0 && time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		ents, _ := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
		for _, e := range ents {
			if n, _ := strconv.Atoi(e.Name()); n > 0 && n != pid {
				tid = n
			}
		}
	}
	if tid == 0 {
		t.Skip("the process has no other thread")
	}
	thread, ok := readProc(tid)
	if !ok {
		t.Fatalf("no stat line for thread %d", tid)
	}
	if killByNumber(tid, thread.start, unix.SIGSTOP) || signalProc(tid, thread.start, unix.SIGSTOP) {
		t.Errorf("a signal went out by the id of thread %d", tid)
	}
	time.Sleep(100 * time.Millisecond)
	if st, _ := readProc(pid); st.state == 'T' {
		unix.Kill(pid, unix.SIGCONT)
		t.Fatalf("a signal by the id of thread %d stopped its process %d", tid, pid)
	}
	proc, ok := readProc(pid)
	if !ok || !killByNumber(pid, proc.start, unix.SIGSTOP) {
		t.Fatalf("no signal went to process %d by its own id", pid)
	}
	for i := 0; ; i++ {
		if st, _ := readProc(pid); st.state == 'T' {
			break
		}
		if i == 200 {
			t.Fatalf("process %d was not stopped", pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Under a /proc of another PID namespace, as a process in a namespace of its
// own sees when no /proc of that namespace is mounted, a command's kill
// looks for no process: the numbers listed there name, in here, unrelated
// processes. A session outside has a member whose number is, in here, that
// of a process of ours, which a kill of a session with the outside leader's
// number must spare.
func TestKillSessionSkipsForeignProc(t *testing.T) {
	if os.Getenv("TERN_TEST_FOREIGNPROC") != "" {
		killSessionUnderForeignProc(t)
		return
	}
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skip("needs unshare(1)")
	}
	outside := exec.Command("sh", "-c", "sleep 60 & echo $!; wait")
	outside.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	out, err := outside.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := outside.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		syscall.Kill(-outside.Process.Pid, syscall.SIGKILL)
		outside.Wait()
	}()
	line, err := bufio.NewReader(out).ReadString('\n')
	member, aerr := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || aerr != nil {
		t.Fatalf("the session's member: %q, %v", line, err)
	}
	// No --mount-proc: the namespace keeps this /proc, another namespace's.
	cmd := exec.Command(unshare, "-Urpf", os.Args[0], "-test.run=^"+t.Name()+"$", "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), "TERN_TEST_FOREIGNPROC=1",
		"TERN_TEST_LEADER="+strconv.Itoa(outside.Process.Pid), "TERN_TEST_MEMBER="+strconv.Itoa(member))
	o, err := cmd.CombinedOutput()
	switch {
	case bytes.Contains(o, []byte("--- FAIL")):
		t.Fatalf("in a PID namespace with another namespace's /proc:\n%s", o)
	case bytes.Contains(o, []byte("--- SKIP")):
		t.Skipf("in a PID namespace with another namespace's /proc:\n%s", o)
	case bytes.Contains(o, []byte("--- PASS: "+t.Name())):
		t.Logf("in a PID namespace with another namespace's /proc:\n%s", o)
	default:
		t.Skipf("no PID namespace here (%v):\n%s", err, o)
	}
}

func killSessionUnderForeignProc(t *testing.T) {
	if ownProc() {
		t.Skip("this namespace has a /proc of its own")
	}
	leader, err1 := strconv.Atoi(os.Getenv("TERN_TEST_LEADER"))
	member, err2 := strconv.Atoi(os.Getenv("TERN_TEST_MEMBER"))
	if err1 != nil || err2 != nil {
		t.Fatal("no session to kill")
	}
	// A process of ours takes the outside member's number, as numbers
	// collide once this namespace's pids reach the outside ones.
	var ours *exec.Cmd
	for try := 0; try < 10 && ours == nil; try++ {
		if err := os.WriteFile("/proc/sys/kernel/ns_last_pid", []byte(strconv.Itoa(member-1)), 0); err != nil {
			t.Skipf("ns_last_pid: %v", err)
		}
		c := exec.Command("sleep", "60")
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		if c.Process.Pid == member {
			ours = c
			break
		}
		c.Process.Kill()
		c.Wait()
	}
	if ours == nil {
		t.Skipf("no process of ours got the number %d", member)
	}
	defer func() {
		ours.Process.Kill()
		ours.Wait()
	}()
	t.Logf("outside, %d leads a session with member %d; in here, %d is a process of ours", leader, member, member)
	killSession(leader)
	time.Sleep(200 * time.Millisecond)
	// Our process still runs, not stopped: nothing about it is waitable.
	var info unix.Siginfo
	if err := unix.Waitid(unix.P_PID, member, &info, unix.WEXITED|unix.WSTOPPED|unix.WNOHANG|unix.WNOWAIT, nil); err != nil {
		t.Fatal(err)
	}
	if info.Signo != 0 {
		t.Errorf("a kill of session %d, led by a process of another namespace, stopped or ended process %d of ours (code %d)", leader, member, info.Code)
	}
}
