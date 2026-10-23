// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

// Package e2e drives the real tern/ternd/ternr/rtern binaries end to end over
// loopback. The exec, relay, copy, forward and REST tests run on every
// platform; the interactive PTY tests (shell, sessions, recording, rtern) run
// on Unix and, on Windows, only with TERN_E2E_PTY set from a real console. The
// binaries are built once in TestMain.
package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/aymanbagabas/go-pty"
	tern "github.com/ternimal/tern/internal/tern"
)

var (
	bin  = map[string]string{} // name -> absolute path of the built binary
	repo string                // module root
)

func exeName(n string) string {
	if runtime.GOOS == "windows" {
		return n + ".exe"
	}
	return n
}

func TestMain(m *testing.M) {
	root, err := filepath.Abs("..")
	if err != nil {
		fmt.Fprintln(os.Stderr, "abs:", err)
		os.Exit(2)
	}
	repo = root
	dir, err := os.MkdirTemp("", "tern-e2e-bin")
	if err != nil {
		fmt.Fprintln(os.Stderr, "mktemp:", err)
		os.Exit(2)
	}
	for _, c := range []string{"tern", "ternd", "ternr", "rtern"} {
		out := filepath.Join(dir, exeName(c))
		cmd := exec.Command("go", "build", "-o", out, "./cmd/"+c)
		cmd.Dir = repo
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "build %s: %v\n", c, err)
			os.RemoveAll(dir)
			os.Exit(2)
		}
		bin[c] = out
	}
	code := m.Run()
	os.RemoveAll(dir) // os.Exit skips deferred calls, so clean up explicitly
	os.Exit(code)
}

// --- helpers ---------------------------------------------------------------

// agentShell returns a shell that is guaranteed to exist on the test host.
// On Unix we force /bin/sh for a deterministic shell regardless of $SHELL; on
// Windows the agent's default cmd.exe is fine.
func agentShell() string {
	if runtime.GOOS == "windows" {
		return "" // default (cmd.exe via ComSpec)
	}
	return "/bin/sh"
}

// execArgv builds a one-shot command (for `tern run` / the REST API) that prints
// marker and exits with code, portable across cmd.exe and /bin/sh.
func execArgv(marker string, code int) []string {
	if runtime.GOOS == "windows" {
		return []string{"cmd", "/c", fmt.Sprintf("echo %s& exit %d", marker, code)}
	}
	return []string{"/bin/sh", "-c", fmt.Sprintf("echo %s; exit %d", marker, code)}
}

func genToken(t *testing.T) string {
	t.Helper()
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return hex.EncodeToString(b) // 48 chars, above the 16-char minimum for agent and relay tokens
}

// freePort returns a port that is free on both loopback addresses, since a
// listener on 127.0.0.1 also holds its port on ::1 and refuses to start when
// that is taken. Where ::1 cannot be listened on at all, a port free on
// 127.0.0.1 is enough.
func freePort(t *testing.T) int {
	t.Helper()
	port := 0
	for range 50 {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("freePort: %v", err)
		}
		port = l.Addr().(*net.TCPAddr).Port
		l6, err := net.Listen("tcp", fmt.Sprintf("[::1]:%d", port))
		l.Close()
		if err == nil {
			l6.Close()
			return port
		}
	}
	return port
}

func addr(port int) string { return fmt.Sprintf("127.0.0.1:%d", port) }

// proc is a spawned long-lived binary with its combined output captured.
type proc struct {
	cmd *exec.Cmd
	buf *lockedBuffer
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func start(t *testing.T, name string, env []string, args ...string) *proc {
	t.Helper()
	cmd := exec.Command(bin[name], args...)
	cmd.Dir = t.TempDir()
	if env != nil {
		cmd.Env = append(os.Environ(), env...)
	}
	lb := &lockedBuffer{}
	cmd.Stdout = lb
	cmd.Stderr = lb
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", name, err)
	}
	p := &proc{cmd: cmd, buf: lb}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		// Bounded wait so a process that ignores Kill can never hang the suite.
		done := make(chan struct{})
		go func() { _, _ = cmd.Process.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	})
	return p
}

// waitFor polls p's output for re until timeout, returning the first submatch[1].
func (p *proc) waitFor(t *testing.T, re *regexp.Regexp, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if m := re.FindStringSubmatch(p.buf.String()); m != nil {
			if len(m) > 1 {
				return m[1]
			}
			return m[0]
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %q; output so far:\n%s", re, p.buf.String())
	return ""
}

var (
	reFingerprint = regexp.MustCompile(`agent fingerprint: ([0-9a-f]{64})`)
	reConnStr     = regexp.MustCompile(`(tern1:[A-Za-z0-9_-]+)`)
	reRelayFP     = regexp.MustCompile(`([0-9a-f]{64})`)
)

// waitListen waits until something accepts connections on address. The
// output of the processes given is shown if nothing does.
func waitListen(t *testing.T, address string, timeout time.Duration, procs ...*proc) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", address, 300*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	var out strings.Builder
	for _, p := range procs {
		out.WriteString(p.buf.String())
	}
	t.Fatalf("nothing listening on %s after %s; output:\n%s", address, timeout, out.String())
}

// agent is a direct-mode ternd.
type agent struct {
	addr, fp, token, cert string
}

func startDirectAgent(t *testing.T, extra ...string) agent {
	t.Helper()
	return startAgentBin(t, "ternd", extra...)
}

// startAgentBin starts a direct-mode agent from binary bin[name].
func startAgentBin(t *testing.T, name string, extra ...string) agent {
	t.Helper()
	tok := genToken(t)
	port := freePort(t)
	cert := filepath.Join(t.TempDir(), "agent")
	args := []string{"--addr", addr(port), "--token", tok, "--cert", cert}
	if s := agentShell(); s != "" {
		args = append(args, "--shell", s)
	}
	args = append(args, extra...)
	p := start(t, name, nil, args...)
	fp := p.waitFor(t, reFingerprint, 15*time.Second)
	waitListen(t, addr(port), 10*time.Second, p)
	return agent{addr: addr(port), fp: fp, token: tok, cert: cert}
}

// runClient runs a short-lived tern subcommand to completion.
func runClient(t *testing.T, timeout time.Duration, args ...string) (string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin["tern"], args...)
	cmd.Dir = t.TempDir()
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("client timed out: tern %s\n%s", strings.Join(args, " "), out.String())
	}
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = -1
		}
	}
	return out.String(), code
}

// cs builds a direct tern1: connection string for this agent (for tests that
// need a connection string rather than explicit flags).
func (a agent) cs(t *testing.T) string {
	t.Helper()
	return tern.ConnString{Mode: "direct", Addr: a.addr, FP: a.fp}.Encode()
}

// dialArgs are the client flags to reach a direct agent.
func (a agent) dialArgs() []string {
	return []string{"--addr", a.addr, "--fingerprint", a.fp, "--token", a.token}
}

// --- tests -----------------------------------------------------------------

func TestExecDirectToken(t *testing.T) {
	a := startDirectAgent(t)
	args := append([]string{"run"}, a.dialArgs()...)
	args = append(args, "--")
	args = append(args, execArgv("EXEC_OK_49", 0)...)
	out, code := runClient(t, 20*time.Second, args...)
	if !strings.Contains(out, "EXEC_OK_49") {
		t.Fatalf("missing marker; got:\n%s", out)
	}
	if code != 0 {
		t.Fatalf("exit=%d want 0; out:\n%s", code, out)
	}
}

func TestExecExitCodePropagation(t *testing.T) {
	a := startDirectAgent(t)
	args := append([]string{"run"}, a.dialArgs()...)
	args = append(args, "--")
	args = append(args, execArgv("bye", 7)...)
	_, code := runClient(t, 20*time.Second, args...)
	if code != 7 {
		t.Fatalf("exit=%d want 7 (remote exit code must propagate)", code)
	}
}

// TestPositionalConn checks the tern1: connection string works as a leading
// positional argument (shorthand for --to).
func TestPositionalConn(t *testing.T) {
	tok := genToken(t)
	port := freePort(t)
	cert := filepath.Join(t.TempDir(), "agent")
	args := []string{"--addr", addr(port), "--token", tok, "--cert", cert}
	if s := agentShell(); s != "" {
		args = append(args, "--shell", s)
	}
	p := start(t, "ternd", nil, args...)
	cs := p.waitFor(t, reConnStr, 15*time.Second)
	waitListen(t, addr(port), 10*time.Second)

	runArgs := []string{"run", cs, "--token", tok, "--"} // connstr as positional, no --to
	runArgs = append(runArgs, execArgv("POSITIONAL_OK", 0)...)
	out, code := runClient(t, 20*time.Second, runArgs...)
	if code != 0 || !strings.Contains(out, "POSITIONAL_OK") {
		t.Fatalf("positional connstr failed exit=%d:\n%s", code, out)
	}
}

// TestShortAliases checks the single-letter flag aliases resolve.
func TestShortAliases(t *testing.T) {
	a := startDirectAgent(t)
	args := []string{"run", "-a", a.addr, "-f", a.fp, "-t", a.token, "--"} // -a/-f/-t
	args = append(args, execArgv("ALIAS_OK", 0)...)
	out, code := runClient(t, 20*time.Second, args...)
	if code != 0 || !strings.Contains(out, "ALIAS_OK") {
		t.Fatalf("short-alias exec failed exit=%d:\n%s", code, out)
	}
}

func TestExecKeyAuth(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id")
	if out, code := runClient(t, 10*time.Second, "keygen", "--out", keyPath); code != 0 {
		t.Fatalf("keygen failed: %s", out)
	}
	pub, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		t.Fatalf("read pub: %v", err)
	}
	ak := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(ak, pub, 0o644); err != nil {
		t.Fatalf("write authorized_keys: %v", err)
	}

	port := freePort(t)
	cert := filepath.Join(dir, "agent")
	args := []string{"--addr", addr(port), "--authorized-keys", ak, "--cert", cert}
	if s := agentShell(); s != "" {
		args = append(args, "--shell", s)
	}
	p := start(t, "ternd", nil, args...)
	fp := p.waitFor(t, reFingerprint, 15*time.Second)
	waitListen(t, addr(port), 10*time.Second)

	runArgs := []string{"run", "--addr", addr(port), "--fingerprint", fp, "--key", keyPath, "--"}
	runArgs = append(runArgs, execArgv("KEY_OK", 0)...)
	out, code := runClient(t, 20*time.Second, runArgs...)
	if code != 0 || !strings.Contains(out, "KEY_OK") {
		t.Fatalf("key-auth exec failed exit=%d:\n%s", code, out)
	}
}

type relay struct {
	addr, fp, token string
}

func startRelayServer(t *testing.T) relay {
	t.Helper()
	tok := genToken(t)
	port := freePort(t)
	cert := filepath.Join(t.TempDir(), "relay")
	p := start(t, "ternr", []string{"TERN_RELAY_TOKEN=" + tok},
		"--addr", addr(port), "--cert", cert)
	fp := p.waitFor(t, reRelayFP, 15*time.Second)
	waitListen(t, addr(port), 10*time.Second)
	return relay{addr: addr(port), fp: fp, token: tok}
}

func TestRelayExec(t *testing.T) {
	r := startRelayServer(t)
	ctok := genToken(t)

	cert := filepath.Join(t.TempDir(), "agentr")
	dargs := []string{"--relay", r.addr, "--relay-fingerprint", r.fp,
		"--id", "box1", "--token", ctok, "--cert", cert}
	if s := agentShell(); s != "" {
		dargs = append(dargs, "--shell", s)
	}
	d := start(t, "ternd", []string{"TERN_RELAY_TOKEN=" + r.token}, dargs...)
	cs := d.waitFor(t, reConnStr, 15*time.Second)

	// ternd prints the string without the relay token, its operator's secret.
	runArgs := []string{"run", "--to", cs, "--token", ctok, "--relay-token", r.token, "--"}
	runArgs = append(runArgs, execArgv("RELAY_OK_42", 0)...)
	out, code := runClient(t, 25*time.Second, runArgs...)
	if code != 0 || !strings.Contains(out, "RELAY_OK_42") {
		t.Fatalf("relay exec failed exit=%d:\n%s", code, out)
	}
}

func TestFileCopyRoundTrip(t *testing.T) {
	a := startDirectAgent(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "src.bin")
	payload := []byte("cp-payload-" + genToken(t))
	if err := os.WriteFile(src, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	remote := filepath.Join(dir, "remote.bin")
	back := filepath.Join(dir, "back.bin")

	up := append([]string{"cp"}, a.dialArgs()...)
	up = append(up, src, "agent:"+remote)
	if out, code := runClient(t, 20*time.Second, up...); code != 0 {
		t.Fatalf("upload failed exit=%d: %s", code, out)
	}
	down := append([]string{"cp"}, a.dialArgs()...)
	down = append(down, "agent:"+remote, back)
	if out, code := runClient(t, 20*time.Second, down...); code != 0 {
		t.Fatalf("download failed exit=%d: %s", code, out)
	}
	got, err := os.ReadFile(back)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, payload)
	}
}

// TestFileCopyIntoDirectories: as with cp and scp, a destination that ends in
// a separator or is an existing local directory keeps the file's name; an
// existing remote directory without one is refused clearly, and nothing is
// left behind.
func TestFileCopyIntoDirectories(t *testing.T) {
	a := startDirectAgent(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "src.bin")
	payload := []byte("dir-payload-" + genToken(t))
	if err := os.WriteFile(src, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	updir, downdir := filepath.Join(dir, "up"), filepath.Join(dir, "down")
	os.Mkdir(updir, 0o755)
	os.Mkdir(downdir, 0o755)
	cp := func(from, to string) (string, int) {
		return runClient(t, 20*time.Second, append(append([]string{"cp"}, a.dialArgs()...), from, to)...)
	}
	if out, code := cp(src, "agent:"+updir+string(filepath.Separator)); code != 0 {
		t.Fatalf("upload into a directory failed: %s", out)
	}
	if b, _ := os.ReadFile(filepath.Join(updir, "src.bin")); !bytes.Equal(b, payload) {
		t.Fatalf("upload into a directory wrote %q", b)
	}
	if out, code := cp(src, "agent:"+updir); code == 0 || !strings.Contains(out, "is a directory") {
		t.Fatalf("upload onto a directory = %d %q, want a clear refusal", code, out)
	}
	remote := "agent:" + filepath.Join(updir, "src.bin")
	for _, to := range []string{downdir + string(filepath.Separator), downdir} {
		os.Remove(filepath.Join(downdir, "src.bin"))
		if out, code := cp(remote, to); code != 0 {
			t.Fatalf("download into %q failed: %s", to, out)
		}
		if b, _ := os.ReadFile(filepath.Join(downdir, "src.bin")); !bytes.Equal(b, payload) {
			t.Fatalf("download into %q wrote %q", to, b)
		}
	}
	for _, d := range []string{dir, updir, downdir} {
		ents, _ := os.ReadDir(d)
		for _, e := range ents {
			if strings.HasSuffix(e.Name(), ".part") || strings.Contains(e.Name(), ".tern-") {
				t.Errorf("left behind: %s", filepath.Join(d, e.Name()))
			}
		}
	}
}

// ptyConn runs an interactive binary under a real PTY with a single background
// reader, so tests can wait for output and inject input without racing.
type ptyConn struct {
	p   pty.Pty
	c   *pty.Cmd
	buf *lockedBuffer
}

func dialPTY(t *testing.T, binName string, args ...string) *ptyConn {
	t.Helper()
	// Hosted Windows runners have no attachable console, so go-pty's ConPTY
	// cannot drive an interactive client there. On Windows these tests run
	// only when TERN_E2E_PTY is set (e.g. TERN_E2E_PTY=1) from a real console.
	if runtime.GOOS == "windows" && os.Getenv("TERN_E2E_PTY") == "" {
		t.Skip("interactive pty test skipped on Windows; set TERN_E2E_PTY=1 from a real console to run it")
	}
	p, err := pty.New()
	if err != nil {
		t.Skipf("pty unavailable: %v", err)
	}
	c := p.Command(bin[binName], args...)
	if err := c.Start(); err != nil {
		t.Fatalf("start %s under pty: %v", binName, err)
	}
	lb := &lockedBuffer{}
	go func() {
		b := make([]byte, 4096)
		for {
			n, err := p.Read(b)
			if n > 0 {
				lb.Write(b[:n])
			}
			if err != nil {
				return
			}
		}
	}()
	pc := &ptyConn{p: p, c: c, buf: lb}
	t.Cleanup(func() { _ = c.Process.Kill(); p.Close() })
	return pc
}

func (pc *ptyConn) waitFor(sub string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(strings.ToLower(pc.buf.String()), strings.ToLower(sub)) {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func (pc *ptyConn) write(s string) { _, _ = pc.p.Write([]byte(s)) }

// typeUntil types line until want shows up. What is typed the moment a
// session attaches can be lost while the shell starts, as seen with cmd.exe
// under ConPTY, so the line is typed again until the shell runs it.
func (pc *ptyConn) typeUntil(line, want string, timeout time.Duration) bool {
	for deadline := time.Now().Add(timeout); time.Now().Before(deadline); {
		pc.write(line)
		if pc.waitFor(want, 2*time.Second) {
			return true
		}
	}
	return false
}

// waitExit reports whether the process exited before timeout.
func (pc *ptyConn) waitExit(timeout time.Duration) bool {
	done := make(chan struct{})
	go func() { _ = pc.c.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		_ = pc.c.Process.Kill()
		return false
	}
}

// TestInteractiveShellExit: typing `exit` must end the client cleanly, never
// hang or reconnect. On Windows this guards the ConPTY case where the PTY read
// does not return EOF when the shell exits (see sharedPTY.pump).
func TestInteractiveShellExit(t *testing.T) {
	a := startDirectAgent(t)
	pc := dialPTY(t, "tern", append([]string{"connect"}, a.dialArgs()...)...)
	if !pc.waitFor("attached to session", 15*time.Second) {
		t.Fatalf("never attached; output:\n%s", pc.buf.String())
	}
	time.Sleep(500 * time.Millisecond)
	pc.write("exit\r\n")
	// Poll for the banner while the reader is still draining: on Windows ConPTY
	// the final line can arrive right as the pty closes.
	gotBanner := pc.waitFor("session ended", 15*time.Second)
	exited := pc.waitExit(10 * time.Second)
	out := pc.buf.String()

	// The terminal is still raw when this line prints: it must end with CR LF
	// so the shell prompt that follows starts at column 0.
	if runtime.GOOS != "windows" && !strings.Contains(out, "[tern] session ended\r\n") {
		t.Errorf("the session-ended line does not end with CR LF; the next prompt would be indented:\n%q", out)
	}
	// The client must quit and must not reconnect.
	if strings.Contains(strings.ToLower(out), "reconnect") {
		t.Fatalf("client tried to reconnect on shell exit; output:\n%s", out)
	}
	if !exited {
		t.Fatalf("client did not exit after `exit`; output:\n%s", out)
	}
	// The banner is captured reliably on Unix; on Windows the pty may drop the
	// very last write when the pseudoconsole closes, so a clean exit is enough.
	if !gotBanner && runtime.GOOS != "windows" {
		t.Fatalf("missing 'session ended' banner; output:\n%s", out)
	}
}

func TestListSessions(t *testing.T) {
	a := startDirectAgent(t)
	hold := dialPTY(t, "tern", append([]string{"connect", "--session", "demo"}, a.dialArgs()...)...)
	if !hold.waitFor("attached to session", 15*time.Second) {
		t.Fatalf("hold session never attached:\n%s", hold.buf.String())
	}
	lsArgs := append([]string{"list"}, a.dialArgs()...)
	out, code := runClient(t, 15*time.Second, lsArgs...)
	if code != 0 {
		t.Fatalf("list exit=%d: %s", code, out)
	}
	if !strings.Contains(out, "demo") {
		t.Fatalf("list did not show session 'demo':\n%s", out)
	}
}

// openWriter creates a session as its (sole) writer and returns once attached.
func openWriter(t *testing.T, a agent, session string) *ptyConn {
	t.Helper()
	w := dialPTY(t, "tern", append([]string{"connect", "--session", session}, a.dialArgs()...)...)
	if !w.waitFor("attached to session", 15*time.Second) {
		t.Fatalf("writer never attached:\n%s", w.buf.String())
	}
	if strings.Contains(strings.ToLower(w.buf.String()), "read-only") {
		t.Fatalf("session creator was unexpectedly read-only:\n%s", w.buf.String())
	}
	return w
}

// TestMultiClientSingleWriter: a second client that does not ask to co-drive
// joins a session that already has an attached writer as read-only.
func TestMultiClientSingleWriter(t *testing.T) {
	a := startDirectAgent(t)
	_ = openWriter(t, a, "sw")
	r := dialPTY(t, "tern", append([]string{"connect", "--session", "sw"}, a.dialArgs()...)...)
	if !r.waitFor("attached to session", 15*time.Second) {
		t.Fatalf("second client never attached:\n%s", r.buf.String())
	}
	if !strings.Contains(strings.ToLower(r.buf.String()), "read-only") {
		t.Fatalf("second client should be read-only by default (single-writer):\n%s", r.buf.String())
	}
}

// TestViewerCtrlCLeaves: the agent ignores a read-only viewer's keys, so its
// Ctrl-C detaches it; the session and its writer carry on.
func TestViewerCtrlCLeaves(t *testing.T) {
	a := startDirectAgent(t)
	w := openWriter(t, a, "watch")
	v := dialPTY(t, "tern", append([]string{"connect", "--session", "watch", "--read-only"}, a.dialArgs()...)...)
	if !v.waitFor("read-only", 15*time.Second) {
		t.Fatalf("viewer never attached:\n%s", v.buf.String())
	}
	v.write("\x03")
	if !v.waitExit(10*time.Second) || !v.waitFor("detached", time.Second) {
		t.Fatalf("Ctrl-C did not detach the viewer:\n%s", v.buf.String())
	}
	if !w.typeUntil(pick("echo STILL_$((40+2))\r", "echo STILL_^4^2\r"), "STILL_42", 10*time.Second) {
		t.Fatalf("the writer lost the session when the viewer left:\n%s", w.buf.String())
	}
}

// TestConnectDetachesOnSIGTERM: a signal ends an attached client cleanly and
// leaves the session running for a later attach, as closing the window does.
func TestConnectDetachesOnSIGTERM(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no SIGTERM")
	}
	a := startDirectAgent(t)
	w := openWriter(t, a, "sig")
	if err := w.c.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if !w.waitExit(10*time.Second) || !w.waitFor("detached", time.Second) {
		t.Fatalf("SIGTERM did not detach the client:\n%s", w.buf.String())
	}
	if out, _ := runClient(t, 15*time.Second, append([]string{"list"}, a.dialArgs()...)...); !strings.Contains(out, "sig") {
		t.Fatalf("the session ended with the client: %q", out)
	}
}

// TestMultiClientExplicitReadOnly: --read-only always attaches as a viewer.
func TestMultiClientExplicitReadOnly(t *testing.T) {
	a := startDirectAgent(t)
	_ = openWriter(t, a, "ro")
	r := dialPTY(t, "tern", append([]string{"connect", "--session", "ro", "--read-only"}, a.dialArgs()...)...)
	if !r.waitFor("read-only", 10*time.Second) {
		t.Fatalf("client with --read-only was not a viewer:\n%s", r.buf.String())
	}
}

// TestMultiClientCoDrive: --read-only=false explicitly opts into co-driving, so
// the second client attaches as a writer (no [read-only] marker).
func TestMultiClientCoDrive(t *testing.T) {
	a := startDirectAgent(t)
	_ = openWriter(t, a, "cd")
	r := dialPTY(t, "tern", append([]string{"connect", "--session", "cd", "--read-only=false"}, a.dialArgs()...)...)
	if !r.waitFor("attached to session", 15*time.Second) {
		t.Fatalf("co-drive client never attached:\n%s", r.buf.String())
	}
	if strings.Contains(strings.ToLower(r.buf.String()), "read-only") {
		t.Fatalf("--read-only=false client should co-drive (writer), got read-only:\n%s", r.buf.String())
	}
}

// TestSessionResume drops a connection without exiting the shell and reconnects
// to the same session, expecting the scrollback replay to carry prior output.
func TestSessionResume(t *testing.T) {
	a := startDirectAgent(t)
	c1 := dialPTY(t, "tern", append([]string{"connect", "--session", "resume"}, a.dialArgs()...)...)
	if !c1.waitFor("attached to session", 15*time.Second) {
		t.Fatalf("first attach failed:\n%s", c1.buf.String())
	}
	if !c1.typeUntil("echo RESUME_MARK_XYZ\r\n", "RESUME_MARK_XYZ", 10*time.Second) {
		t.Fatalf("marker never echoed in session:\n%s", c1.buf.String())
	}
	_ = c1.c.Process.Kill() // drop the connection; session persists (session-idle default)
	time.Sleep(500 * time.Millisecond)

	c2 := dialPTY(t, "tern", append([]string{"connect", "--session", "resume"}, a.dialArgs()...)...)
	if !c2.waitFor("attached to session", 15*time.Second) {
		t.Fatalf("resume attach failed:\n%s", c2.buf.String())
	}
	if !c2.waitFor("RESUME_MARK_XYZ", 10*time.Second) {
		t.Fatalf("scrollback replay did not carry prior output:\n%s", c2.buf.String())
	}
}

// TestSessionRecording checks that --record-dir writes a playable asciicast.
func TestSessionRecording(t *testing.T) {
	recDir := t.TempDir()
	a := startDirectAgent(t, "--record-dir", recDir)
	pc := dialPTY(t, "tern", append([]string{"connect"}, a.dialArgs()...)...)
	if !pc.waitFor("attached to session", 15*time.Second) {
		t.Fatalf("attach failed:\n%s", pc.buf.String())
	}
	if !pc.typeUntil("echo REC_MARK_ABC\r\n", "REC_MARK_ABC", 10*time.Second) {
		t.Fatalf("the shell never ran the command:\n%s", pc.buf.String())
	}
	pc.write("exit\r\n")
	pc.waitExit(15 * time.Second)

	// find a .cast file and verify it is a v2 asciicast with our output
	var cast string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && cast == "" {
		entries, _ := os.ReadDir(recDir)
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".cast") {
				cast = filepath.Join(recDir, e.Name())
			}
		}
		if cast == "" {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if cast == "" {
		t.Fatal("no .cast recording was written")
	}
	data, err := os.ReadFile(cast)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "\"version\":2") {
		t.Fatalf("recording missing asciicast header:\n%s", first(string(data), 200))
	}
	if !strings.Contains(string(data), "REC_MARK_ABC") {
		t.Fatalf("recording did not capture session output")
	}
}

func first(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// warmCert runs a direct ternd once so it mints its persistent TLS cert at
// certPath and prints its fingerprint, then stops it. The fingerprint is stable
// across restarts that reuse the same cert, which rtern needs to pin in advance.
func warmCert(t *testing.T, token, certPath string) string {
	t.Helper()
	port := freePort(t)
	args := []string{"--addr", addr(port), "--token", token, "--cert", certPath}
	if s := agentShell(); s != "" {
		args = append(args, "--shell", s)
	}
	p := start(t, "ternd", nil, args...)
	fp := p.waitFor(t, reFingerprint, 15*time.Second)
	_ = p.cmd.Process.Kill()
	_, _ = p.cmd.Process.Wait()
	time.Sleep(200 * time.Millisecond)
	return fp
}

func (pc *ptyConn) extract(re *regexp.Regexp, timeout time.Duration) string {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if m := re.FindStringSubmatch(pc.buf.String()); m != nil {
			return m[len(m)-1]
		}
		time.Sleep(50 * time.Millisecond)
	}
	return ""
}

// TestRternCombined exercises rtern (combined relay + client): an agent dials in
// and rtern drops into its shell; typing `exit` must quit cleanly through the
// combined relay path too.
func TestRternCombined(t *testing.T) {
	ctok := genToken(t)
	rtok := genToken(t)
	cert := filepath.Join(t.TempDir(), "agent")
	agentFP := warmCert(t, ctok, cert)

	// rtern runs under a PTY (its client side needs a real terminal for raw mode)
	rternPort := freePort(t)
	rternCert := filepath.Join(t.TempDir(), "rtern")
	rtc := dialPTY(t, "rtern",
		"--addr", addr(rternPort), "--fingerprint", agentFP, "--token", ctok,
		"--relay-token", rtok, "--cert", rternCert)
	rternFP := rtc.extract(reRelayFP, 15*time.Second)
	if rternFP == "" {
		t.Fatalf("rtern did not print its fingerprint:\n%s", rtc.buf.String())
	}
	waitListen(t, addr(rternPort), 10*time.Second)

	// agent dials out to rtern, reusing the warmed cert (same fingerprint)
	dargs := []string{"--relay", addr(rternPort), "--relay-fingerprint", rternFP,
		"--relay-token", rtok, "--token", ctok, "--id", "box1", "--cert", cert}
	if s := agentShell(); s != "" {
		dargs = append(dargs, "--shell", s)
	}
	d := start(t, "ternd", []string{"TERN_RELAY_TOKEN=" + rtok}, dargs...)

	if !rtc.waitFor("attached to session", 25*time.Second) {
		t.Fatalf("rtern never attached to the dialing agent:\n--- rtern ---\n%s\n--- agent ---\n%s", rtc.buf.String(), d.buf.String())
	}
	time.Sleep(500 * time.Millisecond)
	rtc.write("exit\r\n")
	if !rtc.waitExit(20 * time.Second) {
		t.Fatalf("rtern did not quit after `exit`:\n%s", rtc.buf.String())
	}
}

func TestLocalForward(t *testing.T) {
	a := startDirectAgent(t)
	// echo server that the forward will reach via the agent ("remote" side)
	echoPort := startEchoServer(t)
	lport := freePort(t)

	fargs := append([]string{"forward"}, a.dialArgs()...)
	fargs = append(fargs, "-L", fmt.Sprintf("127.0.0.1:%d:127.0.0.1:%d", lport, echoPort))
	f := start(t, "tern", nil, fargs...)
	_ = f
	waitListen(t, addr(lport), 10*time.Second)

	if err := echoRoundTrip(addr(lport), "hello-L"); err != nil {
		t.Fatalf("local forward failed: %v", err)
	}
}

// TestForwardBindFailureExits: a forward that cannot start (here the local
// port is already taken) must fail loudly instead of exiting 0 in silence.
func TestForwardBindFailureExits(t *testing.T) {
	a := startDirectAgent(t)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	spec := busy.Addr().String() + ":127.0.0.1:9"
	fargs := append([]string{"forward"}, a.dialArgs()...)
	fargs = append(fargs, "-L", spec)
	out, code := runClient(t, 20*time.Second, fargs...)
	if code == 0 {
		t.Fatalf("forward with an unusable -L exited 0:\n%s", out)
	}
	if !strings.Contains(out, "-L "+spec+":") {
		t.Fatalf("forward failure did not report the -L spec:\n%s", out)
	}
}

// TestDaemonVersionArg: `ternd version` (and the other daemons) prints the
// version and exits instead of starting the server; stray arguments are an
// error, not silently ignored.
func TestDaemonVersionArg(t *testing.T) {
	run := func(name, arg string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin[name], arg)
		cmd.Dir = t.TempDir() // should a daemon start after all, its files stay out of the tree
		return cmd.CombinedOutput()
	}
	for _, name := range []string{"ternd", "ternr", "rtern"} {
		out, err := run(name, "version")
		if err != nil || !strings.HasPrefix(string(out), name+" ") {
			t.Fatalf("%s version: err=%v out=%q", name, err, out)
		}
		out, err = run(name, "bogus")
		if err == nil || !strings.Contains(string(out), "unexpected argument") {
			t.Fatalf("%s bogus: want a usage error, got err=%v out=%q", name, err, out)
		}
	}
}

func TestRemoteForward(t *testing.T) {
	a := startDirectAgent(t)
	// echo server on the "client" side; agent will listen on rport and forward to it
	echoPort := startEchoServer(t)
	rport := freePort(t)

	fargs := append([]string{"forward"}, a.dialArgs()...)
	fargs = append(fargs, "-R", fmt.Sprintf("127.0.0.1:%d:127.0.0.1:%d", rport, echoPort))
	f := start(t, "tern", nil, fargs...)
	_ = f
	waitListen(t, addr(rport), 10*time.Second)

	if err := echoRoundTrip(addr(rport), "hello-R"); err != nil {
		t.Fatalf("remote forward failed: %v", err)
	}
}

func startEchoServer(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); io.Copy(c, c) }(c)
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

func echoRoundTrip(address, msg string) error {
	c, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte(msg)); err != nil {
		return err
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil {
		return err
	}
	if string(buf) != msg {
		return fmt.Errorf("echo mismatch: got %q want %q", buf, msg)
	}
	return nil
}

func TestRESTApi(t *testing.T) {
	a := startDirectAgent(t)
	apiTok := genToken(t)
	apiPort := freePort(t)
	aargs := append([]string{"api"}, a.dialArgs()...)
	aargs = append(aargs, "--api-addr", addr(apiPort), "--api-token", apiTok)
	start(t, "tern", nil, aargs...)
	waitListen(t, addr(apiPort), 10*time.Second)
	base := "http://" + addr(apiPort)

	// health (no auth)
	if resp, err := http.Get(base + "/v1/healthz"); err != nil || resp.StatusCode != 200 {
		t.Fatalf("healthz: err=%v status=%v", err, respStatus(resp))
	}

	// simple run
	body := map[string]any{"cmd": execArgv("API_RUN_OK", 0)}
	var runRes struct {
		Exit   int    `json:"exit"`
		Output string `json:"output"`
	}
	doJSON(t, "POST", base+"/v1/run", apiTok, body, &runRes)
	if runRes.Exit != 0 || !strings.Contains(runRes.Output, "API_RUN_OK") {
		t.Fatalf("/v1/run unexpected: %+v", runRes)
	}

	// stdin echo via run
	var stdinRes struct {
		Output string `json:"output"`
	}
	stdinBody := map[string]any{"cmd": stdinEchoArgv(), "stdin": "STDIN_PING\n"}
	doJSON(t, "POST", base+"/v1/run", apiTok, stdinBody, &stdinRes)
	if !strings.Contains(stdinRes.Output, "STDIN_PING") {
		t.Fatalf("/v1/run stdin not echoed: %q", stdinRes.Output)
	}

	// streaming exec (NDJSON)
	execBody := map[string]any{"cmd": execArgv("API_EXEC_OK", 0)}
	stream := doRaw(t, "POST", base+"/v1/exec", apiTok, execBody)
	if !strings.Contains(stream, "API_EXEC_OK") || !strings.Contains(stream, "\"exit\"") {
		t.Fatalf("/v1/exec stream unexpected:\n%s", stream)
	}

	// async job
	var jobStart struct {
		Job string `json:"job"`
	}
	doJSON(t, "POST", base+"/v1/jobs", apiTok, map[string]any{"cmd": execArgv("API_JOB_OK", 0)}, &jobStart)
	if jobStart.Job == "" {
		t.Fatal("/v1/jobs did not return a job id")
	}
	deadline := time.Now().Add(15 * time.Second)
	var out string
	for time.Now().Before(deadline) {
		out = doRaw(t, "GET", base+"/v1/jobs/"+jobStart.Job+"/output", apiTok, nil)
		if strings.Contains(out, "API_JOB_OK") {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !strings.Contains(out, "API_JOB_OK") {
		t.Fatalf("job output never contained marker:\n%s", out)
	}
}

func stdinEchoArgv() []string {
	if runtime.GOOS == "windows" {
		return []string{"sort"} // reads stdin, writes it back
	}
	return []string{"cat"}
}

func respStatus(r *http.Response) any {
	if r == nil {
		return "nil"
	}
	return r.StatusCode
}

func doJSON(t *testing.T, method, url, token string, body any, out any) {
	t.Helper()
	raw := doRaw(t, method, url, token, body)
	if err := json.Unmarshal([]byte(raw), out); err != nil {
		t.Fatalf("%s %s: bad json: %v\n%s", method, url, err, raw)
	}
}

func doRaw(t *testing.T, method, url, token string, body any) string {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		t.Fatalf("%s %s: status %d: %s", method, url, resp.StatusCode, b)
	}
	return string(b)
}

// --- reconnect, Ctrl-C and forward lifetime ---------------------------------

// stallProxy forwards its first connection to target and black-holes every
// later one (accepts, reads, never answers), like a peer that is reachable but
// wedged.
type stallProxy struct {
	ln    net.Listener
	n     atomic.Int32
	mu    sync.Mutex
	first []net.Conn
}

func newStallProxy(t *testing.T, target string) *stallProxy {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &stallProxy{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if p.n.Add(1) > 1 {
				go io.Copy(io.Discard, c) // never answers
				continue
			}
			u, err := net.Dial("tcp", target)
			if err != nil {
				c.Close()
				continue
			}
			p.mu.Lock()
			p.first = append(p.first, c, u)
			p.mu.Unlock()
			go func() { io.Copy(u, c); u.Close() }()
			go func() { io.Copy(c, u); c.Close() }()
		}
	}()
	return p
}

func (p *stallProxy) dropFirst() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.first {
		c.Close()
	}
}

// dropProxy forwards every connection to target; drop() kills the live ones.
// With halfOpen, drop() closes only the client side, so the agent keeps a
// stale attachment until its keepalive notices.
type dropProxy struct {
	ln       net.Listener
	halfOpen bool
	mu       sync.Mutex
	conns    []net.Conn
}

func newDropProxy(t *testing.T, target string, halfOpen bool) *dropProxy {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &dropProxy{ln: ln, halfOpen: halfOpen}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			u, err := net.Dial("tcp", target)
			if err != nil {
				c.Close()
				continue
			}
			p.mu.Lock()
			p.conns = append(p.conns, c)
			if !p.halfOpen {
				p.conns = append(p.conns, u)
			}
			p.mu.Unlock()
			go func() {
				io.Copy(u, c)
				if !p.halfOpen {
					u.Close()
				}
			}()
			go func() { io.Copy(c, u); c.Close() }()
		}
	}()
	return p
}

func (p *dropProxy) drop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.conns {
		c.Close()
	}
	p.conns = nil
}

// TestRternCtrlCWhileWaiting: Ctrl-C quits rtern while it waits for an agent.
func TestRternCtrlCWhileWaiting(t *testing.T) {
	port := freePort(t)
	rtc := dialPTY(t, "rtern", "--addr", addr(port), "--fingerprint", strings.Repeat("ab", 32),
		"--token", genToken(t), "--relay-token", genToken(t), "--cert", filepath.Join(t.TempDir(), "rt"))
	if !rtc.waitFor("waiting for the agent", 10*time.Second) {
		t.Fatalf("rtern never started waiting:\n%s", rtc.buf.String())
	}
	time.Sleep(300 * time.Millisecond)
	rtc.write("\x03")
	if !rtc.waitExit(5 * time.Second) {
		t.Fatalf("rtern ignored Ctrl-C while waiting for the agent:\n%s", rtc.buf.String())
	}
}

// TestConnectCtrlCDuringStalledReconnect: Ctrl-C quits tern connect even when
// its reconnect reaches a peer that never answers the handshake.
func TestConnectCtrlCDuringStalledReconnect(t *testing.T) {
	a := startDirectAgent(t)
	p := newStallProxy(t, a.addr)
	pc := dialPTY(t, "tern", "connect", "--addr", p.ln.Addr().String(), "--fingerprint", a.fp, "--token", a.token)
	if !pc.waitFor("attached to session", 15*time.Second) {
		t.Fatalf("never attached:\n%s", pc.buf.String())
	}
	p.dropFirst() // the live connection drops; the redial hits the black hole
	time.Sleep(1500 * time.Millisecond)
	pc.write("\x03")
	if !pc.waitExit(5 * time.Second) {
		t.Fatalf("tern connect ignored Ctrl-C during a stalled reconnect:\n%q", pc.buf.String())
	}
}

// TestForwardLocalExitsOnDrop: tern forward -L ends (non-zero) when its
// connection to the agent drops, instead of lingering with a dead tunnel.
func TestForwardLocalExitsOnDrop(t *testing.T) {
	a := startDirectAgent(t)
	p := newStallProxy(t, a.addr)
	echoPort := startEchoServer(t)
	lport := freePort(t)
	f := start(t, "tern", nil, "forward", "--addr", p.ln.Addr().String(), "--fingerprint", a.fp, "--token", a.token,
		"-L", fmt.Sprintf("%s:%s", addr(lport), addr(echoPort)))
	waitListen(t, addr(lport), 10*time.Second)
	if err := echoRoundTrip(addr(lport), "before-drop"); err != nil {
		t.Fatalf("forward did not work: %v", err)
	}
	p.dropFirst()
	done := make(chan error, 1)
	go func() { done <- f.cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("forward exited 0 after losing the agent:\n%s", f.buf.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("tern forward still running 5s after its agent connection dropped:\n%s", f.buf.String())
	}
}

// TestConnectForwardQuietExit: a clean `exit` does not report the -L/-R
// forwards it tears down as errors.
func TestConnectForwardQuietExit(t *testing.T) {
	for i := 0; i < 3; i++ {
		a := startDirectAgent(t)
		echoPort := startEchoServer(t)
		rport := freePort(t)
		pc := dialPTY(t, "tern", "connect", "--addr", a.addr, "--fingerprint", a.fp, "--token", a.token,
			"-R", fmt.Sprintf("%s:%s", addr(rport), addr(echoPort)))
		if !pc.waitFor("attached to session", 15*time.Second) {
			t.Fatalf("never attached:\n%s", pc.buf.String())
		}
		waitListen(t, addr(rport), 10*time.Second)
		pc.write("exit\r\n")
		pc.waitExit(10 * time.Second)
		if out := pc.buf.String(); strings.Contains(out, "connection to the agent closed") {
			t.Fatalf("clean exit reported the forward as an error:\n%q", out)
		}
	}
}

// evalMarker returns a line to type into the agent's shell and the text that
// only the shell's output contains (the echoed input does not), so seeing it
// proves the typed input reached the shell.
func evalMarker(tag string) (line, want string) {
	if runtime.GOOS == "windows" { // cmd.exe
		return "echo " + tag + "_%OS%\r", tag + "_Windows_NT"
	}
	return "echo " + tag + "_$((6*7))\r", tag + "_42"
}

// encryptedKey makes a passphrase-protected ed25519 key with ssh-keygen.
func encryptedKey(t *testing.T, pass string) string {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not available")
	}
	key := filepath.Join(t.TempDir(), "id")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", pass, "-f", key).CombinedOutput(); err != nil {
		t.Skipf("ssh-keygen: %v %s", err, out)
	}
	return key
}

// startKeyAgent starts a direct ternd that accepts only the given public key.
func startKeyAgent(t *testing.T, pubKey string) agent {
	t.Helper()
	port := freePort(t)
	cert := filepath.Join(t.TempDir(), "agent")
	args := []string{"--addr", addr(port), "--authorized-keys", pubKey, "--cert", cert}
	if s := agentShell(); s != "" {
		args = append(args, "--shell", s)
	}
	p := start(t, "ternd", nil, args...)
	fp := p.waitFor(t, reFingerprint, 15*time.Second)
	waitListen(t, addr(port), 10*time.Second)
	return agent{addr: addr(port), fp: fp, cert: cert}
}

// TestEncryptedKeyReconnect: an encrypted key asks for its passphrase once,
// before the shell starts, and auto-reconnect reuses it without asking again.
func TestEncryptedKeyReconnect(t *testing.T) {
	key := encryptedKey(t, "pw-123456")
	a := startKeyAgent(t, key+".pub")
	px := newDropProxy(t, a.addr, false)
	pc := dialPTY(t, "tern", "connect", "--addr", px.ln.Addr().String(), "--fingerprint", a.fp, "--key", key, "--session", "enc")
	if !pc.waitFor("Enter passphrase", 10*time.Second) {
		t.Fatalf("no passphrase prompt:\n%q", pc.buf.String())
	}
	pc.write("pw-123456\r")
	if !pc.waitFor("attached to session", 10*time.Second) {
		t.Fatalf("never attached after the passphrase:\n%q", pc.buf.String())
	}
	px.drop()
	if !pc.waitFor("reconnected to", 15*time.Second) {
		t.Fatalf("did not reconnect:\n%q", pc.buf.String())
	}
	if n := strings.Count(pc.buf.String(), "Enter passphrase"); n != 1 {
		t.Fatalf("passphrase asked %d times:\n%q", n, pc.buf.String())
	}
	line, want := evalMarker("AFTER")
	pc.write(line)
	if !pc.waitFor(want, 10*time.Second) {
		t.Fatalf("cannot type after the reconnect:\n%q", pc.buf.String())
	}
}

// TestWriterReclaimsSeat: a writer that reconnects while the agent still holds
// its old (half-open) attachment comes back as the writer, not read-only.
func TestWriterReclaimsSeat(t *testing.T) {
	a := startDirectAgent(t)
	px := newDropProxy(t, a.addr, true)
	pc := dialPTY(t, "tern", "connect", "--addr", px.ln.Addr().String(), "--fingerprint", a.fp, "--token", a.token, "--session", "seat")
	if !pc.waitFor("attached to session", 10*time.Second) {
		t.Fatalf("never attached:\n%q", pc.buf.String())
	}
	px.drop()
	if !pc.waitFor("reconnected to", 15*time.Second) {
		t.Fatalf("did not reconnect:\n%q", pc.buf.String())
	}
	if strings.Contains(strings.ToLower(pc.buf.String()), "read-only") {
		t.Fatalf("writer came back read-only behind its own stale slot:\n%q", pc.buf.String())
	}
	line, want := evalMarker("SEAT")
	pc.write(line)
	if !pc.waitFor(want, 10*time.Second) {
		t.Fatalf("writer cannot type after the reconnect:\n%q", pc.buf.String())
	}
}

// TestAPIEncryptedKeyNeedsTTY: tern api loads its key at startup, so an
// encrypted key without a terminal fails right away instead of failing every
// request later.
func TestAPIEncryptedKeyNeedsTTY(t *testing.T) {
	key := encryptedKey(t, "pw-123456")
	a := startKeyAgent(t, key+".pub")
	out, code := runClient(t, 20*time.Second, "api", "--addr", a.addr, "--fingerprint", a.fp, "--key", key,
		"--api-addr", addr(freePort(t)), "--api-token", genToken(t))
	if code == 0 || !strings.Contains(out, "load key") {
		t.Fatalf("want a startup failure loading the key, got exit %d:\n%s", code, out)
	}
}

// The REST gateway refuses a bearer token shorter than 16 characters.
func TestAPIShortTokenRejected(t *testing.T) {
	a := startDirectAgent(t)
	out, code := runClient(t, 20*time.Second,
		"api", "--addr", a.addr, "--fingerprint", a.fp, "--api-addr", addr(freePort(t)), "--api-token", "short")
	if code == 0 || !strings.Contains(out, "too short") {
		t.Fatalf("short api token not rejected: exit %d\n%s", code, out)
	}
}

// A tern1: connection string cannot be combined with explicit dial flags,
// which would otherwise be silently ignored.
func TestConnStringConflictsWithDialFlags(t *testing.T) {
	a := startDirectAgent(t)
	cs := a.cs(t)
	out, code := runClient(t, 20*time.Second,
		"run", "--to", cs, "--addr", "203.0.113.9:2222", "--token", a.token, "--", "echo", "x")
	if code == 0 || !strings.Contains(out, "cannot be combined") {
		t.Fatalf("tern1 + --addr conflict not rejected: exit %d\n%s", code, out)
	}
}
