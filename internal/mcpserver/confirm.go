// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Human confirmation uses MCP multi round-trip requests (SEP-2322): the server
// answers a call that needs approval with an input_required result holding a
// one-checkbox form, and the client asks the user and retries the same call
// with the answer. The retry carries requestState back. Because the client
// could alter it, requestState is an HMAC over the exact action, a fresh nonce
// and an expiry: an approval cannot be replayed, reused, kept past its expiry
// or moved to a different command. A client on a protocol before 2026-07-28
// cannot retry: addTool asks it with an elicitation/create request inside the
// call, waits for the answer at most as long as an approval lasts, and retries
// the call for it. The guarantee ends at the client: it is trusted to really
// show the form to the user, and nothing it sends says whether it did.

const (
	confirmTTL      = 5 * time.Minute
	confirmInputKey = "confirm"
	maxShown        = 1000 // longest action a form shows; longer is refused, never cut
	maxPreview      = 800  // bytes of the data an action carries that a form shows
	maxPreviewLines = 20
	// instantAnswer is the least time an answer takes when a person read the
	// form first. A faster one came from the client itself: some clients
	// answer an elicitation request without ever drawing it.
	instantAnswer = time.Second
)

// ConfirmWaitMin and ConfirmWaitMax bound how long a call waits for a client
// that must be asked inside it (see askNow). The longest is how long an
// approval lasts: an answer after that could not be used anyway.
const (
	ConfirmWaitMin = time.Second
	ConfirmWaitMax = confirmTTL
)

type confirmStatus int

const (
	confirmNeeded   confirmStatus = iota // no answer yet: ask the user
	confirmApproved                      // a valid, fresh approval for this exact action
	confirmRejected                      // declined, expired, reused, forged or for another action
)

type confirmer struct {
	key  []byte
	mu   sync.Mutex
	used map[string]int64 // nonce -> expiry in Unix seconds, so an answer is used once
	now  func() time.Time
	wait time.Duration // longest wait for an answer asked inside a call
}

// newConfirmer returns a confirmer that waits wait for an answer asked inside
// a call, held to ConfirmWaitMin..ConfirmWaitMax; 0 means the longest.
func newConfirmer(wait time.Duration) *confirmer {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err) // crypto/rand does not fail on supported platforms
	}
	switch {
	case wait <= 0 || wait > ConfirmWaitMax:
		wait = ConfirmWaitMax
	case wait < ConfirmWaitMin:
		wait = ConfirmWaitMin
	}
	return &confirmer{key: key, used: map[string]int64{}, now: time.Now, wait: wait}
}

// expired reports whether a state that expires at exp, in Unix seconds, has
// expired at now. A spent nonce is forgotten only once its state has expired
// by this same test, never while the state would still pass it.
func expired(now time.Time, exp int64) bool { return now.Unix() > exp }

type confirmState struct {
	Nonce string `json:"n"`
	Exp   int64  `json:"e"`
	MAC   string `json:"m"`
}

// mac binds action, nonce and expiry under the server's key.
func (c *confirmer) mac(action, nonce string, exp int64) string {
	m := hmac.New(sha256.New, c.key)
	fmt.Fprintf(m, "tern-mcp-confirm-v1\x00%s\x00%s\x00%d", action, nonce, exp)
	return hex.EncodeToString(m.Sum(nil))
}

// request builds the input_required result asking the user about action.
func (c *confirmer) request(action, message string) *mcp.CallToolResult {
	b := make([]byte, 16)
	rand.Read(b)
	nonce := hex.EncodeToString(b)
	exp := c.now().Add(confirmTTL).Unix()
	state, _ := json.Marshal(confirmState{Nonce: nonce, Exp: exp, MAC: c.mac(action, nonce, exp)})
	return &mcp.CallToolResult{
		InputRequests: mcp.InputRequestMap{confirmInputKey: &mcp.ElicitParams{
			Mode:            "form",
			Message:         message,
			RequestedSchema: approveSchema,
		}},
		RequestState: base64.RawURLEncoding.EncodeToString(state),
	}
}

var approveSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"approve": map[string]any{
			"type":        "boolean",
			"title":       "Approve",
			"description": "Allow this action once.",
		},
	},
	"required": []string{"approve"},
}

// check judges a call against action. Without requestState the user has not
// been asked yet. With it, the state must be ours, for this exact action,
// unexpired and unused, and the answer an explicit approval. The nonce is
// spent on any genuine answer, approve or not, so a declined form cannot be
// resubmitted as an approval.
func (c *confirmer) check(action string, p *mcp.CallToolParamsRaw) (confirmStatus, string) {
	if p == nil || p.RequestState == "" {
		return confirmNeeded, ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(p.RequestState)
	var st confirmState
	if err != nil || json.Unmarshal(raw, &st) != nil || st.Nonce == "" {
		return confirmRejected, "the confirmation state is not valid"
	}
	if !hmac.Equal([]byte(st.MAC), []byte(c.mac(action, st.Nonce, st.Exp))) {
		return confirmRejected, "the confirmation does not match this action; ask again"
	}
	now := c.now()
	if expired(now, st.Exp) {
		return confirmRejected, "the confirmation expired; ask again"
	}
	c.mu.Lock()
	for n, exp := range c.used {
		if expired(now, exp) {
			delete(c.used, n)
		}
	}
	_, reused := c.used[st.Nonce]
	c.used[st.Nonce] = st.Exp
	c.mu.Unlock()
	if reused {
		return confirmRejected, "this confirmation was already used; ask again"
	}
	er, _ := p.InputResponses[confirmInputKey].(*mcp.ElicitResult)
	if why := refusal(er); why != "" {
		return confirmRejected, why
	}
	return confirmApproved, ""
}

// refusal says why an answer to the form is not an approval, or returns "" for
// one. An answer says only accept, decline or cancel, never whether a person
// saw the form.
func refusal(er *mcp.ElicitResult) string {
	switch {
	case er == nil:
		return "no answer to the confirmation"
	case er.Action == "decline":
		return "the user declined"
	case er.Action != "accept":
		return "the user dismissed the confirmation"
	}
	if approve, _ := er.Content["approve"].(bool); !approve {
		return "the user did not approve"
	}
	return ""
}

// canAsk reports whether the calling client can show a form: it declared
// elicitation, and either form mode or no modes, which older clients mean as
// form support.
func canAsk(req *mcp.CallToolRequest) bool {
	if req == nil {
		return false
	}
	caps := req.ClientCapabilities()
	return caps != nil && caps.Elicitation != nil &&
		(caps.Elicitation.Form != nil || caps.Elicitation.URL == nil)
}

// retryProtocol is the first protocol version whose clients answer an
// input_required result by retrying the call.
const retryProtocol = "2026-07-28"

// retries reports whether the client retries a call that asks for input. It
// is the SDK's own test, clientSupportsMultiRoundTrip in go-sdk's mrtr.go: a
// session without initialize params speaks the newest protocol.
func retries(req *mcp.CallToolRequest) bool {
	if req.Session == nil {
		return true
	}
	ip := req.Session.InitializeParams()
	return ip == nil || ip.ProtocolVersion >= retryProtocol
}

// errNoAnswer ends the wait for an answer that does not come in time.
var errNoAnswer = errors.New("no answer to the confirmation in time")

// askNow asks a client that does not retry for the answers an input_required
// result wants, waiting at most c.wait. It returns errNoAnswer when the wait
// ends first, and the client's, the transport's or the call's own error when
// asking fails.
func (c *confirmer) askNow(ctx context.Context, ss *mcp.ServerSession, requests mcp.InputRequestMap) (mcp.InputResponseMap, time.Duration, error) {
	ctx, cancel := context.WithTimeoutCause(ctx, c.wait, errNoAnswer)
	defer cancel()
	begin := time.Now()
	answers := mcp.InputResponseMap{}
	for key, r := range requests {
		p, ok := r.(*mcp.ElicitParams)
		if !ok {
			return nil, 0, fmt.Errorf("cannot ask for a %T", r)
		}
		er, err := ss.Elicit(ctx, p)
		if err != nil {
			if errors.Is(context.Cause(ctx), errNoAnswer) {
				return nil, 0, errNoAnswer
			}
			return nil, 0, err
		}
		answers[key] = er
	}
	return answers, time.Since(begin), nil
}

// answerDelayKey marks the context of a call retried with an answer the server
// asked for inside the call, holding how long that answer took.
type answerDelayKey struct{}

func withAnswerDelay(ctx context.Context, d time.Duration) context.Context {
	return context.WithValue(ctx, answerDelayKey{}, d)
}

// answerDelay returns how long the client took to answer a form the server
// asked inside the call, and whether that is known at all: a client on
// 2026-07-28 or later answers by making a new call, which the server did not
// time, and a call with no answer has no delay either.
func answerDelay(ctx context.Context) (time.Duration, bool) {
	d, ok := ctx.Value(answerDelayKey{}).(time.Duration)
	return d, ok
}

// shortDur writes d for a person, keeping a sub-millisecond answer readable
// rather than rounding it to 0s.
func shortDur(d time.Duration) string {
	if d < time.Millisecond {
		return d.Round(time.Microsecond).String()
	}
	return d.Round(time.Millisecond).String()
}

// noteAnswer logs the client's answer to a confirmation form, with how long it
// took, and returns what a refusal should add when the answer came back too
// fast for anyone to have read the form. Nothing is logged for a call that
// carries no answer, such as one whose state is forged or expired.
func (s *Server) noteAnswer(ctx context.Context, e AuditEntry, p *mcp.CallToolParamsRaw) string {
	if p == nil {
		return ""
	}
	er, _ := p.InputResponses[confirmInputKey].(*mcp.ElicitResult)
	if er == nil {
		return ""
	}
	e.Phase, e.Reason = "confirm_answered", er.Action
	d, known := answerDelay(ctx)
	if known {
		// Rounded up, so an answer faster than a millisecond is still
		// logged as a time rather than left out as a zero.
		e.DurationMS = int64((d + time.Millisecond - 1) / time.Millisecond)
	}
	s.logOrWarn(e)
	if !known || d >= instantAnswer {
		return ""
	}
	if refusal(er) == "" {
		// A client that approves this fast approves for the user, which
		// defeats the point of asking; it cannot be told apart from one
		// the user has told to approve everything, so this only warns.
		slog.Warn("the client approved an action without a person having time to read the form; it may be answering approval forms by itself",
			"tool", e.Tool, "target", e.Target, "took", shortDur(d))
		return ""
	}
	return clientAnswer(er) + " in " + shortDur(d) +
		", too fast for anyone to have read the form, so it most likely answered by itself instead of showing it; allow this action in the profile, or approve it from a client that shows approval forms"
}

// clientAnswer describes an answer that reached the server too fast to be a
// person's, so the refusal says what the client did instead of putting words
// in the user's mouth.
func clientAnswer(er *mcp.ElicitResult) string {
	if er.Action == "accept" {
		return `the client answered "accept" without the approval ticked`
	}
	return fmt.Sprintf("the client answered %q", er.Action)
}

// unansweredKey marks the context of a call retried without an answer.
type unansweredKey struct{}

func withUnanswered(ctx context.Context, err error) context.Context {
	return context.WithValue(ctx, unansweredKey{}, err)
}

// unanswered returns why the answers a call asked for never came, or nil.
func unanswered(ctx context.Context) error {
	err, _ := ctx.Value(unansweredKey{}).(error)
	return err
}

// actionKey canonicalizes what a confirmation (or an idempotency key) is bound
// to. Maps marshal with sorted keys, so equal actions give equal keys.
func actionKey(tool, target string, args map[string]any) string {
	b, _ := json.Marshal(map[string]any{"tool": tool, "target": target, "args": args})
	return string(b)
}

// confirmView is what a confirmation form shows about an action.
type confirmView struct {
	what    string // the kind of action, such as "run a command"
	subject string // the action itself, with every value from the model passed through show
	data    []byte // what the action carries, such as standard input or file content
	dataOf  string // what data is
}

// confirmMessage is the text the user approves. It shows the whole action, or
// refuses: cutting it short would let the visible part look harmless while
// the hidden rest runs. Data the action carries is previewed, and the form
// says so plainly when the preview is not all of it.
func confirmMessage(target, profile, why string, v confirmView) (string, error) {
	if len(v.subject) > maxShown {
		return "", fmt.Errorf("the action is too long to show the user in full for approval (%d characters, at most %d); split it into shorter steps", len(v.subject), maxShown)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "tern: approve this action on target %q (profile %s)?\n\n%s:\n  %s\n", target, profile, v.what, v.subject)
	if v.data != nil {
		b.WriteString(preview(v.dataOf, v.data))
	}
	fmt.Fprintf(&b, "\nWhy you are asked: %s.\nThe AI model chose this action. Approve only if you expect it.", why)
	return b.String(), nil
}

// show renders a value from the model exactly. It is quoted when it is empty,
// holds anything quote escapes (control and escape sequences, invisible or
// bidirectional characters, invalid UTF-8) or shell syntax, and then those
// bytes appear escaped: nothing is dropped, so nothing is hidden.
func show(s string) string {
	q := quote(s)
	if s == "" || q != `"`+s+`"` || strings.ContainsAny(s, " \t\"'\\$`;|&<>()*?[]{}#~=!") {
		return q
	}
	return s
}

// quote is strconv.Quote, also escaping the invisible characters it counts as
// printable, such as variation selectors.
func quote(s string) string {
	q := strconv.Quote(s)
	if strings.IndexFunc(q, invisible) < 0 {
		return q
	}
	var b strings.Builder
	for _, r := range q {
		if invisible(r) {
			escRune(&b, r)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// escRune writes r as a \u or \U escape.
func escRune(b *strings.Builder, r rune) {
	if r > 0xffff {
		fmt.Fprintf(b, `\U%08x`, r)
	} else {
		fmt.Fprintf(b, `\u%04x`, r)
	}
}

// showArgv renders a command, each argument through show.
func showArgv(argv []string) string {
	parts := make([]string, len(argv))
	for i, a := range argv {
		parts[i] = show(a)
	}
	return strings.Join(parts, " ")
}

// preview shows the start of data line by line, each line marked so it cannot
// pass for the form's own text, with anything but printable text escaped.
// Data that is not UTF-8 text is shown the same way, each byte that is not
// part of a character as \xNN, and the form says it is binary: one stray byte
// in a comment must not hide what a script says.
func preview(name string, data []byte) string {
	cut := 0
	for cut < len(data) {
		_, size := utf8.DecodeRune(data[cut:])
		if cut+size > maxPreview {
			break
		}
		cut += size
	}
	shown := string(data[:cut])
	if i := indexNth(shown, '\n', maxPreviewLines); i >= 0 {
		shown = shown[:i+1]
	}
	kind := ""
	if !utf8.Valid(data) {
		kind = fmt.Sprintf(", BINARY (not UTF-8 text; a byte that is not part of a character shows as \\xNN), sha256 %s", sha(string(data)))
	}
	var b strings.Builder
	if len(shown) == len(data) {
		fmt.Fprintf(&b, "\n%s, all %d bytes%s:\n", name, len(data), kind)
	} else {
		fmt.Fprintf(&b, "\n%s, ONLY THE FIRST %d OF %d BYTES%s:\n", name, len(shown), len(data), kind)
	}
	for _, line := range strings.Split(strings.TrimSuffix(shown, "\n"), "\n") {
		b.WriteString("  | ")
		for i := 0; i < len(line); {
			r, size := utf8.DecodeRuneInString(line[i:])
			switch {
			case r == utf8.RuneError && size == 1:
				fmt.Fprintf(&b, `\x%02x`, line[i])
			case r == '\t' || strconv.IsPrint(r) && !invisible(r):
				b.WriteRune(r)
			case invisible(r):
				escRune(&b, r)
			default:
				q := strconv.QuoteRune(r)
				b.WriteString(q[1 : len(q)-1])
			}
			i += size
		}
		b.WriteString("\n")
	}
	return b.String()
}

// indexNth is the index of the nth c in s, or -1 when s has fewer.
func indexNth(s string, c byte, n int) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			if n--; n == 0 {
				return i
			}
		}
	}
	return -1
}
