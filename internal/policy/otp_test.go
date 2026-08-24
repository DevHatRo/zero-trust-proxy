package policy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/serverconfig"
)

// --- store ---------------------------------------------------------------

func newTestStore(ttl time.Duration) (*otpStore, *time.Time) {
	s := newOTPStore(ttl)
	now := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return now }
	return s, &now
}

func TestOTPStoreIssueVerify(t *testing.T) {
	s, now := newTestStore(10 * time.Minute)

	code, ok := s.issue("a@example.com")
	if !ok || len(code) != otpCodeDigits {
		t.Fatalf("issue: ok=%v code=%q", ok, code)
	}
	if s.verify("a@example.com", "000000") && code != "000000" {
		t.Fatal("wrong code must not verify")
	}
	if !s.verify("a@example.com", code) {
		t.Fatal("correct code must verify")
	}
	// Single use.
	if s.verify("a@example.com", code) {
		t.Fatal("code must be single-use")
	}

	// Expiry.
	code2, _ := s.issue("b@example.com")
	*now = now.Add(11 * time.Minute)
	if s.verify("b@example.com", code2) {
		t.Fatal("expired code must not verify")
	}
}

func TestOTPStoreAttemptLimit(t *testing.T) {
	s, _ := newTestStore(10 * time.Minute)
	code, _ := s.issue("a@example.com")
	for i := 0; i < otpMaxAttempts; i++ {
		if s.verify("a@example.com", "999999") {
			t.Fatal("wrong code verified")
		}
	}
	// Attempts exhausted: even the right code is dead now.
	if s.verify("a@example.com", code) {
		t.Fatal("code must be invalidated after too many attempts")
	}
}

func TestOTPStoreSendRateLimit(t *testing.T) {
	s, now := newTestStore(10 * time.Minute)
	for i := 0; i < otpMaxSends; i++ {
		if _, ok := s.issue("a@example.com"); !ok {
			t.Fatalf("send %d should be allowed", i+1)
		}
	}
	if _, ok := s.issue("a@example.com"); ok {
		t.Fatal("send beyond the window limit must be refused")
	}
	// Other addresses unaffected; window reset restores sends.
	if _, ok := s.issue("other@example.com"); !ok {
		t.Fatal("other address should be unaffected")
	}
	*now = now.Add(otpSendWindow + time.Minute)
	if _, ok := s.issue("a@example.com"); !ok {
		t.Fatal("window reset should allow sending again")
	}
}

// --- brevo sender --------------------------------------------------------

func TestBrevoSender(t *testing.T) {
	var got struct {
		apiKey string
		body   brevoPayload
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.apiKey = r.Header.Get("api-key")
		_ = json.NewDecoder(r.Body).Decode(&got.body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	s := &brevoSender{apiKey: "key-123", from: "auth@example.com", subject: "Your sign-in code",
		ttl: 10 * time.Minute, endpoint: srv.URL, client: srv.Client()}
	if err := s.SendCode(context.Background(), "user@example.com", "123456"); err != nil {
		t.Fatalf("send: %v", err)
	}
	if got.apiKey != "key-123" {
		t.Fatalf("api-key header = %q", got.apiKey)
	}
	if got.body.Sender.Email != "auth@example.com" || len(got.body.To) != 1 || got.body.To[0].Email != "user@example.com" {
		t.Fatalf("payload addresses wrong: %+v", got.body)
	}
	if !strings.Contains(got.body.TextContent, "123456") {
		t.Fatal("code missing from body")
	}

	// Non-2xx surfaces as an error.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer bad.Close()
	s.endpoint = bad.URL
	if err := s.SendCode(context.Background(), "user@example.com", "123456"); err == nil {
		t.Fatal("non-2xx must error")
	}
}

// serveMockSMTP speaks just enough SMTP to reach DATA, optionally
// advertising STARTTLS, and bumps received when a message body arrives.
func serveMockSMTP(conn net.Conn, advertiseSTARTTLS bool, received *int32) {
	defer func() { _ = conn.Close() }()
	w := bufio.NewWriter(conn)
	r := bufio.NewReader(conn)
	line := func(s string) { fmt.Fprint(w, s+"\r\n"); _ = w.Flush() }
	line("220 mock ESMTP")
	for {
		in, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(in))
		switch {
		case strings.HasPrefix(cmd, "EHLO"):
			if advertiseSTARTTLS {
				line("250-mock")
				line("250 STARTTLS")
			} else {
				line("250 mock")
			}
		case cmd == "DATA":
			line("354 go ahead")
			for {
				d, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if d == ".\r\n" {
					break
				}
			}
			atomic.AddInt32(received, 1)
			line("250 OK")
		case cmd == "QUIT":
			line("221 bye")
			return
		default: // HELO/MAIL/RCPT/…
			line("250 OK")
		}
	}
}

func startMockSMTP(t *testing.T, advertiseSTARTTLS bool) (host string, port int, received *int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var got int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveMockSMTP(conn, advertiseSTARTTLS, &got)
		}
	}()
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	n, _ := strconv.Atoi(p)
	return h, n, &got
}

// Regression (finding 7): a server without STARTTLS is refused by
// default (no code crosses the wire), and only proceeds under the
// explicit allow_insecure opt-out.
func TestSMTPRequiresSTARTTLS(t *testing.T) {
	host, port, got := startMockSMTP(t, false)
	s := &smtpSender{host: host, port: port, from: "auth@example.com", subject: "x", ttl: time.Minute}

	if err := s.SendCode(context.Background(), "u@example.com", "123456"); err == nil {
		t.Fatal("delivery to a non-STARTTLS server must fail by default")
	}
	if atomic.LoadInt32(got) != 0 {
		t.Fatal("code body must not be transmitted in cleartext")
	}

	s.allowInsecure = true
	if err := s.SendCode(context.Background(), "u@example.com", "123456"); err != nil {
		t.Fatalf("with allow_insecure the send should proceed: %v", err)
	}
	if atomic.LoadInt32(got) != 1 {
		t.Fatal("message should be delivered once allow_insecure is set")
	}
}

func TestBuildMailMessage(t *testing.T) {
	msg := string(buildMailMessage("auth@example.com", "user@example.com", "Your sign-in code", "body line\nsecond"))
	for _, want := range []string{"From: auth@example.com\r\n", "To: user@example.com\r\n", "Subject: ", "body line\r\nsecond"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message missing %q:\n%s", want, msg)
		}
	}
}

// --- helpers -------------------------------------------------------------

func TestSanitizeReturnPath(t *testing.T) {
	cases := map[string]string{
		"/dash":                    "/dash",
		"/a/b?x=1":                 "/a/b?x=1",
		"":                         "/",
		"https://evil.com/":        "/",
		"//evil.com/":              "/",
		"/\\evil":                  "/",
		"relative":                 "/",
		"/ok/../still-local":       "/ok/../still-local",
		"/line\r\nSet-Cookie: x=1": "/",
	}
	for in, want := range cases {
		if got := sanitizeReturnPath(in); got != want {
			t.Errorf("sanitizeReturnPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidEmail(t *testing.T) {
	if e, ok := validEmail("User@Example.COM"); !ok || e != "user@example.com" {
		t.Fatalf("got (%q,%v)", e, ok)
	}
	for _, bad := range []string{"", "not-an-email", "a b@example.com", "x@example.com\r\nBcc: y@z", "Name <x@example.com>"} {
		if _, ok := validEmail(bad); ok {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

// --- full flow -----------------------------------------------------------

// captureSender records the last code instead of sending mail.
type captureSender struct {
	mu    sync.Mutex
	to    []string
	codes map[string]string
}

func (c *captureSender) SendCode(_ context.Context, to, code string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.codes == nil {
		c.codes = map[string]string{}
	}
	c.to = append(c.to, to)
	c.codes[to] = code
	return nil
}

func otpEngine(t *testing.T) (*Engine, *captureSender) {
	t.Helper()
	cfg := testConfig(t, func(c *serverconfig.AccessConfig) {
		c.EmailOTP = serverconfig.EmailOTPConfig{
			Enabled: true,
			From:    "auth@example.com",
			Brevo:   &serverconfig.BrevoConfig{APIKey: "unused-in-test"},
		}
		c.Rules = []serverconfig.AccessRule{
			{Name: "media", When: serverconfig.AccessMatch{Hosts: []string{"*.home.example.com"}},
				Action: "allow", Require: &serverconfig.AccessRequire{Emails: []string{"vuko@example.com"}}},
		}
	})
	e, err := New(cfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	sender := &captureSender{}
	e.otp.sender = sender // swap the real sender for the capture
	return e, sender
}

// startLogin performs GET /.ztp/login and returns the transaction
// cookie and the csrf token embedded in the form — the pair both POSTs
// now require.
func startLogin(t *testing.T, h http.Handler, rawurl string) (*http.Cookie, string) {
	t.Helper()
	req := httptest.NewRequest("GET", rawurl, nil)
	req.RemoteAddr = "9.9.9.9:1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	var c *http.Cookie
	for _, ck := range rr.Result().Cookies() {
		if ck.Name == loginTxnCookie {
			c = ck
		}
	}
	if c == nil {
		t.Fatalf("no %s cookie from %s (status %d)", loginTxnCookie, rawurl, rr.Code)
	}
	token := hiddenField(rr.Body.String(), "csrf")
	if token == "" {
		t.Fatal("no csrf token in login form")
	}
	return c, token
}

// hiddenField pulls a hidden input's value out of the rendered form.
func hiddenField(body, name string) string {
	marker := `name="` + name + `" value="`
	i := strings.Index(body, marker)
	if i < 0 {
		return ""
	}
	rest := body[i+len(marker):]
	if j := strings.IndexByte(rest, '"'); j >= 0 {
		return rest[:j]
	}
	return ""
}

// postForm posts target with the given transaction cookie and csrf
// token attached (pass nil/"" to simulate a cross-site submission).
func postForm(t *testing.T, h http.Handler, target string, txn *http.Cookie, token string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	if token != "" {
		form.Set("csrf", token)
	}
	req := httptest.NewRequest("POST", target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "9.9.9.9:1"
	if txn != nil {
		req.AddCookie(txn)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestOTPFullLoginFlow(t *testing.T) {
	e, sender := otpEngine(t)
	var hit bool
	h := e.Wrap(okHandler(&hit))

	// 1. Anonymous browser on a protected host → redirected to login.
	rr := send(t, h, "GET", "http://sonarr.home.example.com/series", "9.9.9.9", func(r *http.Request) {
		r.Header.Set("Accept", "text/html")
	})
	if rr.Code != http.StatusFound || !strings.HasPrefix(rr.Header().Get("Location"), "/.ztp/login?rd=") {
		t.Fatalf("expected login redirect, got %d %q", rr.Code, rr.Header().Get("Location"))
	}
	if hit {
		t.Fatal("backend reached before login")
	}

	// 2. Request a code for the eligible address (through a transaction).
	txn, token := startLogin(t, h, "http://sonarr.home.example.com/.ztp/login?rd=/series")
	rr = postForm(t, h, "http://sonarr.home.example.com/.ztp/otp/request", txn, token,
		url.Values{"email": {"vuko@example.com"}, "rd": {"/series"}})
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "Check your email") {
		t.Fatalf("request step: %d", rr.Code)
	}
	e.otp.wait() // delivery is async; let it finish before reading the code
	code := sender.codes["vuko@example.com"]
	if code == "" {
		t.Fatal("no code delivered to the eligible address")
	}

	// 3. Verify the code → session cookie + redirect to the original path.
	rr = postForm(t, h, "http://sonarr.home.example.com/.ztp/otp/verify", txn, token,
		url.Values{"email": {"vuko@example.com"}, "code": {code}, "rd": {"/series"}})
	if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/series" {
		t.Fatalf("verify step: %d loc=%q", rr.Code, rr.Header().Get("Location"))
	}
	var session string
	for _, c := range rr.Result().Cookies() {
		if c.Name == "ztp_session" {
			session = c.Value
		}
	}
	if session == "" {
		t.Fatal("no session cookie minted")
	}

	// 4. The session now satisfies the emails rule.
	rr = send(t, h, "GET", "http://sonarr.home.example.com/series", "9.9.9.9", func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: "ztp_session", Value: session})
	})
	if rr.Code != 200 || !hit {
		t.Fatalf("authenticated request: %d hit=%v", rr.Code, hit)
	}

	// 5. Wrong code fails and counts, without leaking anything.
	rr = postForm(t, h, "http://sonarr.home.example.com/.ztp/otp/verify", txn, token,
		url.Values{"email": {"vuko@example.com"}, "code": {"000000"}, "rd": {"/"}})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("wrong code: %d, want 400", rr.Code)
	}
}

// Ineligible addresses get the identical response and NO mail.
func TestOTPNoEnumerationNoMailForIneligible(t *testing.T) {
	e, sender := otpEngine(t)
	h := e.Wrap(okHandler(nil))

	txn, token := startLogin(t, h, "http://x.home.example.com/.ztp/login?rd=/")
	eligible := postForm(t, h, "http://x.home.example.com/.ztp/otp/request", txn, token,
		url.Values{"email": {"vuko@example.com"}, "rd": {"/"}})
	ineligible := postForm(t, h, "http://x.home.example.com/.ztp/otp/request", txn, token,
		url.Values{"email": {"attacker@evil.com"}, "rd": {"/"}})
	e.otp.wait() // let any dispatched delivery finish before asserting

	if eligible.Code != ineligible.Code {
		t.Fatalf("status codes differ: %d vs %d", eligible.Code, ineligible.Code)
	}
	// Bodies identical modulo the echoed address.
	a := strings.ReplaceAll(eligible.Body.String(), "vuko@example.com", "X")
	b := strings.ReplaceAll(ineligible.Body.String(), "attacker@evil.com", "X")
	if a != b {
		t.Fatal("response bodies must not reveal eligibility")
	}
	if len(sender.to) != 1 || sender.to[0] != "vuko@example.com" {
		t.Fatalf("mail must go only to the eligible address, got %v", sender.to)
	}
}

// Regression (finding 1): the per-address send budget must not reset
// when a code's attempts are exhausted — the old code deleted the whole
// entry, so the next issue() started a fresh window with sends=0.
func TestOTPSendLimitSurvivesAttemptExhaustion(t *testing.T) {
	s, _ := newTestStore(10 * time.Minute)
	for i := 0; i < otpMaxSends; i++ {
		if _, ok := s.issue("a@example.com"); !ok {
			t.Fatalf("send %d should be allowed", i+1)
		}
		for j := 0; j <= otpMaxAttempts; j++ {
			s.verify("a@example.com", "999999") // burn every attempt
		}
	}
	if _, ok := s.issue("a@example.com"); ok {
		t.Fatal("send budget must not reset after attempt exhaustion")
	}
}

// Regression (finding 1): nor may a successful, single-use verify reset
// the budget within the window.
func TestOTPSendLimitSurvivesSuccess(t *testing.T) {
	s, _ := newTestStore(10 * time.Minute)
	for i := 0; i < otpMaxSends; i++ {
		code, ok := s.issue("a@example.com")
		if !ok {
			t.Fatalf("send %d should be allowed", i+1)
		}
		if !s.verify("a@example.com", code) {
			t.Fatalf("code %d should verify", i+1)
		}
	}
	if _, ok := s.issue("a@example.com"); ok {
		t.Fatal("send budget must not reset after successful logins")
	}
}

// Regression (finding 3): eligibility must AND all require clauses, not
// OR the email clause against the rest. An off-network request for an
// allowed domain must send NO mail; the same request on-network must.
func TestOTPEligibilityRespectsANDedClauses(t *testing.T) {
	cfg := testConfig(t, func(c *serverconfig.AccessConfig) {
		c.EmailOTP = serverconfig.EmailOTPConfig{
			Enabled: true, From: "auth@example.com",
			Brevo: &serverconfig.BrevoConfig{APIKey: "unused-in-test"},
		}
		c.Rules = []serverconfig.AccessRule{{
			Name:   "corp",
			When:   serverconfig.AccessMatch{Hosts: []string{"*.home.example.com"}},
			Action: "allow",
			Require: &serverconfig.AccessRequire{
				EmailsDomain: []string{"corp.example"},
				SourceCIDRs:  []string{"10.0.0.0/8"},
			},
		}}
	})
	e, err := New(cfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	sender := &captureSender{}
	e.otp.sender = sender
	h := e.Wrap(okHandler(nil))

	txn, token := startLogin(t, h, "http://x.home.example.com/.ztp/login?rd=/")
	requestFrom := func(addr string) {
		form := url.Values{"email": {"ceo@corp.example"}, "rd": {"/"}, "csrf": {token}}
		req := httptest.NewRequest("POST", "http://x.home.example.com/.ztp/otp/request",
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = addr
		req.AddCookie(txn)
		h.ServeHTTP(httptest.NewRecorder(), req)
		e.otp.wait()
	}

	requestFrom("9.9.9.9:1") // outside 10.0.0.0/8
	if len(sender.to) != 0 {
		t.Fatalf("off-network request must not be mailed, got %v", sender.to)
	}
	requestFrom("10.1.2.3:1") // inside 10.0.0.0/8
	if len(sender.to) != 1 || sender.to[0] != "ceo@corp.example" {
		t.Fatalf("on-network request should be mailed once, got %v", sender.to)
	}
}

// Regression (finding 4): the SMTP path must honor the context. A
// cancelled context aborts the dial at once instead of blocking on the
// OS connect timeout.
func TestSMTPSenderHonorsContext(t *testing.T) {
	s := &smtpSender{host: "10.255.255.1", port: 25, from: "auth@example.com",
		subject: "x", ttl: time.Minute}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if err := s.SendCode(ctx, "user@example.com", "123456"); err == nil {
		t.Fatal("cancelled context must produce an error")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("SendCode ignored the context: took %s", elapsed)
	}
}

// Regression (finding 9): a cross-site verify POST — the attacker's
// form carries a valid code but the SameSite=Strict transaction cookie
// does not ride along — must not mint a session.
func TestOTPCrossSiteVerifyRejected(t *testing.T) {
	e, sender := otpEngine(t)
	h := e.Wrap(okHandler(nil))

	txn, token := startLogin(t, h, "http://x.home.example.com/.ztp/login?rd=/")
	postForm(t, h, "http://x.home.example.com/.ztp/otp/request", txn, token,
		url.Values{"email": {"vuko@example.com"}, "rd": {"/"}})
	e.otp.wait()
	code := sender.codes["vuko@example.com"]
	if code == "" {
		t.Fatal("no code issued")
	}

	// No transaction cookie, no csrf field: the cross-site case.
	rr := postForm(t, h, "http://x.home.example.com/.ztp/otp/verify", nil, "",
		url.Values{"email": {"vuko@example.com"}, "code": {code}})
	for _, c := range rr.Result().Cookies() {
		if c.Name == "ztp_session" && c.Value != "" {
			t.Fatal("cross-site verify minted a session")
		}
	}
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("cross-site verify: got %d, want a restart redirect (303)", rr.Code)
	}

	// Control: the same code still verifies once the transaction is
	// present (the rejected attempt did not consume it).
	rr = postForm(t, h, "http://x.home.example.com/.ztp/otp/verify", txn, token,
		url.Values{"email": {"vuko@example.com"}, "code": {code}, "rd": {"/"}})
	if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/" {
		t.Fatalf("in-transaction verify failed: %d loc=%q", rr.Code, rr.Header().Get("Location"))
	}
}

// blockingSender occupies a delivery slot until released, so a test can
// saturate the concurrency pool deterministically.
type blockingSender struct {
	release <-chan struct{}
	started chan<- struct{}
}

func (b *blockingSender) SendCode(_ context.Context, _, _ string) error {
	b.started <- struct{}{}
	<-b.release
	return nil
}

// Regression (re-review finding A): when the delivery pool is saturated
// a dropped request must NOT consume the caller's send budget — the slot
// is reserved before the code is issued.
func TestOTPSaturatedPoolDoesNotChargeSendBudget(t *testing.T) {
	e, _ := otpEngine(t)
	release := make(chan struct{})
	started := make(chan struct{}, otpDeliverConcurrency)
	e.otp.sender = &blockingSender{release: release, started: started}

	// Fill every delivery slot with an in-flight, blocked send.
	for i := 0; i < otpDeliverConcurrency; i++ {
		e.otp.issueAndDeliver(fmt.Sprintf("filler%d@example.com", i), nil)
	}
	for i := 0; i < otpDeliverConcurrency; i++ {
		<-started
	}

	// A further request is dropped; its address must never be charged.
	e.otp.issueAndDeliver("victim@example.com", nil)
	e.otp.store.mu.Lock()
	_, charged := e.otp.store.entries["victim@example.com"]
	e.otp.store.mu.Unlock()
	if charged {
		t.Fatal("dropped request must not consume the send budget")
	}

	close(release)
	e.otp.wait()
}

// Regression (re-review finding 1): the OTPFailed metric counts genuine
// wrong-code submissions only, not malformed forms (empty code).
func TestOTPFailedMetricOnlyOnWrongCode(t *testing.T) {
	cfg := testConfig(t, func(c *serverconfig.AccessConfig) {
		c.EmailOTP = serverconfig.EmailOTPConfig{
			Enabled: true, From: "auth@example.com",
			Brevo: &serverconfig.BrevoConfig{APIKey: "unused-in-test"},
		}
		c.Rules = []serverconfig.AccessRule{{
			Name: "media", When: serverconfig.AccessMatch{Hosts: []string{"*.home.example.com"}},
			Action: "allow", Require: &serverconfig.AccessRequire{Emails: []string{"vuko@example.com"}}}}
	})
	var failed int32
	e, err := New(cfg, Hooks{OTPFailed: func() { atomic.AddInt32(&failed, 1) }})
	if err != nil {
		t.Fatal(err)
	}
	e.otp.sender = &captureSender{}
	h := e.Wrap(okHandler(nil))
	txn, token := startLogin(t, h, "http://x.home.example.com/.ztp/login?rd=/")

	// Empty code: form-level failure, must NOT count.
	postForm(t, h, "http://x.home.example.com/.ztp/otp/verify", txn, token,
		url.Values{"email": {"vuko@example.com"}, "code": {""}, "rd": {"/"}})
	if n := atomic.LoadInt32(&failed); n != 0 {
		t.Fatalf("empty code must not increment otp_failed, got %d", n)
	}

	// Wrong code: genuine verification failure, must count once.
	postForm(t, h, "http://x.home.example.com/.ztp/otp/verify", txn, token,
		url.Values{"email": {"vuko@example.com"}, "code": {"000000"}, "rd": {"/"}})
	if n := atomic.LoadInt32(&failed); n != 1 {
		t.Fatalf("wrong code must increment otp_failed once, got %d", n)
	}
}

// Regression (re-review finding C): only GET starts a login transaction,
// so a forced cross-site POST cannot rotate the txn cookie.
func TestLoginRejectsNonGET(t *testing.T) {
	e, _ := otpEngine(t)
	h := e.Wrap(okHandler(nil))
	req := httptest.NewRequest("POST", "http://x.home.example.com/.ztp/login", nil)
	req.RemoteAddr = "9.9.9.9:1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /login: got %d, want 405", rr.Code)
	}
	for _, c := range rr.Result().Cookies() {
		if c.Name == loginTxnCookie {
			t.Fatal("POST /login must not issue a transaction cookie")
		}
	}
}

// The login endpoints 404 when OTP is disabled.
func TestOTPEndpointsAbsentWhenDisabled(t *testing.T) {
	e := newTestEngine(t, nil) // no EmailOTP block
	h := e.Wrap(okHandler(nil))
	for _, target := range []string{"/.ztp/login", "/.ztp/otp/request", "/.ztp/otp/verify"} {
		rr := send(t, h, "GET", "http://www.example.com"+target, "9.9.9.9", nil)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("%s: %d, want 404", target, rr.Code)
		}
	}
}
