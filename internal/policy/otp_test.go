package policy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
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

func postForm(t *testing.T, h http.Handler, target string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "9.9.9.9:1"
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

	// 2. Request a code for the eligible address.
	rr = postForm(t, h, "http://sonarr.home.example.com/.ztp/otp/request",
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
	rr = postForm(t, h, "http://sonarr.home.example.com/.ztp/otp/verify",
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
	rr = postForm(t, h, "http://sonarr.home.example.com/.ztp/otp/verify",
		url.Values{"email": {"vuko@example.com"}, "code": {"000000"}, "rd": {"/"}})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("wrong code: %d, want 400", rr.Code)
	}
}

// Ineligible addresses get the identical response and NO mail.
func TestOTPNoEnumerationNoMailForIneligible(t *testing.T) {
	e, sender := otpEngine(t)
	h := e.Wrap(okHandler(nil))

	eligible := postForm(t, h, "http://x.home.example.com/.ztp/otp/request",
		url.Values{"email": {"vuko@example.com"}, "rd": {"/"}})
	ineligible := postForm(t, h, "http://x.home.example.com/.ztp/otp/request",
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

	requestFrom := func(addr string) {
		req := httptest.NewRequest("POST", "http://x.home.example.com/.ztp/otp/request",
			strings.NewReader(url.Values{"email": {"ceo@corp.example"}, "rd": {"/"}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = addr
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
