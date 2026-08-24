package policy

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"sync"
	"time"
)

// Email one-time-code login (Cloudflare-style "one-time PIN"): an
// eligible email receives a short-lived numeric code; exchanging it
// mints a session cookie. Codes are stored hashed, are single-use,
// have a bounded number of verification attempts, and issuance is
// rate-limited per address so the proxy cannot be used to mail-bomb.

const (
	otpCodeDigits = 6
	// Verification attempts per issued code before it is invalidated.
	otpMaxAttempts = 5
	// Send rate limit: at most otpMaxSends per otpSendWindow per email.
	otpMaxSends   = 3
	otpSendWindow = 10 * time.Minute
	// Lazy sweep threshold for the entry map.
	otpSweepThreshold = 4096
	// Ceiling on concurrent outbound deliveries; excess requests drop
	// their code rather than pin a goroutine (see otpManager.dispatch).
	otpDeliverConcurrency = 32
)

// CodeSender delivers a one-time code to an address. Implementations:
// smtpSender, brevoSender (and test mocks).
type CodeSender interface {
	SendCode(ctx context.Context, to, code string) error
}

type otpEntry struct {
	codeHash    [sha256.Size]byte
	expires     time.Time
	attempts    int
	active      bool // a live code is present (cleared on use/exhaustion)
	sends       int
	windowStart time.Time
}

// invalidateCode consumes the code but keeps the entry so its send
// accounting survives — the counter must not reset just because a code
// was used up or guessed to exhaustion.
func (e *otpEntry) invalidateCode() {
	e.active = false
	e.codeHash = [sha256.Size]byte{}
}

// otpStore holds pending codes, keyed by lowercase email.
type otpStore struct {
	mu      sync.Mutex
	entries map[string]*otpEntry
	ttl     time.Duration
	now     func() time.Time // stubbed in tests
}

func newOTPStore(ttl time.Duration) *otpStore {
	return &otpStore{entries: make(map[string]*otpEntry), ttl: ttl, now: time.Now}
}

// issue generates and records a fresh code for the address, enforcing
// the per-address send limit. ok=false means rate-limited.
func (s *otpStore) issue(email string) (code string, ok bool) {
	code, err := randomCode()
	if err != nil {
		// crypto/rand failure: fail closed, no code.
		log.Error("access: otp code generation failed: %v", err)
		return "", false
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()

	e := s.entries[email]
	if e == nil || now.Sub(e.windowStart) >= otpSendWindow {
		e = &otpEntry{windowStart: now}
		s.entries[email] = e
		s.maybeSweep(now)
	}
	if e.sends >= otpMaxSends {
		return "", false
	}
	e.sends++
	e.codeHash = sha256.Sum256([]byte(code))
	e.expires = now.Add(s.ttl)
	e.attempts = 0
	e.active = true
	return code, true
}

// verify checks a presented code: constant-time compare, bounded
// attempts, single-use on success.
func (s *otpStore) verify(email, code string) bool {
	sum := sha256.Sum256([]byte(code))

	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entries[email]
	if e == nil || !e.active || s.now().After(e.expires) {
		return false
	}
	e.attempts++
	if e.attempts > otpMaxAttempts {
		// Too many guesses: kill the code but keep the entry so its send
		// budget cannot be reset by exhausting attempts (mail-bomb guard).
		e.invalidateCode()
		return false
	}
	if subtle.ConstantTimeCompare(sum[:], e.codeHash[:]) != 1 {
		return false
	}
	e.invalidateCode() // single-use
	return true
}

// maybeSweep drops expired entries once the map is large. Called with
// s.mu held.
func (s *otpStore) maybeSweep(now time.Time) {
	if len(s.entries) < otpSweepThreshold {
		return
	}
	for k, e := range s.entries {
		// Drop only once the send window has elapsed AND no usable code
		// remains — a still-live code (ttl may exceed the window) is kept.
		if now.Sub(e.windowStart) >= otpSendWindow && (!e.active || now.After(e.expires)) {
			delete(s.entries, k)
		}
	}
}

// randomCode returns a crypto-random numeric code of otpCodeDigits.
func randomCode() (string, error) {
	var b [otpCodeDigits]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	out := make([]byte, otpCodeDigits)
	for i, v := range b {
		out[i] = '0' + v%10
	}
	return string(out), nil
}

// otpManager binds the store, the sender, and the flow state together.
type otpManager struct {
	store   *otpStore
	sender  CodeSender
	from    string
	subject string
	sem     chan struct{}  // bounds concurrent deliveries
	wg      sync.WaitGroup // tracks in-flight deliveries (drain/tests)
}

func newOTPManager(store *otpStore, sender CodeSender, from, subject string) *otpManager {
	return &otpManager{
		store:   store,
		sender:  sender,
		from:    from,
		subject: subject,
		sem:     make(chan struct{}, otpDeliverConcurrency),
	}
}

// sendTimeout bounds one outbound mail delivery.
const otpSendTimeout = 15 * time.Second

// dispatch delivers a code off the request goroutine so the HTTP
// response time does not depend on eligibility or on how slow the mail
// server is — closing the enumeration/timing oracle. Delivery is bounded
// by sem; if every slot is busy the code is dropped (logged) rather than
// pinning a goroutine, and onSent (a metric hook) fires only on success.
func (m *otpManager) dispatch(email, code string, onSent func()) {
	select {
	case m.sem <- struct{}{}:
	default:
		log.Warn("access: otp delivery capacity reached; dropped code for %s", email)
		return
	}
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer func() { <-m.sem }()
		ctx, cancel := context.WithTimeout(context.Background(), otpSendTimeout)
		defer cancel()
		if err := m.sender.SendCode(ctx, email, code); err != nil {
			// Never surfaced to the client — that would leak eligibility.
			log.Error("access: otp delivery to %s failed: %v", email, err)
			return
		}
		if onSent != nil {
			onSent()
		}
	}()
}

// wait blocks until in-flight deliveries finish (graceful drain; tests).
func (m *otpManager) wait() { m.wg.Wait() }

// otpMessageBody renders the mail body.
func otpMessageBody(code string, ttl time.Duration) string {
	return fmt.Sprintf("Your sign-in code is: %s\n\nIt expires in %d minutes. If you did not request it, ignore this message.\n",
		code, int(ttl.Minutes()))
}
