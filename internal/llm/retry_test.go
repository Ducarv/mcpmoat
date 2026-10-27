package llm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v7"
)

// testRetry is the retry policy of the test clients (see newTestClient): the
// production number of tries and Retry-After cap, with backoff waits of a few
// milliseconds. maxTries stays zero on purpose, so the tests check the
// production number of tries.
var testRetry = retryPolicy{initialWait: time.Millisecond, maxWait: 2 * time.Millisecond}

// slowBackoff has a backoff wait that is longer than any test. A test that
// uses it and still sees a quick retry proves that the client used the
// Retry-After wait, not the backoff.
var slowBackoff = retryPolicy{initialWait: time.Hour, maxWait: time.Hour}

// retryGuard bounds each Classify call of the retry tests. A broken retry
// that waits too long then fails the test with a context error, and does
// not hang it.
const retryGuard = 10 * time.Second

// retryBase is the fixed time of the Retry-After date tests.
var retryBase = time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)

// busyCodes are the status codes that the client tries again.
var busyCodes = []int{
	http.StatusTooManyRequests,
	http.StatusBadGateway,
	http.StatusServiceUnavailable,
	http.StatusGatewayTimeout,
	statusOverloaded,
}

// always is a number of failures that no test reaches.
const always = math.MaxInt32

// failThen returns a handler that answers status, with the Retry-After header
// retryAfter when it is not empty, to the first fails requests, and a valid
// verdict of p (risk low, category other) after that. The body of a failure
// holds llmBodyCanary.
func failThen(p Provider, status, fails int, retryAfter string) http.HandlerFunc {
	var n atomic.Int64
	return func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) <= int64(fails) {
			if retryAfter != "" {
				w.Header().Set("Retry-After", retryAfter)
			}
			reply(status, validReply(p, RiskNone, CategoryOther)+llmBodyCanary)(w, r)
			return
		}
		reply(http.StatusOK, validReply(p, RiskLow, CategoryOther))(w, r)
	}
}

// okVerdict is the verdict of a failThen handler after its failures.
var okVerdict = Verdict{Risk: RiskLow, Category: CategoryOther}

// newRetryClient returns a test client for p at base with the retry policy
// policy.
func newRetryClient(t *testing.T, p Provider, base string, policy retryPolicy) *Client {
	t.Helper()
	c := newTestClient(t, p, base)
	c.retry = policy
	return c
}

// classifyTimed calls Classify with a context that ends after retryGuard,
// and returns the time that the call took.
func classifyTimed(t *testing.T, c *Client) (Verdict, time.Duration, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), retryGuard)
	defer cancel()
	start := time.Now()
	v, err := c.Classify(ctx, Input{ToolName: "t", Description: "d"})
	return v, time.Since(start), err
}

// checkStatusError fails when err is not the *StatusError with code that
// one request without retries gives: the same fixed text, ErrProvider, no
// context error and no error of the backoff library.
func checkStatusError(t *testing.T, err error, code int) {
	t.Helper()
	var se *StatusError
	if !errors.As(err, &se) || se.Code != code {
		t.Fatalf("Classify() error = %v, want *StatusError{Code: %d}", err, code)
	}
	if !errors.Is(err, ErrProvider) || errors.Is(err, ErrInvalidOutput) {
		t.Errorf("Classify() error = %v, want ErrProvider and not ErrInvalidOutput", err)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Classify() error = %v, want no context error", err)
	}
	var re *backoff.RetryError
	if errors.As(err, &re) {
		t.Errorf("Classify() error = %v, want no *backoff.RetryError", err)
	}
	if errors.Is(err, backoff.ErrExhausted) || errors.Is(err, backoff.ErrPermanent) {
		t.Errorf("Classify() error = %v, want no backoff sentinel", err)
	}
	if got, want := err.Error(), (&StatusError{Code: code}).Error(); got != want {
		t.Errorf("Classify() error = %q, want %q", got, want)
	}
	for _, s := range []string{"backoff", "retr", "last error", "exhausted"} {
		if strings.Contains(err.Error(), s) || strings.Contains(Reason(err), s) {
			t.Errorf("Classify() error = %q, Reason = %q, want no %q", err, Reason(err), s)
		}
	}
	if strings.Contains(Reason(err), llmBodyCanary) {
		t.Errorf("Reason() = %q holds the body canary", Reason(err))
	}
	assertNoLeak(t, err)
}

func TestRetryPolicyDefaults(t *testing.T) {
	t.Parallel()
	got := retryPolicy{}.withDefaults()
	if got.maxTries != 3 || got.initialWait != time.Second || got.maxWait != 8*time.Second || got.afterCap != 30*time.Second {
		t.Errorf("withDefaults() = %+v, want 3 tries, 1s, 8s, 30s", got)
	}
	if got.now == nil {
		t.Fatal("withDefaults().now = nil, want time.Now")
	}
	if d := time.Since(got.now()); d < 0 || d > time.Minute {
		t.Errorf("withDefaults().now() is %v from time.Now, want time.Now", d)
	}
	if retryJitter != 0.5 || retryMultiplier != 2 {
		t.Errorf("jitter, multiplier = %v, %v, want 0.5, 2", retryJitter, retryMultiplier)
	}

	fixed := func() time.Time { return retryBase }
	set := retryPolicy{maxTries: 5, initialWait: 2, maxWait: 3, afterCap: 4, now: fixed}.withDefaults()
	if set.maxTries != 5 || set.initialWait != 2 || set.maxWait != 3 || set.afterCap != 4 || !set.now().Equal(retryBase) {
		t.Errorf("withDefaults() = %+v, want the set fields kept", set)
	}
}

func TestRetryableStatus(t *testing.T) {
	t.Parallel()
	for code := -1; code <= 600; code++ {
		want := code == 429 || code == 502 || code == 503 || code == 504 || code == 529
		if got := retryableStatus(code); got != want {
			t.Errorf("retryableStatus(%d) = %v, want %v", code, got, want)
		}
	}
}

func TestRetryPolicyDecide(t *testing.T) {
	t.Parallel()
	p := retryPolicy{}.withDefaults()
	after := func(code int, d time.Duration) *StatusError {
		return &StatusError{Code: code, retryAfter: d, hasRetryAfter: true}
	}
	var typedNil *StatusError
	tests := []struct {
		name     string
		err      error
		want     retryDecision
		wantWait time.Duration
	}{
		{name: "nil", err: nil, want: noRetry},
		{name: "429", err: &StatusError{Code: 429}, want: retryBackoff},
		{name: "502", err: &StatusError{Code: 502}, want: retryBackoff},
		{name: "503", err: &StatusError{Code: 503}, want: retryBackoff},
		{name: "504", err: &StatusError{Code: 504}, want: retryBackoff},
		{name: "529", err: &StatusError{Code: 529}, want: retryBackoff},
		{name: "wrapped 503", err: fmt.Errorf("x: %w", &StatusError{Code: 503}), want: retryBackoff},
		{name: "400", err: &StatusError{Code: 400}, want: noRetry},
		{name: "413", err: &StatusError{Code: 413}, want: noRetry},
		{name: "422", err: &StatusError{Code: 422}, want: noRetry},
		{name: "401", err: &StatusError{Code: 401}, want: noRetry},
		{name: "403", err: &StatusError{Code: 403}, want: noRetry},
		{name: "404", err: &StatusError{Code: 404}, want: noRetry},
		{name: "500", err: &StatusError{Code: 500}, want: noRetry},
		{name: "302", err: &StatusError{Code: 302}, want: noRetry},
		{name: "400 with Retry-After", err: after(400, 0), want: noRetry},
		{name: "500 with Retry-After", err: after(500, time.Second), want: noRetry},
		{name: "typed nil", err: typedNil, want: noRetry},
		{name: "timeout", err: errTimeout, want: noRetry},
		{name: "transport", err: errTransport, want: noRetry},
		{name: "not loopback", err: errNotLoopback, want: noRetry},
		{name: "bad response", err: errBadResponse, want: noRetry},
		{name: "too large", err: errTooLarge, want: noRetry},
		{name: "invalid output", err: ErrInvalidOutput, want: noRetry},
		{name: "rejected", err: ErrRejected, want: noRetry},
		{name: "provider", err: ErrProvider, want: noRetry},
		{name: "stopped", err: stopped(context.Canceled), want: noRetry},
		{name: "Retry-After zero", err: after(429, 0), want: retryWait, wantWait: 0},
		{name: "Retry-After 7s", err: after(503, 7*time.Second), want: retryWait, wantWait: 7 * time.Second},
		{name: "Retry-After at the cap", err: after(529, retryAfterCap), want: retryWait, wantWait: retryAfterCap},
		{name: "Retry-After above the cap", err: after(429, retryAfterCap+time.Nanosecond), want: noRetry},
		{name: "Retry-After max", err: after(429, time.Duration(math.MaxInt64)), want: noRetry},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, wait := p.decide(tt.err)
			if got != tt.want || wait != tt.wantWait {
				t.Errorf("decide(%v) = %v, %v, want %v, %v", tt.err, got, wait, tt.want, tt.wantWait)
			}
		})
	}

	t.Run("small cap", func(t *testing.T) {
		t.Parallel()
		small := retryPolicy{afterCap: time.Second}.withDefaults()
		if got, _ := small.decide(after(429, 2*time.Second)); got != noRetry {
			t.Errorf("decide(2s) with a 1s cap = %v, want noRetry", got)
		}
		if got, wait := small.decide(after(429, time.Second)); got != retryWait || wait != time.Second {
			t.Errorf("decide(1s) with a 1s cap = %v, %v, want retryWait, 1s", got, wait)
		}
	})
}

func TestParseRetryAfter(t *testing.T) {
	t.Parallel()
	now := retryBase
	maxWait := time.Duration(math.MaxInt64)
	tests := []struct {
		name   string
		value  string
		want   time.Duration
		wantOK bool
	}{
		{name: "empty", value: "", wantOK: false},
		{name: "zero", value: "0", want: 0, wantOK: true},
		{name: "seconds", value: "7", want: 7 * time.Second, wantOK: true},
		{name: "leading zeros", value: "007", want: 7 * time.Second, wantOK: true},
		{name: "cap", value: "30", want: 30 * time.Second, wantOK: true},
		{name: "above cap", value: "31", want: 31 * time.Second, wantOK: true},
		{name: "largest exact", value: "9223372036", want: 9223372036 * time.Second, wantOK: true},
		{name: "first overflow", value: "9223372037", want: maxWait, wantOK: true},
		{name: "19 digits", value: "9999999999999999999", want: maxWait, wantOK: true},
		{name: "20 digits", value: "99999999999999999999", want: maxWait, wantOK: true},
		{name: "100 digits", value: strings.Repeat("9", 100), want: maxWait, wantOK: true},
		{name: "negative", value: "-1", wantOK: false},
		{name: "plus sign", value: "+5", wantOK: false},
		{name: "fraction", value: "1.5", wantOK: false},
		{name: "leading space", value: " 5", wantOK: false},
		{name: "trailing space", value: "5 ", wantOK: false},
		{name: "underscore", value: "1_0", wantOK: false},
		{name: "hex", value: "0x10", wantOK: false},
		{name: "unit", value: "5s", wantOK: false},
		{name: "word", value: "abc", wantOK: false},
		{name: "arabic digit", value: "٣", wantOK: false},
		{name: "canary", value: llmBodyCanary, wantOK: false},
		{name: "date in 10s", value: now.Add(10 * time.Second).Format(http.TimeFormat), want: 10 * time.Second, wantOK: true},
		{name: "date now", value: now.Format(http.TimeFormat), want: 0, wantOK: true},
		{name: "date 1s ago", value: now.Add(-time.Second).Format(http.TimeFormat), wantOK: false},
		{name: "date far past", value: "Thu, 01 Jan 1970 00:00:00 GMT", wantOK: false},
		{name: "date above cap", value: now.Add(31 * time.Second).Format(http.TimeFormat), want: 31 * time.Second, wantOK: true},
		{name: "RFC 850 date", value: now.Add(5 * time.Second).Format(time.RFC850), want: 5 * time.Second, wantOK: true},
		{name: "ANSI C date", value: now.Add(5 * time.Second).Format(time.ANSIC), want: 5 * time.Second, wantOK: true},
		{name: "date without GMT", value: "Wed, 02 Jan 2030 03:04:15", wantOK: false},
		{name: "ISO date", value: now.Add(5 * time.Second).Format(time.RFC3339), wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := parseRetryAfter(tt.value, now)
			if got != tt.want || ok != tt.wantOK {
				t.Errorf("parseRetryAfter(%q) = %v, %v, want %v, %v", tt.value, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

// FuzzParseRetryAfter checks that any header value gives a wait that is not
// negative, and that a false result has a zero wait.
func FuzzParseRetryAfter(f *testing.F) {
	for _, s := range []string{"", "0", "7", "-1", "1.5", "99999999999999999999", retryBase.Format(http.TimeFormat)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, value string) {
		got, ok := parseRetryAfter(value, retryBase)
		if got < 0 || (!ok && got != 0) {
			t.Errorf("parseRetryAfter(%q) = %v, %v", value, got, ok)
		}
	})
}

func TestRetryError(t *testing.T) {
	t.Parallel()
	last := &StatusError{Code: 429}
	tests := []struct {
		name     string
		err      error
		canceled bool
		want     error
		wantStop bool
	}{
		{name: "exhausted", err: &backoff.RetryError{LastErr: last, Cause: backoff.ErrExhausted}, want: last},
		{name: "permanent", err: &backoff.RetryError{LastErr: last, Cause: backoff.ErrPermanent}, want: last},
		// The tries are used up first: the error of the last try wins over
		// a context that ended at the same time.
		{name: "exhausted, context ended", err: &backoff.RetryError{LastErr: last, Cause: backoff.ErrExhausted}, canceled: true, want: last},
		{name: "permanent, context ended", err: &backoff.RetryError{LastErr: last, Cause: backoff.ErrPermanent}, canceled: true, want: last},
		{name: "context ended", err: &backoff.RetryError{LastErr: last, Cause: context.Canceled}, canceled: true, wantStop: true},
		{name: "other cause, context ended", err: &backoff.RetryError{LastErr: last, Cause: errors.New("cause")}, canceled: true, wantStop: true},
		{name: "elapsed time", err: &backoff.RetryError{LastErr: last, Cause: backoff.ErrMaxElapsedTime}, want: last},
		{name: "no last error", err: &backoff.RetryError{Cause: backoff.ErrExhausted}, want: ErrProvider},
		{name: "not a RetryError", err: errors.New("backoff: " + llmBodyCanary), want: ErrProvider},
		{name: "nil", err: nil, want: ErrProvider},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tt.canceled {
				cancel()
			}
			got := retryError(ctx, tt.err)
			if tt.wantStop {
				if !errors.Is(got, context.Canceled) || errors.Is(got, ErrProvider) || got.Error() != stopped(context.Canceled).Error() {
					t.Errorf("retryError() = %v, want stopped(context.Canceled)", got)
				}
			} else if !errors.Is(got, tt.want) || got.Error() != tt.want.Error() {
				t.Errorf("retryError() = %v, want %v", got, tt.want)
			}
			var re *backoff.RetryError
			if errors.As(got, &re) {
				t.Errorf("retryError() = %v, want no *backoff.RetryError", got)
			}
			assertNoLeak(t, got)
		})
	}
}

// TestClassifyRetriesBusyStatus checks that each busy status code gives a
// new try, and that a later success gives the verdict.
func TestClassifyRetriesBusyStatus(t *testing.T) {
	t.Parallel()
	for _, p := range bothProviders {
		for _, code := range busyCodes {
			for _, fails := range []int{1, 2} {
				t.Run(fmt.Sprintf("%s/%d/%d failures", p, code, fails), func(t *testing.T) {
					t.Parallel()
					srv := startServer(t, failThen(p, code, fails, ""))
					c := newRetryClient(t, p, srv.URL, testRetry)
					v, _, err := classifyTimed(t, c)
					if err != nil {
						t.Fatalf("Classify() error = %v, want nil", err)
					}
					if v != okVerdict {
						t.Errorf("Classify() = %+v, want %+v", v, okVerdict)
					}
					if n := int(srv.hits.Load()); n != fails+1 {
						t.Errorf("server requests = %d, want %d", n, fails+1)
					}
				})
			}
		}
	}
}

// TestClassifyRetriesExhausted checks that a provider that stays busy gets
// exactly 3 requests, and that the error is the one of the last request,
// with the same text as without retries.
func TestClassifyRetriesExhausted(t *testing.T) {
	t.Parallel()
	for _, p := range bothProviders {
		for _, code := range busyCodes {
			t.Run(fmt.Sprintf("%s/%d", p, code), func(t *testing.T) {
				t.Parallel()
				srv := startServer(t, failThen(p, code, always, ""))
				c := newRetryClient(t, p, srv.URL, testRetry)
				v, _, err := classifyTimed(t, c)
				checkStatusError(t, err, code)
				if errors.Is(err, ErrRejected) || errors.Is(err, errAuth) {
					t.Errorf("Classify() error = %v, want a global failure", err)
				}
				if got, want := Reason(err), fmt.Sprintf("HTTP %d", code); got != want {
					t.Errorf("Reason() = %q, want %q", got, want)
				}
				if v != (Verdict{}) {
					t.Errorf("Classify() = %+v, want zero", v)
				}
				if n := srv.hits.Load(); n != 3 {
					t.Errorf("server requests = %d, want 3", n)
				}
				assertNoLeak(t, err, srv.URL)
			})
		}
	}
}

// TestClassifyRetryMaxTries checks that the client sends maxTries requests
// in total, when a test sets it.
func TestClassifyRetryMaxTries(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		tries uint
		want  int32
	}{{tries: 1, want: 1}, {tries: 2, want: 2}, {tries: 5, want: 5}} {
		t.Run(fmt.Sprint(tt.tries), func(t *testing.T) {
			t.Parallel()
			srv := startServer(t, failThen(ProviderAnthropic, http.StatusTooManyRequests, always, ""))
			policy := testRetry
			policy.maxTries = tt.tries
			c := newRetryClient(t, ProviderAnthropic, srv.URL, policy)
			_, _, err := classifyTimed(t, c)
			checkStatusError(t, err, http.StatusTooManyRequests)
			if n := srv.hits.Load(); n != tt.want {
				t.Errorf("server requests = %d, want %d", n, tt.want)
			}
		})
	}
}

// TestClassifyRetryBackoffWaits checks that the client waits between two
// tries: with a base wait of 40 ms and a jitter of 0.5, each of the 2 waits
// is at least 20 ms.
func TestClassifyRetryBackoffWaits(t *testing.T) {
	t.Parallel()
	const wait = 40 * time.Millisecond
	srv := startServer(t, failThen(ProviderOpenAI, http.StatusServiceUnavailable, always, ""))
	c := newRetryClient(t, ProviderOpenAI, srv.URL, retryPolicy{initialWait: wait, maxWait: wait})
	_, took, err := classifyTimed(t, c)
	checkStatusError(t, err, http.StatusServiceUnavailable)
	if n := srv.hits.Load(); n != 3 {
		t.Errorf("server requests = %d, want 3", n)
	}
	if least := 2 * (wait / 2); took < least {
		t.Errorf("Classify() took %v, want at least %v of backoff", took, least)
	}
}

// TestClassifyNoRetry checks that every status code that is not busy, and
// every answer that is not usable, gives exactly one request.
func TestClassifyNoRetry(t *testing.T) {
	t.Parallel()
	codes := []int{400, 413, 422, 401, 403, 404, 405, 408, 409, 418, 500, 501, 505, 520, 530, 599, 301, 302, 303, 307, 308, 300}
	for _, p := range bothProviders {
		for _, code := range codes {
			t.Run(fmt.Sprintf("%s/%d", p, code), func(t *testing.T) {
				t.Parallel()
				// A Retry-After header must not turn a code into a busy one.
				srv := startServer(t, failThen(p, code, always, "0"))
				c := newRetryClient(t, p, srv.URL, testRetry)
				_, _, err := classifyTimed(t, c)
				checkStatusError(t, err, code)
				if n := srv.hits.Load(); n != 1 {
					t.Errorf("server requests = %d, want 1", n)
				}
			})
		}
		for _, tt := range []struct {
			name    string
			body    string
			wantErr error
		}{
			{name: "invalid output", body: validReply(p, "critical", CategoryOther), wantErr: ErrInvalidOutput},
			{name: "bad response", body: "<html>" + llmBodyCanary, wantErr: errBadResponse},
		} {
			t.Run(string(p)+"/"+tt.name, func(t *testing.T) {
				t.Parallel()
				srv := startServer(t, reply(http.StatusOK, tt.body))
				c := newRetryClient(t, p, srv.URL, testRetry)
				_, _, err := classifyTimed(t, c)
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Classify() error = %v, want %v", err, tt.wantErr)
				}
				if n := srv.hits.Load(); n != 1 {
					t.Errorf("server requests = %d, want 1", n)
				}
				assertNoLeak(t, err, srv.URL)
			})
		}
	}
}

// TestClassifyNoRetryTransport checks that a timeout and other transport
// errors give exactly one try.
func TestClassifyNoRetryTransport(t *testing.T) {
	t.Parallel()
	for _, p := range bothProviders {
		for _, tt := range []struct {
			name    string
			dialErr error
			wantErr error
		}{
			// requestTimeout is a constant (30 s), so a dial error that
			// reports a timeout stands in for a request that timed out.
			{name: "timeout", dialErr: timeoutError{}, wantErr: errTimeout},
			{name: "dial error", dialErr: errors.New("refused " + llmBodyCanary), wantErr: errTransport},
		} {
			t.Run(string(p)+"/"+tt.name, func(t *testing.T) {
				t.Parallel()
				srv := startServer(t, reply(http.StatusOK, validReply(p, RiskNone, CategoryOther)))
				var dials atomic.Int32
				c, err := New(Config{
					Provider: p,
					Model:    llmTestModel,
					BaseURL:  srv.URL,
					APIKey:   testSecret(),
					Dial: func(context.Context, string, string) (net.Conn, error) {
						dials.Add(1)
						return nil, tt.dialErr
					},
				})
				if err != nil {
					t.Fatalf("New() error = %v", err)
				}
				c.retry = testRetry
				t.Cleanup(c.CloseIdleConnections)

				_, _, err = classifyTimed(t, c)
				if !errors.Is(err, tt.wantErr) || !errors.Is(err, ErrProvider) {
					t.Fatalf("Classify() error = %v, want %v", err, tt.wantErr)
				}
				if n := dials.Load(); n != 1 {
					t.Errorf("dials = %d, want 1 (no retry)", n)
				}
				assertNoLeak(t, err, srv.URL)
			})
		}

		t.Run(string(p)+"/connection closed", func(t *testing.T) {
			t.Parallel()
			srv := startServer(t, func(w http.ResponseWriter, _ *http.Request) {
				conn, _, err := http.NewResponseController(w).Hijack()
				if err != nil {
					t.Errorf("server: hijack: %v", err)
					return
				}
				_ = conn.Close()
			})
			c := newRetryClient(t, p, srv.URL, testRetry)
			_, _, err := classifyTimed(t, c)
			if !errors.Is(err, errTransport) || errors.Is(err, errTimeout) {
				t.Fatalf("Classify() error = %v, want errTransport", err)
			}
			if n := srv.hits.Load(); n != 1 {
				t.Errorf("server requests = %d, want 1", n)
			}
			assertNoLeak(t, err, srv.URL)
		})
	}
}

// TestClassifyRetryAfter checks the Retry-After header end to end. The
// first answer is HTTP 429 with the header, the next one a verdict. A
// fake clock turns a date into a wait of milliseconds, so no case waits
// for seconds.
func TestClassifyRetryAfter(t *testing.T) {
	t.Parallel()
	date := retryBase.Format(http.TimeFormat)
	at := func(p retryPolicy, now time.Time) retryPolicy {
		p.now = func() time.Time { return now }
		return p
	}
	smallCap := testRetry
	smallCap.afterCap = 500 * time.Millisecond
	tests := []struct {
		name     string
		header   string
		policy   retryPolicy
		wantHits int32 // 2: one retry, then the verdict; 1: no retry, HTTP 429
		minTook  time.Duration
	}{
		// The backoff of slowBackoff is one hour: a quick retry proves that
		// the client used the Retry-After wait.
		{name: "zero seconds", header: "0", policy: slowBackoff, wantHits: 2},
		{name: "date within the cap", header: date, policy: at(slowBackoff, retryBase.Add(-150*time.Millisecond)), wantHits: 2, minTook: 150 * time.Millisecond},
		{name: "date now", header: date, policy: at(slowBackoff, retryBase), wantHits: 2},
		{name: "RFC 850 date", header: retryBase.Format(time.RFC850), policy: at(slowBackoff, retryBase.Add(-50*time.Millisecond)), wantHits: 2, minTook: 50 * time.Millisecond},
		{name: "ANSI C date", header: retryBase.Format(time.ANSIC), policy: at(slowBackoff, retryBase.Add(-50*time.Millisecond)), wantHits: 2, minTook: 50 * time.Millisecond},

		// Above the cap: no retry, the error comes back at once.
		{name: "seconds above the cap", header: "31", policy: testRetry, wantHits: 1},
		{name: "date above the cap", header: date, policy: at(testRetry, retryBase.Add(-31*time.Second)), wantHits: 1},
		{name: "above a small cap", header: "1", policy: smallCap, wantHits: 1},
		{name: "19 digits", header: "9999999999999999999", policy: testRetry, wantHits: 1},
		{name: "20 digits", header: "99999999999999999999", policy: testRetry, wantHits: 1},

		// Not a valid wait: the normal backoff (milliseconds in testRetry).
		{name: "date in the past", header: date, policy: at(testRetry, retryBase.Add(time.Hour)), wantHits: 2},
		{name: "word", header: "abc", policy: testRetry, wantHits: 2},
		{name: "negative", header: "-1", policy: testRetry, wantHits: 2},
		{name: "plus sign", header: "+5", policy: testRetry, wantHits: 2},
		{name: "fraction", header: "1.5", policy: testRetry, wantHits: 2},
		{name: "unit", header: "5s", policy: testRetry, wantHits: 2},
		{name: "canary", header: llmBodyCanary, policy: testRetry, wantHits: 2},
		{name: "no header", header: "", policy: testRetry, wantHits: 2},
	}
	for _, p := range bothProviders {
		for _, tt := range tests {
			t.Run(string(p)+"/"+tt.name, func(t *testing.T) {
				t.Parallel()
				srv := startServer(t, failThen(p, http.StatusTooManyRequests, 1, tt.header))
				c := newRetryClient(t, p, srv.URL, tt.policy)
				v, took, err := classifyTimed(t, c)
				if n := srv.hits.Load(); n != tt.wantHits {
					t.Errorf("server requests = %d, want %d", n, tt.wantHits)
				}
				if tt.wantHits == 1 {
					checkStatusError(t, err, http.StatusTooManyRequests)
					assertNoLeak(t, err, tt.header)
					return
				}
				if err != nil {
					t.Fatalf("Classify() error = %v, want nil", err)
				}
				if v != okVerdict {
					t.Errorf("Classify() = %+v, want %+v", v, okVerdict)
				}
				if took < tt.minTook {
					t.Errorf("Classify() took %v, want at least the Retry-After wait %v", took, tt.minTook)
				}
			})
		}
	}
}

// TestSendReadsRetryAfter checks that send keeps the Retry-After wait of a
// non-2xx answer in the *StatusError, and nothing else of the answer.
func TestSendReadsRetryAfter(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		header  string
		want    time.Duration
		wantHas bool
	}{
		{name: "seconds", header: "7", want: 7 * time.Second, wantHas: true},
		{name: "date", header: retryBase.Add(12 * time.Second).Format(http.TimeFormat), want: 12 * time.Second, wantHas: true},
		{name: "huge", header: "99999999999999999999", want: time.Duration(math.MaxInt64), wantHas: true},
		{name: "garbage", header: "abc", wantHas: false},
		{name: "none", header: "", wantHas: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srv := startServer(t, failThen(ProviderAnthropic, http.StatusServiceUnavailable, always, tt.header))
			c := newRetryClient(t, ProviderAnthropic, srv.URL, retryPolicy{now: func() time.Time { return retryBase }})
			_, err := c.send(t.Context(), "m")
			var se *StatusError
			if !errors.As(err, &se) || se.Code != http.StatusServiceUnavailable {
				t.Fatalf("send() error = %v, want *StatusError{Code: 503}", err)
			}
			if se.retryAfter != tt.want || se.hasRetryAfter != tt.wantHas {
				t.Errorf("send() retryAfter = %v, %v, want %v, %v", se.retryAfter, se.hasRetryAfter, tt.want, tt.wantHas)
			}
			if n := srv.hits.Load(); n != 1 {
				t.Errorf("server requests = %d, want 1 (send does not retry)", n)
			}
		})
	}
}

// TestClassifyRetryCanceledDuringWait checks that the end of the caller
// context during the wait before a retry stops Classify at once, with the
// stopped error and no other request. The backoff is one hour, so only the
// context can end the wait.
func TestClassifyRetryCanceledDuringWait(t *testing.T) {
	t.Parallel()
	for _, p := range bothProviders {
		t.Run(string(p)+"/canceled", func(t *testing.T) {
			t.Parallel()
			srv := startServer(t, failThen(p, http.StatusTooManyRequests, always, ""))
			// send calls now after the answer came, so the close of answered
			// means: the first try is over and the wait is next.
			answered := make(chan struct{})
			var once sync.Once
			policy := slowBackoff
			policy.now = func() time.Time {
				once.Do(func() { close(answered) })
				return time.Now()
			}
			c := newRetryClient(t, p, srv.URL, policy)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			go func() {
				<-answered
				cancel()
			}()

			done := make(chan error, 1)
			go func() {
				_, err := c.Classify(ctx, Input{ToolName: "t", Description: "d"})
				done <- err
			}()
			var err error
			select {
			case err = <-done:
			case <-time.After(retryGuard):
				t.Fatal("Classify() did not stop when the context was canceled during the wait")
			}
			if !errors.Is(err, context.Canceled) || errors.Is(err, ErrProvider) || errors.Is(err, ErrInvalidOutput) {
				t.Errorf("Classify() error = %v, want context.Canceled only", err)
			}
			if got, want := err.Error(), stopped(context.Canceled).Error(); got != want {
				t.Errorf("Classify() error = %q, want %q", got, want)
			}
			var re *backoff.RetryError
			if errors.As(err, &re) {
				t.Errorf("Classify() error = %v, want no *backoff.RetryError", err)
			}
			if n := srv.hits.Load(); n != 1 {
				t.Errorf("server requests = %d, want 1", n)
			}
			assertNoLeak(t, err, srv.URL)
		})

		t.Run(string(p)+"/deadline", func(t *testing.T) {
			t.Parallel()
			srv := startServer(t, failThen(p, http.StatusServiceUnavailable, always, ""))
			c := newRetryClient(t, p, srv.URL, slowBackoff)
			ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
			defer cancel()
			_, err := c.Classify(ctx, Input{ToolName: "t", Description: "d"})
			if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrProvider) {
				t.Errorf("Classify() error = %v, want context.DeadlineExceeded only", err)
			}
			// On a slow machine the deadline can pass before the request.
			if n := srv.hits.Load(); n > 1 {
				t.Errorf("server requests = %d, want at most 1", n)
			}
		})

		t.Run(string(p)+"/canceled before the call", func(t *testing.T) {
			t.Parallel()
			srv := startServer(t, failThen(p, http.StatusTooManyRequests, always, ""))
			c := newRetryClient(t, p, srv.URL, testRetry)
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			_, err := c.Classify(ctx, Input{ToolName: "t", Description: "d"})
			if !errors.Is(err, context.Canceled) || errors.Is(err, ErrProvider) {
				t.Errorf("Classify() error = %v, want context.Canceled only", err)
			}
			if n := srv.hits.Load(); n != 0 {
				t.Errorf("server requests = %d, want 0", n)
			}
		})
	}
}

// TestClassifyRetryNeverReadsBody checks that the client does not read the
// body of a busy answer. The server sends the headers and part of the body,
// then waits until the client closes the connection. A client that reads
// the body waits until retryGuard ends and gets a context error.
func TestClassifyRetryNeverReadsBody(t *testing.T) {
	t.Parallel()
	for _, p := range bothProviders {
		t.Run(string(p), func(t *testing.T) {
			t.Parallel()
			srv := startServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Debug", llmBodyCanary)
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = io.WriteString(w, validReply(p, RiskNone, CategoryOther)+llmBodyCanary)
				_ = http.NewResponseController(w).Flush()
				<-r.Context().Done()
			})
			c := newRetryClient(t, p, srv.URL, testRetry)
			_, _, err := classifyTimed(t, c)
			checkStatusError(t, err, http.StatusTooManyRequests)
			if n := srv.hits.Load(); n != 3 {
				t.Errorf("server requests = %d, want 3", n)
			}
			assertNoLeak(t, err, srv.URL)
		})
	}
}

// TestClassifyRetrySameRequest checks that each try sends the same request:
// the same body, path and auth header. The key is in the auth header of each
// try, and in no error.
func TestClassifyRetrySameRequest(t *testing.T) {
	t.Parallel()
	tests := []struct {
		provider   Provider
		authHeader string
		authValue  string
	}{
		{provider: ProviderAnthropic, authHeader: "X-Api-Key", authValue: llmTestKey},
		{provider: ProviderOpenAI, authHeader: "Authorization", authValue: "Bearer " + llmTestKey},
	}
	for _, tt := range tests {
		t.Run(string(tt.provider), func(t *testing.T) {
			t.Parallel()
			srv := startServer(t, failThen(tt.provider, http.StatusBadGateway, always, ""))
			c := newRetryClient(t, tt.provider, srv.URL, testRetry)
			_, _, err := classifyTimed(t, c)
			checkStatusError(t, err, http.StatusBadGateway)

			reqs := srv.requests()
			if len(reqs) != 3 {
				t.Fatalf("server requests = %d, want 3", len(reqs))
			}
			wantMessage, _, err := toolMessage(Input{ToolName: "t", Description: "d"})
			if err != nil {
				t.Fatalf("toolMessage() error = %v", err)
			}
			first := reqs[0]
			if len(first.Body) == 0 || !strings.Contains(string(first.Body), llmTestModel) {
				t.Fatalf("first body = %q, want the request", first.Body)
			}
			quoted, _ := encodeJSON(wantMessage) // a string always encodes
			if !strings.Contains(string(first.Body), string(quoted)) {
				t.Errorf("first body = %q, want the tool message", first.Body)
			}
			for i, req := range reqs {
				if string(req.Body) != string(first.Body) {
					t.Errorf("try %d body (%d bytes) differs from the first body (%d bytes)", i+1, len(req.Body), len(first.Body))
				}
				if req.Method != first.Method || req.RequestURI != first.RequestURI {
					t.Errorf("try %d = %s %s, want %s %s", i+1, req.Method, req.RequestURI, first.Method, first.RequestURI)
				}
				if got := req.Header.Values(tt.authHeader); len(got) != 1 || got[0] != tt.authValue {
					t.Errorf("try %d %s header = %q, want exactly one %q", i+1, tt.authHeader, got, tt.authValue)
				}
				if got := req.Header.Get("Content-Type"); got != "application/json" {
					t.Errorf("try %d Content-Type = %q, want application/json", i+1, got)
				}
			}
		})
	}
}

// TestClassifyRetryConcurrent runs many calls at the same time against a
// provider that stays busy. Each call has its own backoff state, so each one
// sends exactly 3 requests. Run it with -race.
func TestClassifyRetryConcurrent(t *testing.T) {
	t.Parallel()
	const calls = 16
	for _, p := range bothProviders {
		t.Run(string(p), func(t *testing.T) {
			t.Parallel()
			srv := startServer(t, failThen(p, http.StatusTooManyRequests, always, ""))
			c := newRetryClient(t, p, srv.URL, testRetry)
			var wg sync.WaitGroup
			for range calls {
				wg.Go(func() {
					_, _, err := classifyTimed(t, c)
					var se *StatusError
					if !errors.As(err, &se) || se.Code != http.StatusTooManyRequests {
						t.Errorf("Classify() error = %v, want *StatusError{Code: 429}", err)
					}
				})
			}
			wg.Wait()
			if n := srv.hits.Load(); n != 3*calls {
				t.Errorf("server requests = %d, want %d", n, 3*calls)
			}
		})
	}
}
