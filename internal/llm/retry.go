package llm

import (
	"context"
	"errors"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/cenkalti/backoff/v7"
)

// The production numbers of the retry policy. A zero field of retryPolicy
// means the number here. RetryMaxTries and RetryAfterCap are exported only so
// that the help text of a caller can show them; nothing outside this package
// can change the policy.
const (
	// RetryMaxTries is the most requests that Classify sends for one tool:
	// 3 tries in total, the first request and 2 retries.
	RetryMaxTries = 3
	// retryInitial is the first backoff wait, before jitter.
	retryInitial = 1 * time.Second
	// retryMax is the longest backoff wait, before jitter.
	retryMax = 8 * time.Second
	// RetryAfterCap is the longest Retry-After wait that Classify honours. A
	// longer wait means no retry: the error comes back at once.
	RetryAfterCap = 30 * time.Second
	// retryJitter is the randomization factor of the backoff: each wait is
	// the base wait times a random value from 0.5 to 1.5.
	retryJitter = 0.5
	// retryMultiplier makes each base wait twice the one before it.
	retryMultiplier = 2
)

// statusOverloaded is HTTP 529, which the Anthropic API sends when it is
// overloaded. net/http has no name for it.
const statusOverloaded = 529

// retryPolicy is the retry policy of Classify. The client tries the request
// again only for HTTP 429, 502, 503, 504 and 529. Every other status code
// (also 400, 413 and 422, which are per tool), a request timeout and every
// other transport error give no retry.
//
// The client sends at most maxTries requests for one tool (RetryMaxTries by
// default: the first request and 2 retries). So a scan sends at most 3 times
// the number of tools that it rates. That is the cost bound of --llm.
//
// Between two tries the client waits for an exponential backoff with jitter:
// the base wait starts at initialWait (1 s) and doubles up to maxWait (8 s),
// and the jitter makes each wait 0.5 to 1.5 times the base wait. With 3
// tries there are 2 waits, of about 1 s and 2 s. When the answer has a valid
// Retry-After header, the client waits for that time instead. A Retry-After
// that is longer than afterCap (RetryAfterCap, 30 s) means no retry: the
// error comes back at once. All waits end when the context of the caller
// ends.
//
// The zero value is the production policy. Tests set small delays. Nothing
// changes a policy after New, so it is safe to copy and to use at the same
// time from many goroutines.
type retryPolicy struct {
	// maxTries is the number of requests in total. Zero means RetryMaxTries.
	maxTries uint
	// initialWait is the first backoff wait. Zero means retryInitial.
	initialWait time.Duration
	// maxWait is the longest backoff wait. Zero means retryMax.
	maxWait time.Duration
	// afterCap is the longest Retry-After wait. Zero means RetryAfterCap.
	afterCap time.Duration
	// now gives the current time, to turn a Retry-After date into a wait.
	// Nil means time.Now.
	now func() time.Time
}

// withDefaults returns p with each zero field set to its production number.
func (p retryPolicy) withDefaults() retryPolicy {
	if p.maxTries == 0 {
		p.maxTries = RetryMaxTries
	}
	if p.initialWait == 0 {
		p.initialWait = retryInitial
	}
	if p.maxWait == 0 {
		p.maxWait = retryMax
	}
	if p.afterCap == 0 {
		p.afterCap = RetryAfterCap
	}
	if p.now == nil {
		p.now = time.Now
	}
	return p
}

// retryDecision is the decision of retryPolicy.decide for one failed try.
type retryDecision int

// The decisions.
const (
	// noRetry means that the client returns the error at once.
	noRetry retryDecision = iota
	// retryBackoff means that the client waits for the backoff time and
	// tries again.
	retryBackoff
	// retryWait means that the client waits for the Retry-After time and
	// tries again.
	retryWait
)

// decide returns whether the client tries again after err, and the wait for
// retryWait. Only a *StatusError with a code of retryableStatus gives a
// retry. p must have its defaults set (see withDefaults).
func (p retryPolicy) decide(err error) (retryDecision, time.Duration) {
	var status *StatusError
	if !errors.As(err, &status) || status == nil || !retryableStatus(status.Code) {
		return noRetry, 0
	}
	if !status.hasRetryAfter {
		return retryBackoff, 0
	}
	if status.retryAfter > p.afterCap {
		return noRetry, 0
	}
	return retryWait, status.retryAfter
}

// retryableStatus reports whether code means that the provider is busy or
// overloaded for a short time, so a later try can succeed.
func retryableStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout,
		statusOverloaded:
		return true
	default:
		return false
	}
}

// parseRetryAfter reads the value of a Retry-After header: a number of
// seconds (ASCII digits only) or an HTTP-date. It returns the wait and true
// for a valid value. An empty value, a value that is not valid (for example
// "-5", "+5" or "1.5") or a date in the past gives false, and the client then
// uses the normal backoff. A number of seconds that is too large for an
// integer gives the largest wait, so decide refuses it as above the cap. The
// value comes from the server, so it is never printed.
func parseRetryAfter(value string, now time.Time) (time.Duration, bool) {
	if value == "" {
		return 0, false
	}
	// ParseUint with base 10 accepts only ASCII digits: no sign, no space
	// and no "_".
	secs, err := strconv.ParseUint(value, 10, 64)
	switch {
	case err == nil:
		// Compare before the multiplication, so that it cannot overflow.
		if secs > uint64(math.MaxInt64/int64(time.Second)) {
			return time.Duration(math.MaxInt64), true
		}
		return time.Duration(secs) * time.Second, true
	case errors.Is(err, strconv.ErrRange):
		// Only digits, but too many of them.
		return time.Duration(math.MaxInt64), true
	}
	// http.ParseTime accepts the three HTTP-date formats of RFC 9110.
	date, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}
	wait := date.Sub(now)
	if wait < 0 {
		return 0, false
	}
	return wait, true
}

// sendWithRetry calls send and tries again as retryPolicy says. It waits
// only inside ctx. When a Retry-After wait would end after the deadline of
// ctx, it returns the provider error at once, without the wait. Each try
// calls send again, so each try builds a new request with a new body.
//
// It never returns an error of the backoff library: their text holds the
// text of the last error, so it unwraps them (see retryError). After the
// last try it returns the error of that try as it is, so the caller sees
// the same error as without retries.
func (c *Client) sendWithRetry(ctx context.Context, message string) (Verdict, error) {
	p := c.retry.withDefaults()
	// The backoff state changes with each wait, so each call has its own.
	b := &backoff.ExponentialBackOff{
		InitialInterval:     p.initialWait,
		RandomizationFactor: retryJitter,
		Multiplier:          retryMultiplier,
		MaxInterval:         p.maxWait,
	}
	// op is one try. Its error tells backoff.Retry what to do next:
	// backoff.Permanent stops at once, backoff.RetryAfter waits for the given
	// time, and a plain error waits for the backoff time.
	op := func() (Verdict, error) {
		v, err := c.send(ctx, message, p.now)
		if err == nil {
			return v, nil
		}
		switch decision, wait := p.decide(err); decision {
		case retryWait:
			// A retry after the deadline of ctx can never happen. Fail now
			// with the provider error, so the worker is free at once.
			if deadline, ok := ctx.Deadline(); ok && wait > time.Until(deadline) {
				return Verdict{}, backoff.Permanent(err)
			}
			return Verdict{}, backoff.RetryAfter(wait, err)
		case retryBackoff:
			return Verdict{}, err
		default:
			return Verdict{}, backoff.Permanent(err)
		}
	}
	v, err := backoff.Retry(ctx, op,
		backoff.WithBackOff(b),
		backoff.WithMaxTries(p.maxTries),
		// 0 turns off the elapsed-time limit of the library (15 minutes by
		// default). The tries and the context of the caller are the limits.
		backoff.WithMaxElapsedTime(0),
	)
	if err != nil {
		return Verdict{}, retryError(ctx, err)
	}
	return v, nil
}

// retryError turns an error of backoff.Retry into an error of this package
// with fixed text. When the context of the caller ended before the next try
// (also during a wait), it returns stopped(ctx.Err()), the same error as
// when the context ends during a request (see transportError). Otherwise it
// returns the error of the last try.
func retryError(ctx context.Context, err error) error {
	var re *backoff.RetryError
	if !errors.As(err, &re) || re.LastErr == nil {
		// backoff.Retry returns a *RetryError with a LastErr for every
		// failure, so this is a guard only. Do not return err: its text
		// can come from the library.
		return ErrProvider
	}
	stoppedByLimit := errors.Is(re.Cause, backoff.ErrPermanent) ||
		errors.Is(re.Cause, backoff.ErrExhausted)
	if !stoppedByLimit {
		if cerr := ctx.Err(); cerr != nil {
			return stopped(cerr)
		}
	}
	return re.LastErr
}
