package inspect

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// ConnectKind tells what kind of failure a ConnectError describes.
//
// The string values are a stable contract: JSON output may use them.
type ConnectKind string

// Kinds of connect failure.
const (
	// KindTLS is a TLS failure: untrusted, expired or wrong certificate,
	// or a failed handshake.
	KindTLS ConnectKind = "tls"
	// KindTimeout is a timeout or a canceled context.
	KindTimeout ConnectKind = "timeout"
	// KindNetwork is a network failure, such as a refused connection or a
	// DNS error.
	KindNetwork ConnectKind = "network"
	// KindHTTP is a non-2xx HTTP status. ConnectError.Status holds it.
	KindHTTP ConnectKind = "http"
	// KindRedirect is a redirect that mcpmoat does not follow: to another
	// origin, or too many.
	KindRedirect ConnectKind = "redirect"
	// KindOrigin is a request to an origin other than the configured one.
	KindOrigin ConnectKind = "origin"
	// KindTooLarge is a response that is larger than the size cap.
	KindTooLarge ConnectKind = "too-large"
	// KindConfig is a server entry that mcpmoat cannot use, such as a URL
	// that does not parse, a reserved header name, an empty stdio command or
	// a server from an untrusted file without the opt-in.
	KindConfig ConnectKind = "config"
	// KindStart is a stdio server whose process did not start: the command
	// was not found or cannot run, or the work directory cannot be made.
	KindStart ConnectKind = "start"
	// KindProtocol is any other failure, such as an invalid MCP answer.
	KindProtocol ConnectKind = "protocol"
)

// maxReasonRunes is the maximum length of scrubbed error text, in runes.
const maxReasonRunes = 200

// ConnectError describes why mcpmoat could not connect to a server, or why
// the server did not answer as expected.
//
// Error never contains the raw URL or a header value: classify and scrub
// remove them. Reason can contain text that the server controls (a status
// text, a JSON-RPC message) and text from the config (Server, header names).
// Callers must escape the result of Error with internal/termsafe before they
// print it to a terminal.
//
// Unwrap gives the cause, so errors.Is can find context.DeadlineExceeded
// and similar errors. The cause is never a *url.Error (its text holds the
// raw URL), and classify replaces any cause whose text still holds the raw
// URL or a header value. Even so, callers must print Error and not the
// unwrapped cause.
type ConnectError struct {
	// Kind tells what kind of failure this is.
	Kind ConnectKind
	// Server is the server name from the config.
	Server string
	// Status is the HTTP status code. It is set only for KindHTTP.
	Status int
	// Reason is a short text that tells what went wrong.
	Reason string
	// URL is the redacted server URL (discover.URL.String). It can be empty.
	URL string

	// Warnings are the problems with the connection that Remote found even
	// though the inspection failed. Remote sets them on every failure after
	// the connect started when the config sends secrets over plain http:// to
	// a host that is not loopback: the secrets can have gone out before the
	// failure, so the user must still hear about it. Remote does not check
	// whether a request reached the server (a failed DNS lookup or dial
	// sends nothing), so the warning errs on the safe side. A Warning holds
	// keys only, never secret values. It is nil when there are none. Error
	// does not print the warnings.
	Warnings []Warning

	// err is the cause. See Unwrap.
	err error
}

// Error returns "<Server>: <Reason> (<URL>)". The part in parentheses is
// left out when URL is empty. Warnings are not part of the text: a caller
// that wants them reads the Warnings field.
func (e *ConnectError) Error() string {
	if e.URL == "" {
		return e.Server + ": " + e.Reason
	}
	return e.Server + ": " + e.Reason + " (" + e.URL + ")"
}

// Unwrap returns the cause, or nil. See the ConnectError doc for what the
// cause can and cannot hold.
func (e *ConnectError) Unwrap() error {
	return e.err
}

// configError returns a KindConfig error for srv. reason must be fixed text:
// it must not hold the URL or a header value. Examples: "URL does not
// parse", "unsupported URL scheme", `header name not allowed: "Host"`.
func configError(srv discover.Server, reason string) *ConnectError {
	return &ConnectError{
		Kind:   KindConfig,
		Server: srv.Name,
		Reason: reason,
		URL:    srv.URL.String(),
	}
}

// configErrorWithCause is configError with cause as the cause of the error
// (see ConnectError.Unwrap). cause can be nil.
func configErrorWithCause(srv discover.Server, reason string, cause error) *ConnectError {
	ce := configError(srv, reason)
	ce.err = cause
	return ce
}

// transportEvents reports what the HTTP layer saw during one inspection. The
// SDK can flatten error chains (it formats some errors with %v), so classify
// asks the transport directly instead of relying only on errors.Is.
type transportEvents interface {
	// stateFor returns what the HTTP layer saw for the request that caused
	// err (see httpEvents.stateFor for how it finds that request).
	//
	// status is the HTTP status of that request: the code of a non-2xx
	// response that was not a followed redirect. It is 0 after a 2xx
	// response, after a request that got no response, or if there was no
	// request yet.
	//
	// blocked is the first error that the HTTP layer raised on purpose for
	// that request, or for a request that breaks the whole session. It wraps
	// one of the sentinel errors of blockedKinds, for example errOtherOrigin
	// or errAddrRefused. It is nil if there was none.
	stateFor(err error) (status int, blocked error)
	// connected reports whether the server answered the MCP handshake. An
	// HTTP status after that comes from a server that speaks the configured
	// transport.
	connected() bool
}

// classify turns err, from net/http or the MCP SDK, into a ConnectError that
// is safe to print.
//
// ev tells what the HTTP layer saw for the request behind err: its non-2xx
// status and the first error that the layer raised on purpose. ev can be nil.
// If the HTTP layer blocked a request on purpose, that error decides the
// kind, even when the SDK flattened err into text. secrets are all the secret
// strings of the server entry: the header values, the credential parts of
// auth headers and the secrets of the URL user info, query and path (see
// Remote). classify removes them from any error text. short are the values
// shorter than discover.MinSecretBytes that the server can echo (configured
// env values, expanded values, argv pieces). classify removes them only where
// they stand as whole words (see replaceWords). short can be nil.
func classify(err error, srv discover.Server, ev transportEvents, secrets, short []string) *ConnectError {
	rawURL := srv.URL.Reveal()
	redacted := srv.URL.String()

	status := 0
	connected := false
	var blocked error
	if ev != nil {
		// Ask with the original err: stripURLError below can drop the wrapper
		// that links err to the record of its request.
		status, blocked = ev.stateFor(err)
		connected = ev.connected()
	}

	// *url.Error prints the raw URL in its Error text. Use the error inside it.
	cause := stripURLError(err)

	// An error that the HTTP layer raised on purpose is more reliable than
	// err, which the SDK may have flattened to text. A nil blocked (no ev, or
	// nothing blocked) is not a blocked error.
	if blocked = stripURLError(blocked); isBlockedErr(blocked) {
		// Keep a context error of err in the chain, so that errors.Is(err,
		// context.DeadlineExceeded) still works, as Remote promises.
		if ctxErr := contextErr(cause); ctxErr != nil {
			blocked = fmt.Errorf("%w: %w", blocked, ctxErr)
		}
		cause = blocked
	}

	ce := &ConnectError{
		Server: srv.Name,
		URL:    redacted,
	}
	ce.Kind, ce.Reason, ce.Status = classifyCause(cause, srv, status, connected, func(text string) string {
		return scrub(text, rawURL, redacted, secrets, short)
	})
	ce.err = safeCause(cause, rawURL, redacted, secrets, short)
	return ce
}

// blockedKinds maps each sentinel error that the HTTP layer raises on purpose
// to its kind and reason. isBlockedErr and classifyCause both read it, so a
// new sentinel needs one entry here and nothing else.
var blockedKinds = []struct {
	err    error
	kind   ConnectKind
	reason string
}{
	{errOtherOrigin, KindOrigin, "server tried to send a request to another origin; request refused"},
	{errCrossOriginRedirect, KindRedirect, "redirects to another origin are not followed; use the final URL in the config"},
	{errTooManyRedirects, KindRedirect, "too many redirects"},
	{errBodyTooLarge, KindTooLarge, "response too large"},
	{errJSONTooComplex, KindTooLarge, "response JSON too large: too deep, too many values or a too long string"},
	{errAddrRefused, KindNetwork, errAddrRefused.Error() + "; mcpmoat did not connect"},
}

// contextErr returns context.DeadlineExceeded or context.Canceled when err
// wraps it, and nil otherwise.
func contextErr(err error) error {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	case errors.Is(err, context.Canceled):
		return context.Canceled
	}
	return nil
}

// isBlockedErr reports whether err wraps one of the sentinel errors that the
// HTTP layer raises on purpose (blockedKinds). A nil err gives false.
func isBlockedErr(err error) bool {
	for _, b := range blockedKinds {
		if errors.Is(err, b.err) {
			return true
		}
	}
	return false
}

// classifyCause finds the kind, the reason and the HTTP status of cause. It
// is the decision table of classify. connected tells whether the session was
// connected (see transportEvents). scrubText removes secrets from error text.
func classifyCause(cause error, srv discover.Server, status int, connected bool, scrubText func(string) string) (kind ConnectKind, reason string, httpStatus int) {
	for _, b := range blockedKinds {
		if errors.Is(cause, b.err) {
			return b.kind, b.reason, 0
		}
	}
	switch {
	case errors.Is(cause, errInvalidProxy):
		return KindConfig, errInvalidProxy.Error(), 0
	case errors.Is(cause, context.DeadlineExceeded):
		return KindTimeout, "timed out", 0
	case errors.Is(cause, context.Canceled):
		return KindTimeout, "canceled", 0
	}

	if reason, ok := tlsReason(cause); ok {
		return KindTLS, reason, 0
	}

	if status != 0 {
		return KindHTTP, httpReason(srv, status, connected), status
	}

	var netErr net.Error
	if errors.As(cause, &netErr) {
		// Some timeouts do not wrap context.DeadlineExceeded, for example the
		// http.Transport TLS handshake timeout. They still are timeouts.
		if netErr.Timeout() {
			return KindTimeout, "timed out", 0
		}
		return KindNetwork, "network error: " + scrubText(cause.Error()), 0
	}
	return KindProtocol, scrubText(cause.Error()), 0
}

// tlsReason returns the reason text for a TLS error in err's chain, and
// whether there was one. It never suggests to skip certificate verification.
//
// errors.As needs a pointer to a variable of the type to look for. For an
// error type whose Error method has a value receiver, such as
// x509.UnknownAuthorityError, the type in the chain is the value type, so
// the target is a pointer to a value: &x509.UnknownAuthorityError{}. For an
// error type whose Error method has a pointer receiver, such as
// *tls.CertificateVerificationError, the type in the chain is the pointer
// type, so the target is a pointer to a pointer variable.
//
// The specific x509 cases come before the generic
// *tls.CertificateVerificationError, because that error wraps them.
func tlsReason(err error) (string, bool) {
	var unknownAuth x509.UnknownAuthorityError // value type
	if errors.As(err, &unknownAuth) {
		return "TLS certificate not trusted: signed by an unknown authority", true
	}

	var hostname x509.HostnameError // value type
	if errors.As(err, &hostname) {
		return "TLS certificate is not valid for this host", true
	}

	var invalid x509.CertificateInvalidError // value type
	if errors.As(err, &invalid) {
		if invalid.Reason == x509.Expired {
			return "TLS certificate expired or not yet valid", true
		}
		return "TLS certificate invalid", true
	}

	var verify *tls.CertificateVerificationError // pointer type
	if errors.As(err, &verify) {
		return "TLS certificate verification failed", true
	}

	var record tls.RecordHeaderError // value type
	if errors.As(err, &record) {
		return "TLS handshake failed: server did not answer with TLS", true
	}

	if errors.Is(err, http.ErrSchemeMismatch) {
		return "TLS handshake failed: server speaks plain HTTP; use an http:// URL", true
	}
	return "", false
}

// httpReason returns the reason text for a non-2xx HTTP status. The status
// text comes from the net/http table, not from the server. The hint about the
// legacy SSE transport appears only before the session connected: after
// that, the server has shown that it speaks streamable HTTP.
func httpReason(srv discover.Server, status int, connected bool) string {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		keys := "none"
		if names := sentHeaderNames(srv); len(names) > 0 {
			keys = strings.Join(names, ", ")
		}
		return fmt.Sprintf("server needs authentication (HTTP %d); headers sent: %s", status, keys)
	case http.StatusBadRequest, http.StatusNotFound, http.StatusMethodNotAllowed:
		if srv.Transport == discover.TransportHTTP && !connected {
			return fmt.Sprintf("HTTP %d; the server may use the legacy SSE transport; set type = sse", status)
		}
	}
	if text := http.StatusText(status); text != "" {
		return fmt.Sprintf("HTTP %d %s", status, text)
	}
	return fmt.Sprintf("HTTP %d", status)
}

// sentHeaderNames returns the names of the config headers that went to the
// server, for the reason text of an HTTP 401 or 403. It holds the names from
// sentHeaders. If the request carried a Basic Authorization header built from
// the URL user info, it ends with "Authorization (from URL user info)". It
// holds names only, never a value.
func sentHeaderNames(srv discover.Server) []string {
	names, basic := sentHeaders(srv)
	if basic {
		names = append(names, "Authorization (from URL user info)")
	}
	return names
}

// sentHeaders returns the keys of the config headers that went to the
// server, in the order of srv.Headers.Keys, and whether the request carried
// a Basic Authorization header built from the URL user info.
//
// Keys that differ only in case were sent as one header (see buildHeader),
// so names holds each header once, in the form of the first key. basic is
// true when the URL has user info and the config sets no Authorization
// header (see headerTransport.RoundTrip). In that case names leaves out an
// Authorization key with an empty value, because the Basic header replaced
// it. The result holds keys only, never a header value or a password.
func sentHeaders(srv discover.Server) (names []string, basic bool) {
	// Build the headers as the client did, so that the rules (the last of two
	// keys wins, an empty Authorization counts as absent) live in one place.
	// The callers run only after newHTTPClient accepted the headers, so
	// buildHeader does not fail here; on a failure, header stays nil.
	raw, _ := splitHeaders(srv.Headers)
	header, _ := buildHeader(raw, "")
	var user *url.Userinfo
	if u, err := url.Parse(srv.URL.Reveal()); err == nil {
		user = u.User
	}
	basic = sendsBasicAuth(header, user)

	// A map with an empty struct{} value is a set: struct{} uses no memory.
	seen := make(map[string]struct{})
	for _, name := range srv.Headers.Keys() {
		canonical := http.CanonicalHeaderKey(name)
		if _, dup := seen[canonical]; dup {
			continue
		}
		// With basic, the Basic header replaced the empty config value.
		if basic && canonical == "Authorization" {
			continue
		}
		seen[canonical] = struct{}{}
		names = append(names, name)
	}
	return names, basic
}

// stripURLError returns the error inside the first *url.Error in err's chain,
// or err if there is none. *url.Error.Error prints the raw URL, so its text
// must not be used. It repeats, in case url.Errors are nested.
func stripURLError(err error) error {
	for {
		var ue *url.Error
		if !errors.As(err, &ue) || ue.Err == nil {
			return err
		}
		err = ue.Err
	}
}

// safeCause returns cause if its text holds no secret, and a plain error with
// the scrubbed text otherwise. The plain error does not keep the chain, which
// is the price for text that is safe to print. A nil cause gives nil. secrets
// and short are the lists of scrub.
func safeCause(cause error, rawURL, redactedURL string, secrets, short []string) error {
	if cause == nil {
		return nil
	}
	text := cause.Error()
	replaced := replaceSecrets(text, rawURL, redactedURL, secrets, short)
	if replaced == text {
		return cause
	}
	return errors.New(cutWords(replaced, short))
}

// scrub removes secrets from text and shortens it, so that it is safe to
// put in a ConnectError. It replaces:
//
//   - rawURL, the URL as written in the config, with redactedURL;
//   - the raw URL without its query and fragment, with the redacted URL
//     without its query and fragment (net/http sometimes prints this
//     variant);
//   - the query of rawURL, after "?", and the user name and password in the
//     authority (in plain and in URL-escaped form), with discover.Mask;
//   - every path segment of rawURL that discover.RedactURL masks, after "/",
//     with discover.Mask;
//   - every non-empty string in secrets with discover.Mask, longest first,
//     wherever it stands;
//   - then every non-empty string in short with discover.Mask, but only where
//     it stands as a whole word (see replaceWords).
//
// For each secret it also replaces the form that %q prints (backslashes and
// quotes escaped). It then cuts the result to maxReasonRunes runes and adds
// "…" if it cut anything (see cutWords: the cut never leaves a value of short
// at the end as a whole word). The result can still hold text that the server
// controls; callers must escape it with internal/termsafe before they print
// it.
func scrub(text, rawURL, redactedURL string, secrets, short []string) string {
	return cutWords(replaceSecrets(text, rawURL, redactedURL, secrets, short), short)
}

// replaceSecrets does the replacements that scrub describes, without the
// cut.
func replaceSecrets(text, rawURL, redactedURL string, secrets, short []string) string {
	if rawURL != "" {
		text = replaceForms(text, rawURL, redactedURL)
		text = replaceURLParts(text, rawURL, redactedURL)
	}

	// Longest first: a value that is a substring of another value must not
	// leave pieces of the longer one behind. Header values are replaced
	// everywhere, even the short ones: a leak is worse than a garbled word.
	values := slices.DeleteFunc(slices.Clone(secrets), func(v string) bool { return v == "" })
	slices.SortFunc(values, func(a, b string) int { return len(b) - len(a) })
	for _, v := range values {
		text = replaceForms(text, v, discover.Mask)
	}
	// The short values last: a short value can be a part of a long one, and
	// the long one must go as a whole.
	return replaceWords(text, short)
}

// replaceWords replaces each value in short, and the form that %q prints for
// it (see quotedInner), with discover.Mask where it stands as a whole word.
// A match is a whole word when the byte before it and the byte after it are
// not word bytes (see isWordByte), or are the edge of text. An escape
// sequence such as \n or \x01 also counts as a boundary before a match (see
// endsWithEscape), so that "\n1234" in %q text loses the value 1234.
//
// Why whole words only: these values are shorter than
// discover.MinSecretBytes, and a short value such as "1" or "true" matches
// too much ordinary text. So a value stays when it is glued to a letter, a
// digit or "_" ("a1234", "1234x"). The cost is that a common word that is
// also a configured value is masked: with a value "1", "exit status 1" becomes
// "exit status ********".
//
// At each position the longest value wins, so "ab-c" goes as a whole and does
// not leave "-c" behind when "ab" is a value too. The checks read text as it
// was before this call, and a discover.Mask already in text is copied as it
// is: a value such as "*" must not mask the stars of a mask again and again.
// A text with no value in it comes back unchanged.
func replaceWords(text string, short []string) string {
	forms := wordForms(text, short)
	if len(forms) == 0 {
		return text
	}
	var b strings.Builder
	b.Grow(len(text))
	for i := 0; i < len(text); {
		if strings.HasPrefix(text[i:], discover.Mask) {
			b.WriteString(discover.Mask)
			i += len(discover.Mask)
			continue
		}
		if n := wordAt(text, i, forms); n > 0 {
			b.WriteString(discover.Mask)
			i += n
			continue
		}
		b.WriteByte(text[i])
		i++
	}
	return b.String()
}

// wordForms returns the forms of the values in short that occur in text: each
// non-empty value and its %q form (see quotedInner), each one time, longest
// first. Values that do not occur are left out, so a text with none of them
// costs one search for each form only.
//
// The result holds raw values. Never print, log or encode them.
func wordForms(text string, short []string) []string {
	var forms []string
	for _, v := range short {
		if v == "" {
			continue
		}
		for _, f := range []string{v, quotedInner(v)} {
			if strings.Contains(text, f) {
				forms = append(forms, f)
			}
		}
	}
	// Longest first, then by bytes, so the order does not depend on the
	// input order. Equal forms are next to each other after the sort, and
	// slices.Compact removes the copies.
	slices.SortFunc(forms, func(a, b string) int {
		if len(a) != len(b) {
			return len(b) - len(a)
		}
		return strings.Compare(a, b)
	})
	return slices.Compact(forms)
}

// wordAt returns the length of the first form in forms that starts at text[i]
// as a whole word (see replaceWords), or 0 if there is none. forms is sorted
// longest first, so the first match is the longest one.
func wordAt(text string, i int, forms []string) int {
	for _, f := range forms {
		if !strings.HasPrefix(text[i:], f) {
			continue
		}
		// All forms start at the same i, so one failed start check ends the
		// search.
		if !wordStart(text, i) {
			return 0
		}
		end := i + len(f)
		if end == len(text) || !isWordByte(text[end]) {
			return len(f)
		}
	}
	return 0
}

// wordStart reports whether a word can start at text[i]: i is the start of
// text, the byte before is not a word byte, or text[:i] ends with an escape
// sequence (see endsWithEscape).
func wordStart(text string, i int) bool {
	return i == 0 || !isWordByte(text[i-1]) || endsWithEscape(text[:i])
}

// isWordByte reports whether c is an ASCII letter, an ASCII digit or "_".
// Every other byte, also each byte of a multi-byte UTF-8 rune, ends a word.
func isWordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}

// endsWithEscape reports whether s ends with an escape sequence of the kind
// that strconv.Quote prints: \a, \b, \f, \n, \r, \t, \v, \xHH, \uHHHH or
// \UHHHHHHHH. The backslash must not be escaped itself: in `\\n` the "n" is a
// plain letter after an escaped backslash. An odd number of backslashes in a
// row before the escape letter means that the last one starts an escape.
func endsWithEscape(s string) bool {
	// n is the length of the escape after its backslash.
	for _, n := range []int{1, 3, 5, 9} {
		if len(s) < n+1 || !isEscapeBody(s[len(s)-n:]) {
			continue
		}
		before := s[:len(s)-n]
		backslashes := len(before) - len(strings.TrimRight(before, `\`))
		if backslashes%2 == 1 {
			return true
		}
	}
	return false
}

// isEscapeBody reports whether body is the part of an escape sequence after
// the backslash: one letter of "abfnrtv", or "x", "u" or "U" followed by 2, 4
// or 8 hex digits.
func isEscapeBody(body string) bool {
	if len(body) == 1 {
		return strings.IndexByte("abfnrtv", body[0]) >= 0
	}
	// size is the length of body for its first letter; 0 for any other
	// letter, which no body of 3, 5 or 9 bytes matches.
	size := 0
	switch body[0] {
	case 'x':
		size = 3
	case 'u':
		size = 5
	case 'U':
		size = 9
	}
	if len(body) != size {
		return false
	}
	for i := 1; i < len(body); i++ {
		if !isHexByte(body[i]) {
			return false
		}
	}
	return true
}

// isHexByte reports whether c is a hex digit, in either letter case.
func isHexByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// cutWords cuts text to maxReasonRunes runes and adds "…" if it cut anything,
// like truncate. A cut can end the text right after a value of short that a
// word byte followed: "PIN 1234x" cut after "1234" shows "PIN 1234…", and the
// value now looks like a whole word that replaceWords did not mask. So when
// the kept text ends with a value of short (or its %q form) that starts as a
// whole word, cutWords cuts that value off too, and checks again. Each round
// removes at least one byte, so the loop ends. text must have been through
// replaceWords with the same short.
func cutWords(text string, short []string) string {
	runes := []rune(text)
	if len(runes) <= maxReasonRunes {
		return text
	}
	kept := string(runes[:maxReasonRunes])
	forms := wordForms(kept, short)
	for {
		n := trailingWord(kept, forms)
		if n == 0 {
			break
		}
		kept = kept[:len(kept)-n]
	}
	return kept + "…"
}

// trailingWord returns the length of the longest form in forms that ends
// text and starts as a whole word (see wordStart), or 0 if there is none.
// forms is sorted longest first.
func trailingWord(text string, forms []string) int {
	for _, f := range forms {
		if strings.HasSuffix(text, f) && wordStart(text, len(text)-len(f)) {
			return len(f)
		}
	}
	return 0
}

// replaceForms replaces old with replacement in text. It does the same for
// the form that %q prints for both, with the outer quotes removed. That form
// differs when the text holds a backslash, a quote or a control character.
func replaceForms(text, old, replacement string) string {
	if old == "" {
		return text
	}
	text = strings.ReplaceAll(text, old, replacement)
	if quotedOld := quotedInner(old); quotedOld != old {
		text = strings.ReplaceAll(text, quotedOld, quotedInner(replacement))
	}
	return text
}

// quotedInner returns s as strconv.Quote prints it, without the outer quotes.
func quotedInner(s string) string {
	q := strconv.Quote(s)
	return q[1 : len(q)-1]
}

// replaceURLParts replaces the variants of rawURL that net/http can print:
// the URL without its query, the query alone and the user info. An
// unparsable rawURL is skipped.
func replaceURLParts(text, rawURL, redactedURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return text
	}

	query := u.RawQuery
	userinfo := u.User
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	u.RawFragment = ""
	u.User = nil // ignore the user info here; it is replaced below
	base := u.String()

	// The redacted URL without its query and fragment, like base. If
	// RedactURL gave Mask for the whole URL, there is nothing safe to show but
	// Mask.
	redactedBase := urlBase(redactedURL)

	// Only "?"+query is replaced, not the bare query: a short query such as
	// "a" must not garble other words.
	if query != "" {
		text = replaceForms(text, "?"+query, "?"+discover.Mask)
	}
	// The base has no user info, so it matches only when the text has no
	// user info either.
	if base != "" {
		text = replaceForms(text, base, redactedBase)
	}
	// A secret path segment can also stand in another URL on the same origin,
	// for example the message endpoint that a legacy SSE server announces
	// under the same path prefix. Replace each segment that RedactURL masks
	// where it follows a "/".
	for _, seg := range discover.SecretPathSegments(rawURL) {
		text = replaceForms(text, "/"+seg, "/"+discover.Mask)
	}
	return replaceUserinfo(text, rawURL, userinfo)
}

// replaceUserinfo replaces the user name and the password of a URL with
// discover.Mask. They are matched only inside the authority, as
// "//name@", "//name:" and ":password@", so that a short name does not
// garble other words. Go prints a URL without its password as
// "scheme://name@host" and escapes the name, so the escaped form is replaced
// too, and so is the user info as written in rawURL.
func replaceUserinfo(text, rawURL string, userinfo *url.Userinfo) string {
	rawInfo := discover.RawUserinfo(rawURL)
	if userinfo == nil && rawInfo == "" {
		return text
	}

	var names, passwords []string
	if userinfo != nil {
		name := userinfo.Username()
		password, hasPassword := userinfo.Password()
		names = append(names, name, url.User(name).String())
		if hasPassword {
			escaped := url.UserPassword(name, password).String()
			_, escapedPassword, _ := strings.Cut(escaped, ":")
			passwords = append(passwords, password, escapedPassword)
		}
	}
	rawName, rawPassword, _ := strings.Cut(rawInfo, ":")
	names = append(names, rawName)
	passwords = append(passwords, rawPassword)

	// The whole user info first: it holds the name and the password.
	if rawInfo != "" {
		text = replaceForms(text, "//"+rawInfo+"@", "//"+discover.Mask+"@")
	}
	for _, name := range names {
		if name == "" {
			continue
		}
		text = replaceForms(text, "//"+name+"@", "//"+discover.Mask+"@")
		text = replaceForms(text, "//"+name+":", "//"+discover.Mask+":")
	}
	for _, password := range passwords {
		if password == "" {
			continue
		}
		text = replaceForms(text, ":"+password+"@", ":"+discover.Mask+"@")
	}
	return text
}

// truncate cuts text to maxReasonRunes runes and adds "…" if it cut
// anything. It counts runes, so it never cuts inside a UTF-8 sequence.
func truncate(text string) string {
	runes := []rune(text)
	if len(runes) <= maxReasonRunes {
		return text
	}
	return string(runes[:maxReasonRunes]) + "…"
}

// showDiscoveredURL makes ce show the URL as discovered, not the expanded one,
// for a remote server. Remote built ce from the expanded server, so its URL,
// its Reason and its cause can hold the redacted expanded URL, and that URL can
// show the values of variables: a host, a port or a path segment that the
// redaction keeps, and values shorter than discover.MinSecretBytes that no
// scrub removes. A port in a dial error that prints the resolved IP:port stays:
// a port is not a secret. showDiscoveredURL sets ce.URL to the discovered URL,
// and replaces the expanded URL in Reason and in the text of the cause with it,
// also in the form without the query and the fragment, the same forms that
// scrub replaces. Then it replaces the expanded host (host:port, then the host
// name alone) with the discovered one, because a DNS or dial error names the
// host without the URL. A host can be a short word, so this can garble other
// text of the error: a leak is worse than a garbled word. A cause whose text
// changes becomes a new error with that text (see withText), which still
// matches the context error and the sentinel of the old cause, so
// errors.Is(err, context.DeadlineExceeded) still works. When the two URLs are
// the same, only ce.URL is set.
//
// short are the short expanded values that classify removed as whole words
// (see replaceWords). classify ran first, so a short value in the expanded
// URL can already be a mask in the text: "localhost:8080" with the value 8080
// stands as "localhost:********". So showDiscoveredURL also replaces each
// expanded form after replaceWords with short. Then it removes short as whole
// words again, because the new URL text can change the bytes next to a value,
// and it cuts with cutWords, so that the new cut does not leave a value at the
// end as a whole word.
func showDiscoveredURL(ce *ConnectError, expanded, discovered discover.URL, short []string) {
	to := discovered.String()
	ce.URL = to
	from := expanded.String()
	if from == to {
		return
	}
	pairs := [][2]string{{from, to}, {urlBase(from), urlBase(to)}}
	if expandedURL, err := url.Parse(expanded.Reveal()); err == nil {
		// A placeholder in the host can make the discovered URL fail to
		// parse. Then Mask stands for its host.
		toHost, toName := discover.Mask, discover.Mask
		if discoveredURL, err := url.Parse(discovered.Reveal()); err == nil {
			toHost, toName = discoveredURL.Host, discoveredURL.Hostname()
		}
		if expandedURL.Host != toHost {
			pairs = append(pairs,
				[2]string{expandedURL.Host, toHost},
				[2]string{expandedURL.Hostname(), toName})
		}
	}
	// The forms as classify left them, after the forms as they are. The
	// range runs over the pairs above only: append does not change the
	// length that range read at the start. A form that is masks only, such
	// as the host "db" with the value "db", is left out: it would replace
	// the mask of every other secret in the text.
	for _, p := range pairs {
		masked := replaceWords(p[0], short)
		if masked != p[0] && strings.ReplaceAll(masked, discover.Mask, "") != "" {
			pairs = append(pairs, [2]string{masked, p[1]})
		}
	}
	replace := func(text string) string {
		for _, p := range pairs {
			text = replaceForms(text, p[0], p[1])
		}
		return replaceWords(text, short)
	}
	ce.Reason = cutWords(replace(ce.Reason), short)
	if ce.err != nil {
		text := ce.err.Error()
		if replaced := replace(text); replaced != text {
			ce.err = withText(ce.err, cutWords(replaced, short))
		}
	}
}

// textError is an error with a fixed text that matches, with errors.Is, the
// errors in matches. It wraps nothing else, so no text of the old error
// stays in the chain.
type textError struct {
	text    string
	matches []error
}

func (e *textError) Error() string { return e.text }

// Unwrap returns the errors that e matches. errors.Is and errors.As walk
// them.
func (e *textError) Unwrap() []error { return e.matches }

// withText returns an error with text that still matches what callers check
// in err with errors.Is: the context error (see contextErr), and the
// sentinel of blockedKinds or errInvalidProxy that err wraps. These are
// fixed sentinels with no config text.
func withText(err error, text string) error {
	var matches []error
	for _, b := range blockedKinds {
		if errors.Is(err, b.err) {
			matches = append(matches, b.err)
			break
		}
	}
	if errors.Is(err, errInvalidProxy) {
		matches = append(matches, errInvalidProxy)
	}
	if ctxErr := contextErr(err); ctxErr != nil {
		matches = append(matches, ctxErr)
	}
	return &textError{text: text, matches: matches}
}

// urlBase returns u without its fragment and its query.
func urlBase(u string) string {
	u, _, _ = strings.Cut(u, "#")
	u, _, _ = strings.Cut(u, "?")
	return u
}
