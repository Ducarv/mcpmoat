package discover

import "strings"

// Length thresholds for LooksLikeCredential. The RedactURL doc comment
// refers to these constants by name, not by value, so a change here needs
// no change there.
const (
	// minMixedTokenLen is the shortest text with letters and digits that
	// counts as a token. Shorter mixed text is often a normal name, such as
	// "v1" or "2024-11-05".
	minMixedTokenLen = 20
	// minTokenLen is the shortest text that counts as a token with no other
	// sign. Readable path segments and query keys are rarely this long.
	minTokenLen = 32
	// uuidLen is the length of a UUID in its 8-4-4-4-12 text form.
	uuidLen = 36
)

// LooksLikeCredential reports whether s (a path segment, a query key, an
// argument or a config value) looks like a token: it starts with a known
// token prefix (see HasTokenPrefix), it is a UUID, it has minMixedTokenLen
// or more bytes with at least one ASCII letter and one digit, or it has
// minTokenLen or more bytes. The RedactURL doc comment lists the rules and
// their limits.
//
// The length rule does not look at the bytes, so a long text with spaces
// counts too. A caller that checks free text, such as an env value, can
// split it into words first. It never prints or stores s. It is exported so
// that the redaction and the credential checks of internal/inspect
// (Result.Credentials) agree on what looks like a token.
func LooksLikeCredential(s string) bool {
	if len(s) >= minTokenLen || isUUID(s) || HasTokenPrefix(s) {
		return true
	}
	if len(s) < minMixedTokenLen {
		return false
	}
	hasLetter, hasDigit := false, false
	for i := range len(s) {
		hasLetter = hasLetter || isLetter(s[i])
		hasDigit = hasDigit || isDigit(s[i])
	}
	return hasLetter && hasDigit
}

// TokenLike reports whether s, or one of its words (the parts between
// spaces), looks like a token: the word looks like a token by the rules of
// LooksLikeCredential, or a piece of it after ".", "@", ":", "+" or "~"
// starts with a known token prefix (see HasTokenPrefix). A credential has no
// space, so free text is checked word by word, and a long sentence does not
// count by its length alone. "production" and "application/json" are not
// token-like.
//
// It is the same rule that ArgCredentials uses. It is exported so that the
// credential checks of internal/inspect (Result.Credentials) read env
// values, header values and the values of expanded variables in the same
// way. It never prints or stores s.
func TokenLike(s string) bool {
	return tokenLike(s)
}

// IsAuthScheme reports whether word is the scheme of an Authorization
// header ("Bearer", "Basic", "Token", "Digest" and similar, in any case) or a
// secret-like name (see IsSecretName), such as "ApiKey". The text after such
// a scheme is a credential. Any other word is no scheme: "My" in "My
// Documents" is not.
//
// It is the same rule that ArgCredentials uses. It is exported so that the
// credential checks of internal/inspect (Result.Credentials) read a header
// value in the same way. It never prints or stores word.
func IsAuthScheme(word string) bool {
	return isAuthScheme(word)
}

// HasTokenPrefix reports whether s starts with the prefix of a well-known
// API token format, such as "ghp_" or "sk-", in any case, and has more text
// after the prefix. It does not look at the rest of s, so a match is a strong
// hint, not proof. It never prints or stores s. It is exported so that the
// redaction and the config checks (threat T4) agree on what looks like a
// secret.
func HasTokenPrefix(s string) bool {
	// tokenPrefixes are in lower case, so the match does not depend on case.
	// The RedactURL and RedactArgs docs name only some of them as examples,
	// so they do not need an update when this list changes.
	tokenPrefixes := [...]string{
		"sk-", "sk_", "pk_", "rk_",
		"ghp_", "gho_", "ghu_", "ghs_", "github_pat_",
		"glpat-",
		"xox",  // Slack
		"akia", // AWS access key ID
		"aiza", // Google API key
		"eyj",  // JWT: base64 of `{"`
	}
	lower := strings.ToLower(s)
	for _, p := range tokenPrefixes {
		if len(s) > len(p) && strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

// isUUID reports whether s has the 8-4-4-4-12 form of a UUID, with hex
// digits in any case.
func isUUID(s string) bool {
	if len(s) != uuidLen {
		return false
	}
	for i := range len(s) {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !isHexDigit(c) {
				return false
			}
		}
	}
	return true
}
