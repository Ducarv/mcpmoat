package discover

import "strings"

// Length thresholds for looksLikeCredential. The RedactURL doc comment
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

// looksLikeCredential reports whether s (a path segment, a query key or an
// argument) looks like a token. The RedactURL doc comment lists the rules
// and their limits.
func looksLikeCredential(s string) bool {
	if len(s) >= minTokenLen || isUUID(s) || hasTokenPrefix(s) {
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

// hasTokenPrefix reports whether s starts with the prefix of a well-known
// API token format, such as "ghp_" or "sk-", in any case, and has more text
// after the prefix.
func hasTokenPrefix(s string) bool {
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
