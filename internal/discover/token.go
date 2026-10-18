package discover

import "strings"

// Length thresholds for looksLikeCredential. The RedactURL doc comment
// states these numbers (20, 32 and 36), so change it with them.
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
	if len(s) >= minTokenLen || isUUID(s) {
		return true
	}
	// tokenPrefixes are the starts of well-known API token formats, in
	// lower case, so the match does not depend on case. The RedactURL doc
	// names only some of them as examples, so it does not need an update
	// when this list changes.
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
