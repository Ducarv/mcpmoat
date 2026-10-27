package inspect

import (
	"slices"
	"strings"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// This file holds the whole-word scrub of error text: the helpers that
// remove the short values (shorter than discover.MinSecretBytes) only where
// they stand as whole words, and the cut that keeps that rule at the end of
// the text. scrub in errors.go calls them.

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
// But a match that starts inside such a Mask and goes on past its end is a
// value that the copy would cut in two (see maskedWordAt), so it goes too. A
// text with no value in it comes back unchanged.
//
// The text can be large (a JSON-RPC error message of some MiB), and the
// server controls it, so the cost must not grow with the number of values
// times the length of the text (NFR-03). replaceWords reads the text one
// time. It does not search the text for each form first, as wordForms does:
// a form that is not in the text never matches, so the result is the same.
// At each position, a walk in a prefix tree of the forms finds the forms
// that start there (see wordTrie), in at most as many steps as the longest
// form has bytes. The loop copies the text between two matches in one write.
func replaceWords(text string, short []string) string {
	forms := shortForms(short)
	if len(forms) == 0 {
		return text
	}
	trie := newWordTrie(forms)

	var b strings.Builder
	// text[:copied] is in b already.
	copied := 0
	for i := 0; i < len(text); {
		// start and n are the start and the length of a match, if any.
		var start, n int
		if text[i] == discover.Mask[0] && strings.HasPrefix(text[i:], discover.Mask) {
			start, n = maskedWordAt(text, i, trie)
			if n == 0 {
				// Keep the Mask as it is: it is copied with the next write.
				i += len(discover.Mask)
				continue
			}
		} else {
			start, n = i, wordAt(text, i, trie)
			if n == 0 {
				i++
				continue
			}
		}
		if copied == 0 {
			b.Grow(len(text))
		}
		// Copy the text before the match (for a match inside a Mask, also
		// the stars before it), then mask the match.
		b.WriteString(text[copied:start])
		b.WriteString(discover.Mask)
		i = start + n
		copied = i
	}
	if copied == 0 {
		// No match: give back text itself, with no copy.
		return text
	}
	b.WriteString(text[copied:])
	return b.String()
}

// wordForms returns the forms of the values in short that occur in text (see
// shortForms), in the order of shortForms. Forms that do not occur are left
// out. cutWords calls it on a cut text of some hundred bytes, so the search
// for each form is cheap there.
//
// The result holds raw values. Never print, log or encode them.
func wordForms(text string, short []string) []string {
	return slices.DeleteFunc(shortForms(short), func(f string) bool {
		return !strings.Contains(text, f)
	})
}

// shortForms returns the forms of the values in short: each non-empty value
// and its %q form (see quotedInner), each one time, longest first.
//
// The result holds raw values. Never print, log or encode them.
func shortForms(short []string) []string {
	var forms []string
	for _, v := range short {
		if v == "" {
			continue
		}
		forms = append(forms, v)
		if q := quotedInner(v); q != v {
			forms = append(forms, q)
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

// wordTrie is a node of a prefix tree (a trie) of the forms of the short
// values (see shortForms). The root stands for the empty prefix, and the
// child for the byte c of a node stands for the prefix of the node plus c.
// A walk from the root along the bytes of a text finds every form that
// starts there, shortest first, and it ends at the first byte that no form
// has at that place. So the walk at one position of the text takes at most
// as many steps as the longest form has bytes, however many forms there are.
//
// The nodes hold raw values in their keys. Never print, log or encode them.
type wordTrie struct {
	// next maps a byte to the child node for it. It is nil for a node
	// with no child.
	next map[byte]*wordTrie
	// end tells whether a form ends at this node.
	end bool
}

// newWordTrie returns the root of the prefix tree of forms. Equal forms give
// one path. An empty form would mark the root, so the callers pass no empty
// form (shortForms removes them).
func newWordTrie(forms []string) *wordTrie {
	root := &wordTrie{}
	for _, f := range forms {
		n := root
		for i := 0; i < len(f); i++ {
			child := n.next[f[i]]
			if child == nil {
				if n.next == nil {
					n.next = make(map[byte]*wordTrie)
				}
				child = &wordTrie{}
				n.next[f[i]] = child
			}
			n = child
		}
		n.end = true
	}
	return root
}

// wordAt returns the length of the longest form that starts at text[i] as a
// whole word (see replaceWords), or 0 if there is none. trie is the result of
// newWordTrie.
//
// A whole word needs a boundary at both ends. The boundary at the end
// depends on the length of the form, so the walk keeps the longest form with
// a boundary after it. The boundary at the start (see wordStart) is the same
// for every form at i, so wordAt checks it one time, at the end.
func wordAt(text string, i int, trie *wordTrie) int {
	best := 0
	n := trie
	for j := i; j < len(text); j++ {
		// A read from a nil map gives the zero value, here a nil node, so a
		// node with no child needs no check of its own.
		n = n.next[text[j]]
		if n == nil {
			break
		}
		if n.end && (j+1 == len(text) || !isWordByte(text[j+1])) {
			best = j + 1 - i
		}
	}
	if best == 0 || !wordStart(text, i) {
		return 0
	}
	return best
}

// maskedWordAt looks for a whole-word match (see wordAt) that starts inside
// the discover.Mask at text[i] and ends after it. It returns the start and
// the length n of the first such match, or n = 0 if there is none.
//
// A value that starts with "*" needs this. For the value "*1234" and the text
// "*******" + "*1234" (the same bytes as discover.Mask + "1234"), a copy of
// the Mask as a whole would take the first "*" of the value and leave "1234".
// A match that ends inside the Mask is only stars (a value such as "*"), so
// the copy of the Mask keeps the rule that a Mask is not masked again.
func maskedWordAt(text string, i int, trie *wordTrie) (start, n int) {
	maskEnd := i + len(discover.Mask)
	for j := i; j < maskEnd; j++ {
		if m := wordAt(text, j, trie); j+m > maskEnd {
			return j, m
		}
	}
	return 0, 0
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

// cutWords cuts text to maxReasonRunes runes and adds "…" if it cut anything.
// It counts runes, so it never cuts inside a UTF-8 sequence. A cut can end
// the text right after a value of short that a word byte followed: "PIN
// 1234x" cut after "1234" shows "PIN 1234…", and the value now looks like a
// whole word that replaceWords did not mask. So when the kept text ends with
// a value of short (or its %q form) that starts as a whole word, cutWords
// cuts that value off too, and checks again. Each round removes at least one
// byte, so the loop ends. text must have been through replaceWords with the
// same short. With a nil short, cutWords only cuts.
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
