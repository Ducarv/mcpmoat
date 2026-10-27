package main

import (
	"cmp"
	"slices"
	"strconv"
	"strings"
)

// This file hides secrets in the error text about command-line arguments. A
// base URL can hold a user name and a password (--llm-base-url, FR-17), and the
// flag package puts the whole argument in some of its errors. Every command
// builds the argHider of its arguments (see newArgHider) and sends the text of
// such an error, and each argument of the "unexpected arguments" list (see
// rejectArgs), through its errorText method before it escapes the text for the
// terminal. argErrorText does the same in one call.

// hiddenArgText replaces the value of a secret flag in an error message.
const hiddenArgText = "(hidden)"

// argErrorText returns text, an error message about args, with the secrets of
// args hidden. It hides each value that args gives to --llm-base-url (see
// newArgHider), also a value without a scheme such as "user:pass@host". Then it
// hides the user info of every URL in the text (see hideUserinfo), so a URL
// with a password in any other place, for example as the value of another
// flag, does not show either. A caller that already has the hider of args
// (newArgHider(args, flagLLMBaseURL)) calls its errorText method instead.
func argErrorText(args []string, text string) string {
	return newArgHider(args, flagLLMBaseURL).errorText(text)
}

// hideUserinfo returns s with the user info of each URL in s replaced by
// hiddenArgText: "https://user:pass@host" becomes "https://(hidden)@host". It
// is a generic scrub, so it needs no rule for each flag.
//
// A URL starts at "://". The text before it is the scheme, with any case, and
// it is not checked: that only hides more. The authority of the URL runs from
// "://" to the first '/', '?' or '#', or to the end of s (RFC 3986). When the
// authority holds an '@', the user info is the text before the last '@' (the
// same rule as net/url), and hideUserinfo replaces it. So:
//   - "https://TOKEN@host" (a user name and no password) is hidden too.
//   - "https://host/a@b" and "https://host?q=a@b" do not change: the '@' is
//     in the path or the query.
//   - "https://@host" does not change: the user info is empty.
//   - The %q form of a URL, as in `invalid value "https://u:p@host"` or
//     `\"https://u\"p@host\"`, is hidden too: quotes, backslashes and escapes
//     do not end the authority.
//
// Only '/', '?' and '#' end the authority, not a space or a quote. When an
// '@' comes later in the text with none of them between, hideUserinfo hides
// the text up to that '@', also text that is not user info. That fails safe.
// A raw '/', '?' or '#' in a password ends the authority early, so the text
// after it can show. A URL must percent-encode them in the user info.
//
// It uses no regular expression. The loop reads each byte of s at most three
// times, so the time is linear in the length of s, also for a long argument.
func hideUserinfo(s string) string {
	const sep = "://"
	var b strings.Builder
	rest := s // the part of s that is not yet in b
	changed := false
	for {
		i := strings.Index(rest, sep)
		if i < 0 {
			break
		}
		start := i + len(sep) // the first byte of the authority
		end := len(rest)
		if j := strings.IndexAny(rest[start:], "/?#"); j >= 0 {
			end = start + j
		}
		b.WriteString(rest[:start])
		// at is 0 for an empty user info, and -1 when there is no '@'.
		if at := strings.LastIndexByte(rest[start:end], '@'); at > 0 {
			b.WriteString(hiddenArgText)
			rest = rest[start+at:] // starts with the '@'
			changed = true
		} else {
			rest = rest[start:]
		}
	}
	if !changed {
		return s
	}
	b.WriteString(rest)
	return b.String()
}

// argHider removes the values of one secret flag from the error text of the
// argument checks. The zero argHider changes nothing.
type argHider struct {
	r *strings.Replacer // nil when the args give no value
}

// newArgHider returns an argHider for the values that args gives to the flag
// name. It looks for the text "-name" in each argument, with one dash or more
// before name:
//   - "-name=" anywhere in the argument: the rest of the argument after each
//     "-name=" is a value. So "--name=value" counts, and so does the value of
//     another flag, as in "--timeout=--name=value", which the flag package
//     quotes whole in its error.
//   - "-name" at the end of the argument: the next argument is a value. So a
//     bare "--name" counts, and so does "--timeout=--name".
//
// It looks at every argument, also after "--" and after a flag that took
// "--name" as its own value, so it can find more values than Parse uses: that
// only hides more. A short value, for example one letter, also hides that
// text in the other words of the message: that is on purpose, because it
// fails safe.
func newArgHider(args []string, name string) argHider {
	token := "-" + name
	var values []string
	for i, arg := range args {
		// Each "-name=" gives a value. A later value is the end of an
		// earlier one. It is kept for a text that shows only that end.
		for rest := arg; ; {
			_, v, ok := strings.Cut(rest, token+"=")
			if !ok {
				break
			}
			values = append(values, v)
			rest = v
		}
		if strings.HasSuffix(arg, token) && i+1 < len(args) {
			values = append(values, args[i+1])
		}
	}
	// The flag package quotes a value with %q in `invalid value "..."`, so a
	// value with a quote, a backslash or a control rune shows escaped. Hide
	// that form too.
	var olds []string
	for _, v := range values {
		if v == "" {
			continue
		}
		olds = append(olds, v)
		if q := strconv.Quote(v); q[1:len(q)-1] != v {
			olds = append(olds, q[1:len(q)-1])
		}
	}
	if len(olds) == 0 {
		return argHider{}
	}
	// strings.Replacer tries the old strings in the order given, so the
	// longest goes first: a value that holds another value is hidden whole.
	// The text order of equal lengths puts duplicates side by side for
	// slices.Compact.
	slices.SortFunc(olds, func(a, b string) int {
		return cmp.Or(cmp.Compare(len(b), len(a)), strings.Compare(a, b))
	})
	olds = slices.Compact(olds)
	pairs := make([]string, 0, 2*len(olds))
	for _, o := range olds {
		pairs = append(pairs, o, hiddenArgText)
	}
	return argHider{r: strings.NewReplacer(pairs...)}
}

// hide returns s with every value of the secret flag replaced by
// hiddenArgText. The rest of s stays as it is.
func (h argHider) hide(s string) string {
	if h.r == nil {
		return s
	}
	return h.r.Replace(s)
}

// errorText returns text, an error message about the args of h, with the
// values of the secret flag hidden (see hide) and then the user info of every
// URL in the text hidden (see hideUserinfo). argErrorText and rejectArgs use
// it.
func (h argHider) errorText(text string) string {
	return hideUserinfo(h.hide(text))
}
