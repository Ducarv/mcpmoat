package inspect

import (
	"cmp"
	"slices"
	"strings"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// resultSecrets returns the values in lists as discover.Secret values, for
// Result.Secrets. It keeps only the values of at least discover.MinSecretBytes
// bytes, each one time.
//
// The scrub of error text (see scrub) also removes shorter header values and
// a short URL password. Result.Secrets does not hold them: a consumer removes
// the values from ordinary text, such as tool descriptions, and a short value
// is too likely to match ordinary words ("1", "true", "json"). So the filter
// applies here only, and the lists of the error scrub stay as they are.
//
// The result is sorted longest first, then by value. The sort makes the
// output stable: it does not depend on the order of a map. The consumer in
// package llm does not need that order (redactWindow marks bytes), and its
// secretValues removes duplicates again. It is nil when no value is long
// enough.
//
// The sort and the duplicate check compare the raw values in memory only.
// Never print, log or encode them.
func resultSecrets(lists ...[]string) []discover.Secret {
	var values []string
	for _, list := range lists {
		for _, v := range list {
			if len(v) >= discover.MinSecretBytes {
				values = append(values, v)
			}
		}
	}
	slices.SortFunc(values, func(a, b string) int {
		return cmp.Or(cmp.Compare(len(b), len(a)), strings.Compare(a, b))
	})
	// Equal values are next to each other after the sort.
	values = slices.Compact(values)

	if len(values) == 0 {
		return nil
	}
	secrets := make([]discover.Secret, len(values))
	for i, v := range values {
		secrets[i] = discover.NewSecret(v)
	}
	return secrets
}

// resultCredentials returns the values of secrets that are also in one of
// lists, for Result.Credentials. secrets is the result of resultSecrets, and
// lists hold the values that the credential checks found (see isCredential,
// envCredentials, argCredentials, headerCredentials, urlCredentials and
// valueCredentials).
//
// Credentials is a subset of Secrets by construction: the function only
// drops values from secrets, so it cannot add a value that Secrets does not
// hold. It keeps the order of secrets (longest first, then by value) and
// adds no duplicate, because secrets has none. A value of lists that is not
// in secrets is dropped: it is shorter than discover.MinSecretBytes, or it is
// not a value that the consumer removes from the Result text anyway. It is
// nil when no value is a credential.
//
// The set compares the raw values in memory only. Never print, log or encode
// them.
func resultCredentials(secrets []discover.Secret, lists ...[]string) []discover.Secret {
	if len(secrets) == 0 {
		return nil
	}
	// A map with empty struct values is the usual Go set: struct{} takes no
	// memory, and only the keys matter.
	found := make(map[string]struct{})
	for _, list := range lists {
		for _, v := range list {
			found[v] = struct{}{}
		}
	}
	var credentials []discover.Secret
	for _, s := range secrets {
		if _, ok := found[s.Reveal()]; ok {
			credentials = append(credentials, s)
		}
	}
	return credentials
}

// isCredential reports whether value, the value of the env key or of the
// variable called name, is a credential for Result.Credentials: name is
// secret-like (discover.IsSecretName, as in "API_KEY"), or value looks like a
// credential by itself (see looksLikeCredential). name can be "" when only
// the value is known. So "NODE_ENV=production" is no credential, and
// "API_KEY=production" is one.
//
// It never prints or stores name or value.
func isCredential(name, value string) bool {
	return discover.IsSecretName(name) || looksLikeCredential(value)
}

// looksLikeCredential reports whether value, a config value with no name to
// go by, looks like a credential: a word of it looks like a token
// (discover.TokenLike), or discover.ArgCredentials finds a credential in it
// when it reads value as one argument. The second check finds a credential
// inside a longer value, such as the password of "postgres://u:pw@h/db", the
// token of "Bearer x" or the value of "password=x" in a connection string.
// Plain words, such as "production" or "application/json", give false.
//
// It never prints or stores value.
func looksLikeCredential(value string) bool {
	return discover.TokenLike(value) || len(discover.ArgCredentials([]string{value})) > 0
}

// valueCredentials returns the credentials inside value, one config value
// (an env value, the value of an expanded variable or a header value): the
// pieces that discover.ArgCredentials finds when it reads value as one
// argument, such as the password of "postgres://u:pw@h/db" or the token of
// "Bearer x". A server can echo such a piece alone, and the lists that hold
// the whole value do not match the piece alone. So the callers add the
// pieces to the lists of the whole value, as argCredentials and argSecrets do
// for the argv.
//
// long holds the pieces of at least discover.MinSecretBytes bytes, for
// Result.Secrets, for Result.Credentials and for the error scrub. short holds
// the shorter pieces, for the whole-word scrub of error text only (see
// replaceWords), as the short list of argSecrets. Each piece is a credential,
// so the caller can add long to both Result lists. A value with no
// credential in it (looksLikeCredential is false), such as "production" or
// "application/json", gives two nil lists.
//
// Each piece is in the lists one time, and value itself is not in them: the
// callers put the whole value in their lists already. When
// discover.ArgCredentials returns value itself, looksLikeCredential is true,
// so the callers also count the whole value as a credential.
//
// The results hold raw values. Never print, log or encode them.
func valueCredentials(value string) (long, short []string) {
	for _, v := range discover.ArgCredentials([]string{value}) {
		switch {
		case v == value, slices.Contains(long, v), slices.Contains(short, v):
			// The whole value, or a piece that is in a list already. The
			// lists are short, so a linear search is enough.
		case len(v) >= discover.MinSecretBytes:
			long = append(long, v)
		case v != "":
			short = append(short, v)
		}
	}
	return long, short
}

// argCredentials returns the pieces of the command line of s that look like
// a credential (see discover.ArgCredentials), with at least
// discover.MinSecretBytes bytes, for Result.Credentials. It reads the same
// line as argSecrets, and discover.ArgCredentials is a subset of
// discover.ArgSecrets, so each piece is also in the long list of argSecrets.
// The list can hold a value more than one time: resultCredentials removes
// duplicates.
//
// The result holds raw values. Never print, log or encode them.
func argCredentials(s discover.Server) []string {
	line := append([]string{s.Command}, s.Args.Values()...)
	var credentials []string
	for _, v := range discover.ArgCredentials(line) {
		if len(v) >= discover.MinSecretBytes {
			credentials = append(credentials, v)
		}
	}
	return credentials
}

// argSecrets returns the secrets in the command line of s: the text that
// discover.RedactArgs masks (see discover.ArgSecrets), in two lists. secrets
// holds the pieces of at least discover.MinSecretBytes bytes, for classify to
// remove from error text wherever they stand and for Result.Secrets (see
// resultSecrets). short holds the shorter pieces, for classify to remove from
// error text as whole words only (see replaceWords). A server gets its argv
// and can echo it. discover.ArgSecrets over-matches on purpose, so short can
// hold ordinary words such as "1"; the whole-word rule keeps the cost low.
//
// s is the expanded server, so these are the command and the args that the
// child gets as argv (see stdioCommand). The configured form is not needed:
// its "${VAR}" text never reaches the child, and the expanded values are in
// the list of the lookup already. The command goes first, as in the report
// (formatCommand in internal/report), so that the same rules see the same
// line.
//
// The results hold raw values. Never print, log or encode them.
func argSecrets(s discover.Server) (secrets, short []string) {
	line := append([]string{s.Command}, s.Args.Values()...)
	for _, v := range discover.ArgSecrets(line) {
		switch {
		case len(v) >= discover.MinSecretBytes:
			secrets = append(secrets, v)
		case v != "":
			short = append(short, v)
		}
	}
	return secrets, short
}
