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

// argSecrets returns the secrets in the command line of s, for classify to
// remove from error text and for Result.Secrets (see resultSecrets): the
// text that discover.RedactArgs masks (see discover.ArgSecrets), with at
// least discover.MinSecretBytes bytes. A server gets its argv and can echo it.
//
// s is the expanded server, so these are the command and the args that the
// child gets as argv (see stdioCommand). The configured form is not needed:
// its "${VAR}" text never reaches the child, and the expanded values are in
// the list of the lookup already. The command goes first, as in the report
// (formatCommand in internal/report), so that the same rules see the same
// line.
//
// The result holds raw values. Never print, log or encode them.
func argSecrets(s discover.Server) []string {
	line := append([]string{s.Command}, s.Args.Values()...)
	var secrets []string
	for _, v := range discover.ArgSecrets(line) {
		if len(v) >= discover.MinSecretBytes {
			secrets = append(secrets, v)
		}
	}
	return secrets
}
