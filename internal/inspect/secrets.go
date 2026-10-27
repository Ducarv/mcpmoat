package inspect

import (
	"cmp"
	"slices"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// resultSecrets returns the values in lists as discover.Secret values, for
// Result.Secrets. It keeps only the values of at least minBareSecretLen
// bytes, each one time.
//
// The scrub of error text (see scrub) also removes shorter header values and
// a short URL password. Result.Secrets does not hold them: a consumer removes
// the values from ordinary text, such as tool descriptions, and a short value
// is too likely to match ordinary words ("1", "true", "json"). So the filter
// applies here only, and the lists of the error scrub stay as they are.
//
// The result is sorted longest first, then by value, so that it does not
// depend on the order of a map, and so that a consumer that replaces the
// values in order does not leave pieces of a longer value behind when a
// shorter value is part of it. It is nil when no value is long enough.
//
// The sort and the duplicate check compare the raw values in memory only.
// Never print, log or encode them.
func resultSecrets(lists ...[]string) []discover.Secret {
	var values []string
	for _, list := range lists {
		for _, v := range list {
			if len(v) >= minBareSecretLen {
				values = append(values, v)
			}
		}
	}
	slices.SortFunc(values, func(a, b string) int {
		if c := cmp.Compare(len(b), len(a)); c != 0 {
			return c
		}
		return cmp.Compare(a, b)
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
