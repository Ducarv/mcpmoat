package rules

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

const (
	// minNameLen is the shortest name that the typosquat check compares. Very
	// short names are always close to each other, so they give noise.
	minNameLen = 5

	// maxNameLen caps the length of a compared name. Names come from untrusted
	// configs, and the edit distance costs time and memory in proportion to
	// the product of the two lengths. The cap keeps that cost bounded.
	maxNameLen = 128

	// shortNameLen is the longest "short" name. Short names allow one edit,
	// longer names allow two.
	shortNameLen = 8

	// sameScopeMaxDistance is the largest edit distance that still counts as
	// close when a package and a popular package share an npm scope. See
	// closest.
	sameScopeMaxDistance = 1
)

// ParsePopular reads the popular-server list format: one name per line. Blank
// lines and lines that start with # are ignored. Space around a name is
// trimmed, and names are lowercased.
func ParsePopular(r io.Reader) ([]string, error) {
	var names []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		names = append(names, strings.ToLower(line))
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read popular server list: %w", err)
	}
	return names, nil
}

// popularName is one entry of the popular list in its two forms.
type popularName struct {
	full string // as listed, such as "@modelcontextprotocol/server-memory"
	bare string // without the "@scope/" prefix, such as "server-memory"
}

// Typosquat compares server and package names with a list of popular MCP
// servers (threat T5). It finds two kinds of look-alike: a name that is a
// small edit away from a popular name, and a package that copies the bare
// name of a scoped popular package under another scope or none (scope
// squatting, such as "@evil/server-filesystem"). Build it with NewTyposquat.
type Typosquat struct {
	popular []popularName
	// ambiguous holds the bare names that belong to two or more different
	// popular names, such as "mcp-server". Such a generic name proves
	// nothing about one scope, so the scope squatting check skips it.
	ambiguous map[string]bool
}

// NewTyposquat returns a check for the given popular names. It copies and
// lowercases the names, so the caller may change the slice afterwards.
func NewTyposquat(popular []string) *Typosquat {
	t := &Typosquat{
		popular:   make([]popularName, 0, len(popular)),
		ambiguous: make(map[string]bool),
	}
	owner := make(map[string]string, len(popular)) // bare name -> first full name
	for _, name := range popular {
		full := strings.ToLower(strings.TrimSpace(name))
		bare := bareName(full)
		t.popular = append(t.popular, popularName{full: full, bare: bare})
		first, seen := owner[bare]
		if !seen {
			owner[bare] = full
		} else if first != full {
			t.ambiguous[bare] = true
		}
	}
	return t
}

// candidate is a name from a server that the check compares.
type candidate struct {
	full      string
	bare      string
	field     string // the Finding.Field for this name
	isPackage bool   // a package from the runner args, not a server name
}

// Check returns the findings for server s: at most one for the server name
// and one for the package that its runner fetches. A name that equals a
// popular name is legitimate and gets no finding. A server name is also fine
// when it equals the bare name of a scoped popular package, because a user
// may name a local server freely. A package is not: it must equal the full
// popular name, or else a copied bare name is scope squatting.
func (t *Typosquat) Check(s discover.Server) []Finding {
	name := strings.ToLower(s.Name)
	candidates := []candidate{{full: name, bare: bareName(name), field: FieldName}}
	if spec, ok := ExtractPackage(s.Command, s.Args.Values()); ok {
		pkg := strings.ToLower(spec.Name)
		candidates = append(candidates, candidate{full: pkg, bare: bareName(pkg), field: FieldArgs, isPackage: true})
	}

	var findings []Finding
	for _, c := range candidates {
		related, found := t.closest(c)
		if !found {
			continue
		}
		findings = append(findings, Finding{
			RuleID:  RuleTyposquat,
			Server:  s.Name,
			Field:   c.field,
			Related: related,
			Message: "name is close to a popular MCP server",
		})
	}
	return findings
}

// closest returns the full name of the popular server that c resembles most.
// On a tie the first one in the list wins, so the result is deterministic.
// It returns false when c is exact, too short or too long, or not close to
// any popular name.
//
// A package (field "args") is exact only when its full name is a popular
// name. A package whose bare name equals the bare name of a scoped popular
// package, under another scope or none, is scope squatting: closest returns
// the popular full name. So is a scoped package whose bare name equals an
// unscoped popular name, such as "@evil/mcp-remote". The exception is a
// generic bare name that several popular names share, such as "mcp-server".
//
// Only the owner of an npm scope can publish inside it. So a package in the
// same scope as a popular package, such as "@modelcontextprotocol/server-gitlab"
// next to "@modelcontextprotocol/server-github", is a sibling from the same
// owner and not an attack. For such a pair closest allows an edit distance of
// at most sameScopeMaxDistance. A one-edit typo like "server-filesytem" still
// gives a finding, as a mistake in the user's config (the name probably does
// not exist, or it is a rare slip in the scope's own packages). A scope that
// differs, even by one letter, gets the normal threshold.
func (t *Typosquat) closest(c candidate) (string, bool) {
	for _, p := range t.popular {
		// An exact match is the legitimate server. This check also stops an
		// exact name from being reported as close to a different popular name.
		if c.full == p.full {
			return "", false
		}
		if !c.isPackage && (c.full == p.bare || c.bare == p.bare) {
			return "", false // a server name is free to copy a bare name
		}
	}

	if c.isPackage {
		if related, ok := t.scopeSquat(c); ok {
			return related, true
		}
	}

	best, related := 0, ""
	for _, p := range t.popular {
		limit := 0 // 0 means the normal threshold of closeDistance
		if c.isPackage && sameScope(c.full, p.full) {
			limit = sameScopeMaxDistance
		}
		// Compare like with like: full with full, bare with bare. The bare
		// comparison adds nothing when neither name has a scope.
		consider := func(a, b string) {
			d, ok := closeDistance(a, b)
			if ok && (limit == 0 || d <= limit) && (related == "" || d < best) {
				best, related = d, p.full
			}
		}
		consider(c.full, p.full)
		if c.full != c.bare || p.full != p.bare {
			consider(c.bare, p.bare)
		}
	}
	return related, related != ""
}

// scopeSquat reports whether package c copies the name of a popular package
// under a different scope. It returns the first matching popular full name.
// Two cases match:
//
//   - the bare name of c equals the bare name of a scoped popular package,
//     such as "@evil/server-github" or "server-github" against
//     "@modelcontextprotocol/server-github";
//   - c is scoped and its bare name equals an unscoped popular name, such as
//     "@evil/mcp-remote" against "mcp-remote". An unscoped c with an unscoped
//     popular name is an exact match, which closest handles before.
//
// The popular list mixes npm, PyPI and docker names. A scoped npm package whose
// bare name equals a PyPI name, such as "@evil/mcp-server-fetch", also matches.
// That is acceptable: the scope is not the owner of that name either.
//
// Bare names that are too short or too long, or shared by several popular
// names, never match.
func (t *Typosquat) scopeSquat(c candidate) (string, bool) {
	n := utf8.RuneCountInString(c.bare)
	if n < minNameLen || n > maxNameLen || t.ambiguous[c.bare] {
		return "", false
	}
	scoped := strings.HasPrefix(c.full, "@")
	for _, p := range t.popular {
		if p.full == c.full {
			continue
		}
		if strings.HasPrefix(p.full, "@") && p.bare == c.bare {
			return p.full, true
		}
		if scoped && !strings.HasPrefix(p.full, "@") && p.full == c.bare {
			return p.full, true
		}
	}
	return "", false
}

// closeDistance returns the edit distance of a and b and true when it is
// between 1 and the threshold for these names. The threshold is 1 when the
// shorter name has at most shortNameLen runes, else 2.
func closeDistance(a, b string) (int, bool) {
	la, lb := utf8.RuneCountInString(a), utf8.RuneCountInString(b)
	if la < minNameLen || lb < minNameLen || la > maxNameLen || lb > maxNameLen {
		return 0, false
	}
	threshold := 2
	if min(la, lb) <= shortNameLen {
		threshold = 1
	}
	if la-lb > threshold || lb-la > threshold {
		return 0, false // cheap exit: the lengths alone rule it out
	}
	d := distance(a, b)
	return d, d >= 1 && d <= threshold
}

// sameScope reports whether a and b are npm packages in the same scope. A name
// with no scope has no scope to share.
func sameScope(a, b string) bool {
	sa, sb := scopeOf(a), scopeOf(b)
	return sa != "" && sa == sb
}

// scopeOf returns the "@scope/" prefix of an npm package name, or "" when the
// name has no scope.
func scopeOf(name string) string {
	if !strings.HasPrefix(name, "@") {
		return ""
	}
	scope, _, found := strings.Cut(name, "/")
	if !found {
		return ""
	}
	return scope + "/"
}

// bareName removes a leading "@scope/" from an npm package name. Any other
// name, such as a PyPI package or a docker image, is returned as it is.
func bareName(name string) string {
	if !strings.HasPrefix(name, "@") {
		return name
	}
	if _, rest, found := strings.Cut(name, "/"); found {
		return rest
	}
	return name
}

// distance returns the optimal string alignment distance of a and b: the
// fewest insertions, deletions, substitutions and swaps of two neighbouring
// runes. It is the restricted form of Damerau-Levenshtein, because it never
// edits the same part of the string twice. Callers cap the input length, so
// the full matrix is cheap.
func distance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	d := make([][]int, len(ra)+1)
	for i := range d {
		d[i] = make([]int, len(rb)+1)
		d[i][0] = i
	}
	for j := range d[0] {
		d[0][j] = j
	}
	for i := 1; i <= len(ra); i++ {
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			d[i][j] = min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				d[i][j] = min(d[i][j], d[i-2][j-2]+1)
			}
		}
	}
	return d[len(ra)][len(rb)]
}
