package rules

import (
	"bufio"
	"fmt"
	"io"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

const (
	// minTyposquatNameLen is the shortest name that the typosquat check
	// compares. Very short names are always close to each other, so they
	// give noise.
	minTyposquatNameLen = 5

	// maxTyposquatNameLen caps the length of a compared name. Names come from
	// untrusted configs, and the edit distance costs time and memory in
	// proportion to the product of the two lengths. The cap keeps that cost
	// bounded.
	maxTyposquatNameLen = 128

	// shortTyposquatNameLen is the longest "short" name. Short names allow
	// one edit, longer names allow two.
	shortTyposquatNameLen = 8

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

// NewTyposquat returns a check for the given popular names. It copies, trims
// and lowercases the names and skips blank ones, so it accepts raw input that
// did not come from ParsePopular, and the caller may change the slice
// afterwards.
func NewTyposquat(popular []string) *Typosquat {
	t := &Typosquat{
		popular:   make([]popularName, 0, len(popular)),
		ambiguous: make(map[string]bool),
	}
	owner := make(map[string]string, len(popular)) // bare name -> first full name
	for _, name := range popular {
		full := strings.ToLower(strings.TrimSpace(name))
		if full == "" {
			continue
		}
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

// typoCandidate is a name from a server that the check compares.
type typoCandidate struct {
	full      string
	bare      string
	field     string // the Finding.Field for this name
	isPackage bool   // a package from the runner args, not a server name
	npm       bool   // an npx or bunx package: only npm has scopes
}

// Check returns the findings for server s: at most one for the server name
// and one for the package that its runner fetches. A name that equals a
// popular name is legitimate and gets no finding. A server name is also fine
// when it equals the bare name of a scoped popular package, because a user
// may name a local server freely, and "_" or "." in it count as "-". A
// package is not free: it must equal the full popular name, or else a copied
// bare name is scope squatting. A server that runs a popular package exactly
// gets no finding at all.
func (t *Typosquat) Check(s discover.Server) []Finding {
	// A user may write "_" or "." where the popular name has "-".
	name := nameForm(strings.ToLower(s.Name))
	candidates := []typoCandidate{{full: name, bare: bareName(name), field: FieldName}}
	if spec, ok := ExtractPackage(s.Command, s.Args.Values()); ok {
		pkg := registryName(spec)
		if slices.ContainsFunc(t.popular, func(p popularName) bool { return p.full == pkg }) {
			// The server runs a popular package exactly, so it is that
			// server, whatever the user calls it.
			return nil
		}
		candidates = append(candidates, typoCandidate{
			full:      pkg,
			bare:      bareName(pkg),
			field:     FieldArgs,
			isPackage: true,
			npm:       spec.Runner.isNPM(),
		})
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
			Message: typosquatMessage,
		})
	}
	return findings
}

// closest returns the full name of the popular server that c resembles most.
// On a tie the first one in the list wins, so the result is deterministic.
// It returns false when c is exact, too short or too long, or not close to
// any popular name.
//
// A server name is compared with the flat form of a scoped popular name
// ("@playwright/mcp" as "playwright-mcp", see flatName), because a user who
// names a server after its package writes it that way.
//
// A package (field "args") is exact only when its full name is a popular
// name. An npm package whose bare name equals the bare name of a scoped popular
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
func (t *Typosquat) closest(c typoCandidate) (string, bool) {
	for _, p := range t.popular {
		// An exact match is the legitimate server. This check also stops an
		// exact name from being reported as close to a different popular name.
		if c.full == compareForm(c, p) {
			return "", false
		}
		if !c.isPackage && (c.full == nameForm(p.bare) || c.bare == nameForm(p.bare)) {
			return "", false // a server name is free to copy a bare name
		}
	}

	if c.npm {
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
		consider(c.full, compareForm(c, p))
		// A bare name that several popular names share, such as
		// "mcp-server", proves nothing, as in scopeSquat.
		if (c.full != c.bare || p.full != p.bare) && !t.ambiguous[p.bare] {
			consider(c.bare, p.bare)
		}
	}
	return related, related != ""
}

// compareForm returns the form of popular name p that closest compares with
// the full name of c: the full name for a package, the flat name in
// nameForm for a server name.
func compareForm(c typoCandidate, p popularName) string {
	if c.isPackage {
		return p.full
	}
	return nameForm(flatName(p.full))
}

// nameForm writes every run of "-", "_" and "." in a server name as "-", so
// "playwright_mcp" and "playwright-mcp" compare as one name.
func nameForm(name string) string {
	return nameSeparators.ReplaceAllString(name, "-")
}

// flatName writes a scoped npm name "@scope/name" as "scope-name". Any other
// name is returned as it is.
func flatName(name string) string {
	if scope := scopeOf(name); scope != "" {
		return strings.TrimSuffix(scope[1:], "/") + "-" + bareName(name)
	}
	return name
}

// scopeSquat reports whether npm package c copies the name of a popular package
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
func (t *Typosquat) scopeSquat(c typoCandidate) (string, bool) {
	n := utf8.RuneCountInString(c.bare)
	if n < minTyposquatNameLen || n > maxTyposquatNameLen || t.ambiguous[c.bare] {
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
// shorter name has at most shortTyposquatNameLen runes, else 2.
func closeDistance(a, b string) (int, bool) {
	la, lb := utf8.RuneCountInString(a), utf8.RuneCountInString(b)
	if min(la, lb) < minTyposquatNameLen || max(la, lb) > maxTyposquatNameLen {
		return 0, false
	}
	threshold := 2
	if min(la, lb) <= shortTyposquatNameLen {
		threshold = 1
	}
	if la-lb > threshold || lb-la > threshold {
		return 0, false // cheap exit: the lengths alone rule it out
	}
	d := osaDistance(a, b)
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
	return strings.TrimPrefix(name, scopeOf(name))
}

// osaDistance returns the optimal string alignment distance of a and b: the
// fewest insertions, deletions, substitutions and swaps of two neighbouring
// runes. It is the restricted form of Damerau-Levenshtein, because it never
// edits the same part of the string twice. Callers cap the input length, so
// the full matrix is cheap.
func osaDistance(a, b string) int {
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
