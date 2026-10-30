package rules

import (
	"bufio"
	"fmt"
	"io"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/Ducarv/mcpmoat/internal/discover"
	builtinrules "github.com/Ducarv/mcpmoat/rules"
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
	// one edit. Longer names allow two edits only in the cases that
	// closeDistance lists.
	shortTyposquatNameLen = 8

	// minTwoEditTailLen is the shortest tail in which two edits count as
	// close. The tail is the part of the shorter name after the last
	// separator that the two names share (see distinctiveTailRunes).
	minTwoEditTailLen = 5

	// sameScopeMaxDistance is the largest edit distance that still counts as
	// close when a package and a popular package share an npm scope. See
	// closest.
	sameScopeMaxDistance = 1
)

// PopularEntry is one entry of the popular server list: a package name and the
// registry that it belongs to.
type PopularEntry struct {
	Kind RegistryKind // the registry of the package: KindNPM, KindPyPI or KindDocker
	Name string       // the full package name, such as "@modelcontextprotocol/server-memory"
}

// ParsePopular reads the popular-server list format: one entry per line,
// written as kind:name. The line is split at the first colon, so a name may
// itself contain colons. The kind must be npm, pypi or docker. Blank lines and
// lines that start with # are ignored. Space around the kind and the name is
// trimmed (a CRLF line ending too), and both are lowercased.
//
// A line without a kind, with an unknown kind, or with an empty name is an
// error. The message names the 1-based line number and does not repeat the
// line.
func ParsePopular(r io.Reader) ([]PopularEntry, error) {
	var entries []PopularEntry
	scanner := bufio.NewScanner(r)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rawKind, rawName, found := strings.Cut(line, ":")
		if !found {
			return nil, fmt.Errorf("popular server list line %d: want kind:name, found no colon", lineNo)
		}
		kind := RegistryKind(strings.ToLower(strings.TrimSpace(rawKind)))
		if kind == "" {
			return nil, fmt.Errorf("popular server list line %d: the kind is empty", lineNo)
		}
		if !validPopularKind(kind) {
			return nil, fmt.Errorf("popular server list line %d: unknown kind (want npm, pypi or docker)", lineNo)
		}
		name := strings.ToLower(strings.TrimSpace(rawName))
		if name == "" {
			return nil, fmt.Errorf("popular server list line %d: the name is empty", lineNo)
		}
		entries = append(entries, PopularEntry{Kind: kind, Name: name})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read popular server list: %w", err)
	}
	return entries, nil
}

// validPopularKind reports whether k is a registry kind that the popular list
// accepts.
func validPopularKind(k RegistryKind) bool {
	switch k {
	case KindNPM, KindPyPI, KindDocker:
		return true
	}
	return false
}

// popularName is one entry of the popular list in the forms that the check
// compares.
type popularName struct {
	kind RegistryKind // the registry of the package
	full string       // as listed, such as "@modelcontextprotocol/server-memory"
	bare string       // without the "@scope/" prefix, such as "server-memory"

	// base is the last "/" component of full, such as "fetch" for "mcp/fetch". It
	// is set only for docker entries and is "" for the others. Unlike bare, it
	// also drops the owner path of an image (see dockerSquat).
	base string

	// The forms that a server name is compared with (see nameForm).
	flatForm string // nameForm(flatName(full)), such as "modelcontextprotocol-server-memory"
	bareForm string // nameForm(bare)
}

// Typosquat compares server and package names with a list of popular MCP
// servers (threat T5). It finds two kinds of look-alike: a name that is a
// small edit away from a popular name, and a package that copies the bare
// name of a popular package under another owner: a npm scope (scope squatting,
// such as "@evil/server-filesystem") or a docker owner path (docker namespace
// squatting, such as "evil/fetch" for "mcp/fetch"). Build it with NewTyposquat.
type Typosquat struct {
	popular []popularName
	// ambiguous holds the bare names that belong to two or more different
	// popular names, such as "mcp-server". Such a generic name proves
	// nothing about one scope, so the scope squatting check skips it.
	ambiguous map[string]bool
	// ambiguousBase holds the docker bases (the last "/" component) that belong
	// to two or more different popular docker names. Such a base proves nothing
	// about one owner, so the docker squatting check skips it. It is separate
	// from ambiguous because the two maps key different forms of a name.
	ambiguousBase map[string]bool
}

// NewTyposquat returns a check for the given popular entries. It copies the
// entries, trims and lowercases the names and kinds, and skips entries with a
// blank name, so it accepts raw input that did not come from ParsePopular, and
// the caller may change the slice afterwards. It stores the kind of each entry:
// Check uses it to decide what is an exact match. It also skips an entry whose
// kind is not valid (see validPopularKind), so a caller cannot add an entry
// that reports its own exact name as a kind mismatch.
func NewTyposquat(popular []PopularEntry) *Typosquat {
	t := &Typosquat{
		popular:       make([]popularName, 0, len(popular)),
		ambiguous:     make(map[string]bool),
		ambiguousBase: make(map[string]bool),
	}
	owner := make(map[string]string, len(popular))       // bare name -> first full name
	dockerOwner := make(map[string]string, len(popular)) // docker base -> first full name
	for _, entry := range popular {
		full := strings.ToLower(strings.TrimSpace(entry.Name))
		if full == "" {
			continue
		}
		kind := RegistryKind(strings.ToLower(strings.TrimSpace(string(entry.Kind))))
		if !validPopularKind(kind) {
			continue
		}
		bare := bareName(full)
		p := popularName{
			kind:     kind,
			full:     full,
			bare:     bare,
			flatForm: nameForm(flatName(full)),
			bareForm: nameForm(bare),
		}
		if kind == KindDocker {
			p.base = dockerBase(full)
			if first, seen := dockerOwner[p.base]; !seen {
				dockerOwner[p.base] = full
			} else if first != full {
				t.ambiguousBase[p.base] = true
			}
		}
		t.popular = append(t.popular, p)
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
	isNPM     bool   // an npx or bunx package: only npm has scopes

	// kind is the registry of a package, taken from its runner. It is empty for
	// a server name, which has no registry.
	kind RegistryKind
}

// Check returns the findings for server s: at most one for the server name
// and one for the package that its runner fetches. A server name is fine when
// it equals a popular name of any registry kind, or the bare name of a scoped
// popular package, because a user may name a local server freely, and "_" or
// "." in it count as "-".
//
// A package is not free. It is exact only when the popular list has an entry
// with the same registry kind and the same name (the kind comes from the
// runner: npx and bunx are npm, uvx and pipx are PyPI, "docker run" is docker).
// A server that runs a popular package exactly gets no finding at all.
//
// A npm or PyPI package whose name equals a popular name of another kind, such
// as an npm package named like a popular PyPI server, gets a finding with
// typosquatKindMessage: the name is popular, but on another registry. Its
// Related is the plain popular name. A docker package never gets this finding.
//
// Any other package is compared by edit distance, scope squatting and, for a
// docker image, namespace squatting with the popular names (see closest).
func (t *Typosquat) Check(s discover.Server) []Finding {
	// A user may write "_", "." or "/" where the popular name has "-", or
	// copy a scoped package name: compare the flat form.
	name := nameForm(flatName(strings.ToLower(s.Name)))
	candidates := []typoCandidate{{full: name, bare: bareName(name), field: FieldName}}
	if spec, ok := ExtractPackage(s.Command, s.Args.Values()); ok {
		pkg := registryName(spec)
		kind := spec.Runner.kind()
		if t.hasExact(kind, pkg) {
			// The server runs a popular package exactly, so it is that
			// server, whatever the user calls it.
			return nil
		}
		candidates = append(candidates, typoCandidate{
			full:      pkg,
			bare:      bareName(pkg),
			field:     FieldArgs,
			isPackage: true,
			isNPM:     spec.Runner.isNPM(),
			kind:      kind,
		})
	}

	var findings []Finding
	for _, c := range candidates {
		related, message, found := t.match(c)
		if !found {
			continue
		}
		findings = append(findings, Finding{
			RuleID:  RuleTyposquat,
			Server:  s.Name,
			Field:   c.field,
			Related: related,
			Message: message,
		})
	}
	return findings
}

// match returns the popular name that c resembles and the finding message for
// it. A npm or PyPI package with the name of a popular entry of another kind
// matches that entry with typosquatKindMessage. Anything else goes to closest
// and uses typosquatMessage. The returned text comes only from constants and the
// popular list, never from c.
func (t *Typosquat) match(c typoCandidate) (related, message string, found bool) {
	if related, ok := t.otherKindName(c); ok {
		return related, typosquatKindMessage, true
	}
	related, found = t.closest(c)
	return related, typosquatMessage, found
}

// hasExact reports whether the popular list has an entry with this registry
// kind and this full name. The caller passes a name in the form that the
// registry resolves (see registryName).
func (t *Typosquat) hasExact(kind RegistryKind, full string) bool {
	return slices.ContainsFunc(t.popular, func(p popularName) bool {
		return p.kind == kind && p.full == full
	})
}

// otherKindName looks for a popular entry with the same name as package c but
// another registry kind. It returns that name and true. It skips server names
// and docker packages: only npm and PyPI packages get this finding, because a
// docker image name and an npm or PyPI name are separate namespaces that often
// share a word by chance. On a tie the first entry in the list wins.
func (t *Typosquat) otherKindName(c typoCandidate) (string, bool) {
	if !c.isPackage || (c.kind != KindNPM && c.kind != KindPyPI) {
		return "", false
	}
	for _, p := range t.popular {
		if p.full == c.full && p.kind != c.kind {
			return p.full, true
		}
	}
	return "", false
}

// closest returns the full name of the popular server that c resembles most.
// On a tie the first one in the list wins, so the result is deterministic.
// It returns false when c is exact, too short or too long, or not close to
// any popular name.
//
// Exact depends on what c is. A package is exact when a popular entry has the
// same registry kind and the same full name. A server name has no registry, so
// it is exact when its form equals the popular name of any kind. The edit
// distance and scope squatting checks compare against the names of all kinds.
// A package with the name of a popular entry of another kind is not exact here;
// Check reports it before closest runs (see otherKindName).
//
// A server name is compared with the flat form of a scoped popular name
// ("@playwright/mcp" as "playwright-mcp", see flatName), because a user who
// names a server after its package writes it that way.
//
// A package (field "args") is exact only when its full name is a popular
// name of its own kind. An npm package whose bare name equals the bare name of a scoped popular
// package, under another scope or none, is scope squatting: closest returns
// the popular full name. So is a scoped package whose bare name equals an
// unscoped popular name, such as "@evil/mcp-remote". The exception is a
// generic bare name that several popular names share, such as "mcp-server".
//
// A docker image is also checked for namespace squatting: an image under
// another owner path with the same last component as a popular image, such as
// "evil/fetch" for "mcp/fetch" (see dockerSquat).
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
		if !c.isPackage && (c.full == p.bareForm || c.bare == p.bareForm) {
			return "", false // a server name is free to copy a bare name
		}
	}

	if c.isNPM {
		if related, ok := t.scopeSquat(c); ok {
			return related, true
		}
	}
	if related, ok := t.dockerSquat(c); ok {
		return related, true
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
// the full name of c: the full name for a package, the flat form for a
// server name.
func compareForm(c typoCandidate, p popularName) string {
	if c.isPackage {
		return p.full
	}
	return p.flatForm
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

// dockerBase returns the last "/" component of a docker image name, such as
// "fetch" for "mcp/fetch". A name without "/" is returned as it is.
func dockerBase(name string) string {
	return name[strings.LastIndex(name, "/")+1:]
}

// hasDockerOwner reports whether the docker image name has an owner, which is
// a path component before the image name. If the first component looks like a
// registry host (it holds "." or ":", or it is "localhost"), the owner is the
// next component, so the name needs at least two more components after the
// host: "ghcr.io/evil/fetch" has an owner, "ghcr.io/fetch" has none. Else the
// name needs at least two components: "evil/fetch" has an owner, "fetch" has
// none.
func hasDockerOwner(name string) bool {
	parts := strings.Split(name, "/")
	first := parts[0]
	isHost := strings.ContainsAny(first, ".:") || first == "localhost"
	if isHost {
		return len(parts) >= 3
	}
	return len(parts) >= 2
}

// dockerSquat reports whether docker image c copies the name of a popular image
// under another owner. It returns the first matching popular full name in list
// order, which comes from the popular list and never from c. All of these must
// hold:
//
//   - c is a docker package, and the popular entry is a docker entry;
//   - the full names differ. The full name is compared as is, after
//     registryName: the Docker Hub host and "library/" are already dropped, so
//     "docker.io/mcp/fetch" equals "mcp/fetch" and is no finding, while
//     "ghcr.io/mcp/fetch" is another registry and a finding;
//   - c has an owner (see hasDockerOwner). A single component such as
//     "postgres" is an official Docker Hub image, and a registry host with a
//     name but no owner, such as "ghcr.io/fetch", has no owner either; both
//     are skipped;
//   - the last component of c equals the last component of the popular name;
//   - that last component has minTyposquatNameLen to maxTyposquatNameLen runes;
//   - that last component is not in ambiguousBase.
//
// Example: "evil/github-mcp-server" and "ghcr.io/evil/github-mcp-server" both
// match "ghcr.io/github/github-mcp-server".
//
// Known gaps, accepted on purpose:
//   - A last component with fewer than minTyposquatNameLen runes, such as
//     "mcp/git", is skipped. Short names are too common.
//   - A typo in the last component, such as "evil/fecth", gives no finding. Only
//     an equal last component counts.
func (t *Typosquat) dockerSquat(c typoCandidate) (string, bool) {
	if !c.isPackage || c.kind != KindDocker || !hasDockerOwner(c.full) {
		return "", false
	}
	base := dockerBase(c.full)
	n := utf8.RuneCountInString(base)
	if n < minTyposquatNameLen || n > maxTyposquatNameLen || t.ambiguousBase[base] {
		return "", false
	}
	for _, p := range t.popular {
		if p.kind == KindDocker && p.full != c.full && p.base == base {
			return p.full, true
		}
	}
	return "", false
}

// closeDistance returns the edit distance of a and b and true when it is
// between 1 and the threshold for these names. The threshold is 2 when the
// shorter name has more than shortTyposquatNameLen runes and one of these is
// true:
//   - the longer name starts with the whole shorter name, so the edits only
//     add or drop runes at the end ("mcp-server-gitxx" against
//     "mcp-server-git"), or
//   - the tail (see distinctiveTailRunes) has at least minTwoEditTailLen
//     runes.
//
// Else the threshold is 1.
//
// Known limits:
//   - Two edits inside a tail shorter than minTwoEditTailLen runes give no
//     finding. A short tail cannot tell a typo from a different product
//     ("gcp" against "git"). This covers every popular name whose last word
//     is short, such as "mcp-server-gxx" against "mcp-server-git" and
//     "tavily-mxx" against "tavily-mcp". One edit there still gives a
//     finding.
//   - Two runes added at the end count even after a short last word, so a
//     real product that extends a popular name by two runes, such as
//     "mcp-server-gitee" against "mcp-server-git", gives a finding. Appending
//     runes is a common way to squat a name, and no such package was found
//     on npm or PyPI when the threshold was set.
//   - The tail runs to the end of the name, so a shared suffix makes it
//     longer: "ana-mcp-server" against "exa-mcp-server" still counts as
//     close.
//   - Real names that differ by 2 edits in a tail of 5 runes or more, such as
//     "mcp-server-github" and "mcp-server-gitlab", also count as close. That
//     matters only if both are on the popular list.
func closeDistance(a, b string) (int, bool) {
	la, lb := utf8.RuneCountInString(a), utf8.RuneCountInString(b)
	short := min(la, lb)
	if short < minTyposquatNameLen || max(la, lb) > maxTyposquatNameLen {
		return 0, false
	}
	appended := strings.HasPrefix(a, b) || strings.HasPrefix(b, a)
	threshold := 1
	if short > shortTyposquatNameLen && (appended || distinctiveTailRunes(a, b, short) >= minTwoEditTailLen) {
		threshold = 2
	}
	if la-lb > threshold || lb-la > threshold {
		return 0, false // cheap exit: the lengths alone rule it out
	}
	d := osaDistance(a, b)
	return d, d >= 1 && d <= threshold
}

// distinctiveTailRunes returns the length in runes of the part of the shorter
// name that starts after the last separator ("-", "/", "_", "." or "@") inside
// the prefix that a and b share. short is the rune count of the shorter name;
// the caller passes it because it has already counted both names.
// For "mcp-server-gcp" and "mcp-server-git" the shared prefix is
// "mcp-server-g", the last separator in it is the second "-", and the result
// is 3: the word "gcp". It allocates nothing.
//
// A long shared prefix, such as "mcp-server-", would make two edits in a short
// word look like a typo when they are not. Measuring from the last separator
// keeps two edits in a long word ("mcp-server-fexxh") visible. closeDistance
// handles runes added at the end of the whole shorter name ("mcp-server-gitxx")
// on its own.
func distinctiveTailRunes(a, b string, short int) int {
	start, n := 0, 0 // start: runes up to and including the last separator
	for a != "" && b != "" {
		ra, sa := utf8.DecodeRuneInString(a)
		rb, sb := utf8.DecodeRuneInString(b)
		if ra != rb {
			break
		}
		n++
		if isNameSeparator(ra) {
			start = n
		}
		a, b = a[sa:], b[sb:]
	}
	return short - start
}

// isNameSeparator reports whether r separates the words of a package name.
func isNameSeparator(r rune) bool {
	switch r {
	case '-', '/', '_', '.', '@':
		return true
	}
	return false
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

// builtinPopular parses the embedded popular server list into entries. Each
// call parses the list again, so no global state is kept.
func builtinPopular() ([]PopularEntry, error) {
	return ParsePopular(strings.NewReader(builtinrules.PopularServers))
}

// NewBuiltinTyposquat builds the T5 check from the embedded popular server
// list. It parses the list each time it is called. A scan calls it once for
// the native T5 check, and NewAnalyzer calls it once more when it compiles the
// typosquat rule. It returns an error if the embedded list does not parse.
func NewBuiltinTyposquat() (*Typosquat, error) {
	popular, err := builtinPopular()
	if err != nil {
		return nil, err
	}
	return NewTyposquat(popular), nil
}
