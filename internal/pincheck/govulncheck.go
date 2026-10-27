package main

import (
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// The govulncheck rules. They port the govulncheck part of the old
// check-tool-pins.sh. The rules read the decoded YAML, so quotes, escapes,
// flow style and block scalars cannot hide a value:
//   - ci.yml has exactly one GOVULNCHECK_VERSION pin version. It is the
//     reference.
//   - release.yml and govulncheck.yml have at least one pin, and every pin
//     has the version of ci.yml.
//   - Each of the three files has at least one step whose run value is
//     exactly gvCall.
//   - In the three files, every scalar (key, value or list item) that names
//     govulncheck, in any case, is a pin key, a call or, in govulncheck.yml
//     only, one of the allowed names (see gvWeeklyNames).
//   - The three files have no continue-on-error key.
//   - Any other workflow does not name govulncheck.
//
// A pin is a mapping key that is exactly GOVULNCHECK_VERSION and has a full
// version as its scalar value. As in the old script, the pin can be in any
// mapping of the file.

// The workflows that may name govulncheck. ci.yml holds the reference pin.
const (
	gvCIPath      = ".github/workflows/ci.yml"
	gvReleasePath = ".github/workflows/release.yml"
	gvWeeklyPath  = ".github/workflows/govulncheck.yml"
)

const (
	// gvPinKey is the name of the pin, with its exact case.
	gvPinKey = "GOVULNCHECK_VERSION"
	// gvCall is the only allowed run value that runs govulncheck.
	gvCall = `go run "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION" ./...`
	// gvName is the job ID and the workflow name in govulncheck.yml.
	gvName = "govulncheck"
	// gvFailureIf is the if: value of the failure job in govulncheck.yml.
	// notify-failure-test.sh matches the same text.
	gvFailureIf = "failure() || needs.govulncheck.result == 'cancelled'"
)

// gvVersionRe matches a full version only. A short one such as v1.9 is a
// query, and Go picks the newest version that matches it. In Go regexp, $
// matches only at the end of the text, so a trailing newline does not match.
var gvVersionRe = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)

// gvPin is one GOVULNCHECK_VERSION pin.
type gvPin struct {
	version string     // the decoded version, such as v1.9.0
	key     *yaml.Node // the key node, for its line
}

// gvListedPaths returns the workflows that may name govulncheck, ci.yml
// first. It is a function and not a package variable, so that no code can
// change the list at run time.
func gvListedPaths() []string {
	return []string{gvCIPath, gvReleasePath, gvWeeklyPath}
}

// checkGovulncheck returns one message per problem with the govulncheck pin.
//
// The first parameter is the repository root. The govulncheck rules do not
// read files other than the workflows, so it is not used. The blank name _
// tells the reader (and the linter) that this is on purpose.
func checkGovulncheck(_ fs.FS, wfs map[string]*workflow) []string {
	var msgs []string
	for _, p := range gvListedPaths() {
		if !gvUsable(wfs[p]) {
			msgs = append(msgs, fmt.Sprintf("%s: the govulncheck check needs this workflow, but it is missing or did not parse", p))
		}
	}
	if len(msgs) == 0 {
		want, refMsgs := gvReferencePin(wfs[gvCIPath])
		msgs = append(msgs, refMsgs...)
		for _, p := range gvListedPaths() {
			msgs = append(msgs, gvCheckListed(p, wfs[p], want)...)
		}
	}
	return append(msgs, gvCheckOthers(wfs)...)
}

// gvUsable reports whether w is a parsed workflow that the rules can walk.
func gvUsable(w *workflow) bool {
	return w != nil && w.top != nil
}

// gvReferencePin returns the one pin version of ci.yml. When ci.yml has no
// pin, or pins more than one version, it returns "" and a message.
func gvReferencePin(w *workflow) (string, []string) {
	seen := make(map[string]bool)
	var versions []string
	for _, p := range gvPins(w) {
		if !seen[p.version] {
			seen[p.version] = true
			versions = append(versions, p.version)
		}
	}
	if len(versions) == 1 {
		return versions[0], nil
	}
	found := "none"
	if len(versions) > 0 {
		sort.Strings(versions)
		// A version can be long and ci.yml can hold many, so cut the list.
		found = cutText(strings.Join(versions, ", "), maxShown)
	}
	return "", []string{fmt.Sprintf("%s: the file must pin one version of govulncheck in %s (a full version such as v1.2.3), found: %s", w.file, gvPinKey, found)}
}

// gvCheckListed applies the rules for one of the listed workflows. path is
// its key in the map, want is the pin of ci.yml ("" when ci.yml has no single
// pin; gvReferencePin reported that).
func gvCheckListed(path string, w *workflow, want string) []string {
	var msgs []string
	pins := gvPins(w)
	// ci.yml is the reference, so gvReferencePin checked its pins.
	if path != gvCIPath {
		if len(pins) == 0 {
			msgs = append(msgs, fmt.Sprintf("%s: the file has no %s pin (a full version such as v1.2.3)", w.file, gvPinKey))
		}
		for _, p := range pins {
			if want != "" && p.version != want {
				msgs = append(msgs, fmt.Sprintf("%s:%d: the govulncheck pin %s differs from %s, the pin in ci.yml", w.file, p.key.Line, cutText(p.version, maxShown), cutText(want, maxShown)))
			}
		}
	}

	calls, callMsgs := gvCalls(w)
	msgs = append(msgs, callMsgs...)
	if len(calls) == 0 {
		msgs = append(msgs, fmt.Sprintf("%s: no step has the run value %s", w.file, gvCall))
	}

	// allowed holds the nodes that may name govulncheck. A map with pointer
	// keys compares node identity, not text: the same text in another place
	// is a different node and is not allowed.
	allowed := make(map[*yaml.Node]bool)
	for _, p := range pins {
		allowed[p.key] = true
	}
	for _, c := range calls {
		allowed[c] = true
	}
	if path == gvWeeklyPath {
		for _, n := range gvWeeklyNames(w) {
			allowed[n] = true
		}
	}
	for _, s := range w.scalars() {
		if gvNamesTool(s.Value) && !allowed[s] {
			msgs = append(msgs, fmt.Sprintf("%s:%d: %s names govulncheck, but it is not the %s pin, the call or an allowed name", w.file, s.Line, show(s.Value), gvPinKey))
		}
	}

	return append(msgs, gvContinueOnError(w)...)
}

// gvPins returns the pins of w in file order. A key that is exactly
// GOVULNCHECK_VERSION with a value that is not a full version is not a pin.
// Its key names govulncheck, so the name rule of gvCheckListed reports it.
func gvPins(w *workflow) []gvPin {
	var pins []gvPin
	gvWalk(w.root(), func(n *yaml.Node) {
		if n.Kind != yaml.MappingNode {
			return
		}
		// Content of a mapping holds key, value, key, value and so on.
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if k.Value == gvPinKey && v.Kind == yaml.ScalarNode && gvVersionRe.MatchString(v.Value) {
				pins = append(pins, gvPin{version: v.Value, key: k})
			}
		}
	})
	return pins
}

// gvCalls returns the run value nodes of the steps of w that are exactly
// gvCall. It also returns a message for each jobs or steps value that is not
// the shape GitHub needs, so that a broken file cannot hide a step. A run
// value that is not a scalar is not a call; the name rule still reads it.
func gvCalls(w *workflow) ([]*yaml.Node, []string) {
	jobs, msgs := gvJobs(w)
	var calls []*yaml.Node
	for _, j := range jobs {
		steps, err := w.steps(j)
		if err != nil {
			msgs = append(msgs, err.Error())
			continue
		}
		for _, s := range steps {
			run, err := w.scalarAt(s, "run")
			if err != nil || run == nil {
				continue
			}
			if run.Value == gvCall {
				calls = append(calls, run)
			}
		}
	}
	return calls, msgs
}

// gvJobs returns the jobs of w whose body is a mapping, in file order, and a
// message for each problem: no jobs mapping, or a job that is not a mapping.
// It differs from workflow.jobs, which returns no job at all on the first
// bad one: here a bad job does not hide the call in a good job, so the
// messages name only the real problem.
func gvJobs(w *workflow) ([]job, []string) {
	jobsNode, err := w.mappingAt(w.root(), "jobs")
	if err != nil {
		return nil, []string{err.Error()}
	}
	if jobsNode == nil {
		return nil, []string{w.errorAt(w.root(), "the workflow has no jobs mapping").Error()}
	}
	var out []job
	var msgs []string
	for i := 0; i+1 < len(jobsNode.Content); i += 2 {
		k, body := jobsNode.Content[i], jobsNode.Content[i+1]
		if body.Kind != yaml.MappingNode {
			// The same text as workflow.jobs, so dedupe removes the copy.
			msgs = append(msgs, w.errorAt(body, "the job %s must be a mapping, found %s", show(k.Value), kindName(body)).Error())
			continue
		}
		out = append(out, job{id: k.Value, key: k, body: body})
	}
	return out, msgs
}

// gvWeeklyNames returns the nodes of govulncheck.yml that may name
// govulncheck besides the pins and the calls. The old script allowed these
// lines, with this exact case:
//
//	name: govulncheck                      (the top-level name)
//	  govulncheck:                         (a job ID)
//	    needs: govulncheck                 (a needs key of a job, not a list)
//	    if: failure() || needs.govulncheck.result == 'cancelled'
//
// A key with another case, a list or another value is not allowed.
func gvWeeklyNames(w *workflow) []*yaml.Node {
	var out []*yaml.Node
	if v := gvExactScalar(w, w.root(), "name", gvName); v != nil {
		out = append(out, v)
	}
	jobs, _ := gvJobs(w) // gvCalls reports the messages
	for _, j := range jobs {
		if j.id == gvName {
			out = append(out, j.key)
		}
		if v := gvExactScalar(w, j.body, "needs", gvName); v != nil {
			out = append(out, v)
		}
		if v := gvExactScalar(w, j.body, "if", gvFailureIf); v != nil {
			out = append(out, v)
		}
	}
	return out
}

// gvExactScalar returns the value node of key in the mapping m when the key
// has exactly that case and the value is a scalar with exactly the text want.
// Else it returns nil.
func gvExactScalar(w *workflow, m *yaml.Node, key, want string) *yaml.Node {
	k, v, err := w.lookup(m, key)
	if err != nil || k == nil || k.Value != key {
		return nil
	}
	if v.Kind != yaml.ScalarNode || v.Value != want {
		return nil
	}
	return v
}

// gvContinueOnError returns one message for each continue-on-error key of w,
// in file order. The compare ignores case and the spaces around the key.
func gvContinueOnError(w *workflow) []string {
	var msgs []string
	gvWalk(w.root(), func(n *yaml.Node) {
		if n.Kind != yaml.MappingNode {
			return
		}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if strings.EqualFold(strings.TrimSpace(k.Value), "continue-on-error") {
				msgs = append(msgs, fmt.Sprintf("%s:%d: continue-on-error is not allowed in this file: a step that cannot fail would hide a vulnerability", w.file, k.Line))
			}
		}
	})
	return msgs
}

// gvCheckOthers returns one message for each workflow that is not in the
// list and names govulncheck. The message has the line of the first such
// scalar.
func gvCheckOthers(wfs map[string]*workflow) []string {
	listed := make(map[string]bool)
	for _, p := range gvListedPaths() {
		listed[p] = true
	}
	// Go visits a map in a random order, so sort the paths for stable output.
	paths := make([]string, 0, len(wfs))
	for p := range wfs {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	var msgs []string
	for _, p := range paths {
		w := wfs[p]
		if listed[p] || !gvUsable(w) {
			continue
		}
		for _, s := range w.scalars() {
			if gvNamesTool(s.Value) {
				msgs = append(msgs, fmt.Sprintf("%s:%d: the workflow names govulncheck. Only ci.yml, release.yml and govulncheck.yml may. To add a workflow, add it to gvListedPaths in internal/pincheck/govulncheck.go", w.file, s.Line))
				break
			}
		}
	}
	return msgs
}

// gvNamesTool reports whether s names govulncheck, in any case.
func gvNamesTool(s string) bool {
	return strings.Contains(strings.ToLower(s), gvName)
}

// gvWalk calls visit for n and for every node below it, in file order.
// parseWorkflow limits the depth, so the recursion is bounded.
func gvWalk(n *yaml.Node, visit func(*yaml.Node)) {
	if n == nil {
		return
	}
	visit(n)
	for _, child := range n.Content {
		gvWalk(child, visit)
	}
}
