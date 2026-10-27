package main

import (
	"maps"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// The govulncheck rules. The rules read the decoded YAML, so quotes, escapes,
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
// version as its scalar value. The pin can be in any mapping of the file:
// GitHub merges the env of the workflow, the job and the step, and the rules
// only need every pin to have the version of ci.yml.

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

// gvPin is one GOVULNCHECK_VERSION pin.
type gvPin struct {
	version string     // the decoded version, such as v1.9.0
	key     *yaml.Node // the key node, for its line
}

// gvListedPaths returns the workflows that may name govulncheck, ci.yml
// first. It is a function and not a package variable, so that no code can
// change the list at run time.
func gvListedPaths() []string {
	return []string{ciPath, releasePath, weeklyPath}
}

// checkGovulncheck returns one message per problem with the govulncheck pin.
// The rules for the listed workflows compare the three files, so they run
// only when all three are in wfs. A missing one gives no message here: check
// reports the missing workflow once, in checkRequired or notLoaded. The rule
// for the other workflows always runs.
func checkGovulncheck(wfs map[string]*workflow) []string {
	others := gvCheckOthers(wfs)
	for _, p := range gvListedPaths() {
		if wfs[p] == nil {
			return others
		}
	}
	want, msgs := gvReferencePin(wfs[ciPath])
	for _, p := range gvListedPaths() {
		msgs = append(msgs, gvCheckListed(p, wfs[p], want)...)
	}
	return append(msgs, others...)
}

// gvReferencePin returns the one pin version of ci.yml. When ci.yml has no
// pin, or pins more than one version, it returns "" and a message.
func gvReferencePin(w *workflow) (string, []string) {
	var versions []string
	for _, p := range gvPins(w) {
		versions = append(versions, p.version)
	}
	version, found := onlyVersion(versions)
	if found == "" {
		return version, nil
	}
	return "", []string{w.errorAt(nil, "the file must pin one version of govulncheck in %s (a full version such as v1.2.3), found: %s", gvPinKey, found).Error()}
}

// gvCheckListed applies the rules for one of the listed workflows. path is
// its key in the map, want is the pin of ci.yml ("" when ci.yml has no single
// pin; gvReferencePin reported that).
func gvCheckListed(path string, w *workflow, want string) []string {
	var msgs []string
	pins := gvPins(w)
	// ci.yml is the reference, so gvReferencePin checked its pins.
	if path != ciPath {
		if len(pins) == 0 {
			msgs = append(msgs, w.errorAt(nil, "the file has no %s pin (a full version such as v1.2.3)", gvPinKey).Error())
		}
		for _, p := range pins {
			if want != "" && p.version != want {
				msgs = append(msgs, w.errorAt(p.key, "the govulncheck pin %s differs from %s, the pin in ci.yml", show(p.version), show(want)).Error())
			}
		}
	}

	calls, callMsgs := gvCalls(w)
	msgs = append(msgs, callMsgs...)
	if len(calls) == 0 {
		msgs = append(msgs, w.errorAt(nil, "no step has the run value %s", gvCall).Error())
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
	if path == weeklyPath {
		for _, n := range gvWeeklyNames(w) {
			allowed[n] = true
		}
	}
	for _, s := range w.scalars() {
		if gvNamesTool(s.Value) && !allowed[s] {
			msgs = append(msgs, w.errorAt(s, "%s names govulncheck, but it is not the %s pin, the call or an allowed name", show(s.Value), gvPinKey).Error())
		}
	}

	return append(msgs, gvContinueOnError(w)...)
}

// gvPins returns the pins of w in file order. A key that is exactly
// GOVULNCHECK_VERSION with a value that is not a full version is not a pin.
// Its key names govulncheck, so the name rule of gvCheckListed reports it.
func gvPins(w *workflow) []gvPin {
	var pins []gvPin
	walk(w.top, func(n *yaml.Node) {
		if n.Kind != yaml.MappingNode {
			return
		}
		// Content of a mapping holds key, value, key, value and so on.
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if k.Value == gvPinKey && v.Kind == yaml.ScalarNode && fullVersion.MatchString(v.Value) {
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
// It reads the jobs with jobsAndProblems, so a bad job does not hide the call
// in a good job, and the messages name only the real problem.
func gvCalls(w *workflow) ([]*yaml.Node, []string) {
	jobs, problems := w.jobsAndProblems()
	var msgs []string
	for _, err := range problems {
		msgs = append(msgs, err.Error())
	}
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

// gvWeeklyNames returns the nodes of govulncheck.yml that may name
// govulncheck besides the pins and the calls. govulncheck.yml needs these
// names for its own name, its job and its failure job, so they are allowed,
// with this exact case only:
//
//	name: govulncheck                      (the top-level name)
//	  govulncheck:                         (a job ID)
//	    needs: govulncheck                 (a needs key of a job, not a list)
//	    if: failure() || needs.govulncheck.result == 'cancelled'
//
// A key with another case, a list or another value is not allowed.
func gvWeeklyNames(w *workflow) []*yaml.Node {
	var out []*yaml.Node
	if v := gvExactScalar(w, w.top, "name", gvName); v != nil {
		out = append(out, v)
	}
	jobs, _ := w.jobsAndProblems() // gvCalls reports the problems
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
	walk(w.top, func(n *yaml.Node) {
		if n.Kind != yaml.MappingNode {
			return
		}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if strings.EqualFold(strings.TrimSpace(k.Value), "continue-on-error") {
				msgs = append(msgs, w.errorAt(k, "continue-on-error is not allowed in this file: a step that cannot fail would hide a vulnerability").Error())
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
	var msgs []string
	// Go visits a map in a random order, so sort the paths for stable output.
	for _, p := range slices.Sorted(maps.Keys(wfs)) {
		w := wfs[p]
		if listed[p] {
			continue
		}
		for _, s := range w.scalars() {
			if gvNamesTool(s.Value) {
				msgs = append(msgs, w.errorAt(s, "the workflow names govulncheck. Only ci.yml, release.yml and govulncheck.yml may. To add a workflow, add it to gvListedPaths in internal/pincheck/govulncheck.go").Error())
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
