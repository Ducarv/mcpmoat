package main

import (
	"path"
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
//   - govulncheck.yml has a job with the ID gvName, and that job runs gvCall.
//     notify-failure waits for that job.
//   - In the three files, a job that has such a step has no job-level if: key
//     and no job-level needs: key. GitHub skips a job whose if is false, and
//     it skips a job that waits for a skipped job. Then the scan does not run.
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

// gvListedNames returns the base names of gvListedPaths for a message, such as
// "ci.yml, release.yml and govulncheck.yml".
func gvListedNames() string {
	var names []string
	for _, p := range gvListedPaths() {
		names = append(names, path.Base(p))
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
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
		msgs = append(msgs, gvCheckListed(wfs[p], want)...)
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
	version, ok, found := onlyVersion(versions)
	if ok {
		return version, nil
	}
	return "", []string{w.problemAt(nil, "the file must pin one version of govulncheck in %s (a full version such as v1.2.3), found: %s", gvPinKey, found)}
}

// gvCheckListed applies the rules for one of the listed workflows. w.file is
// its path, and want is the pin of ci.yml ("" when ci.yml has no single pin;
// gvReferencePin reported that).
func gvCheckListed(w *workflow, want string) []string {
	var msgs []string
	pins := gvPins(w)
	// ci.yml is the reference, so gvReferencePin checked its pins.
	if w.file != ciPath {
		if len(pins) == 0 {
			msgs = append(msgs, w.problemAt(nil, "the file has no %s pin (a full version such as v1.2.3)", gvPinKey))
		}
		for _, pin := range pins {
			if want != "" && pin.version != want {
				msgs = append(msgs, w.problemAt(pin.key, "the govulncheck pin %s differs from %s, the pin in %s", show(pin.version), show(want), ciName))
			}
		}
	}

	// jobs is read once here and passed to the rules. gvScanJobs reports the
	// problems of the jobs and the steps, so each one is reported once.
	jobs, jobMsgs := gvScanJobs(w)
	msgs = append(msgs, jobMsgs...)
	var calls []*yaml.Node
	for _, j := range jobs {
		calls = append(calls, j.calls...)
	}
	if len(calls) == 0 {
		msgs = append(msgs, w.problemAt(nil, "no step has the run value %s", gvCall))
	}
	msgs = append(msgs, gvJobSkipProblems(w, jobs)...)
	if w.file == weeklyPath {
		msgs = append(msgs, gvNameJobProblems(w, jobs)...)
	}

	// allowed holds the nodes that may name govulncheck. A map with pointer
	// keys compares node identity, not text: the same text in another place
	// is a different node and is not allowed.
	allowed := make(map[*yaml.Node]bool)
	for _, pin := range pins {
		allowed[pin.key] = true
	}
	for _, c := range calls {
		allowed[c] = true
	}
	if w.file == weeklyPath {
		for _, n := range gvWeeklyNames(w, jobs) {
			allowed[n] = true
		}
	}
	for _, s := range w.scalars() {
		if gvNamesTool(s.Value) && !allowed[s] {
			msgs = append(msgs, w.problemAt(s, "%s names govulncheck, but it is not the %s pin, the call or an allowed name", show(s.Value), gvPinKey))
		}
	}

	return append(msgs, gvContinueOnError(w)...)
}

// gvPins returns the pins of w in file order. A key that is exactly
// GOVULNCHECK_VERSION with a value that is not a full version is not a pin.
// Its key names govulncheck, so the name rule of gvCheckListed reports it.
func gvPins(w *workflow) []gvPin {
	var pins []gvPin
	for k, v := range w.allPairs() {
		if k.Value == gvPinKey && v.Kind == yaml.ScalarNode && fullVersion.MatchString(v.Value) {
			pins = append(pins, gvPin{version: v.Value, key: k})
		}
	}
	return pins
}

// gvJob is a job of a workflow with the run value nodes of its govulncheck
// calls. calls is empty for a job that runs no call. It is also empty for a
// job whose steps are not a list of mappings, because gvJobCalls returns no
// calls then.
type gvJob struct {
	job
	calls []*yaml.Node
}

// gvScanJobs returns the jobs of w in file order, each with its calls, and the
// messages for the problems of the jobs and of their steps. It is the one place
// that reports these problems, so each one is reported once. It reads the jobs
// with jobsAndProblems, so a bad job does not hide the call in a good job. A
// job whose steps are broken stays in the list, with no calls, so that the name
// rules still see its keys. A run value that is not a scalar is not a call;
// the name rule still reads it.
func gvScanJobs(w *workflow) ([]gvJob, []string) {
	jobs, problems := w.jobsAndProblems()
	msgs := errorStrings(problems)
	out := make([]gvJob, 0, len(jobs))
	for _, j := range jobs {
		calls, err := gvJobCalls(w, j)
		if err != nil {
			msgs = append(msgs, err.Error())
		}
		out = append(out, gvJob{job: j, calls: calls})
	}
	return out, msgs
}

// gvJobCalls returns the run value nodes of the steps of the job j that are
// exactly gvCall. It returns an error when the steps of j are not a sequence of
// mappings. A job that returns no call does not run govulncheck.
//
// GitHub reads the keys steps and run with their exact spelling. So a job with
// the key Steps has no steps, and a step with the key Run has no run value. This
// function reads only the exact keys, with exactPair and exactValue. The name
// rule still reports the text of such a call.
func gvJobCalls(w *workflow, j job) ([]*yaml.Node, error) {
	k, seq := exactPair(j.body, "steps")
	if seq == nil {
		return nil, nil
	}
	if seq.Kind != yaml.SequenceNode {
		return nil, w.wrongKind(k, seq, yaml.SequenceNode)
	}
	var calls []*yaml.Node
	for _, s := range seq.Content {
		if s.Kind != yaml.MappingNode {
			return nil, w.errorAt(s, "a step of the job %s must be a mapping, found %s", show(j.id), kindName(s))
		}
		run := exactValue(s, "run")
		if run == nil || run.Kind != yaml.ScalarNode {
			continue
		}
		if run.Value == gvCall {
			calls = append(calls, run)
		}
	}
	return calls, nil
}

// exactPair returns the key node and the value node of the key whose text is
// exactly name in the mapping m. It returns two nil nodes when m has no such key.
// The caller must check first that m is a mapping. It is for the keys that
// GitHub reads case-sensitively. lookup ignores case, so it is not used here.
func exactPair(m *yaml.Node, name string) (*yaml.Node, *yaml.Node) {
	for k, v := range pairs(m) {
		if k.Value == name {
			return k, v
		}
	}
	return nil, nil
}

// exactValue returns the value node of the key whose text is exactly name in the
// mapping m, or nil when m has no such key. See exactPair.
func exactValue(m *yaml.Node, name string) *yaml.Node {
	_, v := exactPair(m, name)
	return v
}

// gvNameJobProblems returns one message when govulncheck.yml has no job with the
// ID gvName, or when the job with that ID runs no call. notify-failure waits for
// the job with that ID (needs: govulncheck). So the job with that ID must be the
// job that runs the scan. Else a job renamed to scan, and a job named govulncheck
// that runs nothing, would pass the other rules. jobs comes from gvScanJobs.
func gvNameJobProblems(w *workflow, jobs []gvJob) []string {
	for _, j := range jobs {
		if j.id != gvName {
			continue
		}
		if len(j.calls) == 0 {
			return []string{w.problemAt(j.key, "the job %s must run the govulncheck call: notify-failure waits for it", show(gvName))}
		}
		return nil
	}
	return []string{w.problemAt(nil, "the job %s is missing: notify-failure waits for it", show(gvName))}
}

// gvJobSkipProblems returns one message for each job that runs the govulncheck
// call and has a job-level if: or needs: key. GitHub skips a job whose if is
// false. It also skips a job that waits for a skipped job. Then the scan would
// not run while the pin check still passes. A step-level if is not read here.
func gvJobSkipProblems(w *workflow, jobs []gvJob) []string {
	var msgs []string
	for _, j := range jobs {
		if len(j.calls) == 0 {
			continue
		}
		for k := range pairs(j.body) {
			switch {
			case keyIs(k, "if"):
				msgs = append(msgs, w.problemAt(k, "the job %s runs govulncheck, so it must not have a job-level if: a skipped job would hide a vulnerability", show(j.id)))
			case keyIs(k, "needs"):
				msgs = append(msgs, w.problemAt(k, "the job %s runs govulncheck, so it must not have a job-level needs: a skipped job it waits for would skip the scan too", show(j.id)))
			}
		}
	}
	return msgs
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
// The needs and the if names are allowed only in a job that runs no call. A
// job that runs the call must not have a job-level if or needs (see
// gvJobSkipProblems), so the scan cannot be skipped. A key with another case,
// a list or another value is not allowed. jobs comes from gvScanJobs.
func gvWeeklyNames(w *workflow, jobs []gvJob) []*yaml.Node {
	var out []*yaml.Node
	if v := gvExactScalar(w.top, "name", gvName); v != nil {
		out = append(out, v)
	}
	for _, j := range jobs {
		if j.id == gvName {
			out = append(out, j.key)
		}
		if len(j.calls) > 0 {
			continue // a job that runs the call may not name needs or if
		}
		if v := gvExactScalar(j.body, "needs", gvName); v != nil {
			out = append(out, v)
		}
		if v := gvExactScalar(j.body, "if", gvFailureIf); v != nil {
			out = append(out, v)
		}
	}
	return out
}

// gvExactScalar returns the value node of key in the mapping m when the key
// has exactly that case and the value is a scalar with exactly the text want.
// Else it returns nil. m must be a mapping.
func gvExactScalar(m *yaml.Node, key, want string) *yaml.Node {
	v := exactValue(m, key)
	if v == nil || v.Kind != yaml.ScalarNode || v.Value != want {
		return nil
	}
	return v
}

// gvContinueOnError returns one message for each continue-on-error key of w,
// in the order of allPairs. The compare is keyIs: it ignores case and the spaces
// around the key.
func gvContinueOnError(w *workflow) []string {
	var msgs []string
	for k := range w.allPairs() {
		if keyIs(k, "continue-on-error") {
			msgs = append(msgs, w.problemAt(k, "continue-on-error is not allowed in this file: a step that cannot fail would hide a vulnerability"))
		}
	}
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
	names := gvListedNames()
	var msgs []string
	for _, p := range sortedPaths(wfs) {
		if listed[p] {
			continue
		}
		w := wfs[p]
		for _, s := range w.scalars() {
			if gvNamesTool(s.Value) {
				msgs = append(msgs, w.problemAt(s, "the workflow names govulncheck. Only %s may. To add a workflow, add it to gvListedPaths in internal/pincheck/govulncheck.go", names))
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
