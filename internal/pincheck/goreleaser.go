package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

// The directories and the names that the GoReleaser rules read. The files are
// ciPath, releasePath and docPath in main.go.
const (
	grActionsDir = "actions" // the directory of the local actions, below .github
	// grActionsPath is the directory of the local actions, relative to the root.
	grActionsPath = githubDir + "/" + grActionsDir

	// grPinKey is the env key of the pin. The key must have this exact case.
	grPinKey = "GORELEASER_VERSION"
	// grVersionKey is the key of the version input in the with mapping of a
	// goreleaser-action step. The key must have this exact case.
	grVersionKey = "version"
	// grVersionInput is the only allowed value of the version input.
	grVersionInput = "${{ env.GORELEASER_VERSION }}"
	// grAction is the action, in lower case. A uses value is this text, or
	// this text and "@" and a ref, in any case.
	grAction = "goreleaser/goreleaser-action"
	// grMention is the text, in lower case, that marks a use of the pin.
	grMention = "goreleaser_version"
)

// grDocVersion finds a GoReleaser version in CONTRIBUTING.md, such as
// "goreleaser/v2@v2.19.0". Group 1 is the text after the @, up to a space, a
// backtick or a double quote. The counts are bounded: a longer text is cut, so
// it differs from the pin and fails.
var grDocVersion = regexp.MustCompile("goreleaser(?:/v[0-9]{1,9})?@([^[:space:]`\"]{1,256})")

// grPin is one GORELEASER_VERSION entry with a full version in the env of a
// job.
type grPin struct {
	node  *yaml.Node // the value node, for its line
	value string     // the version
}

// grScan is what grScanWorkflow found in one workflow.
type grScan struct {
	w    *workflow
	pins []grPin  // the pins with a full version, in file order
	msgs []string // the problems that do not need the pin of ci.yml
}

// checkGoreleaser returns one message per problem with the GoReleaser pin.
// When ci.yml or release.yml is not in wfs, the rules that need it do not run
// and give no message: check reports the missing workflow once, in
// checkRequired or notLoaded.
func checkGoreleaser(fsys fs.FS, wfs map[string]*workflow) []string {
	var msgs []string
	var scans []grScan
	for _, p := range sortedPaths(wfs) {
		scans = append(scans, grScanWorkflow(wfs[p]))
	}

	want, msg := grWant(scans)
	if msg != "" {
		msgs = append(msgs, msg)
	}
	for _, s := range scans {
		msgs = append(msgs, s.msgs...)
		if want == "" {
			continue
		}
		for _, pin := range s.pins {
			if pin.value != want {
				msgs = append(msgs, s.w.problemAt(pin.node, "GORELEASER_VERSION is %s, expected %s (the pin in %s)", show(pin.value), show(want), ciName))
			}
		}
		if s.w.file == releasePath && len(s.pins) == 0 {
			msgs = append(msgs, s.w.problemAt(nil, "the workflow has no full GORELEASER_VERSION pin in the env of a job, expected %s (the pin in %s)", show(want), ciName))
		}
	}
	if want != "" {
		msgs = append(msgs, grCheckDoc(fsys, want)...)
	}
	return append(msgs, grCheckActions(fsys)...)
}

// grWant returns the pin of ci.yml. ci.yml must pin exactly one full version
// (it may repeat it in more jobs). Otherwise grWant returns an empty pin and a
// message. It returns no pin and no message when ci.yml is not in scans,
// because check reports a missing workflow.
func grWant(scans []grScan) (want, msg string) {
	for _, s := range scans {
		if s.w.file != ciPath {
			continue
		}
		var versions []string
		for _, pin := range s.pins {
			versions = append(versions, pin.value)
		}
		version, ok, found := onlyVersion(versions)
		if ok {
			return version, ""
		}
		return "", s.w.problemAt(nil, "%s must pin one full version of GoReleaser (GORELEASER_VERSION in the env of a job). Found: %s", ciName, found)
	}
	return "", ""
}

// grScanWorkflow applies the rules that need no pin of ci.yml to the workflow
// w, and collects its pins. w.file is the path of the workflow.
func grScanWorkflow(w *workflow) grScan {
	s := grScan{w: w}
	// The two sets hold the nodes that a rule accepts. A map with pointer keys
	// is a set of nodes: the key is the address of a node, not its text, so a
	// copy of the same text in another place is not in the set.
	okPin := make(map[*yaml.Node]bool)  // pin keys, pin values and version inputs
	okUses := make(map[*yaml.Node]bool) // uses values of goreleaser-action steps

	// jobsAndProblems keeps the good jobs when one job is bad. A rule that
	// gave up at the first bad job would drop all the jobs, and the scalar
	// scan below would then fail every pin and uses value of the file. The
	// text of a bad-job problem is the same as in the govulncheck rule, so
	// dedupe keeps one line.
	jobs, problems := w.jobsAndProblems()
	s.msgs = append(s.msgs, errorStrings(problems)...)
	for _, j := range jobs {
		hasPin, pins, msgs := grJobPins(w, j, okPin)
		s.pins = append(s.pins, pins...)
		s.msgs = append(s.msgs, msgs...)

		// w.steps reads the key steps ignoring case, on purpose: a Steps: key is
		// read as steps, so the rules below cover its steps too.
		steps, err := w.steps(j)
		if err != nil {
			s.msgs = append(s.msgs, err.Error())
		}
		hasStep := false
		for _, step := range steps {
			isAction, msgs := grCheckStep(w, step, okPin, okUses)
			hasStep = hasStep || isAction
			s.msgs = append(s.msgs, msgs...)
		}
		if hasStep && !hasPin {
			s.msgs = append(s.msgs, w.problemAt(j.key, "the job %s has a goreleaser-action step, but its env does not define GORELEASER_VERSION", show(j.id)))
		}
	}

	// Every other text that names the action or the pin fails. This catches a
	// form that the rules above do not read, such as a write to $GITHUB_ENV, a
	// key in another case or a uses value in another form.
	for _, n := range w.scalars() {
		lower := strings.ToLower(n.Value)
		if strings.Contains(lower, grAction) && !okUses[n] {
			s.msgs = append(s.msgs, w.problemAt(n, "the text %s names goreleaser/goreleaser-action, but it is not the uses value of a step that this check reads", show(n.Value)))
		}
		if strings.Contains(lower, grMention) && !okPin[n] {
			s.msgs = append(s.msgs, w.problemAt(n, "the text %s mentions GORELEASER_VERSION in a form this check does not allow. Allowed: the pin GORELEASER_VERSION: <full version> in the env of a job, and the value %s of the version input of a goreleaser-action step", show(n.Value), grVersionInput))
		}
	}
	return s
}

// grJobPins reads the GORELEASER_VERSION entry of the env of the job j. It
// reports whether the env has the key, and returns the pin when its value is a
// full version. It adds the key and the value nodes to okPin.
func grJobPins(w *workflow, j job, okPin map[*yaml.Node]bool) (hasPin bool, pins []grPin, msgs []string) {
	// An env that is not a mapping, such as an expression, is an error.
	env, err := w.mappingAt(j.body, "env")
	if err != nil {
		return false, nil, []string{err.Error()}
	}
	if env == nil {
		return false, nil, nil
	}
	for k, v := range pairs(env) {
		if k.Value != grPinKey {
			continue // a key in another case is not a pin; the mention rule fails it
		}
		hasPin = true
		okPin[k], okPin[v] = true, true
		switch {
		case v.Kind != yaml.ScalarNode || v.ShortTag() == "!!null":
			msgs = append(msgs, w.problemAt(v, "the GORELEASER_VERSION pin must be a full version (vMAJOR.MINOR.PATCH), found %s", kindName(v)))
		case !fullVersion.MatchString(v.Value):
			msgs = append(msgs, w.problemAt(v, "the GORELEASER_VERSION pin %s is not a full version (vMAJOR.MINOR.PATCH)", show(v.Value)))
		default:
			pins = append(pins, grPin{node: v, value: v.Value})
		}
	}
	return hasPin, pins, msgs
}

// grCheckStep checks one step. It reports whether the step uses
// goreleaser-action. Such a step must have with.version equal to
// grVersionInput. It adds the uses value to okUses and an allowed version
// input to okPin.
func grCheckStep(w *workflow, step *yaml.Node, okPin, okUses map[*yaml.Node]bool) (isAction bool, msgs []string) {
	// The keys uses and with are read with lookup, which ignores case. This is
	// deliberate: a Uses: key is read as uses, so the GoReleaser rules overmatch
	// and a key in another case cannot hide a step.
	uses, err := w.scalarAt(step, "uses")
	if err != nil {
		return false, []string{err.Error()}
	}
	if uses == nil || !grIsAction(uses.Value) {
		return false, nil
	}
	okUses[uses] = true
	label := show(grStepLabel(w, step, uses))

	with, err := w.mappingAt(step, "with")
	if err != nil {
		return true, []string{err.Error()}
	}
	if with == nil {
		return true, []string{w.problemAt(step, "the goreleaser-action step %s has no with mapping, so it has no version input", label)}
	}
	found := false
	for k, v := range pairs(with) {
		if !strings.EqualFold(k.Value, grVersionKey) {
			continue
		}
		found = true
		switch {
		case k.Value != grVersionKey:
			msgs = append(msgs, w.problemAt(k, "the goreleaser-action step %s has the key %s in its with mapping. Write the version input key as version", label, show(k.Value)))
		case v.Kind != yaml.ScalarNode || v.Value != grVersionInput:
			msgs = append(msgs, w.problemAt(v, "the goreleaser-action step %s has a version input that is not %s", label, grVersionInput))
		default:
			okPin[v] = true
		}
	}
	if !found {
		msgs = append(msgs, w.problemAt(with, "the goreleaser-action step %s has no version input in its with mapping", label))
	}
	return true, msgs
}

// grIsAction reports whether the decoded uses value s is goreleaser-action:
// the action name alone or with "@" and a ref, in any case.
func grIsAction(s string) bool {
	lower := strings.ToLower(s)
	return lower == grAction || strings.HasPrefix(lower, grAction+"@")
}

// grStepLabel names a step for a message: its name when it has a text name,
// else its uses value.
func grStepLabel(w *workflow, step, uses *yaml.Node) string {
	_, name, err := w.lookup(step, "name")
	if err == nil && name != nil && name.Kind == yaml.ScalarNode && name.Value != "" {
		return name.Value
	}
	return uses.Value
}

// grCheckDoc checks that every GoReleaser version in CONTRIBUTING.md is want,
// and that there is at least one. A CONTRIBUTING.md that is missing, that
// fs.Stat cannot read or that is not a regular file gives no message here,
// because checkRequired reports it.
func grCheckDoc(fsys fs.FS, want string) []string {
	info, err := fs.Stat(fsys, docPath)
	if err != nil || !info.Mode().IsRegular() {
		return nil
	}
	data, err := readLimited(fsys, docPath)
	if err != nil {
		return []string{fmt.Sprintf("%s: %v", docPath, err)}
	}
	// FindAllSubmatchIndex returns, per match, the start and end offsets of
	// the match and then of each group. -1 means no limit on the matches.
	matches := grDocVersion.FindAllSubmatchIndex(data, -1)
	if len(matches) == 0 {
		return []string{fmt.Sprintf("%s: names no GoReleaser version (goreleaser/vN@<version>), expected %s (the pin in %s)", docPath, show(want), ciName)}
	}
	var msgs []string
	for _, m := range matches {
		got := string(data[m[2]:m[3]])
		if got == want {
			continue
		}
		line := bytes.Count(data[:m[0]], []byte("\n")) + 1
		msgs = append(msgs, fmt.Sprintf("%s:%d: the GoReleaser version %s differs from the pin %s in %s", docPath, line, show(got), show(want), ciName))
	}
	return msgs
}

// grCheckActions fails each file under .github/actions that names
// goreleaser-action, because this check does not read the local actions. A
// symlink there fails too, because the check does not follow it. A missing
// .github/actions is fine.
func grCheckActions(fsys fs.FS) []string {
	entries, err := fs.ReadDir(fsys, githubDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return []string{fmt.Sprintf("%s: read the directory: %v", githubDir, noPath(err))}
	}
	var msgs []string
	for _, e := range entries {
		// GitHub runs on a file system where case matters, but a uses path
		// can name .github/Actions too. So every case of the name counts.
		if !strings.EqualFold(e.Name(), grActionsDir) {
			continue
		}
		dir := path.Join(githubDir, e.Name())
		if e.Type()&fs.ModeSymlink != 0 {
			msgs = append(msgs, symlinkUnder(dir, grActionsPath))
			continue
		}
		msgs = append(msgs, grWalkActions(fsys, dir)...)
	}
	return msgs
}

// symlinkUnder returns the problem for the symlink p, which is under dir. The
// check does not follow a symlink, so it fails the link. grCheckActions and
// grWalkActions both use it, so their text is the same.
func symlinkUnder(p, dir string) string {
	return fmt.Sprintf("%s: is a symlink. This check does not follow symlinks under %s", p, dir)
}

// grWalkActions walks the tree dir and returns the problems. fs.WalkDir does
// not follow a symlink to a directory: it reports the link as an entry with
// the ModeSymlink type, so grWalkActions can fail it.
func grWalkActions(fsys fs.FS, dir string) []string {
	var msgs []string
	walkErr := fs.WalkDir(fsys, dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			// Report the problem and go on with the other entries.
			msgs = append(msgs, fmt.Sprintf("%s: read: %v", p, noPath(err)))
			return nil
		}
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			msgs = append(msgs, symlinkUnder(p, grActionsPath))
			return nil
		case d.IsDir():
			return nil
		case !d.Type().IsRegular():
			msgs = append(msgs, fmt.Sprintf("%s: is not a regular file. This check reads only regular files under %s", p, grActionsPath))
			return nil
		}
		data, err := readLimited(fsys, p)
		if err != nil {
			msgs = append(msgs, fmt.Sprintf("%s: %v", p, err))
			return nil
		}
		if msg := grActionProblem(p, data); msg != "" {
			msgs = append(msgs, msg)
		}
		return nil
	})
	if walkErr != nil {
		msgs = append(msgs, fmt.Sprintf("%s: walk: %v", dir, noPath(walkErr)))
	}
	return msgs
}

// grActionProblem returns the one problem of the file p under .github/actions,
// with its bytes data, or "" when the file is fine. Every file is searched as
// raw bytes, in any case. A file named .yml or .yaml is also parsed with
// parseWorkflow, so that its decoded scalars are searched too. A YAML escape
// such as \x2d can hide the name in the raw bytes, but not in the decoded text.
// A YAML file that does not parse fails closed, with the error of parseWorkflow,
// which starts with the path. The raw hit and the decoded hit give the same text.
func grActionProblem(p string, data []byte) string {
	if bytes.Contains(bytes.ToLower(data), []byte(grAction)) {
		return grActionText(p)
	}
	if !grIsYAMLName(p) {
		return ""
	}
	w, err := parseWorkflow(p, data)
	if err != nil {
		return err.Error()
	}
	for _, n := range w.scalars() {
		if strings.Contains(strings.ToLower(n.Value), grAction) {
			return grActionText(p)
		}
	}
	return ""
}

// grActionText returns the problem of the file p, which names the action.
func grActionText(p string) string {
	return fmt.Sprintf("%s: names goreleaser/goreleaser-action. This check does not read %s. Extend the check before you add such a file", p, grActionsPath)
}

// grIsYAMLName reports whether the file name p ends in .yml or .yaml, in any case.
func grIsYAMLName(p string) bool {
	ext := strings.ToLower(path.Ext(p))
	return ext == ".yml" || ext == ".yaml"
}
