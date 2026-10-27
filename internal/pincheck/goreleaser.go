package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// The directories and the names that the GoReleaser rules read. The files are
// ciPath, releasePath and docPath in main.go.
const (
	grGitHubDir  = ".github"
	grActionsDir = "actions" // the directory of the local actions, below .github

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
	path string
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
	// maps.Keys returns an iterator over the keys, and slices.Sorted collects
	// them into a sorted slice. A Go map has no order, so the sort makes the
	// order of the messages stable.
	var scans []grScan
	for _, p := range slices.Sorted(maps.Keys(wfs)) {
		scans = append(scans, grScanWorkflow(p, wfs[p]))
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
				msgs = append(msgs, s.w.errorAt(pin.node, "GORELEASER_VERSION is %s, expected %s (the pin in ci.yml)", show(pin.value), show(want)).Error())
			}
		}
		if s.path == releasePath && len(s.pins) == 0 {
			msgs = append(msgs, s.w.errorAt(nil, "the workflow has no full GORELEASER_VERSION pin in the env of a job, expected %s (the pin in ci.yml)", show(want)).Error())
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
		if s.path != ciPath {
			continue
		}
		var versions []string
		for _, pin := range s.pins {
			versions = append(versions, pin.value)
		}
		version, found := onlyVersion(versions)
		if found == "" {
			return version, ""
		}
		return "", s.w.errorAt(nil, "ci.yml must pin one full version of GoReleaser (GORELEASER_VERSION in the env of a job). Found: %s", found).Error()
	}
	return "", ""
}

// grScanWorkflow applies the rules that need no pin of ci.yml to the workflow
// w, and collects its pins.
func grScanWorkflow(p string, w *workflow) grScan {
	s := grScan{path: p, w: w}
	// The two sets hold the nodes that a rule accepts. A map with pointer keys
	// is a set of nodes: the key is the address of a node, not its text, so a
	// copy of the same text in another place is not in the set.
	okPin := make(map[*yaml.Node]bool)  // pin keys, pin values and version inputs
	okUses := make(map[*yaml.Node]bool) // uses values of goreleaser-action steps

	jobs, err := w.jobs()
	if err != nil {
		s.msgs = append(s.msgs, err.Error())
	}
	for _, j := range jobs {
		hasPin, pins, msgs := grJobPins(w, j, okPin)
		s.pins = append(s.pins, pins...)
		s.msgs = append(s.msgs, msgs...)

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
			s.msgs = append(s.msgs, w.errorAt(j.key, "the job %s has a goreleaser-action step, but its env does not define GORELEASER_VERSION", show(j.id)).Error())
		}
	}

	// Every other text that names the action or the pin fails. This catches a
	// form that the rules above do not read, such as a write to $GITHUB_ENV, a
	// key in another case or a uses value in another form.
	for _, n := range w.scalars() {
		lower := strings.ToLower(n.Value)
		if strings.Contains(lower, grAction) && !okUses[n] {
			s.msgs = append(s.msgs, w.errorAt(n, "the text %s names goreleaser/goreleaser-action, but it is not the uses value of a step that this check reads", show(n.Value)).Error())
		}
		if strings.Contains(lower, grMention) && !okPin[n] {
			s.msgs = append(s.msgs, w.errorAt(n, "the text %s mentions GORELEASER_VERSION in a form this check does not allow. Allowed: the pin GORELEASER_VERSION: <full version> in the env of a job, and the value %s of the version input of a goreleaser-action step", show(n.Value), grVersionInput).Error())
		}
	}
	return s
}

// grJobPins reads the GORELEASER_VERSION entry of the env of the job j. It
// reports whether the env has the key, and returns the pin when its value is a
// full version. It adds the key and the value nodes to okPin.
func grJobPins(w *workflow, j job, okPin map[*yaml.Node]bool) (hasPin bool, pins []grPin, msgs []string) {
	env, err := w.jobEnv(j)
	if err != nil {
		return false, nil, []string{err.Error()}
	}
	if env == nil {
		return false, nil, nil
	}
	for i := 0; i+1 < len(env.Content); i += 2 {
		k, v := env.Content[i], env.Content[i+1]
		if k.Value != grPinKey {
			continue // a key in another case is not a pin; the mention rule fails it
		}
		hasPin = true
		okPin[k], okPin[v] = true, true
		switch {
		case v.Kind != yaml.ScalarNode || v.ShortTag() == "!!null":
			msgs = append(msgs, w.errorAt(v, "the GORELEASER_VERSION pin must be a full version (vMAJOR.MINOR.PATCH), found %s", kindName(v)).Error())
		case !fullVersion.MatchString(v.Value):
			msgs = append(msgs, w.errorAt(v, "the GORELEASER_VERSION pin %s is not a full version (vMAJOR.MINOR.PATCH)", show(v.Value)).Error())
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
		return true, []string{w.errorAt(step, "the goreleaser-action step %s has no with mapping, so it has no version input", label).Error()}
	}
	found := false
	for i := 0; i+1 < len(with.Content); i += 2 {
		k, v := with.Content[i], with.Content[i+1]
		if !strings.EqualFold(k.Value, grVersionKey) {
			continue
		}
		found = true
		switch {
		case k.Value != grVersionKey:
			msgs = append(msgs, w.errorAt(k, "the goreleaser-action step %s has the key %s in its with mapping. Write the version input key as version", label, show(k.Value)).Error())
		case v.Kind != yaml.ScalarNode || v.Value != grVersionInput:
			msgs = append(msgs, w.errorAt(v, "the goreleaser-action step %s has a version input that is not %s", label, grVersionInput).Error())
		default:
			okPin[v] = true
		}
	}
	if !found {
		msgs = append(msgs, w.errorAt(with, "the goreleaser-action step %s has no version input in its with mapping", label).Error())
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
// and that there is at least one. A missing CONTRIBUTING.md gives no message
// here, because checkRequired reports it.
func grCheckDoc(fsys fs.FS, want string) []string {
	data, err := readLimited(fsys, docPath, maxFileBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return []string{fmt.Sprintf("%s: %v", docPath, err)}
	}
	// FindAllSubmatchIndex returns, per match, the start and end offsets of
	// the match and then of each group. -1 means no limit on the matches.
	matches := grDocVersion.FindAllSubmatchIndex(data, -1)
	if len(matches) == 0 {
		return []string{fmt.Sprintf("%s: names no GoReleaser version (goreleaser/vN@<version>), expected %s (the pin in ci.yml)", docPath, show(want))}
	}
	var msgs []string
	for _, m := range matches {
		got := string(data[m[2]:m[3]])
		if got == want {
			continue
		}
		line := bytes.Count(data[:m[0]], []byte("\n")) + 1
		msgs = append(msgs, fmt.Sprintf("%s:%d: the GoReleaser version %s differs from the pin %s in ci.yml", docPath, line, show(got), show(want)))
	}
	return msgs
}

// grCheckActions fails each file under .github/actions that names
// goreleaser-action, because this check does not read the local actions. A
// symlink there fails too, because the check does not follow it. A missing
// .github/actions is fine.
func grCheckActions(fsys fs.FS) []string {
	entries, err := fs.ReadDir(fsys, grGitHubDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return []string{fmt.Sprintf("%s: read the directory: %v", grGitHubDir, err)}
	}
	var msgs []string
	for _, e := range entries {
		// GitHub runs on a file system where case matters, but a uses path
		// can name .github/Actions too. So every case of the name counts.
		if !strings.EqualFold(e.Name(), grActionsDir) {
			continue
		}
		dir := path.Join(grGitHubDir, e.Name())
		if e.Type()&fs.ModeSymlink != 0 {
			msgs = append(msgs, fmt.Sprintf("%s: is a symlink. This check does not follow symlinks under .github/actions", dir))
			continue
		}
		msgs = append(msgs, grWalkActions(fsys, dir)...)
	}
	return msgs
}

// grWalkActions walks the tree dir and returns the problems. fs.WalkDir does
// not follow a symlink to a directory: it reports the link as an entry with
// the ModeSymlink type, so grWalkActions can fail it.
func grWalkActions(fsys fs.FS, dir string) []string {
	var msgs []string
	walkErr := fs.WalkDir(fsys, dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			// Report the problem and go on with the other entries.
			msgs = append(msgs, fmt.Sprintf("%s: read: %v", p, err))
			return nil
		}
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			msgs = append(msgs, fmt.Sprintf("%s: is a symlink. This check does not follow symlinks under .github/actions", p))
			return nil
		case d.IsDir():
			return nil
		case !d.Type().IsRegular():
			msgs = append(msgs, fmt.Sprintf("%s: is not a regular file. This check reads only regular files under .github/actions", p))
			return nil
		}
		data, err := readLimited(fsys, p, maxFileBytes)
		if err != nil {
			msgs = append(msgs, fmt.Sprintf("%s: %v", p, err))
			return nil
		}
		if bytes.Contains(bytes.ToLower(data), []byte(grAction)) {
			msgs = append(msgs, fmt.Sprintf("%s: names goreleaser/goreleaser-action. This check does not read .github/actions. Extend the check before you add such a file", p))
		}
		return nil
	})
	if walkErr != nil {
		msgs = append(msgs, fmt.Sprintf("%s: walk: %v", dir, walkErr))
	}
	return msgs
}
