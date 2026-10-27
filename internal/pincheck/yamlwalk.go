package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Limits for one workflow file. The workflows of this repository are about
// 10 KiB each, so the limits are far above real use. They stop a hostile or
// broken file before the checks walk it.
const (
	// maxWorkflowBytes is the largest workflow file that parseWorkflow
	// accepts (1 MiB). The check runs before any YAML decoding.
	maxWorkflowBytes = 1 << 20
	// maxNodeDepth is the deepest nesting of YAML nodes that parseWorkflow
	// accepts. The document node has depth 0 and the top mapping depth 1.
	maxNodeDepth = 64
)

// Limits for the text of a message. A key, a value or a name in a workflow
// can be about 1 MiB long, so every message cuts such a text. Then a hostile
// file cannot make one message flood the log.
const (
	// maxShown is the most bytes of a text from a workflow file that a
	// message shows: a key, a job ID, a scalar value, a version, an anchor,
	// an alias or a tag.
	maxShown = 80
	// maxCauseShown is the most bytes of the text of a YAML decoder error or
	// panic that a message shows. It is larger than maxShown, because a
	// decoder error is fixed text, such as "yaml: line 3: did not find
	// expected key", but it can hold an anchor name from the file.
	maxCauseShown = 200
)

// nodeError is a problem in one workflow file. Every error that this file
// returns for a workflow is a *nodeError, so the message always names the
// file and, when it is known, the line.
type nodeError struct {
	file string // the file name, as the caller gave it to parseWorkflow
	line int    // the 1-based line, or 0 when no line applies
	msg  string // the problem, without the file and the line
	err  error  // the cause, or nil
}

// Error returns "file:line: msg", or "file: msg" when the line is 0. When
// there is a cause, ": cause" follows, cut to maxCauseShown bytes.
func (e *nodeError) Error() string {
	s := e.file + ": " + e.msg
	if e.line > 0 {
		s = fmt.Sprintf("%s:%d: %s", e.file, e.line, e.msg)
	}
	if e.err != nil {
		s += ": " + cutText(e.err.Error(), maxCauseShown)
	}
	return s
}

// Unwrap returns the cause, so that errors.Is and errors.As see it.
func (e *nodeError) Unwrap() error {
	return e.err
}

// workflow is one parsed workflow file. parseWorkflow makes it. Its nodes
// passed the checks of checkNode, so they hold no alias, no anchor, no merge
// key, no explicit tag, no key that is not a plain ASCII scalar and no
// duplicate key.
type workflow struct {
	file string     // the file name for messages
	top  *yaml.Node // the top-level mapping of the only document
}

// job is one entry of the jobs mapping of a workflow.
type job struct {
	id   string     // the job ID: the key under jobs
	key  *yaml.Node // the key node of the job ID, for its line
	body *yaml.Node // the job mapping
}

// parseWorkflow parses the bytes of one workflow file. file names the file in
// every error. It fails closed: any input that the checks cannot read with
// certainty gives an error. These are:
//   - input larger than maxWorkflowBytes
//   - a YAML parse error, or a panic of the YAML decoder
//   - no document, or more than one document
//   - a top-level node that is not a mapping
//   - an alias (*name), an anchor (&name) or a merge key (<<)
//   - an explicit tag, such as !!str (the non-specific tag "!" leaves no mark
//     in the node, so it is not detected; it cannot change a value)
//   - a mapping key that is not a scalar, or that has a non-ASCII byte
//   - two keys in one mapping that are equal when compared case-insensitively
//   - nesting deeper than maxNodeDepth
//
// Flow style, quoted keys and values, and escapes are accepted. The decoder
// decodes them, so the checks read Node.Value and never the raw text.
func parseWorkflow(file string, data []byte) (*workflow, error) {
	w := &workflow{file: file}
	if len(data) > maxWorkflowBytes {
		return nil, w.errorAt(nil, "the file has %d bytes, more than the limit of %d", len(data), maxWorkflowBytes)
	}
	doc, err := w.decodeOne(data)
	if err != nil {
		return nil, err
	}
	if err := w.checkNode(doc, 0); err != nil {
		return nil, err
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, w.errorAt(doc, "the top level of the workflow must be a mapping")
	}
	w.top = doc.Content[0]
	return w, nil
}

// decodeOne decodes data and returns its only document node. It reads the
// whole stream, because yaml.Unmarshal would drop a second document without
// an error.
//
// yaml.v3 panics on some malformed inputs (an "internal error" in the
// parser). The deferred recover turns such a panic into an error, so that a
// bad file cannot crash the checker.
func (w *workflow) decodeOne(data []byte) (doc *yaml.Node, err error) {
	defer func() {
		if r := recover(); r != nil {
			doc = nil
			err = w.errorAt(nil, "the YAML decoder failed: %s", cutText(fmt.Sprint(r), maxCauseShown))
		}
	}()
	dec := yaml.NewDecoder(bytes.NewReader(data))
	for {
		var n yaml.Node
		decErr := dec.Decode(&n)
		if errors.Is(decErr, io.EOF) {
			break
		}
		if decErr != nil {
			// The yaml error text names the line, such as "yaml: line 3: ...".
			return nil, &nodeError{file: w.file, msg: "parse YAML", err: decErr}
		}
		if doc != nil {
			return nil, w.errorAt(&n, "the file has more than one YAML document")
		}
		doc = &n
	}
	if doc == nil {
		return nil, w.errorAt(nil, "the file has no YAML document")
	}
	return doc, nil
}

// checkNode checks n and every node below it against the rules of
// parseWorkflow. depth is the nesting depth of n.
func (w *workflow) checkNode(n *yaml.Node, depth int) error {
	if depth > maxNodeDepth {
		return w.errorAt(n, "the YAML nesting is deeper than %d", maxNodeDepth)
	}
	if n.Kind == yaml.AliasNode {
		return w.errorAt(n, "an alias (*%s) is not allowed", cutText(n.Value, maxShown))
	}
	if n.Anchor != "" {
		return w.errorAt(n, "an anchor (&%s) is not allowed", cutText(n.Anchor, maxShown))
	}
	if n.Style&yaml.TaggedStyle != 0 {
		return w.errorAt(n, "an explicit tag (%s) is not allowed", cutText(n.Tag, maxShown))
	}
	if n.Kind == yaml.MappingNode {
		if err := w.checkKeys(n); err != nil {
			return err
		}
	}
	for _, child := range n.Content {
		if err := w.checkNode(child, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// checkKeys checks the keys of the mapping m: each key is a plain ASCII
// scalar, no key is the merge key <<, and no two keys are equal when compared
// case-insensitively. A key with a non-ASCII byte fails, so that the
// case-insensitive compare is exact (Unicode case folding has corner cases,
// such as the long s that folds to s).
func (w *workflow) checkKeys(m *yaml.Node) error {
	seen := make(map[string]int) // the folded key and the line of its first use
	for i := 0; i+1 < len(m.Content); i += 2 {
		k := m.Content[i]
		// An alias, an anchor or a tag on the key gets its own, clearer message.
		if k.Kind == yaml.AliasNode || k.Anchor != "" || k.Style&yaml.TaggedStyle != 0 {
			return w.checkNode(k, 0)
		}
		if k.Kind != yaml.ScalarNode {
			return w.errorAt(k, "a mapping key must be a scalar, found %s", kindName(k))
		}
		if k.Value == "<<" {
			return w.errorAt(k, "a merge key (<<) is not allowed")
		}
		if !isASCII(k.Value) {
			return w.errorAt(k, "the mapping key %s has a non-ASCII character", show(k.Value))
		}
		folded := strings.ToLower(k.Value)
		if first, dup := seen[folded]; dup {
			return w.errorAt(k, "the key %s is a duplicate (case-insensitive) of the key on line %d", show(k.Value), first)
		}
		seen[folded] = k.Line
	}
	return nil
}

// root returns the top-level mapping of the workflow. parseWorkflow checked
// that it is a mapping.
func (w *workflow) root() *yaml.Node {
	return w.top
}

// lookup finds key in the mapping m, compared case-insensitively. It returns
// the key node and the value node, or two nil nodes when m has no such key.
// It returns an error when m is not a mapping. parseWorkflow rejected
// duplicate keys, so there is at most one match.
func (w *workflow) lookup(m *yaml.Node, key string) (k, v *yaml.Node, err error) {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil, nil, w.errorAt(m, "looking for %q: want a mapping, found %s", key, kindName(m))
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if strings.EqualFold(m.Content[i].Value, key) {
			return m.Content[i], m.Content[i+1], nil
		}
	}
	return nil, nil, nil
}

// mappingAt returns the value of key in the mapping m when that value is a
// mapping. It returns nil when m has no such key. It returns an error when m
// is not a mapping or when the value is not a mapping (an empty value such as
// "env:" is a null scalar, so it fails too).
func (w *workflow) mappingAt(m *yaml.Node, key string) (*yaml.Node, error) {
	return w.valueOfKind(m, key, yaml.MappingNode)
}

// sequenceAt is mappingAt for a value that must be a sequence.
func (w *workflow) sequenceAt(m *yaml.Node, key string) (*yaml.Node, error) {
	return w.valueOfKind(m, key, yaml.SequenceNode)
}

// scalarAt is mappingAt for a value that must be a scalar. Read the text with
// the Value field of the node.
func (w *workflow) scalarAt(m *yaml.Node, key string) (*yaml.Node, error) {
	return w.valueOfKind(m, key, yaml.ScalarNode)
}

// valueOfKind returns the value of key in the mapping m, or nil when m has no
// such key. It returns an error when the value is not of the kind want.
func (w *workflow) valueOfKind(m *yaml.Node, key string, want yaml.Kind) (*yaml.Node, error) {
	k, v, err := w.lookup(m, key)
	if err != nil || v == nil {
		return nil, err
	}
	if v.Kind != want {
		return nil, w.errorAt(v, "the value of %s must be %s, found %s", show(k.Value), kindWord(want), kindName(v))
	}
	return v, nil
}

// jobs returns the entries of the jobs mapping, in file order. It returns an
// error when the workflow has no jobs key, when jobs is not a mapping or when
// a job is not a mapping. GitHub needs jobs in every workflow, so a missing
// key fails closed.
func (w *workflow) jobs() ([]job, error) {
	jobsNode, err := w.mappingAt(w.top, "jobs")
	if err != nil {
		return nil, err
	}
	if jobsNode == nil {
		return nil, w.errorAt(w.top, "the workflow has no jobs mapping")
	}
	var out []job
	for i := 0; i+1 < len(jobsNode.Content); i += 2 {
		k, body := jobsNode.Content[i], jobsNode.Content[i+1]
		if body.Kind != yaml.MappingNode {
			return nil, w.errorAt(body, "the job %s must be a mapping, found %s", show(k.Value), kindName(body))
		}
		out = append(out, job{id: k.Value, key: k, body: body})
	}
	return out, nil
}

// steps returns the step mappings of the job j, in file order. It returns no
// steps and no error when the job has no steps key (a job that calls a
// reusable workflow has none). It returns an error when steps is not a
// sequence or when a step is not a mapping.
func (w *workflow) steps(j job) ([]*yaml.Node, error) {
	seq, err := w.sequenceAt(j.body, "steps")
	if err != nil || seq == nil {
		return nil, err
	}
	for _, s := range seq.Content {
		if s.Kind != yaml.MappingNode {
			return nil, w.errorAt(s, "a step of the job %s must be a mapping, found %s", show(j.id), kindName(s))
		}
	}
	return seq.Content, nil
}

// jobEnv returns the env mapping of the job j, or nil when the job has no env
// key. It returns an error when env is not a mapping, for example an
// expression such as ${{ fromJSON(...) }} that could build a variable.
func (w *workflow) jobEnv(j job) (*yaml.Node, error) {
	return w.mappingAt(j.body, "env")
}

// envProblems returns one problem for each mapping key named env (compared
// case-insensitively) whose value is not a mapping, at any depth of the
// workflow, in file order. GitHub reads env at the workflow, the job and the
// step level, and a lower level overrides a higher one. A value that is not a
// mapping, such as an expression ${{ fromJSON(...) }}, a block scalar or an
// empty value, can build a variable such as GORELEASER_VERSION at run time,
// and no check can read its name. So the rule fails closed on any such value.
// The message is the same as the one of mappingAt, so dedupe removes the copy
// when a rule also reads the same env key.
func (w *workflow) envProblems() []string {
	var out []string
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		if n.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(n.Content); i += 2 {
				k, v := n.Content[i], n.Content[i+1]
				if strings.EqualFold(k.Value, "env") && v.Kind != yaml.MappingNode {
					err := w.errorAt(v, "the value of %s must be %s, found %s", show(k.Value), kindWord(yaml.MappingNode), kindName(v))
					out = append(out, err.Error())
				}
			}
		}
		// parseWorkflow checked the depth, so the recursion is bounded.
		for _, child := range n.Content {
			walk(child)
		}
	}
	walk(w.top)
	return out
}

// scalars returns every scalar node of the workflow in file order: mapping
// keys and values, and sequence items. Use it for the rules that look at any
// text that names a tool or a variable. Each node has its decoded text in
// Value and its line in Line. For a block scalar (run: |) Line is the line of
// the | or > indicator, and Value holds all the lines of the body. Comments
// are not nodes, so scalars does not return them.
func (w *workflow) scalars() []*yaml.Node {
	var out []*yaml.Node
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		if n.Kind == yaml.ScalarNode {
			out = append(out, n)
		}
		for _, child := range n.Content {
			walk(child)
		}
	}
	walk(w.top)
	return out
}

// errorAt returns a *nodeError for the file of w at the line of n. n may be
// nil; then the error has no line.
func (w *workflow) errorAt(n *yaml.Node, format string, args ...any) error {
	e := &nodeError{file: w.file, msg: fmt.Sprintf(format, args...)}
	if n != nil {
		e.line = n.Line
	}
	return e
}

// kindName names the kind of n for a message, such as "a mapping". It names
// a null scalar (an empty value or null) "an empty value".
func kindName(n *yaml.Node) string {
	if n == nil {
		return "nothing"
	}
	if n.Kind == yaml.ScalarNode && n.ShortTag() == "!!null" {
		return "an empty value"
	}
	return kindWord(n.Kind)
}

// kindWord names a node kind for a message, such as "a mapping".
func kindWord(k yaml.Kind) string {
	switch k {
	case yaml.DocumentNode:
		return "a document"
	case yaml.SequenceNode:
		return "a sequence"
	case yaml.MappingNode:
		return "a mapping"
	case yaml.ScalarNode:
		return "a scalar"
	case yaml.AliasNode:
		return "an alias"
	default:
		return "an unknown node"
	}
}

// show returns s for a message: cut to maxShown bytes as cutText cuts it,
// and quoted as a Go string, so a line break or a control character shows as
// an escape such as \n. When s was cut, "..." follows the closing quote, so
// the marker cannot look like a part of the text. The result has at most
// about 4*maxShown bytes (each byte can become an escape such as \x1b).
func show(s string) string {
	short := cutPrefix(s, maxShown)
	if len(short) < len(s) {
		return strconv.Quote(short) + "..."
	}
	return strconv.Quote(s)
}

// cutText returns s when it has at most n bytes. Else it returns the start of
// s cut as cutPrefix cuts it, and then "...". It does not quote. Use it for a
// text that a message shows as it is, such as a version or an anchor name.
func cutText(s string, n int) string {
	short := cutPrefix(s, n)
	if len(short) < len(s) {
		return short + "..."
	}
	return s
}

// cutPrefix returns the longest start of s that has at most n bytes and ends
// at the start of a UTF-8 character, so that the cut never splits a valid
// character. An invalid byte counts as one character.
func cutPrefix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := 0
	// A range loop over a string steps by character: i is the byte index of
	// each character start, and an invalid byte is a character of one byte.
	for i := range s {
		if i > n {
			break
		}
		cut = i
	}
	return s[:cut]
}

// isASCII reports whether s has only ASCII bytes.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
