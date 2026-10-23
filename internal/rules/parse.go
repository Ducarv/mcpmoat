package rules

import (
	"bytes"
	"cmp"
	"errors"
	"io"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Limits for one rule file. A rule file is untrusted (a cloned repository can
// ship it), so the parser checks them before it builds any Go value.
const (
	// maxFileBytes is the largest rule file the parser reads. The loader reuses
	// it. The check runs before any YAML decoding.
	maxFileBytes = 64 << 10
	// maxNodeDepth is the deepest nesting of YAML nodes the parser accepts.
	maxNodeDepth = 32
	// maxNodes is the largest number of YAML nodes in one document.
	maxNodes = 10000
	// maxErrorsPerFile is the largest number of real errors that Parse returns
	// for one file. A hostile file can hold thousands of bad items, and each
	// one would give an error and a line of output. When there are more errors,
	// Parse returns the first maxErrorsPerFile in file order and one last
	// ReasonTooManyErrors error, so the result has at most maxErrorsPerFile+1
	// items.
	maxErrorsPerFile = 20
)

// Fixed explanatory texts for LoadError.Err. They never hold input from a rule
// file and never hold text from the YAML library, because that text can name
// Go types. (The syntax errors of the YAML library are a separate case: see
// readDocument.)
var (
	errAnchors     = errors.New("anchors and aliases are not allowed")
	errTooDeep     = errors.New("YAML nesting is too deep")
	errTooManyNode = errors.New("YAML document has too many nodes")
	errNotMapping  = errors.New("rule must be a mapping")
	errKeyNotStr   = errors.New("keys must be plain strings")
	errNullItem    = errors.New("list item must not be empty")
	// errNoDecoder is a bug of mcpmoat: a key that checkKeys allows has no case
	// in decodeField. TestDecodeFieldHandlesEveryKey guards against it.
	errNoDecoder = errors.New("no decoder for this key")
)

// Parse reads one rule from the YAML text in data. file is the display name
// used in messages; Parse also stores it in Rule.Source. It returns a valid
// rule and nil, or a zero Rule and one or more errors in file order. It returns
// at most maxErrorsPerFile real errors; if there are more, the last item is one
// ReasonTooManyErrors error that says how many were not shown. It never panics
// on any input.
//
// Parse does not use KnownFields(true) of the YAML library. Instead it checks
// the keys itself and decodes each field alone. That way every problem with a
// field has a fixed message with the line and column, and the failed decode of
// a field value never shows text from the YAML library. A YAML syntax error is
// different: Parse wraps it with ReasonInvalidYAML, so its library text (it can
// hold text of the file, for example an anchor name) reaches LoadError.Err.
// That is safe because LoadError.Error quotes this text and cuts it to
// maxDisplayRunes runes. Parse does not compile regexes and does not run
// matchers.
func Parse(file string, data []byte) (Rule, []*LoadError) {
	if len(data) > maxFileBytes {
		return Rule{}, []*LoadError{newLoadError(file, ReasonTooLarge)}
	}

	root, errs, stop := readDocument(file, data)
	if stop {
		return Rule{}, errs
	}

	if bad, err := checkTree(root); err != nil {
		e := newLoadError(file, ReasonInvalidYAML).at(bad.Line, bad.Column).wrap(err)
		return Rule{}, append([]*LoadError{e}, errs...)
	}
	if root.Kind != yaml.MappingNode {
		e := newLoadError(file, ReasonInvalidYAML).at(root.Line, root.Column).wrap(errNotMapping)
		return Rule{}, append([]*LoadError{e}, errs...)
	}

	var rule Rule
	fields, fieldErrs, dropped := decodeRule(file, root, &rule)
	// errs holds at most the error about a second document, which comes last in
	// the file.
	fieldErrs = append(fieldErrs, errs...)
	if len(fieldErrs) > 0 {
		return Rule{}, capErrors(file, fieldErrs, dropped)
	}

	rule.Source = file
	// Validate builds all its errors (its own caps bound their number), in the
	// order of the fields of Rule. Set the positions and sort by them first,
	// so the cap keeps the first errors in file order.
	verrs := rule.Validate()
	if len(verrs) > 0 {
		addPositions(verrs, fields)
		slices.SortStableFunc(verrs, comparePos)
		return Rule{}, capErrors(file, verrs, 0)
	}
	return rule, nil
}

// capErrors limits errs to maxErrorsPerFile items. dropped is the number of
// errors that the caller already left out. When any error is left out, the
// result ends with one ReasonTooManyErrors error with the number, so the user
// knows the list is not complete. The number is an int, never untrusted text.
func capErrors(file string, errs []*LoadError, dropped int) []*LoadError {
	if len(errs) > maxErrorsPerFile {
		dropped += len(errs) - maxErrorsPerFile
		// The full slice expression gives the slice no spare capacity, so the
		// append below cannot write into the array of the caller.
		errs = errs[:maxErrorsPerFile:maxErrorsPerFile]
	}
	if dropped == 0 {
		return errs
	}
	return append(errs, newLoadError(file, ReasonTooManyErrors).wrap(moreErrors(dropped)))
}

// errList collects errors of a file in file order, but keeps only the first
// maxErrorsPerFile and builds only those. It counts the others. The count is
// exact, because counting is cheap: the callers walk nodes that already exist
// (at most maxNodes) and only the kept errors are allocated.
type errList struct {
	errs    []*LoadError
	dropped int
}

// add records one error at the position of node, or counts it when the
// list is full. field and err may be empty and nil.
func (l *errList) add(file string, r Reason, node *yaml.Node, field string, err error) {
	if len(l.errs) >= maxErrorsPerFile {
		l.dropped++
		return
	}
	l.errs = append(l.errs, newLoadError(file, r).at(node.Line, node.Column).inField(field).wrap(err))
}

// total returns the number of errors added, kept or not.
func (l *errList) total() int {
	return len(l.errs) + l.dropped
}

// readDocument decodes the first YAML document of data into a node tree and
// returns its root node. stop is true when the caller cannot go on; errs then
// holds the reason. When stop is false, errs holds the error about a second
// document or nothing. Decoding into a yaml.Node does not expand aliases.
//
// A syntax error of the YAML library is wrapped as it is. Its text can hold
// text of the file (for example "unknown anchor 'x' referenced"). That is safe:
// LoadError.Error quotes it and cuts it to maxDisplayRunes runes.
func readDocument(file string, data []byte) (root *yaml.Node, errs []*LoadError, stop bool) {
	dec := yaml.NewDecoder(bytes.NewReader(data))

	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, []*LoadError{newLoadError(file, ReasonEmptyFile)}, true
		}
		return nil, []*LoadError{newLoadError(file, ReasonInvalidYAML).wrap(err)}, true
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, []*LoadError{newLoadError(file, ReasonInvalidYAML).wrap(errNotMapping)}, true
	}
	// A file with only "---" is one document with an empty value: it is empty.
	if v := doc.Content[0]; v.Kind == yaml.ScalarNode && v.ShortTag() == "!!null" && v.Value == "" {
		return nil, []*LoadError{newLoadError(file, ReasonEmptyFile)}, true
	}

	// A second Decode must find the end of the input. A second document is an
	// error. A syntax error in it is reported as a syntax error, and its text
	// from the YAML library names the line.
	var next yaml.Node
	switch err := dec.Decode(&next); {
	case err == nil:
		errs = append(errs, newLoadError(file, ReasonMultipleDocuments).at(next.Line, next.Column))
	case !errors.Is(err, io.EOF):
		errs = append(errs, newLoadError(file, ReasonInvalidYAML).wrap(err))
	}
	return doc.Content[0], errs, false
}

// frame is one node waiting in the walk of checkTree.
type frame struct {
	node  *yaml.Node
	depth int
}

// checkTree walks the whole tree below root and rejects anchors, aliases, a
// tree that is too deep and a tree with too many nodes. Aliases are the way to
// build an alias bomb (a small file that expands to a huge value), so the
// parser forbids them. It returns the first bad node and a fixed error. The
// walk uses its own stack instead of recursion, and the caps bound its work.
func checkTree(root *yaml.Node) (*yaml.Node, error) {
	stack := []frame{{node: root, depth: 1}}
	count := 0
	for len(stack) > 0 {
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		count++
		switch {
		case count > maxNodes:
			return f.node, errTooManyNode
		case f.depth > maxNodeDepth:
			return f.node, errTooDeep
		case f.node.Kind == yaml.AliasNode || f.node.Anchor != "":
			return f.node, errAnchors
		}
		for i := len(f.node.Content) - 1; i >= 0; i-- {
			stack = append(stack, frame{node: f.node.Content[i], depth: f.depth + 1})
		}
	}
	return nil, nil
}

// field is one accepted key of a mapping with its value.
type field struct {
	name string
	key  *yaml.Node
	val  *yaml.Node
}

// checkKeys checks the keys of the mapping node m against allowed. It reports
// keys that are not plain strings, unknown keys and repeated keys to out, in
// file order. It returns the first occurrence of every allowed key. prefix is
// put before the key in the Field of an error ("" or "match."). A nil allowed
// accepts every plain string key, for the free-form mapping match.params.
func checkKeys(file, prefix string, m *yaml.Node, allowed []string, out *errList) []field {
	var fields []field
	seen := make(map[string]bool)

	// A mapping node keeps its content as a flat list: key, value, key, value...
	for i := 0; i+1 < len(m.Content); i += 2 {
		key, val := m.Content[i], m.Content[i+1]
		name := key.Value
		switch {
		case key.Kind != yaml.ScalarNode || key.ShortTag() != "!!str":
			out.add(file, ReasonInvalidYAML, key, "", errKeyNotStr)
		case seen[name]:
			out.add(file, ReasonDuplicateField, key, prefix+name, nil)
		case allowed != nil && !slices.Contains(allowed, name):
			seen[name] = true
			out.add(file, ReasonUnknownField, key, prefix+name, nil)
		default:
			seen[name] = true
			fields = append(fields, field{name: name, key: key, val: val})
		}
	}
	return fields
}

// decodeRule checks the keys of the rule mapping root and decodes every field
// into r, one key at a time. It returns the accepted fields, the errors in file
// order (at most maxErrorsPerFile) and the number of errors left out.
func decodeRule(file string, root *yaml.Node, r *Rule) ([]field, []*LoadError, int) {
	var keyErrs, valueErrs errList
	fields := checkKeys(file, "", root, ruleKeys(), &keyErrs)
	// Errors must stay in file order, but the key errors above come first.
	// Collect the value errors separately, then merge both by position. The
	// fields come in file order, so the first maxErrorsPerFile value errors
	// (before sorting) are the first ones of the file.
	for _, f := range fields {
		if f.name == "match" && !checkMatch(file, f.val, &valueErrs) {
			continue
		}
		if err := decodeField(r, f.name, f.val); err != nil {
			valueErrs.add(file, ReasonInvalidValue, f.val, f.name, fixedCaseError(err))
		}
		nullItemErrors(file, f.name, f.val, &valueErrs)
	}
	// A null item sits after the start of its list, but a decode error of the
	// same list is reported at the start. Sorting keeps the list in file order.
	slices.SortStableFunc(valueErrs.errs, comparePos)
	return fields, mergeByPosition(keyErrs.errs, valueErrs.errs), keyErrs.dropped + valueErrs.dropped
}

// nullItemErrors reports to out every null item (~, null or an empty item) in
// the list fields of the field called name: should_match, should_not_match,
// references and the lists any_regex, all_regex and keywords of match. The YAML
// library skips null items of a sequence before it decodes the rest, so
// decoding alone would drop such an item without any error. A dropped case
// weakens the rule tests (NFR-05), and a dropped item of all_regex changes what
// the rule means. The two case lists report errCaseShape; the other lists
// report errNullItem. The value of any other field, and a value that is not a
// list, give no errors here: a null list is not an error, and decodeField
// reports a value of the wrong shape.
func nullItemErrors(file, name string, val *yaml.Node, out *errList) {
	switch name {
	case "should_match", "should_not_match":
		nullItems(file, name, val, errCaseShape, out)
	case "references":
		nullItems(file, name, val, errNullItem, out)
	case "match":
		if val.Kind != yaml.MappingNode {
			return
		}
		// Content is key, value, key, value...
		for i := 0; i+1 < len(val.Content); i += 2 {
			switch key := val.Content[i].Value; key {
			case "any_regex", "all_regex", "keywords":
				nullItems(file, "match."+key, val.Content[i+1], errNullItem, out)
			}
		}
	}
}

// nullItems reports every null item of the list node val to out. The Field of
// an error is the name of the list and the index of the item, "references[1]".
func nullItems(file, name string, val *yaml.Node, why error, out *errList) {
	if val.Kind != yaml.SequenceNode {
		return
	}
	for i, item := range val.Content {
		if item.Kind != yaml.ScalarNode || item.ShortTag() != "!!null" {
			continue
		}
		out.add(file, ReasonInvalidValue, item, indexField(name, i), why)
	}
}

// checkMatch checks the shape and the keys of the value of the match field and
// reports problems to out. It returns false when the value must not be decoded.
func checkMatch(file string, val *yaml.Node, out *errList) bool {
	if val.Kind == yaml.ScalarNode && val.ShortTag() == "!!null" {
		return true // an empty match is a missing field; Validate reports it
	}
	if val.Kind != yaml.MappingNode {
		out.add(file, ReasonInvalidValue, val, "match", nil)
		return false
	}
	start := out.total()
	for _, f := range checkKeys(file, "match.", val, matchKeys(), out) {
		if f.name == "params" {
			checkParams(file, f.val, out)
		}
	}
	return out.total() == start
}

// checkParams checks the value of match.params: a mapping with plain string
// keys that are not repeated, or an empty value. Decoding alone would turn a
// bool or int key into a string and drop a null key without a word.
func checkParams(file string, val *yaml.Node, out *errList) {
	switch {
	case val.Kind == yaml.ScalarNode && val.ShortTag() == "!!null":
		// An empty params is the same as no params.
	case val.Kind != yaml.MappingNode:
		out.add(file, ReasonInvalidValue, val, "match.params", nil)
	default:
		checkKeys(file, "match.params.", val, nil, out)
	}
}

// decodeField decodes the value node v into the field of r that is named name.
func decodeField(r *Rule, name string, v *yaml.Node) error {
	switch name {
	case "id":
		return v.Decode(&r.ID)
	case "title":
		return v.Decode(&r.Title)
	case "severity":
		return v.Decode(&r.Severity)
	case "target":
		return v.Decode(&r.Target)
	case "match":
		return v.Decode(&r.Match)
	case "risk":
		return v.Decode(&r.Risk)
	case "remediation":
		return v.Decode(&r.Remediation)
	case "references":
		return v.Decode(&r.References)
	case "should_match":
		return v.Decode(&r.ShouldMatch)
	case "should_not_match":
		return v.Decode(&r.ShouldNotMatch)
	default:
		// checkKeys only lets the keys above through. A key in ruleKeys without
		// a case here would be dropped without a word, so fail instead.
		return errNoDecoder
	}
}

// fixedCaseError returns the fixed error of Case that err wraps, or nil. The
// text of err is dropped, because the YAML library puts Go type names in it.
// Only the fixed errors of Case are kept.
func fixedCaseError(err error) error {
	for _, fixed := range caseErrors() {
		if errors.Is(err, fixed) {
			return fixed
		}
	}
	return nil
}

// mergeByPosition merges two lists of errors into one list in file order. Each
// input list is already in file order. Errors with equal positions keep the
// order a, then b.
func mergeByPosition(a, b []*LoadError) []*LoadError {
	out := make([]*LoadError, 0, len(a)+len(b))
	for len(a) > 0 && len(b) > 0 {
		if comparePos(b[0], a[0]) < 0 {
			out, b = append(out, b[0]), b[1:]
		} else {
			out, a = append(out, a[0]), a[1:]
		}
	}
	out = append(out, a...)
	out = append(out, b...)
	if len(out) == 0 {
		return nil
	}
	return out
}

// comparePos orders two errors by their position in the file: it returns a
// negative number when x comes before y, zero when the positions are equal and
// a positive number otherwise.
func comparePos(x, y *LoadError) int {
	return cmp.Or(cmp.Compare(x.Line, y.Line), cmp.Compare(x.Col, y.Col))
}

// addPositions sets Line and Col of validation errors. An error gets the
// position of the value of the top-level key that is the first part of its
// Field ("match" for "match.any_regex[2]"). An error for a missing field has no
// key, so it keeps the position 0.
func addPositions(errs []*LoadError, fields []field) {
	values := make(map[string]*yaml.Node, len(fields))
	for _, f := range fields {
		values[f.name] = f.val
	}
	for _, e := range errs {
		head, _, _ := strings.Cut(e.Field, ".")
		head, _, _ = strings.Cut(head, "[")
		if v, ok := values[head]; ok {
			e.Line, e.Col = v.Line, v.Column
		}
	}
}
