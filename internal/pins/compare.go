package pins

import (
	"cmp"
	"errors"
	"slices"
	"strings"

	"github.com/Ducarv/mcpmoat/internal/inspect"
)

// ChangeKind is the kind of a pin change that Compare reports.
type ChangeKind string

// The kinds of pin change. Each kind has a rule ID and a severity (see
// ChangeKind.RuleID and ChangeKind.Severity).
const (
	// KindChanged is a tool whose hash differs from its pin (FR-12, T2).
	KindChanged ChangeKind = "changed"
	// KindNew is a tool that a pinned server has now and the pin does not have.
	KindNew ChangeKind = "new"
	// KindRemoved is a pinned tool that the server no longer has.
	KindRemoved ChangeKind = "removed"
	// KindUnverified is a tool that Compare cannot check against the pin.
	// The name is empty or duplicate, the tool has no canonical form, the pin
	// uses another hash version, or the pin text does not match its hash.
	// Change.Reason says which.
	KindUnverified ChangeKind = "unverified"
)

// The severities of the pin changes. They have the same spelling as the
// severities of the rules, but this package does not import internal/rules.
const (
	severityHigh   = "high"
	severityMedium = "medium"
	severityLow    = "low"
)

// The Diff of a changed or new tool when there is no diff text. All are fixed
// notes, never server text. The change is still reported, and its Diff is
// never empty: a tool must never hide behind a render error or an invisible
// change.
const (
	// diffUnavailable is the Diff of a changed tool when the diff cannot be
	// made.
	diffUnavailable = "pinned text could not be rendered"
	// diffNewUnavailable is the Diff of a new tool, or of a pinned tool that
	// cannot be verified, when the diff of its current text cannot be made.
	diffNewUnavailable = "current text could not be rendered"
	// diffNotVisible is the Diff when the hashes differ but the rendered texts
	// are equal. The canonical form has a key that render does not show, or two
	// keys that differ only in case.
	diffNotVisible = "the tool changed, but the change is not visible in the rendered text"
)

// The reasons of a KindUnverified change. They are fixed texts, safe to print.
const (
	// ReasonDuplicateName means that two or more current tools share the name.
	ReasonDuplicateName = "duplicate tool name"
	// ReasonEmptyName means that the tool has an empty name.
	ReasonEmptyName = "empty tool name"
	// ReasonInvalidTool means that the tool has no canonical form or no hash.
	ReasonInvalidTool = "invalid tool data"
	// ReasonHashVersion means that the pin has a hash of another HashVersion.
	ReasonHashVersion = "pinned with another hash version"
	// ReasonPinMismatch means that the pinned canonical text does not match the
	// pinned hash, so the pin is corrupt or was edited.
	ReasonPinMismatch = "pinned text does not match its hash"
)

// ReasonOf returns the reason constant for an error of Snapshot or Canonical:
// ReasonDuplicateName, ReasonEmptyName or ReasonInvalidTool. It returns the
// empty string for any other error. Compare gives the same reason for the same
// tool, so a first run and a later run name a bad tool in the same way.
func ReasonOf(err error) string {
	switch {
	case errors.Is(err, ErrDuplicateTool):
		return ReasonDuplicateName
	case errors.Is(err, ErrEmptyName):
		return ReasonEmptyName
	case errors.Is(err, ErrInvalidTool):
		return ReasonInvalidTool
	}
	return ""
}

// ruleIDPrefix is the start of every rule ID that ChangeKind.RuleID returns.
const ruleIDPrefix = "MOAT-T2-"

// IsPinRuleID reports whether id is the rule ID of a pin change, that is, an
// ID that starts with ruleIDPrefix. The match is exact and case-sensitive.
func IsPinRuleID(id string) bool {
	return strings.HasPrefix(id, ruleIDPrefix)
}

// RuleID returns the rule ID of the findings for this kind: MOAT-T2-001
// (changed), MOAT-T2-002 (new), MOAT-T2-003 (removed) or MOAT-T2-004
// (unverified). It returns the empty string for an unknown kind.
func (k ChangeKind) RuleID() string {
	switch k {
	case KindChanged:
		return ruleIDPrefix + "001"
	case KindNew:
		return ruleIDPrefix + "002"
	case KindRemoved:
		return ruleIDPrefix + "003"
	case KindUnverified:
		return ruleIDPrefix + "004"
	}
	return ""
}

// Severity returns the default severity of the findings for this kind, spelled
// as the rule severities are: "high" (changed), "medium" (new and unverified)
// or "low" (removed). It returns the empty string for an unknown kind.
//
// Change.Severity is the severity to use for a finding. It can be higher than
// this default: an unverified change of a pinned tool is "high".
func (k ChangeKind) Severity() string {
	switch k {
	case KindChanged:
		return severityHigh
	case KindNew, KindUnverified:
		return severityMedium
	case KindRemoved:
		return severityLow
	}
	return ""
}

// The fixed risk texts of the pin changes. They follow the style of the risk
// field of the rules: one plain sentence, with no text from a server.
const (
	riskChanged    = "A pinned tool differs from the version the user accepted, so the server may have swapped in hostile instructions after the approval (a rug pull)."
	riskNew        = "A pinned server now offers a tool that is not pinned, so the server may have added a hostile tool, or renamed a pinned tool to avoid the check."
	riskRemoved    = "A pinned tool is no longer on the server, so the server changed, or it renamed the tool to avoid the check of the pin."
	riskUnverified = "mcpmoat cannot check this tool against its pin, so a changed tool could pass without a review."
	riskUnknown    = "mcpmoat found a change of the pins that it does not know, so the tools of the server may differ from the ones the user accepted."
)

// The fixed remediation texts of the pin changes. They name the command that
// scan prints in its "To accept" line, and they hold no text from a server.
const (
	remediationChanged    = "Read the diff, and if the change is expected, run mcpmoat pin --accept <server> --expect <digest>; if not, remove the server or do not use it."
	remediationNew        = "Read the diff to see what the new tool does, and if the tool is expected, run mcpmoat pin --accept <server> --expect <digest>; if not, remove the server or do not use it."
	remediationRemoved    = "Check that the server dropped the tool on purpose, and if the change is expected, run mcpmoat pin --accept <server> --expect <digest>; if not, remove the server or do not use it."
	remediationUnverified = "Read the reason and the diff to see why the tool cannot be checked, and if the tools are as expected, run mcpmoat pin --accept <server> --expect <digest>; if not, remove the server or do not use it."
	remediationUnknown    = "Read the change and review the tools of the server, and remove the server or do not use it if you do not trust the change."
)

// Risk returns one fixed sentence that says what the risk is for this kind of
// pin change. The text is the same for every change of the kind and holds no
// text from a server. It returns a generic text for an unknown kind, so a new
// kind never gets an empty risk.
func (k ChangeKind) Risk() string {
	switch k {
	case KindChanged:
		return riskChanged
	case KindNew:
		return riskNew
	case KindRemoved:
		return riskRemoved
	case KindUnverified:
		return riskUnverified
	}
	return riskUnknown
}

// Remediation returns one fixed sentence that says what the user should do for
// this kind of pin change: review the diff, then run "mcpmoat pin --accept" if
// the change is expected. The text is the same for every change of the kind and
// holds no text from a server. It returns a generic text for an unknown kind,
// so a new kind never gets an empty remediation.
func (k ChangeKind) Remediation() string {
	switch k {
	case KindChanged:
		return remediationChanged
	case KindNew:
		return remediationNew
	case KindRemoved:
		return remediationRemoved
	case KindUnverified:
		return remediationUnverified
	}
	return remediationUnknown
}

// Change is one difference between the pins of a server and its current tools.
//
// Tool and Diff hold raw text from the server, which is not trusted. They can
// hold control characters or terminal escape sequences. The caller must escape
// them before it writes them to a terminal or a report. Reason is not server
// text.
type Change struct {
	// Kind is the kind of change.
	Kind ChangeKind
	// Tool is the tool name. For KindUnverified it can be empty.
	Tool string
	// Diff is the unified diff between the pinned and the current tool. It is
	// set for KindChanged and KindNew, and it is never empty there: when no
	// diff text exists, it is a fixed note. For KindNew the diff is from empty
	// text, so every content line is an added line. The labels are "--- pinned"
	// and "+++ current".
	//
	// A KindUnverified change with ReasonHashVersion or ReasonPinMismatch has a
	// Diff too, made like the one of KindNew: the pin cannot be trusted, so the
	// diff shows the whole current tool. The user must see that text before they
	// accept it. The other KindUnverified changes have no single current tool to
	// show, so their Diff is empty.
	Diff string
	// Truncated is true when the diff window was cut by the size caps (64 KiB
	// or 2000 lines) and Diff ends with a truncated marker line. It can only be
	// true when Diff is set.
	Truncated bool
	// Reason says why a tool is KindUnverified. It is always one of the Reason
	// constants, never text from a server, so it is safe to print. It is empty
	// for the other kinds.
	Reason string
	// Severity is the severity of the finding for this change: "high", "medium"
	// or "low". Compare always sets it. It equals Kind.Severity(), except for a
	// KindUnverified change whose Tool is a pinned name, and for a KindNew or
	// KindUnverified change next to a KindRemoved change (a likely rename, see
	// Compare): those are "high".
	//
	// A pinned tool that Compare cannot verify (a duplicate name, invalid tool
	// data, another hash version or a corrupt pin) can hide a rug pull. A hostile
	// server can return a pinned name twice, or with data that has no canonical
	// form, to avoid the KindChanged check. The change must then fail the default
	// "high" threshold, as a changed tool does. An unverified tool whose name is
	// not pinned stays at the default "medium".
	Severity string
}

// Compare returns the differences between the pins of a server and the tools
// that the server has now. The result is sorted by tool name, then by kind,
// and is nil when there is no difference.
//
// Compare never skips a tool, because a server could use a skipped tool to
// avoid detection:
//   - A tool with an empty name, or without a canonical form, is
//     KindUnverified.
//   - A name that two or more current tools share gives one KindUnverified
//     change for that name. Compare does not pick one of the tools.
//   - A pinned tool with a hash of another HashVersion is KindUnverified. The
//     hashes of two versions cannot be compared, and Compare must not accept
//     the tool silently.
//   - A pinned tool with another hash is KindChanged, also when the diff can
//     not be made (Diff then holds a short note, never the empty string).
//   - A pinned tool whose canonical text does not match its hash is
//     KindUnverified, because the diff would show the wrong tool.
//
// A tool that is not pinned is KindNew. A pinned tool that no current tool has
// by name is KindRemoved. A current tool with an invalid or duplicate name
// counts as present, so it is not also reported as removed.
//
// A KindNew change, and a KindUnverified change of a name that is not pinned,
// is "high", not "medium", when the result also has a KindRemoved change: a
// server can rename a pinned tool (drop "read_file", add "read_fi1e" with new
// text, or with data that cannot be verified) to avoid the "high" KindChanged
// check.
func Compare(stored ServerPins, current []inspect.Tool) []Change {
	counts := make(map[string]int, len(current))
	for _, t := range current {
		counts[t.Name]++
	}

	var changes []Change
	reported := make(map[string]bool) // names with a duplicate, already reported
	for _, t := range current {
		if counts[t.Name] > 1 {
			if !reported[t.Name] {
				reported[t.Name] = true
				changes = append(changes, unverifiedChange(stored, t.Name, ReasonDuplicateName))
			}
			continue
		}
		if c, ok := compareTool(stored, t); ok {
			changes = append(changes, c)
		}
	}

	removed := false
	for name := range stored {
		if counts[name] == 0 {
			removed = true
			changes = append(changes, Change{Kind: KindRemoved, Tool: name, Severity: KindRemoved.Severity()})
		}
	}
	if removed {
		for i := range changes {
			if changes[i].Kind == KindNew || changes[i].Kind == KindUnverified {
				changes[i].Severity = severityHigh
			}
		}
	}

	slices.SortFunc(changes, func(a, b Change) int {
		return cmp.Or(
			strings.Compare(a.Tool, b.Tool),
			strings.Compare(a.Kind.RuleID(), b.Kind.RuleID()),
		)
	})
	return changes
}

// compareTool compares one current tool, which has a unique name, with its
// pin. It returns false when there is nothing to report.
func compareTool(stored ServerPins, t inspect.Tool) (Change, bool) {
	unverified := func(reason string) (Change, bool) {
		return unverifiedChange(stored, t.Name, reason), true
	}
	if t.Name == "" {
		return unverified(ReasonEmptyName)
	}
	canonical, err := Canonical(t)
	if err != nil {
		return unverified(ReasonInvalidTool)
	}
	hash := hashCanonical(canonical)

	pin, ok := stored[t.Name]
	if !ok {
		// The user must see a new tool before they accept it, so it has a diff
		// too: all its lines are added lines.
		diff, truncated := currentToolDiff(canonical)
		return Change{Kind: KindNew, Tool: t.Name, Diff: diff, Truncated: truncated, Severity: KindNew.Severity()}, true
	}
	// The pin cannot be checked in the next two cases, so the change shows the
	// whole current tool, like a new tool.
	unverifiedWithText := func(reason string) (Change, bool) {
		c := unverifiedChange(stored, t.Name, reason)
		c.Diff, c.Truncated = currentToolDiff(canonical)
		return c, true
	}
	if !strings.HasPrefix(pin.Hash, HashVersion+":") {
		return unverifiedWithText(ReasonHashVersion)
	}
	if pin.Hash == hash {
		return Change{}, false
	}
	// The verdict comes from the hash, and the diff from the canonical text.
	// They must belong together, or the diff would show another tool.
	if hashCanonical([]byte(pin.Canonical)) != pin.Hash {
		return unverifiedWithText(ReasonPinMismatch)
	}

	diff, truncated, err := unifiedDiff(pin.Canonical, string(canonical))
	switch {
	case err != nil:
		diff, truncated = diffUnavailable, false
	case diff == "":
		diff = diffNotVisible
	}
	return Change{Kind: KindChanged, Tool: t.Name, Diff: diff, Truncated: truncated, Severity: KindChanged.Severity()}, true
}

// currentToolDiff returns the diff of the whole current tool from empty text,
// and whether it was cut. When the diff cannot be made, it returns the fixed
// note diffNewUnavailable.
func currentToolDiff(canonical []byte) (diff string, truncated bool) {
	diff, truncated, err := newToolDiff(string(canonical))
	if err != nil {
		return diffNewUnavailable, false
	}
	return diff, truncated
}

// unverifiedChange returns a KindUnverified change, with the severity of
// UnverifiedSeverity.
func unverifiedChange(stored ServerPins, name, reason string) Change {
	_, pinned := stored[name]
	return Change{Kind: KindUnverified, Tool: name, Reason: reason, Severity: UnverifiedSeverity(pinned)}
}

// UnverifiedSeverity returns the severity of a KindUnverified finding: "high"
// when the tool or the server is pinned, because a pinned item that cannot be
// verified can hide a rug pull, and "medium" otherwise.
func UnverifiedSeverity(pinned bool) string {
	if pinned {
		return severityHigh
	}
	return KindUnverified.Severity()
}

// DiffIsNote reports whether Diff is one of the fixed notes that replace the
// diff text, so the user sees no text of the tool in it. A real diff always
// starts with the "--- pinned" label, so it never equals a note.
func (c Change) DiffIsNote() bool {
	switch c.Diff {
	case diffUnavailable, diffNewUnavailable, diffNotVisible:
		return true
	}
	return false
}
