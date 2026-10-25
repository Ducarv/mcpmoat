package pins

import (
	"cmp"
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
	// KindUnverified is a tool that Compare can not check against the pin.
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

// The Diff of a changed tool when there is no diff text. Both are fixed notes,
// never server text. The change is still reported, and its Diff is never
// empty: a tool must never hide behind a render error or an invisible change.
const (
	// diffUnavailable is the Diff when the diff can not be made.
	diffUnavailable = "pinned text could not be rendered"
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

// RuleID returns the rule ID of the findings for this kind: MOAT-T2-001
// (changed), MOAT-T2-002 (new), MOAT-T2-003 (removed) or MOAT-T2-004
// (unverified). It returns the empty string for an unknown kind.
func (k ChangeKind) RuleID() string {
	switch k {
	case KindChanged:
		return "MOAT-T2-001"
	case KindNew:
		return "MOAT-T2-002"
	case KindRemoved:
		return "MOAT-T2-003"
	case KindUnverified:
		return "MOAT-T2-004"
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
	// set only for KindChanged, and it is never empty there: when no diff text
	// exists, it is a fixed note.
	Diff string
	// Reason says why a tool is KindUnverified. It is always one of the Reason
	// constants, never text from a server, so it is safe to print. It is empty
	// for the other kinds.
	Reason string
	// Severity is the severity of the finding for this change: "high", "medium"
	// or "low". Compare always sets it. It equals Kind.Severity(), except for a
	// KindUnverified change whose Tool is a pinned name: that one is "high".
	//
	// A pinned tool that Compare can not verify (a duplicate name, invalid tool
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
//     hashes of two versions can not be compared, and Compare must not accept
//     the tool silently.
//   - A pinned tool with another hash is KindChanged, also when the diff can
//     not be made (Diff then holds a short note, never the empty string).
//   - A pinned tool whose canonical text does not match its hash is
//     KindUnverified, because the diff would show the wrong tool.
//
// A tool that is not pinned is KindNew. A pinned tool that no current tool has
// by name is KindRemoved. A current tool with an invalid or duplicate name
// counts as present, so it is not also reported as removed.
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

	for name := range stored {
		if counts[name] == 0 {
			changes = append(changes, Change{Kind: KindRemoved, Tool: name, Severity: KindRemoved.Severity()})
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
		return Change{Kind: KindNew, Tool: t.Name, Severity: KindNew.Severity()}, true
	}
	if !strings.HasPrefix(pin.Hash, HashVersion+":") {
		return unverified(ReasonHashVersion)
	}
	if pin.Hash == hash {
		return Change{}, false
	}
	// The verdict comes from the hash, and the diff from the canonical text.
	// They must belong together, or the diff would show another tool.
	if hashCanonical([]byte(pin.Canonical)) != pin.Hash {
		return unverified(ReasonPinMismatch)
	}

	diff, err := unifiedDiff(pin.Canonical, string(canonical))
	switch {
	case err != nil:
		diff = diffUnavailable
	case diff == "":
		diff = diffNotVisible
	}
	return Change{Kind: KindChanged, Tool: t.Name, Diff: diff, Severity: KindChanged.Severity()}, true
}

// unverifiedChange returns a KindUnverified change. Its severity is "high" when
// the name is pinned, because a pinned tool that can not be verified can hide a
// rug pull, and "medium" otherwise.
func unverifiedChange(stored ServerPins, name, reason string) Change {
	severity := KindUnverified.Severity()
	if _, pinned := stored[name]; pinned {
		severity = severityHigh
	}
	return Change{Kind: KindUnverified, Tool: name, Reason: reason, Severity: severity}
}
