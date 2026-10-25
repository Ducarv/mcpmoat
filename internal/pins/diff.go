package pins

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/aymanbagabas/go-udiff"
)

const (
	// maxRenderedBytes limits the size of each rendered text before the diff,
	// so a hostile server can not make the diff use a lot of time or memory.
	maxRenderedBytes = 64 * 1024

	// maxRenderedLines limits the lines of each rendered text before the diff,
	// for the same reason: the diff work grows with the number of lines.
	maxRenderedLines = 2000

	// diffContextLines is the number of unchanged lines around a change.
	diffContextLines = 3

	// diffOldLabel and diffNewLabel are the file names in the diff header.
	diffOldLabel = "pinned"
	diffNewLabel = "current"

	// truncatedMarker is the last line of a text that capText cut.
	truncatedMarker = "[truncated: text over the limit]"
)

// hunkHeader matches the header line of a hunk in the output of go-udiff:
// "@@ -12,7 +12,8 @@" or, for a one-line side, "@@ -12 +12 @@". A line of the
// diff body always starts with " ", "+", "-" or "\\", so only a header starts
// with "@@".
var hunkHeader = regexp.MustCompile(`^@@ -(\d+)(,\d+)? \+(\d+)(,\d+)? @@$`)

// unifiedDiff returns the unified diff between two canonical forms of a tool
// (the output of Canonical): oldCanonical is the pinned tool and newCanonical
// is the current tool. The diff shows the changed lines with three lines of
// context. It is the empty string only when the rendered texts are equal.
//
// Each canonical form goes through render. Then unifiedDiff removes the lines
// that both texts share at the start and at the end, and keeps diffContextLines
// of them on each side. Only this middle window is cut to maxRenderedBytes and
// maxRenderedLines, and ends with a marker line when it was cut. So a change
// after a very long text is still in the diff, and the first change is always
// in the window. The line numbers in the hunk headers are those of the full
// rendered texts. The truncated result is true when a text was cut. This
// function returns an error when a canonical form does not parse.
//
// The diff keeps the bytes of the server text. The caller must escape it
// before it writes it to a terminal.
func unifiedDiff(oldCanonical, newCanonical string) (diff string, truncated bool, err error) {
	before, err := render(oldCanonical)
	if err != nil {
		return "", false, fmt.Errorf("render pinned tool: %w", err)
	}
	after, err := render(newCanonical)
	if err != nil {
		return "", false, fmt.Errorf("render current tool: %w", err)
	}
	return diffRendered(before, after)
}

// newToolDiff returns the unified diff from no text to the current tool: every
// content line is an added line. It is the diff of a tool that the pin does
// not have yet. The labels, the caps and the truncated result are those of
// unifiedDiff. The diff is never empty, because a rendered tool always has
// lines. newToolDiff returns an error when newCanonical does not parse.
func newToolDiff(newCanonical string) (diff string, truncated bool, err error) {
	after, err := render(newCanonical)
	if err != nil {
		return "", false, fmt.Errorf("render current tool: %w", err)
	}
	return diffRendered("", after)
}

// diffRendered returns the unified diff of two rendered texts, with the window
// and the caps that the unifiedDiff comment describes. It is the empty string
// only when the texts are equal.
func diffRendered(before, after string) (diff string, truncated bool, err error) {
	if before == after {
		return "", false, nil
	}

	before, after, skipped := trimCommon(before, after, diffContextLines)
	before, cutBefore := capText(before)
	after, cutAfter := capText(after)

	edits := udiff.Lines(before, after)
	diff, err = udiff.ToUnified(diffOldLabel, diffNewLabel, before, edits, diffContextLines)
	if err != nil {
		return "", false, fmt.Errorf("make unified diff: %w", err)
	}
	return shiftHunks(diff, skipped), cutBefore || cutAfter, nil
}

// trimCommon removes the whole lines that a and b share at the start and at the
// end, and keeps context of them on each side. It returns the two middle
// windows and the number of lines it removed at the start. The work is linear
// in the length of the texts.
//
// A line is shared at the start when both texts have it at the same position,
// and shared at the end when both texts have it at the same distance from the
// end. The two kinds never overlap. The texts must not be equal.
func trimCommon(a, b string, context int) (trimmedA, trimmedB string, skipped int) {
	// Start: the first whole line that differs, then back up by context lines.
	p := commonPrefixLen(a, b)
	firstDiffLineStart := strings.LastIndexByte(a[:p], '\n') + 1
	start := firstDiffLineStart
	for range context {
		if start == 0 {
			break
		}
		start = strings.LastIndexByte(a[:start-1], '\n') + 1
	}
	skipped = strings.Count(a[:start], "\n")

	// End: the shared tail, but not into the lines at the start. Then move
	// forward to a line start, and move on by context lines.
	shorterLen := min(len(a), len(b))
	q := min(commonSuffixLen(a, b), shorterLen-firstDiffLineStart)
	endA, endB := len(a)-q, len(b)-q
	atLineStart := (endA == 0 || a[endA-1] == '\n') && (endB == 0 || b[endB-1] == '\n')
	if !atLineStart {
		// The shared tail is identical in a and b, so its first line break is at
		// the same distance from the end in both.
		n := strings.IndexByte(a[endA:], '\n')
		if n < 0 {
			n = q - 1
		}
		endA += n + 1
		endB += n + 1
	}
	for range context {
		n := strings.IndexByte(a[endA:], '\n')
		if n < 0 {
			endA, endB = len(a), len(b)
			break
		}
		endA += n + 1
		endB += n + 1
	}
	return a[start:endA], b[start:endB], skipped
}

// commonPrefixLen returns the length in bytes of the longest common prefix.
func commonPrefixLen(a, b string) int {
	n := min(len(a), len(b))
	i := 0
	for i < n && a[i] == b[i] {
		i++
	}
	return i
}

// commonSuffixLen returns the length in bytes of the longest common suffix.
func commonSuffixLen(a, b string) int {
	n := min(len(a), len(b))
	i := 0
	for i < n && a[len(a)-1-i] == b[len(b)-1-i] {
		i++
	}
	return i
}

// shiftHunks adds offset to the line numbers of every hunk header in diff, so
// that they count lines of the full texts and not of the window that was
// diffed. A header that it can not parse stays as it is.
func shiftHunks(diff string, offset int) string {
	if offset == 0 || diff == "" {
		return diff
	}
	lines := strings.Split(diff, "\n")
	for i, line := range lines {
		m := hunkHeader.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		oldStart, err1 := strconv.Atoi(m[1])
		newStart, err2 := strconv.Atoi(m[3])
		if err1 != nil || err2 != nil {
			continue
		}
		lines[i] = fmt.Sprintf("@@ -%d%s +%d%s @@", oldStart+offset, m[2], newStart+offset, m[4])
	}
	return strings.Join(lines, "\n")
}

// capText cuts s to maxRenderedBytes and maxRenderedLines. When it cuts, it
// ends the text with truncatedMarker on its own line, and the second result is
// true. The cut is always at the start of a UTF-8 character. A text inside the
// limits is returned as it is, with false.
func capText(s string) (string, bool) {
	cut := len(s)
	if cut > maxRenderedBytes {
		cut = maxRenderedBytes
		// s[cut] is the first dropped byte. Move back until it starts a
		// character, so the kept text does not end inside one. For valid
		// UTF-8 this takes at most utf8.UTFMax-1 steps.
		for steps := 0; cut > 0 && !utf8.RuneStart(s[cut]) && steps < utf8.UTFMax; steps++ {
			cut--
		}
	}
	cut = min(cut, lineLimitIndex(s[:cut]))

	if cut == len(s) {
		return s, false
	}
	kept := s[:cut]
	if kept != "" && !strings.HasSuffix(kept, "\n") {
		kept += "\n"
	}
	return kept + truncatedMarker + "\n", true
}

// lineLimitIndex returns the index in s after its maxRenderedLines-th line. It
// returns len(s) when s has fewer lines.
func lineLimitIndex(s string) int {
	idx := 0
	for range maxRenderedLines {
		n := strings.IndexByte(s[idx:], '\n')
		if n < 0 {
			return len(s)
		}
		idx += n + 1
	}
	return idx
}
