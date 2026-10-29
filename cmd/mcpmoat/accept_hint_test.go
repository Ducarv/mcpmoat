package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/pins"
	"github.com/Ducarv/mcpmoat/internal/report"
)

// TestAcceptAdvice checks when acceptAdvice gives a command and when it gives
// prose steps, and that the prose never holds a command line or the name.
func TestAcceptAdvice(t *testing.T) {
	t.Parallel()

	const cmdPrefix = "mcpmoat pin --accept "
	tests := []struct {
		name          string
		hint          acceptHint
		config        string
		configProblem bool
		wantCommand   bool
		wantText      string // exact text; empty means "check the shape only"
		mustNotAppear string // text that the prose must not hold; empty means none
	}{
		{name: "bare name", hint: acceptHint{name: "srv", digest: testDigest}, wantCommand: true,
			wantText: "mcpmoat pin --accept srv --expect " + testDigest},
		{name: "project", hint: acceptHint{name: "srv", digest: testDigest, project: "/p"}, wantCommand: true,
			wantText: "mcpmoat pin --accept srv --project /p --expect " + testDigest},
		{name: "config", hint: acceptHint{name: "srv", digest: testDigest}, config: "/c.json", wantCommand: true,
			wantText: "mcpmoat pin --accept srv --config /c.json --expect " + testDigest},
		{name: "project and config", hint: acceptHint{name: "srv", digest: testDigest, project: "/p"}, config: "/c.json", wantCommand: true,
			wantText: "mcpmoat pin --accept srv --project /p --config /c.json --expect " + testDigest},
		{name: "name at the length cap", hint: acceptHint{name: strings.Repeat("a", maxWarnNameRunes), digest: testDigest}, wantCommand: true},

		{name: "name with a space", hint: acceptHint{name: "my srv", digest: testDigest}, mustNotAppear: "my srv"},
		{name: "name with a quote", hint: acceptHint{name: "a'b", digest: testDigest}, mustNotAppear: "a'b"},
		{name: "name with a dollar", hint: acceptHint{name: "a$(id)", digest: testDigest}, mustNotAppear: "$(id)"},
		{name: "name with a leading dash", hint: acceptHint{name: "-config", digest: testDigest}, mustNotAppear: "-config"},
		{name: "name with unicode", hint: acceptHint{name: "sérv", digest: testDigest}, mustNotAppear: "sérv"},
		{name: "empty name", hint: acceptHint{name: "", digest: testDigest}},
		{name: "name over the length cap", hint: acceptHint{name: strings.Repeat("a", maxWarnNameRunes+1), digest: testDigest},
			mustNotAppear: strings.Repeat("a", maxWarnNameRunes+1)},

		{name: "project with a space", hint: acceptHint{name: "srv", digest: testDigest, project: "/my p"}, mustNotAppear: "/my p"},
		{name: "project with a quote", hint: acceptHint{name: "srv", digest: testDigest, project: "/p'q"}, mustNotAppear: "/p'q"},
		{name: "config with a space", hint: acceptHint{name: "srv", digest: testDigest}, config: "/my c.json", mustNotAppear: "/my c.json"},
		{name: "config with a dollar", hint: acceptHint{name: "srv", digest: testDigest}, config: "/c$HOME.json", mustNotAppear: "/c$HOME.json"},

		{name: "cut diff", hint: acceptHint{name: "srv", digest: testDigest, truncated: true}},
		{name: "ignored", hint: acceptHint{name: "srv", digest: testDigest, ignored: true}},
		{name: "no diff text", hint: acceptHint{name: "srv", digest: testDigest, noText: true}},
		{name: "ambiguous name", hint: acceptHint{name: "srv", digest: testDigest, ambiguous: true}},
		{name: "ambiguous with project", hint: acceptHint{name: "srv", digest: testDigest, ambiguous: true, project: "/p"}, config: "/c.json"},
		{name: "config problem", hint: acceptHint{name: "srv", digest: testDigest}, configProblem: true},
		{name: "config problem with config", hint: acceptHint{name: "srv", digest: testDigest}, config: "/c.json", configProblem: true},

		// pins.json has no room for the tools: pin --accept would refuse the
		// command, so the hint gives the prose steps with the digest.
		{name: "pins file full", hint: acceptHint{name: "srv", digest: testDigest, full: fileFull},
			wantText: "run pin --accept with this server name and --expect " + testDigest},
		{name: "pins file full with config", hint: acceptHint{name: "srv", digest: testDigest, full: fileFull}, config: "/c.json",
			wantText: "run pin --accept with this server name, --config with the file of this scan, and --expect " + testDigest},
		{name: "pins file full with project", hint: acceptHint{name: "srv", digest: testDigest, project: "/p", full: fileFull},
			wantText: "run pin --accept with this server name, --project with its project path, and --expect " + testDigest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			text, isCommand := acceptAdvice(tt.hint, tt.config, tt.configProblem)
			if isCommand != tt.wantCommand {
				t.Fatalf("acceptAdvice() isCommand = %v, want %v (text %q)", isCommand, tt.wantCommand, text)
			}
			if tt.wantText != "" && text != tt.wantText {
				t.Errorf("acceptAdvice() text = %q, want %q", text, tt.wantText)
			}
			if !strings.Contains(text, tt.hint.digest) {
				t.Errorf("acceptAdvice() text = %q, want the digest in it", text)
			}
			if isCommand {
				if !strings.HasPrefix(text, cmdPrefix) {
					t.Errorf("acceptAdvice() text = %q, want prefix %q", text, cmdPrefix)
				}
				if !strings.HasSuffix(text, " --expect "+tt.hint.digest) {
					t.Errorf("acceptAdvice() text = %q, want suffix %q", text, " --expect "+tt.hint.digest)
				}
				return
			}
			if strings.Contains(text, cmdPrefix) {
				t.Errorf("acceptAdvice() text = %q, want prose with no %q command", text, cmdPrefix)
			}
			if tt.mustNotAppear != "" && strings.Contains(text, tt.mustNotAppear) {
				t.Errorf("acceptAdvice() text = %q, want no untrusted text %q", text, tt.mustNotAppear)
			}
			if !strings.HasPrefix(text, "run pin --accept with ") && !strings.HasPrefix(text, "fix the config file first, then run pin --accept with ") {
				t.Errorf("acceptAdvice() text = %q, want the prose steps", text)
			}
		})
	}
}

// TestWriteAcceptHintsMatchesAdvice checks that each line of writeAcceptHints is
// "To accept <name>: <acceptAdvice text>" plus the fixed notes, so the terminal
// and the JSON output share one decision.
func TestWriteAcceptHintsMatchesAdvice(t *testing.T) {
	t.Parallel()

	hints := []acceptHint{
		{name: "plain", digest: testDigest},
		{name: "withproject", digest: testDigest, project: "/p"},
		{name: "spaced name", digest: testDigest},
		{name: "cut", digest: testDigest, truncated: true},
		{name: "hidden", digest: testDigest, ignored: true},
		{name: "note", digest: testDigest, noText: true},
		{name: "all", digest: testDigest, truncated: true, ignored: true, noText: true},
		{name: "ambig", digest: testDigest, ambiguous: true},
		{name: "badproject", digest: testDigest, project: "/my p"},
		{name: "full", digest: testDigest, full: fileFull},
		{name: "fullcut", digest: testDigest, truncated: true, full: fileFull},
		{name: "share", digest: testDigest, full: shareFull},
		{name: "sharecut", digest: testDigest, truncated: true, full: shareFull},
	}
	tests := []struct {
		name          string
		config        string
		configProblem bool
	}{
		{name: "no config"},
		{name: "config", config: "/c.json"},
		{name: "config with a space", config: "/my c.json"},
		{name: "config problem", configProblem: true},
		{name: "config problem with config", config: "/c.json", configProblem: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var b strings.Builder
			if err := writeAcceptHints(&b, hints, tt.config, tt.configProblem); err != nil {
				t.Fatalf("writeAcceptHints() error = %v, want nil", err)
			}
			lines := strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n")
			if len(lines) != len(hints) {
				t.Fatalf("writeAcceptHints() wrote %d lines, want %d:\n%s", len(lines), len(hints), b.String())
			}
			for i, h := range hints {
				text, _ := acceptAdvice(h, tt.config, tt.configProblem)
				want := "To accept " + cutName(h.name) + ": " + text
				if h.truncated {
					want += hintCutNote
				}
				if h.ignored {
					want += hintIgnoredNote
				}
				if h.noText {
					want += hintNoTextNote
				}
				want += h.full.hintNote()
				if lines[i] != want {
					t.Errorf("line %d = %q, want %q", i, lines[i], want)
				}
			}
		})
	}
}

// TestWriteAcceptHintsStoreFull checks the exact "To accept" lines when
// pins.json has no room for the tools of a server (full is fileFull, #220): the line
// gives the prose steps and the digest, no "mcpmoat pin --accept" command, and
// ends with fileFull.hintNote(), after the notes for changes the user did not
// see. A hint with full notFull keeps its command and gets no such note. The
// name before the colon still goes through cutName: a name with control
// characters is escaped, and a long name is cut.
//
// When only the share of the project servers is full (full is shareFull), the
// line ends with shareFull.hintNote() instead. It must not tell the user to
// remove servers of the user scope: removing one frees no room in the share,
// and that server would then be pinned again with no alert (T2).
func TestWriteAcceptHintsStoreFull(t *testing.T) {
	t.Parallel()

	const steps = "run pin --accept with this server name and --expect " + testDigest
	hostile := "bad\x1b[31m\u202ename"
	long := strings.Repeat("n", maxWarnNameRunes+20)
	tests := []struct {
		name string
		hint acceptHint
		want string
	}{
		{
			name: "full",
			hint: acceptHint{name: "srv", digest: testDigest, full: fileFull},
			want: "To accept srv: " + steps + fileFull.hintNote(),
		},
		{
			name: "not full keeps the command",
			hint: acceptHint{name: "srv", digest: testDigest},
			want: "To accept srv: mcpmoat pin --accept srv --expect " + testDigest,
		},
		{
			name: "full after the notes of unseen changes",
			hint: acceptHint{name: "srv", digest: testDigest, truncated: true, ignored: true, noText: true, full: fileFull},
			want: "To accept srv: " + steps + hintCutNote + hintIgnoredNote + hintNoTextNote + fileFull.hintNote(),
		},
		{
			name: "cut diff without full has no full note",
			hint: acceptHint{name: "srv", digest: testDigest, truncated: true},
			want: "To accept srv: " + steps + hintCutNote,
		},
		{
			name: "control characters in the name",
			hint: acceptHint{name: hostile, digest: testDigest, full: fileFull},
			want: "To accept " + cutName(hostile) + ": " + steps + fileFull.hintNote(),
		},
		{
			name: "long name",
			hint: acceptHint{name: long, digest: testDigest, full: fileFull},
			want: "To accept " + cutName(long) + ": " + steps + fileFull.hintNote(),
		},
		{
			name: "project share full",
			hint: acceptHint{name: "srv", digest: testDigest, full: shareFull},
			want: "To accept srv: " + steps + shareFull.hintNote(),
		},
		{
			name: "project share full after the notes of unseen changes",
			hint: acceptHint{name: "srv", digest: testDigest, truncated: true, ignored: true, noText: true, full: shareFull},
			want: "To accept srv: " + steps + hintCutNote + hintIgnoredNote + hintNoTextNote + shareFull.hintNote(),
		},
		{
			name: "project share full with control characters in the name",
			hint: acceptHint{name: hostile, digest: testDigest, full: shareFull},
			want: "To accept " + cutName(hostile) + ": " + steps + shareFull.hintNote(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var b strings.Builder
			if err := writeAcceptHints(&b, []acceptHint{tt.hint}, "", false); err != nil {
				t.Fatalf("writeAcceptHints() error = %v, want nil", err)
			}
			got := b.String()
			if got != tt.want+"\n" {
				t.Errorf("writeAcceptHints() = %q, want %q", got, tt.want+"\n")
			}
			assertTerminalSafe(t, got)
			full := tt.hint.full != notFull
			if full && strings.Contains(got, "mcpmoat pin --accept") {
				t.Errorf("writeAcceptHints() = %q holds a command, want none when pins.json is full", got)
			}
			wantFile, wantShare := tt.hint.full == fileFull, tt.hint.full == shareFull
			if n := strings.Count(got, fileFull.hintNote()); n != boolCount(wantFile) {
				t.Errorf("writeAcceptHints() has the full note %d times, want %d", n, boolCount(wantFile))
			}
			if n := strings.Count(got, shareFull.hintNote()); n != boolCount(wantShare) {
				t.Errorf("writeAcceptHints() has the share note %d times, want %d", n, boolCount(wantShare))
			}
			if wantShare && strings.Contains(got, fileFull.fix()) {
				t.Errorf("writeAcceptHints() = %q tells the user to remove any server, want only project servers when the share is full", got)
			}
			if _, isCommand := acceptAdvice(tt.hint, "", false); full && isCommand {
				t.Errorf("acceptAdvice() isCommand = true, want false when pins.json is full")
			}
		})
	}
}

// boolCount returns 1 for true and 0 for false.
func boolCount(b bool) int {
	if b {
		return 1
	}
	return 0
}

// TestAcceptDecisionReason checks the reason of acceptDecision for each cause
// that stops the command, the order of the causes when more than one applies,
// and that the reason is empty exactly when acceptAdvice gives a command. The
// JSON "accept.reason" comes from it (see acceptOf).
func TestAcceptDecisionReason(t *testing.T) {
	t.Parallel()

	ok := acceptHint{name: "srv", digest: testDigest}
	with := func(f func(h *acceptHint)) acceptHint {
		h := ok
		f(&h)
		return h
	}
	tests := []struct {
		name          string
		hint          acceptHint
		config        string
		configProblem bool
		want          string
	}{
		{name: "command", hint: ok},
		{name: "cut diff", hint: with(func(h *acceptHint) { h.truncated = true }), want: report.AcceptReasonReview},
		{name: "ignored change", hint: with(func(h *acceptHint) { h.ignored = true }), want: report.AcceptReasonReview},
		{name: "change with no text", hint: with(func(h *acceptHint) { h.noText = true }), want: report.AcceptReasonReview},
		{name: "pins file full", hint: with(func(h *acceptHint) { h.full = fileFull }), want: report.AcceptReasonPinsFull},
		{name: "project share full", hint: with(func(h *acceptHint) { h.full = shareFull }), want: report.AcceptReasonProjectShareFull},
		{name: "unknown full kind fails closed", hint: with(func(h *acceptHint) { h.full = fullKind(99) }), want: report.AcceptReasonPinsFull},
		{name: "config problem", hint: ok, configProblem: true, want: report.AcceptReasonConfigProblem},
		{name: "ambiguous name", hint: with(func(h *acceptHint) { h.ambiguous = true }), want: report.AcceptReasonAmbiguousName},
		{name: "name with a space", hint: with(func(h *acceptHint) { h.name = "my srv" }), want: report.AcceptReasonNotShellSafe},
		{name: "empty name", hint: with(func(h *acceptHint) { h.name = "" }), want: report.AcceptReasonNotShellSafe},
		{name: "project with a quote", hint: with(func(h *acceptHint) { h.project = "/p'q" }), want: report.AcceptReasonNotShellSafe},
		{name: "config with a space", hint: ok, config: "/my c.json", want: report.AcceptReasonNotShellSafe},
		// More than one cause: the first of the order in acceptDecision wins.
		{
			name: "review comes before full",
			hint: with(func(h *acceptHint) { h.truncated, h.full = true, fileFull }),
			want: report.AcceptReasonReview,
		},
		{
			name: "full comes before config problem",
			hint: with(func(h *acceptHint) { h.full = shareFull }), configProblem: true,
			want: report.AcceptReasonProjectShareFull,
		},
		{
			name: "config problem comes before ambiguous name",
			hint: with(func(h *acceptHint) { h.ambiguous = true }), configProblem: true,
			want: report.AcceptReasonConfigProblem,
		},
		{
			name: "ambiguous name comes before unsafe word",
			hint: with(func(h *acceptHint) { h.ambiguous, h.name = true, "my srv" }),
			want: report.AcceptReasonAmbiguousName,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			text, reason := acceptDecision(tt.hint, tt.config, tt.configProblem)
			if reason != tt.want {
				t.Errorf("acceptDecision() reason = %q, want %q", reason, tt.want)
			}
			if reason != "" && !slices.Contains(report.AcceptReasons(), reason) {
				t.Errorf("acceptDecision() reason = %q, which is not in report.AcceptReasons()", reason)
			}
			advice, isCommand := acceptAdvice(tt.hint, tt.config, tt.configProblem)
			if advice != text || isCommand != (reason == "") {
				t.Errorf("acceptAdvice() = (%q, %v), want (%q, %v) (same decision)", advice, isCommand, text, reason == "")
			}
		})
	}
}

// TestAcceptOfReason checks the accept object that acceptOf builds: a command
// and no reason when the hint is a command, and a reason and no command for a
// full pins.json or a full project share (storeFull and shareFull cannot be
// made by a small scan, so the hint is built by hand). A server with no hint
// has no accept object.
func TestAcceptOfReason(t *testing.T) {
	t.Parallel()

	srv := discover.Server{Name: "srv", Client: discover.ClientClaudeCode, Scope: discover.ScopeGlobal, Source: "/home/u/.claude.json"}
	id := serverIdentity(srv)
	hint := func(f func(h *acceptHint)) map[pins.Identity]acceptHint {
		h := acceptHint{name: "srv", id: id, digest: testDigest}
		f(&h)
		return map[pins.Identity]acceptHint{id: h}
	}
	tests := []struct {
		name        string
		hints       map[pins.Identity]acceptHint
		wantNil     bool
		wantCommand bool
		wantReason  string
	}{
		{name: "no hint", hints: nil, wantNil: true},
		{name: "command", hints: hint(func(*acceptHint) {}), wantCommand: true},
		{name: "cut diff", hints: hint(func(h *acceptHint) { h.truncated = true }), wantReason: report.AcceptReasonReview},
		{name: "ignored", hints: hint(func(h *acceptHint) { h.ignored = true }), wantReason: report.AcceptReasonReview},
		{name: "no diff text", hints: hint(func(h *acceptHint) { h.noText = true }), wantReason: report.AcceptReasonReview},
		{name: "pins file full", hints: hint(func(h *acceptHint) { h.full = fileFull }), wantReason: report.AcceptReasonPinsFull},
		{name: "project share full", hints: hint(func(h *acceptHint) { h.full = shareFull }), wantReason: report.AcceptReasonProjectShareFull},
		{name: "ambiguous name", hints: hint(func(h *acceptHint) { h.ambiguous = true }), wantReason: report.AcceptReasonAmbiguousName},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := acceptOf(srv, tt.hints, "", false)
			if tt.wantNil {
				if got != nil {
					t.Fatalf("acceptOf() = %+v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatal("acceptOf() = nil, want an accept object")
			}
			if got.Digest != testDigest {
				t.Errorf("Digest = %q, want %q", got.Digest, testDigest)
			}
			if (got.Command != "") != tt.wantCommand {
				t.Errorf("Command = %q, want a command: %v", got.Command, tt.wantCommand)
			}
			if got.Reason != tt.wantReason {
				t.Errorf("Reason = %q, want %q", got.Reason, tt.wantReason)
			}
		})
	}

	t.Run("config problem", func(t *testing.T) {
		t.Parallel()
		got := acceptOf(srv, hint(func(*acceptHint) {}), "", true)
		if got == nil || got.Command != "" || got.Reason != report.AcceptReasonConfigProblem {
			t.Errorf("acceptOf() = %+v, want no command and reason %q", got, report.AcceptReasonConfigProblem)
		}
	})
}
