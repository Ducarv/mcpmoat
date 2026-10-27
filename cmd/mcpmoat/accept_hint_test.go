package main

import (
	"strings"
	"testing"
)

// testDigest has the real digest format: "pd1:" and 64 hex characters.
const testDigest = "pd1:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

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
				if lines[i] != want {
					t.Errorf("line %d = %q, want %q", i, lines[i], want)
				}
			}
		})
	}
}
