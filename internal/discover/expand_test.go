package discover

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode"

	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

// The tests in this file are in package discover (not discover_test), so they
// can check that a zero Args, URL or Secret stays zero (its pointer is nil),
// which no exported method can tell apart from an empty value.

// expandProjectPath is the ProjectPath of the test servers. It is built with
// filepath.Join, so ${workspaceFolder} and ${workspaceFolderBasename} give
// the same result on every system.
var expandProjectPath = filepath.Join(string(filepath.Separator)+"home", "dev", "proj")

// expandLookup returns a lookup that gives the values in env. A name that is
// not a key of env is not set.
func expandLookup(env map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		v, ok := env[name]
		return v, ok
	}
}

// expandServer returns a server of client c with no placeholders and every
// field that Expand must keep as written set to a non-zero value.
func expandServer(c Client, projectPath string) Server {
	return Server{
		Name:        "srv",
		Client:      c,
		Scope:       ScopeProject,
		ProjectPath: projectPath,
		Source:      "/cfg/.mcp.json",
		Untrusted:   true,
		State:       StateUnapproved,
		Transport:   TransportStdio,
		Dir:         "/work",
	}
}

// expandField puts a text into one Server field and reads it back.
type expandField struct {
	// name is the fixed ExpandError.Field text for the field.
	name string
	set  func(s *Server, text string)
	get  func(s Server) string
}

// expandFields returns one expandField for each field that Expand expands.
// Each call returns a new slice.
func expandFields() []expandField {
	return []expandField{
		{
			name: "command",
			set:  func(s *Server, v string) { s.Command = v },
			get:  func(s Server) string { return s.Command },
		},
		{
			name: "args",
			set:  func(s *Server, v string) { s.Args = NewArgs([]string{"--flag", v}) },
			get: func(s Server) string {
				vals := s.Args.Values()
				if len(vals) != 2 || vals[0] != "--flag" {
					return fmt.Sprintf("<bad args, len %d>", len(vals))
				}
				return vals[1]
			},
		},
		{
			name: "env",
			set:  func(s *Server, v string) { s.Env = SecretMap{"API_KEY": NewSecret(v)} },
			get:  func(s Server) string { return s.Env["API_KEY"].Reveal() },
		},
		{
			name: "url",
			set:  func(s *Server, v string) { s.URL = NewURL(v) },
			get:  func(s Server) string { return s.URL.Reveal() },
		},
		{
			name: "headers",
			set:  func(s *Server, v string) { s.Headers = SecretMap{"Authorization": NewSecret(v)} },
			get:  func(s Server) string { return s.Headers["Authorization"].Reveal() },
		},
	}
}

// expandCommand expands text as the Command of a server of client c.
func expandCommand(c Client, projectPath, text string, env map[string]string) (string, error) {
	s := expandServer(c, projectPath)
	s.Command = text
	out, err := Expand(s, expandLookup(env))
	if err != nil {
		return "", err
	}
	return out.Command, nil
}

// checkExpandError fails the test unless err is an *ExpandError with the
// given field, name and sentinel error.
func checkExpandError(t *testing.T, err error, field, name string, sentinel error) {
	t.Helper()
	if err == nil {
		t.Fatalf("Expand() error = nil, want *ExpandError{Field: %q, Name: %q}", field, name)
	}
	var xe *ExpandError
	if !errors.As(err, &xe) {
		t.Fatalf("Expand() error = %T (%v), want *ExpandError", err, err)
	}
	if xe.Field != field {
		t.Errorf("ExpandError.Field = %q, want %q", xe.Field, field)
	}
	if xe.Name != name {
		t.Errorf("ExpandError.Name = %q, want %q", xe.Name, name)
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("errors.Is(err, %v) = false, err = %v", sentinel, err)
	}
}

func TestExpandClaudeCodeSyntax(t *testing.T) {
	t.Parallel()
	env := map[string]string{
		"A":     "a",
		"B":     "b",
		"EMPTY": "",
		// REF holds a placeholder. One pass means it stays as written.
		"REF":   "${A}",
		"OTHER": "o",
	}
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "no placeholder", in: "npx -y server", want: "npx -y server"},
		{name: "empty text", in: "", want: ""},
		{name: "whole value", in: "${A}", want: "a"},
		{name: "inside text", in: "pre-${A}-post", want: "pre-a-post"},
		{name: "set but empty", in: "x${EMPTY}y", want: "xy"},
		{name: "default when unset", in: "${UNSET:-def}", want: "def"},
		{name: "set but empty ignores the default", in: "${EMPTY:-def}", want: ""},
		{name: "set ignores the default", in: "${A:-def}", want: "a"},
		{name: "empty default", in: "${UNSET:-}", want: ""},
		// The body splits at the first ":-", so the default of
		// ${X:-a:-b} is "a:-b". This is the chosen behaviour.
		{name: "split at the first :-", in: "${UNSET:-a:-b}", want: "a:-b"},
		{name: "set with two :-", in: "${A:-a:-b}", want: "a"},
		{name: "empty name with default", in: "${:-d}", want: "d"},
		{name: "default with spaces and colons", in: "${UNSET:-http://h:8080/x y}", want: "http://h:8080/x y"},
		{name: "several placeholders", in: "${A}${B}", want: "ab"},
		{name: "several with text", in: "x ${A} y ${B} z ${UNSET:-d}", want: "x a y b z d"},
		{name: "same placeholder twice", in: "${A}/${A}", want: "a/a"},
		{name: "unicode around", in: "é${A}ü", want: "éaü"},
		{name: "no braces", in: "$A and $B", want: "$A and $B"},
		{name: "braces without dollar", in: "{A}", want: "{A}"},
		{name: "lone dollar", in: "$", want: "$"},
		{name: "unterminated", in: "${A", want: "${A"},
		{name: "unterminated at end", in: "x${", want: "x${"},
		{name: "unterminated after a placeholder", in: "${A}${B", want: "a${B"},
		{name: "empty body", in: "${}", want: "${}"},
		{name: "empty body then placeholder", in: "${}${A}", want: "${}a"},
		{name: "empty body with extra brace", in: "${}}", want: "${}}"},
		{name: "double dollar", in: "$${A}", want: "$a"},
		{name: "value is not expanded again", in: "${REF}", want: "${A}"},
		// The body ends at the first "}", so the default is "${OTHER" and
		// the last "}" is plain text. The default is not expanded again.
		{name: "default is not expanded again", in: "${UNSET:-${OTHER}}", want: "${OTHER}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := expandCommand(ClientClaudeCode, expandProjectPath, tt.in, env)
			if err != nil {
				t.Fatalf("Expand(%q) error = %v, want nil", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("Expand(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestExpandClaudeCodeMissing(t *testing.T) {
	t.Parallel()
	env := map[string]string{"A": "a", "EMPTY": ""}
	tests := []struct {
		name     string
		in       string
		wantName string
	}{
		{name: "whole value", in: "${MISSING}", wantName: "MISSING"},
		{name: "before a set one", in: "${MISSING}${A}", wantName: "MISSING"},
		{name: "after a set one", in: "${A}-${MISSING}", wantName: "MISSING"},
		{name: "first missing wins", in: "${M1}${M2}", wantName: "M1"},
		{name: "cursor userHome is a name", in: "${userHome}", wantName: "userHome"},
		{name: "case matters", in: "${a}", wantName: "a"},
		{name: "underscore name", in: "${_M_1}", wantName: "_M_1"},
		// The body is looked up as written, so these forms are missing
		// variables too. The body is not a plain variable name, so the
		// error drops it: Name is "".
		{name: "bash dash form", in: "${M-x}", wantName: ""},
		{name: "single colon", in: "${M:x}", wantName: ""},
		{name: "spaces around the name", in: "${ A }", wantName: ""},
		{name: "body ends at the first close brace", in: "${A ${B}", wantName: ""},
		{name: "nested placeholder", in: "${${A}}", wantName: ""},
		{name: "cursor env form", in: "${env:A}", wantName: ""},
		{name: "digit first", in: "${1A}", wantName: ""},
		{name: "non-ASCII letter", in: "${Ä}", wantName: ""},
		{name: "secret with a placeholder form", in: "p4ss${w0rd-9f8e7d}", wantName: ""},
		{name: "name of 64 bytes is kept", in: "${" + strings.Repeat("M", 64) + "}", wantName: strings.Repeat("M", 64)},
		{name: "name of 65 bytes is dropped", in: "${" + strings.Repeat("M", 65) + "}", wantName: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := expandCommand(ClientClaudeCode, expandProjectPath, tt.in, env)
			checkExpandError(t, err, "command", tt.wantName, ErrMissingVariable)
		})
	}
}

func TestExpandCursorSyntax(t *testing.T) {
	t.Parallel()
	sep := string(filepath.Separator)
	env := map[string]string{
		"A":     "a",
		"EMPTY": "",
		"HOME":  "/home/dev",
		"REF":   "${env:A}",
	}
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "env", in: "${env:A}", want: "a"},
		{name: "env inside text", in: "pre-${env:A}-post", want: "pre-a-post"},
		{name: "env set but empty", in: "x${env:EMPTY}y", want: "xy"},
		{name: "userHome", in: "${userHome}/.config", want: "/home/dev/.config"},
		{name: "workspaceFolder", in: "${workspaceFolder}", want: expandProjectPath},
		{name: "workspaceFolderBasename", in: "${workspaceFolderBasename}", want: "proj"},
		{name: "pathSeparator", in: "a${pathSeparator}b", want: "a" + sep + "b"},
		{name: "slash", in: "a${/}b", want: "a" + sep + "b"},
		{name: "workspace path", in: "${workspaceFolder}${/}src", want: expandProjectPath + sep + "src"},
		{name: "several", in: "${env:A}${userHome}${env:A}", want: "a/home/deva"},
		// Claude Code forms are not Cursor placeholders: they stay as
		// written, also when the variable is set.
		{name: "claude form stays", in: "${A}", want: "${A}"},
		{name: "claude default form stays", in: "${A:-d}", want: "${A:-d}"},
		{name: "unknown placeholder stays", in: "${config:x}", want: "${config:x}"},
		{name: "env prefix is case sensitive", in: "${ENV:A}", want: "${ENV:A}"},
		{name: "userhome is case sensitive", in: "${userhome}", want: "${userhome}"},
		{name: "workspacefolder is case sensitive", in: "${workspacefolder}", want: "${workspacefolder}"},
		{name: "empty body", in: "${}", want: "${}"},
		{name: "unterminated", in: "${env:A", want: "${env:A"},
		{name: "no placeholder", in: "node server.js", want: "node server.js"},
		{name: "value is not expanded again", in: "${env:REF}", want: "${env:A}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := expandCommand(ClientCursor, expandProjectPath, tt.in, env)
			if err != nil {
				t.Fatalf("Expand(%q) error = %v, want nil", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("Expand(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestExpandCursorErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		in          string
		projectPath string
		env         map[string]string
		wantName    string
		wantErr     error
	}{
		{name: "env missing", in: "${env:MISSING}", projectPath: expandProjectPath, wantName: "MISSING", wantErr: ErrMissingVariable},
		{name: "env empty name", in: "${env:}", projectPath: expandProjectPath, wantName: "", wantErr: ErrMissingVariable},
		{name: "env with claude default", in: "${env:M:-d}", projectPath: expandProjectPath, wantName: "", wantErr: ErrMissingVariable},
		{name: "env with a dash", in: "${env:M-x}", projectPath: expandProjectPath, wantName: "", wantErr: ErrMissingVariable},
		{name: "env with spaces", in: "${env: A }", projectPath: expandProjectPath, wantName: "", wantErr: ErrMissingVariable},
		{name: "env secret with a placeholder form", in: "p4ss${env:w0rd-9f8e7d}", projectPath: expandProjectPath, wantName: "", wantErr: ErrMissingVariable},
		{name: "userHome without HOME", in: "${userHome}", projectPath: expandProjectPath, wantName: "HOME", wantErr: ErrMissingVariable},
		{name: "workspaceFolder without project", in: "${workspaceFolder}", wantName: "workspaceFolder", wantErr: ErrNoWorkspaceFolder},
		{name: "workspaceFolderBasename without project", in: "${workspaceFolderBasename}", wantName: "workspaceFolderBasename", wantErr: ErrNoWorkspaceFolder},
		{name: "workspaceFolder without project, env set", in: "${workspaceFolder}", env: map[string]string{"workspaceFolder": "/x"}, wantName: "workspaceFolder", wantErr: ErrNoWorkspaceFolder},
		{name: "first error wins", in: "${env:M1}${workspaceFolder}", wantName: "M1", wantErr: ErrMissingVariable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := expandCommand(ClientCursor, tt.projectPath, tt.in, tt.env)
			checkExpandError(t, err, "command", tt.wantName, tt.wantErr)
		})
	}
}

// TestExpandCursorNoWorkspaceOK checks that a server with no ProjectPath
// expands when it uses no workspace placeholder.
func TestExpandCursorNoWorkspaceOK(t *testing.T) {
	t.Parallel()
	got, err := expandCommand(ClientCursor, "", "${env:A}${/}x", map[string]string{"A": "a"})
	if err != nil {
		t.Fatalf("Expand() error = %v, want nil", err)
	}
	if want := "a" + string(filepath.Separator) + "x"; got != want {
		t.Errorf("Expand() = %q, want %q", got, want)
	}
}

// TestExpandEveryField checks that each client expands every field, and that
// a missing variable gives the field name of the failing field.
func TestExpandEveryField(t *testing.T) {
	t.Parallel()
	clients := []struct {
		client  Client
		text    string
		missing string
	}{
		{client: ClientClaudeCode, text: "pre-${V}-post", missing: "pre-${MISSING}"},
		{client: ClientCursor, text: "pre-${env:V}-post", missing: "pre-${env:MISSING}"},
	}
	env := map[string]string{"V": "val"}
	for _, c := range clients {
		for _, f := range expandFields() {
			t.Run(string(c.client)+"/"+f.name, func(t *testing.T) {
				t.Parallel()
				s := expandServer(c.client, expandProjectPath)
				f.set(&s, c.text)
				out, err := Expand(s, expandLookup(env))
				if err != nil {
					t.Fatalf("Expand() error = %v, want nil", err)
				}
				if got := f.get(out); got != "pre-val-post" {
					t.Errorf("%s = %q, want %q", f.name, got, "pre-val-post")
				}
				if got := f.get(s); got != c.text {
					t.Errorf("input %s = %q after Expand, want %q (input changed)", f.name, got, c.text)
				}

				bad := expandServer(c.client, expandProjectPath)
				f.set(&bad, c.missing)
				out, err = Expand(bad, expandLookup(env))
				checkExpandError(t, err, f.name, "MISSING", ErrMissingVariable)
				if !reflect.DeepEqual(out, Server{}) {
					t.Errorf("Expand() on error returned a non-zero Server: %+v", out)
				}
			})
		}
	}
}

// TestExpandFieldOrder checks the fixed order of the checks: Command, Args,
// Env in sorted key order, URL, then Headers in sorted key order. It runs
// each case many times, because Go map order changes between runs.
func TestExpandFieldOrder(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		set       func(s *Server)
		wantField string
		wantName  string
	}{
		{
			name: "command before args",
			set: func(s *Server) {
				s.Command = "${M_CMD}"
				s.Args = NewArgs([]string{"${M_ARGS}"})
			},
			wantField: "command", wantName: "M_CMD",
		},
		{
			name: "args before env",
			set: func(s *Server) {
				s.Args = NewArgs([]string{"ok", "${M_ARG1}", "${M_ARG2}"})
				s.Env = SecretMap{"A": NewSecret("${M_ENV}")}
			},
			wantField: "args", wantName: "M_ARG1",
		},
		{
			name: "env in sorted key order",
			set: func(s *Server) {
				s.Env = SecretMap{
					"Z_KEY": NewSecret("${M_Z}"),
					"A_KEY": NewSecret("${M_A}"),
					"M_KEY": NewSecret("${M_M}"),
				}
			},
			wantField: "env", wantName: "M_A",
		},
		{
			name: "env before url",
			set: func(s *Server) {
				s.Env = SecretMap{"K": NewSecret("${M_ENV}")}
				s.URL = NewURL("${M_URL}")
			},
			wantField: "env", wantName: "M_ENV",
		},
		{
			name: "url before headers",
			set: func(s *Server) {
				s.URL = NewURL("${M_URL}")
				s.Headers = SecretMap{"H": NewSecret("${M_H}")}
			},
			wantField: "url", wantName: "M_URL",
		},
		{
			name: "headers in sorted key order",
			set: func(s *Server) {
				s.Headers = SecretMap{
					"X-Zed":   NewSecret("${M_Z}"),
					"X-Alpha": NewSecret("${M_A}"),
					"X-Mid":   NewSecret("${M_M}"),
				}
			},
			wantField: "headers", wantName: "M_A",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := expandServer(ClientClaudeCode, expandProjectPath)
			tt.set(&s)
			for range 50 {
				_, err := Expand(s, expandLookup(nil))
				checkExpandError(t, err, tt.wantField, tt.wantName, ErrMissingVariable)
				if t.Failed() {
					return
				}
			}
		})
	}
}

// TestExpandKeysNotExpanded checks that env and header names stay as
// written.
func TestExpandKeysNotExpanded(t *testing.T) {
	t.Parallel()
	tests := []struct {
		client Client
		key    string
	}{
		{client: ClientClaudeCode, key: "${A}"},
		{client: ClientCursor, key: "${env:A}"},
	}
	for _, tt := range tests {
		t.Run(string(tt.client), func(t *testing.T) {
			t.Parallel()
			s := expandServer(tt.client, expandProjectPath)
			s.Env = SecretMap{tt.key: NewSecret("v")}
			s.Headers = SecretMap{"X-" + tt.key: NewSecret("h")}
			out, err := Expand(s, expandLookup(map[string]string{"A": "a"}))
			if err != nil {
				t.Fatalf("Expand() error = %v, want nil", err)
			}
			if got := out.Env.Keys(); !reflect.DeepEqual(got, []string{tt.key}) {
				t.Errorf("Env keys = %q, want %q", got, []string{tt.key})
			}
			if got := out.Headers.Keys(); !reflect.DeepEqual(got, []string{"X-" + tt.key}) {
				t.Errorf("Headers keys = %q, want %q", got, []string{"X-" + tt.key})
			}
		})
	}
}

// expandFullServer returns a server of client c with a placeholder in every
// field. text is the placeholder form of variable V for the client.
func expandFullServer(c Client, text string) Server {
	s := expandServer(c, expandProjectPath)
	s.Command = "run-" + text
	s.Args = NewArgs([]string{"--token", text, ""})
	s.Env = SecretMap{"API_KEY": NewSecret(text), "ZERO": {}, "PLAIN": NewSecret("p")}
	s.URL = NewURL("https://example.com/" + text)
	s.Headers = SecretMap{"Authorization": NewSecret("Bearer " + text), "Zero": {}}
	return s
}

// TestExpandCopy checks for every client that Expand does not change its
// input, that the result does not share the Env and Headers maps with the
// input, and that the fields Expand does not expand stay as written.
func TestExpandCopy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		client Client
		text   string
		// want is the expanded text, or text itself for no expansion.
		want string
	}{
		{name: "claude-code", client: ClientClaudeCode, text: "${V}", want: "val"},
		{name: "cursor", client: ClientCursor, text: "${env:V}", want: "val"},
		{name: "codex", client: ClientCodex, text: "${V}", want: "${V}"},
		{name: "unknown client", client: Client("other"), text: "${V}", want: "${V}"},
		{name: "empty client", client: Client(""), text: "${V}", want: "${V}"},
	}
	env := map[string]string{"V": "val"}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			in := expandFullServer(tt.client, tt.text)
			out, err := Expand(in, expandLookup(env))
			if err != nil {
				t.Fatalf("Expand() error = %v, want nil", err)
			}

			if !reflect.DeepEqual(in, expandFullServer(tt.client, tt.text)) {
				t.Error("Expand() changed its input")
			}

			want := expandFullServer(tt.client, tt.want)
			if !reflect.DeepEqual(out, want) {
				t.Errorf("Expand() = %#v, want %#v (views: got %+v, want %+v)",
					out, want, viewOf(out), viewOf(want))
			}
			// The zero Secrets in the maps stay zero, not NewSecret("").
			if out.Env["ZERO"].v != nil || out.Headers["Zero"].v != nil {
				t.Error("a zero Secret in a map is not zero after Expand")
			}

			// A change to the result maps must not reach the input maps.
			out.Env["API_KEY"] = NewSecret("changed")
			out.Env["NEW"] = NewSecret("new")
			out.Headers["Authorization"] = NewSecret("changed")
			delete(out.Headers, "Zero")
			if !reflect.DeepEqual(in, expandFullServer(tt.client, tt.text)) {
				t.Error("a change to the Expand result maps changed the input: the maps are shared")
			}
		})
	}
}

// TestExpandZeroValues checks that zero and empty values keep their form.
func TestExpandZeroValues(t *testing.T) {
	t.Parallel()
	for _, c := range []Client{ClientClaudeCode, ClientCursor, ClientCodex} {
		t.Run(string(c)+"/zero", func(t *testing.T) {
			t.Parallel()
			in := expandServer(c, expandProjectPath)
			out, err := Expand(in, expandLookup(nil))
			if err != nil {
				t.Fatalf("Expand() error = %v, want nil", err)
			}
			if out.Args.v != nil {
				t.Error("zero Args is not zero after Expand")
			}
			if out.URL.v != nil {
				t.Error("zero URL is not zero after Expand")
			}
			if out.Env != nil || out.Headers != nil {
				t.Errorf("nil maps after Expand: Env nil = %v, Headers nil = %v, want both nil",
					out.Env == nil, out.Headers == nil)
			}
			if !reflect.DeepEqual(out, in) {
				t.Errorf("Expand() = %+v, want %+v", out, in)
			}
		})
		t.Run(string(c)+"/empty", func(t *testing.T) {
			t.Parallel()
			in := expandServer(c, expandProjectPath)
			in.Args = NewArgs([]string{})
			in.URL = NewURL("")
			in.Env = SecretMap{}
			in.Headers = SecretMap{}
			out, err := Expand(in, expandLookup(nil))
			if err != nil {
				t.Fatalf("Expand() error = %v, want nil", err)
			}
			if out.Args.v == nil || out.Args.Len() != 0 {
				t.Errorf("empty Args: zero = %v, Len = %d, want non-zero and 0", out.Args.v == nil, out.Args.Len())
			}
			if out.URL.v == nil || out.URL.Reveal() != "" {
				t.Errorf("empty URL: zero = %v, want non-zero empty URL", out.URL.v == nil)
			}
			if out.Env == nil || len(out.Env) != 0 {
				t.Errorf("empty Env: nil = %v, len = %d, want non-nil and empty", out.Env == nil, len(out.Env))
			}
			if out.Headers == nil || len(out.Headers) != 0 {
				t.Errorf("empty Headers: nil = %v, len = %d, want non-nil and empty", out.Headers == nil, len(out.Headers))
			}
			if !reflect.DeepEqual(out, in) {
				t.Errorf("Expand() = %+v, want %+v", out, in)
			}
		})
	}
}

func TestExpandCodexUnchanged(t *testing.T) {
	t.Parallel()
	in := expandFullServer(ClientCodex, "${V}${env:V}${userHome}${workspaceFolder}")
	in.ProjectPath = ""
	out, err := Expand(in, func(string) (string, bool) {
		t.Error("Expand() called lookup for a Codex server")
		return "x", true
	})
	if err != nil {
		t.Fatalf("Expand() error = %v, want nil", err)
	}
	if !reflect.DeepEqual(out, in) {
		t.Errorf("Expand() = %+v, want the input unchanged", viewOf(out))
	}
}

func TestExpandNilLookup(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		client   Client
		in       string
		want     string
		wantName string
		wantErr  error
	}{
		{name: "claude default", client: ClientClaudeCode, in: "${A:-d}", want: "d"},
		{name: "claude missing", client: ClientClaudeCode, in: "${A}", wantName: "A", wantErr: ErrMissingVariable},
		{name: "claude no placeholder", client: ClientClaudeCode, in: "plain", want: "plain"},
		{name: "cursor separator", client: ClientCursor, in: "${/}", want: string(filepath.Separator)},
		{name: "cursor workspace", client: ClientCursor, in: "${workspaceFolderBasename}", want: "proj"},
		{name: "cursor env missing", client: ClientCursor, in: "${env:A}", wantName: "A", wantErr: ErrMissingVariable},
		{name: "cursor userHome missing", client: ClientCursor, in: "${userHome}", wantName: "HOME", wantErr: ErrMissingVariable},
		{name: "codex", client: ClientCodex, in: "${A}", want: "${A}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := expandServer(tt.client, expandProjectPath)
			s.Command = tt.in
			out, err := Expand(s, nil)
			if tt.wantErr != nil {
				checkExpandError(t, err, "command", tt.wantName, tt.wantErr)
				return
			}
			if err != nil {
				t.Fatalf("Expand() error = %v, want nil", err)
			}
			if out.Command != tt.want {
				t.Errorf("Command = %q, want %q", out.Command, tt.want)
			}
		})
	}
}

func TestExpandErrorText(t *testing.T) {
	t.Parallel()
	name64 := strings.Repeat("N", maxNameLen)
	name65 := strings.Repeat("N", maxNameLen+1)
	tests := []struct {
		name string
		err  *ExpandError
		want string
	}{
		{
			name: "missing",
			err:  &ExpandError{Field: "env", Name: "TOKEN", Err: ErrMissingVariable},
			want: "cannot expand env: variable TOKEN: variable is not set",
		},
		{
			name: "no workspace",
			err:  &ExpandError{Field: "args", Name: "workspaceFolder", Err: ErrNoWorkspaceFolder},
			want: "cannot expand args: variable workspaceFolder: server has no workspace folder",
		},
		{
			name: "name of maxNameLen bytes is shown",
			err:  &ExpandError{Field: "env", Name: name64, Err: ErrMissingVariable},
			want: "cannot expand env: variable " + name64 + ": variable is not set",
		},
		{
			name: "nil Err",
			err:  &ExpandError{Field: "command", Name: "X"},
			want: "cannot expand command: variable X",
		},
		{
			name: "nil Err and invalid name",
			err:  &ExpandError{Field: "command", Name: "A-B"},
			want: "cannot expand command: variable with an invalid name",
		},
		// A name that is not a plain variable name is never shown, also
		// when an ExpandError is built by hand with it.
		{
			name: "empty name",
			err:  &ExpandError{Field: "url", Name: "", Err: ErrMissingVariable},
			want: "cannot expand url: variable with an invalid name: variable is not set",
		},
		{
			name: "control characters",
			err:  &ExpandError{Field: "headers", Name: "A\x1b[31mB\n", Err: ErrMissingVariable},
			want: "cannot expand headers: variable with an invalid name: variable is not set",
		},
		{
			name: "bidi character",
			err:  &ExpandError{Field: "env", Name: "A\u202eB", Err: ErrMissingVariable},
			want: "cannot expand env: variable with an invalid name: variable is not set",
		},
		{
			name: "name over maxNameLen bytes",
			err:  &ExpandError{Field: "env", Name: name65, Err: ErrMissingVariable},
			want: "cannot expand env: variable with an invalid name: variable is not set",
		},
		{
			name: "secret part with a dash",
			err:  &ExpandError{Field: "env", Name: "w0rd-9f8e7d", Err: ErrMissingVariable},
			want: "cannot expand env: variable with an invalid name: variable is not set",
		},
		{
			name: "invalid name with no workspace",
			err:  &ExpandError{Field: "args", Name: "work space", Err: ErrNoWorkspaceFolder},
			want: "cannot expand args: variable with an invalid name: server has no workspace folder",
		},
		{
			name: "too long has no name part",
			err:  &ExpandError{Field: "args", Err: ErrExpandedTooLong},
			want: "cannot expand args: expanded text is too long",
		},
		{
			name: "too long with an invalid name has no name part",
			err:  &ExpandError{Field: "url", Name: "a b", Err: ErrExpandedTooLong},
			want: "cannot expand url: expanded text is too long",
		},
		{
			// Expand never builds this error, but the text stays
			// readable.
			name: "too long with a valid name",
			err:  &ExpandError{Field: "url", Name: "X", Err: ErrExpandedTooLong},
			want: "cannot expand url: variable X: expanded text is too long",
		},
		{
			// Field is fixed text when Expand builds the error. A hand-made
			// Field with a control character is still quoted.
			name: "field is escaped",
			err:  &ExpandError{Field: "env\x1b[2J", Name: "X", Err: ErrMissingVariable},
			want: `cannot expand "env\x1b[2J": variable X: variable is not set`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
			// errors.Is(nil, nil) is true, so the nil Err case checks
			// that Unwrap gives nil.
			if !errors.Is(tt.err.Unwrap(), tt.err.Err) {
				t.Errorf("Unwrap() = %v, want %v", tt.err.Unwrap(), tt.err.Err)
			}
		})
	}
}

// TestExpandErrorInvalidNameFromConfig checks the error that Expand itself
// returns for a placeholder body that is not a plain variable name, such as
// an escape sequence in the config: Name is "", and the text holds no part
// of the body and no raw control character.
func TestExpandErrorInvalidNameFromConfig(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		client Client
		in     string
	}{
		{client: ClientClaudeCode, in: "${\x1b]0;title\x07X}"},
		{client: ClientCursor, in: "${env:\x1b]0;title\x07X}"},
	} {
		t.Run(string(tt.client), func(t *testing.T) {
			t.Parallel()
			_, err := expandCommand(tt.client, expandProjectPath, tt.in, nil)
			checkExpandError(t, err, "command", "", ErrMissingVariable)
			if err == nil {
				return
			}
			msg := err.Error()
			if want := "cannot expand command: variable with an invalid name: variable is not set"; msg != want {
				t.Errorf("Error() = %q, want %q", msg, want)
			}
			if strings.ContainsFunc(msg, unicode.IsControl) {
				t.Errorf("Error() holds a raw control character: %q", msg)
			}
			for _, part := range []string{"title", `\x1b`, "]0;"} {
				if strings.Contains(msg, part) {
					t.Errorf("Error() = %q, want no part of the body (%q)", msg, part)
				}
			}
		})
	}
}

// TestExpandErrorSecretWithPlaceholderForm is the case of review round 1: a
// secret env or header value can hold "${" by chance, as in
// p4ss${w0rd-9f8e7d}. The text inside ${...} is then part of the secret, and
// the error must not show it. "w0rd-9f8e7d" is not a plain variable name, so
// the error has no name.
func TestExpandErrorSecretWithPlaceholderForm(t *testing.T) {
	t.Parallel()
	const secretPart = "w0rd-9f8e7d" //nolint:gosec // G101: fake test credential
	tests := []struct {
		name   string
		client Client
		value  string
	}{
		{name: "claude-code", client: ClientClaudeCode, value: "p4ss${" + secretPart + "}"},
		{name: "claude-code with text after", client: ClientClaudeCode, value: "p4ss${" + secretPart + "}tail"},
		{name: "cursor env form", client: ClientCursor, value: "p4ss${env:" + secretPart + "}"},
	}
	fields := []struct {
		name string
		set  func(s *Server, v string)
	}{
		{name: "env", set: func(s *Server, v string) { s.Env = SecretMap{"API_KEY": NewSecret(v)} }},
		{name: "headers", set: func(s *Server, v string) { s.Headers = SecretMap{"Authorization": NewSecret("Bearer " + v)} }},
	}
	for _, tt := range tests {
		for _, f := range fields {
			t.Run(tt.name+"/"+f.name, func(t *testing.T) {
				t.Parallel()
				s := expandServer(tt.client, expandProjectPath)
				f.set(&s, tt.value)
				out, err := Expand(s, expandLookup(map[string]string{"w0rd": "x"}))
				checkExpandError(t, err, f.name, "", ErrMissingVariable)
				if err == nil {
					return
				}
				for what, text := range expandOutputs(t, err) {
					for _, part := range []string{secretPart, "9f8e7d", "p4ss"} {
						if strings.Contains(text, part) {
							t.Errorf("error %s = %q, want no %q", what, text, part)
						}
					}
				}
				if !reflect.DeepEqual(out, Server{}) {
					t.Error("Expand() on error returned a non-zero Server")
				}
			})
		}
	}
}

// TestExpandIsVariableName checks the rule for a plain variable name: 1 to
// maxNameLen bytes, ASCII letters, ASCII digits and "_", not a digit first.
// The cases at the edges of each ASCII range catch an off-by-one in a range
// check.
func TestExpandIsVariableName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{name: "upper", in: "TOKEN", want: true},
		{name: "lower", in: "token", want: true},
		{name: "mixed case", in: "workspaceFolderBasename", want: true},
		{name: "one letter", in: "A", want: true},
		{name: "underscore only", in: "_", want: true},
		{name: "underscore first", in: "_1", want: true},
		{name: "digits after first", in: "A0123456789", want: true},
		{name: "range edges", in: "AZaz_09", want: true},
		{name: "maxNameLen bytes", in: strings.Repeat("A", maxNameLen), want: true},
		{name: "cursor HOME", in: "HOME", want: true},

		{name: "empty", in: "", want: false},
		{name: "over maxNameLen bytes", in: strings.Repeat("A", maxNameLen+1), want: false},
		{name: "digit first", in: "1A", want: false},
		{name: "zero first", in: "0", want: false},
		{name: "nine first", in: "9A", want: false},
		{name: "dash", in: "A-B", want: false},
		{name: "colon", in: "env:A", want: false},
		{name: "default form", in: "A:-d", want: false},
		{name: "dot", in: "A.B", want: false},
		{name: "space inside", in: "A B", want: false},
		{name: "space first", in: " A", want: false},
		{name: "space last", in: "A ", want: false},
		{name: "dollar", in: "$A", want: false},
		{name: "brace", in: "${A", want: false},
		{name: "secret part", in: "w0rd-9f8e7d", want: false},
		{name: "byte before A", in: "@", want: false},
		{name: "byte after Z", in: "[", want: false},
		{name: "byte before a", in: "`", want: false},
		{name: "byte after z", in: "{", want: false},
		{name: "byte before 0", in: "A/", want: false},
		{name: "byte after 9", in: "A:", want: false},
		{name: "NUL", in: "A\x00", want: false},
		{name: "ESC", in: "A\x1b", want: false},
		{name: "DEL", in: "A\x7f", want: false},
		{name: "non-ASCII letter", in: "\u00c4", want: false},
		{name: "non-ASCII after a letter", in: "A\u00e9", want: false},
		{name: "bidi", in: "A\u202eB", want: false},
		{name: "invalid UTF-8", in: "A\xff", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isVariableName(tt.in); got != tt.want {
				t.Errorf("isVariableName(%q) = %v, want %v", tt.in, got, tt.want)
			}
			// variableName keeps exactly the names that isVariableName
			// accepts.
			want := ""
			if tt.want {
				want = tt.in
			}
			if got := variableName(tt.in); got != want {
				t.Errorf("variableName(%q) = %q, want %q", tt.in, got, want)
			}
		})
	}
}

// expandFill returns a text of exactly n bytes made of copies of the env
// canary, so a leak check can find any part of it.
func expandFill(n int) string {
	c := discovertest.CanaryEnv
	return strings.Repeat(c, n/len(c)+1)[:n]
}

// expandSizeEnv returns the variables of the size limit tests:
//   - BIG has 40 KiB: one fits in a text, two do not;
//   - MAX has maxExpandedLen bytes: exactly the limit of one text;
//   - ONE has 1 byte and EMPTY has 0 bytes.
func expandSizeEnv() map[string]string {
	return map[string]string{
		"BIG":   expandFill(40 << 10),
		"MAX":   expandFill(maxExpandedLen),
		"ONE":   "1",
		"EMPTY": "",
	}
}

// checkTooLong fails the test unless err is the ErrExpandedTooLong error of
// field, with no Name, and its text holds no part of a value.
func checkTooLong(t *testing.T, err error, field string) {
	t.Helper()
	checkExpandError(t, err, field, "", ErrExpandedTooLong)
	if err == nil {
		return
	}
	if want := "cannot expand " + field + ": expanded text is too long"; err.Error() != want {
		t.Errorf("Error() = %q, want %q", err.Error(), want)
	}
	for what, text := range expandOutputs(t, err) {
		discovertest.AssertNoLeak(t, "error "+what, text, discovertest.CanaryEnv)
	}
}

// TestExpandTooLongPerText checks the limit of maxExpandedLen bytes for one
// expanded text, at the exact edge, for both ways the limit is checked:
// before a value is written, and for the text after the last placeholder.
func TestExpandTooLongPerText(t *testing.T) {
	t.Parallel()
	below := strings.Repeat("L", maxExpandedLen-1)
	tests := []struct {
		name    string
		client  Client
		in      string
		wantLen int // the length of the result; 0 means ErrExpandedTooLong
	}{
		{name: "one 40 KiB value", client: ClientClaudeCode, in: "${BIG}", wantLen: 40 << 10},
		{name: "two 40 KiB values in one text", client: ClientClaudeCode, in: "${BIG}${BIG}"},
		{name: "two 40 KiB values with text between", client: ClientClaudeCode, in: "${BIG}-${BIG}"},
		{name: "value of exactly the limit", client: ClientClaudeCode, in: "${MAX}", wantLen: maxExpandedLen},
		{name: "one byte before a value of the limit", client: ClientClaudeCode, in: "x${MAX}"},
		{name: "one byte after a value of the limit", client: ClientClaudeCode, in: "${MAX}x"},
		{name: "literal and value end at the limit", client: ClientClaudeCode, in: below + "${ONE}", wantLen: maxExpandedLen},
		{name: "literal, value and one byte over the limit", client: ClientClaudeCode, in: below + "${ONE}y"},
		{name: "literal and empty value end at the limit", client: ClientClaudeCode, in: "z" + below + "${EMPTY}", wantLen: maxExpandedLen},
		// A replaced placeholder makes the whole text count, also when
		// the value is empty: the literal text is then over the limit.
		{name: "long literal with an empty value", client: ClientClaudeCode, in: below + "zz${EMPTY}"},
		{name: "default text counts", client: ClientClaudeCode, in: "${UNSET:-" + strings.Repeat("d", maxExpandedLen+1) + "}"},
		{name: "default text of the limit", client: ClientClaudeCode, in: "${UNSET:-" + strings.Repeat("d", maxExpandedLen) + "}", wantLen: maxExpandedLen},
		{name: "cursor one 40 KiB value", client: ClientCursor, in: "${env:BIG}", wantLen: 40 << 10},
		{name: "cursor two 40 KiB values", client: ClientCursor, in: "${env:BIG}${env:BIG}"},
		{name: "cursor separator after a value of the limit", client: ClientCursor, in: "${env:MAX}${/}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := expandCommand(tt.client, expandProjectPath, tt.in, expandSizeEnv())
			if tt.wantLen == 0 {
				checkTooLong(t, err, "command")
				return
			}
			if err != nil {
				t.Fatalf("Expand() error = %v, want nil", err)
			}
			if len(got) != tt.wantLen {
				t.Errorf("len(Command) = %d, want %d", len(got), tt.wantLen)
			}
		})
	}
}

// TestExpandTooLongEveryField checks that the limit of one text applies to
// every field, and that the error names the field.
func TestExpandTooLongEveryField(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		client Client
		text   string
	}{
		{client: ClientClaudeCode, text: "${BIG}${BIG}"},
		{client: ClientCursor, text: "${env:BIG}${env:BIG}"},
	} {
		for _, f := range expandFields() {
			t.Run(string(c.client)+"/"+f.name, func(t *testing.T) {
				t.Parallel()
				s := expandServer(c.client, expandProjectPath)
				f.set(&s, c.text)
				out, err := Expand(s, expandLookup(expandSizeEnv()))
				checkTooLong(t, err, f.name)
				if !reflect.DeepEqual(out, Server{}) {
					t.Error("Expand() on error returned a non-zero Server")
				}
			})
		}
	}
}

// expandRepeat returns n copies of text.
func expandRepeat(text string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = text
	}
	return out
}

// TestExpandTooLongPerServer checks the limit of maxExpandedTotal bytes for
// all expanded texts of one server together, at the exact edge and across
// fields.
func TestExpandTooLongPerServer(t *testing.T) {
	t.Parallel()
	// full is the number of MAX values that fill maxExpandedTotal exactly.
	const full = maxExpandedTotal / maxExpandedLen
	tests := []struct {
		name      string
		set       func(s *Server)
		wantField string // "" means no error
	}{
		{
			// 25 * 40 KiB = 1000 KiB, under 1 MiB.
			name: "25 args of 40 KiB",
			set:  func(s *Server) { s.Args = NewArgs(expandRepeat("${BIG}", 25)) },
		},
		{
			// 26 * 40 KiB = 1040 KiB, over 1 MiB.
			name:      "26 args of 40 KiB",
			set:       func(s *Server) { s.Args = NewArgs(expandRepeat("${BIG}", 26)) },
			wantField: "args",
		},
		{
			name: "exactly the total",
			set:  func(s *Server) { s.Args = NewArgs(expandRepeat("${MAX}", full)) },
		},
		{
			name:      "one byte over the total",
			set:       func(s *Server) { s.Args = NewArgs(append(expandRepeat("${MAX}", full), "${ONE}")) },
			wantField: "args",
		},
		{
			name: "empty value at the total",
			set:  func(s *Server) { s.Args = NewArgs(append(expandRepeat("${MAX}", full), "${EMPTY}")) },
		},
		{
			// Texts with no replaced placeholder do not count, at any
			// size. The literal texts come first, so a count of them
			// would leave no room for the placeholders after them.
			name: "literal texts do not count",
			set: func(s *Server) {
				lit := strings.Repeat("L", 100<<10)
				s.Command = lit + "${}"
				args := expandRepeat(lit, 6)
				args = append(args, expandRepeat(lit+"${", 6)...)
				s.Args = NewArgs(append(args, expandRepeat("${MAX}", full)...))
			},
		},
		{
			name: "over the total across fields, error in env",
			set: func(s *Server) {
				s.Command = "${MAX}"
				s.Args = NewArgs(expandRepeat("${MAX}", full-1))
				s.Env = SecretMap{"K": NewSecret("${ONE}")}
			},
			wantField: "env",
		},
		{
			name: "over the total across fields, error in url",
			set: func(s *Server) {
				s.Args = NewArgs(expandRepeat("${MAX}", full-1))
				s.Env = SecretMap{"K": NewSecret("${MAX}")}
				s.URL = NewURL("https://example.com/${ONE}")
			},
			wantField: "url",
		},
		{
			name: "over the total across fields, error in headers",
			set: func(s *Server) {
				s.Args = NewArgs(expandRepeat("${MAX}", full-2))
				s.Env = SecretMap{"K": NewSecret("${MAX}")}
				s.URL = NewURL("${MAX}")
				s.Headers = SecretMap{"H": NewSecret("${ONE}")}
			},
			wantField: "headers",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := expandServer(ClientClaudeCode, expandProjectPath)
			tt.set(&s)
			// Two calls: each Expand has its own count, so the second call
			// gives the same result as the first.
			for range 2 {
				_, err := Expand(s, expandLookup(expandSizeEnv()))
				if tt.wantField != "" {
					checkTooLong(t, err, tt.wantField)
					continue
				}
				if err != nil {
					t.Fatalf("Expand() error = %v, want nil", err)
				}
			}
		})
	}
}

// TestExpandTooLongLiteralOnly checks that a long text with no replaced
// placeholder stays as written: "${}", a "${" with no "}", a Cursor
// placeholder that Cursor does not know, and a Codex server.
func TestExpandTooLongLiteralOnly(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("L", 200<<10)
	tests := []struct {
		name   string
		client Client
		in     string
	}{
		{name: "no placeholder", client: ClientClaudeCode, in: long},
		{name: "empty body", client: ClientClaudeCode, in: long + "${}" + long},
		{name: "no close brace", client: ClientClaudeCode, in: long + "${BIG"},
		{name: "cursor unknown placeholder", client: ClientCursor, in: long + "${config:x}"},
		{name: "cursor claude form", client: ClientCursor, in: long + "${BIG}"},
		{name: "codex", client: ClientCodex, in: "${BIG}${BIG}${MAX}" + long},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := expandServer(tt.client, expandProjectPath)
			s.Command = tt.in
			s.Args = NewArgs(expandRepeat(tt.in, 8)) // 8 * 200 KiB and more: over the total
			out, err := Expand(s, expandLookup(expandSizeEnv()))
			if err != nil {
				t.Fatalf("Expand() error = %v, want nil", err)
			}
			if out.Command != tt.in {
				t.Errorf("Command changed: len %d, want len %d as written", len(out.Command), len(tt.in))
			}
			if !reflect.DeepEqual(out.Args.Values(), s.Args.Values()) {
				t.Error("Args changed, want them as written")
			}
		})
	}
}

// expandCanaryEnv maps variable names to the canary values, one per field.
func expandCanaryEnv() map[string]string {
	return map[string]string{
		"E": discovertest.CanaryEnv,
		"T": discovertest.CanaryArgs,
		"U": discovertest.CanaryURL,
		"H": discovertest.CanaryHeader,
	}
}

// expandOutputs returns the texts of v that a caller can print: fmt with
// several verbs and the JSON encoding.
func expandOutputs(t *testing.T, v any) map[string]string {
	t.Helper()
	out := make(map[string]string)
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		out[verb] = fmt.Sprintf(verb, v)
	}
	if _, isErr := v.(error); !isErr {
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		out["json"] = string(data)
	}
	return out
}

// TestExpandResultMasksSecrets checks that the expanded values are in the
// masked types: printing or encoding the result never shows them. The
// placeholders are in the Args, Env, URL and Headers, which mask their
// values. Command is plain text and prints as written (see Server.Command),
// so it holds no placeholder here.
func TestExpandResultMasksSecrets(t *testing.T) {
	t.Parallel()
	tests := []struct {
		client Client
		ph     func(name string) string
	}{
		{client: ClientClaudeCode, ph: func(n string) string { return "${" + n + "}" }},
		{client: ClientCursor, ph: func(n string) string { return "${env:" + n + "}" }},
	}
	for _, tt := range tests {
		t.Run(string(tt.client), func(t *testing.T) {
			t.Parallel()
			s := expandServer(tt.client, expandProjectPath)
			s.Command = "npx"
			s.Args = NewArgs([]string{"--token", tt.ph("T")})
			s.Env = SecretMap{"API_KEY": NewSecret(tt.ph("E"))}
			s.URL = NewURL("https://example.com/mcp?api_key=" + tt.ph("U"))
			s.Headers = SecretMap{"Authorization": NewSecret("Bearer " + tt.ph("H"))}

			out, err := Expand(s, expandLookup(expandCanaryEnv()))
			if err != nil {
				t.Fatalf("Expand() error = %v, want nil", err)
			}
			// Prove that the values were expanded, so the leak checks
			// below cannot pass on an unexpanded result.
			if got := out.Args.Values()[1]; got != discovertest.CanaryArgs {
				t.Fatalf("Args[1] = %q, want the args canary", got)
			}
			if got := out.Env["API_KEY"].Reveal(); got != discovertest.CanaryEnv {
				t.Fatalf("Env value is not the env canary")
			}
			if !strings.Contains(out.URL.Reveal(), discovertest.CanaryURL) {
				t.Fatalf("URL does not hold the url canary")
			}
			if got := out.Headers["Authorization"].Reveal(); got != "Bearer "+discovertest.CanaryHeader {
				t.Fatalf("header value does not hold the header canary")
			}

			for what, text := range expandOutputs(t, out) {
				discovertest.AssertNoLeak(t, "Server "+what, text)
			}
			for what, text := range expandOutputs(t, &out) {
				discovertest.AssertNoLeak(t, "*Server "+what, text)
			}
		})
	}
}

// TestExpandErrorHoldsNoValue checks that an error never holds a value: not
// the value of a set variable in the same text, not a default text, and not
// the text of the field.
func TestExpandErrorHoldsNoValue(t *testing.T) {
	t.Parallel()
	canary := discovertest.CanaryEnv
	tests := []struct {
		name   string
		client Client
		text   string
	}{
		{name: "set before missing", client: ClientClaudeCode, text: "${E}${MISSING}"},
		{name: "set after missing", client: ClientClaudeCode, text: "${MISSING}${E}"},
		{name: "default before missing", client: ClientClaudeCode, text: "${Z:-" + canary + "} ${MISSING}"},
		{name: "literal text before missing", client: ClientClaudeCode, text: canary + "${MISSING}"},
		{name: "cursor set before missing", client: ClientCursor, text: "${env:E}${env:MISSING}"},
		{name: "cursor literal text", client: ClientCursor, text: canary + "${env:MISSING}"},
		{name: "cursor workspace", client: ClientCursor, text: "${env:E}${workspaceFolder}"},
	}
	for _, tt := range tests {
		for _, f := range expandFields() {
			t.Run(tt.name+"/"+f.name, func(t *testing.T) {
				t.Parallel()
				// No ProjectPath, so ${workspaceFolder} fails.
				s := expandServer(tt.client, "")
				f.set(&s, tt.text)
				out, err := Expand(s, expandLookup(expandCanaryEnv()))
				if err == nil {
					t.Fatal("Expand() error = nil, want an error")
				}
				for what, text := range expandOutputs(t, err) {
					discovertest.AssertNoLeak(t, "error "+what, text, canary)
				}
				for what, text := range expandOutputs(t, out) {
					discovertest.AssertNoLeak(t, "Server on error "+what, text, canary)
				}
				if !reflect.DeepEqual(out, Server{}) {
					t.Error("Expand() on error returned a non-zero Server")
				}
			})
		}
	}
}

// expandFuzzServer builds the fuzz server: text in every expanded field.
func expandFuzzServer(c Client, text, projectPath string) Server {
	s := expandServer(c, projectPath)
	s.Command = text
	s.Args = NewArgs([]string{text, "--token", text})
	s.Env = SecretMap{"K": NewSecret(text), "Z": {}}
	s.URL = NewURL(text)
	s.Headers = SecretMap{"H": NewSecret(text)}
	return s
}

// FuzzExpand fuzzes Expand with the Claude Code, Cursor and Codex syntax.
//
//	go test -run '^$' -fuzz=FuzzExpand -fuzztime=30s ./internal/discover/
//
// Properties checked for any input:
//   - Expand does not panic and does not change its input;
//   - Codex gives the input unchanged;
//   - a text with no "${" stays as written;
//   - an expanded Command is at most maxExpandedLen bytes, or the input as
//     written;
//   - on error: the result is the zero Server, the error is an *ExpandError
//     with a fixed Field and a known Err (ErrMissingVariable,
//     ErrNoWorkspaceFolder or ErrExpandedTooLong), its Name is "" or a plain
//     variable name ("" for ErrExpandedTooLong), its text has no raw control
//     character, and it never holds the canary value of a set variable
//     (unless the input text itself holds the canary).
func FuzzExpand(f *testing.F) {
	canary := discovertest.CanaryEnv
	seeds := []string{
		"", "plain", "${A}", "${MISSING}", "${A:-d}", "${MISSING:-d}", "${X:-a:-b}",
		"${", "${}", "${}}", "$${A}", "${A ${B}", "${${A}}", "${A}${MISSING}",
		"${env:A}", "${env:MISSING}", "${env:}", "${userHome}", "${workspaceFolder}",
		"${workspaceFolderBasename}", "${pathSeparator}", "${/}", "${\x1b[31m}",
		"${env:\x1b]0;x\x07}", "\xff${A}\xfe", "${REF}", "p4ss${w0rd-9f8e7d}",
		// The A value is the canary, so 3000 copies are over the limit of
		// one text.
		strings.Repeat("${A}", 3000), strings.Repeat("${env:A}", 3000),
	}
	for i, s := range seeds {
		f.Add(uint8(i%3), s, "")
		f.Add(uint8(i%3), s, expandProjectPath)
	}
	clients := []Client{ClientClaudeCode, ClientCursor, ClientCodex}
	env := map[string]string{"A": canary, "HOME": canary, "EMPTY": "", "REF": "${A}"}
	fields := map[string]bool{"command": true, "args": true, "env": true, "url": true, "headers": true}

	f.Fuzz(func(t *testing.T, which uint8, text, projectPath string) {
		if len(text) > maxFuzzInput || len(projectPath) > maxFuzzInput {
			t.Skip("input too large")
		}
		c := clients[int(which)%len(clients)]
		in := expandFuzzServer(c, text, projectPath)
		out, err := Expand(in, expandLookup(env))

		if !reflect.DeepEqual(in, expandFuzzServer(c, text, projectPath)) {
			t.Fatal("Expand() changed its input")
		}
		if c == ClientCodex {
			if err != nil || !reflect.DeepEqual(out, in) {
				t.Fatalf("Codex: Expand() = (%+v, %v), want the input and nil", viewOf(out), err)
			}
			return
		}

		if err == nil {
			if !strings.Contains(text, "${") && out.Command != text {
				t.Errorf("Command = %q, want %q (no placeholder)", out.Command, text)
			}
			if out.Command != text && len(out.Command) > maxExpandedLen {
				t.Errorf("len(Command) = %d, want at most %d for an expanded text", len(out.Command), maxExpandedLen)
			}
			if out.Env["Z"].v != nil {
				t.Error("zero Secret is not zero after Expand")
			}
			return
		}

		if !reflect.DeepEqual(out, Server{}) {
			t.Error("Expand() on error returned a non-zero Server")
		}
		var xe *ExpandError
		if !errors.As(err, &xe) {
			t.Fatalf("error = %T, want *ExpandError", err)
		}
		if !fields[xe.Field] {
			t.Errorf("ExpandError.Field = %q, want a fixed field name", xe.Field)
		}
		tooLong := errors.Is(err, ErrExpandedTooLong)
		if !errors.Is(err, ErrMissingVariable) && !errors.Is(err, ErrNoWorkspaceFolder) && !tooLong {
			t.Errorf("error %v is not ErrMissingVariable, ErrNoWorkspaceFolder or ErrExpandedTooLong", err)
		}
		if xe.Name != "" && (tooLong || !isVariableName(xe.Name)) {
			t.Errorf("ExpandError.Name = %q, want \"\" or a plain variable name (\"\" when too long)", xe.Name)
		}
		msg := err.Error()
		if strings.ContainsFunc(msg, unicode.IsControl) {
			t.Errorf("Error() holds a raw control character: %q", msg)
		}
		// The name in the error comes from the text, so a text that holds
		// the canary can show it by design.
		if len(discovertest.Leaks(text+"\x00"+projectPath, canary)) == 0 {
			if leaks := discovertest.Leaks(msg, canary); len(leaks) > 0 {
				t.Errorf("Error() leaks the canary: %q", msg)
			}
		}
	})
}
