package discover

import (
	"errors"
	"maps"
	"path/filepath"
	"strings"
)

// ErrMissingVariable is the error when a placeholder names a variable that
// is not set and the placeholder gives no default. It is the Err of an
// [ExpandError].
var ErrMissingVariable = errors.New("variable is not set")

// ErrNoWorkspaceFolder is the error when a Cursor placeholder needs the
// workspace folder (${workspaceFolder} or ${workspaceFolderBasename}) and the
// server has no ProjectPath, for example a server from the global Cursor
// config. It is the Err of an [ExpandError].
var ErrNoWorkspaceFolder = errors.New("server has no workspace folder")

// ErrExpandedTooLong is the error when an expanded text is over a size
// limit: one text over maxExpandedLen, or all expanded texts of one server
// together over maxExpandedTotal. It is the Err of an [ExpandError] with no
// Name.
var ErrExpandedTooLong = errors.New("expanded text is too long")

// The size limits of the expansion. A placeholder can read a long variable,
// and a config can hold the same placeholder many times, so without a limit
// a small config could make a very large text. Only a text in which Expand
// replaces at least one placeholder counts. A text with no replaced
// placeholder stays as written, at any size.
const (
	// maxExpandedLen is the largest expanded text: 64 KiB.
	maxExpandedLen = 64 << 10

	// maxExpandedTotal is the largest sum of the expanded texts of one
	// server: 1 MiB. It is the same size as the limit of macOS for the args
	// and the environment of a new process together, so a server that
	// passes it could not start anyway.
	maxExpandedTotal = 1 << 20

	// maxNameLen is the longest variable name that an ExpandError shows.
	maxNameLen = 64
)

// The fixed values of ExpandError.Field: the Server field that holds the
// placeholder.
const (
	fieldCommand = "command"
	fieldArgs    = "args"
	fieldEnv     = "env"
	fieldURL     = "url"
	fieldHeaders = "headers"
)

// ExpandError tells which placeholder [Expand] could not expand. It holds the
// field and, when it is a plain variable name, the variable name. It never
// holds a variable value or a default text.
//
// The placeholder is part of the text of the field, and the env values, the
// header values and the URL can be secrets. A secret can hold "${" by
// chance, for example the value p4ss${w0rd-9f8e7d}. So the text inside
// ${...} can be part of a secret. Expand keeps the name only when it looks
// like a variable name (see isVariableName). A secret part that looks like
// a variable name, such as "w0rd" in p4ss${w0rd}, can still show.
type ExpandError struct {
	// Field is the Server field that holds the placeholder. It is fixed
	// text: "command", "args", "env", "url" or "headers".
	Field string

	// Name is the variable name in the placeholder, as written in the
	// config, without the default text. For a Cursor placeholder that is not
	// ${env:NAME}, it is the placeholder name: "userHome" gives "HOME" (the
	// variable it reads), and the workspace placeholders give
	// "workspaceFolder" or "workspaceFolderBasename".
	//
	// Name is empty when the name is not a plain variable name (ASCII
	// letters, digits and "_", not first a digit, at most 64 bytes), and for
	// ErrExpandedTooLong. Name is untrusted text from the config file.
	Name string

	// Err is ErrMissingVariable, ErrNoWorkspaceFolder or
	// ErrExpandedTooLong.
	Err error
}

var _ error = (*ExpandError)(nil)

// Error returns the message in the form
// "cannot expand <field>: variable <name>: <Err>". When Name is not a plain
// variable name, the middle part is "variable with an invalid name", and
// for ErrExpandedTooLong there is no middle part:
// "cannot expand <field>: expanded text is too long".
func (e *ExpandError) Error() string {
	msg := "cannot expand " + displayText(e.Field)
	switch {
	case isVariableName(e.Name):
		msg += ": variable " + e.Name
	case !errors.Is(e.Err, ErrExpandedTooLong):
		msg += ": variable with an invalid name"
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

// Unwrap returns Err, so errors.Is(err, ErrMissingVariable),
// errors.Is(err, ErrNoWorkspaceFolder) and errors.Is(err, ErrExpandedTooLong)
// work.
func (e *ExpandError) Unwrap() error {
	return e.Err
}

// Expand returns a copy of s with the variable placeholders in Command, Args,
// the Env values, URL and the Header values replaced, with the syntax of the
// client that declared s. It never changes s. Env and header names (the map
// keys) and the other fields (Name, Source, ProjectPath, Dir and so on) stay
// as written.
//
// lookup gives the value of a variable and whether it is set. The caller
// passes the environment of the client process, which is the user's own
// environment, the same one that the client uses. A nil lookup acts as an
// empty environment.
//
// The syntax per client:
//
//   - Claude Code: ${VAR} and ${VAR:-default}. The text splits at the first
//     ":-". A set variable gives its value, also when the value is empty.
//     An unset variable gives the default, or ErrMissingVariable when there
//     is no default. A placeholder is "${", one or more characters other
//     than "}", then "}" (the regular expression \$\{([^}]+)\}), so "${}"
//     and a "${" with no "}" after it stay as written.
//   - Cursor: ${env:NAME}, ${userHome} (the HOME variable),
//     ${workspaceFolder} (ProjectPath), ${workspaceFolderBasename} (the last
//     element of ProjectPath), and ${pathSeparator} and ${/} (the path
//     separator of this system). An unset variable gives
//     ErrMissingVariable, and a workspace placeholder on a server with no
//     ProjectPath gives ErrNoWorkspaceFolder. Cursor probably uses an empty
//     value for an unset variable; Expand fails closed instead, so that
//     inspect never runs a server with a value the user did not set. Other
//     ${...} forms stay as written.
//   - Codex and any other client: no expansion. The result is a copy of s.
//
// Expand makes one pass over each text. A value or a default text that holds
// "${" is not expanded again.
//
// An expanded text can be at most maxExpandedLen (64 KiB) long, and the
// expanded texts of the server together at most maxExpandedTotal (1 MiB).
// Only a text in which Expand replaces a placeholder counts. Over a limit,
// Expand fails with ErrExpandedTooLong.
//
// The result does not share the Env and Headers maps with s. A zero URL, a
// zero Args, a zero Secret and a nil map stay zero (or nil) in the result,
// and the expanded values are in new Args, URL and Secret values, which mask
// them in all output as before.
//
// On a failure Expand returns the zero Server and an *[ExpandError]. The
// error holds the field and at most a plain variable name, never a value.
// Expand
// checks the fields in a fixed order (Command, Args, Env in sorted key
// order, URL, then Headers in sorted key order), so the same server always
// gives the same error.
func Expand(s Server, lookup func(string) (string, bool)) (Server, error) {
	if lookup == nil {
		lookup = func(string) (string, bool) { return "", false }
	}

	var x *expander
	switch s.Client {
	case ClientClaudeCode:
		x = &expander{resolve: claudeCodeResolver(lookup)}
	case ClientCursor:
		x = &expander{resolve: cursorResolver(lookup, s.ProjectPath)}
	default:
		out := s
		out.Env = maps.Clone(s.Env)
		out.Headers = maps.Clone(s.Headers)
		return out, nil
	}
	return x.server(s)
}

// resolver returns the text for the body of one placeholder (the text
// between "${" and "}"). ok is false when the body is not a placeholder of
// the client, so the placeholder stays as written. A non-nil error has no
// Field yet; expander.text sets it.
type resolver func(body string) (value string, ok bool, err *ExpandError)

// expander expands the placeholders of one client in all fields of one
// Server. It counts the expanded bytes for maxExpandedTotal, so use a new
// expander for each Server.
type expander struct {
	resolve resolver
	// total is the sum of the lengths of the expanded texts so far.
	total int
}

// server returns the expanded copy of s. See Expand.
func (x *expander) server(s Server) (Server, error) {
	out := s

	var err error
	if out.Command, err = x.text(fieldCommand, s.Command); err != nil {
		return Server{}, err
	}
	if out.Args, err = x.args(s.Args); err != nil {
		return Server{}, err
	}
	if out.Env, err = x.secrets(fieldEnv, s.Env); err != nil {
		return Server{}, err
	}
	if out.URL, err = x.url(s.URL); err != nil {
		return Server{}, err
	}
	if out.Headers, err = x.secrets(fieldHeaders, s.Headers); err != nil {
		return Server{}, err
	}
	return out, nil
}

// args returns a with every arg expanded. The zero Args stays zero.
func (x *expander) args(a Args) (Args, error) {
	if a.v == nil {
		return Args{}, nil
	}
	values := a.Values()
	for i, v := range values {
		e, err := x.text(fieldArgs, v)
		if err != nil {
			return Args{}, err
		}
		values[i] = e
	}
	return NewArgs(values), nil
}

// url returns u expanded. The zero URL stays zero.
func (x *expander) url(u URL) (URL, error) {
	if u.v == nil {
		return URL{}, nil
	}
	e, err := x.text(fieldURL, u.Reveal())
	if err != nil {
		return URL{}, err
	}
	return NewURL(e), nil
}

// secrets returns a new map with every value of m expanded and the keys as
// written. A nil map stays nil, and a zero Secret stays zero. The keys are
// read in sorted order, so the first error is the same on every call.
func (x *expander) secrets(field string, m SecretMap) (SecretMap, error) {
	if m == nil {
		return nil, nil
	}
	out := make(SecretMap, len(m))
	for _, k := range m.Keys() {
		sec := m[k]
		if sec.v == nil {
			out[k] = sec
			continue
		}
		e, err := x.text(field, sec.Reveal())
		if err != nil {
			return nil, err
		}
		out[k] = NewSecret(e)
	}
	return out, nil
}

// text returns s with its placeholders replaced. On a failure it returns an
// *ExpandError with Field set to field. It adds the length of an expanded
// text to x.total, and the limit for the text is the smaller of
// maxExpandedLen and what is left of maxExpandedTotal.
func (x *expander) text(field, s string) (string, error) {
	limit := min(maxExpandedLen, maxExpandedTotal-x.total)
	out, replaced, e := replacePlaceholders(s, x.resolve, limit)
	if e != nil {
		e.Field = field
		return "", e
	}
	if replaced {
		x.total += len(out)
	}
	return out, nil
}

// replacePlaceholders returns s with each placeholder replaced by the text
// that resolve gives, and whether it replaced at least one placeholder. It
// finds the same placeholders as the regular expression \$\{([^}]+)\}:
// "${", one or more characters other than "}", then "}". A body that
// resolve does not know stays as written. The result of resolve is not
// scanned again.
//
// When it replaced a placeholder, the result must not be longer than limit
// bytes, else the error is ErrExpandedTooLong. It checks the length before
// it writes each value, so it never builds a text much longer than limit.
func replacePlaceholders(s string, resolve resolver, limit int) (string, bool, *ExpandError) {
	if !strings.Contains(s, "${") {
		return s, false, nil
	}

	var b strings.Builder
	replaced := false
	rest := s
	for {
		start := strings.Index(rest, "${")
		if start < 0 {
			break
		}
		bodyStart := start + len("${")
		n := strings.IndexByte(rest[bodyStart:], '}')
		if n < 0 {
			// No "}" after this "${", so no placeholder can follow.
			break
		}
		if n == 0 {
			// "${}" has an empty body and is not a placeholder. Keep the
			// "$" and look again from the "{", as the regular expression
			// does.
			b.WriteString(rest[:start+1])
			rest = rest[start+1:]
			continue
		}
		body := rest[bodyStart : bodyStart+n]
		end := bodyStart + n + len("}")

		b.WriteString(rest[:start])
		value, ok, err := resolve(body)
		if err != nil {
			err.Name = variableName(err.Name)
			return "", false, err
		}
		if ok {
			if b.Len()+len(value) > limit {
				return "", false, &ExpandError{Err: ErrExpandedTooLong}
			}
			b.WriteString(value)
			replaced = true
		} else {
			b.WriteString(rest[start:end])
		}
		rest = rest[end:]
	}
	if !replaced {
		return s, false, nil
	}
	if b.Len()+len(rest) > limit {
		return "", false, &ExpandError{Err: ErrExpandedTooLong}
	}
	b.WriteString(rest)
	return b.String(), true, nil
}

// variableName returns name when it is a plain variable name (see
// isVariableName), and "" otherwise. The text inside ${...} can be part of
// a secret value, so an ExpandError keeps only a name that looks like a
// variable name.
func variableName(name string) string {
	if isVariableName(name) {
		return name
	}
	return ""
}

// isVariableName reports whether name is a plain variable name: 1 to
// maxNameLen bytes, only ASCII letters, ASCII digits and "_", and not a
// digit first. All Cursor placeholder names ("HOME", "workspaceFolder",
// "workspaceFolderBasename") pass.
func isVariableName(name string) bool {
	if name == "" || len(name) > maxNameLen {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c == '_', 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z':
		case '0' <= c && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// claudeCodeResolver returns the resolver for the Claude Code syntax:
// ${VAR} and ${VAR:-default}. See Expand.
func claudeCodeResolver(lookup func(string) (string, bool)) resolver {
	return func(body string) (string, bool, *ExpandError) {
		name, def, hasDefault := strings.Cut(body, ":-")
		if value, ok := lookup(name); ok {
			return value, true, nil
		}
		if hasDefault {
			return def, true, nil
		}
		return "", false, &ExpandError{Name: name, Err: ErrMissingVariable}
	}
}

// Cursor placeholder names. See Expand.
const (
	cursorEnvPrefix         = "env:"
	cursorUserHome          = "userHome"
	cursorWorkspace         = "workspaceFolder"
	cursorWorkspaceBasename = "workspaceFolderBasename"
	cursorPathSeparator     = "pathSeparator"
	cursorSlash             = "/"
)

// cursorResolver returns the resolver for the Cursor syntax. projectPath is
// the ProjectPath of the server, the value of ${workspaceFolder}. See
// Expand.
func cursorResolver(lookup func(string) (string, bool), projectPath string) resolver {
	return func(body string) (string, bool, *ExpandError) {
		if name, ok := strings.CutPrefix(body, cursorEnvPrefix); ok {
			return lookupRequired(lookup, name)
		}
		switch body {
		case cursorUserHome:
			return lookupRequired(lookup, "HOME")
		case cursorWorkspace:
			if projectPath == "" {
				return "", false, &ExpandError{Name: body, Err: ErrNoWorkspaceFolder}
			}
			return projectPath, true, nil
		case cursorWorkspaceBasename:
			if projectPath == "" {
				return "", false, &ExpandError{Name: body, Err: ErrNoWorkspaceFolder}
			}
			return filepath.Base(projectPath), true, nil
		case cursorPathSeparator, cursorSlash:
			return string(filepath.Separator), true, nil
		}
		return "", false, nil
	}
}

// lookupRequired returns the value of the variable name, or
// ErrMissingVariable when it is not set. A set but empty variable gives "".
func lookupRequired(lookup func(string) (string, bool), name string) (string, bool, *ExpandError) {
	value, ok := lookup(name)
	if !ok {
		return "", false, &ExpandError{Name: name, Err: ErrMissingVariable}
	}
	return value, true, nil
}
