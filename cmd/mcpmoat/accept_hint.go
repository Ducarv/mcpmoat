package main

import (
	"io"
	"strings"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/pins"
)

// This file holds the "To accept" line that scan prints for each changed
// server, with the digest for "pin --accept --expect".

// acceptHint is the digest of the tools that scan saw on one changed server.
type acceptHint struct {
	name   string        // the server name from the config file: untrusted
	id     pins.Identity // the identity of the server, to check what pin selects
	digest string        // pins.Digest of the tools; our own hex, safe to print
	// truncated is true when at least one diff of the server, in the report, was
	// cut at the size limit: the user did not see the full tool.
	truncated bool
	// ignored is true when --ignore dropped at least one pin finding of the
	// server. The digest still covers that change, but the report shows no diff
	// for it.
	ignored bool
	// project is the --project value that pin needs to select this server,
	// or empty when the name alone selects it (see selectServers).
	project string
	// ambiguous is true when the name, with or without --project, selects
	// another server or more than one among the servers of this scan. pin then
	// needs a --config that names the config file of the server.
	ambiguous bool
	// noText is true when a kept change of the server has a fixed note as its
	// diff (pins.Change.DiffIsNote): the user saw no text of that change.
	noText bool
	// full says whether pins.json has no room for the new tools of the server,
	// so "pin --accept" would fail: the hint then prints no command. It is
	// fileFull when the whole file is full, and shareFull when only the share of
	// the project servers is full. The note of the hint differs (see
	// fullKind.hintNote). notFull is the zero value.
	full fullKind
	// snap holds the new pins of the server, the pins that "pin --accept"
	// would save. markStoreFull checks with them that they fit in pins.json.
	// The hint never prints them.
	snap pins.ServerPins
}

// The notes at the end of a "To accept" line. They are fixed text.
const (
	// hintCutNote ends the line of a server that has a cut diff.
	hintCutNote = " (the diff was cut: review the full tool first)"
	// hintIgnoredNote ends the line of a server with a pin finding that
	// --ignore dropped.
	hintIgnoredNote = " (--ignore hid some changes: run scan without it to review them first)"
	// hintNoTextNote ends the line of a server with a change whose diff is a
	// fixed note.
	hintNoTextNote = " (a change has no diff text: review the tool first)"
)

// writeAcceptHints writes one line on w for each hint:
//
//	To accept <server>: mcpmoat pin --accept <server> --expect <digest>
//
// The user reviews the diff of scan, then runs the line. "pin --accept" saves
// the tools only when they have the same digest, so a server cannot show good
// tools to scan and bad tools to pin (a time-of-check to time-of-use attack).
// configPath is the --config of the scan, or empty. pin must read the same
// file, so the command holds "--config <configPath>" too, and "--project
// <path>" when pin needs it to select the server. configProblem is true when a
// config file of the scan has a problem: pin then refuses to run.
//
// The line holds a command only when pin can run it as printed and the user saw
// every change (see acceptCommand). Else it says what to run and gives the
// digest, so the user must type the command: when the user did not see every
// change (a cut diff, a change that --ignore hid, or a diff that is a fixed
// note), when the name and --project do not select the server, when a config
// file has a problem, when pins.json has no room for the tools, or when the
// name, the project or configPath is not a bare shell word. Before the colon
// the name is escaped and cut for the terminal. The digest is made by mcpmoat
// from hex, so it needs no escape. The line ends with hintCutNote,
// hintIgnoredNote or hintNoTextNote for each change that the user did not see,
// and then with fileFull.hintNote when pins.json has no room for the tools, or
// shareFull.hintNote when only the share of the project servers has no room.
// writeAcceptHints returns the first write error: the caller must check it,
// like for the report.
func writeAcceptHints(w io.Writer, hints []acceptHint, configPath string, configProblem bool) error {
	for _, h := range hints {
		text, _ := acceptAdvice(h, configPath, configProblem)
		line := "To accept " + cutName(h.name) + ": " + text
		if h.truncated {
			line += hintCutNote
		}
		if h.ignored {
			line += hintIgnoredNote
		}
		if h.noText {
			line += hintNoTextNote
		}
		line += h.full.hintNote()
		if _, err := io.WriteString(w, line+"\n"); err != nil {
			return err
		}
	}
	return nil
}

// acceptAdvice decides what the "To accept" hint of h says, in one place. text
// is exactly the text that the terminal prints after "To accept <name>: ", before
// the notes for a cut, ignored or no-text change and the note for a full
// pins.json (fileFull) or a full project share (shareFull). isCommand is true only when
// text is the shell command from acceptCommand, and false when text is the prose
// steps from acceptSteps. The text is a command only when the name, the project
// and configPath are bare shell words, the user saw every change, the name
// selects the server, no config file has a problem, and pins.json has room for
// the tools. A command that pin refuses would mislead the user, so a full
// pins.json gives the prose steps; they still hold the digest. The JSON output
// reuses this function, so the terminal and the JSON cannot disagree. It does
// no I/O.
func acceptAdvice(h acceptHint, configPath string, configProblem bool) (text string, isCommand bool) {
	text, ok := acceptCommand(h.name, h.project, configPath, h.digest)
	if !ok || !h.fullyReviewed() || h.ambiguous || configProblem || h.full != notFull {
		return acceptSteps(h, configPath, configProblem), false
	}
	return text, true
}

// acceptCommand returns the command that accepts the tools with the digest, and
// true. It returns false when name, project or configPath (when not empty) is
// not a bare shell word (see isBareShellWord): quotes are not safe, because
// each shell (POSIX, PowerShell, cmd.exe) escapes them in its own way.
func acceptCommand(name, project, configPath, digest string) (string, bool) {
	if !isBareShellWord(name, maxWarnNameRunes) {
		return "", false
	}
	cmd := "mcpmoat pin --accept " + name
	for _, f := range []struct{ flag, value string }{{"--project", project}, {"--config", configPath}} {
		if f.value == "" {
			continue
		}
		if !isBareShellWord(f.value, maxWarnPathRunes) {
			return "", false
		}
		cmd += " " + f.flag + " " + f.value
	}
	return cmd + " --expect " + digest, true
}

// fullyReviewed reports whether the report showed the user every change that
// the digest covers: no diff was cut, --ignore hid no change, and no diff is
// only a fixed note.
func (h acceptHint) fullyReviewed() bool {
	return !h.truncated && !h.ignored && !h.noText
}

// acceptSteps returns the text of a "To accept" line for h that has no
// command: what to run, and the digest. configPath is the --config of the
// scan, or empty. pin needs a --config that names the config file of the
// server when the name is ambiguous or a config file has a problem
// (configProblem); with a problem, pin refuses to run until the file is fixed,
// also with --config.
func acceptSteps(h acceptHint, configPath string, configProblem bool) string {
	digest := h.digest
	parts := []string{"this server name"}
	switch {
	case configPath != "":
		parts = append(parts, "--config with the file of this scan")
	case h.ambiguous || configProblem:
		parts = append(parts, "--config with its config file")
	}
	if h.project != "" {
		parts = append(parts, "--project with its project path")
	}
	sep := " and "
	if len(parts) > 1 {
		sep = ", and "
	}
	steps := "run pin --accept with " + strings.Join(parts, ", ") + sep + "--expect " + digest
	if configProblem {
		return "fix the config file first, then " + steps
	}
	return steps
}

// isBareShellWord reports whether s is not empty, has at most maxLen bytes, and
// holds only the ASCII characters [A-Za-z0-9._@/:+=-]. For these characters a
// byte is a rune, so maxLen can be a rune cap.
// POSIX shells, PowerShell and cmd.exe read such a word as plain text when its
// first character is a letter, "_" or "/". Other first characters can be
// special: pin reads "-config" as a flag, zsh expands "=ls", PowerShell reads
// "@x" as a variable and "1kb" as a number.
func isBareShellWord(s string, maxLen int) bool {
	if s == "" || len(s) > maxLen {
		return false
	}
	switch c := s[0]; {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_', c == '/':
	default:
		return false
	}
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("._@/:+=-", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// setSelectors sets project and ambiguous on each hint: it checks which server
// "pin --accept <name>" would select among servers (see selectServers), first
// without --project, then with the project path of the server. When neither
// selects it, the hint is ambiguous: pin needs --config with the config file of
// the server. project is then the --project that pin still needs among the
// servers of that one file.
func setSelectors(hints []acceptHint, servers []discover.Server) {
	selects := func(among []discover.Server, h acceptHint, project string) bool {
		m := selectServers(among, h.name, project)
		return len(m) == 1 && serverIdentity(m[0]) == h.id
	}
	project := func(among []discover.Server, h acceptHint) (string, bool) {
		switch {
		case selects(among, h, ""):
			return "", true
		case h.id.ProjectPath != "" && selects(among, h, h.id.ProjectPath):
			return h.id.ProjectPath, true
		}
		return "", false
	}
	for i := range hints {
		h := &hints[i]
		if p, ok := project(servers, *h); ok {
			h.project = p
			continue
		}
		h.ambiguous = true
		var sameFile []discover.Server
		for _, s := range servers {
			if s.Source == h.id.Source {
				sameFile = append(sameFile, s)
			}
		}
		h.project, _ = project(sameFile, *h)
	}
}
