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
// file has a problem, or when the name, the project or configPath is not a bare
// shell word. Before the
// colon the name is escaped and cut for the terminal. The digest is made by
// mcpmoat from hex, so it needs no escape. The line ends with hintCutNote,
// hintIgnoredNote or hintNoTextNote for each change that the user did not see.
// writeAcceptHints returns the first write error: the caller must check it,
// like for the report.
func writeAcceptHints(w io.Writer, hints []acceptHint, configPath string, configProblem bool) error {
	for _, h := range hints {
		text, ok := acceptCommand(h.name, h.project, configPath, h.digest)
		if !ok || h.truncated || h.ignored || h.noText || h.ambiguous || configProblem {
			text = acceptSteps(configPath, h.project, h.ambiguous || configProblem, configProblem, h.digest)
		}
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
		if _, err := io.WriteString(w, line+"\n"); err != nil {
			return err
		}
	}
	return nil
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

// acceptSteps returns the text of a "To accept" line that has no command: what
// to run, and the digest. project is the --project value that pin needs, or
// empty. needConfig is true when pin needs a --config that names the config
// file of the server. configProblem is true when a config file has a problem:
// pin refuses to run until it is fixed, also with --config.
func acceptSteps(configPath, project string, needConfig, configProblem bool, digest string) string {
	parts := []string{"this server name"}
	switch {
	case configPath != "":
		parts = append(parts, "--config with the file of this scan")
	case needConfig:
		parts = append(parts, "--config with its config file")
	}
	if project != "" {
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
// without --project, then with the project path of the server.
func setSelectors(hints []acceptHint, servers []discover.Server) {
	selects := func(h acceptHint, project string) bool {
		m := selectServers(servers, h.name, project)
		return len(m) == 1 && serverIdentity(m[0]) == h.id
	}
	for i, h := range hints {
		switch {
		case selects(h, ""):
		case h.id.ProjectPath != "" && selects(h, h.id.ProjectPath):
			hints[i].project = h.id.ProjectPath
		default:
			hints[i].ambiguous = true
		}
	}
}
