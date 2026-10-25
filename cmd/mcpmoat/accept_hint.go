package main

import (
	"io"
	"strings"
)

// This file holds the "To accept" line that scan prints for each changed
// server, with the digest for "pin --accept --expect".

// acceptHint is the digest of the tools that scan saw on one changed server.
type acceptHint struct {
	name   string // the server name from the config file: untrusted
	digest string // pins.Digest of the tools; our own hex, safe to print
	// truncated is true when at least one diff of the server, in the report, was
	// cut at the size limit: the user did not see the full tool.
	truncated bool
	// ignored is true when --ignore dropped at least one pin finding of the
	// server. The digest still covers that change, but the report shows no diff
	// for it.
	ignored bool
	// shared is true when another server that scan inspected has the same
	// name. pin refuses such a name without a --config that narrows it.
	shared bool
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
// file, so the command holds "--config <configPath>" too. configProblem is true
// when a config file of the scan has a problem: pin then refuses to run.
//
// The line holds a command only when pin can run it as printed and the user saw
// every change (see acceptCommand). Else it says what to run and gives the
// digest, so the user must type the command: when the user did not see every
// change (a cut diff, a change that --ignore hid, or a diff that is a fixed
// note), when another server has the same name, when a config file has a
// problem, or when the name or configPath is not a bare shell word. Before the
// colon the name is escaped and cut for the terminal. The digest is made by
// mcpmoat from hex, so it needs no escape. The line ends with hintCutNote,
// hintIgnoredNote or hintNoTextNote for each change that the user did not see.
// writeAcceptHints returns the first write error: the caller must check it,
// like for the report.
func writeAcceptHints(w io.Writer, hints []acceptHint, configPath string, configProblem bool) error {
	for _, h := range hints {
		text, ok := acceptCommand(h.name, configPath, h.digest)
		if !ok || h.truncated || h.ignored || h.noText || h.shared || configProblem {
			text = acceptSteps(configPath, h.shared, configProblem, h.digest)
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
// true. It returns false when name or configPath (when not empty) is not a bare
// shell word (see isBareShellWord): quotes are not safe, because each shell
// (POSIX, PowerShell, cmd.exe) escapes them in its own way.
func acceptCommand(name, configPath, digest string) (string, bool) {
	if !isBareShellWord(name, maxWarnNameRunes) {
		return "", false
	}
	cmd := "mcpmoat pin --accept " + name
	if configPath != "" {
		if !isBareShellWord(configPath, maxWarnPathRunes) {
			return "", false
		}
		cmd += " --config " + configPath
	}
	return cmd + " --expect " + digest, true
}

// acceptSteps returns the text of a "To accept" line that has no command: what
// to run, and the digest. shared is true when another server has the same
// name, so pin needs a --config that names the config file of the server.
// configProblem is true when a config file has a problem: pin refuses to run
// until it is fixed, also with --config.
func acceptSteps(configPath string, shared, configProblem bool, digest string) string {
	config := ""
	switch {
	case configPath != "":
		config = ", --config with the file of this scan,"
	case shared || configProblem:
		config = ", --config with its config file,"
	}
	steps := "run pin --accept with this server name" + config + " and --expect " + digest
	if configProblem {
		return "fix the config file first, then " + steps
	}
	return steps
}

// isBareShellWord reports whether s is not empty, has at most maxBytes bytes,
// and holds only the ASCII characters [A-Za-z0-9._@/:+=-], so a byte is a rune.
// POSIX shells, PowerShell and cmd.exe read such a word as plain text when its
// first character is a letter, "_" or "/". Other first characters can be
// special: pin reads "-config" as a flag, zsh expands "=ls", PowerShell reads
// "@x" as a variable and "1kb" as a number.
func isBareShellWord(s string, maxBytes int) bool {
	if s == "" || len(s) > maxBytes {
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
