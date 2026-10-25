package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// The status words of ServerStatus.Status.
const (
	// StatusOK is a server that mcpmoat inspected.
	StatusOK = "ok"
	// StatusTimeout is a server that did not answer in time.
	StatusTimeout = "timeout"
	// StatusFailed is a server that mcpmoat could not inspect because of an
	// error.
	StatusFailed = "failed"
	// StatusNotInspected is a server that mcpmoat did not start or connect
	// to, for example a server that the client config turns off.
	StatusNotInspected = "not inspected"
)

// maxReasonRunes caps the failure reason of a server, in runes of raw text.
// The reason can hold server or system error text.
const maxReasonRunes = 500

// maxSummaryNameRunes caps a header key in a warning line, in runes of raw
// text. A header key comes from a config file and has no length limit.
const maxSummaryNameRunes = 100

// maxSummaryHeaderKeys caps how many header keys one cleartext-secrets warning
// lists. A config file can hold any number of headers, and one warning line
// must stay short. The rest shows as a count.
const maxSummaryHeaderKeys = 10

// ServerStatus is the outcome of one server, as WriteSummary prints it.
type ServerStatus struct {
	// ServerRef names the server and says where it comes from.
	ServerRef

	// Status is one of StatusOK, StatusTimeout, StatusFailed and
	// StatusNotInspected. Any other text is escaped and printed as it is.
	Status string

	// Reason is the text that says why the server failed. It can hold server
	// or system error text, so WriteSummary escapes and cuts it. It shows only
	// when it is not empty and Status is not StatusOK.
	Reason string

	// Tools is the number of tools that the server listed. It shows only when
	// Status is StatusOK.
	Tools int

	// Findings is the number of findings about the server.
	Findings int

	// Warnings are the inspection warnings of the server. A Warning holds
	// keys and flags, never values (see inspect.Warning).
	Warnings []inspect.Warning
}

// WriteSummary writes the summary of the servers to w. When servers is empty
// it writes nothing and returns nil. Otherwise it writes one blank line, the
// heading "SUMMARY" and one line for each server, in the given order:
//
//	github (claude-code, global): ok, 3 tools, 2 findings
//	  warning: cleartext-secrets: secrets go over plain http ...
//	github (cursor, project:/x (untrusted)): failed (<reason>), 0 findings
//	other (codex, global): not inspected, 1 finding
//
// Each warning has its own line under the server. The warning text is
// WarningText, the text that "mcpmoat pin" prints on stderr. It shows header keys, never header
// values.
//
// Every text from a config file or a server goes through internal/termsafe,
// and names and paths are cut (see ServerRef). The Style only colours the
// status word and the heading, after the escape.
//
// WriteSummary builds the whole text first and writes it with one call, so it
// returns the first write error. Callers must check it: a failed write has to
// become exit code 2 in cmd/mcpmoat.
func WriteSummary(w io.Writer, servers []ServerStatus, st Style) error {
	if len(servers) == 0 {
		return nil
	}

	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(st.heading("SUMMARY"))
	b.WriteString("\n")

	for _, s := range servers {
		b.WriteString("  ")
		b.WriteString(s.label())
		b.WriteString(": ")

		status := termsafe.QuoteCut(s.Status, maxShortCellRunes)
		b.WriteString(st.status(s.Status, status))
		if s.Status != StatusOK && s.Reason != "" {
			b.WriteString(" (")
			b.WriteString(termsafe.QuoteCut(s.Reason, maxReasonRunes))
			b.WriteString(")")
		}
		if s.Status == StatusOK {
			fmt.Fprintf(&b, ", %d %s", s.Tools, plural(s.Tools, "tool", "tools"))
		}
		fmt.Fprintf(&b, ", %d %s\n", s.Findings, plural(s.Findings, "finding", "findings"))

		for _, warning := range s.Warnings {
			b.WriteString("    warning: ")
			b.WriteString(WarningText(warning))
			b.WriteString("\n")
		}
	}

	_, err := io.WriteString(w, b.String())
	return err
}

// plural returns one when n is 1, else many. It is the same as plural in
// cmd/mcpmoat; report cannot import main.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// WarningText returns "<kind>: <what it means>" for one inspection warning:
// the escaped, capped, one-line detail of a warning. It never holds a header
// value. "mcpmoat pin" prints it on stderr after a "server <name>: " prefix,
// and WriteSummary prints it under the server.
//
// The header keys come from a config file, so they are escaped and cut, and
// at most maxSummaryHeaderKeys of them show. Nothing here prints a header
// value, a URL or the user info of a URL: a Warning holds none.
func WarningText(w inspect.Warning) string {
	var detail string
	switch w.Kind {
	case inspect.WarnCleartextSecrets:
		keys := w.HeaderKeys
		if len(keys) > maxSummaryHeaderKeys {
			keys = keys[:maxSummaryHeaderKeys]
		}
		// At most: the keys, "and N more", the user info and the URL secrets.
		parts := make([]string, 0, len(keys)+3)
		for _, k := range keys {
			parts = append(parts, "header "+termsafe.QuoteCut(k, maxSummaryNameRunes))
		}
		if more := len(w.HeaderKeys) - len(keys); more > 0 {
			parts = append(parts, fmt.Sprintf("and %d more header %s", more, plural(more, "key", "keys")))
		}
		if w.URLUserInfo {
			parts = append(parts, "the user info of the URL")
		}
		if w.URLSecrets {
			parts = append(parts, "secret parts of the URL")
		}
		detail = "secrets go over plain http to a host that is not loopback: " + strings.Join(parts, ", ")
	case inspect.WarnUndeclaredCapability:
		detail = "the server answered lists that it did not declare (it can show other lists to other clients): " +
			termsafe.Quote(strings.Join(w.Capabilities, ", "))
	case inspect.WarnDNSPinUnavailable:
		detail = "a proxy from the environment resolves the host, so the DNS pin and the address checks do not apply"
	default:
		detail = "unknown warning"
	}
	return termsafe.Quote(string(w.Kind)) + ": " + detail
}
