package report

// Style tells the report writers how to decorate their output.
//
// Colour is decoration only. Every text that WriteFindings and WriteSummary
// write carries its meaning in words (a severity word, a status word), so the
// plain output is complete.
type Style struct {
	// Color is true only when stdout is a terminal, the user did not pass
	// --no-color, and the NO_COLOR environment variable is unset or empty. The
	// caller decides: this package does not read the environment or look at
	// the terminal.
	Color bool
}

// ANSI SGR (Select Graphic Rendition) sequences. This is the only place in
// the package where the ESC byte (\x1b) is written. Text from a config file
// or a server never reaches the output unescaped (see internal/termsafe), so
// no other ESC can appear in the report.
const (
	sgrReset   = "\x1b[0m"
	sgrBold    = "\x1b[1m"
	sgrBoldRed = "\x1b[1;31m"
	sgrRed     = "\x1b[31m"
	sgrGreen   = "\x1b[32m"
	sgrYellow  = "\x1b[33m"
	sgrCyan    = "\x1b[36m"
)

// paint wraps text in the SGR code and the reset sequence. The caller has
// already escaped text. With Color false it returns text unchanged, so the
// plain output is the same bytes as the output without a Style.
func (s Style) paint(code, text string) string {
	if !s.Color {
		return text
	}
	return code + text + sgrReset
}

// severity colours text for the severity word sev: bold red for "critical",
// red for "high", yellow for "medium" and cyan for "low". Any other word has
// the style of "critical", so an unknown severity never looks harmless.
func (s Style) severity(sev, text string) string {
	switch groupSeverity(sev) {
	case severityHigh:
		return s.paint(sgrRed, text)
	case severityMedium:
		return s.paint(sgrYellow, text)
	case severityLow:
		return s.paint(sgrCyan, text)
	}
	return s.paint(sgrBoldRed, text)
}

// heading makes text bold, for a section heading such as "FINDINGS".
func (s Style) heading(text string) string {
	return s.paint(sgrBold, text)
}

// status colours text for the server status word st: green for "ok", yellow
// for "timeout" and "failed". Any other status stays plain.
func (s Style) status(st, text string) string {
	switch st {
	case StatusOK:
		return s.paint(sgrGreen, text)
	case StatusTimeout, StatusFailed:
		return s.paint(sgrYellow, text)
	}
	return text
}
