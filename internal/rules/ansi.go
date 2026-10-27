package rules

import (
	"regexp"
	"strings"
)

// oscExpr matches an OSC for ansiSeq: ESC ] (or U+009D), at most 256 runes
// of text, and BEL, ESC \ or U+009C. The text can hold U+009D. So each
// U+009D starts a match that stays open for up to 256 runes, and in a run of
// U+009D the regex engine keeps up to 256 threads for each rune. That is
// slow (see the cost comment in match.go), so baseFormsCut reads a text with
// more than maxStrictOSCStarts U+009D with ansiSeqFast instead.
const oscExpr = `(?:\x1b\]|\x{9d})[^\x07\x1b\x{9c}]{0,256}(?:\x07|\x1b\\|\x{9c})`

// oscExprC0 is oscExpr for ansiSeqC0 and ansiSeqFast: the text of an OSC
// also holds no U+009D, so U+009D starts a new OSC, as ESC does. The regex
// engine then keeps one OSC thread, also in a run of U+009D.
const oscExprC0 = `(?:\x1b\]|\x{9d})[^\x07\x1b\x{9c}\x{9d}]{0,256}(?:\x07|\x1b\\|\x{9c})`

// maxStrictOSCStarts is the largest number of U+009D (C1 OSC) in a text for
// which the strict-reading forms of baseFormsCut read the sequences with
// ansiSeq.
// Up to it, the OSC part of ansiSeq costs at most maxStrictOSCStarts x 256
// extra thread steps for one regex pass, which is negligible. Above it, these
// forms read with ansiSeqFast and baseFormsCut sets the cut flag, so
// match_window (MOAT-T1-017, MOAT-T1-018, high) flags the text. A well-formed
// description rarely holds so many U+009D, but a benign text can: UTF-8 read
// as Latin-1 (mojibake) turns each right double quote (E2 80 9D) into
// U+00E2, U+20AC and U+009D, so more than 256 such quotes give a high
// finding. The owner accepts this false positive by design (#146). The
// count reads the part of the text that normalizeForMatch reads (see
// scanFormFlags). The seams of matchSeams must stay at or below this count
// (see the check next to seamSideBytes).
const maxStrictOSCStarts = 256

// csiExpr matches a CSI for ansiSeq and ansiSeqFast: ESC [ (or U+009B),
// parameter and intermediate bytes, and a final byte. It holds no C0 control
// rune.
const csiExpr = `(?:\x1b\[|\x{9b})[0-?]*[ -/]*[@-~]`

// ansiSeq matches an ANSI escape sequence that a terminal runs and does not
// show:
//
//   - CSI: ESC [ (or U+009B), parameter and intermediate bytes, and a final
//     byte, such as ESC [ 8 m (SGR 8, which hides the text after it);
//   - OSC: ESC ] (or U+009D), at most 256 runes of text, and BEL, ESC \ or
//     U+009C (see oscExpr).
//
// An OSC with no end, or with more than 256 runes of text, does not match,
// so it cannot swallow the rest of the text; its ESC is an invisible control
// rune, so step 4 of normalizeForMatch drops it, and its text stays.
//
// A CSI here holds no C0 control rune (see csiExpr). The strict-reading forms
// of baseFormsCut read the sequences with ansiSeq, or with ansiSeqFast when
// the text holds more than maxStrictOSCStarts U+009D. The other forms (the
// ansiSeqC0 forms) read them with ansiSeqC0.
var ansiSeq = regexp.MustCompile(csiExpr + `|` + oscExpr)

// ansiSeqFast is ansiSeq with oscExprC0 for its OSC part: a U+009D ends the
// text of an OSC and starts a new one. Its CSI part is the same as in
// ansiSeq, so a CSI, also one that starts with U+009B, still holds no C0
// control rune. The strict-reading forms of baseFormsCut read a text that
// holds more than maxStrictOSCStarts U+009D with it (see ansiFastToSpace).
// The one difference from ansiSeq: an OSC whose text holds U+009D does not
// match from its start. So in ESC "]x" + U+009D + BEL, only U+009D BEL is an OSC, and
// ESC "]x" stays as text (step 4 of normalizeForMatch drops the ESC).
var ansiSeqFast = regexp.MustCompile(csiExpr + `|` + oscExprC0)

// csiC0 is the content of a regex class: the C0 control runes that a
// terminal (VT500 and xterm) runs inside a CSI and then goes on with the
// sequence. It is U+0000 to U+001F and DEL (U+007F), but not CAN (U+0018) and
// SUB (U+001A), which cancel the sequence, and not ESC (U+001B), which starts
// a new one. It holds TAB, LF and CR too.
const csiC0 = `\x00-\x17\x19\x1c-\x1f\x7f`

// isCSIC0 reports whether r is a C0 control rune of csiC0: U+0000 to U+0017,
// U+0019, U+001C to U+001F, or DEL (U+007F). It is the regex class csiC0 as a
// plain rune check, so scanFormFlags needs no regex.
func isCSIC0(r rune) bool {
	switch {
	case r >= 0x00 && r <= 0x17, r == 0x19, r >= 0x1c && r <= 0x1f, r == 0x7f:
		return true
	}
	return false
}

// startsSeq reports whether r is ESC, U+009B (CSI) or U+009D (OSC), a rune
// that starts an ANSI escape sequence in ansiSeq and ansiSeqC0.
func startsSeq(r rune) bool {
	return startsCSI(r) || r == '\u009d'
}

// startsCSI reports whether r is ESC or U+009B, a rune that starts a CSI in
// ansiSeq and ansiSeqC0.
func startsCSI(r rune) bool {
	return r == '\x1b' || r == '\u009b'
}

// ansiSeqC0 is ansiSeq, but a CSI can hold C0 control runes (see csiC0), as
// in a terminal: between ESC and "[", and among the parameter and
// intermediate bytes. So ESC + U+0001 + "[8m" and U+009B + U+0001 + "8m" are
// a CSI too. Its OSC text holds no U+009D (see oscExprC0).
//
// The final byte of a CSI can be a letter of the text: in ESC [ "Ignore",
// the CSI is ESC [ I, as for a terminal. And a C0 rune lets a CSI take
// parameter bytes of the text: ESC [ LF "<IMPORTANT>" is the CSI ESC [ LF < I.
// So only the ansiSeqC0 forms of baseFormsCut read the sequences with
// ansiSeqC0, and the keepSeqText and keepSeqTextSpaced forms give back the
// text of a CSI with a letter final byte (see ansiKeepText).
var ansiSeqC0 = regexp.MustCompile(
	`(?:\x1b[` + csiC0 + `]*\[|\x{9b})[0-?` + csiC0 + `]*[ -/` + csiC0 + `]*[@-~]` +
		`|` + oscExprC0)

// ansiToSpace replaces each ANSI escape sequence (see ansiSeq) with U+0020.
// Without this step, ESC [ 8 m before "Ignore" leaves "[8mIgnore", and the
// word edge before "Ignore" is lost. A sequence is at least 2 bytes long, so
// the text does not grow.
//
// These control runes change how a sequence is read, and they are invisible
// control runes (see isInvisible). So buildForm drops or replaces
// them only after this step:
//
//   - ESC (U+001B) and the C1 controls CSI (U+009B), ST (U+009C) and OSC
//     (U+009D) start or end a sequence in ansiSeq;
//   - BEL (U+0007) ends an OSC in ansiSeq;
//   - the other C0 control runes (see csiC0) can stand inside a CSI of
//     ansiSeqC0 (see ansiC0ToSpace);
//   - CAN (U+0018) and SUB (U+001A) cancel a sequence in a terminal, and the
//     terminal shows the text after them. They are still in the text here,
//     so ESC [ CAN "Ignore" is not read as ESC [ I, a CSI that hides the "I".
func ansiToSpace(s string) string {
	return ansiSeq.ReplaceAllLiteralString(s, " ")
}

// ansiFastToSpace is ansiToSpace with ansiSeqFast: it replaces each ANSI
// escape sequence of ansiSeqFast with U+0020. It is the ANSI step of the
// strict-reading forms of baseFormsCut for a text that holds more than
// maxStrictOSCStarts U+009D (see formMode.ansiStepFor). A sequence is at
// least 2 bytes long, so the text does not grow.
func ansiFastToSpace(s string) string {
	return ansiSeqFast.ReplaceAllLiteralString(s, " ")
}

// ansiC0ToSpace is ansiToSpace with ansiSeqC0: it replaces each ANSI escape
// sequence, also a CSI that holds C0 control runes, with U+0020. It is the
// ANSI step of the spaceFormats and dropSeqC0 forms of baseFormsCut. A
// sequence is at least 2 bytes long, so the text does not grow.
func ansiC0ToSpace(s string) string {
	return ansiSeqC0.ReplaceAllLiteralString(s, " ")
}

// ansiKeepText is the ANSI step of the keepSeqText and keepSeqTextSpaced
// forms of baseFormsCut. It replaces each ANSI escape sequence (see
// ansiSeqC0) with the text that seqText gives for it.
// So a CSI that takes characters of the text gives them back, and the text
// of an OSC, which a terminal does not show but a model reads, is matched.
//
// No replacement is longer than its sequence, so the text does not grow:
//
//   - a CSI with a letter other than 'm' as its final byte becomes 1 byte
//     (U+0020), its kept parameter and intermediate bytes, and its final
//     byte. It is at least 2 bytes (ESC [ or U+009B), the same kept bytes
//     and more, and its final byte;
//   - an SGR (a CSI with the final byte 'm') becomes nothing;
//   - an OSC becomes U+0020, at most its text, and U+0020, and it is its
//     text and at least 3 bytes long (ESC ] and BEL; U+009D is 2 bytes, and
//     its end is 1 or 2 bytes). Its text is read with these same rules, so
//     the text does not grow either;
//   - each other sequence becomes 1 byte, and it is at least 2 bytes long.
func ansiKeepText(s string) string {
	return ansiSeqC0.ReplaceAllStringFunc(s, seqText)
}

// ansiKeepCSIText is ansiKeepText, but an OSC becomes two U+0020, without
// its text. The cut flag of baseFormsCut reads the keepSeqText and
// keepSeqTextSpaced forms with it, so every byte of these forms counts for
// the window except the text of an OSC: the two U+0020 of an OSC with no text
// count too.
func ansiKeepCSIText(s string) string {
	return ansiSeqC0.ReplaceAllStringFunc(s, func(seq string) string {
		if _, ok := oscText(seq); ok {
			return "  "
		}
		return csiSeqText(seq)
	})
}

// seqText returns what ansiKeepText puts in place of seq, a match of
// ansiSeqC0:
//
//   - for an OSC: U+0020, its text and U+0020. Each CSI in the text (it can
//     only start with U+009B) is replaced as below, so ESC ] + U+009B +
//     "8mIgnore" BEL is " Ignore ", not " 8mIgnore ";
//   - for a CSI whose final byte is 'm' (SGR: colour and bold): nothing, as a
//     terminal shows it. So "Ig" + ESC [ 0 m + "nore" is "Ignore", and
//     ESC [ 1 m "iPhone" is "iPhone", not "miPhone";
//   - for a CSI whose final byte is another ASCII letter: U+0020, the bytes
//     of csiText, and the final byte. So ESC [ "<IMPORTANT>" (the CSI
//     ESC [ < I) is " <IMPORTANT>", and ESC [ 2 K is " K";
//   - for each other sequence: one U+0020.
func seqText(seq string) string {
	if text, ok := oscText(seq); ok {
		// One level only: the text holds no ESC, U+009D, BEL or U+009C, so it
		// holds no OSC and the inner matches are CSIs, which do not recurse.
		return " " + ansiKeepText(text) + " "
	}
	return csiSeqText(seq)
}

// csiSeqText returns what seqText puts in place of seq, a CSI or another
// sequence of ansiSeqC0 that is not an OSC.
func csiSeqText(seq string) string {
	final := seq[len(seq)-1]
	switch {
	case final == 'm':
		return ""
	case isASCIILetter(final):
		return " " + csiText(seq[:len(seq)-1]) + string(final)
	}
	return " "
}

// csiText returns the bytes of head that a CSI takes from the text: head is
// a CSI of ansiSeqC0 without its final byte. They are its parameter bytes
// < = > ? (0x3C to 0x3F) and its intermediate bytes (0x20 to 0x2F, such as
// "." and "/"), in order. The introducer (ESC, its C0 runes and "[", or
// U+009B), the numeric parameter bytes (digits, ";" and ":") and the C0 runes
// are dropped: a numeric parameter is mostly a real SGR or cursor parameter,
// not text.
func csiText(head string) string {
	if body, ok := strings.CutPrefix(head, "\u009b"); ok {
		head = body
	} else {
		// ESC, C0 runes and "[": the first "[" ends the introducer,
		// because no rune before it and no parameter or intermediate
		// byte is "[".
		_, head, _ = strings.Cut(head, "[")
	}
	kept := make([]byte, 0, len(head))
	for i := range len(head) {
		if c := head[i]; (' ' <= c && c <= '/') || ('<' <= c && c <= '?') {
			kept = append(kept, c)
		}
	}
	return string(kept)
}

// oscEnds are the runes that end an OSC in oscExpr and oscExprC0: BEL, ESC \
// and U+009C.
var oscEnds = [...]string{"\x07", "\x1b\\", "\u009c"}

// oscText returns the text of seq, a match of ansiSeqC0, when seq is an OSC:
// the part between ESC ] (or U+009D) and its end (BEL, ESC \ or U+009C). It
// returns false when seq is a CSI. The text of an OSC holds no BEL, ESC or
// U+009C (see oscExprC0), so the end is not ambiguous.
func oscText(seq string) (string, bool) {
	var text string
	switch {
	case strings.HasPrefix(seq, "\x1b]"):
		text = seq[len("\x1b]"):]
	case strings.HasPrefix(seq, "\u009d"):
		text = seq[len("\u009d"):]
	default:
		return "", false
	}
	for _, end := range oscEnds {
		if t, ok := strings.CutSuffix(text, end); ok {
			return t, true
		}
	}
	return text, true // not reached: ansiSeqC0 ends each OSC with one of them
}

// isASCIILetter reports whether c is an ASCII letter, A to Z or a to z.
func isASCIILetter(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z'
}
