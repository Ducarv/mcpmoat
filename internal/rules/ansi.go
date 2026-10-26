package rules

import (
	"regexp"
	"strings"
)

// oscExpr matches an OSC for ansiSeq: ESC ] (or U+009D), at most 256 runes
// of text, and BEL, ESC \ or U+009C.
const oscExpr = `(?:\x1b\]|\x{9d})[^\x07\x1b\x{9c}]{0,256}(?:\x07|\x1b\\|\x{9c})`

// oscExprC0 is oscExpr for ansiSeqC0: the text of an OSC also holds no
// U+009D, so U+009D starts a new OSC, as ESC does. In oscExpr, each U+009D
// of a run of U+009D starts a match that stays open for up to 256 runes, so
// the regex engine keeps up to 256 threads for each rune (see the cost
// comment in match.go for the time). oscExprC0 keeps one thread.
// ansiSeq keeps oscExpr, so the forms that read with ansiSeq do not change.
const oscExprC0 = `(?:\x1b\]|\x{9d})[^\x07\x1b\x{9c}\x{9d}]{0,256}(?:\x07|\x1b\\|\x{9c})`

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
// A CSI here holds no C0 control rune. The forms 1 to 3 of matchForms read
// the sequences with ansiSeq. The forms 4 to 7 read them with ansiSeqC0.
var ansiSeq = regexp.MustCompile(`(?:\x1b\[|\x{9b})[0-?]*[ -/]*[@-~]|` + oscExpr)

// csiC0 is the content of a regex class: the C0 control runes that a
// terminal (VT500 and xterm) runs inside a CSI and then goes on with the
// sequence. It is U+0000 to U+001F and DEL (U+007F), but not CAN (U+0018) and
// SUB (U+001A), which cancel the sequence, and not ESC (U+001B), which starts
// a new one. It holds TAB, LF and CR too.
const csiC0 = `\x00-\x17\x19\x1c-\x1f\x7f`

// ansiSeqC0 is ansiSeq, but a CSI can hold C0 control runes (see csiC0), as
// in a terminal: between ESC and "[", and among the parameter and
// intermediate bytes. So ESC + U+0001 + "[8m" and U+009B + U+0001 + "8m" are
// a CSI too. Its OSC text holds no U+009D (see oscExprC0).
//
// The final byte of a CSI can be a letter of the text: in ESC [ "Ignore",
// the CSI is ESC [ I, as for a terminal. And a C0 rune lets a CSI take
// parameter bytes of the text: ESC [ LF "<IMPORTANT>" is the CSI ESC [ LF < I.
// So only the forms 4 to 7 of matchForms read the sequences with ansiSeqC0,
// and the fifth and the seventh form give back the text of a CSI with a
// letter final byte (see ansiKeepText).
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

// ansiC0ToSpace is ansiToSpace with ansiSeqC0: it replaces each ANSI escape
// sequence, also a CSI that holds C0 control runes, with U+0020. It is the
// ANSI step of the fourth and the sixth form of matchForms. A sequence is at
// least 2 bytes long, so the text does not grow.
func ansiC0ToSpace(s string) string {
	return ansiSeqC0.ReplaceAllLiteralString(s, " ")
}

// ansiKeepText is the ANSI step of the fifth and the seventh form of
// matchForms (see keepSeqText and keepSeqTextSpaced). It replaces each ANSI
// escape sequence (see ansiSeqC0) with the text that seqText gives for it.
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
// its text. matchWindowCut reads the fifth and the seventh form with it, so
// every byte of these forms counts for the window except the text of an
// OSC: the two U+0020 of an OSC with no text count too.
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
