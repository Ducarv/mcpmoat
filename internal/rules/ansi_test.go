package rules

import (
	"regexp"
	"testing"
	"unicode/utf8"
)

// csiC0Oracle matches one rune of the C0 class that a terminal runs inside a
// CSI. It is a copy of the regex class csiC0 in ansi.go, kept here so that
// the tests of isCSIC0 do not read the code under test.
var csiC0Oracle = regexp.MustCompile(`[\x00-\x17\x19\x1c-\x1f\x7f]`)

// TestOSCTextEndsAtC1OSC checks oscExprC0: in ansiSeqC0, the text of an OSC
// holds no U+009D, so a U+009D starts a new OSC. In ansiSeq (oscExpr), the
// OSC runs on to its end.
func TestOSCTextEndsAtC1OSC(t *testing.T) {
	t.Parallel()

	in := "\x1b]x\u009d\x07"
	if got, want := ansiSeqC0.FindString(in), "\u009d\x07"; got != want {
		t.Errorf("ansiSeqC0.FindString(%+q) = %+q, want %+q", in, got, want)
	}
	if got := ansiSeq.FindString(in); got != in {
		t.Errorf("ansiSeq.FindString(%+q) = %+q, want %+q", in, got, in)
	}
	text := "previous\x1b]x\u009d\x07instructions"
	for _, tt := range []struct {
		mode formMode
		want string
	}{
		{mode: dropSeqC0, want: "previous]x instructions"},
		{mode: keepSeqText, want: "previous]x  instructions"},
	} {
		if got := buildForm(text, tt.mode); got != tt.want {
			t.Errorf("buildForm(%+q, %v) = %+q, want %+q", text, tt.mode, got, tt.want)
		}
	}
}

// TestSeqText checks what the fifth and the seventh form put in place of each
// kind of escape sequence. Each input is one whole match of ansiSeqC0, the
// regex whose matches ansiKeepText passes to seqText.
func TestSeqText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		seq  string
		want string
	}{
		{name: "CSI with letter", seq: "\x1b[I", want: " I"},
		{name: "SGR m final is removed", seq: "\x1b[8m", want: ""},
		{name: "CSI with a non-m letter final keeps it", seq: "\x1b[2K", want: " K"},
		{name: "C1 CSI with letter", seq: "\u009bI", want: " I"},
		{name: "CSI with control rune and letter", seq: "\x1b[\x01z", want: " z"},
		{name: "CSI with no letter", seq: "\x1b[1@", want: " "},
		{name: "CSI with a ~ final", seq: "\x1b[~", want: " "},
		// csiText: the bytes 0x20 to 0x2F and 0x3C to 0x3F are kept, and the
		// introducer, the digits, ";", ":" and the C0 runes are dropped.
		{name: "CSI keeps a < parameter byte", seq: "\x1b[<I", want: " <I"},
		{name: "CSI keeps a . intermediate byte", seq: "\x1b[.e", want: " .e"},
		{name: "CSI drops a digit", seq: "\x1b[1I", want: " I"},
		{name: "CSI drops digits and ;", seq: "\x1b[1;2I", want: " I"},
		{name: "CSI keeps ? and drops digits", seq: "\x1b[?25l", want: " ?l"},
		{name: "CSI drops : and keeps =", seq: "\x1b[=1:2>K", want: " =>K"},
		{name: "CSI drops a C0 rune", seq: "\x1b[\x01<I", want: " <I"},
		{name: "CSI drops C0 runes between ESC and [", seq: "\x1b\x01\n[<I", want: " <I"},
		{name: "C1 CSI keeps a < parameter byte", seq: "\u009b<I", want: " <I"},
		// The OSC text stays as it is, also its digits and "<".
		{name: "OSC with BEL", seq: "\x1b]0;t\x07", want: " 0;t "},
		{name: "OSC keeps < and digits", seq: "\x1b]<1>\x07", want: " <1> "},
		{name: "OSC with ST", seq: "\x1b]t\x1b\\", want: " t "},
		{name: "C1 OSC with C1 ST", seq: "\u009dt\u009c", want: " t "},
		{name: "empty OSC", seq: "\u009d\x07", want: "  "},
		// A CSI in the OSC text is read as outside an OSC: an SGR becomes
		// nothing, and a CSI with a letter final gives a space and its letter.
		{name: "OSC text drops a C1 SGR", seq: "\x1b]\u009b8mt\x07", want: " t "},
		{name: "OSC text keeps the letter of a C1 CSI", seq: "\x1b]0;\u009b2Kt\x07", want: " 0; Kt "},
		{name: "OSC text with a C1 CSI that takes a letter", seq: "\x1b]\u009bIgnore\x07", want: "  Ignore "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if m := ansiSeqC0.FindString(tt.seq); m != tt.seq {
				t.Fatalf("ansiSeqC0.FindString(%+q) = %+q, want the whole input", tt.seq, m)
			}
			if got := seqText(tt.seq); got != tt.want {
				t.Errorf("seqText(%+q) = %+q, want %+q", tt.seq, got, tt.want)
			}
		})
	}
}

// TestIsCSIC0AllRunes checks isCSIC0 against csiC0Oracle for every valid
// rune. The surrogates are not valid runes, so they are skipped. The oracle
// reads all runes in one regex pass, because one call for each rune is slow
// with the race detector.
func TestIsCSIC0AllRunes(t *testing.T) {
	t.Parallel()

	var all []byte
	for r := rune(0); r <= utf8.MaxRune; r++ {
		if utf8.ValidRune(r) {
			all = utf8.AppendRune(all, r)
		}
	}
	text := string(all)
	want := make(map[rune]bool)
	for _, loc := range csiC0Oracle.FindAllStringIndex(text, -1) {
		r, _ := utf8.DecodeRuneInString(text[loc[0]:])
		want[r] = true
	}
	if len(want) == 0 {
		t.Fatal("csiC0Oracle matched no rune, want the C0 runes of csiC0")
	}
	for _, r := range text {
		if got := isCSIC0(r); got != want[r] {
			t.Errorf("isCSIC0(%U) = %v, want %v", r, got, want[r])
		}
	}
	for _, r := range []rune{-1, utf8.MaxRune + 1} {
		if isCSIC0(r) {
			t.Errorf("isCSIC0(%d) = true, want false", r)
		}
	}
}
