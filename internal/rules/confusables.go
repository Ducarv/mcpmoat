package rules

import (
	"strings"
	"unicode/utf8"
)

// This file holds the confusable skeleton of the regex fold (issue #140).
//
// The fold of foldMarks maps fullwidth and mathematical letters to ASCII,
// but it does not map a letter of another script that only looks like a
// Latin letter. So "~/." + U+0455 U+0455 U+04BB (Cyrillic dze twice and
// shha) is not "~/.ssh" for the regexes, but a model reads it as "~/.ssh".
// The mixed_script heuristic does not flag it either: the word has letters
// of one script only, as a real Russian word does.
//
// A list of scripts cannot fix this, because the problem is the shape of
// each letter, not its script. Unicode TR39 (section 4) solves it with a
// skeleton: each character is mapped to a prototype that looks the same, so
// two strings that look the same get the same skeleton. The skeleton here is
// a small part of that idea: it maps one rune to one ASCII letter, and only
// in the regex fold. The keyword fold, mixedScript and appendFold do not
// change.

// The sources of lookalikeScripts and of both look-alike tables.
// confusablesVersion is the version of Unicode TR39 confusables.txt
// (https://www.unicode.org/reports/tr39/) and scriptTablesVersion is the
// Unicode version of the Go unicode tables (unicode.Version) when the lists
// were made. When Go updates its tables, or TR39 has a new version, check
// the lists again: a new script or a new confusable can add a script or a
// table entry.
const (
	confusablesVersion  = "18.0.0"
	scriptTablesVersion = "17.0.0"
)

// confusable maps one rune to the ASCII letter that it looks like.
type confusable struct {
	from rune // a letter or a spacing mark that is not ASCII
	to   byte // an ASCII letter: a-z or A-Z
}

// skeletonTable is the table of skeletonOf, sorted by from with no
// duplicates. It is a hand-checked subset of TR39 confusables.txt, version
// confusablesVersion (the same version that lookalikeScripts comes from).
// When confusablesVersion or scriptTablesVersion changes, make the table
// again from a local copy of confusables.txt with TestGenTables
// (gentables_test.go). With -update it rewrites the table; without it, it
// compares the table with the generated one:
//
//	go test ./internal/rules/ -run TestGenTables -args -confusables=PATH [-update]
//
// Every entry comes from one line of confusables.txt whose source is one rune
// and whose target is one ASCII letter, alone or followed only by combining
// marks of category Mn. The entry maps the rune to that letter and drops the
// marks, because foldMarks drops every mark of the text too: TR39 maps
// U+0268 (i with stroke) to "i" + U+0335 and U+00F8 (o with stroke) to "o" +
// U+0338, so the table maps them to "i" and "o", and U+0268 + "gnore" reads
// as "ignore". The rune is:
//
//   - a letter (unicode.IsLetter) or a spacing mark (category Mc) in the Go
//     unicode tables (scriptTablesVersion), or the symbol U+212E (estimated
//     sign, "e"). Runes that are new in TR39 but not yet in the Go tables
//     are left out;
//   - not mapped to ASCII by foldMarks already, such as U+FF49 (fullwidth
//     "i") or U+00E9 ("e" with acute): the fold handles those;
//   - not a rune whose fold is one rune of this table with the same target,
//     such as U+1D6C2 (mathematical bold alpha), whose fold is U+03B1
//     (Greek alpha, "a"): foldSkeleton maps the fold;
//   - not Han. As in lookalikeScripts, Chinese and Japanese text puts Han
//     letters next to Latin names, so U+4E2B and U+4E05 are left out.
//
// The target keeps the case of TR39, so Cyrillic U+0410 is "A" and U+0430
// is "a". The regex fold is not lowercased, and a regex gets no automatic
// (?i), so a case-sensitive pattern still sees the case that a reader sees.
//
// The I/l rule. TR39 maps "I" (U+0049) and every rune that looks like "I"
// or "l" to "l", so its skeleton cannot tell them apart. The rules need
// both: "i" in ignore, "l" in all. The table maps a rune with the TR39
// target "l" to "I" when the rune is an uppercase letter (unicode.IsUpper),
// such as Cyrillic U+0406 and Greek U+0399, and to "l" otherwise, such as
// Cyrillic U+04CF (small palochka) and Hebrew vav U+05D5. Such an entry has
// "(TR39: l)" in its comment when it maps to "I". One caseless rune maps to
// "I" too: U+A7FE (Latin epigraphic letter I longa), which is an "I" by its
// name (see latinILonga in the test).
//
// So the table still picks one letter for each rune, and some texts need
// the other one: an uppercase look-alike used as "l" ("a" + U+0406 U+0406
// reads "aII") and a caseless or lowercase one used as "I" (U+01C0, a bare
// bar, or U+04CF + "gnore" reads "lgnore"). So in the skeleton folds, the
// any_regex and all_regex patterns run as their I/l-blind twin (see
// twinFromTree in twin.go), which reads "I" and "l" as one letter. So
// "lgnore" and "aII" in a skeleton fold match `(?i)ignore` and `(?i)all`,
// also when one rune is used both ways. For such a pattern the pick of the
// table does not matter, within the limits of the twin (a keyword, an "i" or
// "L" without (?i), a wide or negated class: see twin.go). A plain ASCII text
// has no skeleton fold, so ASCII "lgnore" does not match.
//
// The runes that are not in the table but that the plain fold (foldMarks)
// turns into an ASCII "I" or "l" by a compatibility mapping get the same
// reading: 38 runes fold to exactly "I" or "l", such as fullwidth U+FF29
// and U+FF4C, the roman numerals U+2160 and U+217C, and the mathematical
// letters U+1D5A8 and U+1D5C5, and 27 more fold to a longer text with an
// "I" or "l", such as U+2161 ("II"). A plain fold with such a rune is read
// with the twin too (see foldAddsIL in prepare.go). The 23 accented letters
// that fold to "I" or "l" because the fold drops their marks, such as
// U+00CF (I with diaeresis) and U+013E (l with caron), are normal letters,
// not look-alikes, so they do not get the twin.
//
// The I/l rule uses the letter of the target, also when marks follow it:
// U+0197 (capital I with stroke, TR39 "l" + U+0335) maps to "I", and U+019A
// (small l with bar) maps to "l".
//
// Left out on purpose: digits as targets and as sources (leetspeak, such as
// Devanagari zero U+0966 for "o"), symbols and punctuation other than
// U+212E (such as U+00D7 for "x" and U+2502 for "l"), every source of two
// or more runes, and every target with two or more letters (such as "rn"
// for "m") or with a rune after the letter that is not an Mn mark.
//
// A known limit: U+017F (long s). TR39 maps it to "f", but its fold in
// foldMarks is "s" (NFKD), so the table cannot hold it (the rule above), and
// U+017F + "orget" reads as "sorget" for the regexes.
//
// The spacing marks (the entries marked "spacing mark") map only in the
// first pass of foldSkeleton, because foldMarks drops every mark: "Ign" +
// U+0C02 + "re" (Telugu anusvara) reads as "Ignore".
var skeletonTable = [...]confusable{
	{0x00D0, 'D'},  // LATIN CAPITAL LETTER ETH
	{0x00D8, 'O'},  // LATIN CAPITAL LETTER O WITH STROKE
	{0x00F8, 'o'},  // LATIN SMALL LETTER O WITH STROKE
	{0x00FE, 'p'},  // LATIN SMALL LETTER THORN
	{0x0110, 'D'},  // LATIN CAPITAL LETTER D WITH STROKE
	{0x0111, 'd'},  // LATIN SMALL LETTER D WITH STROKE
	{0x0126, 'H'},  // LATIN CAPITAL LETTER H WITH STROKE
	{0x0127, 'h'},  // LATIN SMALL LETTER H WITH STROKE
	{0x0131, 'i'},  // LATIN SMALL LETTER DOTLESS I
	{0x0141, 'L'},  // LATIN CAPITAL LETTER L WITH STROKE
	{0x0142, 'l'},  // LATIN SMALL LETTER L WITH STROKE
	{0x014B, 'n'},  // LATIN SMALL LETTER ENG
	{0x0166, 'T'},  // LATIN CAPITAL LETTER T WITH STROKE
	{0x0167, 't'},  // LATIN SMALL LETTER T WITH STROKE
	{0x0180, 'b'},  // LATIN SMALL LETTER B WITH STROKE
	{0x0182, 'b'},  // LATIN CAPITAL LETTER B WITH TOPBAR
	{0x0183, 'b'},  // LATIN SMALL LETTER B WITH TOPBAR
	{0x0184, 'b'},  // LATIN CAPITAL LETTER TONE SIX
	{0x0189, 'D'},  // LATIN CAPITAL LETTER AFRICAN D
	{0x018B, 'd'},  // LATIN CAPITAL LETTER D WITH TOPBAR
	{0x018C, 'd'},  // LATIN SMALL LETTER D WITH TOPBAR
	{0x018D, 'g'},  // LATIN SMALL LETTER TURNED DELTA
	{0x0191, 'F'},  // LATIN CAPITAL LETTER F WITH HOOK
	{0x0192, 'f'},  // LATIN SMALL LETTER F WITH HOOK
	{0x0196, 'I'},  // LATIN CAPITAL LETTER IOTA (TR39: l)
	{0x0197, 'I'},  // LATIN CAPITAL LETTER I WITH STROKE (TR39: l)
	{0x0199, 'k'},  // LATIN SMALL LETTER K WITH HOOK
	{0x019A, 'l'},  // LATIN SMALL LETTER L WITH BAR
	{0x019D, 'N'},  // LATIN CAPITAL LETTER N WITH LEFT HOOK
	{0x019E, 'n'},  // LATIN SMALL LETTER N WITH LONG RIGHT LEG
	{0x019F, 'O'},  // LATIN CAPITAL LETTER O WITH MIDDLE TILDE
	{0x01A5, 'p'},  // LATIN SMALL LETTER P WITH HOOK
	{0x01A6, 'R'},  // LATIN LETTER YR
	{0x01AB, 't'},  // LATIN SMALL LETTER T WITH PALATAL HOOK
	{0x01AD, 't'},  // LATIN SMALL LETTER T WITH HOOK
	{0x01AE, 'T'},  // LATIN CAPITAL LETTER T WITH RETROFLEX HOOK
	{0x01B4, 'y'},  // LATIN SMALL LETTER Y WITH HOOK
	{0x01B5, 'Z'},  // LATIN CAPITAL LETTER Z WITH STROKE
	{0x01B6, 'z'},  // LATIN SMALL LETTER Z WITH STROKE
	{0x01BD, 's'},  // LATIN SMALL LETTER TONE FIVE
	{0x01BF, 'p'},  // LATIN LETTER WYNN
	{0x01C0, 'l'},  // LATIN LETTER DENTAL CLICK
	{0x01E4, 'G'},  // LATIN CAPITAL LETTER G WITH STROKE
	{0x01E5, 'g'},  // LATIN SMALL LETTER G WITH STROKE
	{0x0224, 'Z'},  // LATIN CAPITAL LETTER Z WITH HOOK
	{0x0225, 'z'},  // LATIN SMALL LETTER Z WITH HOOK
	{0x0237, 'j'},  // LATIN SMALL LETTER DOTLESS J
	{0x023C, 'c'},  // LATIN SMALL LETTER C WITH STROKE
	{0x023E, 'T'},  // LATIN CAPITAL LETTER T WITH DIAGONAL STROKE
	{0x0244, 'U'},  // LATIN CAPITAL LETTER U BAR
	{0x0246, 'E'},  // LATIN CAPITAL LETTER E WITH STROKE
	{0x0247, 'e'},  // LATIN SMALL LETTER E WITH STROKE
	{0x0248, 'J'},  // LATIN CAPITAL LETTER J WITH STROKE
	{0x0249, 'j'},  // LATIN SMALL LETTER J WITH STROKE
	{0x024C, 'R'},  // LATIN CAPITAL LETTER R WITH STROKE
	{0x024D, 'r'},  // LATIN SMALL LETTER R WITH STROKE
	{0x024E, 'Y'},  // LATIN CAPITAL LETTER Y WITH STROKE
	{0x024F, 'y'},  // LATIN SMALL LETTER Y WITH STROKE
	{0x0251, 'a'},  // LATIN SMALL LETTER ALPHA
	{0x0253, 'b'},  // LATIN SMALL LETTER B WITH HOOK
	{0x0256, 'd'},  // LATIN SMALL LETTER D WITH TAIL
	{0x0257, 'd'},  // LATIN SMALL LETTER D WITH HOOK
	{0x025F, 'j'},  // LATIN SMALL LETTER DOTLESS J WITH STROKE
	{0x0260, 'g'},  // LATIN SMALL LETTER G WITH HOOK
	{0x0261, 'g'},  // LATIN SMALL LETTER SCRIPT G
	{0x0263, 'y'},  // LATIN SMALL LETTER GAMMA
	{0x0266, 'h'},  // LATIN SMALL LETTER H WITH HOOK
	{0x0268, 'i'},  // LATIN SMALL LETTER I WITH STROKE
	{0x0269, 'i'},  // LATIN SMALL LETTER IOTA
	{0x026A, 'i'},  // LATIN LETTER SMALL CAPITAL I
	{0x026B, 'l'},  // LATIN SMALL LETTER L WITH MIDDLE TILDE
	{0x026D, 'l'},  // LATIN SMALL LETTER L WITH RETROFLEX HOOK
	{0x026F, 'w'},  // LATIN SMALL LETTER TURNED M
	{0x0272, 'n'},  // LATIN SMALL LETTER N WITH LEFT HOOK
	{0x0273, 'n'},  // LATIN SMALL LETTER N WITH RETROFLEX HOOK
	{0x0275, 'o'},  // LATIN SMALL LETTER BARRED O
	{0x027C, 'r'},  // LATIN SMALL LETTER R WITH LONG LEG
	{0x027D, 'r'},  // LATIN SMALL LETTER R WITH TAIL
	{0x0282, 's'},  // LATIN SMALL LETTER S WITH HOOK
	{0x0284, 'f'},  // LATIN SMALL LETTER DOTLESS J WITH STROKE AND HOOK
	{0x028B, 'u'},  // LATIN SMALL LETTER V WITH HOOK
	{0x028F, 'y'},  // LATIN LETTER SMALL CAPITAL Y
	{0x0290, 'z'},  // LATIN SMALL LETTER Z WITH RETROFLEX HOOK
	{0x02A0, 'q'},  // LATIN SMALL LETTER Q WITH HOOK
	{0x037F, 'J'},  // GREEK CAPITAL LETTER YOT
	{0x0391, 'A'},  // GREEK CAPITAL LETTER ALPHA
	{0x0392, 'B'},  // GREEK CAPITAL LETTER BETA
	{0x0395, 'E'},  // GREEK CAPITAL LETTER EPSILON
	{0x0396, 'Z'},  // GREEK CAPITAL LETTER ZETA
	{0x0397, 'H'},  // GREEK CAPITAL LETTER ETA
	{0x0398, 'O'},  // GREEK CAPITAL LETTER THETA
	{0x0399, 'I'},  // GREEK CAPITAL LETTER IOTA (TR39: l)
	{0x039A, 'K'},  // GREEK CAPITAL LETTER KAPPA
	{0x039C, 'M'},  // GREEK CAPITAL LETTER MU
	{0x039D, 'N'},  // GREEK CAPITAL LETTER NU
	{0x039F, 'O'},  // GREEK CAPITAL LETTER OMICRON
	{0x03A1, 'P'},  // GREEK CAPITAL LETTER RHO
	{0x03A4, 'T'},  // GREEK CAPITAL LETTER TAU
	{0x03A5, 'Y'},  // GREEK CAPITAL LETTER UPSILON
	{0x03A7, 'X'},  // GREEK CAPITAL LETTER CHI
	{0x03B1, 'a'},  // GREEK SMALL LETTER ALPHA
	{0x03B3, 'y'},  // GREEK SMALL LETTER GAMMA
	{0x03B7, 'n'},  // GREEK SMALL LETTER ETA
	{0x03B8, 'O'},  // GREEK SMALL LETTER THETA
	{0x03B9, 'i'},  // GREEK SMALL LETTER IOTA
	{0x03BD, 'v'},  // GREEK SMALL LETTER NU
	{0x03BF, 'o'},  // GREEK SMALL LETTER OMICRON
	{0x03C1, 'p'},  // GREEK SMALL LETTER RHO
	{0x03C3, 'o'},  // GREEK SMALL LETTER SIGMA
	{0x03C5, 'u'},  // GREEK SMALL LETTER UPSILON
	{0x03DC, 'F'},  // GREEK LETTER DIGAMMA
	{0x03ED, 'o'},  // COPTIC SMALL LETTER SHIMA
	{0x03F2, 'c'},  // GREEK LUNATE SIGMA SYMBOL
	{0x03F3, 'j'},  // GREEK LETTER YOT
	{0x03F8, 'p'},  // GREEK SMALL LETTER SHO
	{0x03F9, 'C'},  // GREEK CAPITAL LUNATE SIGMA SYMBOL
	{0x03FA, 'M'},  // GREEK CAPITAL LETTER SAN
	{0x0405, 'S'},  // CYRILLIC CAPITAL LETTER DZE
	{0x0406, 'I'},  // CYRILLIC CAPITAL LETTER BYELORUSSIAN-UKRAINIAN I (TR39: l)
	{0x0408, 'J'},  // CYRILLIC CAPITAL LETTER JE
	{0x0410, 'A'},  // CYRILLIC CAPITAL LETTER A
	{0x0411, 'b'},  // CYRILLIC CAPITAL LETTER BE
	{0x0412, 'B'},  // CYRILLIC CAPITAL LETTER VE
	{0x0415, 'E'},  // CYRILLIC CAPITAL LETTER IE
	{0x041A, 'K'},  // CYRILLIC CAPITAL LETTER KA
	{0x041C, 'M'},  // CYRILLIC CAPITAL LETTER EM
	{0x041D, 'H'},  // CYRILLIC CAPITAL LETTER EN
	{0x041E, 'O'},  // CYRILLIC CAPITAL LETTER O
	{0x0420, 'P'},  // CYRILLIC CAPITAL LETTER ER
	{0x0421, 'C'},  // CYRILLIC CAPITAL LETTER ES
	{0x0422, 'T'},  // CYRILLIC CAPITAL LETTER TE
	{0x0423, 'Y'},  // CYRILLIC CAPITAL LETTER U
	{0x0425, 'X'},  // CYRILLIC CAPITAL LETTER HA
	{0x042C, 'b'},  // CYRILLIC CAPITAL LETTER SOFT SIGN
	{0x0430, 'a'},  // CYRILLIC SMALL LETTER A
	{0x0433, 'r'},  // CYRILLIC SMALL LETTER GHE
	{0x0435, 'e'},  // CYRILLIC SMALL LETTER IE
	{0x043E, 'o'},  // CYRILLIC SMALL LETTER O
	{0x0440, 'p'},  // CYRILLIC SMALL LETTER ER
	{0x0441, 'c'},  // CYRILLIC SMALL LETTER ES
	{0x0443, 'y'},  // CYRILLIC SMALL LETTER U
	{0x0445, 'x'},  // CYRILLIC SMALL LETTER HA
	{0x0448, 'w'},  // CYRILLIC SMALL LETTER SHA
	{0x0455, 's'},  // CYRILLIC SMALL LETTER DZE
	{0x0456, 'i'},  // CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
	{0x0458, 'j'},  // CYRILLIC SMALL LETTER JE
	{0x045B, 'h'},  // CYRILLIC SMALL LETTER TSHE
	{0x045F, 'u'},  // CYRILLIC SMALL LETTER DZHE
	{0x0461, 'w'},  // CYRILLIC SMALL LETTER OMEGA
	{0x0462, 'b'},  // CYRILLIC CAPITAL LETTER YAT
	{0x0463, 'b'},  // CYRILLIC SMALL LETTER YAT
	{0x0472, 'O'},  // CYRILLIC CAPITAL LETTER FITA
	{0x0473, 'o'},  // CYRILLIC SMALL LETTER FITA
	{0x0474, 'V'},  // CYRILLIC CAPITAL LETTER IZHITSA
	{0x0475, 'v'},  // CYRILLIC SMALL LETTER IZHITSA
	{0x047D, 'w'},  // CYRILLIC SMALL LETTER OMEGA WITH TITLO
	{0x048C, 'b'},  // CYRILLIC CAPITAL LETTER SEMISOFT SIGN
	{0x048D, 'b'},  // CYRILLIC SMALL LETTER SEMISOFT SIGN
	{0x0493, 'r'},  // CYRILLIC SMALL LETTER GHE WITH STROKE
	{0x049A, 'K'},  // CYRILLIC CAPITAL LETTER KA WITH DESCENDER
	{0x049E, 'K'},  // CYRILLIC CAPITAL LETTER KA WITH STROKE
	{0x04A2, 'H'},  // CYRILLIC CAPITAL LETTER EN WITH DESCENDER
	{0x04AA, 'C'},  // CYRILLIC CAPITAL LETTER ES WITH DESCENDER
	{0x04AB, 'c'},  // CYRILLIC SMALL LETTER ES WITH DESCENDER
	{0x04AC, 'T'},  // CYRILLIC CAPITAL LETTER TE WITH DESCENDER
	{0x04AE, 'Y'},  // CYRILLIC CAPITAL LETTER STRAIGHT U
	{0x04AF, 'y'},  // CYRILLIC SMALL LETTER STRAIGHT U
	{0x04B0, 'Y'},  // CYRILLIC CAPITAL LETTER STRAIGHT U WITH STROKE
	{0x04B1, 'y'},  // CYRILLIC SMALL LETTER STRAIGHT U WITH STROKE
	{0x04B2, 'X'},  // CYRILLIC CAPITAL LETTER HA WITH DESCENDER
	{0x04BA, 'h'},  // CYRILLIC CAPITAL LETTER SHHA
	{0x04BB, 'h'},  // CYRILLIC SMALL LETTER SHHA
	{0x04BD, 'e'},  // CYRILLIC SMALL LETTER ABKHASIAN CHE
	{0x04BF, 'e'},  // CYRILLIC SMALL LETTER ABKHASIAN CHE WITH DESCENDER
	{0x04C0, 'I'},  // CYRILLIC LETTER PALOCHKA (TR39: l)
	{0x04C7, 'H'},  // CYRILLIC CAPITAL LETTER EN WITH HOOK
	{0x04C9, 'H'},  // CYRILLIC CAPITAL LETTER EN WITH TAIL
	{0x04CD, 'M'},  // CYRILLIC CAPITAL LETTER EM WITH TAIL
	{0x04CF, 'l'},  // CYRILLIC SMALL LETTER PALOCHKA
	{0x04E8, 'O'},  // CYRILLIC CAPITAL LETTER BARRED O
	{0x04E9, 'o'},  // CYRILLIC SMALL LETTER BARRED O
	{0x0501, 'd'},  // CYRILLIC SMALL LETTER KOMI DE
	{0x050C, 'G'},  // CYRILLIC CAPITAL LETTER KOMI SJE
	{0x051A, 'Q'},  // CYRILLIC CAPITAL LETTER QA
	{0x051B, 'q'},  // CYRILLIC SMALL LETTER QA
	{0x051C, 'W'},  // CYRILLIC CAPITAL LETTER WE
	{0x051D, 'w'},  // CYRILLIC SMALL LETTER WE
	{0x054D, 'U'},  // ARMENIAN CAPITAL LETTER SEH
	{0x054F, 'S'},  // ARMENIAN CAPITAL LETTER TIWN
	{0x0555, 'O'},  // ARMENIAN CAPITAL LETTER OH
	{0x0561, 'w'},  // ARMENIAN SMALL LETTER AYB
	{0x0563, 'q'},  // ARMENIAN SMALL LETTER GIM
	{0x0566, 'q'},  // ARMENIAN SMALL LETTER ZA
	{0x0570, 'h'},  // ARMENIAN SMALL LETTER HO
	{0x0572, 'n'},  // ARMENIAN SMALL LETTER GHAD
	{0x0575, 'j'},  // ARMENIAN SMALL LETTER YI
	{0x0578, 'n'},  // ARMENIAN SMALL LETTER VO
	{0x057C, 'n'},  // ARMENIAN SMALL LETTER RA
	{0x057D, 'u'},  // ARMENIAN SMALL LETTER SEH
	{0x0581, 'g'},  // ARMENIAN SMALL LETTER CO
	{0x0582, 'i'},  // ARMENIAN SMALL LETTER YIWN
	{0x0584, 'f'},  // ARMENIAN SMALL LETTER KEH
	{0x0585, 'o'},  // ARMENIAN SMALL LETTER OH
	{0x05D5, 'l'},  // HEBREW LETTER VAV
	{0x05D8, 'v'},  // HEBREW LETTER TET
	{0x05DF, 'l'},  // HEBREW LETTER FINAL NUN
	{0x05E1, 'o'},  // HEBREW LETTER SAMEKH
	{0x0627, 'l'},  // ARABIC LETTER ALEF
	{0x0629, 'o'},  // ARABIC LETTER TAA MARBUTA (common name: misspell rejects the Unicode name)
	{0x0647, 'o'},  // ARABIC LETTER HEH
	{0x0673, 'l'},  // ARABIC LETTER ALEF WITH WAVY HAMZA BELOW
	{0x06BE, 'o'},  // ARABIC LETTER HEH DOACHASHMEE
	{0x06C1, 'o'},  // ARABIC LETTER HEH GOAL
	{0x06C3, 'o'},  // ARABIC LETTER TAA MARBUTA GOAL (common name: misspell rejects the Unicode name)
	{0x06D5, 'o'},  // ARABIC LETTER AE
	{0x06FF, 'o'},  // ARABIC LETTER HEH WITH INVERTED V
	{0x07CA, 'l'},  // NKO LETTER A
	{0x07CB, 'o'},  // NKO LETTER EE
	{0x07CC, 'Y'},  // NKO LETTER I
	{0x07D3, 'F'},  // NKO LETTER BA
	{0x07D5, 'b'},  // NKO LETTER TA
	{0x07E0, 'T'},  // NKO LETTER NA WOLOSO
	{0x0840, 'o'},  // MANDAIC LETTER HALQA
	{0x0B20, 'O'},  // ORIYA LETTER TTHA
	{0x0C02, 'o'},  // TELUGU SIGN ANUSVARA (spacing mark)
	{0x0C82, 'o'},  // KANNADA SIGN ANUSVARA (spacing mark)
	{0x0D02, 'o'},  // MALAYALAM SIGN ANUSVARA (spacing mark)
	{0x0D1F, 's'},  // MALAYALAM LETTER TTA
	{0x0D20, 'o'},  // MALAYALAM LETTER TTHA
	{0x0D82, 'o'},  // SINHALA SIGN ANUSVARAYA (spacing mark)
	{0x1004, 'c'},  // MYANMAR LETTER NGA
	{0x101D, 'o'},  // MYANMAR LETTER WA
	{0x105A, 'c'},  // MYANMAR LETTER MON NGA
	{0x10B9, 'h'},  // GEORGIAN CAPITAL LETTER CHIN
	{0x10BD, 'S'},  // GEORGIAN CAPITAL LETTER CHAR
	{0x10CD, 'Z'},  // GEORGIAN CAPITAL LETTER AEN
	{0x10E7, 'y'},  // GEORGIAN LETTER QAR
	{0x10FD, 'S'},  // GEORGIAN LETTER AEN
	{0x10FF, 'o'},  // GEORGIAN LETTER LABIAL SIGN
	{0x110B, 'o'},  // HANGUL CHOSEONG IEUNG
	{0x11BC, 'o'},  // HANGUL JONGSEONG IEUNG
	{0x1200, 'U'},  // ETHIOPIC SYLLABLE HA
	{0x12D0, 'O'},  // ETHIOPIC SYLLABLE PHARYNGEAL A
	{0x1340, 'O'},  // ETHIOPIC SYLLABLE TZA
	{0x13A0, 'D'},  // CHEROKEE LETTER A
	{0x13A1, 'R'},  // CHEROKEE LETTER E
	{0x13A2, 'T'},  // CHEROKEE LETTER I
	{0x13A4, 'O'},  // CHEROKEE LETTER U
	{0x13A5, 'i'},  // CHEROKEE LETTER V
	{0x13A9, 'Y'},  // CHEROKEE LETTER GI
	{0x13AA, 'A'},  // CHEROKEE LETTER GO
	{0x13AB, 'J'},  // CHEROKEE LETTER GU
	{0x13AC, 'E'},  // CHEROKEE LETTER GV
	{0x13B3, 'W'},  // CHEROKEE LETTER LA
	{0x13B7, 'M'},  // CHEROKEE LETTER LU
	{0x13BB, 'H'},  // CHEROKEE LETTER MI
	{0x13BD, 'Y'},  // CHEROKEE LETTER MU
	{0x13BE, 'O'},  // CHEROKEE LETTER NA
	{0x13BF, 't'},  // CHEROKEE LETTER HNA
	{0x13C0, 'G'},  // CHEROKEE LETTER NAH
	{0x13C2, 'h'},  // CHEROKEE LETTER NI
	{0x13C3, 'Z'},  // CHEROKEE LETTER NO
	{0x13CC, 'U'},  // CHEROKEE LETTER SA
	{0x13CF, 'b'},  // CHEROKEE LETTER SI
	{0x13D2, 'R'},  // CHEROKEE LETTER SV
	{0x13D4, 'W'},  // CHEROKEE LETTER TA
	{0x13D5, 'S'},  // CHEROKEE LETTER DE
	{0x13D9, 'V'},  // CHEROKEE LETTER DO
	{0x13DA, 'S'},  // CHEROKEE LETTER DU
	{0x13DE, 'L'},  // CHEROKEE LETTER TLE
	{0x13DF, 'C'},  // CHEROKEE LETTER TLI
	{0x13E2, 'P'},  // CHEROKEE LETTER TLV
	{0x13E6, 'K'},  // CHEROKEE LETTER TSO
	{0x13E7, 'd'},  // CHEROKEE LETTER TSU
	{0x13EB, 'O'},  // CHEROKEE LETTER WI
	{0x13F2, 'h'},  // CHEROKEE LETTER YO
	{0x13F3, 'G'},  // CHEROKEE LETTER YU
	{0x13F4, 'B'},  // CHEROKEE LETTER YV
	{0x142F, 'V'},  // CANADIAN SYLLABICS PE
	{0x144C, 'U'},  // CANADIAN SYLLABICS TE
	{0x146D, 'P'},  // CANADIAN SYLLABICS KI
	{0x146F, 'd'},  // CANADIAN SYLLABICS KO
	{0x1472, 'b'},  // CANADIAN SYLLABICS KA
	{0x1473, 'b'},  // CANADIAN SYLLABICS KAA
	{0x148D, 'J'},  // CANADIAN SYLLABICS CO
	{0x14AA, 'L'},  // CANADIAN SYLLABICS MA
	{0x1541, 'x'},  // CANADIAN SYLLABICS SAYISI YI
	{0x157C, 'H'},  // CANADIAN SYLLABICS NUNAVUT H
	{0x157D, 'x'},  // CANADIAN SYLLABICS HK
	{0x1587, 'R'},  // CANADIAN SYLLABICS TLHI
	{0x15AF, 'b'},  // CANADIAN SYLLABICS AIVILIK B
	{0x15B4, 'F'},  // CANADIAN SYLLABICS BLACKFOOT WE
	{0x15C5, 'A'},  // CANADIAN SYLLABICS CARRIER GHO
	{0x15DE, 'D'},  // CANADIAN SYLLABICS CARRIER THE
	{0x15EA, 'D'},  // CANADIAN SYLLABICS CARRIER PE
	{0x15F0, 'M'},  // CANADIAN SYLLABICS CARRIER GO
	{0x15F7, 'B'},  // CANADIAN SYLLABICS CARRIER KHE
	{0x16B7, 'X'},  // RUNIC LETTER GEBO GYFU G
	{0x16C1, 'l'},  // RUNIC LETTER ISAZ IS ISS I
	{0x16C5, 'l'},  // RUNIC LETTER LONG-BRANCH-AR AE
	{0x16D0, 'l'},  // RUNIC LETTER SHORT-TWIG-TYR T
	{0x16D5, 'K'},  // RUNIC LETTER OPEN-P
	{0x16D6, 'M'},  // RUNIC LETTER EHWAZ EH E
	{0x1763, 'x'},  // TAGBANWA LETTER KA
	{0x1A45, 'o'},  // TAI THAM LETTER WA
	{0x1BEA, 'o'},  // BATAK VOWEL SIGN I (spacing mark)
	{0x1BEC, 'x'},  // BATAK VOWEL SIGN O (spacing mark)
	{0x1C82, 'o'},  // CYRILLIC SMALL LETTER NARROW O
	{0x1C83, 'c'},  // CYRILLIC SMALL LETTER WIDE ES
	{0x1CBD, 'S'},  // GEORGIAN MTAVRULI CAPITAL LETTER AEN
	{0x1CBF, 'O'},  // GEORGIAN MTAVRULI CAPITAL LETTER LABIAL SIGN
	{0x1CF5, 'X'},  // VEDIC SIGN JIHVAMULIYA
	{0x1D04, 'c'},  // LATIN LETTER SMALL CAPITAL C
	{0x1D0F, 'o'},  // LATIN LETTER SMALL CAPITAL O
	{0x1D11, 'o'},  // LATIN SMALL LETTER SIDEWAYS O
	{0x1D1C, 'u'},  // LATIN LETTER SMALL CAPITAL U
	{0x1D20, 'v'},  // LATIN LETTER SMALL CAPITAL V
	{0x1D21, 'w'},  // LATIN LETTER SMALL CAPITAL W
	{0x1D22, 'z'},  // LATIN LETTER SMALL CAPITAL Z
	{0x1D26, 'r'},  // GREEK LETTER SMALL CAPITAL GAMMA
	{0x1D6E, 'f'},  // LATIN SMALL LETTER F WITH MIDDLE TILDE
	{0x1D70, 'n'},  // LATIN SMALL LETTER N WITH MIDDLE TILDE
	{0x1D72, 'r'},  // LATIN SMALL LETTER R WITH MIDDLE TILDE
	{0x1D74, 's'},  // LATIN SMALL LETTER S WITH MIDDLE TILDE
	{0x1D75, 't'},  // LATIN SMALL LETTER T WITH MIDDLE TILDE
	{0x1D76, 'z'},  // LATIN SMALL LETTER Z WITH MIDDLE TILDE
	{0x1D7B, 'i'},  // LATIN SMALL CAPITAL LETTER I WITH STROKE
	{0x1D7C, 'i'},  // LATIN SMALL LETTER IOTA WITH STROKE
	{0x1D7D, 'p'},  // LATIN SMALL LETTER P WITH STROKE
	{0x1D7E, 'u'},  // LATIN SMALL CAPITAL LETTER U WITH STROKE
	{0x1D83, 'g'},  // LATIN SMALL LETTER G WITH PALATAL HOOK
	{0x1D8C, 'y'},  // LATIN SMALL LETTER V WITH PALATAL HOOK
	{0x1E9D, 'f'},  // LATIN SMALL LETTER LONG S WITH HIGH STROKE
	{0x1EFF, 'y'},  // LATIN SMALL LETTER Y WITH LOOP
	{0x212E, 'e'},  // ESTIMATED SYMBOL
	{0x2C67, 'H'},  // LATIN CAPITAL LETTER H WITH DESCENDER
	{0x2C69, 'K'},  // LATIN CAPITAL LETTER K WITH DESCENDER
	{0x2C6B, 'Z'},  // LATIN CAPITAL LETTER Z WITH DESCENDER
	{0x2C6C, 'z'},  // LATIN SMALL LETTER Z WITH DESCENDER
	{0x2C82, 'B'},  // COPTIC CAPITAL LETTER VIDA
	{0x2C85, 'r'},  // COPTIC SMALL LETTER GAMMA
	{0x2C8C, 'Z'},  // COPTIC CAPITAL LETTER ZATA
	{0x2C8D, 'z'},  // COPTIC SMALL LETTER ZATA
	{0x2C8E, 'H'},  // COPTIC CAPITAL LETTER HATE
	{0x2C90, 'O'},  // COPTIC CAPITAL LETTER THETHE
	{0x2C91, 'o'},  // COPTIC SMALL LETTER THETHE
	{0x2C92, 'I'},  // COPTIC CAPITAL LETTER IAUDA (TR39: l)
	{0x2C93, 'i'},  // COPTIC SMALL LETTER IAUDA
	{0x2C94, 'K'},  // COPTIC CAPITAL LETTER KAPA
	{0x2C98, 'M'},  // COPTIC CAPITAL LETTER MI
	{0x2C9A, 'N'},  // COPTIC CAPITAL LETTER NI
	{0x2C9E, 'O'},  // COPTIC CAPITAL LETTER O
	{0x2C9F, 'o'},  // COPTIC SMALL LETTER O
	{0x2CA2, 'P'},  // COPTIC CAPITAL LETTER RO
	{0x2CA3, 'p'},  // COPTIC SMALL LETTER RO
	{0x2CA4, 'C'},  // COPTIC CAPITAL LETTER SIMA
	{0x2CA5, 'c'},  // COPTIC SMALL LETTER SIMA
	{0x2CA6, 'T'},  // COPTIC CAPITAL LETTER TAU
	{0x2CA8, 'Y'},  // COPTIC CAPITAL LETTER UA
	{0x2CA9, 'y'},  // COPTIC SMALL LETTER UA
	{0x2CAC, 'X'},  // COPTIC CAPITAL LETTER KHI
	{0x2CBD, 'w'},  // COPTIC SMALL LETTER CRYPTOGRAMMIC NI
	{0x2CCE, 'P'},  // COPTIC CAPITAL LETTER OLD COPTIC HA
	{0x2CCF, 'p'},  // COPTIC SMALL LETTER OLD COPTIC HA
	{0x2CD0, 'L'},  // COPTIC CAPITAL LETTER L-SHAPED HA
	{0x2D2D, 'z'},  // GEORGIAN SMALL LETTER AEN
	{0x2D31, 'O'},  // TIFINAGH LETTER YAB
	{0x2D38, 'V'},  // TIFINAGH LETTER YADH
	{0x2D39, 'E'},  // TIFINAGH LETTER YADD
	{0x2D41, 'O'},  // TIFINAGH LETTER BERBER ACADEMY YAH
	{0x2D4A, 'l'},  // TIFINAGH LETTER YAZH
	{0x2D4F, 'l'},  // TIFINAGH LETTER YAN
	{0x2D54, 'O'},  // TIFINAGH LETTER YAR
	{0x2D55, 'Q'},  // TIFINAGH LETTER YARR
	{0x2D5D, 'X'},  // TIFINAGH LETTER YATH
	{0x3112, 'T'},  // BOPOMOFO LETTER X
	{0x311A, 'Y'},  // BOPOMOFO LETTER A
	{0xA4D0, 'B'},  // LISU LETTER BA
	{0xA4D1, 'P'},  // LISU LETTER PA
	{0xA4D2, 'd'},  // LISU LETTER PHA
	{0xA4D3, 'D'},  // LISU LETTER DA
	{0xA4D4, 'T'},  // LISU LETTER TA
	{0xA4D6, 'G'},  // LISU LETTER GA
	{0xA4D7, 'K'},  // LISU LETTER KA
	{0xA4D9, 'J'},  // LISU LETTER JA
	{0xA4DA, 'C'},  // LISU LETTER CA
	{0xA4DC, 'Z'},  // LISU LETTER DZA
	{0xA4DD, 'F'},  // LISU LETTER TSA
	{0xA4DF, 'M'},  // LISU LETTER MA
	{0xA4E0, 'N'},  // LISU LETTER NA
	{0xA4E1, 'L'},  // LISU LETTER LA
	{0xA4E2, 'S'},  // LISU LETTER SA
	{0xA4E3, 'R'},  // LISU LETTER ZHA
	{0xA4E6, 'V'},  // LISU LETTER HA
	{0xA4E7, 'H'},  // LISU LETTER XA
	{0xA4EA, 'W'},  // LISU LETTER WA
	{0xA4EB, 'X'},  // LISU LETTER SHA
	{0xA4EC, 'Y'},  // LISU LETTER YA
	{0xA4EE, 'A'},  // LISU LETTER A
	{0xA4F0, 'E'},  // LISU LETTER E
	{0xA4F2, 'l'},  // LISU LETTER I
	{0xA4F3, 'O'},  // LISU LETTER O
	{0xA4F4, 'U'},  // LISU LETTER U
	{0xA50B, 'T'},  // VAI SYLLABLE GBEE
	{0xA557, 'B'},  // VAI SYLLABLE GBA
	{0xA56F, 'l'},  // VAI SYLLABLE NA
	{0xA576, 'S'},  // VAI SYLLABLE POO
	{0xA5CB, 'E'},  // VAI SYLLABLE TO
	{0xA647, 'i'},  // CYRILLIC SMALL LETTER IOTA
	{0xA68C, 'T'},  // CYRILLIC CAPITAL LETTER TWE
	{0xA695, 'h'},  // CYRILLIC SMALL LETTER HWE
	{0xA6A2, 'o'},  // BAMUM LETTER U
	{0xA6B2, 'Y'},  // BAMUM LETTER NJAEM
	{0xA6C9, 'Z'},  // BAMUM LETTER WUE
	{0xA6DF, 'V'},  // BAMUM LETTER KO
	{0xA731, 's'},  // LATIN LETTER SMALL CAPITAL S
	{0xA740, 'K'},  // LATIN CAPITAL LETTER K WITH STROKE
	{0xA74A, 'O'},  // LATIN CAPITAL LETTER O WITH LONG STROKE OVERLAY
	{0xA74B, 'o'},  // LATIN SMALL LETTER O WITH LONG STROKE OVERLAY
	{0xA761, 'w'},  // LATIN SMALL LETTER VY
	{0xA781, 'l'},  // LATIN SMALL LETTER TURNED L
	{0xA798, 'F'},  // LATIN CAPITAL LETTER F WITH STROKE
	{0xA799, 'f'},  // LATIN SMALL LETTER F WITH STROKE
	{0xA79F, 'u'},  // LATIN SMALL LETTER VOLAPUK UE
	{0xA7AE, 'I'},  // LATIN CAPITAL LETTER SMALL CAPITAL I (TR39: l)
	{0xA7B2, 'J'},  // LATIN CAPITAL LETTER J WITH CROSSED-TAIL
	{0xA7B3, 'X'},  // LATIN CAPITAL LETTER CHI
	{0xA7B4, 'B'},  // LATIN CAPITAL LETTER BETA
	{0xA7C5, 'S'},  // LATIN CAPITAL LETTER S WITH HOOK
	{0xA7FA, 'w'},  // LATIN LETTER SMALL CAPITAL TURNED M
	{0xA7FE, 'I'},  // LATIN EPIGRAPHIC LETTER I LONGA (TR39: l)
	{0xAB32, 'e'},  // LATIN SMALL LETTER BLACKLETTER E
	{0xAB35, 'f'},  // LATIN SMALL LETTER LENIS F
	{0xAB3D, 'o'},  // LATIN SMALL LETTER BLACKLETTER O
	{0xAB3E, 'o'},  // LATIN SMALL LETTER BLACKLETTER O WITH STROKE
	{0xAB47, 'r'},  // LATIN SMALL LETTER R WITHOUT HANDLE
	{0xAB48, 'r'},  // LATIN SMALL LETTER DOUBLE R
	{0xAB4E, 'u'},  // LATIN SMALL LETTER U WITH SHORT RIGHT LEG
	{0xAB52, 'u'},  // LATIN SMALL LETTER U WITH LEFT HOOK
	{0xAB5A, 'y'},  // LATIN SMALL LETTER Y WITH SHORT RIGHT LEG
	{0xAB64, 'a'},  // LATIN SMALL LETTER INVERTED ALPHA
	{0xAB74, 'o'},  // CHEROKEE SMALL LETTER U
	{0xAB75, 'i'},  // CHEROKEE SMALL LETTER V
	{0xAB81, 'r'},  // CHEROKEE SMALL LETTER HU
	{0xAB83, 'w'},  // CHEROKEE SMALL LETTER LA
	{0xAB8E, 'o'},  // CHEROKEE SMALL LETTER NA
	{0xAB93, 'z'},  // CHEROKEE SMALL LETTER NO
	{0xAB9C, 'u'},  // CHEROKEE SMALL LETTER SA
	{0xABA4, 'w'},  // CHEROKEE SMALL LETTER TA
	{0xABA9, 'v'},  // CHEROKEE SMALL LETTER DO
	{0xABAA, 's'},  // CHEROKEE SMALL LETTER DU
	{0xABAF, 'c'},  // CHEROKEE SMALL LETTER TLI
	{0xABBB, 'o'},  // CHEROKEE SMALL LETTER WI
	{0x10282, 'B'}, // LYCIAN LETTER B
	{0x10286, 'E'}, // LYCIAN LETTER I
	{0x10287, 'F'}, // LYCIAN LETTER W
	{0x1028A, 'l'}, // LYCIAN LETTER J
	{0x10290, 'X'}, // LYCIAN LETTER MM
	{0x10292, 'O'}, // LYCIAN LETTER U
	{0x10295, 'P'}, // LYCIAN LETTER R
	{0x10296, 'S'}, // LYCIAN LETTER S
	{0x10297, 'T'}, // LYCIAN LETTER T
	{0x102A0, 'A'}, // CARIAN LETTER A
	{0x102A1, 'B'}, // CARIAN LETTER P2
	{0x102A2, 'C'}, // CARIAN LETTER D
	{0x102A5, 'F'}, // CARIAN LETTER R
	{0x102AB, 'O'}, // CARIAN LETTER O
	{0x102B0, 'M'}, // CARIAN LETTER S
	{0x102B1, 'T'}, // CARIAN LETTER C-18
	{0x102B2, 'Y'}, // CARIAN LETTER U
	{0x102B4, 'X'}, // CARIAN LETTER X
	{0x102CF, 'H'}, // CARIAN LETTER E2
	{0x10301, 'B'}, // OLD ITALIC LETTER BE
	{0x10302, 'C'}, // OLD ITALIC LETTER KE
	{0x10309, 'l'}, // OLD ITALIC LETTER I
	{0x1030F, 'O'}, // OLD ITALIC LETTER O
	{0x10311, 'M'}, // OLD ITALIC LETTER SHE
	{0x10315, 'T'}, // OLD ITALIC LETTER TE
	{0x10317, 'X'}, // OLD ITALIC LETTER EKS
	{0x1031C, 'b'}, // OLD ITALIC LETTER CHE
	{0x10404, 'O'}, // DESERET CAPITAL LETTER LONG O
	{0x10415, 'C'}, // DESERET CAPITAL LETTER CHEE
	{0x1041B, 'L'}, // DESERET CAPITAL LETTER ETH
	{0x10420, 'S'}, // DESERET CAPITAL LETTER ZHEE
	{0x1042C, 'o'}, // DESERET SMALL LETTER LONG O
	{0x1043D, 'c'}, // DESERET SMALL LETTER CHEE
	{0x10448, 's'}, // DESERET SMALL LETTER ZHEE
	{0x104B4, 'R'}, // OSAGE CAPITAL LETTER BRA
	{0x104C2, 'O'}, // OSAGE CAPITAL LETTER O
	{0x104CE, 'U'}, // OSAGE CAPITAL LETTER U
	{0x104EA, 'o'}, // OSAGE SMALL LETTER O
	{0x104F6, 'u'}, // OSAGE SMALL LETTER U
	{0x10507, 'Z'}, // ELBASAN LETTER EI
	{0x1050E, 'l'}, // ELBASAN LETTER JE
	{0x10513, 'N'}, // ELBASAN LETTER NE
	{0x10516, 'O'}, // ELBASAN LETTER O
	{0x10518, 'K'}, // ELBASAN LETTER QE
	{0x1051B, 'C'}, // ELBASAN LETTER SE
	{0x1051D, 'V'}, // ELBASAN LETTER TE
	{0x1051E, 'O'}, // ELBASAN LETTER THE
	{0x10525, 'F'}, // ELBASAN LETTER GHE
	{0x10526, 'L'}, // ELBASAN LETTER GHAMMA
	{0x10527, 'X'}, // ELBASAN LETTER KHE
	{0x10926, 'l'}, // LYDIAN LETTER I
	{0x1092C, 'o'}, // LYDIAN LETTER O
	{0x10C13, 'X'}, // OLD TURKIC LETTER ORKHON AED
	{0x10C17, 'O'}, // OLD TURKIC LETTER YENISEI AY
	{0x10C1F, 'V'}, // OLD TURKIC LETTER YENISEI AL
	{0x10C20, 'Y'}, // OLD TURKIC LETTER ORKHON AEL
	{0x10C21, 'M'}, // OLD TURKIC LETTER ORKHON ELT
	{0x10C3E, 'l'}, // OLD TURKIC LETTER ORKHON AES
	{0x10C82, 'X'}, // OLD HUNGARIAN CAPITAL LETTER EB
	{0x10CA5, 'I'}, // OLD HUNGARIAN CAPITAL LETTER ESZ (TR39: l)
	{0x10CC2, 'x'}, // OLD HUNGARIAN SMALL LETTER EB
	{0x10D07, 'o'}, // HANIFI ROHINGYA LETTER HA
	{0x11124, 'o'}, // CHAKMA LETTER WAA
	{0x11302, 'o'}, // GRANTHA SIGN ANUSVARA (spacing mark)
	{0x114C5, 'w'}, // TIRHUTA GVANG
	{0x11706, 'v'}, // AHOM LETTER PA
	{0x1170A, 'w'}, // AHOM LETTER JA
	{0x1170E, 'w'}, // AHOM LETTER LA
	{0x1170F, 'w'}, // AHOM LETTER SA
	{0x118A0, 'V'}, // WARANG CITI CAPITAL LETTER NGAA
	{0x118A2, 'F'}, // WARANG CITI CAPITAL LETTER WI
	{0x118A3, 'L'}, // WARANG CITI CAPITAL LETTER YU
	{0x118A4, 'Y'}, // WARANG CITI CAPITAL LETTER YA
	{0x118A6, 'E'}, // WARANG CITI CAPITAL LETTER II
	{0x118A9, 'Z'}, // WARANG CITI CAPITAL LETTER O
	{0x118AE, 'E'}, // WARANG CITI CAPITAL LETTER YUJ
	{0x118B2, 'L'}, // WARANG CITI CAPITAL LETTER TTE
	{0x118B5, 'O'}, // WARANG CITI CAPITAL LETTER AT
	{0x118B8, 'U'}, // WARANG CITI CAPITAL LETTER PU
	{0x118BC, 'T'}, // WARANG CITI CAPITAL LETTER HAR
	{0x118C0, 'v'}, // WARANG CITI SMALL LETTER NGAA
	{0x118C1, 's'}, // WARANG CITI SMALL LETTER A
	{0x118C2, 'F'}, // WARANG CITI SMALL LETTER WI
	{0x118C3, 'i'}, // WARANG CITI SMALL LETTER YU
	{0x118C4, 'y'}, // WARANG CITI SMALL LETTER YA
	{0x118C8, 'o'}, // WARANG CITI SMALL LETTER E
	{0x118D7, 'o'}, // WARANG CITI SMALL LETTER BU
	{0x118D8, 'u'}, // WARANG CITI SMALL LETTER PU
	{0x118DC, 'y'}, // WARANG CITI SMALL LETTER HAR
	{0x11ABC, 'Z'}, // CANADIAN SYLLABICS SPE
	{0x11ABE, 'N'}, // CANADIAN SYLLABICS SPO
	{0x11DDA, 'l'}, // TOLONG SIKI SIGN HECAKA
	{0x1699B, 'O'}, // BAMUM LETTER PHASE-E SUAEN
	{0x16A19, 'r'}, // BAMUM LETTER PHASE-F NU
	{0x16AD6, 'S'}, // BASSA VAH LETTER GAH
	{0x16AE4, 'l'}, // BASSA VAH LETTER YEIN
	{0x16AE9, 'O'}, // BASSA VAH LETTER OO
	{0x16D63, 'l'}, // KIRAT RAI VOWEL SIGN AA
	{0x16EAA, 'I'}, // BERIA ERFE CAPITAL LETTER LAKKO (TR39: l)
	{0x16EB6, 'b'}, // BERIA ERFE CAPITAL LETTER UI
	{0x16F08, 'V'}, // MIAO LETTER VA
	{0x16F0A, 'T'}, // MIAO LETTER TA
	{0x16F16, 'L'}, // MIAO LETTER LA
	{0x16F28, 'l'}, // MIAO LETTER GHA
	{0x16F35, 'R'}, // MIAO LETTER ZHA
	{0x16F3A, 'S'}, // MIAO LETTER SA
	{0x16F40, 'A'}, // MIAO LETTER ZZYA
	{0x16F42, 'U'}, // MIAO LETTER WA
	{0x16F43, 'Y'}, // MIAO LETTER AH
}

// skeletonOf returns the ASCII letter that r looks like, and true, when r
// is in skeletonTable. It returns false for every other rune, also for every
// ASCII rune. The range check comes first, so most runes of a text (ASCII,
// and the accented Latin letters below U+00D0, the first entry) cost no
// binary search. The search is written by hand, as in scriptOf: with
// slices.BinarySearchFunc, skeleton took 160 ms instead of 57 ms on 10 MB of
// Cyrillic text (Apple M1 Pro, go1.27.3), because the comparison function is
// not inlined.
func skeletonOf(r rune) (byte, bool) {
	if r < skeletonTable[0].from || r > skeletonTable[len(skeletonTable)-1].from {
		return 0, false
	}
	lo, hi := 0, len(skeletonTable)
	for lo < hi {
		mid := int(uint(lo+hi) >> 1) // the shift halves the sum with no overflow
		if skeletonTable[mid].from < r {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo < len(skeletonTable) && skeletonTable[lo].from == r {
		return skeletonTable[lo].to, true
	}
	return 0, false
}

// skeleton returns s with each rune of skeletonTable replaced by its ASCII
// letter. Every other rune, and each invalid byte, stays as it is.
//
// The result is never longer than s, in bytes: every source rune is not
// ASCII, so it is 2 to 4 bytes long in UTF-8, and its target is 1 byte. So
// the skeleton cannot push a payload out of the MaxMatchInputBytes window,
// as foldMarks cannot.
//
// When no rune of s maps, skeleton returns s itself, with no copy. A text
// that is only ASCII returns at once.
func skeleton(s string) string {
	if isASCII(s) {
		return s
	}
	first := -1 // the byte offset of the first rune that maps
	for i, r := range s {
		if r < utf8.RuneSelf { // ASCII never maps
			continue
		}
		if _, ok := skeletonOf(r); ok {
			first = i
			break
		}
	}
	if first < 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s)) // the result is never longer than s
	b.WriteString(s[:first])
	for i := first; i < len(s); {
		if s[i] < utf8.RuneSelf { // ASCII never maps
			b.WriteByte(s[i])
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if c, ok := skeletonOf(r); ok {
			b.WriteByte(c)
		} else {
			b.WriteString(s[i : i+size]) // keeps an invalid byte as it is
		}
		i += size
	}
	return b.String()
}

// foldSkeleton returns the regex fold of s, a base form of baseFormsCut: the
// fold of foldMarks with the skeleton applied before it and after it. So
// "~/." + U+0455 U+0455 U+04BB becomes "~/.ssh".
//
// foldSkeleton is the definition of this fold. The matchers call skeletonFold
// (see prepare.go), which gives the same result and runs foldMarks once less.
// The tests and the fuzz tests check that the two agree, so only they call
// foldSkeleton.
//
// The skeleton runs twice, because each pass maps runes that the other
// cannot see:
//
//   - The first pass runs before foldMarks, which drops every mark and
//     changes a few letters. It maps the spacing marks of skeletonTable,
//     such as Telugu U+0C02 ("o"), and U+03F2 and U+03F9 (lunate sigma, "c"
//     and "C"), whose fold is another Greek letter.
//   - The second pass runs after foldMarks. It maps a letter whose fold is
//     a letter of skeletonTable: U+03AC (alpha with tonos) folds to U+03B1
//     and becomes "a", and U+1D6C2 (mathematical bold alpha) too.
//
// A rune maps to ASCII in one pass at most, and an ASCII rune never maps,
// so the order of the passes does not change the result of the other
// runes. Neither pass, nor foldMarks, makes the text longer, so the result
// is never longer than s and at most MaxMatchInputBytes long.
func foldSkeleton(s string) string {
	return skeleton(foldMarks(skeleton(s)))
}
