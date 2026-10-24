// Package rules loads YAML detection rules (embedded and external) and applies
// regex matchers and native heuristics to tool descriptions, schemas and
// server configs.
//
// See docs/PRD.md, FR-07 to FR-10.
//
// # The match block
//
// Each rule has a `match:` block, the type [Match]. It holds exactly one of
// any_regex, all_regex, keywords or heuristic. [Match.Compile] checks it and
// returns a [Matcher]. The loader calls it at load time through a [Compiler]
// given with [WithCompiler].
// Every error from Compile is a *[FieldError] that names the field, for
// example "any_regex[2]". An error never holds text from the rule file (a
// pattern, a keyword or a parameter key) or input text, so it is safe to
// print.
//
// # Cost bounds
//
// Rule files from --rules and the text from MCP servers are untrusted, so
// each match has a cost bound. Go's regexp package runs in linear time but has
// no timeout. The cost of one regex is about the input bytes times the
// program size.
//
// The regex and keyword matchers read at most [MaxMatchInputBytes] (32 KiB)
// of a text. The invisible runes are dropped from the first 128 KiB of the
// raw text before this cut, so invisible padding does not use up the 32 KiB.
// This is an evasion window: instructions placed after the first 32 KiB of
// visible text (or after the first 128 KiB of raw text) are not seen by regex
// and keyword rules. The max_length heuristic flags such a long text, because
// it and the other text heuristics read the full raw text.
//
// A list holds at most [MaxPatterns] entries of at most [MaxPatternBytes]
// bytes each, and the compiled programs of one regex and of one list have
// instruction caps. The comment on these caps in match.go gives the worst
// case for one match block and its cost, measured by
// BenchmarkWorstCaseBlock. A hostile --rules directory multiplies this cost
// by the number of rules and texts. A cap at the loader level is future work
// (#33).
//
// # Normalization
//
// Before regex and keyword matching, the text is normalized: invisible runes
// are removed, and the text is put in Unicode form NFC. The invisible runes
// are the zero-width, bidi, tag and other format characters, and every
// control character (such as U+0000, U+0001, ESC, BEL and DEL) other than
// the white space (tab, LF, VT, FF, CR and NEL). So "Ig" + U+0001 + "nore"
// and "Ig" + BEL + "nore" are "Ignore". An ANSI escape sequence (CSI or OSC),
// which a terminal runs and does not show, becomes one space. The control
// characters are removed only after this step, so the step still sees the
// ESC, BEL, CAN, SUB and C1 controls that start, end or cancel a sequence,
// and a removed control character cannot join the parts of a sequence: ESC [
// U+0001 "Ignore" keeps its "I". Each white-space rune that the regex \s
// does not match (VT, NEL, the no-break space and the other Unicode spaces,
// U+2028, U+2029 and the Braille blank U+2800) becomes U+0020, so a regex
// sees it as a space and cannot match the rune itself.
//
// When the text holds invisible runes, it is also matched in a second form
// where each run of invisible runes is one space (or two, when the run has a
// control character and ends with a format character). When one of them is a
// control character, it is also matched in a third form, where the other
// invisible runes are removed and each run of control characters is one
// space. So an invisible rune cannot split a word (the first form) or the
// space between two words (the second form), and "Ig" + ZWSP + "nore" +
// U+0001 + "all" + U+0001 + "previous" still matches (the third form).
//
// A text that uses one kind of invisible rune both inside a word and between
// words can still defeat a regex, and so can a text with a control character
// inside a word and a format character (such as ZWSP) between words. Also, a
// raw ESC before a letter can make the letter the final byte of a CSI, so
// ANSI text before a word can hide its first letter from a regex, and a
// terminal still runs a CSI with a control character inside it (ESC [ U+0001
// 8 m), which the normalization does not find. A format character after
// ESC or U+009B can also defeat a regex (ESC + ZWSP + "[8mIgnore" + ZWSP +
// "all"): one form keeps "[8m" before the word, and the other forms join the
// words. In a description, the invisible_unicode heuristic flags such a
// text: it flags the invisible runes and the ESC.
//
// A regex reads this normalized text, and also a folded form of it. The text
// is folded one rune at a time: the rune is split into its compatibility
// parts (NFKD), its combining marks (category M) are dropped, and the rest is
// joined again (NFKC). The pattern is not folded. So a regex such as `ignore`
// also matches fullwidth and mathematical letters ("ignore" in U+FF49 ... or
// in U+1D422 ...) and a word with a mark in it ("ig" + U+0336 + "nore"). A
// fold that is longer than the rune is not used, so the folded form is never
// longer than the text: a ligature that folds to many letters, such as
// U+FDFA, stays as it is and cannot push a payload out of the 32 KiB.
// A text that is only ASCII has no folded form. A rule matches when it
// matches in one form, and each regex of an all_regex list can match in a
// different form. So a regex reads up to six forms of a text, and a keyword
// up to three: such a text costs up to six times as much to match.
//
// A regex cannot match an invisible rune (use the invisible_unicode heuristic
// for that), and a pattern must be written in NFC: a pattern with a letter
// and a separate combining mark does not match the composed letter. The
// should_match cases of a rule (NFR-05) catch such a pattern.
//
// Keywords are normalized in the same way, but for keywords both the keyword
// and the text are folded, and only the folded forms are matched. So a mark
// cannot hide a keyword, fullwidth and mathematical letters match the plain
// letters, and accents are folded: "cafe" matches "caf" + U+00E9. Homoglyphs
// from other scripts (for example Cyrillic U+0430 for Latin "a") are not
// folded, for regexes or keywords. Instead, the mixed_script heuristic (rules
// MOAT-T1-010 and MOAT-T1-011) flags a word that mixes letters of two or
// more look-alike scripts, such as Latin and Cyrillic, except a Greek unit
// letter after a number. See the Heuristics and hits section for details.
//
// Any run of white space, or U+2800 (braille blank), matches the space
// between the words of a keyword. Punctuation does not: the keyword "ignore
// previous" does not match "ignore-previous"; write a regex for such
// variants. A keyword matches without regard to case, and only as a whole
// word, with Unicode word edges. A keyword is compiled to a regex, so a very
// long keyword can fail the instruction cap. A regex gets no automatic (?i):
// write it in the pattern when you need it.
//
// # Heuristics and hits
//
// The text heuristics (invisible_unicode, max_length, base64_blob and
// mixed_script) read the raw text, not the normalized text. A [Hit] from a
// text heuristic gives a byte offset in the raw text. A hit from a regex or a
// keyword has the offset -1, because it comes from the normalized text.
//
// The invisible_unicode heuristic flags the same invisible runes that the
// normalization removes, so it flags every control character except the
// white space, such as U+0000, ESC and DEL.
//
// The base64_blob heuristic checks each run of base64 characters on its own.
// An invisible rune inside a run, also a control character such as U+0000 or
// ESC, is skipped. Any other character, such as a space, a newline or '=',
// ends a run, and runs are not joined. So a payload that is split into short
// chunks is not flagged when no chunk reaches min_length on its own.
//
// The mixed_script heuristic flags a word that mixes letters of two or more
// look-alike scripts, such as "Ignore" with a Cyrillic "I" (U+0406). The
// look-alike scripts are Latin, Cyrillic, Greek, Armenian, Cherokee, Lisu,
// Coptic, Canadian Aboriginal and Tifinagh. So a word with no Latin letter
// is flagged too when it mixes two of them, such as Cyrillic and Armenian
// letters that read as "ignore". Only Greek has an exemption, for a unit (see
// below). The heuristic reads the full raw text. A hit gives the raw byte
// offset of the first rune of the word and names the scripts in the order of
// the list above, but it never holds the word: the terminal-safe output does
// not change look-alike letters, so the word would show as normal Latin
// text.
//
// A word is a run of letters, marks, invisible runes, private-use runes and
// unassigned code points. So a ZWSP, a combining mark or a private-use rune
// (such as U+E000, which many fonts draw as nothing) cannot split a word. Any
// other rune, such as a digit, '_', '-', a space or punctuation, ends a word.
//
// Each letter counts for its own script. So Armenian small oh (U+0585) and
// Lisu letter ga (U+A4D6) count for their scripts. A letter of the Common or
// Inherited script counts by its fold, the same fold that the regexes read.
// So the mathematical Greek letters (U+1D6A8 to U+1D7CB) and the
// double-struck Greek letters (U+213C to U+213F) count as Greek, the
// mathematical Latin letters (such as U+1D400) count as Latin, and U+00B5
// (micro sign) counts as Greek mu. A letter of any other script, such as
// Han, counts for no script.
//
// The heuristic decodes JSON escapes: \b, \f, \n, \r, \t, \\, \", \/ and \u
// plus exactly 4 hex digits. A surrogate pair is one rune, and a lone
// surrogate is U+FFFD. The decoded rune acts like a raw rune: a letter, a
// mark or an invisible rune joins the word, and any other rune ends it. So
// the escape of U+0406 is a Cyrillic letter in the word, and rule
// MOAT-T1-011 can use the same heuristic on the raw JSON of a schema. The
// decoding also runs on description text, so a backslash and a "t" in a
// description read as a tab.
//
// A word with Greek letters is not flagged for them when it is a unit after
// a number. The word must have exactly one Greek letter at its start or end,
// up to 3 Latin letters and no other letter, and the two parts must form a
// unit:
//
//   - mu (U+03BC or U+00B5) and then an SI unit: s, m, g, l, L, A, V, W, F,
//     H, C, J, K, M, N, S, T, Hz, Pa, mol or sec;
//   - k, M, G or m and then Omega (U+03A9 or the ohm sign U+2126);
//   - Omega and then m or cm (ohm metre).
//
// The word must come directly after an ASCII digit, or after one space that
// comes directly after an ASCII digit. An escaped digit, such as \u0035,
// does not count. So "5" + U+03BC + "s", "5 " + U+03BC + "mol" and "10k" +
// U+03A9 are not flagged. But U+03BC + "s" with no number before it, "2 " +
// U+03BC + "ser" and "5" + U+03BC + "pdate" are flagged. Math notation is
// also flagged: U+0394 (capital Delta) + "t" gives a known false positive.
// To accept such a word, ignore the rule (MOAT-T1-010 or MOAT-T1-011) for
// that one tool in .mcpmoat-ignore.
//
// The mixed_script heuristic does not flag:
//
//   - a word written fully in look-alikes of one script, such as Cyrillic
//     "copy" (U+0441 U+043E U+0440 U+0443) or the Cyrillic "ssh" in "~/." +
//     U+0455 U+0455 U+04BB;
//   - a word of one letter, because it cannot mix two scripts;
//   - Latin-script look-alikes that do not fold, such as U+0131 (dotless i),
//     U+01C0 (dental click) and U+0261 (script g);
//   - look-alikes from scripts outside the list, such as the Ethiopic
//     syllable U+12D0, which looks like an "O", and the Runic letter U+16C1,
//     which looks like an "I";
//   - a word that a visible rune other than a letter splits in two, such as
//     U+FFFD from an invalid UTF-8 byte, U+2800 (braille blank) or U+212E
//     (estimated sign, a symbol that looks like an "e").
//
// The config heuristics (insecure_url, plaintext_secret, unpinned_package,
// auto_install and typosquat) read one line of text each, not the whole text.
// Only a rule with target: config may use them (Validate checks this). The
// built-in config rules use them on the lines of their test cases.
// insecure_url reads a URL. plaintext_secret reads an env entry
// ("KEY=VALUE"), a header entry ("Name: value"), a URL or a command line (the
// args of a stdio server). It reports a literal secret in env values, header
// values, command args and URLs. It never reports the value. unpinned_package
// and auto_install read a command line. unpinned_package also covers git and
// GitHub shorthand package specs, unless the spec is pinned to a full 40-hex
// commit, and tarball, URL and "pipx run" script specs, which are always
// unpinned (an https URL of a repository on a known git host counts as a git
// spec). typosquat reads a command line or a bare package name. An adapter in
// this package turns the line into a server and runs the native config check
// on it. A hit from a config heuristic has the offset -1.
//
// # Schema text
//
// The text of a tool schema (InputSchema or OutputSchema) is the value of
// every "description" and "title" string, at any depth, in document order.
// The keys match in any case. The rules do not model JSON Schema keywords.
// JSON escapes are decoded first, before any normalization or fold, so an
// invisible rune written as \u200b cannot hide as literal text. The read is
// bounded by the depth and value caps of the inspect package, so a schema
// that inspect accepts is read in full.
//
// The shadowing check (MOAT-T3-001) scans this text, together with the tool
// description, the tool title and the annotations title. A rule with target:
// schema does not read this text. It reads the raw JSON of the input schema,
// so property names and enum values are checked too (see MOAT-T1-009 and
// MOAT-T1-011).
//
// # The ignore file
//
// The file .mcpmoat-ignore ([IgnoreFileName]) in the working directory lists
// findings to ignore, one on each line: RULE-ID [server[/tool]]. A '#' starts
// a comment. See [ParseIgnore] for the full format.
//
// The file is untrusted, because a cloned repository can ship one. So
// [ParseIgnore] never fails: it skips a malformed line with a warning, caps
// what it keeps, and its warnings never show content of the file.
package rules
