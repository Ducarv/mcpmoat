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
// case for one match block and its cost. A text has up to twelve forms (see
// Normalization below). BenchmarkWorstCaseBlock measures that cost on a text
// with all twelve forms: about 9.0 s on an Apple M1 Pro (see match.go). A
// hostile --rules directory multiplies this cost by the number of rules and
// texts. A cap at the loader level is future work (#33).
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
// ESC, BEL, CAN, SUB and C1 controls that start, end or cancel a sequence.
// CAN and SUB cancel a sequence, so ESC [ CAN "Ignore" is not a CSI. Each
// white-space rune that the regex \s does not match (VT, NEL, the no-break
// space and the other Unicode spaces, U+2028, U+2029 and the Braille blank
// U+2800) becomes U+0020, so a regex sees it as a space and cannot match the
// rune itself.
//
// As in a terminal, a CSI can also hold C0 control characters (U+0000 to
// U+001F and DEL, but not CAN, SUB and ESC) between ESC and "[" and among
// its parameter and intermediate bytes: for a terminal, ESC [ U+0001 8 m is
// one CSI. The forms 1 to 3 below do not read such a CSI as a sequence, and
// the forms 4 to 6 do. A C0 character lets a CSI take text: ESC [ LF
// "<IMPORTANT>" is the CSI ESC [ LF < I and the text "MPORTANT>". So the
// forms 1 to 3 keep "<IMPORTANT>", and the forms 4 to 6 only add matches.
//
// A text gives up to six base forms. The first form is always built. Each
// other form is built only when the first 128 KiB of the raw text hold the
// runes that it needs. Equal forms are kept only once.
//
//  1. Always: the invisible runes are removed, so an invisible rune cannot
//     split a word: "ign" + ZWSP + "ore" is "ignore".
//  2. When the text holds an invisible rune: each run of invisible runes is
//     one space, so an invisible rune cannot take the place of the space
//     between two words: "ignore" + ZWSP + "previous" is "ignore previous".
//  3. When the text holds an invisible control character: the format
//     characters (such as ZWSP) are removed, and each run of control
//     characters is one space. So "Ig" + ZWSP + "nore" + U+0001 + "all" is
//     "Ignore all".
//  4. When the text holds an invisible control character and a format
//     character: the control characters are removed, and each run that holds
//     a format character is one space. A run of only control characters
//     gives no space. So "Ig" + U+0001 + "nore" + ZWSP + "all" is "Ignore
//     all". When the last control character of a run is ESC, U+009B or
//     U+009D, the space goes before the run, so the sequence that it starts
//     is still found: ESC + ZWSP + "[8mIgnore" + ZWSP + "all" is "  Ignore
//     all".
//  5. When the text holds ESC, U+009B (CSI) or U+009D (OSC), or the JSON
//     text \u001b or \u001B: as the sixth form, but a sequence keeps the text
//     that it takes. A raw ESC before a letter can make the letter the final
//     byte of a CSI, as for a terminal: ESC [ "Ignore" is the CSI ESC [ I and
//     the text "gnore". In this form, a CSI whose final byte is an ASCII
//     letter other than "m" becomes a space and that letter, so
//     ESC [ "Ignore" is " Ignore". A CSI with the final byte "m" is SGR
//     (colour and bold), so it becomes one space: ESC [ 1 m "iPhone" is
//     " iPhone", not " miPhone", which looks like a camelCase tool name. An
//     OSC, which a terminal does not show but a model reads, becomes its
//     text between two spaces: ESC ] "Ignore all" BEL is " Ignore all ".
//     So this form shows the OSC text, such as a window title or the URL of
//     a link, and a rule can match it: ESC ] "0;~/.ssh" BEL "Lists files."
//     is a MOAT-T1-004 hit.
//  6. When the text holds ESC or U+009B and a C0 control character that can
//     stand inside a CSI (also TAB, LF and CR): as the first form, but a CSI
//     can hold C0 control characters, and each sequence becomes one space.
//     So ESC + U+0001 + "[8mIgnore" is " Ignore". The first form keeps
//     "[8mIgnore", with no word edge before "Ignore".
//
// A text without invisible runes and escape sequences has one form, so it
// costs no more.
//
// These texts still defeat all the forms. In a description, the
// invisible_unicode heuristic flags each of them, because it flags the
// invisible runes and the ESC:
//
//   - one kind of invisible rune both inside a word and between words, such
//     as a ZWSP in both places, or U+0001 in both places;
//   - a CSI that takes a letter together with a format character between
//     words: in ESC [ "Ignore" + ZWSP + "all", the fifth form removes the
//     ZWSP, so it joins "Ignoreall", and the other forms lose the "I";
//   - a control character between ESC (or U+009B, U+009D) and a format
//     character: the fourth form looks only at the last control character of
//     a run. So in ESC + U+0001 + ZWSP + "[8mIgnore" + ZWSP + "all", the
//     fourth form keeps "[8m" before "Ignore", and the other forms join
//     "Ignoreall";
//   - a payload that only the fifth form shows, after more than 32 KiB of
//     text that the fifth form keeps from escape sequences (OSC text and CSI
//     letters). The max_length heuristic flags such a long text;
//   - a CSI with the final byte "m" that takes the "m" of a word:
//     ESC [ 1 "make" is the CSI ESC [ 1 m and the text "ake", and no form
//     gives the "m" back.
//
// An OSC with more than 256 runes of text is not a sequence for any form. So
// its ESC and its end are removed, and its text stays in every form, where
// the regexes and keywords read it.
//
// A regex reads these base forms, and also a folded form of each. The text
// is folded one rune at a time: the rune is split into its compatibility
// parts (NFKD), its combining marks (category M) are dropped, and the rest is
// joined again (NFKC). The pattern is not folded. So a regex such as `ignore`
// also matches fullwidth and mathematical letters ("ignore" in U+FF49 ... or
// in U+1D422 ...) and a word with a mark in it ("ig" + U+0336 + "nore"). A
// fold that is longer than the rune is not used, so the folded form is never
// longer than the text: a ligature that folds to many letters, such as
// U+FDFA, stays as it is and cannot push a payload out of the 32 KiB.
// A form that is only ASCII is its own fold, so it adds no folded form. A
// rule matches when it matches in one form, and each regex of an all_regex
// list can match in a different form. So a regex reads up to twelve forms of
// a text (the six base forms and their folds), and a keyword up to six (the
// folds of the base forms): such a text costs up to twelve times as much to
// match. The forms are built only when a regex or keyword matcher reads the
// text, and only once for each match: a heuristic reads only the raw text.
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
// folded, for regexes or keywords.
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
// The text heuristics (invisible_unicode, max_length and base64_blob) read the
// raw text, not the normalized text. A [Hit] from a text heuristic gives a byte
// offset in the raw text. A hit from a regex or a keyword has the offset -1,
// because it comes from the normalized text.
//
// The invisible_unicode heuristic flags the same invisible runes that the
// normalization removes, so it flags every control character except the
// white space, such as U+0000, ESC and DEL.
//
// The base64_blob heuristic checks each run of base64 characters on its own.
// An invisible rune inside a run, also a control character such as U+0000 or
// ESC, is skipped. Any other character, such as a space, a newline or '=', ends a
// run, and runs are not joined. So a payload that is split into short chunks
// is not flagged when no chunk reaches min_length on its own.
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
// description, the tool title and the annotations title.
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
