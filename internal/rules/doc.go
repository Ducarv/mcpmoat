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
// are the zero-width, bidi, tag and other format characters, and the control
// characters (such as U+0000, U+0001 and DEL) other than the white space
// (tab, LF, VT, FF, CR and NEL) and the runes that change how an ANSI escape
// sequence is read (ESC, BEL, CAN, SUB and the C1 controls U+009B, U+009C and
// U+009D). So "Ig" + U+0001 + "nore" is "Ignore". Each white-space or
// control rune that is left and that the regex \s does not match (VT, NEL,
// the no-break space and the other Unicode spaces, U+2028, U+2029, the
// Braille blank U+2800, and an ESC that does not start an escape sequence)
// becomes U+0020, so a regex sees it as a space and cannot match the rune
// itself. An ANSI escape sequence (CSI or OSC), which a terminal runs and
// does not show, also becomes one space. The control characters are removed
// only after this step, so they cannot make an escape sequence: ESC [ U+0001
// "Ignore" keeps its "I".
//
// When the text holds invisible runes, it is also matched in a second form
// where each run of invisible runes is one space. When one of them is a
// control character, it is also matched in a third form, where the other
// invisible runes are removed and each control character is one space. So an
// invisible rune cannot split a word (the first form) or the space between
// two words (the second form), and "Ig" + ZWSP + "nore" + U+0001 + "all" +
// U+0001 + "previous" still matches (the third form).
//
// A text that uses one kind of invisible rune both inside a word and between
// words can still defeat a regex. Also, a raw ESC before a letter can make
// the letter the final byte of a CSI, so ANSI text before a word can hide its
// first letter from a regex. In a description, the invisible_unicode
// heuristic flags such a text: it flags the invisible runes and the ESC.
//
// A regex reads this normalized text, and also a folded form of it: the text
// is put in the compatibility form NFKC and loses its combining marks
// (category M). The pattern is not folded. So a regex such as `ignore` also
// matches fullwidth and mathematical letters ("ignore" in U+FF49 ... or in
// U+1D422 ...) and a word with a mark in it ("ig" + U+0336 + "nore"). A rune
// is folded only when its fold is not longer than the rune, so the folded
// form is never longer than the text: a ligature that folds to many letters,
// such as U+FDFA, stays as it is and cannot push a payload out of the 32 KiB.
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
// normalization removes, so it also flags a control character such as U+0000
// or DEL. It also flags the runes that the normalization keeps to read an
// ANSI escape sequence. So it flags every control character except the white
// space.
//
// The base64_blob heuristic checks each run of base64 characters on its own.
// An invisible rune inside a run, also a control character such as U+0000, is
// skipped. Any other character, such as a space, a newline or '=', ends a
// run, and runs are not joined. So a payload that is split into short chunks
// is not flagged when no chunk reaches min_length on its own.
//
// The config heuristics (insecure_url, plaintext_secret, unpinned_package,
// auto_install and typosquat) read one line of text each, not the whole text.
// Only a rule with target: config may use them (Validate checks this). The
// built-in config rules use them on the lines of their test cases.
// insecure_url reads a URL. plaintext_secret reads a KEY=VALUE or "Name:
// value" entry. unpinned_package and auto_install read a command line.
// typosquat reads a command line or a bare package name. An adapter in this
// package turns the line into a server and runs the native config check on
// it. A hit from a config heuristic has the offset -1.
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
