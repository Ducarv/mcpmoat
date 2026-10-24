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
// (zero-width, bidi, tag and other format characters) are removed, and the
// text is put in Unicode form NFC. Each white-space or control rune that the
// regex \s does not match (VT, NEL, the no-break space and the other Unicode
// spaces, U+2028, U+2029, the Braille blank U+2800, and control characters
// such as U+001F) becomes U+0020, so a regex sees it as a space and cannot
// match the rune itself. An ANSI escape sequence (CSI or OSC), which a
// terminal runs and does not show, also becomes one space. When the text holds invisible runes, it is
// also matched in a second form where each run of invisible runes is one
// space, so an invisible rune can split neither a word nor the space between
// two words. A rule matches when it matches in one form, so such a text costs
// twice as much to match.
//
// A regex reads only this normalized text. So a regex cannot match an
// invisible rune (use the invisible_unicode heuristic for that), and a
// pattern must be written in NFC: a pattern with a letter and a separate
// combining mark does not match the composed letter. The should_match cases
// of a rule (NFR-05) catch such a pattern. The form is not NFKC, so a regex
// does not see fullwidth or mathematical letters as plain letters.
//
// Keywords are normalized in the same way. For keywords only, the keyword and
// the text are then put in the compatibility form NFKC and lose their
// combining marks (category M). So a mark cannot hide a keyword, fullwidth
// and mathematical letters match the plain letters, and accents are folded:
// "cafe" matches "caf" + U+00E9. Homoglyphs from other scripts (for example
// Cyrillic U+0430 for Latin "a") are not folded.
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
// The base64_blob heuristic checks each run of base64 characters on its own.
// An invisible rune inside a run is skipped. Any other character, such as a
// space, a newline or '=', ends a run, and runs are not joined. So a payload
// that is split into short chunks is not flagged when no chunk reaches
// min_length on its own.
//
// The config heuristics (insecure_url, plaintext_secret, unpinned_package,
// auto_install and typosquat) read one line of text each, not the whole text.
// Only a rule with target: config may use them (Validate checks this). The
// built-in config rules use them on the lines of their test cases.
// insecure_url reads a URL. plaintext_secret reads an env entry
// ("KEY=VALUE"), a header entry ("Name: value"), a URL or a command line (the
// args of a stdio server). It reports a literal secret in env values, header
// values, command args and URLs. It never reports the value. unpinned_package
// and auto_install read a command line. unpinned_package also covers git,
// tarball, URL and GitHub shorthand package specs, unless the spec is pinned
// to a full 40-hex commit, and a script URL given to "pipx run". typosquat
// reads a command line or a bare package name. An adapter in this package
// turns the line into a server and runs the native config check on it. A hit
// from a config heuristic has the offset -1.
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
