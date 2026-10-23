// Package rules loads YAML detection rules (embedded and external) and applies
// regex matchers and native heuristics to tool descriptions, schemas and
// server configs.
//
// See docs/PRD.md, FR-07 to FR-10.
//
// # The match block
//
// Each rule has a `match:` block, the type [Match]. It holds exactly one of
// any_regex, all_regex, keywords or heuristic. The rule loader (#33) calls
// [Match.Compile] once, at load time, and keeps the [Matcher] it returns.
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
// it and the other heuristics read the full raw text.
//
// A list holds at most [MaxPatterns] entries of at most [MaxPatternBytes]
// bytes each. The compiled program of one regex has a cap of 1000
// instructions, and the sum of the programs of one list has a cap of 2500
// instructions. So the worst case for one match block is about 32 KiB x 2500,
// about 80M instruction-bytes. BenchmarkWorstCaseBlock measures it; the
// result is in the comment on the caps in match.go. A hostile --rules
// directory multiplies this cost by the number of rules and texts. A cap at
// the loader level is future work (#33).
//
// # Normalization
//
// Before regex and keyword matching, the text is normalized: invisible runes
// (zero-width, bidi, tag and other format characters) are removed, and the
// text is put in Unicode form NFC. The form is not NFKC, so fullwidth letters
// and homoglyphs (for example Cyrillic U+0430 for Latin "a") are not folded.
//
// Keywords are normalized in the same way. For keywords only, the
// non-spacing marks (category Mn) are then dropped from the keyword and the
// text, so a mark cannot hide a keyword, and accents are folded: "cafe"
// matches "caf" + U+00E9. U+2800 (braille blank) counts as white space
// between the words of a keyword. A keyword matches without regard to case,
// and only as a whole word, with Unicode word edges. A regex gets no
// automatic (?i): write it in the pattern when you need it.
//
// # Heuristics and hits
//
// The heuristics read the raw text, not the normalized text. A [Hit] from a
// heuristic gives a byte offset in the raw text. A hit from a regex or a
// keyword has the offset -1, because it comes from the normalized text.
//
// The base64_blob heuristic checks each run of base64 characters on its own.
// An invisible rune inside a run is skipped. Any other character, such as a
// space, a newline or '=', ends a run, and runs are not joined. So a payload that is split into short chunks is not
// flagged when no chunk reaches min_length on its own.
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
