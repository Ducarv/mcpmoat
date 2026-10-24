// Package rules loads YAML detection rules (embedded and external) and applies
// regex matchers and native heuristics to tool descriptions, schemas and
// server configs.
//
// See docs/PRD.md, FR-07 to FR-10.
//
// # The match block
//
// Each rule has a `match:` block, the type [Match]. It holds exactly one of
// any_regex, all_regex, keywords or heuristic. [Match.CompileFor] checks it
// and returns a [Matcher] for the target of the rule. The target decides how
// the Matcher reads its text (see Schema text below). [Match.Compile] is
// CompileFor with the description target. The loader compiles at load time
// through a [Compiler] given with [WithCompiler].
// Every error from CompileFor is a *[FieldError] that names the field, for
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
// and keyword rules. The match_window heuristic closes it: a high rule with
// it fires on every text that the regex and keyword rules do not read in
// full, also when only one form of the text is cut. The max_length heuristic
// also flags a long text. Both read the full raw text, as the other text
// heuristics do.
//
// A schema has its own budget (see Schema text). The regex and keyword rules
// read one schema in three passes:
//
//   - the strings, in document order: at most 4096 strings and at most
//     128 KiB, where a string counts for min(its length, 32 KiB) and is read
//     in the 32 KiB window;
//   - the seams of neighbour strings, only when no string matched: at most
//     128 KiB of seam text in all, at most 544 bytes for each seam;
//   - the raw text once, in the 32 KiB window, only when the JSON cannot be
//     read in full.
//
// So one schema costs about nine times as much as one description: four for
// the strings, four for the seams and one for the raw text. That is about
// twice the cost before the seam pass. The match_window heuristic also fires
// on a schema whose strings the caps cut, on a schema with a string longer
// than the window, and on JSON that cannot be read in full. It does not fire
// when the seam budget is used up (see Schema text).
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
// The text heuristics (invisible_unicode, tag_or_bidi_override, max_length,
// base64_blob and match_window) read the raw text, not the normalized text. A
// [Hit] from a text heuristic gives a byte offset in the raw text, except a
// match_window hit, which is about the whole text and has the offset -1
// ([NoOffset]). A hit from a regex or a keyword has the offset -1, because it
// comes from the normalized text. Every hit of a schema rule has the offset
// -1, also a hit of a text heuristic. Its Detail starts with one of these
// texts (see Schema text), where N is the 1-based place of a string in the
// list of distinct schema strings:
//
//   - "schema string N": a hit in one string;
//   - "schema strings N and N+1": a hit in the seam of two neighbour strings;
//   - "schema raw text": a hit in the raw text of a schema that cannot be
//     read in full;
//   - "schema JSON cannot be read in full" or "schema is longer than the
//     match window": the two match_window hits for the whole schema. A
//     match_window hit for one string that is longer than the window starts
//     with "schema string N".
//
// A schema rule returns at most 16 such hits, plus one summary hit
// "and N more schema hits".
//
// The invisible_unicode heuristic flags the same invisible runes that the
// normalization removes, so it flags every control character except the
// white space, such as U+0000, ESC and DEL.
//
// The tag_or_bidi_override heuristic flags a narrower set: the Unicode tag
// characters (U+E0000 to U+E007F), which can hide a full ASCII text, and the
// bidi overrides LRO and RLO, which reverse the text a reader sees. It
// excuses the tag characters of the England, Scotland and Wales flag emoji.
// One hit stands for one run, and its Detail gives the length of the run but
// never its runes.
//
// The match_window heuristic flags a text that the regex and keyword rules do
// not read in full (see Cost bounds). It has no parameters.
//
// The base64_blob heuristic checks each run of base64 characters on its own.
// An invisible rune inside a run, also a control character such as U+0000 or
// ESC, is skipped. Any other character, such as a space, a newline or '=', ends a
// run, and runs are not joined. So a payload that is split into short chunks
// is not flagged when no chunk reaches min_length on its own. With min_words
// set above 0 (the range is 0 to 64, and 0 is the default), the decoded text
// must also hold that many words in a row. The
// text is split into tokens at white space and at '-', '_', '/' and '\', and
// the punctuation and symbols at the two ends of each token are removed. A
// word is a token of letters, with an optional apostrophe inside. An empty
// token or a token of digits is skipped. Any other token ends the run. A
// field between white space that holds a '/' or a '\' is a path, and it
// counts as one word at most. So a JWT, which decodes to JSON, and a path
// alone are not flagged, but an encoded sentence is, also when it is written
// with hyphens or holds a path or a number.
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
// A rule with target: schema (the T1 schema rules) reads the tool input
// schema as JSON. It reads every object key and every string value, at any
// depth, in document order. A string that comes more than once is read once,
// at its first place, so the list of strings holds each distinct string once.
// Each string is matched alone, as a description is matched. Numbers,
// booleans and null are not read.
//
// An any_regex, all_regex or keywords rule reads the strings until the caps
// stop it (see Cost bounds). When no string matched, it also reads the seams:
// a seam is one text made of the last 256 bytes of a string, 32 newlines and
// the first 256 bytes of the next string in the list. So an instruction that
// is split over two neighbour strings is still found. A seam hit has a Detail
// that starts with "schema strings N and N+1". The seams use only the strings
// that fit the caps. The heuristics and match_window have no seam pass.
//
// In a seam, all_regex matches when all its regexes match in one string or
// all in one seam. A keyword of several words can cross a seam, because any
// run of white space matches the space between its words, but one word cannot
// be built from the parts of two strings. A regex gap such as [\s\S]{0,N},
// with N up to 31, cannot cross the 32 newlines, but \s+ and \s* can.
//
// The seams do not catch:
//
//   - a split with one benign string between the two halves;
//   - a split over strings that are not neighbours in the list;
//   - a split over three or more strings;
//   - a split with more than 256 bytes on one side of the seam;
//   - a split between the name and the description of the first property:
//     the key "description" is usually listed there for the first time, so
//     it sits between the two halves (in the next properties, the list drops
//     the repeated key, so the halves are neighbours);
//   - an indirection, such as "the URL in the endpoint field" or a $ref that
//     points to the other half.
//
// The seam texts of one schema total at most 128 KiB, and a seam is at most
// 544 bytes long. When this budget is used up, the seam pass stops silently:
// the match_window heuristic does not fire. One benign string between the two
// halves already defeats any join in document order, so a hit there would be
// a false positive on large benign schemas, with no gain in security.
//
// JSON escapes are decoded first, before any normalization or fold, so an
// invisible rune written as \u200b cannot hide as literal text, and an ESC
// written as \u001b is an ESC. The read is bounded by the depth and value
// caps of the inspect package, so a schema that inspect accepts is read in
// full. When the JSON cannot be read in full (it is malformed, has data after
// the first value, or goes over a cap), the rule also reads the raw text once,
// so a broken schema is still scanned. Its hits have a Detail that starts with
// "schema raw text".
//
// The shadowing check (MOAT-T3-001) still reads a narrower text: the value of
// every "description" and "title" string of the schema (InputSchema or
// OutputSchema), at any depth, in document order, with the keys matched in
// any case. It scans this text, together with the tool description, the tool
// title and the annotations title. The rules do not model JSON Schema
// keywords.
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
