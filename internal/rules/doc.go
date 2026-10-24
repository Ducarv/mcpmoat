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
// instruction caps. A text has up to fourteen forms for a regex (see
// Normalization below). For the worst case of one match block and its cost,
// see the cost comment on these caps in match.go. A hostile --rules
// directory multiplies this cost by the number of rules and texts. A cap at
// the loader level is future work (#33).
//
// # Normalization
//
// Before regex and keyword matching, the text is normalized: invisible runes
// are handled, and the text is put in Unicode form NFC. The invisible runes
// are the zero-width, bidi, tag and other format characters, and every
// control character (such as U+0000, U+0001, ESC, BEL and DEL) other than
// the white space (tab, LF, VT, FF, CR and NEL). An ANSI escape sequence (CSI
// or OSC), which a terminal runs and does not show, is handled before the
// control characters, so the sequence is still found. CAN and SUB cancel a
// sequence. Each white-space rune that the regex \s does not match (VT, NEL,
// the no-break space and the other Unicode spaces, U+2028, U+2029 and the
// Braille blank U+2800) becomes U+0020, so a regex sees it as a space and
// cannot match the rune itself.
//
// A text gives up to seven base forms. The first form is always built, and
// each other form only when the first 128 KiB of the raw text hold the runes
// that it needs. Equal forms are kept only once. In short:
//
//   - form 1 removes the invisible runes, so "ign" + ZWSP + "ore" is
//     "ignore", and turns each sequence into one space;
//   - forms 2 to 4 turn some runs of invisible runes into one space, so an
//     invisible rune cannot take the place of the space between two words:
//     form 2 each run, form 3 each run of control characters (it removes
//     the format characters), and form 4 each run with a format character
//     (it removes the control characters);
//   - forms 4 to 7 read a CSI as a terminal does, with C0 control
//     characters inside it, so ESC + U+0001 + "[8mIgnore" is " Ignore";
//   - forms 5 and 7 give back the text that a sequence takes: an OSC text
//     (a model reads it, a terminal does not show it), and the letter and
//     the < = > ? and intermediate bytes of a CSI, so ESC [ "Ignore" is
//     " Ignore" and ESC [ "<IMPORTANT>" is " <IMPORTANT>". An SGR (colour
//     and bold) becomes nothing, as a terminal shows it. Form 5 removes the
//     invisible runes, and form 7 turns each run of them into a space, as
//     form 2 does.
//
// The doc comment of matchForms in normalize.go has the full list with the
// build conditions, and the texts that still defeat all the forms. In a
// description, the invisible_unicode heuristic flags each of those texts,
// because it flags the invisible runes and the ESC. CONTRIBUTING.md has the
// same list for rule authors.
//
// A text without invisible runes and escape sequences has one form, so it
// costs no more.
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
// list can match in a different form. So a regex reads up to fourteen forms
// of a text (the seven base forms and their folds), and a keyword up to
// seven (the folds of the base forms): such a text costs up to fourteen
// times as much to match. The forms are built only when a regex or keyword
// matcher reads the text, and only once for each match: a heuristic reads
// only the raw text.
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
