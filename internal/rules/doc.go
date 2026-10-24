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
// it fires on a text longer than 128 KiB, and when the window cuts one of
// the forms (see matchForms), also when only one of them is cut. The OSC
// text of a form does not count: the OSC text, such as an OSC 8 link URL,
// makes a benign text long in the forms that keep sequence text only (see
// matchWindowCut). The max_length heuristic also flags a long text. Both
// read the full raw text, as the other text heuristics do.
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
// the strings, four for the seams and one for the raw text. The seam pass
// doubles the cost of the string pass. The match_window heuristic also fires
// on a schema whose strings the caps cut, on a schema with a string longer
// than the window, and on JSON that cannot be read in full. It does not fire
// when the seam budget is used up (see Schema text).
//
// A list holds at most [MaxPatterns] entries of at most [MaxPatternBytes]
// bytes each, and the compiled programs of one regex and of one list have
// instruction caps. A text has up to 21 forms for a regex (see
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
// The regex and keyword matchers read a few base forms of the text, and
// each form handles the invisible runes and the escape sequences in another
// way, so that an invisible rune or a sequence cannot hide a word in all of
// them. The doc comment of matchForms in normalize.go lists the forms, when
// each one is built and the texts that still defeat all of them, and
// CONTRIBUTING.md has the same list for rule authors. A text without
// invisible runes and escape sequences has one form, so it costs no more.
//
// A regex reads these base forms, and also a folded form of each. The text
// is folded one rune at a time: the rune is split into its compatibility
// parts (NFKD), its combining marks (category M) are dropped, and the rest is
// joined again (NFKC). The pattern is not folded. So a regex such as `ignore`
// also matches fullwidth and mathematical letters ("ignore" in U+FF49 ... or
// in U+1D422 ...) and a word with a mark in it ("ig" + U+0336 + "nore").
//
// A regex also reads a second fold of each base form, the skeleton fold
// (foldSkeleton in confusables.go). It is the fold above (the plain fold,
// foldMarks) that also maps look-alike letters of other scripts to one
// ASCII letter: the confusable skeleton. Its table, skeletonTable, holds
// 562 runes from Unicode TR39 confusables.txt (version 18.0.0), each a
// single rune that TR39 maps to one ASCII letter, alone or followed only by
// combining marks (category Mn). The marks are dropped, so U+0268 (i with
// stroke, TR39 "i" + U+0335) maps to "i". The target keeps the case of
// TR39, but a TR39 target "l" becomes "I" for an uppercase rune. A spacing
// mark of the table, such as Telugu U+0C02 ("o"), maps before the fold
// drops the marks. So `ignore` also matches U+0456 + "gnore" (Cyrillic i),
// and `~/\.ssh` matches "~/." + U+0455 U+0455 U+04BB (Cyrillic). The keyword
// fold does not get the skeleton. For the limits, see the end of the
// Heuristics and hits section.
//
// A fold that is longer than the rune is not used, so the folded form is never
// longer than the text: a ligature that folds to many letters, such as
// U+FDFA, stays as it is and cannot push a payload out of the 32 KiB. A form
// that is only ASCII is its own fold, so it adds no folded form. A rule
// matches when it matches in one form, and each regex of an all_regex list
// can match in a different form. So a regex reads up to 21 forms of a text
// (maxRegexForms: the 7 base forms, their plain folds and their skeleton
// folds), and a keyword up to 7 (maxKeywordForms: the plain folds of the
// base forms): such a text costs up to 21 times as much to match. The plain
// fold stays a regex form next to the skeleton fold, so no match of the
// plain fold is lost. A skeleton fold is a new form only when it differs
// from the plain fold, that is when the base form or its plain fold holds a
// rune of skeletonTable. So a text with no such rune has at most 14 regex
// forms, as before the skeleton. The worst case for one match block is 21 x
// 32 KiB x 2500, about 1.7G instruction-bytes: about 16 s for one Match call
// on an Apple M1 Pro (an order of magnitude, not a precise figure; see the
// cost comment in match.go). The forms are built only when a regex or
// keyword matcher reads the text, and only once for each match. A heuristic
// gets only the raw text. The match_window heuristic builds the forms
// itself, to check their length.
//
// A regex cannot match an invisible rune (use the invisible_unicode heuristic
// for that), and a pattern must be written in NFC: a pattern with a letter
// and a separate combining mark does not match the composed letter. The
// should_match cases of a rule (NFR-05) catch such a pattern.
//
// Keywords are normalized in the same way, but for keywords both the keyword
// and the text are folded, and only the folded forms are matched. So a mark
// cannot hide a keyword, fullwidth and mathematical letters match the plain
// letters, and accents are folded: "cafe" matches "caf" + U+00E9. Keywords
// do not get the confusable skeleton, so a homoglyph from another script
// (for example Cyrillic U+0430 for Latin "a") is not folded for a keyword.
// The mixed_script heuristic (rules MOAT-T1-010 and MOAT-T1-011) flags a
// word that mixes letters of two or more look-alike scripts, such as Latin
// and Cyrillic, except a Greek unit letter after a number. See the
// Heuristics and hits section for details.
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
// base64_blob, mixed_script and match_window) read the raw text, not the normalized text. A
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
// A schema rule returns at most [MaxHits] such hits, plus one summary hit
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
// counts as one word at most. In a decoded JSON object or array, one string
// (a key or a value) must hold twice min_words words in a row. So a JWT, an
// encoded JSON cursor and a path alone are not flagged, but an encoded
// sentence is, also when it is written with hyphens or holds a path or a
// number, or sits in a JSON wrapper. YAML, shell or log text with spaces can
// still count as words. A sentence that a '/' joins into one field, or that
// one token which is not a word (such as "e.g") cuts, stays below the run. The
// medium rules without min_words still flag such a text.
//
// The mixed_script heuristic flags a word that mixes letters of two or more
// look-alike scripts, such as "Ignore" with a Cyrillic "I" (U+0406). The
// look-alike scripts are the scripts in the table lookalikeScripts in
// mixedscript.go. The table holds Latin and each script of the Go unicode
// tables (Unicode 17.0.0) with a letter or mark that Unicode TR39
// confusables.txt (version 18.0.0) maps to a Latin letter. It also holds
// Gothic, which has Latin look-alikes that TR39 does not list.
//
// Each script in the table has one of two tiers:
//
//   - strict: a letter or mark of the script counts at any place in the
//     word, so any mix with Latin flags the word. Cyrillic, Greek, Armenian,
//     Georgian, Lycian, Osage, NKo, Ethiopic and Runic are examples. A word
//     with no Latin letter is flagged too when it mixes two strict scripts,
//     such as Cyrillic and Armenian letters that read as "ignore".
//   - edge: a letter or mark of the script counts inside a word, with a
//     Latin letter before it and a Latin letter after it. Real text puts
//     these scripts next to a Latin name with no space between them. So a
//     run of edge-tier letters at the start or the end of a word is excused
//     when it has 2 or more visible letters, or when its one letter is not
//     in the table edgeLookalikes. That table holds the edge-tier letters
//     that TR39 confusables.txt maps to one Latin letter, or to one Latin
//     letter and then only non-spacing marks or U+0674 (high hamza), for
//     example Arabic alef (U+0627), Arabic alef with wavy hamza below
//     (U+0673) and Hebrew vav (U+05D5) as "l", and Hangul ieung
//     (U+3147) as "o". It also holds their composed and compatibility forms,
//     which have the same base letter after NFKD with the marks removed,
//     such as Arabic alef with hamza above (U+0623) and Hebrew vav with
//     holam (U+FB4B). So NFC text and decomposed text give the same result.
//     A run of one table letter at the edge counts. The marks after a base
//     letter of their own script belong to the same run.
//     An invisible letter, such as the Hangul filler U+3164, does not count
//     toward the length of the run, and a run with no visible letter is
//     excused. So Thai "use" (U+0E43 U+0E0A U+0E49) + "Google", Hebrew bet
//     (U+05D1) + "Google", Arabic "al" (U+0627 U+0644) + "Google" and
//     "Google" + a Korean particle (U+C744) are not flagged. Thai, Lao,
//     Khmer, Myanmar, Hebrew, Arabic, Bopomofo, Hangul and the Indic scripts
//     with spacing marks, such as Telugu and Kannada, are examples. Bopomofo
//     is here because informal Taiwanese text puts a Bopomofo particle next
//     to a Latin name.
//
// Only Greek has an exemption, for a unit (see below). The heuristic reads
// the full raw text. A hit gives the raw byte offset of the first rune of the
// word and names the scripts in the order of the table, but it never holds
// the word: the terminal-safe output does not change look-alike letters, so
// the word would show as normal Latin text.
//
// A word is a run of letters, marks, invisible runes, private-use runes,
// unassigned code points, U+FFFD (from an invalid UTF-8 byte or a lone
// surrogate) and runes whose fold is only letters. So a ZWSP, a combining
// mark, a private-use rune (such as U+E000, which many fonts draw as
// nothing), a Roman numeral (such as U+216E, "D") or a circled letter (such
// as U+24D6, "g") cannot split a word. Any other rune, such as a digit, '_',
// '-', a space or punctuation, ends a word.
//
// Each letter counts for its own script. So Armenian small oh (U+0585) and
// Lisu letter ga (U+A4D6) count for their scripts. A letter of the Common or
// Inherited script, a Latin letter that is not ASCII and a rune that is not a
// letter but folds to letters count by their fold, the same fold that the
// regexes read. So the mathematical Greek letters (in U+1D6A8 to U+1D7CB) and
// the double-struck Greek letters (U+213C to U+213F) count as Greek, the
// mathematical Latin letters (such as U+1D400), the fullwidth Latin letters
// and the Roman numerals count as Latin, and U+00B5 (micro sign) counts as
// Greek mu. A letter of any other script, such as Han, counts for no script.
// The heuristic does not use the confusable skeleton of the regex fold.
//
// A mark counts for its own script, with no fold, as in TR39 section 5.1. So
// a mark of a script in the table counts for that script, in the tier of
// that script. A mark of the Common or Inherited script, such as U+0336
// (combining long stroke overlay), or of a script outside the table only
// joins the word.
//
// An edge-tier mark after a base letter of its own script joins the run of
// that letter, so it stays benign at the edge. Any other edge-tier mark
// counts at once, as a strict-tier mark does, when it reads as a Latin
// letter (it is in skeletonTable): the word has no letter yet, or the last
// letter is of another script, and real text does not put such a mark
// there. So "hell" + U+0C02 (Telugu anusvara, which looks like an "o") and
// U+0C02 + "pen" are flagged. An edge-tier mark that does not read as a
// letter joins the run too. So Burmese text in the Zawgyi encoding, which
// stores the vowel sign U+1031 before its consonant, is not flagged at the
// edge of a word, next to a Latin name.
//
// The parameter json_escapes (default 0) says whether the text is raw JSON.
// A schema rule reads decoded strings (see Schema text), so MOAT-T1-011 keeps
// the default 0 too. With json_escapes: 1 the heuristic decodes JSON escapes: \b, \f, \n, \r, \t, \\, \", \/ and \u plus
// exactly 4 hex digits. A surrogate pair is one rune, and a lone surrogate
// is U+FFFD. The decoded rune acts like a raw rune: a letter, a mark or an
// invisible rune joins the word, and any other rune ends it. So the escape
// of U+0406 is a Cyrillic letter in the word. A description is decoded text,
// so rule MOAT-T1-010 keeps the default 0: a backslash is a normal rune that
// ends a word, as the model reads it. A schema string is decoded before the
// heuristic reads it, so a second decode would turn a literal "\b" into a
// backspace.
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
// comes directly after an ASCII digit. With json_escapes: 1, an escaped
// digit, such as \u0035, does not count. So "5" + U+03BC + "s", "5 " +
// U+03BC + "mol" and "10k" + U+03A9 are not flagged. But U+03BC + "s" with
// no number before it, "2 " + U+03BC + "ser" and "5" + U+03BC + "pdate" are
// flagged. Math notation is also flagged: U+0394 (capital Delta) + "t" gives
// a known false positive. To accept such a word, ignore the rule
// (MOAT-T1-010 or MOAT-T1-011) for that one tool in .mcpmoat-ignore.
//
// The mixed_script heuristic does not flag:
//
//   - a word written fully in look-alikes of one script, such as Cyrillic
//     "copy" (U+0441 U+043E U+0440 U+0443) or the Cyrillic "ssh" in "~/." +
//     U+0455 U+0455 U+04BB. The regexes read such a word in ASCII letters
//     (see Normalization), so the sensitive-path rules catch that "~/.ssh";
//   - a word of one letter, because it cannot mix two scripts;
//   - Latin-script look-alikes, such as U+0131 (dotless i), U+01C0 (dental
//     click) and U+0261 (script g): they are Latin, so the word does not mix
//     scripts. The regexes read U+0131 as "i" and U+0261 as "g";
//   - a word that a visible rune splits in two, when the rune is not a
//     letter and does not fold to letters, such as U+2800 (braille blank) or
//     U+212E (estimated sign, a symbol that looks like an "e"). The regexes
//     read U+212E as "e";
//   - a digit or punctuation look-alike, such as U+0966 (Devanagari digit
//     zero) for an "o": the rune ends the word, as the "0" in the leetspeak
//     "ign0re" does. A script whose only Latin look-alikes are digits or
//     punctuation, such as Devanagari, is not in the table. Thai, Lao and
//     Khmer are the exceptions, in the edge tier;
//   - a run of two or more visible edge-tier letters at the start or the end
//     of a word, whether or not each letter is a look-alike, such as Arabic
//     alef and lam (U+0627 U+0644) + "gnore" or two Hebrew vav (U+05D5
//     U+05D5) + "gnore". A small Arabic modifier letter (Lm), such as U+06E5
//     (small waw), next to the table letter counts as the second visible
//     letter, so it excuses the run too (a residual risk). U+0674 (high
//     hamza) is the exception: it is a small mark that Unicode makes a
//     letter, so the run does not count it, and U+0627 U+0674 + "gnore" is
//     flagged;
//   - one edge-tier letter at the start or the end of a word that is not in
//     edgeLookalikes: a letter that TR39 maps to a Latin letter and a
//     spacing mark, such as Myanmar U+1010 ("o" + U+102C), a letter that TR39
//     maps to two Latin letters, such as U+11EE ("oo") and U+1EE64 ("ol"), and
//     a letter with no Latin mapping, such as alef wasla (U+0671);
//   - Han letters next to Latin letters, such as "API" + U+63A5 U+53E3: Han
//     is not in the table, because Chinese and Japanese text puts Han
//     letters next to Latin names, also between two names;
//   - a code point that is new in Unicode 18.0.0 and not yet in the Go
//     tables: Go reads it as unassigned, so it joins the word but counts for
//     no script.
//
// The regexes fold U+0261 and U+212E (see Normalization). U+01C0 is not
// caught: see the first limit below.
//
// The confusable skeleton of the regex fold has these limits:
//
//   - a caseless look-alike of "I", such as U+01C0 (dental click, a bare
//     bar) or Runic U+16C1, maps to "l". So U+01C0 + "gnore" reads "lgnore",
//     and no rule catches it (mixed_script flags U+16C1 in a Latin word, but
//     U+01C0 is Latin; issue #149 tracks it). The one exception is U+A7FE (I
//     longa), which maps to "I" by its name. An uppercase look-alike of "l", such as U+04C0
//     (palochka), maps to "I", so U+04C0 U+04C0 does not read as "ll";
//   - the skeleton can join a look-alike to a payload. A look-alike of "l"
//     or "I", such as U+04CF, directly before a payload that is written in
//     look-alike letters (a Cyrillic "id_rsa") becomes an ASCII letter of
//     the same word ("lid_rsa"), so a pattern with `\b` does not match. The
//     plain fold does not help, because the payload is not ASCII in it. Such
//     a payload had no detection before the skeleton fold;
//   - Cyrillic has no look-alike of a small "n" or "g", so "ignore" cannot
//     be written fully in Cyrillic. A look-alike "ignore" needs a second
//     script, such as Armenian U+0578 ("n") and U+0581 ("g");
//   - digit look-alikes, such as U+0966 (Devanagari digit zero) for an "o",
//     and ASCII leetspeak, such as "ign0re", are not folded;
//   - U+017F (long s): TR39 reads it as "f", but the plain fold reads it as
//     "s", so it is not in the table. So U+017F + "orget all previous
//     instructions" reads "sorget" and is not caught;
//   - a look-alike whose TR39 target is a letter followed by a rune that is
//     not a combining mark of category Mn, or two or more letters (such as
//     "rn" for "m"), is not folded;
//   - in a word of another script, a letter that is not in the table stays
//     as it is, and the ASCII-only \w of the regex engine reads it as a word
//     edge. So the table letters of the word become ASCII fragments between
//     such edges: the skeleton fold of the Greek word U+03B7 U+03B3 U+03BF
//     U+03CD U+03BC U+03B5 U+03BD U+03BF U+03C2 is "nyou" + U+03BC U+03B5 +
//     "vo" + U+03C2, so a pattern such as `\bvo\b` matches in it;
//   - real Russian, Greek and Armenian text gets ASCII letters in the
//     skeleton fold. A few should_not_match cases of the built-in rules
//     check short Russian and Greek texts. No case checks Armenian text, and
//     other real text is not tested, so a built-in rule or a new pattern can
//     hit it;
//   - Han letters, such as U+4E05 and U+4E2B, and symbols other than
//     U+212E, such as U+00D7 for "x", are not in the table;
//   - a look-alike from a script or code point that the Go tables (Unicode
//     17.0.0) or TR39 confusables.txt (version 18.0.0) do not list is not
//     folded.
//
// The mixed_script heuristic flags these words, which are known false
// positives:
//
//   - an edge-tier run between two Latin names in one word, such as
//     "Google" + Thai "and" (U+0E41 U+0E25 U+0E30) + "Apple";
//   - a Latin word with one edgeLookalikes letter at its start or end, such
//     as the Hebrew prefix vav (U+05D5, "and") + "Google".
//
// Rules MOAT-T1-010 and MOAT-T1-011 have severity medium, so with the
// default --fail-on high they do not change the exit code. To accept such a
// word, ignore the rule (MOAT-T1-010 or MOAT-T1-011) for that one tool in
// .mcpmoat-ignore.
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
// with N up to 31, cannot cross the 32 newlines, but \s+ and \s* can. When
// a side is cut at 256 bytes, the cut point acts like the start or the end of
// the text, so ^, $ and \b can match there although the full string has no
// edge at that place; a seam can therefore give a rare hit that the string
// alone does not give.
//
// The seams do not catch:
//
//   - a split with one benign string between the two halves;
//   - a split over strings that are not neighbours in the list, also when a
//     string is a copy of an earlier string: the list keeps only the first
//     copy, so an early copy of the second half removes it from its place;
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
