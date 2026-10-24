package rules

import "strings"

// fullSHALen is the length of a full Git commit hash in hex (SHA-1).
const fullSHALen = 40

// remoteSpecUnpinned reports whether the package runner fetches its package
// from a git repository, a GitHub shorthand or a URL, and the spec is not
// pinned to a full commit. These specs are the ones that ExtractPackage
// refuses, so the registry check (PackageSpec.Unpinned) never sees them.
//
// It returns true only for:
//   - npx, bunx: "github:u/r" and the gitlab:, bitbucket: and gist: forms,
//     "u/r", "git+https://", "git+http://", "git+ssh://", "git://", "ssh://",
//     "git@host:u/r" and "http(s)://" URLs, with or without a "name@" prefix.
//     A git form is pinned only by a "#" fragment of exactly 40 hex digits.
//     A URL is never pinned.
//   - uvx --from and pipx run --spec: "git+https://", "git+http://",
//     "git+ssh://" and "git+git://" unless the repository path ends in
//     "@<40 hex digits>", and "http(s)://" URLs of a .whl, .tar.gz, .tgz, .zip
//     or .tar file.
//
// It returns false for everything else: a registry spec, a local path, a doubtful
// parse (see rawSpecAt), docker, a uvx or pipx spec that is not given with
// --from or --spec, and any form it does not know. When unsure, it says false.
//
// The spec is untrusted config text and can hold credentials. This function
// only reads it and returns a bool; it never builds an error, a log line or a
// message from it.
func remoteSpecUnpinned(command string, args []string) bool {
	if _, _, ok := packageAt(command, args); ok {
		return false // a registry spec: the registry check handles it
	}
	runner, spec, at, ok := rawSpecAt(command, args)
	if !ok {
		return false
	}
	switch runner {
	case RunnerNPX, RunnerBunx:
		return npmRemoteUnpinned(spec)
	case RunnerUVX:
		return givenByFlag(args, at, "--from") && pythonRemoteUnpinned(spec)
	case RunnerPipx:
		return givenByFlag(args, at, "--spec") && pythonRemoteUnpinned(spec)
	default:
		return false
	}
}

// givenByFlag reports whether args[at] is the value of flag, either in the
// "flag value" form or in the "flag=value" form. rawSpecAt returns a spec that
// comes from the override flag or from the first positional argument. This
// tells the two apart. Known limit: "--with --from <spec>" (a flag that takes
// "--from" as its value) is read as the override flag.
func givenByFlag(args []string, at int, flag string) bool {
	if at < 0 || at >= len(args) {
		return false
	}
	if strings.HasPrefix(args[at], flag+"=") {
		return true
	}
	return at > 0 && args[at-1] == flag
}

// npmRemoteUnpinned classifies an npx or bunx spec (see remoteSpecUnpinned).
// A spec can also be an alias, "name@<remote spec>", so it tries the part
// after the first "@" that follows the name.
func npmRemoteUnpinned(spec string) bool {
	if unpinned, remote := classifyNPM(spec); remote {
		return unpinned
	}
	// Index(spec[1:], "@")+1 skips the "@" of a scope ("@scope/name"). When
	// there is no "@", Index gives -1 and i is 0, which the check below skips.
	i := strings.Index(spec[1:], "@") + 1
	if i > 0 && validNPMName(spec[:i]) {
		unpinned, _ := classifyNPM(spec[i+1:])
		return unpinned
	}
	return false
}

// classifyNPM reports whether spec is a remote npm spec, and if so whether it
// is unpinned. The two results are separate so the caller can tell "pinned"
// from "not a remote spec".
func classifyNPM(spec string) (unpinned, remote bool) {
	// A git spec ends in "#<commit-ish>". Only a full commit hash pins it.
	base, fragment, _ := strings.Cut(spec, "#")
	switch {
	case hasHTTPScheme(base):
		return true, true // a URL cannot be pinned
	case isNPMGitSpec(base), isGitHubShorthand(base):
		return !isFullSHA(fragment), true
	default:
		return false, false
	}
}

// npmGitPrefixes are the prefixes of npm git specs, in lower case. A local
// "git+file:" spec is not in the list on purpose.
var npmGitPrefixes = []string{
	"github:", "gitlab:", "bitbucket:", "gist:",
	"git+https://", "git+http://", "git+ssh://", "git://", "ssh://",
}

// isNPMGitSpec reports whether spec (without its "#" fragment) is an npm git
// spec: a known prefix with something after it, or the "git@host:path" form.
func isNPMGitSpec(spec string) bool {
	for _, prefix := range npmGitPrefixes {
		if hasPrefixFold(spec, prefix) && len(spec) > len(prefix) {
			return true
		}
	}
	return hasPrefixFold(spec, "git@") && strings.Contains(spec, ":")
}

// isGitHubShorthand reports whether spec (without its "#" fragment) is the
// npm shorthand "user/repo". Both parts must look like GitHub names, so a
// path ("./x", "../x", "/x", "~/x"), a scope ("@scope/pkg") and a "host:path"
// never match. A repo that ends in an archive suffix may be a local file, so it
// does not match either.
func isGitHubShorthand(spec string) bool {
	user, repo, found := strings.Cut(spec, "/")
	if !found || !isGitHubName(user) || !isGitHubName(repo) {
		return false
	}
	for _, suffix := range []string{".tgz", ".tar.gz", ".tar"} {
		if strings.HasSuffix(strings.ToLower(repo), suffix) {
			return false
		}
	}
	return true
}

// isGitHubName reports whether s is not empty, starts with an ASCII letter or
// digit, and has only letters, digits and "._-". A "/" is not allowed, so a
// third path part makes a shorthand fail.
func isGitHubName(s string) bool {
	if s == "" || !isASCIIAlnum(rune(s[0])) {
		return false
	}
	return !strings.ContainsFunc(s, func(r rune) bool {
		return !isASCIIAlnum(r) && !strings.ContainsRune("._-", r)
	})
}

// isASCIIAlnum reports whether r is an ASCII letter or digit.
func isASCIIAlnum(r rune) bool {
	return isLowerAlnum(r) || (r >= 'A' && r <= 'Z')
}

// pythonRemoteUnpinned classifies a uvx --from or pipx --spec spec (see
// remoteSpecUnpinned). Like npm, it also reads "name@<remote spec>".
func pythonRemoteUnpinned(spec string) bool {
	if unpinned, remote := classifyPython(spec); remote {
		return unpinned
	}
	// The name must come first, so the first "@" after index 0 splits it.
	if i := strings.Index(spec, "@"); i > 0 && validPyPIName(spec[:i]) {
		unpinned, _ := classifyPython(spec[i+1:])
		return unpinned
	}
	return false
}

// pythonGitSchemes are the schemes that a pip or uv git spec can use, in lower
// case, after the "git+" prefix. "git+file" is local and is not in the list.
var pythonGitSchemes = []string{"git+https://", "git+http://", "git+ssh://", "git+git://"}

// pythonArchiveSuffixes are the file types that make a URL a Python package
// download, in lower case.
var pythonArchiveSuffixes = []string{".whl", ".tar.gz", ".tgz", ".zip", ".tar"}

// classifyPython reports whether spec is a remote Python spec, and if so
// whether it is unpinned.
func classifyPython(spec string) (unpinned, remote bool) {
	// The fragment holds "egg=" or "subdirectory=" options, not a version.
	base, _, _ := strings.Cut(spec, "#")
	for _, scheme := range pythonGitSchemes {
		if hasPrefixFold(base, scheme) && len(base) > len(scheme) {
			return !isPinnedGitURL(base[len(scheme):]), true
		}
	}
	if hasHTTPScheme(base) {
		path, _, _ := strings.Cut(base, "?")
		path = strings.ToLower(path)
		for _, suffix := range pythonArchiveSuffixes {
			if strings.HasSuffix(path, suffix) {
				return true, true // a URL cannot be pinned
			}
		}
	}
	return false, false
}

// isPinnedGitURL reports whether rest, a git URL without its "git+scheme://"
// prefix, ends its repository path in "@<40 hex digits>". The host part is
// skipped first, because it can hold "user@" (as in "git@host/u/r").
func isPinnedGitURL(rest string) bool {
	_, path, found := strings.Cut(rest, "/")
	if !found {
		return false
	}
	at := strings.LastIndex(path, "@")
	return at >= 0 && isFullSHA(path[at+1:])
}

// hasHTTPScheme reports whether s starts with "http://" or "https://" (any
// case) and has a host part.
func hasHTTPScheme(s string) bool {
	for _, scheme := range []string{"http://", "https://"} {
		if hasPrefixFold(s, scheme) && len(s) > len(scheme) {
			return true
		}
	}
	return false
}

// isFullSHA reports whether s is exactly fullSHALen hex digits (upper or lower
// case). A short hash or a 64 digit hash is not a full SHA-1 commit.
func isFullSHA(s string) bool {
	if len(s) != fullSHALen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isHexDigit(s[i]) { // isHexDigit is in heuristics.go
			return false
		}
	}
	return true
}
