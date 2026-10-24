package rules

import (
	"slices"
	"strings"
)

// fullSHALen is the length of a full Git commit hash in hex (SHA-1).
const fullSHALen = 40

// nonRegistrySpecUnpinned reports whether the package runner fetches its package
// from a git repository, a GitHub shorthand or a URL, and the spec is not
// pinned to a full commit. These specs are the ones that ExtractPackage
// refuses, so the registry check (PackageSpec.Unpinned) never sees them.
//
// It returns true only for:
//   - npx, bunx: "github:u/r" and the gitlab:, bitbucket: and gist: forms,
//     "u/r", "git+https://", "git+http://", "git+ssh://", "git://", "ssh://",
//     "git@host:u/r" and "http(s)://" URLs, with or without a "name@" prefix.
//     A git form is pinned only by a "#" fragment of exactly 40 hex digits
//     (npm options after "::" are ignored). So is an https URL of a repository
//     on github.com, gitlab.com or bitbucket.org, which npm reads as a git
//     spec. Any other URL is never pinned.
//   - uvx --from and pipx run --spec: "git+https://", "git+http://",
//     "git+ssh://" and "git+git://" unless the repository path ends in
//     "@<40 hex digits>", and "http(s)://" URLs of a .whl, .tar.gz, .tgz, .zip,
//     .tar, .tar.bz2 or .tar.xz file. The name may carry extras, as in
//     "tool[extra]@git+https://...".
//   - pipx run <URL>.py: a script that pipx downloads and runs. It cannot be
//     pinned.
//
// It returns false for everything else: a registry spec, a local path, a doubtful
// parse (see rawSpecAt), docker, a uvx spec that is not given with --from, a pipx
// spec that is neither given with --spec nor a script URL, and any form it does
// not know (for example hg+, svn+ and bzr+ specs, and "name @ url" with spaces).
// When unsure, it says false.
//
// The spec is untrusted config text and can hold credentials. This function
// only reads it and returns a bool; it never builds an error, a log line or a
// message from it.
func nonRegistrySpecUnpinned(command string, args []string) bool {
	runner, spec, at, ok := rawSpecAt(command, args)
	if !ok {
		return false
	}
	switch runner {
	case RunnerNPX, RunnerBunx:
		return npmNonRegistryUnpinned(spec)
	case RunnerUVX:
		return givenByFlag(args, at, "--from") && pythonNonRegistryUnpinned(spec)
	case RunnerPipx:
		if givenByFlag(args, at, "--spec") {
			return pythonNonRegistryUnpinned(spec)
		}
		return isScriptURL(spec)
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

// npmNonRegistryUnpinned classifies an npx or bunx spec (see nonRegistrySpecUnpinned).
// A spec can also be an alias, "name@<non-registry spec>", so it tries the part
// after the first "@" that follows the name.
func npmNonRegistryUnpinned(spec string) bool {
	if unpinned, nonRegistry := classifyNPM(spec); nonRegistry {
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

// classifyNPM reports whether spec is a non-registry npm spec, and if so whether it
// is unpinned. The two results are separate so the caller can tell "pinned"
// from "not a non-registry spec".
func classifyNPM(spec string) (unpinned, nonRegistry bool) {
	// A git spec ends in "#<commit-ish>". Only a full commit hash pins it.
	base, fragment, _ := strings.Cut(spec, "#")
	// npm allows options after the commit-ish: "#<commit>::path:packages/x".
	commit, _, _ := strings.Cut(fragment, "::")
	switch {
	case hasHTTPScheme(base):
		// npm reads the https URL of a repository on a known git host as a git
		// spec. Any other URL is a tarball, and a tarball cannot be pinned.
		return !isHostedGitURL(base) || !isFullSHA(commit), true
	case isNPMGitSpec(base), isGitHubShorthand(base):
		return !isFullSHA(commit), true
	default:
		return false, false
	}
}

// hostedGitHosts are the hosts whose repository URLs npm reads as git specs.
var hostedGitHosts = []string{"github.com", "gitlab.com", "bitbucket.org"}

// isHostedGitURL reports whether rawURL, without its "#" fragment, is the
// URL of a repository on one of hostedGitHosts: "https://host/user/repo" or
// "https://host/user/repo.git", with an optional "www." and user info. A longer
// path is not a repository root (it can be an archive), so it does not count.
//
// The URL is cut by hand and not with url.Parse, which refuses a reference such
// as "https://${TOKEN}@github.com/u/r" (braces in the user info), the safe form
// of a private repository.
func isHostedGitURL(rawURL string) bool {
	_, rest, found := strings.Cut(rawURL, "://")
	if !found {
		return false
	}
	rest, _, _ = strings.Cut(rest, "?")
	authority, path, _ := strings.Cut(rest, "/")
	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		authority = authority[at+1:] // drop the user info
	}
	host, _, _ := strings.Cut(authority, ":") // drop the port
	host = strings.TrimPrefix(strings.ToLower(host), "www.")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	return slices.Contains(hostedGitHosts, host) && len(parts) == 2 && parts[0] != "" && parts[1] != ""
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

// npmArchiveSuffixes are the suffixes of a local npm package file, in lower
// case. A repo name that ends in one of them is a file, not a GitHub repo.
var npmArchiveSuffixes = []string{".tgz", ".tar.gz", ".tar"}

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
	for _, suffix := range npmArchiveSuffixes {
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

// isNonRegistryURLSpec reports whether spec starts with "git+", "http://" or
// "https://", compared without regard to case.
func isNonRegistryURLSpec(spec string) bool {
	return hasPrefixFold(spec, "git+") || hasPrefixFold(spec, "http://") || hasPrefixFold(spec, "https://")
}

// isScriptURL reports whether spec is an http(s) URL of a .py file, a script
// that "pipx run" downloads and runs.
func isScriptURL(spec string) bool {
	if !hasHTTPScheme(spec) {
		return false
	}
	path, _, _ := strings.Cut(spec, "#")
	path, _, _ = strings.Cut(path, "?")
	return strings.HasSuffix(strings.ToLower(path), ".py")
}

// pythonNonRegistryUnpinned classifies a uvx --from or pipx --spec spec (see
// nonRegistrySpecUnpinned). Like npm, it also reads "name@<non-registry spec>".
func pythonNonRegistryUnpinned(spec string) bool {
	if unpinned, nonRegistry := classifyPython(spec); nonRegistry {
		return unpinned
	}
	// The name must come first, so the first "@" after index 0 splits it. The
	// name may carry extras: "tool[extra]".
	if i := strings.Index(spec, "@"); i > 0 && validPyPIName(stripExtras(spec[:i])) {
		unpinned, _ := classifyPython(spec[i+1:])
		return unpinned
	}
	return false
}

// stripExtras cuts a trailing "[extra,...]" from a Python package name.
func stripExtras(name string) string {
	if before, ok := strings.CutSuffix(name, "]"); ok {
		if i := strings.IndexByte(before, '['); i > 0 {
			return before[:i]
		}
	}
	return name
}

// pythonGitSchemes are the schemes that a pip or uv git spec can use, in lower
// case, after the "git+" prefix. "git+file" is local and is not in the list.
var pythonGitSchemes = []string{"git+https://", "git+http://", "git+ssh://", "git+git://"}

// pythonArchiveSuffixes are the file types that make a URL a Python package
// download, in lower case.
var pythonArchiveSuffixes = []string{".whl", ".tar.gz", ".tgz", ".zip", ".tar", ".tar.bz2", ".tar.xz"}

// classifyPython reports whether spec is a non-registry Python spec, and if so
// whether it is unpinned.
func classifyPython(spec string) (unpinned, nonRegistry bool) {
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
	// pip and uv read the revision from the path only. An "@<sha>" in the query
	// is not a pin.
	path, _, _ = strings.Cut(path, "?")
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
	return len(s) == fullSHALen && isHexString(s, fullSHALen)
}
