package rules

import (
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// sha40Upper is testSHA (a synthetic commit hash, not a real commit) in upper
// case hex.
const sha40Upper = "0123456789ABCDEF0123456789ABCDEF01234567"

// nonRegistryCase is one command line for the non-registry spec tests.
type nonRegistryCase struct {
	name    string
	command string
	args    []string
}

func TestRawSpecAt(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		command    string
		args       []string
		wantRunner Runner
		wantSpec   string
		wantAt     int
		wantOK     bool
	}{
		// npx and bunx
		{name: "npx -y github", command: "npx", args: []string{"-y", "github:user/repo"},
			wantRunner: RunnerNPX, wantSpec: "github:user/repo", wantAt: 1, wantOK: true},
		{name: "npx registry spec", command: "npx", args: []string{"pkg@1.0.0"},
			wantRunner: RunnerNPX, wantSpec: "pkg@1.0.0", wantAt: 0, wantOK: true},
		{name: "bunx shorthand", command: "bunx", args: []string{"user/repo"},
			wantRunner: RunnerBunx, wantSpec: "user/repo", wantAt: 0, wantOK: true},
		{name: "npx -p", command: "npx", args: []string{"-p", "github:user/repo", "cmd"},
			wantRunner: RunnerNPX, wantSpec: "github:user/repo", wantAt: 1, wantOK: true},
		{name: "npx --package value", command: "npx", args: []string{"--package", "github:user/repo", "cmd"},
			wantRunner: RunnerNPX, wantSpec: "github:user/repo", wantAt: 1, wantOK: true},
		{name: "npx --package=", command: "npx", args: []string{"--package=github:user/repo", "cmd"},
			wantRunner: RunnerNPX, wantSpec: "github:user/repo", wantAt: 0, wantOK: true},
		{name: "npx double dash", command: "npx", args: []string{"-y", "--", "user/repo"},
			wantRunner: RunnerNPX, wantSpec: "user/repo", wantAt: 2, wantOK: true},
		{name: "npx valued flag skipped", command: "npx", args: []string{"--registry", "https://r.example", "user/repo"},
			wantRunner: RunnerNPX, wantSpec: "user/repo", wantAt: 2, wantOK: true},
		{name: "npx command path", command: "/usr/local/bin/npx", args: []string{"user/repo"},
			wantRunner: RunnerNPX, wantSpec: "user/repo", wantAt: 0, wantOK: true},

		// uvx
		{name: "uvx --from then tool", command: "uvx", args: []string{"--from", "git+https://h/u/r", "tool"},
			wantRunner: RunnerUVX, wantSpec: "git+https://h/u/r", wantAt: 1, wantOK: true},
		{name: "uvx --from=", command: "uvx", args: []string{"--from=git+https://h/u/r", "tool"},
			wantRunner: RunnerUVX, wantSpec: "git+https://h/u/r", wantAt: 0, wantOK: true},
		{name: "uvx positional", command: "uvx", args: []string{"--isolated", "git+https://h/u/r"},
			wantRunner: RunnerUVX, wantSpec: "git+https://h/u/r", wantAt: 1, wantOK: true},
		{name: "uvx valued flag skipped", command: "uvx", args: []string{"--python", "3.12", "--from", "git+https://h/u/r", "tool"},
			wantRunner: RunnerUVX, wantSpec: "git+https://h/u/r", wantAt: 3, wantOK: true},

		// pipx
		{name: "pipx --verbose run --spec", command: "pipx",
			args:       []string{"--verbose", "run", "--spec", "git+https://h/u/r", "tool"},
			wantRunner: RunnerPipx, wantSpec: "git+https://h/u/r", wantAt: 3, wantOK: true},
		{name: "pipx run --spec=", command: "pipx", args: []string{"run", "--spec=git+https://h/u/r", "tool"},
			wantRunner: RunnerPipx, wantSpec: "git+https://h/u/r", wantAt: 1, wantOK: true},
		{name: "pipx run positional", command: "pipx", args: []string{"run", "tool"},
			wantRunner: RunnerPipx, wantSpec: "tool", wantAt: 1, wantOK: true},

		// cmd /c wrapper: at is the index in the original args
		{name: "cmd /c npx", command: "cmd", args: []string{"/c", "npx", "-y", "user/repo"},
			wantRunner: RunnerNPX, wantSpec: "user/repo", wantAt: 3, wantOK: true},
		{name: "cmd /s /c uvx --from", command: "cmd", args: []string{"/s", "/c", "uvx", "--from", "git+https://h/u/r", "tool"},
			wantRunner: RunnerUVX, wantSpec: "git+https://h/u/r", wantAt: 4, wantOK: true},

		// S3: a non-registry URL spec that ends in ".py" is a repository, not a script
		{name: "uvx --from repo named discord.py", command: "uvx",
			args:       []string{"--from", "git+https://github.com/Rapptz/discord.py", "tool"},
			wantRunner: RunnerUVX, wantSpec: "git+https://github.com/Rapptz/discord.py", wantAt: 1, wantOK: true},
		{name: "uvx --from fragment ends in .py", command: "uvx",
			args:       []string{"--from", "git+https://github.com/u/r.git#subdirectory=a.py"},
			wantRunner: RunnerUVX, wantSpec: "git+https://github.com/u/r.git#subdirectory=a.py", wantAt: 1, wantOK: true},
		{name: "pipx run --spec repo ends in .py", command: "pipx",
			args:       []string{"run", "--spec", "git+https://github.com/u/r.py", "tool"},
			wantRunner: RunnerPipx, wantSpec: "git+https://github.com/u/r.py", wantAt: 2, wantOK: true},
		{name: "uvx https URL ends in .py", command: "uvx", args: []string{"--from", "https://h/script.py"},
			wantRunner: RunnerUVX, wantSpec: "https://h/script.py", wantAt: 1, wantOK: true},

		// not ok
		{name: "npx second -p", command: "npx", args: []string{"-p", "a", "-p", "github:u/r"}},
		{name: "npx -p missing value", command: "npx", args: []string{"-p"}},
		{name: "npx --package= empty", command: "npx", args: []string{"--package="}},
		{name: "npx -c stop flag", command: "npx", args: []string{"-c", "echo hi"}},
		{name: "uvx second --from", command: "uvx", args: []string{"--from", "a", "--from", "git+https://h/u/r"}},
		{name: "uvx --from missing value", command: "uvx", args: []string{"--from"}},
		{name: "uvx --from= empty", command: "uvx", args: []string{"--from="}},
		{name: "pipx second --spec", command: "pipx", args: []string{"run", "--spec", "a", "--spec", "b"}},
		{name: "docker run image", command: "docker", args: []string{"run", "-i", "--rm", "u/r"}},
		{name: "unknown command node", command: "node", args: []string{"server.js"}},
		{name: "empty command", command: "", args: []string{"user/repo"}},
		{name: "bare npx", command: "npx"},
		{name: "npx only flags", command: "npx", args: []string{"-y"}},
		{name: "npx trailing double dash", command: "npx", args: []string{"-y", "--"}},
		{name: "spec with space", command: "npx", args: []string{"github:u/r extra"}},
		{name: "spec with tab", command: "npx", args: []string{"github:u/r\textra"}},
		{name: "spec with newline", command: "npx", args: []string{"github:u/r\n"}},
		{name: "spec with NUL", command: "npx", args: []string{"github:u/r\x00"}},
		{name: "spec with DEL", command: "npx", args: []string{"github:u/r\x7f"}},
		{name: "spec with unicode space", command: "npx", args: []string{"github:u/r\u00a0x"}},
		{name: "spec over maxSpecLen", command: "npx", args: []string{"github:u/" + strings.Repeat("a", maxSpecLen)}},
		{name: "uvx script", command: "uvx", args: []string{"x.py"}},
		{name: "uvx script via --from", command: "uvx", args: []string{"--from", "x.py", "tool"}},
		{name: "pipx run script", command: "pipx", args: []string{"run", "script.py"}},
		{name: "pipx install", command: "pipx", args: []string{"install", "tool"}},
		{name: "pipx no subcommand", command: "pipx"},
		{name: "pipx run no spec", command: "pipx", args: []string{"run"}},
		{name: "cmd without /c", command: "cmd", args: []string{"npx", "user/repo"}},
		{name: "cmd /c without command", command: "cmd", args: []string{"/c"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			runner, spec, at, ok := rawSpecAt(tt.command, tt.args)
			if ok != tt.wantOK {
				t.Fatalf("rawSpecAt(%q, %q) ok = %v, want %v", tt.command, tt.args, ok, tt.wantOK)
			}
			if !ok {
				if runner != "" || spec != "" || at != 0 {
					t.Errorf("rawSpecAt(%q, %q) = (%q, %q, %d, false), want zero values", tt.command, tt.args, runner, spec, at)
				}
				return
			}
			if runner != tt.wantRunner || spec != tt.wantSpec || at != tt.wantAt {
				t.Errorf("rawSpecAt(%q, %q) = (%q, %q, %d), want (%q, %q, %d)",
					tt.command, tt.args, runner, spec, at, tt.wantRunner, tt.wantSpec, tt.wantAt)
			}
			if tt.args[at] != tt.wantSpec && !strings.HasSuffix(tt.args[at], "="+tt.wantSpec) {
				t.Errorf("args[%d] = %q does not hold the spec %q", at, tt.args[at], tt.wantSpec)
			}
		})
	}
}

// nonRegistryUnpinnedCases are the command lines for which nonRegistrySpecUnpinned must be
// true. The strict T5 test reuses them.
func nonRegistryUnpinnedCases() []nonRegistryCase {
	return []nonRegistryCase{
		// npx and bunx: GitHub and other host shorthands
		{"npx github no ref", "npx", []string{"-y", "github:u/r"}},
		{"npx github branch", "npx", []string{"-y", "github:u/r#main"}},
		{"npx github short sha", "npx", []string{"-y", "github:u/r#abc1234"}},
		{"npx github semver", "npx", []string{"-y", "github:u/r#semver:^1.0.0"}},
		{"npx github 41 hex", "npx", []string{"-y", "github:u/r#" + testSHA + "a"}},
		{"npx github 39 hex", "npx", []string{"-y", "github:u/r#" + testSHA[:39]}},
		{"npx github 64 hex", "npx", []string{"-y", "github:u/r#" + strings.Repeat("ab12", 16)}},
		{"npx github 40 chars not hex", "npx", []string{"-y", "github:u/r#" + testSHA[:39] + "g"}},
		{"npx github empty fragment", "npx", []string{"-y", "github:u/r#"}},
		{"npx gitlab", "npx", []string{"gitlab:u/r"}},
		{"npx bitbucket", "npx", []string{"bitbucket:u/r"}},
		{"npx gist", "npx", []string{"gist:abc123"}},
		{"npx shorthand", "npx", []string{"u/r"}},
		{"npx shorthand .git", "npx", []string{"u/r.git"}},
		{"bunx shorthand branch", "bunx", []string{"u/r#main"}},
		{"bunx github", "bunx", []string{"github:u/r"}},
		{"npx mixed case prefix", "npx", []string{"GITHUB:u/r"}},
		{"npx mixed case git+https", "npx", []string{"Git+HTTPS://h/u/r"}},

		// npx: git URLs
		{"npx git+https", "npx", []string{"git+https://github.com/u/r.git"}},
		{"npx git+http", "npx", []string{"git+http://h/u/r.git"}},
		{"npx git+ssh", "npx", []string{"git+ssh://git@github.com/u/r.git"}},
		{"npx git://", "npx", []string{"git://github.com/u/r.git"}},
		{"npx ssh://", "npx", []string{"ssh://git@h/u/r.git"}},
		{"npx scp-like git@", "npx", []string{"git@github.com:u/r.git"}},
		{"npx git+https sha in userinfo", "npx", []string{"git+https://" + testSHA + "@h/u/r"}},
		{"npx git+https short sha fragment", "npx", []string{"git+https://h/u/r#abc1234"}},

		// npx: URLs
		{"npx https tgz", "npx", []string{"https://example.com/x-1.0.0.tgz"}},
		{"npx http tgz", "npx", []string{"http://example.com/x.tgz"}},
		{"npx https no suffix", "npx", []string{"https://example.com/x"}},
		{"npx url ignores sha fragment", "npx", []string{"https://example.com/x.tgz#" + testSHA}},
		{"npx hosted git url no ref", "npx", []string{"https://github.com/u/r"}},
		{"npx hosted git url branch", "npx", []string{"https://github.com/u/r#main"}},
		{"npx hosted git url short sha", "npx", []string{"https://gitlab.com/u/r.git#abc1234"}},
		{"npx hosted git archive ignores sha fragment", "npx", []string{"https://github.com/u/r/archive/main.tar.gz#" + testSHA}},
		{"npx unknown git host ignores sha fragment", "npx", []string{"https://git.example.com/u/r#" + testSHA}},
		{"npx github branch with options", "npx", []string{"github:u/r#main::path:packages/x"}},
		{"npx hosted git url, longer path", "npx", []string{"https://github.com/u/r/tree/main#" + testSHA}},
		{"npx hosted git url, no repo", "npx", []string{"https://github.com/u#" + testSHA}},
		{"uvx --from commit only in the query", "uvx", []string{"--from", "git+https://h/u/r?x=@" + testSHA, "tool"}},

		// npx: alias and flag forms
		{"npx alias github", "npx", []string{"foo@github:u/r"}},
		{"npx alias git+https", "npx", []string{"foo@git+https://h/u/r"}},
		{"npx alias url", "npx", []string{"foo@https://example.com/x.tgz"}},
		{"npx scoped alias github", "npx", []string{"@s/foo@github:u/r"}},
		{"npx -p github", "npx", []string{"-p", "github:u/r", "cmd"}},
		{"npx --package= github", "npx", []string{"--package=github:u/r", "cmd"}},
		{"npx double dash github", "npx", []string{"-y", "--", "github:u/r"}},
		{"cmd /c npx github", "cmd", []string{"/c", "npx", "-y", "github:u/r"}},
		{"cmd /s /c bunx shorthand", "cmd", []string{"/s", "/c", "bunx", "u/r"}},
		{"npx.cmd shorthand", "npx.cmd", []string{"u/r"}},

		// uvx
		{"uvx --from git+https", "uvx", []string{"--from", "git+https://h/u/r", "tool"}},
		{"uvx --from= git+https", "uvx", []string{"--from=git+https://h/u/r", "tool"}},
		{"uvx --from git+http", "uvx", []string{"--from", "git+http://h/u/r", "tool"}},
		{"uvx --from git+git", "uvx", []string{"--from", "git+git://h/u/r", "tool"}},
		{"uvx --from branch", "uvx", []string{"--from", "git+https://h/u/r@main", "tool"}},
		{"uvx --from short sha", "uvx", []string{"--from", "git+https://h/u/r@abc1234", "tool"}},
		{"uvx --from 39 hex", "uvx", []string{"--from", "git+https://h/u/r@" + testSHA[:39], "tool"}},
		{"uvx --from 41 hex", "uvx", []string{"--from", "git+https://h/u/r@" + testSHA + "a", "tool"}},
		{"uvx --from 64 hex", "uvx", []string{"--from", "git+https://h/u/r@" + strings.Repeat("ab12", 16), "tool"}},
		{"uvx --from sha in userinfo", "uvx", []string{"--from", "git+https://" + testSHA + "@h/u/r", "tool"}},
		{"uvx --from sha in host part", "uvx", []string{"--from", "git+https://h@" + testSHA + "/u/r", "tool"}},
		{"uvx --from sha in fragment only", "uvx", []string{"--from", "git+https://h/u/r#" + testSHA, "tool"}},
		{"uvx --from git+ssh", "uvx", []string{"--from", "git+ssh://git@h/u/r", "tool"}},
		{"uvx --from whl", "uvx", []string{"--from", "https://h/x.whl", "tool"}},
		{"uvx --from tar.gz with query", "uvx", []string{"--from", "https://h/x-1.tar.gz?a=1", "tool"}},
		{"uvx --from zip upper case", "uvx", []string{"--from", "HTTP://h/X.ZIP", "tool"}},
		{"uvx --from tgz", "uvx", []string{"--from", "https://h/x.tgz", "tool"}},
		{"uvx --from tar", "uvx", []string{"--from", "https://h/x.tar", "tool"}},
		{"uvx --from tar.bz2", "uvx", []string{"--from", "https://h/x.tar.bz2", "tool"}},
		{"uvx --from tar.xz", "uvx", []string{"--from", "https://h/x.tar.xz", "tool"}},
		{"uvx --from alias with extras", "uvx", []string{"--from", "pkg[extra,more]@git+https://h/u/r", "tool"}},
		{"uvx --from alias git+https", "uvx", []string{"--from", "pkg@git+https://h/u/r", "tool"}},
		{"uvx --from mixed case scheme", "uvx", []string{"--from", "Git+HTTPS://h/u/r", "tool"}},
		{"uvx --from egg fragment", "uvx", []string{"--from", "git+https://h/u/r#egg=x", "tool"}},
		{"cmd /c uvx --from", "cmd", []string{"/c", "uvx", "--from", "git+https://h/u/r", "tool"}},

		// S3: repository names that end in ".py"
		{"uvx --from repo discord.py", "uvx", []string{"--from", "git+https://github.com/Rapptz/discord.py", "tool"}},
		{"uvx --from subdirectory a.py", "uvx", []string{"--from", "git+https://github.com/u/r.git#subdirectory=a.py"}},
		{"pipx --spec repo r.py", "pipx", []string{"run", "--spec", "git+https://github.com/u/r.py", "tool"}},

		// pipx
		{"pipx run --spec", "pipx", []string{"run", "--spec", "git+https://h/u/r", "tool"}},
		{"pipx --verbose run --spec", "pipx", []string{"--verbose", "run", "--spec", "git+https://h/u/r", "tool"}},
		{"pipx run --spec=", "pipx", []string{"run", "--spec=git+https://h/u/r", "tool"}},
		{"pipx run --spec branch", "pipx", []string{"run", "--spec", "git+https://h/u/r@main", "tool"}},
		{"pipx run --spec whl", "pipx", []string{"run", "--spec", "https://h/x.whl", "tool"}},
		{"pipx run --spec mixed case", "pipx", []string{"run", "--spec", "GIT+https://h/u/r", "tool"}},
		{"pipx run positional script url", "pipx", []string{"run", "https://h/script.py"}},
		{"pipx run positional script url upper case", "pipx", []string{"run", "HTTPS://h/SCRIPT.PY"}},
		{"pipx run positional script url with query", "pipx", []string{"run", "https://h/script.py?a=1#frag"}},
	}
}

// nonRegistryFalseCases are the command lines for which nonRegistrySpecUnpinned must
// be false.
func nonRegistryFalseCases() []nonRegistryCase {
	tooLong := "github:u/" + strings.Repeat("a", maxSpecLen)
	return []nonRegistryCase{
		// pinned to a full commit
		{"npx github 40 hex", "npx", []string{"-y", "github:u/r#" + testSHA}},
		{"npx github 40 hex upper", "npx", []string{"-y", "github:u/r#" + sha40Upper}},
		{"npx github 40 hex with options", "npx", []string{"-y", "github:u/r#" + testSHA + "::path:packages/x"}},
		{"npx hosted git url 40 hex", "npx", []string{"https://github.com/u/r#" + testSHA}},
		{"npx hosted git url .git 40 hex", "npx", []string{"https://gitlab.com/u/r.git#" + testSHA}},
		{"npx bitbucket url 40 hex", "npx", []string{"-y", "https://bitbucket.org/u/r#" + testSHA}},
		{"npx hosted git url alias 40 hex", "npx", []string{"foo@https://github.com/u/r#" + testSHA}},
		{"npx hosted git url, token reference as user", "npx", []string{"https://${GH_TOKEN}@github.com/u/r#" + testSHA}},
		{"npx hosted git url, user and password references", "npx", []string{"https://x-access-token:${GH_TOKEN}@github.com/u/r#" + testSHA}},
		{"npx hosted git url, www and port", "npx", []string{"https://www.github.com:443/u/r.git#" + testSHA}},
		{"uvx --from commit in the path, query after it", "uvx", []string{"--from", "git+https://h/u/r@" + testSHA + "?x=1", "tool"}},
		{"uvx --from alias with extras 40 hex", "uvx", []string{"--from", "pkg[extra]@git+https://h/u/r@" + testSHA, "tool"}},
		{"npx gitlab 40 hex", "npx", []string{"gitlab:u/r#" + testSHA}},
		{"bunx shorthand 40 hex", "bunx", []string{"u/r#" + testSHA}},
		{"npx shorthand 40 hex", "npx", []string{"u/r#" + testSHA}},
		{"npx git+https 40 hex", "npx", []string{"git+https://h/u/r#" + testSHA}},
		{"npx git+ssh 40 hex", "npx", []string{"git+ssh://git@h/u/r.git#" + testSHA}},
		{"npx scp-like 40 hex", "npx", []string{"git@h:u/r.git#" + testSHA}},
		{"npx scoped alias 40 hex", "npx", []string{"@s/foo@github:u/r#" + testSHA}},
		{"npx alias 40 hex", "npx", []string{"foo@github:u/r#" + testSHA}},
		{"npx -p github 40 hex", "npx", []string{"-p", "github:u/r#" + testSHA, "cmd"}},
		{"uvx --from git+https @40 hex", "uvx", []string{"--from", "git+https://h/u/r@" + testSHA, "tool"}},
		{"uvx --from git+https @40 hex egg", "uvx", []string{"--from", "git+https://h/u/r@" + testSHA + "#egg=x", "tool"}},
		{"uvx --from git+https @40 hex upper", "uvx", []string{"--from", "git+https://h/u/r@" + sha40Upper, "tool"}},
		{"uvx --from= git+https @40 hex", "uvx", []string{"--from=git+https://h/u/r@" + testSHA, "tool"}},
		{"uvx --from git+ssh @40 hex", "uvx", []string{"--from", "git+ssh://git@h/u/r@" + testSHA, "tool"}},
		{"uvx --from alias @40 hex", "uvx", []string{"--from", "pkg@git+https://h/u/r@" + testSHA, "tool"}},
		{"pipx run --spec= @40 hex", "pipx", []string{"run", "--spec=git+https://h/u/r@" + testSHA, "tool"}},
		{"pipx run --spec @40 hex", "pipx", []string{"run", "--spec", "git+https://h/u/r@" + testSHA, "tool"}},

		// registry specs: the registry check handles them
		{"npx scoped", "npx", []string{"@scope/pkg"}},
		{"npx scoped version", "npx", []string{"@scope/pkg@1.2.3"}},
		{"npx plain", "npx", []string{"pkg"}},
		{"npx plain latest", "npx", []string{"pkg@latest"}},
		{"uvx plain", "uvx", []string{"pkg"}},
		{"uvx --from pkg==1", "uvx", []string{"--from", "pkg==1", "tool"}},
		{"uvx --from pkg", "uvx", []string{"--from", "pkg", "tool"}},
		{"pipx run pkg", "pipx", []string{"run", "pkg"}},

		// local paths
		{"npx ./x", "npx", []string{"./x"}},
		{"npx ../x/y", "npx", []string{"../x/y"}},
		{"npx /abs/x", "npx", []string{"/abs/x"}},
		{"npx ~/x", "npx", []string{"~/x"}},
		{"npx file:", "npx", []string{"file:../x"}},
		{"npx git+file", "npx", []string{"git+file:///x"}},
		{"npx shorthand archive", "npx", []string{"u/r.tgz"}},
		{"npx shorthand tar.gz", "npx", []string{"u/r.tar.gz"}},
		{"npx shorthand tar upper", "npx", []string{"u/r.TAR"}},
		{"npx windows path", "npx", []string{`C:\x`}},
		{"uvx --from ./x", "uvx", []string{"--from", "./x", "tool"}},
		{"uvx --from git+file", "uvx", []string{"--from", "git+file:///x", "tool"}},
		{"uvx --from /abs/x.whl", "uvx", []string{"--from", "/abs/x.whl", "tool"}},

		// doubtful parse or out of scope
		{"npx second -p", "npx", []string{"-p", "a", "-p", "github:u/r"}},
		{"npx -p missing value", "npx", []string{"-p"}},
		{"npx -c stop flag", "npx", []string{"-c", "github:u/r"}},
		{"docker run u/r", "docker", []string{"run", "u/r"}},
		{"docker run github", "docker", []string{"run", "github:u/r"}},
		{"command node", "node", []string{"github:u/r"}},
		{"empty command", "", []string{"github:u/r"}},
		{"bare npx", "npx", nil},
		{"uvx positional git+https", "uvx", []string{"git+https://h/u/r"}},
		{"uvx positional after flag", "uvx", []string{"--isolated", "git+https://h/u/r"}},
		{"uvx tool then --from", "uvx", []string{"tool", "--from", "git+https://h/u/r"}},
		{"pipx run positional git+https", "pipx", []string{"run", "git+https://h/u/r"}},
		{"pipx run positional whl", "pipx", []string{"run", "https://h/x.whl"}},
		{"pipx install --spec", "pipx", []string{"install", "--spec", "git+https://h/u/r"}},
		{"uvx --from https no archive", "uvx", []string{"--from", "https://h/simple"}},
		{"uvx --from https html", "uvx", []string{"--from", "https://h/x.html"}},
		{"uvx --from archive in query only", "uvx", []string{"--from", "https://h/x?f=a.whl"}},
		{"uvx --from second", "uvx", []string{"--from", "a", "--from", "git+https://h/u/r"}},
		{"uvx --from missing value", "uvx", []string{"--from"}},
		{"uvx script", "uvx", []string{"x.py"}},
		{"pipx run script", "pipx", []string{"run", "script.py"}},
		{"cmd without /c", "cmd", []string{"npx", "u/r"}},

		// a prefix with nothing after it
		{"npx github: only", "npx", []string{"github:"}},
		{"npx https:// only", "npx", []string{"https://"}},
		{"npx git+https:// only", "npx", []string{"git+https://"}},
		{"uvx --from git+https:// only", "uvx", []string{"--from", "git+https://"}},
		{"uvx --from https:// only", "uvx", []string{"--from", "https://"}},

		// shorthand shapes that are not "user/repo"
		{"npx a/b/c", "npx", []string{"a/b/c"}},
		{"npx u/", "npx", []string{"u/"}},
		{"npx /r", "npx", []string{"/r"}},
		{"npx -u/r is a flag", "npx", []string{"-u/r"}},
		{"npx _u/r", "npx", []string{"_u/r"}},
		{"npx u/r?x", "npx", []string{"u/r?x"}},
		{"npx unknown scheme", "npx", []string{"ftp://h/x.tgz"}},

		// bad text
		{"spec over maxSpecLen", "npx", []string{tooLong}},
		{"spec with space", "npx", []string{"github:u/r x"}},
		{"spec with newline", "npx", []string{"github:u/r\n"}},
		{"spec with control char", "npx", []string{"github:u/r\x01"}},
		{"uvx --from with space", "uvx", []string{"--from", "git+https://h/u/r x"}},
		{"empty spec", "npx", []string{""}},
	}
}

func TestNonRegistrySpecUnpinned(t *testing.T) {
	t.Parallel()

	for _, tc := range nonRegistryUnpinnedCases() {
		t.Run("unpinned/"+tc.name, func(t *testing.T) {
			t.Parallel()
			if !nonRegistrySpecUnpinned(tc.command, tc.args) {
				t.Errorf("nonRegistrySpecUnpinned(%q, %q) = false, want true", tc.command, tc.args)
			}
		})
	}
	for _, tc := range nonRegistryFalseCases() {
		t.Run("not-flagged/"+tc.name, func(t *testing.T) {
			t.Parallel()
			if nonRegistrySpecUnpinned(tc.command, tc.args) {
				t.Errorf("nonRegistrySpecUnpinned(%q, %q) = true, want false", tc.command, tc.args)
			}
		})
	}
}

// TestNonRegistrySpecStrictT5 checks that ExtractPackage refuses every non-registry spec.
// If it returned a name for one, T5 would compare a guessed name with the popular
// list.
func TestNonRegistrySpecStrictT5(t *testing.T) {
	t.Parallel()

	extra := []nonRegistryCase{
		{"pinned github", "npx", []string{"github:u/r#" + testSHA}},
		{"pinned shorthand", "bunx", []string{"u/r#" + testSHA}},
		{"pinned alias", "npx", []string{"@s/foo@github:u/r#" + testSHA}},
		{"pinned git+https", "npx", []string{"git+https://h/u/r#" + testSHA}},
		{"uvx pinned", "uvx", []string{"--from", "git+https://h/u/r@" + testSHA, "tool"}},
		{"pipx pinned", "pipx", []string{"run", "--spec=git+https://h/u/r@" + testSHA, "tool"}},
		{"npx file", "npx", []string{"file:../x"}},
	}
	for _, tc := range append(nonRegistryUnpinnedCases(), extra...) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if spec, ok := ExtractPackage(tc.command, tc.args); ok {
				t.Errorf("ExtractPackage(%q, %q) = (%+v, true), want false", tc.command, tc.args, spec)
			}
		})
	}
}

// TestNonRegistrySpecLeak builds a server whose npx arg is a tarball URL with
// credentials and checks that the T4-003 finding holds none of them.
func TestNonRegistrySpecLeak(t *testing.T) {
	t.Parallel()

	const (
		secret = "SECRETTOKEN123"
		host   = "host.example"
	)
	arg := "https://user:" + secret + "@" + host + "/x.tgz"
	if !nonRegistrySpecUnpinned("npx", []string{arg}) {
		t.Fatal("nonRegistrySpecUnpinned() = false, want true for a URL with credentials")
	}

	s := discover.Server{
		Name:      "srv",
		Transport: discover.TransportStdio,
		Command:   "npx",
		Args:      discover.NewArgs([]string{"-y", arg}),
	}
	findings := CheckConfig(s)

	var unpinned []Finding
	for _, f := range findings {
		if f.RuleID == RuleUnpinnedPackage {
			unpinned = append(unpinned, f)
		}
	}
	if len(unpinned) != 1 {
		t.Fatalf("CheckConfig() has %d %s findings, want 1: %+v", len(unpinned), RuleUnpinnedPackage, findings)
	}
	if got := unpinned[0].Related; got != "" {
		t.Errorf("Related = %q, want empty for a URL spec", got)
	}

	for _, f := range findings {
		assertFindingNoLeak(t, f, secret, host, "user:")
	}
}

func FuzzNonRegistrySpec(f *testing.F) {
	for _, tc := range append(nonRegistryUnpinnedCases(), nonRegistryFalseCases()...) {
		for _, a := range tc.args {
			f.Add(tc.command, a)
		}
	}
	f.Add("npx", "https://user:SECRETTOKEN123@host.example/x.tgz")
	f.Add("cmd", "/c")
	f.Add("uvx", "--from")
	f.Add("pipx", "run")
	f.Add("npx", "@")
	f.Add("npx", "@@")
	f.Add("npx", "#")
	f.Add("uvx", "@git+https://h/u/r")
	f.Add("uvx", "git+https:///@")

	f.Fuzz(func(t *testing.T, command, spec string) {
		lines := []struct {
			command string
			args    []string
		}{
			{command, []string{spec}},
			{command, []string{"-y", spec}},
			{"npx", []string{"-y", spec}},
			{"npx", []string{"-p", spec, "cmd"}},
			{"bunx", []string{spec}},
			{"uvx", []string{"--from", spec, "tool"}},
			{"uvx", []string{"--from=" + spec, "tool"}},
			{"pipx", []string{"run", "--spec", spec, "tool"}},
			{"pipx", []string{"--verbose", "run", "--spec=" + spec}},
			{"cmd", []string{"/c", command, spec}},
			{"cmd", []string{"/c", "npx", "-y", spec}},
		}
		for _, l := range lines {
			got := nonRegistrySpecUnpinned(l.command, l.args)
			// A non-registry spec is never a registry package: T5 must not see a name.
			if got {
				if pkg, ok := ExtractPackage(l.command, l.args); ok {
					t.Fatalf("nonRegistrySpecUnpinned true and ExtractPackage ok for (%q, %q): %+v", l.command, l.args, pkg)
				}
			}
		}
	})
}
