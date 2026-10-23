package rules

import (
	"strings"
	"testing"
)

// testDigest is a valid sha256 image digest for the docker cases.
var testDigest = "sha256:" + strings.Repeat("ab12", 16)

func TestExtractPackage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		command string
		args    []string
		want    PackageSpec // checked only when ok is true
		ok      bool
		// unpinned is checked only when ok is true.
		unpinned bool
	}{
		// npx
		{name: "npx scoped latest", command: "npx", args: []string{"-y", "@scope/server@latest"},
			want: PackageSpec{RunnerNPX, "@scope/server", "latest"}, ok: true, unpinned: true},
		{name: "npx scoped pinned", command: "npx", args: []string{"-y", "@scope/server@1.4.2"},
			want: PackageSpec{RunnerNPX, "@scope/server", "1.4.2"}, ok: true},
		{name: "npx scoped no version", command: "npx", args: []string{"@scope/server"},
			want: PackageSpec{RunnerNPX, "@scope/server", ""}, ok: true, unpinned: true},
		{name: "npx plain no version", command: "npx", args: []string{"some-pkg"},
			want: PackageSpec{RunnerNPX, "some-pkg", ""}, ok: true, unpinned: true},
		{name: "npx LATEST any case", command: "npx", args: []string{"some-pkg@LATEST"},
			want: PackageSpec{RunnerNPX, "some-pkg", "LATEST"}, ok: true, unpinned: true},
		{name: "npx --yes pinned", command: "npx", args: []string{"--yes", "pkg@1.0.0"},
			want: PackageSpec{RunnerNPX, "pkg", "1.0.0"}, ok: true},
		{name: "npx -p overrides", command: "npx", args: []string{"-p", "pkg@1.0.0", "cmd"},
			want: PackageSpec{RunnerNPX, "pkg", "1.0.0"}, ok: true},
		{name: "npx -p unpinned beats pinned command", command: "npx", args: []string{"-p", "pkg", "cmd@1.0.0"},
			want: PackageSpec{RunnerNPX, "pkg", ""}, ok: true, unpinned: true},
		{name: "npx --package= overrides", command: "npx", args: []string{"--package=pkg@latest", "bin"},
			want: PackageSpec{RunnerNPX, "pkg", "latest"}, ok: true, unpinned: true},
		{name: "npx --package value", command: "npx", args: []string{"--package", "pkg@2", "bin"},
			want: PackageSpec{RunnerNPX, "pkg", "2"}, ok: true},
		{name: "npx valued flag skipped", command: "npx", args: []string{"--registry", "https://r.example", "pkg@1"},
			want: PackageSpec{RunnerNPX, "pkg", "1"}, ok: true},
		{name: "npx valued flag with equals", command: "npx", args: []string{"--registry=https://r.example", "pkg"},
			want: PackageSpec{RunnerNPX, "pkg", ""}, ok: true, unpinned: true},
		{name: "npx double dash", command: "npx", args: []string{"--", "pkg@1.0.0"},
			want: PackageSpec{RunnerNPX, "pkg", "1.0.0"}, ok: true},
		{name: "npx flag then double dash", command: "npx", args: []string{"-y", "--", "pkg"},
			want: PackageSpec{RunnerNPX, "pkg", ""}, ok: true, unpinned: true},
		{name: "npx range counts as pinned", command: "npx", args: []string{"pkg@^1.2.0"},
			want: PackageSpec{RunnerNPX, "pkg", "^1.2.0"}, ok: true},
		{name: "npx command path", command: "/usr/local/bin/npx", args: []string{"pkg"},
			want: PackageSpec{RunnerNPX, "pkg", ""}, ok: true, unpinned: true},
		{name: "npx.cmd", command: "npx.cmd", args: []string{"pkg@1"},
			want: PackageSpec{RunnerNPX, "pkg", "1"}, ok: true},
		{name: "NPX.EXE upper case", command: `NPX.EXE`, args: []string{"pkg@1"},
			want: PackageSpec{RunnerNPX, "pkg", "1"}, ok: true},
		{name: "npx -c is doubtful", command: "npx", args: []string{"-c", "echo hi"}},
		{name: "npx --call is doubtful", command: "npx", args: []string{"--call=echo hi"}},
		{name: "npx no args", command: "npx"},
		{name: "npx only flags", command: "npx", args: []string{"-y"}},
		{name: "npx trailing double dash", command: "npx", args: []string{"-y", "--"}},
		{name: "npx lone dash", command: "npx", args: []string{"-"}},
		{name: "npx -p without value", command: "npx", args: []string{"-p"}},
		{name: "npx --package= empty", command: "npx", args: []string{"--package="}},
		{name: "npx relative path", command: "npx", args: []string{"./local"}},
		{name: "npx parent path", command: "npx", args: []string{"../local"}},
		{name: "npx absolute path", command: "npx", args: []string{"/abs/path"}},
		{name: "npx home path", command: "npx", args: []string{"~/pkg"}},
		{name: "npx windows path", command: "npx", args: []string{`C:\pkg`}},
		{name: "npx file url", command: "npx", args: []string{"file:../x"}},
		{name: "npx https url", command: "npx", args: []string{"https://x/y.tgz"}},
		{name: "npx git+ url", command: "npx", args: []string{"git+https://x/y.git"}},
		{name: "npx github prefix", command: "npx", args: []string{"github:user/repo"}},
		{name: "npx github shorthand", command: "npx", args: []string{"user/repo"}},
		{name: "npx npm alias", command: "npx", args: []string{"npm:other@1"}},
		{name: "npx git ref in version", command: "npx", args: []string{"pkg@user/repo"}},
		{name: "npx empty version", command: "npx", args: []string{"pkg@"}},
		{name: "npx scope only", command: "npx", args: []string{"@scope"}},
		{name: "npx scope empty package", command: "npx", args: []string{"@scope/"}},
		{name: "npx tgz archive", command: "npx", args: []string{"pkg.tgz"}},
		{name: "npx spec with space", command: "npx", args: []string{"pkg --flag"}},
		{name: "npx spec with newline", command: "npx", args: []string{"pkg\n@1"}},
		{name: "npx spec too long", command: "npx", args: []string{strings.Repeat("a", maxSpecLen+1)}},

		// npx: names must fit the npm charset. A token-like prefix does not
		// reject a name (see the token-prefix cases below).
		{name: "npx upper case name", command: "npx", args: []string{"Pkg"}},
		{name: "npx upper case scope", command: "npx", args: []string{"@Scope/pkg"}},
		{name: "npx name starts with underscore", command: "npx", args: []string{"_pkg"}},
		{name: "npx scoped name starts with underscore", command: "npx", args: []string{"@scope/_pkg"}},
		{name: "npx scoped name starts with dot", command: "npx", args: []string{"@scope/.pkg"}},
		{name: "npx name with quote", command: "npx", args: []string{"pk'g"}},
		{name: "npx name with comma", command: "npx", args: []string{"a,b"}},
		{name: "npx name with percent", command: "npx", args: []string{"p%kg"}},
		{name: "npx non-ASCII name", command: "npx", args: []string{"pkg\u00e9"}},
		{name: "npx name with tilde", command: "npx", args: []string{"a~b"},
			want: PackageSpec{RunnerNPX, "a~b", ""}, ok: true, unpinned: true},
		{name: "npx name with dots and digits", command: "npx", args: []string{"@scope/a.b_c-1"},
			want: PackageSpec{RunnerNPX, "@scope/a.b_c-1", ""}, ok: true, unpinned: true},

		// A token-like prefix in a name does not reject it: an attacker can
		// publish "@xoxo/server-filesystem". Findings never carry the name
		// unless discover.RedactArgs shows it (see TestCheckConfigNoLeak).
		{name: "npx scope with xox prefix", command: "npx", args: []string{"-y", "@xoxo/server-filesystem"},
			want: PackageSpec{RunnerNPX, "@xoxo/server-filesystem", ""}, ok: true, unpinned: true},
		{name: "npx scope with eyj prefix", command: "npx", args: []string{"-y", "@eyjay/server-github"},
			want: PackageSpec{RunnerNPX, "@eyjay/server-github", ""}, ok: true, unpinned: true},
		{name: "npx name with sk- prefix", command: "npx", args: []string{"sk-server"},
			want: PackageSpec{RunnerNPX, "sk-server", ""}, ok: true, unpinned: true},
		{name: "npx lower-case token after unknown flag", command: "npx", args: []string{"--token", "ghp_secretsecret0123", "pkg"},
			want: PackageSpec{RunnerNPX, "ghp_secretsecret0123", ""}, ok: true, unpinned: true},
		{name: "npx upper-case token is not an npm name", command: "npx", args: []string{"--token", "ghp_SECRETSECRET", "pkg"}},
		{name: "npx token in scope", command: "npx", args: []string{"@ghp_secretsecret0123/pkg"},
			want: PackageSpec{RunnerNPX, "@ghp_secretsecret0123/pkg", ""}, ok: true, unpinned: true},
		{name: "uvx lower-case token after unknown flag", command: "uvx", args: []string{"--token", "ghp_secretsecret0123", "pkg"},
			want: PackageSpec{RunnerUVX, "ghp_secretsecret0123", ""}, ok: true, unpinned: true},
		{name: "pipx token-like name after unknown flag", command: "pipx", args: []string{"run", "--token", "ghp_SECRETSECRET", "pkg"},
			want: PackageSpec{RunnerPipx, "ghp_SECRETSECRET", ""}, ok: true, unpinned: true},
		{name: "docker lower-case token after unknown flag", command: "docker", args: []string{"run", "--token", "ghp_secretsecret0123", "image"},
			want: PackageSpec{RunnerDocker, "ghp_secretsecret0123", ""}, ok: true, unpinned: true},
		{name: "docker upper-case token is not an image", command: "docker", args: []string{"run", "--token", "ghp_SECRETSECRET", "image"}},

		// npx: value-taking flags must not steer the parse.
		{name: "npx --loglevel value skipped", command: "npx", args: []string{"--loglevel", "silent", "@evil/server-filesystem"},
			want: PackageSpec{RunnerNPX, "@evil/server-filesystem", ""}, ok: true, unpinned: true},
		{name: "npx -w value skipped", command: "npx", args: []string{"-w", "ws", "pkg@1"},
			want: PackageSpec{RunnerNPX, "pkg", "1"}, ok: true},
		{name: "npx --workspace value skipped", command: "npx", args: []string{"--workspace", "ws", "pkg@1"},
			want: PackageSpec{RunnerNPX, "pkg", "1"}, ok: true},
		{name: "npx --shell value skipped", command: "npx", args: []string{"--shell", "bash", "pkg"},
			want: PackageSpec{RunnerNPX, "pkg", ""}, ok: true, unpinned: true},
		{name: "npx --script-shell value skipped", command: "npx", args: []string{"--script-shell", "sh", "pkg"},
			want: PackageSpec{RunnerNPX, "pkg", ""}, ok: true, unpinned: true},
		{name: "npx --globalconfig value skipped", command: "npx", args: []string{"--globalconfig", "rc", "pkg"},
			want: PackageSpec{RunnerNPX, "pkg", ""}, ok: true, unpinned: true},
		{name: "npx --otp value skipped", command: "npx", args: []string{"--otp", "123456", "pkg"},
			want: PackageSpec{RunnerNPX, "pkg", ""}, ok: true, unpinned: true},
		{name: "npx --tag value skipped", command: "npx", args: []string{"--tag", "next", "pkg"},
			want: PackageSpec{RunnerNPX, "pkg", ""}, ok: true, unpinned: true},
		{name: "npx --loglevel= keeps next word", command: "npx", args: []string{"--loglevel=silent", "pkg"},
			want: PackageSpec{RunnerNPX, "pkg", ""}, ok: true, unpinned: true},

		// bunx
		{name: "bunx --cwd value skipped", command: "bunx", args: []string{"--cwd", "dir", "pkg@1"},
			want: PackageSpec{RunnerBunx, "pkg", "1"}, ok: true},
		{name: "bunx --registry value skipped", command: "bunx", args: []string{"--registry", "https://r.example", "pkg"},
			want: PackageSpec{RunnerBunx, "pkg", ""}, ok: true, unpinned: true},
		{name: "bunx --bun is boolean", command: "bunx", args: []string{"--bun", "pkg@1"},
			want: PackageSpec{RunnerBunx, "pkg", "1"}, ok: true},
		{name: "bunx -p overrides", command: "bunx", args: []string{"-p", "pkg@1", "cmd"},
			want: PackageSpec{RunnerBunx, "pkg", "1"}, ok: true},
		// In Bun, -c/--config is the path of the bunfig file.
		{name: "bunx --config value skipped", command: "bunx", args: []string{"--config", "bunfig.toml", "pkg@latest"},
			want: PackageSpec{RunnerBunx, "pkg", "latest"}, ok: true, unpinned: true},
		{name: "bunx pinned", command: "bunx", args: []string{"pkg@1.2.3"},
			want: PackageSpec{RunnerBunx, "pkg", "1.2.3"}, ok: true},
		{name: "bunx unpinned", command: "bunx", args: []string{"pkg"},
			want: PackageSpec{RunnerBunx, "pkg", ""}, ok: true, unpinned: true},
		{name: "bunx flag and latest", command: "bunx", args: []string{"--bun", "@scope/pkg@latest"},
			want: PackageSpec{RunnerBunx, "@scope/pkg", "latest"}, ok: true, unpinned: true},
		{name: "bunx local path", command: "bunx", args: []string{"./x"}},

		// uvx
		{name: "uvx no version", command: "uvx", args: []string{"some-server"},
			want: PackageSpec{RunnerUVX, "some-server", ""}, ok: true, unpinned: true},
		{name: "uvx == pinned", command: "uvx", args: []string{"some-server==0.3.1"},
			want: PackageSpec{RunnerUVX, "some-server", "0.3.1"}, ok: true},
		{name: "uvx @latest", command: "uvx", args: []string{"some-server@latest"},
			want: PackageSpec{RunnerUVX, "some-server", "latest"}, ok: true, unpinned: true},
		{name: "uvx @ pinned", command: "uvx", args: []string{"some-server@0.3.1"},
			want: PackageSpec{RunnerUVX, "some-server", "0.3.1"}, ok: true},
		{name: "uvx --from pinned", command: "uvx", args: []string{"--from", "some-server==1.0", "cmd"},
			want: PackageSpec{RunnerUVX, "some-server", "1.0"}, ok: true},
		{name: "uvx --from= unpinned", command: "uvx", args: []string{"--from=some-server", "cmd"},
			want: PackageSpec{RunnerUVX, "some-server", ""}, ok: true, unpinned: true},
		{name: "uvx extras pinned", command: "uvx", args: []string{"pkg[extra]==1.0"},
			want: PackageSpec{RunnerUVX, "pkg", "1.0"}, ok: true},
		{name: "uvx extras unpinned", command: "uvx", args: []string{"pkg[extra]"},
			want: PackageSpec{RunnerUVX, "pkg", ""}, ok: true, unpinned: true},
		{name: "uvx range counts as pinned", command: "uvx", args: []string{"pkg>=1.0"},
			want: PackageSpec{RunnerUVX, "pkg", ">=1.0"}, ok: true},
		{name: "uvx compatible release", command: "uvx", args: []string{"pkg~=1.4"},
			want: PackageSpec{RunnerUVX, "pkg", "~=1.4"}, ok: true},
		{name: "uvx valued flag skipped", command: "uvx", args: []string{"--python", "3.12", "pkg==2"},
			want: PackageSpec{RunnerUVX, "pkg", "2"}, ok: true},
		{name: "uvx --with value skipped", command: "uvx", args: []string{"--with", "x", "pkg"},
			want: PackageSpec{RunnerUVX, "pkg", ""}, ok: true, unpinned: true},
		{name: "uvx -w value skipped", command: "uvx", args: []string{"-w", "x", "pkg==1"},
			want: PackageSpec{RunnerUVX, "pkg", "1"}, ok: true},
		{name: "uvx --with-requirements value skipped", command: "uvx", args: []string{"--with-requirements", "r.txt", "pkg"},
			want: PackageSpec{RunnerUVX, "pkg", ""}, ok: true, unpinned: true},
		{name: "uvx --index-url value skipped", command: "uvx", args: []string{"--index-url", "https://i.example/simple", "pkg"},
			want: PackageSpec{RunnerUVX, "pkg", ""}, ok: true, unpinned: true},
		{name: "uvx --constraints value skipped", command: "uvx", args: []string{"--constraints", "c.txt", "pkg"},
			want: PackageSpec{RunnerUVX, "pkg", ""}, ok: true, unpinned: true},
		{name: "uvx --directory value skipped", command: "uvx", args: []string{"--directory", "dir", "pkg"},
			want: PackageSpec{RunnerUVX, "pkg", ""}, ok: true, unpinned: true},
		{name: "uvx --resolution value skipped", command: "uvx", args: []string{"--resolution", "lowest", "pkg"},
			want: PackageSpec{RunnerUVX, "pkg", ""}, ok: true, unpinned: true},
		{name: "uvx --compile-bytecode is boolean", command: "uvx", args: []string{"--compile-bytecode", "pkg"},
			want: PackageSpec{RunnerUVX, "pkg", ""}, ok: true, unpinned: true},
		{name: "uvx command path", command: "/home/u/.local/bin/uvx", args: []string{"pkg"},
			want: PackageSpec{RunnerUVX, "pkg", ""}, ok: true, unpinned: true},
		{name: "uvx script", command: "uvx", args: []string{"script.py"}},
		{name: "uvx no args", command: "uvx"},
		{name: "uvx git url", command: "uvx", args: []string{"--from", "git+https://x/y.git", "cmd"}},
		{name: "uvx path", command: "uvx", args: []string{"./pkg"}},
		{name: "uvx operator without version", command: "uvx", args: []string{"pkg=="}},
		{name: "uvx unclosed extras", command: "uvx", args: []string{"pkg[extra==1"}},
		{name: "uvx marker", command: "uvx", args: []string{"pkg==1;python_version>'3'"}},

		{name: "uvx name with invalid char", command: "uvx", args: []string{"pk$g"}},
		{name: "uvx name with comma", command: "uvx", args: []string{"a,b"}},
		{name: "uvx name ends with dot", command: "uvx", args: []string{"pkg."}},
		{name: "uvx name ends with underscore", command: "uvx", args: []string{"pkg_"}},
		{name: "uvx name starts with underscore", command: "uvx", args: []string{"_pkg"}},
		{name: "uvx upper case name is valid on PyPI", command: "uvx", args: []string{"Some_Server"},
			want: PackageSpec{RunnerUVX, "Some_Server", ""}, ok: true, unpinned: true},

		// pipx
		{name: "pipx run unpinned", command: "pipx", args: []string{"run", "pkg"},
			want: PackageSpec{RunnerPipx, "pkg", ""}, ok: true, unpinned: true},
		{name: "pipx run pinned", command: "pipx", args: []string{"run", "pkg==1.0"},
			want: PackageSpec{RunnerPipx, "pkg", "1.0"}, ok: true},
		{name: "pipx run --spec", command: "pipx", args: []string{"run", "--spec", "pkg==1.0", "cmd"},
			want: PackageSpec{RunnerPipx, "pkg", "1.0"}, ok: true},
		{name: "pipx run --spec= unpinned", command: "pipx", args: []string{"run", "--spec=pkg", "cmd"},
			want: PackageSpec{RunnerPipx, "pkg", ""}, ok: true, unpinned: true},
		{name: "pipx run --python value skipped", command: "pipx", args: []string{"run", "--python", "python3.12", "pkg"},
			want: PackageSpec{RunnerPipx, "pkg", ""}, ok: true, unpinned: true},
		{name: "pipx run --pip-args value skipped", command: "pipx", args: []string{"run", "--pip-args", "--pre", "pkg"},
			want: PackageSpec{RunnerPipx, "pkg", ""}, ok: true, unpinned: true},
		{name: "pipx run --index-url value skipped", command: "pipx", args: []string{"run", "--index-url", "https://i.example", "pkg"},
			want: PackageSpec{RunnerPipx, "pkg", ""}, ok: true, unpinned: true},
		{name: "pipx run --editable is boolean", command: "pipx", args: []string{"run", "--editable", "pkg"},
			want: PackageSpec{RunnerPipx, "pkg", ""}, ok: true, unpinned: true},
		{name: "pipx run --fetch-missing-python is boolean", command: "pipx", args: []string{"run", "--fetch-missing-python", "pkg"},
			want: PackageSpec{RunnerPipx, "pkg", ""}, ok: true, unpinned: true},
		{name: "pipx install", command: "pipx", args: []string{"install", "pkg"}},
		{name: "pipx run @ is not valid", command: "pipx", args: []string{"run", "pkg@1"}},
		{name: "pipx run script", command: "pipx", args: []string{"run", "script.py"}},
		{name: "pipx run alone", command: "pipx", args: []string{"run"}},
		{name: "pipx no args", command: "pipx"},
		{name: "pipx name with invalid char", command: "pipx", args: []string{"run", "pk#g"}},
		{name: "pipx flag before run", command: "pipx", args: []string{"--quiet", "run", "pkg"},
			want: PackageSpec{RunnerPipx, "pkg", ""}, ok: true, unpinned: true},

		// docker
		{name: "docker no tag", command: "docker", args: []string{"run", "-i", "--rm", "image"},
			want: PackageSpec{RunnerDocker, "image", ""}, ok: true, unpinned: true},
		{name: "docker latest", command: "docker", args: []string{"run", "image:latest"},
			want: PackageSpec{RunnerDocker, "image", "latest"}, ok: true, unpinned: true},
		{name: "docker tag", command: "docker", args: []string{"run", "image:1.2"},
			want: PackageSpec{RunnerDocker, "image", "1.2"}, ok: true},
		{name: "docker digest", command: "docker", args: []string{"run", "image@" + testDigest},
			want: PackageSpec{RunnerDocker, "image", testDigest}, ok: true},
		{name: "docker tag and digest", command: "docker", args: []string{"run", "image:1@" + testDigest},
			want: PackageSpec{RunnerDocker, "image", testDigest}, ok: true},
		{name: "docker value flags skipped", command: "docker", args: []string{"run", "-e", "TOKEN", "-v", "/a:/b", "image:1.0"},
			want: PackageSpec{RunnerDocker, "image", "1.0"}, ok: true},
		{name: "docker --env=", command: "docker", args: []string{"run", "--env=X=1", "image"},
			want: PackageSpec{RunnerDocker, "image", ""}, ok: true, unpinned: true},
		{name: "docker registry port no tag", command: "docker", args: []string{"run", "localhost:5000/img"},
			want: PackageSpec{RunnerDocker, "localhost:5000/img", ""}, ok: true, unpinned: true},
		{name: "docker registry port tag", command: "docker", args: []string{"run", "localhost:5000/img:2"},
			want: PackageSpec{RunnerDocker, "localhost:5000/img", "2"}, ok: true},
		{name: "docker ghcr unpinned", command: "docker", args: []string{"run", "-i", "ghcr.io/github/github-mcp-server"},
			want: PackageSpec{RunnerDocker, "ghcr.io/github/github-mcp-server", ""}, ok: true, unpinned: true},
		{name: "docker container run", command: "docker", args: []string{"container", "run", "image:1"},
			want: PackageSpec{RunnerDocker, "image", "1"}, ok: true},
		{name: "docker global flag", command: "docker", args: []string{"--context", "remote", "run", "image:1"},
			want: PackageSpec{RunnerDocker, "image", "1"}, ok: true},
		{name: "docker double dash before image", command: "docker", args: []string{"run", "--rm", "--", "image:1"},
			want: PackageSpec{RunnerDocker, "image", "1"}, ok: true},
		{name: "docker.exe path", command: `/usr/bin/docker.exe`, args: []string{"run", "image"},
			want: PackageSpec{RunnerDocker, "image", ""}, ok: true, unpinned: true},
		{name: "docker --ip value skipped", command: "docker", args: []string{"run", "--ip", "10.0.0.1", "realimage"},
			want: PackageSpec{RunnerDocker, "realimage", ""}, ok: true, unpinned: true},
		{name: "docker --ip6 value skipped", command: "docker", args: []string{"run", "--ip6", "fd00::1", "realimage"},
			want: PackageSpec{RunnerDocker, "realimage", ""}, ok: true, unpinned: true},
		{name: "docker memory flags value skipped", command: "docker", args: []string{"run", "--memory-swap", "2g", "--memory-reservation", "1g", "realimage:1"},
			want: PackageSpec{RunnerDocker, "realimage", "1"}, ok: true},
		{name: "docker dns flags value skipped", command: "docker", args: []string{"run", "--dns", "8.8.8.8", "--dns-search", "example.com", "--dns-option", "ndots:1", "realimage"},
			want: PackageSpec{RunnerDocker, "realimage", ""}, ok: true, unpinned: true},
		{name: "docker cpu flags value skipped", command: "docker", args: []string{"run", "--cpu-period", "100000", "--cpu-quota", "50000", "--cpuset-cpus", "0-1", "--cpuset-mems", "0", "realimage"},
			want: PackageSpec{RunnerDocker, "realimage", ""}, ok: true, unpinned: true},
		{name: "docker security flags value skipped", command: "docker", args: []string{"run", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--oom-score-adj", "500", "realimage"},
			want: PackageSpec{RunnerDocker, "realimage", ""}, ok: true, unpinned: true},
		{name: "docker health flags value skipped", command: "docker", args: []string{"run", "--health-cmd", "true", "--health-start-period", "5s", "realimage"},
			want: PackageSpec{RunnerDocker, "realimage", ""}, ok: true, unpinned: true},
		{name: "docker cgroup flags value skipped", command: "docker", args: []string{"run", "--cgroup-parent", "grp", "--blkio-weight", "300", "--device-cgroup-rule", "c 1:3 mr", "realimage"},
			want: PackageSpec{RunnerDocker, "realimage", ""}, ok: true, unpinned: true},
		{name: "docker storage and volume flags value skipped", command: "docker", args: []string{"run", "--storage-opt", "size=1G", "--volume-driver", "local", "--domainname", "example.com", "realimage"},
			want: PackageSpec{RunnerDocker, "realimage", ""}, ok: true, unpinned: true},
		{name: "docker umask value skipped", command: "docker", args: []string{"run", "--umask", "0022", "-i", "realimage:1.0"},
			want: PackageSpec{RunnerDocker, "realimage", "1.0"}, ok: true},
		{name: "docker IP address is not an image", command: "docker", args: []string{"run", "10.0.0.1"}},
		{name: "docker IP address with tag is not an image", command: "docker", args: []string{"run", "10.0.0.1:8080"}},
		{name: "docker number is not an image", command: "docker", args: []string{"run", "42"}},
		{name: "docker ps", command: "docker", args: []string{"ps"}},
		{name: "docker run alone", command: "docker", args: []string{"run"}},
		{name: "docker only flags after run", command: "docker", args: []string{"run", "-it", "--rm"}},
		{name: "docker no args", command: "docker"},
		{name: "docker container ps", command: "docker", args: []string{"container", "ps"}},
		{name: "docker container alone", command: "docker", args: []string{"container"}},
		{name: "docker empty tag", command: "docker", args: []string{"run", "image:"}},
		{name: "docker bad digest algorithm", command: "docker", args: []string{"run", "image@md5:abc"}},
		{name: "docker digest without hex", command: "docker", args: []string{"run", "image@sha256:"}},
		{name: "docker local path", command: "docker", args: []string{"run", "./image"}},

		{name: "docker upper case image", command: "docker", args: []string{"run", "Image"}},
		{name: "docker upper case path", command: "docker", args: []string{"run", "ghcr.io/Org/img:1"}},
		// A registry host ignores case; the path after it must be lower case.
		{name: "docker upper case registry", command: "docker", args: []string{"run", "GHCR.io/org/img"},
			want: PackageSpec{RunnerDocker, "GHCR.io/org/img", ""}, ok: true, unpinned: true},
		{name: "docker upper case path", command: "docker", args: []string{"run", "ghcr.io/Org/img"}},
		{name: "docker empty path component", command: "docker", args: []string{"run", "a//b"}},
		{name: "docker dot-dot component", command: "docker", args: []string{"run", "a/../b"}},
		{name: "docker component starts with dash char", command: "docker", args: []string{"run", "a/-b"}},
		{name: "docker invalid char", command: "docker", args: []string{"run", "im$age"}},
		{name: "docker bad registry port", command: "docker", args: []string{"run", "host:port/img"}},
		{name: "docker registry with port and tag", command: "docker", args: []string{"run", "my-registry.example.com:5000/team/img:1.0"},
			want: PackageSpec{RunnerDocker, "my-registry.example.com:5000/team/img", "1.0"}, ok: true},

		// other commands
		{name: "node", command: "node", args: []string{"server.js"}},
		{name: "python", command: "python", args: []string{"-m", "server"}},
		{name: "uv tool run not covered", command: "uv", args: []string{"tool", "run", "pkg"}},
		{name: "pnpm dlx not covered", command: "pnpm", args: []string{"dlx", "pkg"}},
		{name: "empty command", command: "", args: []string{"pkg"}},
		{name: "npx-like name", command: "mynpx", args: []string{"pkg"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := ExtractPackage(tt.command, tt.args)
			if ok != tt.ok {
				t.Fatalf("ExtractPackage(%q, %q) ok = %v, want %v (spec %+v)", tt.command, tt.args, ok, tt.ok, got)
			}
			if !ok {
				if got != (PackageSpec{}) {
					t.Errorf("ExtractPackage(%q, %q) = %+v with ok false, want zero value", tt.command, tt.args, got)
				}
				return
			}
			if got != tt.want {
				t.Errorf("ExtractPackage(%q, %q) = %+v, want %+v", tt.command, tt.args, got, tt.want)
			}
			if got.Unpinned() != tt.unpinned {
				t.Errorf("ExtractPackage(%q, %q).Unpinned() = %v, want %v", tt.command, tt.args, got.Unpinned(), tt.unpinned)
			}
		})
	}
}

func TestUnpinned(t *testing.T) {
	t.Parallel()

	tests := []struct {
		runner  Runner
		version string
		want    bool
	}{
		{RunnerNPX, "", true},
		{RunnerNPX, "latest", true},
		{RunnerNPX, "LATEST", true},
		{RunnerNPX, "Latest", true},
		{RunnerNPX, "*", true},
		{RunnerNPX, "x", true},
		{RunnerBunx, "X", true},
		{RunnerNPX, "1.0.0", false},
		{RunnerNPX, "latest1", false},
		{RunnerNPX, "not-latest", false},
		{RunnerNPX, ">=1.0", false},
		{RunnerNPX, "^1.2", false},
		{RunnerNPX, "1.x", false},
		{RunnerUVX, "", true},
		{RunnerUVX, "x", false},
		{RunnerDocker, "latest", true},
		{RunnerDocker, "x", false},
		{RunnerDocker, testDigest, false},
		{RunnerUVX, "!=1.0", true},
		{RunnerUVX, "!=1.0,>=0.5", false},
	}
	for _, tt := range tests {
		t.Run(string(tt.runner)+" version "+tt.version, func(t *testing.T) {
			t.Parallel()
			spec := PackageSpec{Runner: tt.runner, Version: tt.version}
			if got := spec.Unpinned(); got != tt.want {
				t.Errorf("%+v.Unpinned() = %v, want %v", spec, got, tt.want)
			}
		})
	}
}

// TestPackageAt checks the index of the spec argument, which launchKey and
// the MOAT-T4-003 Related gate use.
func TestPackageAt(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		command string
		args    []string
		wantAt  int
		ok      bool
	}{
		{"npx positional", "npx", []string{"-y", "pkg-a"}, 1, true},
		{"npx --package=", "npx", []string{"--package=pkg-a", "bin"}, 0, true},
		{"npx -p value", "npx", []string{"-y", "-p", "pkg-a", "bin"}, 2, true},
		{"npx after --", "npx", []string{"--", "pkg-a"}, 1, true},
		{"npx server -p after the command", "npx", []string{"-p", "pkg-a", "bin", "-p", "3000"}, 1, true},
		{"npx second -p is doubtful", "npx", []string{"-p", "pkg-a", "-p", "pkg-b", "bin"}, 0, false},
		{"npx second --package= is doubtful", "npx", []string{"--package=pkg-a", "--package=pkg-b", "bin"}, 0, false},
		{"pipx run", "pipx", []string{"run", "pkg-a"}, 1, true},
		{"pipx run --spec", "pipx", []string{"run", "--spec", "pkg-a", "bin"}, 2, true},
		{"uvx --from", "uvx", []string{"--from", "pkg-a", "bin"}, 1, true},
		{"docker run", "docker", []string{"run", "-i", "image"}, 2, true},
		{"docker container run", "docker", []string{"--context", "x", "container", "run", "-i", "image"}, 5, true},
		{"cmd /c npx", "cmd", []string{"/c", "npx", "-y", "pkg-a"}, 3, true},
		{"cmd.exe /C pipx run", "cmd.exe", []string{"/C", "pipx", "run", "pkg-a"}, 3, true},
		{"cmd without /c", "cmd", []string{"npx", "pkg-a"}, 0, false},
		{"cmd /s /c npx", "cmd", []string{"/s", "/c", "npx", "pkg-a"}, 3, true},
		{"cmd /c with nothing after", "cmd", []string{"/c"}, 0, false},
		{"pipx global flag before run", "pipx", []string{"--verbose", "run", "pkg-a"}, 2, true},
		{"docker upper-case registry host", "docker", []string{"run", "Registry.example.com/mcp/x"}, 1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, at, ok := packageAt(tt.command, tt.args)
			if ok != tt.ok || (ok && at != tt.wantAt) {
				t.Errorf("packageAt(%q, %q) = %d, %v, want %d, %v", tt.command, tt.args, at, ok, tt.wantAt, tt.ok)
			}
		})
	}
}

// FuzzExtractPackage checks that the parse of untrusted args never panics,
// that a returned spec passes the registry name check, and that the spec
// index points into args.
func FuzzExtractPackage(f *testing.F) {
	f.Add("npx", "-y\x00@scope/pkg@1.0.0")
	f.Add("cmd", "/c\x00npx\x00-p\x00pkg\x00bin")
	f.Add("docker", "--context\x00x\x00container\x00run\x00-i\x00ghcr.io/org/img:1")
	f.Add("pipx", "--verbose\x00run\x00--spec\x00pkg==1.0\x00bin")
	f.Add("uvx", "--from\x00pkg\x00--from\x00other\x00bin")
	f.Fuzz(func(t *testing.T, command, joined string) {
		args := strings.Split(joined, "\x00")
		spec, at, ok := packageAt(command, args)
		if !ok {
			return
		}
		if !validName(spec.Runner, spec.Name) {
			t.Errorf("packageAt(%q, %q) = %+v, which fails validName", command, args, spec)
		}
		if at < 0 || at >= len(args) {
			t.Errorf("packageAt(%q, %q) index %d is outside args", command, args, at)
		}
	})
}
