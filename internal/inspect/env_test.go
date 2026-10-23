package inspect

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

// TestIsBaseEnv checks the allowlist of parent variables: every listed name
// passes, and names that can carry secrets or inject code do not.
func TestIsBaseEnv(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		want bool
	}{
		{name: "HOME", want: true},
		{name: "LANG", want: true},
		{name: "LC_ALL", want: true},
		{name: "LC_CTYPE", want: true},
		{name: "LOGNAME", want: true},
		{name: "PATH", want: true},
		{name: "SHELL", want: true},
		{name: "TERM", want: true},
		{name: "TMPDIR", want: true},
		{name: "TZ", want: true},
		{name: "USER", want: true},
		{name: "__CF_USER_TEXT_ENCODING", want: true},

		{name: "AWS_SECRET_ACCESS_KEY", want: false},
		{name: "GITHUB_TOKEN", want: false},
		{name: "SSH_AUTH_SOCK", want: false},
		{name: "HTTPS_PROXY", want: false},
		{name: "http_proxy", want: false},
		{name: "LD_PRELOAD", want: false},
		{name: "DYLD_INSERT_LIBRARIES", want: false},
		{name: "NODE_OPTIONS", want: false},
		{name: "PWD", want: false},
		{name: "XDG_RUNTIME_DIR", want: false},
		{name: "path", want: false},
		{name: "Home", want: false},
		{name: "", want: false},
		{name: "PATH ", want: false},
		{name: " PATH", want: false},
		{name: "PATH=", want: false},
		{name: "LC_MESSAGES", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isBaseEnv(tt.name); got != tt.want {
				t.Errorf("isBaseEnv(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

// TestBuildEnv checks the scrubbed environment for valid input: the
// allowlist filter, declared overrides, parsing of parent entries and the
// sort order.
func TestBuildEnv(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		parent   []string
		declared map[string]string
		want     []string
	}{
		{
			name: "only allowlisted parent vars kept",
			parent: []string{
				"PATH=/usr/bin:/bin",
				"AWS_SECRET_ACCESS_KEY=" + discovertest.CanaryEnv,
				"HOME=/home/u",
				"GITHUB_TOKEN=" + discovertest.CanaryHeader,
				"SSH_AUTH_SOCK=/tmp/agent.sock",
				"LD_PRELOAD=/tmp/evil.so",
				"NODE_OPTIONS=--require /tmp/evil.js",
				"https_proxy=http://proxy",
				"LANG=en_US.UTF-8",
			},
			want: []string{
				"HOME=/home/u",
				"LANG=en_US.UTF-8",
				"PATH=/usr/bin:/bin",
			},
		},
		{
			name:     "declared overrides PATH and HOME",
			parent:   []string{"PATH=/usr/bin", "HOME=/home/u", "USER=u"},
			declared: map[string]string{"PATH": "/opt/bin", "HOME": "/srv"},
			want:     []string{"HOME=/srv", "PATH=/opt/bin", "USER=u"},
		},
		{
			name:     "declared var not in the allowlist is added",
			parent:   []string{"PATH=/usr/bin"},
			declared: map[string]string{"API_KEY": discovertest.CanaryEnv},
			want:     []string{"API_KEY=" + discovertest.CanaryEnv, "PATH=/usr/bin"},
		},
		{
			name:     "declared var that the parent also has but the allowlist refuses",
			parent:   []string{"GITHUB_TOKEN=parent"},
			declared: map[string]string{"GITHUB_TOKEN": "declared"},
			want:     []string{"GITHUB_TOKEN=declared"},
		},
		{
			// os.Environ cannot hold a NUL byte, but Environ is a slice
			// from the caller. The bad entry is skipped, so the next PATH
			// entry is the first valid one.
			name:   "parent entry with a NUL byte in the value is skipped",
			parent: []string{"HOME=/h\x00x", "PATH=/a\x00b", "PATH=/ok"},
			want:   []string{"PATH=/ok"},
		},
		{
			name:   "first parent entry wins for duplicate keys",
			parent: []string{"PATH=/first", "TERM=xterm", "PATH=/second", "PATH="},
			want:   []string{"PATH=/first", "TERM=xterm"},
		},
		{
			name:   "first parent entry wins also when it is empty",
			parent: []string{"TZ=", "TZ=UTC"},
			want:   []string{"TZ="},
		},
		{
			name:   "malformed parent entries skipped",
			parent: []string{"NOEQUALS", "PATH", "=value", "=", "", "HOME=/home/u"},
			want:   []string{"HOME=/home/u"},
		},
		{
			name: "variable references in a declared value kept literally",
			parent: []string{
				"HOME=/home/u",
			},
			declared: map[string]string{
				"A": "${HOME}",
				"B": "${MISSING:-x}",
				"C": "$HOME/bin",
			},
			want: []string{
				"A=${HOME}",
				"B=${MISSING:-x}",
				"C=$HOME/bin",
				"HOME=/home/u",
			},
		},
		{
			name:     "empty declared value allowed",
			declared: map[string]string{"FOO": ""},
			want:     []string{"FOO="},
		},
		{
			name:     "declared value with equals signs kept",
			declared: map[string]string{"A": "b=c"},
			want:     []string{"A=b=c"},
		},
		{
			name:   "parent value with equals signs kept",
			parent: []string{"TERM=a=b=c"},
			want:   []string{"TERM=a=b=c"},
		},
		{
			name:     "declared value with newline kept",
			declared: map[string]string{"A": "line1\nline2"},
			want:     []string{"A=line1\nline2"},
		},
		{
			name:   "output sorted by key",
			parent: []string{"USER=u", "TZ=UTC", "HOME=/h", "PATH=/p"},
			declared: map[string]string{
				"ZED":   "z",
				"ALPHA": "a",
				"MID":   "m",
			},
			want: []string{
				"ALPHA=a",
				"HOME=/h",
				"MID=m",
				"PATH=/p",
				"TZ=UTC",
				"USER=u",
				"ZED=z",
			},
		},
		{
			// '-' sorts before '=', so a sort of the whole "name=value"
			// strings would put "A-B=2" first. The key order puts "A" first.
			name:     "sort uses the key and not the whole entry",
			declared: map[string]string{"A": "1", "A-B": "2"},
			want:     []string{"A=1", "A-B=2"},
		},
		{
			name:   "no allowlisted parent vars and no declared vars",
			parent: []string{"AWS_SECRET_ACCESS_KEY=" + discovertest.CanaryEnv},
			want:   []string{},
		},
		{
			name:     "empty non-nil inputs",
			parent:   []string{},
			declared: map[string]string{},
			want:     []string{},
		},
		{
			name: "nil parent and nil declared",
			want: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := buildEnv(tt.parent, secrets(tt.declared))
			if err != nil {
				t.Fatalf("buildEnv() error = %v, want nil", err)
			}
			// A nil Env makes exec.Cmd inherit the whole parent environment,
			// so a nil result would undo the scrub (NFR-04).
			if got == nil {
				t.Fatal("buildEnv() = nil, want a non-nil slice")
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("buildEnv() =\n  %q\nwant\n  %q", got, tt.want)
			}
		})
	}
}

// TestBuildEnvZeroSecret pins the result for a zero discover.Secret, which
// a JSON null env value in a config decodes to: the child gets the name with
// an empty value, and the zero value overrides a parent entry.
func TestBuildEnvZeroSecret(t *testing.T) {
	t.Parallel()

	declared := discover.SecretMap{"API_KEY": {}, "PATH": {}}
	got, err := buildEnv([]string{"PATH=/usr/bin", "HOME=/h"}, declared)
	if err != nil {
		t.Fatalf("buildEnv() error = %v, want nil", err)
	}
	want := []string{"API_KEY=", "HOME=/h", "PATH="}
	if !slices.Equal(got, want) {
		t.Errorf("buildEnv() = %q, want %q", got, want)
	}
}

// TestBuildEnvDoesNotAliasInput checks that a change to the result does not
// change the parent slice.
func TestBuildEnvDoesNotAliasInput(t *testing.T) {
	t.Parallel()

	parent := []string{"HOME=/h", "PATH=/p"}
	orig := slices.Clone(parent)
	got, err := buildEnv(parent, nil)
	if err != nil {
		t.Fatalf("buildEnv() error = %v", err)
	}
	for i := range got {
		got[i] = "X=changed"
	}
	if !slices.Equal(parent, orig) {
		t.Errorf("parent = %q after a change to the result, want %q", parent, orig)
	}
}

// TestBuildEnvErrors checks that an invalid declared name or value gives the
// right sentinel error, a nil result, and an error text without the input.
func TestBuildEnvErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		parent   []string
		declared map[string]string
		wantErr  error
	}{
		{
			name:     "empty name",
			declared: map[string]string{"": discovertest.CanaryEnv},
			wantErr:  errInvalidEnvName,
		},
		{
			name:     "name with equals sign",
			declared: map[string]string{"A=B": discovertest.CanaryEnv},
			wantErr:  errInvalidEnvName,
		},
		{
			name:     "name with NUL byte",
			declared: map[string]string{"A\x00B": discovertest.CanaryEnv},
			wantErr:  errInvalidEnvName,
		},
		{
			// The part after "=" looks like a value. It must not leak.
			name:     "name that holds a secret after an equals sign",
			declared: map[string]string{"TOKEN=supersecret": discovertest.CanaryEnv},
			wantErr:  errInvalidEnvName,
		},
		{
			name:     "name that holds a canary after an equals sign",
			declared: map[string]string{"TOKEN=" + discovertest.CanaryArgs: "x"},
			wantErr:  errInvalidEnvName,
		},
		{
			name:     "value with NUL byte",
			declared: map[string]string{"API_KEY": "a\x00b"},
			wantErr:  errInvalidEnvValue,
		},
		{
			name:     "canary value with NUL byte",
			declared: map[string]string{"API_KEY": discovertest.CanaryEnv + "\x00tail"},
			wantErr:  errInvalidEnvValue,
		},
		{
			name:     "bad name next to valid entries",
			parent:   []string{"PATH=/usr/bin", "HOME=/h"},
			declared: map[string]string{"GOOD": "ok", "BAD=x": "y"},
			wantErr:  errInvalidEnvName,
		},
		{
			// Names are checked in sorted order: "A=x" comes before "B", so
			// the name error comes first on every run.
			name:     "first error in sorted order is a name error",
			declared: map[string]string{"A=x": "ok", "B": "a\x00b"},
			wantErr:  errInvalidEnvName,
		},
		{
			// "A" comes before "B=x", so the value error comes first.
			name:     "first error in sorted order is a value error",
			declared: map[string]string{"A": "a\x00b", "B=x": "ok"},
			wantErr:  errInvalidEnvValue,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := buildEnv(tt.parent, secrets(tt.declared))
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("buildEnv() error = %v, want %v", err, tt.wantErr)
			}
			if got != nil {
				t.Errorf("buildEnv() = %d entries on error, want nil", len(got))
			}
			msg := err.Error()
			if msg != tt.wantErr.Error() {
				t.Errorf("error text = %q, want exactly %q", msg, tt.wantErr.Error())
			}

			var inputs []string
			for k, v := range tt.declared {
				inputs = append(inputs, k, v)
				// The part after "=" in a bad name can be a secret.
				if _, after, ok := strings.Cut(k, "="); ok {
					inputs = append(inputs, after)
				}
			}
			inputs = slices.DeleteFunc(inputs, func(s string) bool { return s == "" })
			if len(inputs) > 0 {
				discovertest.AssertNoLeak(t, "error", msg, inputs...)
			}
		})
	}
}

// FuzzBuildEnv checks the invariants of buildEnv for arbitrary parent
// entries and one declared entry.
func FuzzBuildEnv(f *testing.F) {
	f.Add("PATH=/usr/bin", "API_KEY", "value")
	f.Add("AWS_SECRET_ACCESS_KEY=x", "PATH", "/opt/bin")
	f.Add("NOEQUALS", "HOME", "")
	f.Add("=value", "", "x")
	f.Add("", "A=B", "x")
	f.Add("HOME=/h", "A\x00B", "x")
	f.Add("TERM=a=b", "TOKEN", "a\x00b")
	f.Add("TZ=UTC", "A-B", "${VAR:-x}")
	f.Add("PATH=a\x00b", "PATH", "x")

	f.Fuzz(func(t *testing.T, parentEntry, key, value string) {
		parent := []string{parentEntry, "HOME=/fixed-home", parentEntry}
		declared := discover.SecretMap{key: discover.NewSecret(value)}

		got, err := buildEnv(parent, declared)

		// The oracle does not call hasNUL, so a bug in hasNUL cannot hide
		// here.
		holdsNUL := func(s string) bool { return strings.IndexByte(s, 0) >= 0 }
		badName := key == "" || strings.ContainsAny(key, "=\x00")
		badValue := holdsNUL(value)
		if badName || badValue {
			want := errInvalidEnvValue
			if badName {
				want = errInvalidEnvName
			}
			if !errors.Is(err, want) {
				t.Fatalf("buildEnv() error = %v, want %v", err, want)
			}
			if err.Error() != want.Error() {
				t.Fatalf("error text = %q, want exactly %q", err.Error(), want.Error())
			}
			if got != nil {
				t.Fatalf("buildEnv() = %d entries on error, want nil", len(got))
			}
			return
		}

		if err != nil {
			t.Fatalf("buildEnv() error = %v, want nil", err)
		}
		if got == nil {
			t.Fatal("buildEnv() = nil, want a non-nil slice")
		}

		keys := make([]string, 0, len(got))
		values := make(map[string]string, len(got))
		for _, entry := range got {
			k, v, ok := strings.Cut(entry, "=")
			if !ok {
				t.Fatalf("entry %q has no '='", entry)
			}
			if holdsNUL(v) {
				t.Fatalf("entry %q has a NUL byte in its value", k)
			}
			if k != key && !isBaseEnv(k) {
				t.Fatalf("entry key %q is neither allowlisted nor declared", k)
			}
			if _, dup := values[k]; dup {
				t.Fatalf("duplicate key %q in %q", k, got)
			}
			keys = append(keys, k)
			values[k] = v
		}
		if !slices.IsSorted(keys) {
			t.Fatalf("keys %q are not sorted", keys)
		}

		// The declared entry is always present with its exact value.
		if v, ok := values[key]; !ok || v != value {
			t.Fatalf("declared %q = %q (present %v), want %q", key, v, ok, value)
		}

		// The first parent entry for each allowlisted key wins, unless the
		// declared entry overrides it. A parent entry with a NUL byte in its
		// value is skipped.
		want := map[string]string{key: value}
		for _, entry := range parent {
			k, v, ok := strings.Cut(entry, "=")
			if !ok || !isBaseEnv(k) || holdsNUL(v) {
				continue
			}
			if _, seen := want[k]; !seen {
				want[k] = v
			}
		}
		if !reflect.DeepEqual(values, want) {
			t.Fatalf("buildEnv() = %q, want entries %q", got, want)
		}
	})
}

// TestNoAutoInstallEnv checks that noAutoInstallEnv adds npm_config_yes=false
// (issue #104), keeps a declared value of that variable in any letter case,
// and keeps the result sorted by name.
func TestNoAutoInstallEnv(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		env  []string
		want []string
	}{
		{
			name: "nil env",
			env:  nil,
			want: []string{"npm_config_yes=false"},
		},
		{
			name: "empty env",
			env:  []string{},
			want: []string{"npm_config_yes=false"},
		},
		{
			// Upper case names sort before lower case names, so the new
			// entry goes to the end.
			name: "added after upper case names",
			env:  []string{"HOME=/h", "PATH=/p", "TERM=xterm"},
			want: []string{"HOME=/h", "PATH=/p", "TERM=xterm", "npm_config_yes=false"},
		},
		{
			name: "added in sort order between names",
			env:  []string{"API_KEY=k", "PATH=/p", "npm_config_cache=/c", "npm_config_yes_extra=1", "zz=1"},
			want: []string{"API_KEY=k", "PATH=/p", "npm_config_cache=/c", "npm_config_yes=false", "npm_config_yes_extra=1", "zz=1"},
		},
		{
			name: "declared lower case value wins",
			env:  []string{"PATH=/p", "npm_config_yes=true"},
			want: []string{"PATH=/p", "npm_config_yes=true"},
		},
		{
			// npm matches env names with ASCII case folding only, so it
			// ignores U+017F (long s). The entry must not stop the default.
			name: "non-ASCII look-alike name does not count",
			env:  []string{"npm_config_ye\u017f=false"},
			want: []string{"npm_config_yes=false", "npm_config_ye\u017f=false"},
		},
		{
			name: "declared upper case value wins",
			env:  []string{"NPM_CONFIG_YES=true", "PATH=/p"},
			want: []string{"NPM_CONFIG_YES=true", "PATH=/p"},
		},
		{
			name: "declared mixed case value wins",
			env:  []string{"Npm_Config_Yes=1", "PATH=/p"},
			want: []string{"Npm_Config_Yes=1", "PATH=/p"},
		},
		{
			// A declared empty value is still a declared value: npm reads
			// it, so mcpmoat must not add a second entry.
			name: "declared empty value wins",
			env:  []string{"PATH=/p", "npm_config_yes="},
			want: []string{"PATH=/p", "npm_config_yes="},
		},
		{
			name: "declared false is kept once",
			env:  []string{"npm_config_yes=false"},
			want: []string{"npm_config_yes=false"},
		},
		{
			// Only the name counts. A value that looks like the entry does
			// not stop the add.
			name: "value with the name does not count",
			env:  []string{"X=npm_config_yes=true"},
			want: []string{"X=npm_config_yes=true", "npm_config_yes=false"},
		},
		{
			name: "similar names do not count",
			env:  []string{"npm_config_y=1", "npm_config_yes_x=1", "NPM_CONFIG_YESS=1", "npm-config-yes=1", " npm_config_yes=1"},
			want: []string{" npm_config_yes=1", "NPM_CONFIG_YESS=1", "npm-config-yes=1", "npm_config_y=1", "npm_config_yes=false", "npm_config_yes_x=1"},
		},
		{
			// An unsorted input still gives a sorted result.
			name: "unsorted input is sorted",
			env:  []string{"zz=1", "PATH=/p", "HOME=/h"},
			want: []string{"HOME=/h", "PATH=/p", "npm_config_yes=false", "zz=1"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			orig := slices.Clone(tt.env)
			got := noAutoInstallEnv(tt.env)
			if got == nil {
				t.Fatal("noAutoInstallEnv() = nil, want a non-nil slice")
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("noAutoInstallEnv(%q) = %q, want %q", tt.env, got, tt.want)
			}
			if !slices.Equal(tt.env, orig) {
				t.Errorf("input = %q after the call, want %q unchanged", tt.env, orig)
			}
		})
	}
}

// TestNoAutoInstallEnvDoesNotAliasInput checks that the result has its own
// backing array: a change to it does not change the input, also when the
// input has spare capacity that append could reuse.
func TestNoAutoInstallEnvDoesNotAliasInput(t *testing.T) {
	t.Parallel()

	backing := make([]string, 2, 8)
	backing[0], backing[1] = "HOME=/h", "PATH=/p"
	env := backing[:2]

	got := noAutoInstallEnv(env)
	for i, spare := range backing[len(env):cap(backing)] {
		if spare != "" {
			t.Errorf("spare capacity %d of the input = %q, want it untouched", i, spare)
		}
	}
	for i := range got {
		got[i] = "X=changed"
	}
	if want := []string{"HOME=/h", "PATH=/p"}; !slices.Equal(env, want) {
		t.Errorf("input = %q after a change to the result, want %q", env, want)
	}
}

// TestNoAutoInstallEnvAfterBuildEnv checks the order of the real caller:
// buildEnv, then noAutoInstallEnv. The parent npm_config_yes is not on the
// allowlist, so it never reaches the child, and the forced value applies; a
// declared value wins.
func TestNoAutoInstallEnvAfterBuildEnv(t *testing.T) {
	t.Parallel()

	parent := []string{"PATH=/p", "npm_config_yes=true", "NPM_CONFIG_YES=true"}

	t.Run("parent value is dropped", func(t *testing.T) {
		t.Parallel()
		env, err := buildEnv(parent, nil)
		if err != nil {
			t.Fatalf("buildEnv() error = %v", err)
		}
		want := []string{"PATH=/p", "npm_config_yes=false"}
		if got := noAutoInstallEnv(env); !slices.Equal(got, want) {
			t.Errorf("noAutoInstallEnv(buildEnv()) = %q, want %q", got, want)
		}
	})

	t.Run("declared value wins", func(t *testing.T) {
		t.Parallel()
		env, err := buildEnv(parent, discover.SecretMap{"NPM_CONFIG_YES": discover.NewSecret("true")})
		if err != nil {
			t.Fatalf("buildEnv() error = %v", err)
		}
		want := []string{"NPM_CONFIG_YES=true", "PATH=/p"}
		if got := noAutoInstallEnv(env); !slices.Equal(got, want) {
			t.Errorf("noAutoInstallEnv(buildEnv()) = %q, want %q", got, want)
		}
	})
}

// TestEnvName checks the name part of an entry and the npm_config_yes match.
func TestEnvName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		entry    string
		wantName string
		wantNpm  bool
	}{
		{entry: "PATH=/p", wantName: "PATH"},
		{entry: "A=b=c", wantName: "A"},
		{entry: "=value", wantName: ""},
		{entry: "", wantName: ""},
		{entry: "NOEQUALS", wantName: "NOEQUALS"},
		{entry: "npm_config_yes=false", wantName: "npm_config_yes", wantNpm: true},
		{entry: "NPM_CONFIG_YES=", wantName: "NPM_CONFIG_YES", wantNpm: true},
		{entry: "nPm_CoNfIg_YeS=1", wantName: "nPm_CoNfIg_YeS", wantNpm: true},
		// No "=": the whole entry is the name.
		{entry: "npm_config_yes", wantName: "npm_config_yes", wantNpm: true},
		{entry: "npm_config_yes_x=1", wantName: "npm_config_yes_x"},
		{entry: "npm_config_ye=1", wantName: "npm_config_ye"},
		{entry: "X=npm_config_yes", wantName: "X"},
		{entry: " npm_config_yes=1", wantName: " npm_config_yes"},
	}
	for _, tt := range tests {
		t.Run(tt.entry, func(t *testing.T) {
			t.Parallel()
			if got := envName(tt.entry); got != tt.wantName {
				t.Errorf("envName(%q) = %q, want %q", tt.entry, got, tt.wantName)
			}
			if got := isNpmYesEntry(tt.entry); got != tt.wantNpm {
				t.Errorf("isNpmYesEntry(%q) = %v, want %v", tt.entry, got, tt.wantNpm)
			}
		})
	}
}

// FuzzNoAutoInstallEnv checks the invariants of noAutoInstallEnv for
// arbitrary entries: the input is unchanged, the result is sorted by name,
// holds every input entry, and holds exactly one npm_config_yes entry, the
// added one only when the input had none.
func FuzzNoAutoInstallEnv(f *testing.F) {
	f.Add("PATH=/p", "HOME=/h")
	f.Add("npm_config_yes=true", "PATH=/p")
	f.Add("NPM_CONFIG_YES=", "zz=1")
	f.Add("", "=x")
	f.Add("npm_config_yes", "npm_config_yes_x=1")

	f.Fuzz(func(t *testing.T, a, b string) {
		env := []string{a, b}
		orig := slices.Clone(env)
		got := noAutoInstallEnv(env)

		if !slices.Equal(env, orig) {
			t.Fatalf("input changed: %q, want %q", env, orig)
		}
		if !slices.IsSortedFunc(got, func(x, y string) int { return strings.Compare(envName(x), envName(y)) }) {
			t.Fatalf("result %q is not sorted by name", got)
		}
		for _, e := range env {
			if !slices.Contains(got, e) {
				t.Fatalf("result %q lost the input entry %q", got, e)
			}
		}
		had := slices.ContainsFunc(env, isNpmYesEntry)
		wantLen := len(env)
		if !had {
			wantLen++
			if !slices.Contains(got, "npm_config_yes=false") {
				t.Fatalf("result %q has no npm_config_yes=false", got)
			}
		}
		if len(got) != wantLen {
			t.Fatalf("len(result) = %d, want %d", len(got), wantLen)
		}
	})
}
