package inspect

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

// fakeGetenv returns a getenv function that reads from parent instead of the
// real environment, so the tests never need t.Setenv and can run in
// parallel. A key that is not in parent gives "", like os.Getenv.
func fakeGetenv(parent map[string]string) func(string) string {
	return func(key string) string {
		return parent[key]
	}
}

// secrets turns plain values into a SecretMap for the config env.
func secrets(values map[string]string) discover.SecretMap {
	if values == nil {
		return nil
	}
	m := make(discover.SecretMap, len(values))
	for k, v := range values {
		m[k] = discover.NewSecret(v)
	}
	return m
}

func TestChildEnv(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		parent map[string]string
		env    discover.SecretMap
		want   []string
		// absent lists keys that must not appear in the result.
		absent []string
	}{
		{
			name: "base only",
			parent: map[string]string{
				"PATH":         "/usr/bin:/bin",
				"HOME":         "/home/dev",
				"SECRET_TOKEN": discovertest.CanaryEnv,
			},
			env:    discover.SecretMap{},
			want:   []string{"HOME=/home/dev", "PATH=/usr/bin:/bin"},
			absent: []string{"SECRET_TOKEN"},
		},
		{
			name: "parent var not in base is dropped",
			parent: map[string]string{
				"PATH":                  "/usr/bin",
				"AWS_SECRET_ACCESS_KEY": discovertest.CanaryEnv,
				"GITHUB_TOKEN":          discovertest.CanaryHeader,
				"USER":                  "dev",
			},
			env:    nil,
			want:   []string{"PATH=/usr/bin"},
			absent: []string{"AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "USER"},
		},
		{
			name: "config adds keys sorted by key",
			parent: map[string]string{
				"PATH": "/usr/bin",
				"HOME": "/home/dev",
			},
			env: secrets(map[string]string{
				"ZED_KEY": "z",
				"API_KEY": discovertest.CanaryEnv,
				"MIDDLE":  "m",
			}),
			want: []string{
				"API_KEY=" + discovertest.CanaryEnv,
				"HOME=/home/dev",
				"MIDDLE=m",
				"PATH=/usr/bin",
				"ZED_KEY=z",
			},
		},
		{
			name: "config PATH overrides parent PATH",
			parent: map[string]string{
				"PATH": "/parent/bin",
				"HOME": "/home/dev",
			},
			env: secrets(map[string]string{"PATH": "/config/bin"}),
			want: []string{
				"HOME=/home/dev",
				"PATH=/config/bin",
			},
		},
		{
			name: "config HOME overrides parent HOME",
			parent: map[string]string{
				"PATH": "/usr/bin",
				"HOME": "/home/dev",
			},
			env: secrets(map[string]string{"HOME": "/srv/app"}),
			want: []string{
				"HOME=/srv/app",
				"PATH=/usr/bin",
			},
		},
		{
			name: "empty parent HOME and PATH are omitted",
			parent: map[string]string{
				"PATH": "",
				"HOME": "",
			},
			env:    nil,
			want:   []string{},
			absent: []string{"PATH", "HOME"},
		},
		{
			name:   "empty parent HOME is omitted but PATH kept",
			parent: map[string]string{"PATH": "/usr/bin", "HOME": ""},
			env:    nil,
			want:   []string{"PATH=/usr/bin"},
			absent: []string{"HOME"},
		},
		{
			name:   "empty parent and config env gives empty result",
			parent: map[string]string{},
			env:    discover.SecretMap{},
			want:   []string{},
		},
		{
			name:   "nil SecretMap is ok",
			parent: map[string]string{"PATH": "/usr/bin", "HOME": "/home/dev"},
			env:    nil,
			want:   []string{"HOME=/home/dev", "PATH=/usr/bin"},
		},
		{
			name:   "empty SecretMap is ok",
			parent: map[string]string{"PATH": "/usr/bin", "HOME": "/home/dev"},
			env:    discover.SecretMap{},
			want:   []string{"HOME=/home/dev", "PATH=/usr/bin"},
		},
		{
			name:   "config value may be empty",
			parent: map[string]string{},
			env:    secrets(map[string]string{"EMPTY": ""}),
			want:   []string{"EMPTY="},
		},
		{
			name:   "zero Secret gives an empty value",
			parent: map[string]string{},
			env:    discover.SecretMap{"UNSET": discover.Secret{}},
			want:   []string{"UNSET="},
		},
		{
			name:   "config value may contain '='",
			parent: map[string]string{},
			env:    secrets(map[string]string{"OPTS": "a=b=c"}),
			want:   []string{"OPTS=a=b=c"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := childEnv(fakeGetenv(tt.parent), tt.env)
			if err != nil {
				t.Fatalf("childEnv() error = %v, want nil", err)
			}
			if got == nil {
				t.Fatal("childEnv() = nil, want non-nil slice")
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("childEnv() =\n  %q\nwant\n  %q", got, tt.want)
			}
			if !slices.IsSorted(got) {
				t.Errorf("childEnv() = %q, want entries sorted", got)
			}
			assertOneEntryPerKey(t, got)
			for _, key := range tt.absent {
				for _, entry := range got {
					if strings.HasPrefix(entry, key+"=") {
						t.Errorf("childEnv() has entry %q, want key %s absent", entry, key)
					}
				}
			}
		})
	}
}

// assertOneEntryPerKey fails the test if a key appears in more than one
// entry.
func assertOneEntryPerKey(t *testing.T, entries []string) {
	t.Helper()
	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		key, _, ok := strings.Cut(entry, "=")
		if !ok {
			t.Errorf("entry %q has no '='", entry)
			continue
		}
		if seen[key] {
			t.Errorf("key %s appears more than once in %q", key, entries)
		}
		seen[key] = true
	}
}

// TestChildEnvReadsOnlyBaseKeys checks that childEnv asks getenv only for
// the base keys, so no other parent variable can reach the child (NFR-04).
func TestChildEnvReadsOnlyBaseKeys(t *testing.T) {
	t.Parallel()

	var asked []string
	getenv := func(key string) string {
		asked = append(asked, key)
		return "value"
	}
	env := secrets(map[string]string{"API_KEY": discovertest.CanaryEnv})

	if _, err := childEnv(getenv, env); err != nil {
		t.Fatalf("childEnv() error = %v, want nil", err)
	}
	slices.Sort(asked)
	want := []string{"HOME", "PATH"}
	if !slices.Equal(asked, want) {
		t.Errorf("getenv was called with %q, want %q", asked, want)
	}
}

func TestChildEnvInvalid(t *testing.T) {
	t.Parallel()

	parent := map[string]string{"PATH": "/usr/bin", "HOME": "/home/dev"}

	tests := []struct {
		name string
		env  discover.SecretMap
		// wantText is a part of the error text that names the problem.
		wantText string
		// keyMustNotLeak is true when the key bytes must not appear in
		// the error text.
		keyMustNotLeak bool
		badKey         string
	}{
		{
			name:     "empty key",
			env:      secrets(map[string]string{"": discovertest.CanaryEnv}),
			wantText: "key is empty",
		},
		{
			name:           "key with equals sign",
			env:            secrets(map[string]string{"A=B": discovertest.CanaryEnv}),
			wantText:       "key contains '='",
			keyMustNotLeak: true,
			badKey:         "A=B",
		},
		{
			name:           "long key with equals sign",
			env:            secrets(map[string]string{"LEAKY_KEY=injected": discovertest.CanaryEnv}),
			wantText:       "key contains '='",
			keyMustNotLeak: true,
			badKey:         "LEAKY_KEY=injected",
		},
		{
			name:           "key with NUL byte",
			env:            secrets(map[string]string{"A\x00B": discovertest.CanaryEnv}),
			wantText:       "key contains a NUL byte",
			keyMustNotLeak: true,
			badKey:         "A\x00B",
		},
		{
			name:     "value with NUL byte",
			env:      secrets(map[string]string{"API_KEY": discovertest.CanaryEnv + "\x00tail"}),
			wantText: "value contains a NUL byte",
		},
		{
			name:     "value with only a NUL byte",
			env:      secrets(map[string]string{"API_KEY": "\x00"}),
			wantText: "value contains a NUL byte",
		},
		{
			name: "bad key after good keys",
			env: secrets(map[string]string{
				"API_KEY":   discovertest.CanaryEnv,
				"OTHER_KEY": discovertest.CanaryHeader,
				"Z=Z":       discovertest.CanaryArgs,
			}),
			wantText:       "env key #3 (sorted order): key contains '='",
			keyMustNotLeak: true,
			badKey:         "Z=Z",
		},
		{
			name: "bad value after a good key",
			env: secrets(map[string]string{
				"API_KEY": discovertest.CanaryEnv,
				"B_KEY":   discovertest.CanaryHeader + "\x00",
			}),
			wantText: "env key #2 (sorted order): value contains a NUL byte",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := childEnv(fakeGetenv(parent), tt.env)
			if err == nil {
				t.Fatalf("childEnv() error = nil, want error; got %q", got)
			}
			if !errors.Is(err, ErrInvalidServer) {
				t.Errorf("childEnv() error = %v, want errors.Is ErrInvalidServer", err)
			}
			if got != nil {
				t.Errorf("childEnv() = %q, want nil on error", got)
			}

			msg := err.Error()
			if !strings.Contains(msg, tt.wantText) {
				t.Errorf("childEnv() error = %q, want it to contain %q", msg, tt.wantText)
			}
			// No value may reach the error, not even the values of
			// the good keys.
			discovertest.AssertNoLeak(t, "error", msg)
			if tt.keyMustNotLeak && strings.Contains(msg, tt.badKey) {
				t.Errorf("childEnv() error = %q, want no key bytes %q", msg, tt.badKey)
			}
			if tt.keyMustNotLeak {
				discovertest.AssertNoLeak(t, "error", msg, tt.badKey)
			}
		})
	}
}

func TestChildEnvDeterministic(t *testing.T) {
	t.Parallel()

	parent := map[string]string{"PATH": "/usr/bin", "HOME": "/home/dev"}
	values := map[string]string{
		"API_KEY": discovertest.CanaryEnv,
		"PATH":    "/config/bin",
		"B":       "b",
		"A":       "a",
		"C":       "c",
		"D":       "d",
		"E":       "e",
		"F":       "f",
	}

	first, err := childEnv(fakeGetenv(parent), secrets(values))
	if err != nil {
		t.Fatalf("childEnv() error = %v, want nil", err)
	}
	// Map iteration order is random in Go, so build the SecretMap again
	// and run several times to give a different order a chance to show.
	for range 20 {
		again, err := childEnv(fakeGetenv(parent), secrets(values))
		if err != nil {
			t.Fatalf("childEnv() error = %v, want nil", err)
		}
		if !slices.Equal(first, again) {
			t.Fatalf("childEnv() not deterministic:\n  first %q\n  again %q", first, again)
		}
	}
}
