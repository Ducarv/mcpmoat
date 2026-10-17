package main

import (
	"runtime/debug"
	"strings"
	"testing"
)

// versionDefaults is what a build without -ldflags contains.
var versionDefaults = buildInfo{version: defaultVersion, commit: defaultCommit, date: defaultDate}

// versionFakeRead returns a read function for resolveBuildInfo. It reports the
// given info and ok values, and sets *called when resolveBuildInfo uses it.
func versionFakeRead(called *bool, info *debug.BuildInfo, ok bool) func() (*debug.BuildInfo, bool) {
	return func() (*debug.BuildInfo, bool) {
		*called = true
		return info, ok
	}
}

func TestResolveBuildInfo(t *testing.T) {
	t.Parallel()

	rev40 := strings.Repeat("a1b2c3d4e5", 4) // 40 characters
	if len(rev40) != 40 {
		t.Fatalf("test setup: revision has %d characters, want 40", len(rev40))
	}
	const vcsTime = "2026-03-04T05:06:07Z"

	settings := func(rev, tm string) []debug.BuildSetting {
		var s []debug.BuildSetting
		if rev != "" {
			s = append(s, debug.BuildSetting{Key: "vcs.revision", Value: rev})
		}
		if tm != "" {
			s = append(s, debug.BuildSetting{Key: "vcs.time", Value: tm})
		}
		return s
	}

	tests := []struct {
		name       string
		linked     buildInfo
		info       *debug.BuildInfo
		ok         bool
		want       buildInfo
		wantCalled bool
	}{
		{
			name:   "ldflags version set: read is not called",
			linked: buildInfo{version: "1.2.3", commit: "none", date: "unknown"},
			info: &debug.BuildInfo{
				Main:     debug.Module{Version: "v9.9.9"},
				Settings: settings(rev40, vcsTime),
			},
			ok:         true,
			want:       buildInfo{version: "1.2.3", commit: "none", date: "unknown"},
			wantCalled: false,
		},
		{
			name:   "dev with module version and vcs settings",
			linked: versionDefaults,
			info: &debug.BuildInfo{
				Main:     debug.Module{Version: "v0.1.0"},
				Settings: settings(rev40, vcsTime),
			},
			ok:         true,
			want:       buildInfo{version: "v0.1.0", commit: rev40[:shortRevisionLen], date: vcsTime},
			wantCalled: true,
		},
		{
			name:   "dev with (devel) keeps dev, vcs settings still fill",
			linked: versionDefaults,
			info: &debug.BuildInfo{
				Main:     debug.Module{Version: "(devel)"},
				Settings: settings(rev40, vcsTime),
			},
			ok:         true,
			want:       buildInfo{version: "dev", commit: rev40[:shortRevisionLen], date: vcsTime},
			wantCalled: true,
		},
		{
			name:   "dev with empty module version",
			linked: versionDefaults,
			info: &debug.BuildInfo{
				Main: debug.Module{Version: ""},
			},
			ok:         true,
			want:       versionDefaults,
			wantCalled: true,
		},
		{
			name:   "dev with ok=false is unchanged",
			linked: versionDefaults,
			info: &debug.BuildInfo{
				Main:     debug.Module{Version: "v0.1.0"},
				Settings: settings(rev40, vcsTime),
			},
			ok:         false,
			want:       versionDefaults,
			wantCalled: true,
		},
		{
			name:       "dev with nil info and ok=true is unchanged",
			linked:     versionDefaults,
			info:       nil,
			ok:         true,
			want:       versionDefaults,
			wantCalled: true,
		},
		{
			name:   "revision of exactly the short length is kept",
			linked: versionDefaults,
			info: &debug.BuildInfo{
				Settings: settings(rev40[:shortRevisionLen], ""),
			},
			ok:         true,
			want:       buildInfo{version: "dev", commit: rev40[:shortRevisionLen], date: "unknown"},
			wantCalled: true,
		},
		{
			name:   "revision one character over the short length is cut",
			linked: versionDefaults,
			info: &debug.BuildInfo{
				Settings: settings(rev40[:shortRevisionLen+1], ""),
			},
			ok:         true,
			want:       buildInfo{version: "dev", commit: rev40[:shortRevisionLen], date: "unknown"},
			wantCalled: true,
		},
		{
			name:   "revision shorter than the short length is kept",
			linked: versionDefaults,
			info: &debug.BuildInfo{
				Settings: settings("abc1234", ""),
			},
			ok:         true,
			want:       buildInfo{version: "dev", commit: "abc1234", date: "unknown"},
			wantCalled: true,
		},
		{
			name:   "injected commit is not overwritten by vcs.revision",
			linked: buildInfo{version: "dev", commit: "abc", date: "unknown"},
			info: &debug.BuildInfo{
				Settings: settings(rev40, vcsTime),
			},
			ok:         true,
			want:       buildInfo{version: "dev", commit: "abc", date: vcsTime},
			wantCalled: true,
		},
		{
			name:   "injected date is not overwritten by vcs.time",
			linked: buildInfo{version: "dev", commit: "none", date: "2020-01-01T00:00:00Z"},
			info: &debug.BuildInfo{
				Settings: settings(rev40, vcsTime),
			},
			ok:         true,
			want:       buildInfo{version: "dev", commit: rev40[:shortRevisionLen], date: "2020-01-01T00:00:00Z"},
			wantCalled: true,
		},
		{
			name:   "empty vcs values do not overwrite defaults",
			linked: versionDefaults,
			info: &debug.BuildInfo{
				Settings: []debug.BuildSetting{
					{Key: "vcs.revision", Value: ""},
					{Key: "vcs.time", Value: ""},
				},
			},
			ok:         true,
			want:       versionDefaults,
			wantCalled: true,
		},
		{
			name:   "unrelated settings are ignored",
			linked: versionDefaults,
			info: &debug.BuildInfo{
				Settings: []debug.BuildSetting{
					{Key: "vcs.modified", Value: "true"},
					{Key: "GOOS", Value: "linux"},
				},
			},
			ok:         true,
			want:       versionDefaults,
			wantCalled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var called bool
			read := versionFakeRead(&called, tt.info, tt.ok)

			got := resolveBuildInfo(tt.linked, read)

			if got != tt.want {
				t.Errorf("resolveBuildInfo() = %+v, want %+v", got, tt.want)
			}
			if called != tt.wantCalled {
				t.Errorf("read called = %v, want %v", called, tt.wantCalled)
			}
		})
	}
}

func TestBuildInfoString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		b    buildInfo
		want string
	}{
		{
			name: "defaults",
			b:    versionDefaults,
			want: "mcpmoat dev (commit none, built unknown)",
		},
		{
			name: "injected",
			b:    buildInfo{version: "1.2.3", commit: "abc123", date: "2026-01-01T00:00:00Z"},
			want: "mcpmoat 1.2.3 (commit abc123, built 2026-01-01T00:00:00Z)",
		},
		{
			name: "v prefix is printed as injected",
			b:    buildInfo{version: "v0.1.0", commit: "abc123", date: "2026-01-01T00:00:00Z"},
			want: "mcpmoat v0.1.0 (commit abc123, built 2026-01-01T00:00:00Z)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := tt.b.String()
			if got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}
