package main

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

// Tests for the findings block of "scan --no-connect" on the fixtures under
// testdata/configs (the rule checks themselves are tested in internal/rules,
// see fixtures_test.go). Each test runs the scan on a copy of the fixture, in
// auto-discovery and with --config, and compares the whole findings table.

// Synthetic canaries of testdata/configs/dangerous. They must not appear
// anywhere in stdout or stderr.
const (
	findingsCanaryHeader = "mcpmoat-canary-header-8Fk2Zs"
	findingsCanaryToken  = "ghp_mcpmoatcanaryZk3Qp8Vw2LxN7rTb5HcYd4M" //nolint:gosec // G101: synthetic canary of the test fixture, not a credential
	findingsCanaryArg    = "Zq8Lm3Vx0Rt5Ws2Hy7Nb4Kd1"                 //nolint:gosec // G101: synthetic canary of the test fixture, not a credential
	findingsCanaryURL    = "Jt6Pc9Gh2Fw8Ye4Ua1Xs7Mq3"

	// findingsFixtureHost is the host of the remote servers of the fixtures.
	// The server table may show it, the findings block must not.
	findingsFixtureHost = "mcp.example.invalid"
)

// findingsScan runs "scan --no-connect" on a copy of the fixture
// testdata/configs/<fixture>, in auto-discovery (mode "auto") or with
// --config on the copy of .cursor/mcp.json (mode "config"). It returns the
// exit code, stdout and stderr. It never touches the real $HOME.
func findingsScan(t *testing.T, fixture, mode string) (code int, stdout, stderr string) {
	t.Helper()
	home, work := discovertest.CopyFixture(t, testdataPath("configs", fixture))
	args := []string{"scan", "--no-connect"}
	if mode == "config" {
		args = append(args, "--config", filepath.Join(home, ".cursor", "mcp.json"))
	}
	c, out, errOut := dirsCLI(t, home, work)
	return runScanArgs(c, out, errOut, args...)
}

// assertFindingRows fails the test unless the findings table of stdout has
// exactly the rows in want, in this order. A row is RULE, SEVERITY, SERVER,
// FIELD and KEY/RELATED, as printed.
func assertFindingRows(t *testing.T, stdout string, want [][]string) {
	t.Helper()
	got := findingRows(t, stdout)
	if len(got) != len(want) {
		t.Errorf("findings table has %d rows, want %d\nstdout:\n%s", len(got), len(want), stdout)
	}
	for i := range min(len(got), len(want)) {
		if !slices.Equal(got[i], want[i]) {
			t.Errorf("finding row %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// findingsBlock returns the part of stdout after the first blank line, which
// is the findings table. It fails the test when stdout has no blank line.
func findingsBlock(t *testing.T, stdout string) string {
	t.Helper()
	_, block, found := strings.Cut(stdout, "\n\n")
	if !found {
		t.Fatalf("stdout has no findings block\nstdout:\n%s", stdout)
	}
	return block
}

// TestScanFindingsDangerousFixture scans testdata/configs/dangerous: nine
// servers, with findings of every T4 rule. It has high findings, so the exit
// code is 1. The rows are sorted by server name, and the T4 checks keep the
// order of rules.CheckConfig inside one server. No secret of the fixture
// shows, and the findings block names no host.
func TestScanFindingsDangerousFixture(t *testing.T) {
	t.Parallel()

	wantServers := []string{
		"docker-arg-secret", "docker-untagged", "env-secret", "latest-pkg", "npx-git-pinned",
		"npx-git-unpinned", "remote-local", "remote-plain", "remote-url-secret",
	}
	wantRows := [][]string{
		{"MOAT-T4-002", "high", "docker-arg-secret", "args", "-"},
		{"MOAT-T4-003", "medium", "docker-untagged", "args", "registry.invalid/example/mcp-server"},
		{"MOAT-T4-002", "high", "env-secret", "env", "GITHUB_TOKEN"},
		{"MOAT-T4-004", "low", "env-secret", "args", "-"},
		{"MOAT-T4-003", "medium", "latest-pkg", "args", "@example-corp/files-mcp"},
		{"MOAT-T4-004", "low", "latest-pkg", "args", "-"},
		{"MOAT-T4-004", "low", "npx-git-pinned", "args", "-"},
		{"MOAT-T4-003", "medium", "npx-git-unpinned", "args", "-"},
		{"MOAT-T4-004", "low", "npx-git-unpinned", "args", "-"},
		{"MOAT-T4-001", "high", "remote-plain", "url", "-"},
		{"MOAT-T4-002", "high", "remote-plain", "headers", "X-Api-Key"},
		{"MOAT-T4-002", "high", "remote-url-secret", "url", "-"},
	}
	canaries := []string{findingsCanaryHeader, findingsCanaryToken, findingsCanaryArg, findingsCanaryURL}

	for _, mode := range []string{"auto", "config"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()

			code, stdout, stderr := findingsScan(t, "dangerous", mode)

			assertScanResult(t, code, stdout, stderr, scanWant{code: exitFindings, noStdout: canaries})
			assertCleanStderr(t, stderr)
			assertContainsNone(t, "stderr", stderr, canaries)
			if got := column(tableRows(t, stdout), 0); !slices.Equal(got, wantServers) {
				t.Errorf("table servers = %v, want %v\nstdout:\n%s", got, wantServers, stdout)
			}
			assertFindingRows(t, stdout, wantRows)
			assertContainsNone(t, "the findings block", findingsBlock(t, stdout), []string{findingsFixtureHost})
		})
	}

	// The same input gives the same output: the order of the rows is fixed.
	t.Run("same output on every run", func(t *testing.T) {
		t.Parallel()

		_, first, _ := findingsScan(t, "dangerous", "config")
		for range 5 {
			_, again, _ := findingsScan(t, "dangerous", "config")
			if got, want := findingsBlock(t, again), findingsBlock(t, first); got != want {
				t.Fatalf("the findings block changed between runs\nfirst:\n%s\nagain:\n%s", want, got)
			}
		}
	})
}

// TestScanFindingsTyposquatFixture scans testdata/configs/typosquat: three
// servers, with T5 (medium) and T4-004 (low) findings only. Nothing reaches
// severity high, so the exit code is 0.
func TestScanFindingsTyposquatFixture(t *testing.T) {
	t.Parallel()

	wantServers := []string{"filesystem", "mcp-server-fecth", "memory"}
	wantRows := [][]string{
		{"MOAT-T4-004", "low", "filesystem", "args", "-"},
		{"MOAT-T5-001", "medium", "filesystem", "args", "@modelcontextprotocol/server-filesystem"},
		{"MOAT-T5-001", "medium", "mcp-server-fecth", "name", "mcp-server-fetch"},
		{"MOAT-T4-004", "low", "memory", "args", "-"},
	}

	for _, mode := range []string{"auto", "config"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()

			code, stdout, stderr := findingsScan(t, "typosquat", mode)

			assertScanResult(t, code, stdout, stderr, scanWant{code: exitOK})
			assertCleanStderr(t, stderr)
			if got := column(tableRows(t, stdout), 0); !slices.Equal(got, wantServers) {
				t.Errorf("table servers = %v, want %v\nstdout:\n%s", got, wantServers, stdout)
			}
			assertFindingRows(t, stdout, wantRows)
			assertContainsNone(t, "the findings block", findingsBlock(t, stdout), []string{findingsFixtureHost})
		})
	}
}

// TestPrintIgnored checks the one stderr line that counts the findings which
// the ignore list dropped (FR-10): the noun, the total, the sorted rule IDs
// with their counts, and no output for an empty or nil map.
func TestPrintIgnored(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		ignored map[string]int
		want    string // the whole stderr, "" for nothing
	}{
		{name: "nil map", ignored: nil, want: ""},
		{name: "empty map", ignored: map[string]int{}, want: ""},
		{
			name:    "one finding is singular",
			ignored: map[string]int{"MOAT-T4-002": 1},
			want:    "mcpmoat scan: 1 finding ignored: MOAT-T4-002 (1)\n",
		},
		{
			name:    "several findings of one rule are plural",
			ignored: map[string]int{"MOAT-T4-002": 2},
			want:    "mcpmoat scan: 2 findings ignored: MOAT-T4-002 (2)\n",
		},
		{
			name:    "rule IDs are sorted",
			ignored: map[string]int{"MOAT-T4-002": 4, "MOAT-T4-001": 1},
			want:    "mcpmoat scan: 5 findings ignored: MOAT-T4-001 (1), MOAT-T4-002 (4)\n",
		},
		{
			name: "many rules sort as text and add up",
			ignored: map[string]int{
				"MOAT-T5-001": 1, "MOAT-T4-004": 3, "MOAT-T4-001": 2, "MOAT-T4-003": 1,
			},
			want: "mcpmoat scan: 7 findings ignored: " +
				"MOAT-T4-001 (2), MOAT-T4-003 (1), MOAT-T4-004 (3), MOAT-T5-001 (1)\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c, stdout, stderr := newTestCLI(fakeGetenv(nil), testBuild)

			c.printIgnored(tt.ignored)

			if got := stderr.String(); got != tt.want {
				t.Errorf("stderr = %q, want %q", got, tt.want)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q, want empty: the line goes to stderr", stdout.String())
			}
		})
	}
}
