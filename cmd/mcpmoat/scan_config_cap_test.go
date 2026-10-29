package main

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
	"github.com/Ducarv/mcpmoat/internal/report"
	"github.com/Ducarv/mcpmoat/internal/rules"
)

// Tests for the caps of the config findings (issue #213): at most
// configRowsPerServer rows for one server and configRowsTotal rows for the
// whole scan, with one MOAT-T4-005 row for each server that lost rows.

// cfgCapCanary is the env value of the servers of the cap tests. It looks
// like a secret, and no row, stdout or stderr may hold it.
const cfgCapCanary = "mcpmoat-canary-cap-Vb7Nm2Kq9Wx4"

// cfgCapServer returns a stdio server with n env keys TOKEN_000, TOKEN_001
// and so on, which all hold cfgCapCanary. Each key gives one MOAT-T4-002 row
// (high with the built-in rules), in key order. With npx true, the server
// runs "npx -y pkg", which adds one MOAT-T4-003 row (medium) and then one
// MOAT-T4-004 row (low) after the env rows. Else it runs "node server.js",
// which gives no other row.
func cfgCapServer(name string, n int, npx bool) discover.Server {
	env := make(discover.SecretMap, n)
	for i := range n {
		env[cfgCapKey(i)] = discover.NewSecret(cfgCapCanary)
	}
	s := discover.Server{
		Name:      name,
		Transport: discover.TransportStdio,
		Command:   "node",
		Args:      discover.NewArgs([]string{"server.js"}),
		Env:       env,
	}
	if npx {
		s.Command = "npx"
		s.Args = discover.NewArgs([]string{"-y", "pkg"})
	}
	return s
}

// cfgCapUntrusted returns s as a server from a project file (discover marks
// such a server Untrusted).
func cfgCapUntrusted(s discover.Server) discover.Server {
	s.Untrusted = true
	return s
}

// cfgCapKey returns the env key number i of cfgCapServer.
func cfgCapKey(i int) string { return fmt.Sprintf("TOKEN_%03d", i) }

// cfgCapSet returns the built-in rule set with the severities in sev in place
// of the YAML severities, and without the rules in drop. A severity can be a
// word that mcpmoat does not know: NewSet does not check it. A dropped rule is
// unknown to the set, so findingRule gives its rows "critical".
func cfgCapSet(t *testing.T, sev map[string]rules.Severity, drop ...string) *rules.Set {
	t.Helper()
	builtin, errs := rules.Builtin()
	if len(errs) > 0 {
		t.Fatalf("rules.Builtin() returned %d errors, first: %v", len(errs), errs[0])
	}
	var kept []rules.Rule
	for _, r := range builtin {
		if slices.Contains(drop, r.ID) {
			continue
		}
		if s, ok := sev[r.ID]; ok {
			r.Severity = s
		}
		kept = append(kept, r)
	}
	set, errs := rules.NewSet(kept, nil)
	if len(errs) > 0 {
		t.Fatalf("rules.NewSet() returned %d errors, first: %v", len(errs), errs[0])
	}
	return set
}

// cfgCapView returns a row as "server|rule|severity|field|key|related", so a
// test can compare rows as short strings.
func cfgCapView(r report.FindingRow) string {
	return strings.Join([]string{r.Name, r.RuleID, r.Severity, r.Field, r.Key, r.Related}, "|")
}

// The views of the rows of cfgCapServer, for the want lists.
func secretView(server string, i int, sev string) string {
	return server + "|" + rules.RulePlaintextSecret + "|" + sev + "|env|" + cfgCapKey(i) + "|"
}

func unpinnedView(server, sev string) string {
	return server + "|" + rules.RuleUnpinnedPackage + "|" + sev + "|args||pkg"
}

func autoInstallView(server, sev string) string {
	return server + "|" + rules.RuleAutoInstall + "|" + sev + "|args||"
}

// cfgCapRowView is the view, as cfgCapView shows a row, of the MOAT-T4-005 row
// of server with sev and related. The row has no field and no key.
func cfgCapRowView(server, sev, related string) string {
	return server + "|" + rules.RuleConfigFindingCap + "|" + sev + "|||" + related
}

// cfgCapIgnores returns a scanIgnores. The entries in file are only in the
// all list, as if they came from .mcpmoat-ignore with --use-ignore-file. The
// entries in flags are in both lists, as if they came from --ignore.
func cfgCapIgnores(file, flags []rules.IgnoreEntry) *scanIgnores {
	ign := &scanIgnores{fileEntries: len(file)}
	for _, e := range file {
		ign.all.Add(e)
	}
	for _, e := range flags {
		ign.all.Add(e)
		ign.flags.Add(e)
	}
	return ign
}

// TestConfigFindingsCaps checks the caps of configChecks.findings with small
// caps: the rows that it keeps, their order, the MOAT-T4-005 row of each
// server that lost rows, the counts of each server, the ignored counts and
// the rule IDs that .mcpmoat-ignore cannot drop.
func TestConfigFindingsCaps(t *testing.T) {
	t.Parallel()
	typo, err := rules.NewBuiltinTyposquat()
	if err != nil {
		t.Fatalf("rules.NewBuiltinTyposquat() error = %v", err)
	}
	builtin := builtinSet(t)
	// lowFirst makes the env rows low and the last row (MOAT-T4-004)
	// critical, so the low rows come before the critical one.
	lowFirst := cfgCapSet(t, map[string]rules.Severity{
		rules.RulePlaintextSecret: rules.SeverityLow,
		rules.RuleAutoInstall:     rules.SeverityCritical,
	})
	secretCritical := cfgCapSet(t, map[string]rules.Severity{rules.RulePlaintextSecret: rules.SeverityCritical})
	secretBogus := cfgCapSet(t, map[string]rules.Severity{rules.RulePlaintextSecret: "bogus"})
	secretUnknown := cfgCapSet(t, nil, rules.RulePlaintextSecret)

	capEntry := rules.IgnoreEntry{RuleID: rules.RuleConfigFindingCap}
	secretEntry := rules.IgnoreEntry{RuleID: rules.RulePlaintextSecret, Server: "a"}

	tests := []struct {
		name    string
		set     *rules.Set
		caps    configCaps
		ignore  *scanIgnores
		servers []discover.Server
		want    []string // the rows, see cfgCapView
		// wantCounts is the number of rows of each server (the third result).
		wantCounts      []int
		wantIgnored     map[string]int
		wantFileBlocked []string
		// wantCut is the number of servers that lost rows to a cap (the
		// fifth result). It does not change when --ignore drops cap rows.
		wantCut int
	}{
		{
			name:    "below the per-server cap",
			set:     builtin,
			caps:    configCaps{perServer: 5, total: 100},
			servers: []discover.Server{cfgCapServer("a", 3, true), cfgCapServer("b", 2, false)},
			want: []string{
				secretView("a", 0, "high"), secretView("a", 1, "high"), secretView("a", 2, "high"),
				unpinnedView("a", "medium"), autoInstallView("a", "low"),
				secretView("b", 0, "high"), secretView("b", 1, "high"),
			},
			wantCounts: []int{5, 2},
		},
		{
			name:    "exactly at both caps",
			set:     builtin,
			caps:    configCaps{perServer: 5, total: 7},
			servers: []discover.Server{cfgCapServer("a", 3, true), cfgCapServer("b", 2, false)},
			want: []string{
				secretView("a", 0, "high"), secretView("a", 1, "high"), secretView("a", 2, "high"),
				unpinnedView("a", "medium"), autoInstallView("a", "low"),
				secretView("b", 0, "high"), secretView("b", 1, "high"),
			},
			wantCounts: []int{5, 2},
		},
		{
			name:    "equal severity keeps the first rows",
			set:     builtin,
			caps:    configCaps{perServer: 2},
			servers: []discover.Server{cfgCapServer("a", 5, false)},
			want: []string{
				secretView("a", 0, "high"), secretView("a", 1, "high"),
				cfgCapRowView("a", "high", "3 more config findings are not listed; limit 2"),
			},
			// The cap row is one of the rows of the server, but it does not
			// count toward the cap: 2 rows and the cap row.
			wantCounts: []int{3},
			wantCut:    1,
		},
		{
			// The scan cap keeps the rows of b first: a project file can ship
			// many servers, and must not push out the rows of a server that
			// the user set up.
			name:    "a project server does not push out the rows of a user server",
			set:     builtin,
			caps:    configCaps{perServer: 10, total: 3},
			servers: []discover.Server{cfgCapUntrusted(cfgCapServer("a", 3, false)), cfgCapServer("b", 2, false)},
			want: []string{
				secretView("a", 0, "high"),
				cfgCapRowView("a", "high", "2 more config findings are not listed; limit 3"),
				secretView("b", 0, "high"), secretView("b", 1, "high"),
			},
			wantCounts: []int{2, 2},
			wantCut:    1,
		},
		{
			name:    "the most severe rows win and keep their order",
			set:     builtin,
			caps:    configCaps{perServer: 4},
			servers: []discover.Server{cfgCapServer("a", 3, true)},
			want: []string{
				secretView("a", 0, "high"), secretView("a", 1, "high"), secretView("a", 2, "high"),
				unpinnedView("a", "medium"),
				cfgCapRowView("a", "high", "1 more config finding is not listed; limit 4"),
			},
			wantCounts: []int{5},
			wantCut:    1,
		},
		{
			name:    "a critical row after low rows is kept",
			set:     lowFirst,
			caps:    configCaps{perServer: 2},
			servers: []discover.Server{cfgCapServer("a", 3, true)},
			// The medium and the critical row are kept, in scan order. The
			// three low rows are left out, and the cap row is still high.
			want: []string{
				unpinnedView("a", "medium"), autoInstallView("a", "critical"),
				cfgCapRowView("a", "high", "3 more config findings are not listed; limit 2"),
			},
			wantCounts: []int{3},
			wantCut:    1,
		},
		{
			name:    "an omitted critical row makes the cap row critical",
			set:     secretCritical,
			caps:    configCaps{perServer: 1},
			servers: []discover.Server{cfgCapServer("a", 3, false)},
			want: []string{
				secretView("a", 0, "critical"),
				cfgCapRowView("a", "critical", "2 more config findings are not listed; limit 1"),
			},
			wantCounts: []int{2},
			wantCut:    1,
		},
		{
			name:    "an unknown severity counts as critical",
			set:     secretBogus,
			caps:    configCaps{perServer: 2},
			servers: []discover.Server{cfgCapServer("a", 3, true)},
			// The env rows keep the unknown word. They rank as critical, so
			// the first two win over the medium and the low row, and the
			// left-out one makes the cap row critical.
			want: []string{
				secretView("a", 0, "bogus"), secretView("a", 1, "bogus"),
				cfgCapRowView("a", "critical", "3 more config findings are not listed; limit 2"),
			},
			wantCounts: []int{3},
			wantCut:    1,
		},
		{
			name:    "a rule that the set does not have counts as critical",
			set:     secretUnknown,
			caps:    configCaps{perServer: 1},
			servers: []discover.Server{cfgCapServer("a", 2, true)},
			want: []string{
				secretView("a", 0, "critical"),
				cfgCapRowView("a", "critical", "3 more config findings are not listed; limit 1"),
			},
			wantCounts: []int{2},
			wantCut:    1,
		},
		{
			name:    "only medium and low rows left out give a high cap row",
			set:     builtin,
			caps:    configCaps{perServer: 3},
			servers: []discover.Server{cfgCapServer("a", 3, true)},
			want: []string{
				secretView("a", 0, "high"), secretView("a", 1, "high"), secretView("a", 2, "high"),
				cfgCapRowView("a", "high", "2 more config findings are not listed; limit 3"),
			},
			wantCounts: []int{4},
			wantCut:    1,
		},
		{
			name:    "the caps count only the rows that the ignore list keeps",
			set:     builtin,
			caps:    configCaps{perServer: 2},
			ignore:  cfgCapIgnores([]rules.IgnoreEntry{secretEntry}, nil),
			servers: []discover.Server{cfgCapServer("a", 5, true), cfgCapServer("b", 3, false)},
			// The file drops the five env rows of server a, so its other two
			// rows fit. Server b has no entry and loses a row.
			want: []string{
				unpinnedView("a", "medium"), autoInstallView("a", "low"),
				secretView("b", 0, "high"), secretView("b", 1, "high"),
				cfgCapRowView("b", "high", "1 more config finding is not listed; limit 2"),
			},
			wantCounts:  []int{2, 3},
			wantIgnored: map[string]int{rules.RulePlaintextSecret: 5},
			wantCut:     1,
		},
		{
			name:    "the scan cap cuts the later servers",
			set:     builtin,
			caps:    configCaps{perServer: 3, total: 4},
			servers: []discover.Server{cfgCapServer("a", 3, false), cfgCapServer("b", 3, false), cfgCapServer("c", 2, false)},
			// a takes 3 of the 4 rows, b gets the last one and c gets only
			// its cap row. The cap rows name the scan cap, which cut them.
			want: []string{
				secretView("a", 0, "high"), secretView("a", 1, "high"), secretView("a", 2, "high"),
				secretView("b", 0, "high"),
				cfgCapRowView("b", "high", "2 more config findings are not listed; limit 4"),
				cfgCapRowView("c", "high", "2 more config findings are not listed; limit 4"),
			},
			wantCounts: []int{3, 2, 1},
			wantCut:    2,
		},
		{
			name:    "the per-server cap and then the scan cap",
			set:     builtin,
			caps:    configCaps{perServer: 3, total: 4},
			servers: []discover.Server{cfgCapServer("a", 5, false), cfgCapServer("b", 3, false)},
			// The per-server cap cuts a (limit 3). The scan cap cuts b
			// (limit 4). The cap row of a does not use the scan cap.
			want: []string{
				secretView("a", 0, "high"), secretView("a", 1, "high"), secretView("a", 2, "high"),
				cfgCapRowView("a", "high", "2 more config findings are not listed; limit 3"),
				secretView("b", 0, "high"),
				cfgCapRowView("b", "high", "2 more config findings are not listed; limit 4"),
			},
			wantCounts: []int{4, 2},
			wantCut:    2,
		},
		{
			name:    "a server with no rows after the scan cap gets no cap row",
			set:     builtin,
			caps:    configCaps{perServer: 3, total: 3},
			servers: []discover.Server{cfgCapServer("a", 3, false), cfgCapServer("b", 0, false)},
			want: []string{
				secretView("a", 0, "high"), secretView("a", 1, "high"), secretView("a", 2, "high"),
			},
			wantCounts: []int{3, 0},
		},
		{
			name:    "--ignore drops the cap row",
			set:     builtin,
			caps:    configCaps{perServer: 2},
			ignore:  cfgCapIgnores(nil, []rules.IgnoreEntry{capEntry}),
			servers: []discover.Server{cfgCapServer("a", 3, false), cfgCapServer("b", 4, false)},
			want: []string{
				secretView("a", 0, "high"), secretView("a", 1, "high"),
				secretView("b", 0, "high"), secretView("b", 1, "high"),
			},
			wantCounts:  []int{2, 2},
			wantIgnored: map[string]int{rules.RuleConfigFindingCap: 2},
			// Both servers still count: the report is not complete.
			wantCut: 2,
		},
		{
			name:    "--ignore for one server drops only its cap row",
			set:     builtin,
			caps:    configCaps{perServer: 2},
			ignore:  cfgCapIgnores(nil, []rules.IgnoreEntry{{RuleID: rules.RuleConfigFindingCap, Server: "b"}}),
			servers: []discover.Server{cfgCapServer("a", 3, false), cfgCapServer("b", 4, false)},
			want: []string{
				secretView("a", 0, "high"), secretView("a", 1, "high"),
				cfgCapRowView("a", "high", "1 more config finding is not listed; limit 2"),
				secretView("b", 0, "high"), secretView("b", 1, "high"),
			},
			wantCounts:  []int{3, 2},
			wantIgnored: map[string]int{rules.RuleConfigFindingCap: 1},
			wantCut:     2,
		},
		{
			name:    ".mcpmoat-ignore cannot drop the cap row",
			set:     builtin,
			caps:    configCaps{perServer: 2},
			ignore:  cfgCapIgnores([]rules.IgnoreEntry{capEntry}, nil),
			servers: []discover.Server{cfgCapServer("a", 3, false), cfgCapServer("b", 4, false)},
			// Both cap rows stay. The blocked rule ID is listed once.
			want: []string{
				secretView("a", 0, "high"), secretView("a", 1, "high"),
				cfgCapRowView("a", "high", "1 more config finding is not listed; limit 2"),
				secretView("b", 0, "high"), secretView("b", 1, "high"),
				cfgCapRowView("b", "high", "2 more config findings are not listed; limit 2"),
			},
			wantCounts:      []int{3, 3},
			wantFileBlocked: []string{rules.RuleConfigFindingCap},
			wantCut:         2,
		},
		{
			name:    "a .mcpmoat-ignore entry with no cap row is not blocked",
			set:     builtin,
			caps:    configCaps{perServer: 5},
			ignore:  cfgCapIgnores([]rules.IgnoreEntry{capEntry}, nil),
			servers: []discover.Server{cfgCapServer("a", 2, false)},
			want: []string{
				secretView("a", 0, "high"), secretView("a", 1, "high"),
			},
			wantCounts: []int{2},
		},
		// The scan cap keeps the most severe rows of the whole scan (issue
		// #213), not the rows of the first servers. Servers early in the
		// order cannot push a severe row of a later server out of the
		// report with many weak rows.
		{
			name:    "the scan cap keeps a critical row of a later server",
			set:     lowFirst,
			caps:    configCaps{perServer: 3, total: 4},
			servers: []discover.Server{cfgCapServer("a", 3, false), cfgCapServer("b", 2, false), cfgCapServer("c", 0, true)},
			// a has 3 low rows, b 2 low rows, c a medium and a critical row:
			// 7 rows for a cap of 4. The critical and the medium row of c
			// are kept. The 2 other places go to low rows, and among equal
			// rows the earlier server wins: a keeps 2 rows, b keeps none.
			// Each kept row stays in scan order, and the cap rows name the
			// scan cap.
			want: []string{
				secretView("a", 0, "low"), secretView("a", 1, "low"),
				cfgCapRowView("a", "high", "1 more config finding is not listed; limit 4"),
				cfgCapRowView("b", "high", "2 more config findings are not listed; limit 4"),
				unpinnedView("c", "medium"), autoInstallView("c", "critical"),
			},
			wantCounts: []int{3, 1, 2},
			wantCut:    2,
		},
		{
			name:    "the scan cap keeps a high row of a later server",
			set:     builtin,
			caps:    configCaps{perServer: 3, total: 3},
			servers: []discover.Server{cfgCapServer("a", 0, true), cfgCapServer("b", 0, true), cfgCapServer("c", 1, false)},
			// a and b each have a medium and a low row, c one high row: 5
			// rows for a cap of 3. The high row of c and the two medium
			// rows are kept. The low rows are left out, and the cap rows
			// are high.
			want: []string{
				unpinnedView("a", "medium"),
				cfgCapRowView("a", "high", "1 more config finding is not listed; limit 3"),
				unpinnedView("b", "medium"),
				cfgCapRowView("b", "high", "1 more config finding is not listed; limit 3"),
				secretView("c", 0, "high"),
			},
			wantCounts: []int{2, 2, 1},
			wantCut:    2,
		},
		{
			name:    "at the scan cap rows of mixed severity keep scan order",
			set:     lowFirst,
			caps:    configCaps{perServer: 3, total: 7},
			servers: []discover.Server{cfgCapServer("a", 3, false), cfgCapServer("b", 2, false), cfgCapServer("c", 0, true)},
			// The same servers as above, with a scan cap that all 7 rows
			// fit: no row moves and there is no cap row.
			want: []string{
				secretView("a", 0, "low"), secretView("a", 1, "low"), secretView("a", 2, "low"),
				secretView("b", 0, "low"), secretView("b", 1, "low"),
				unpinnedView("c", "medium"), autoInstallView("c", "critical"),
			},
			wantCounts: []int{3, 2, 2},
		},
		{
			name:    "a server cut by both caps gets one cap row",
			set:     secretCritical,
			caps:    configCaps{perServer: 3, total: 4},
			servers: []discover.Server{cfgCapServer("z", 3, false), cfgCapServer("a", 2, true)},
			// z has 3 critical rows. a has 2 critical rows, a medium and a
			// low row. The per-server cap leaves out the low row of a. The
			// scan cap then keeps the 3 rows of z and the first critical row
			// of a, so it leaves out a critical and the medium row of a. The
			// one cap row of a counts all 3 rows (1 + 2), names the scan cap
			// and has the highest severity of both steps: critical.
			want: []string{
				secretView("z", 0, "critical"), secretView("z", 1, "critical"), secretView("z", 2, "critical"),
				secretView("a", 0, "critical"),
				cfgCapRowView("a", "critical", "3 more config findings are not listed; limit 4"),
			},
			wantCounts: []int{3, 2},
			// a counts once, although both caps cut it.
			wantCut: 1,
		},
		{
			name:    "a server cut by both caps with only weak rows left out is high",
			set:     lowFirst,
			caps:    configCaps{perServer: 3, total: 2},
			servers: []discover.Server{cfgCapServer("a", 3, true), cfgCapServer("b", 0, true)},
			// a has 3 low rows, a medium and a critical row. The per-server
			// cap leaves out 2 low rows. b has a medium and a critical row.
			// The scan cap keeps the two critical rows, so a loses its
			// medium and one more low row, and b loses its medium row.
			want: []string{
				autoInstallView("a", "critical"),
				cfgCapRowView("a", "high", "4 more config findings are not listed; limit 2"),
				autoInstallView("b", "critical"),
				cfgCapRowView("b", "high", "1 more config finding is not listed; limit 2"),
			},
			wantCounts: []int{2, 2},
			wantCut:    2,
		},
		{
			name:    "--ignore drops the cap rows of both caps",
			set:     secretCritical,
			caps:    configCaps{perServer: 3, total: 4},
			ignore:  cfgCapIgnores(nil, []rules.IgnoreEntry{capEntry}),
			servers: []discover.Server{cfgCapServer("z", 3, false), cfgCapServer("a", 2, true)},
			// The same cut as above. The cap row is gone, but a still
			// counts as a server that lost rows.
			want: []string{
				secretView("z", 0, "critical"), secretView("z", 1, "critical"), secretView("z", 2, "critical"),
				secretView("a", 0, "critical"),
			},
			wantCounts:  []int{3, 1},
			wantIgnored: map[string]int{rules.RuleConfigFindingCap: 1},
			wantCut:     1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rows, ignored, counts, fileBlocked, cutServers := configChecks{set: tt.set, typo: typo, caps: tt.caps}.findings(tt.ignore, tt.servers)
			if cutServers != tt.wantCut {
				t.Errorf("cutServers = %d, want %d", cutServers, tt.wantCut)
			}

			got := make([]string, 0, len(rows))
			for _, r := range rows {
				got = append(got, cfgCapView(r))
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("rows =\n  %s\nwant\n  %s", strings.Join(got, "\n  "), strings.Join(tt.want, "\n  "))
			}
			if !slices.Equal(counts, tt.wantCounts) {
				t.Errorf("counts = %v, want %v", counts, tt.wantCounts)
			}
			if !maps.Equal(ignored, tt.wantIgnored) {
				t.Errorf("ignored = %v, want %v", ignored, tt.wantIgnored)
			}
			if tt.wantIgnored == nil && ignored != nil {
				t.Errorf("ignored = %#v, want nil", ignored)
			}
			if !slices.Equal(fileBlocked, tt.wantFileBlocked) || (tt.wantFileBlocked == nil && fileBlocked != nil) {
				t.Errorf("fileBlocked = %#v, want %#v", fileBlocked, tt.wantFileBlocked)
			}
			assertCapRowText(t, rows)
		})
	}
}

// assertCapRowText fails the test unless every MOAT-T4-005 row of rows has
// the fixed texts, no field and no key. It also fails when a row holds
// cfgCapCanary.
func assertCapRowText(t *testing.T, rows []report.FindingRow) {
	t.Helper()
	for i, r := range rows {
		for name, field := range map[string]string{
			"RuleID": r.RuleID, "Severity": r.Severity, "Server": r.Name, "Title": r.Title,
			"Risk": r.Risk, "Remediation": r.Remediation, "Field": r.Field, "Key": r.Key, "Related": r.Related,
		} {
			if strings.Contains(field, cfgCapCanary) {
				t.Errorf("row %d (%s) field %s holds the secret value", i, r.RuleID, name)
			}
		}
		if r.RuleID != rules.RuleConfigFindingCap {
			continue
		}
		if r.Title != configCapTitle || r.Risk != configCapRisk || r.Remediation != configCapRemediation {
			t.Errorf("cap row %d has Title %q, Risk %q, Remediation %q, want the fixed texts", i, r.Title, r.Risk, r.Remediation)
		}
		if r.Field != "" || r.Key != "" {
			t.Errorf("cap row %d has Field %q and Key %q, want both empty", i, r.Field, r.Key)
		}
	}
}

// TestConfigFindingsCapsDefault checks the real caps (the zero configCaps):
// 100 rows for one server and 10,000 rows for the scan. Below the caps, the
// rows are the same as with caps that are much larger.
func TestConfigFindingsCapsDefault(t *testing.T) {
	t.Parallel()
	set := builtinSet(t)
	typo, err := rules.NewBuiltinTyposquat()
	if err != nil {
		t.Fatalf("rules.NewBuiltinTyposquat() error = %v", err)
	}
	// rowsOf returns the views of the rows, the counts of findings and the
	// number of servers that lost rows to a cap.
	rowsOf := func(caps configCaps, servers []discover.Server) ([]string, []int, int) {
		rows, _, counts, _, cut := configChecks{set: set, typo: typo, caps: caps}.findings(nil, servers)
		views := make([]string, 0, len(rows))
		for _, r := range rows {
			views = append(views, cfgCapView(r))
		}
		return views, counts, cut
	}

	t.Run("below the caps the rows do not change", func(t *testing.T) {
		t.Parallel()
		servers := []discover.Server{cfgCapServer("a", configRowsPerServer-2, true), cfgCapServer("b", 7, false)}
		got, gotCounts, gotCut := rowsOf(configCaps{}, servers)
		want, wantCounts, _ := rowsOf(configCaps{perServer: 1 << 20, total: 1 << 20}, servers)
		if !slices.Equal(got, want) || !slices.Equal(gotCounts, wantCounts) {
			t.Errorf("rows with the default caps differ from the rows with no cap\ngot:  %v %q\nwant: %v %q", gotCounts, got, wantCounts, want)
		}
		if gotCut != 0 {
			t.Errorf("cutServers = %d, want 0", gotCut)
		}
		if gotCounts[0] != configRowsPerServer {
			t.Errorf("server a has %d rows, want %d", gotCounts[0], configRowsPerServer)
		}
	})

	t.Run("the per-server cap is 100", func(t *testing.T) {
		t.Parallel()
		got, counts, cut := rowsOf(configCaps{}, []discover.Server{cfgCapServer("a", 150, false)})
		if cut != 1 {
			t.Errorf("cutServers = %d, want 1", cut)
		}
		if counts[0] != configRowsPerServer+1 || len(got) != configRowsPerServer+1 {
			t.Fatalf("counts = %v and %d rows, want %d", counts, len(got), configRowsPerServer+1)
		}
		if want := secretView("a", configRowsPerServer-1, "high"); got[configRowsPerServer-1] != want {
			t.Errorf("last kept row = %q, want %q", got[configRowsPerServer-1], want)
		}
		if want := cfgCapRowView("a", "high", "50 more config findings are not listed; limit 100"); got[configRowsPerServer] != want {
			t.Errorf("cap row = %q, want %q", got[configRowsPerServer], want)
		}
	})

	t.Run("the scan cap is 10000", func(t *testing.T) {
		t.Parallel()
		// 101 servers of 100 rows each: the first 100 fill the scan cap, and
		// the last one gets only its cap row.
		n := configRowsTotal/configRowsPerServer + 1
		servers := make([]discover.Server, n)
		for i := range servers {
			servers[i] = cfgCapServer(fmt.Sprintf("s%03d", i), configRowsPerServer, false)
		}
		got, counts, cut := rowsOf(configCaps{}, servers)
		if cut != 1 {
			t.Errorf("cutServers = %d, want 1", cut)
		}
		if len(got) != configRowsTotal+1 {
			t.Fatalf("got %d rows, want %d", len(got), configRowsTotal+1)
		}
		if counts[n-2] != configRowsPerServer || counts[n-1] != 1 {
			t.Errorf("the last two counts = %v, want [%d 1]", counts[n-2:], configRowsPerServer)
		}
		want := cfgCapRowView(fmt.Sprintf("s%03d", n-1), "high", "100 more config findings are not listed; limit 10000")
		if got[len(got)-1] != want {
			t.Errorf("last row = %q, want %q", got[len(got)-1], want)
		}
	})
}

// TestConfigCapsOrDefault checks that a zero or negative cap gives the
// default, and that a positive cap stays.
func TestConfigCapsOrDefault(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   configCaps
		want configCaps
	}{
		{"zero value", configCaps{}, configCaps{perServer: configRowsPerServer, total: configRowsTotal}},
		{"negative values", configCaps{perServer: -1, total: -5}, configCaps{perServer: configRowsPerServer, total: configRowsTotal}},
		{"only per server", configCaps{perServer: 3}, configCaps{perServer: 3, total: configRowsTotal}},
		{"only total", configCaps{total: 7}, configCaps{perServer: configRowsPerServer, total: 7}},
		{"both set", configCaps{perServer: 3, total: 7}, configCaps{perServer: 3, total: 7}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.in.orDefault(); got != tt.want {
				t.Errorf("%+v.orDefault() = %+v, want %+v", tt.in, got, tt.want)
			}
		})
	}
	if configRowsPerServer != 100 || configRowsTotal != 10_000 {
		t.Errorf("caps = %d and %d, want 100 and 10000 (the help text and docs name them)", configRowsPerServer, configRowsTotal)
	}
}

// cfgHits returns one configHit for each severity word, with index i.
func cfgHits(severities ...string) []configHit {
	hits := make([]configHit, 0, len(severities))
	for i, s := range severities {
		hits = append(hits, configHit{index: i, severity: s})
	}
	return hits
}

// TestConfigCapCutHits checks which hits cutConfigHits keeps: the most severe
// ones (an unknown severity counts as critical), the first ones among equal
// severities, in their first order.
func TestConfigCapCutHits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		hits        []configHit
		limit       int
		wantKept    []int // the indexes of the kept hits
		wantOmitted []int // the indexes of the omitted hits, in any order
	}{
		{"no hits", nil, 3, nil, nil},
		{"all fit", cfgHits("low", "high"), 2, []int{0, 1}, nil},
		{"equal severity keeps the first", cfgHits("high", "high", "high"), 2, []int{0, 1}, []int{2}},
		{"severe hits win and keep their order", cfgHits("low", "critical", "low", "medium"), 2, []int{1, 3}, []int{0, 2}},
		{"unknown word ranks as critical", cfgHits("high", "bogus", "critical"), 2, []int{1, 2}, []int{0}},
		{"empty word ranks as critical", cfgHits("medium", ""), 1, []int{1}, []int{0}},
		{"wrong case ranks as critical", cfgHits("high", "HIGH"), 1, []int{1}, []int{0}},
		{"zero limit keeps nothing", cfgHits("high", "low"), 0, []int{}, []int{0, 1}},
		{"negative limit keeps nothing", cfgHits("high"), -1, []int{}, []int{0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			kept, omitted := cutConfigHits(tt.hits, tt.limit)
			indexes := func(hs []configHit) []int {
				out := make([]int, 0, len(hs))
				for _, h := range hs {
					out = append(out, h.index)
				}
				return out
			}
			if got := indexes(kept); !slices.Equal(got, tt.wantKept) {
				t.Errorf("kept = %v, want %v", got, tt.wantKept)
			}
			gotOmitted := indexes(omitted)
			slices.Sort(gotOmitted)
			if !slices.Equal(gotOmitted, tt.wantOmitted) {
				t.Errorf("omitted = %v, want %v", gotOmitted, tt.wantOmitted)
			}
		})
	}
}

// TestConfigCapCutHitsTrustedFirst checks that, among hits of the same
// severity, cutConfigHits keeps the hits of trusted servers before the hits of
// untrusted ones, and that severity still comes first.
func TestConfigCapCutHitsTrustedFirst(t *testing.T) {
	t.Parallel()

	hits := []configHit{
		{index: 0, severity: "high", untrusted: true},
		{index: 1, severity: "high", untrusted: true},
		{index: 2, severity: "high"},
		{index: 3, severity: "critical", untrusted: true},
		{index: 4, severity: "high"},
	}
	tests := []struct {
		name  string
		limit int
		want  []int // the indexes of the kept hits, in their first order
	}{
		{"a critical untrusted hit still beats a high trusted one", 2, []int{2, 3}},
		{"trusted hits come before untrusted ones of the same severity", 3, []int{2, 3, 4}},
		{"untrusted hits fill the room that is left, first ones first", 4, []int{0, 2, 3, 4}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			kept, _ := cutConfigHits(hits, tt.limit)
			got := make([]int, 0, len(kept))
			for _, h := range kept {
				got = append(got, h.index)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("kept = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestConfigCapSeverity checks the severity of the cap row: the highest
// severity of the omitted hits, never below high, and critical for an
// unknown word.
func TestConfigCapSeverity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		omitted []configHit
		want    rules.Severity
	}{
		{"no hits is high", nil, rules.SeverityHigh},
		{"low is raised to high", cfgHits("low"), rules.SeverityHigh},
		{"medium and low are raised to high", cfgHits("medium", "low"), rules.SeverityHigh},
		{"high stays high", cfgHits("high", "low"), rules.SeverityHigh},
		{"a critical hit makes it critical", cfgHits("low", "critical", "high"), rules.SeverityCritical},
		{"an unknown word is critical", cfgHits("low", "bogus"), rules.SeverityCritical},
		{"an empty word is critical", cfgHits(""), rules.SeverityCritical},
		{"a wrong case word is critical", cfgHits("HIGH"), rules.SeverityCritical},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := configCapSeverity(tt.omitted); got != tt.want {
				t.Errorf("configCapSeverity(%v) = %q, want %q", tt.omitted, got, tt.want)
			}
		})
	}
}

// TestConfigCapText checks the Related text of the cap row and the stderr
// warning text: singular for one, plural for more.
func TestConfigCapText(t *testing.T) {
	t.Parallel()

	related := []struct {
		omitted, limit int
		want           string
	}{
		{1, 100, "1 more config finding is not listed; limit 100"},
		{2, 100, "2 more config findings are not listed; limit 100"},
		{9990, 10000, "9990 more config findings are not listed; limit 10000"},
	}
	for _, tt := range related {
		if got := configCapText(tt.omitted, tt.limit); got != tt.want {
			t.Errorf("configCapText(%d, %d) = %q, want %q", tt.omitted, tt.limit, got, tt.want)
		}
	}

	warnings := []struct {
		servers int
		want    string
	}{
		{1, "config findings were left out for 1 server; see MOAT-T4-005"},
		{2, "config findings were left out for 2 servers; see MOAT-T4-005"},
		{37, "config findings were left out for 37 servers; see MOAT-T4-005"},
	}
	for _, tt := range warnings {
		if got := configCapWarningText(tt.servers); got != tt.want {
			t.Errorf("configCapWarningText(%d) = %q, want %q", tt.servers, got, tt.want)
		}
	}
}

// cfgCapEnv returns n env entries TOKEN_000, TOKEN_001 and so on, which all
// hold value, for a server of writeServers.
func cfgCapEnv(n int, value string) map[string]string {
	env := make(map[string]string, n)
	for i := range n {
		env[cfgCapKey(i)] = value
	}
	return env
}

// cfgCapScanServers are the servers of TestScanConfigCap. With a per-server
// cap of 2, env-srv (5 env secrets) loses 3 rows and hdr-srv (3 header
// secrets) loses 1. small-srv (1 env secret) fits. The values are the
// canaries of discovertest, which assertNoLeakBoth looks for.
func cfgCapScanServers() map[string]any {
	headers := make(map[string]string, 3)
	for i := range 3 {
		headers[fmt.Sprintf("X-Api-Key-%d", i)] = discovertest.CanaryHeader
	}
	return map[string]any{
		"env-srv":   map[string]any{"command": "run", "env": cfgCapEnv(5, discovertest.CanaryEnv)},
		"hdr-srv":   map[string]any{"type": "http", "url": "https://" + findingsFixtureHost + "/mcp", "headers": headers},
		"small-srv": map[string]any{"command": "run", "env": cfgCapEnv(1, discovertest.CanaryEnv)},
	}
}

// cfgCapWarning is the stderr line of a scan in which two servers lost config
// rows. It prints also when --ignore drops the cap rows.
const cfgCapWarning = scanWarnPrefix + "config findings were left out for 2 servers; see MOAT-T4-005"

// TestScanConfigCap runs "scan --no-connect" with a per-server cap of 2 config
// rows (cli.maxConfigRows) and checks what the user sees: the MOAT-T4-005 rows
// in the report and in --json, the one stderr warning, the exit code, the
// .mcpmoat-ignore file that cannot drop the cap rows, and --ignore that can.
// No env or header value shows anywhere.
func TestScanConfigCap(t *testing.T) {
	t.Parallel()

	envRelated := "3 more config findings are not listed; limit 2"
	hdrRelated := "1 more config finding is not listed; limit 2"

	tests := []struct {
		name string
		// flags are the scan flags after the --no-connect and --config ones.
		flags []string
		// ignoreFile is the content of .mcpmoat-ignore, or "" for no file.
		ignoreFile string
		wantCode   int
		wantLines  []lineWant // all stderr lines, in order
		// wantCapRows is true when the report holds the two cap rows.
		wantCapRows bool
	}{
		{
			name:        "default",
			wantCode:    exitFindings,
			wantLines:   []lineWant{exactLine(cfgCapWarning)},
			wantCapRows: true,
		},
		{
			name:        "--fail-on critical",
			flags:       []string{"--fail-on", "critical"},
			wantCode:    exitOK,
			wantLines:   []lineWant{exactLine(failOnCriticalNotice), exactLine(cfgCapWarning)},
			wantCapRows: true,
		},
		{
			name:     "--ignore MOAT-T4-005",
			flags:    []string{"--ignore", rules.RuleConfigFindingCap},
			wantCode: exitFindings,
			// The cap rows are gone, but the report is still not complete,
			// so the warning prints. The config step prints it before the
			// count of ignored findings.
			wantLines: []lineWant{
				exactLine(cfgCapWarning),
				exactLine(scanPrefix + "2 findings ignored: MOAT-T4-005 (2)"),
			},
		},
		{
			name:       ".mcpmoat-ignore cannot drop the cap rows",
			flags:      []string{useIgnoreFileFlag},
			ignoreFile: rules.RuleConfigFindingCap + "\n",
			wantCode:   exitFindings,
			wantLines: []lineWant{
				exactLine(scanPrefix + "using 1 entry from .mcpmoat-ignore"),
				exactLine(fileCannotIgnoreWarning(rules.RuleConfigFindingCap)),
				exactLine(cfgCapWarning),
			},
			wantCapRows: true,
		},
	}
	for _, tt := range tests {
		for _, format := range []string{"text", "json"} {
			t.Run(tt.name+"/"+format, func(t *testing.T) {
				t.Parallel()

				home, work := t.TempDir(), t.TempDir()
				args := scanServersArgs(t, "config", home, cfgCapScanServers())
				args = append(args, tt.flags...)
				if format == "json" {
					args = append(args, "--json")
				}
				if tt.ignoreFile != "" {
					writeTestFile(t, work, rules.IgnoreFileName, tt.ignoreFile)
				}
				c, stdout, stderr := dirsCLI(t, home, work)
				c.maxConfigRows = 2

				code, out, errOut := runScanArgs(c, stdout, stderr, args...)

				if code != tt.wantCode {
					t.Errorf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tt.wantCode, out, errOut)
				}
				assertStderrLines(t, errOut, tt.wantLines)
				assertNoLeakBoth(t, out, errOut)
				assertNoEscape(t, out, errOut)
				assertContainsNone(t, "stderr", errOut, []string{"env-srv", "hdr-srv", "TOKEN_", "X-Api-Key"})

				if format == "json" {
					cfgCapCheckJSON(t, out, tt.wantCapRows, envRelated, hdrRelated)
					return
				}
				cfgCapCheckText(t, out, tt.wantCapRows, envRelated, hdrRelated)
			})
		}
	}
}

// cfgCapCheckText checks the terminal report of TestScanConfigCap: two kept rows
// for env-srv and hdr-srv, one for small-srv, and, when wantCap is true, one
// high MOAT-T4-005 row for env-srv and for hdr-srv with its Related text.
func cfgCapCheckText(t *testing.T, stdout string, wantCap bool, envRelated, hdrRelated string) {
	t.Helper()
	perServer := map[string]int{}
	var capRows []scanFinding
	for _, f := range parseFindings(t, stdout) {
		if f.RuleID == rules.RuleConfigFindingCap {
			capRows = append(capRows, f)
			continue
		}
		if f.RuleID != rules.RulePlaintextSecret {
			t.Errorf("unexpected finding %s for %s", f.RuleID, f.Name)
		}
		perServer[f.Name]++
	}
	if want := map[string]int{"env-srv": 2, "hdr-srv": 2, "small-srv": 1}; !maps.Equal(perServer, want) {
		t.Errorf("MOAT-T4-002 findings by server = %v, want %v\nstdout:\n%s", perServer, want, stdout)
	}
	if !wantCap {
		if len(capRows) != 0 {
			t.Errorf("stdout has %d MOAT-T4-005 findings, want none\nstdout:\n%s", len(capRows), stdout)
		}
		return
	}
	if len(capRows) != 2 {
		t.Fatalf("stdout has %d MOAT-T4-005 findings, want 2\nstdout:\n%s", len(capRows), stdout)
	}
	for _, f := range capRows {
		if f.Severity != "high" || f.Title != configCapTitle || f.Risk != configCapRisk || f.Fix != configCapRemediation {
			t.Errorf("cap finding of %s = %+v, want high with the fixed texts", f.Name, f)
		}
	}
	assertContainsAll(t, "stdout", stdout, []string{envRelated, hdrRelated})
	// The summary counts the cap row as a finding of the server.
	for _, row := range summaryRows(t, stdout) {
		want := map[string]int{"env-srv": 3, "hdr-srv": 3, "small-srv": 1}[row.Name]
		if row.Findings != want {
			t.Errorf("summary of %s has %d findings, want %d", row.Name, row.Findings, want)
		}
	}
}

// cfgCapCheckJSON checks the --json report of TestScanConfigCap: the report is
// complete, and, when wantCap is true, it has one high MOAT-T4-005 finding
// for env-srv and for hdr-srv with no field and no key.
func cfgCapCheckJSON(t *testing.T, stdout string, wantCap bool, envRelated, hdrRelated string) {
	t.Helper()
	doc := decodeScanJSON(t, stdout)
	if !doc.Complete {
		t.Errorf("complete = false, want true: a cut of config findings is not an execution error")
	}
	var got []report.JSONFinding
	for _, f := range doc.Findings {
		if f.RuleID == rules.RuleConfigFindingCap {
			got = append(got, f)
		}
	}
	var want []report.JSONFinding
	if wantCap {
		want = []report.JSONFinding{
			{RuleID: rules.RuleConfigFindingCap, Severity: "high", Server: "env-srv", Related: envRelated, Source: report.SourceRule},
			{RuleID: rules.RuleConfigFindingCap, Severity: "high", Server: "hdr-srv", ServerIndex: 1, Related: hdrRelated, Source: report.SourceRule},
		}
	}
	if !slices.Equal(got, want) {
		t.Errorf("MOAT-T4-005 findings = %+v, want %+v", got, want)
	}
	if n := len(doc.Findings) - len(got); n != 5 {
		t.Errorf("JSON has %d other findings, want 5 (2 + 2 + 1 kept rows)", n)
	}
}

// TestScanConfigCapOneServer checks the singular warning: one server lost
// config rows. The warning prints also when --ignore drops the cap row. Below
// the cap, the same scan prints no warning and no cap row.
func TestScanConfigCapOneServer(t *testing.T) {
	t.Parallel()

	servers := map[string]any{"env-srv": map[string]any{"command": "run", "env": cfgCapEnv(3, discovertest.CanaryEnv)}}
	const oneServerWarning = scanWarnPrefix + "config findings were left out for 1 server; see MOAT-T4-005"
	tests := []struct {
		name      string
		maxRows   int
		flags     []string
		wantLines []lineWant
		wantIDs   []string
	}{
		{
			name:      "over the cap",
			maxRows:   2,
			wantLines: []lineWant{exactLine(oneServerWarning)},
			wantIDs:   []string{rules.RulePlaintextSecret, rules.RulePlaintextSecret, rules.RuleConfigFindingCap},
		},
		{
			name:    "over the cap with --ignore MOAT-T4-005",
			maxRows: 2,
			flags:   []string{"--ignore", rules.RuleConfigFindingCap},
			wantLines: []lineWant{
				exactLine(oneServerWarning),
				exactLine(scanPrefix + "1 finding ignored: MOAT-T4-005 (1)"),
			},
			wantIDs: []string{rules.RulePlaintextSecret, rules.RulePlaintextSecret},
		},
		{
			name:    "at the cap",
			maxRows: 3,
			wantIDs: []string{rules.RulePlaintextSecret, rules.RulePlaintextSecret, rules.RulePlaintextSecret},
		},
	}
	for _, tt := range tests {
		for _, mode := range configModes {
			t.Run(tt.name+"/"+mode, func(t *testing.T) {
				t.Parallel()
				home, work := t.TempDir(), t.TempDir()
				args := scanServersArgs(t, mode, home, servers)
				args = append(args, tt.flags...)
				c, stdout, stderr := dirsCLI(t, home, work)
				c.maxConfigRows = tt.maxRows

				code, out, errOut := runScanArgs(c, stdout, stderr, args...)

				if code != exitFindings {
					t.Errorf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitFindings, out, errOut)
				}
				assertStderrLines(t, errOut, tt.wantLines)
				assertFindingIDs(t, out, tt.wantIDs)
				assertNoLeakBoth(t, out, errOut)
			})
		}
	}
}
