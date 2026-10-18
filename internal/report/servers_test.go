package report_test

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
	"github.com/Ducarv/mcpmoat/internal/report"
)

// threeServers returns one stdio, one http and one project-scope sse server.
// The http server has canary values in the URL, and the stdio and http
// servers have canary values in Env and Headers.
func threeServers() []discover.Server {
	return []discover.Server{
		{
			Name:      "fs",
			Client:    discover.ClientClaudeCode,
			Scope:     discover.ScopeGlobal,
			Source:    "/home/u/.claude.json",
			Transport: discover.TransportStdio,
			Command:   "npx",
			Args:      []string{"-y", "@scope/server-fs", "/data"},
			Env:       discover.SecretMap{"API_KEY": discover.NewSecret(discovertest.CanaryEnv)},
		},
		{
			Name:      "remote",
			Client:    discover.ClientCursor,
			Scope:     discover.ScopeGlobal,
			Source:    "/home/u/.cursor/mcp.json",
			Transport: discover.TransportHTTP,
			URL: discover.NewURL("https://user:" + discovertest.CanaryURL +
				"@example.com/mcp?k=" + discovertest.CanaryURL),
			Headers: discover.SecretMap{
				"Authorization": discover.NewSecret("Bearer " + discovertest.CanaryHeader),
			},
		},
		{
			Name:        "legacy",
			Client:      discover.ClientClaudeCode,
			Scope:       discover.ScopeProject,
			ProjectPath: "/work/app",
			Source:      "/work/app/.mcp.json",
			Transport:   discover.TransportSSE,
			URL:         discover.NewURL("https://sse.example.com/events"),
		},
	}
}

func TestWriteServersExactTable(t *testing.T) {
	t.Parallel()

	// Columns are padded to the widest cell plus 3 spaces. The last column has
	// no padding. Secrets and credentials never show.
	const want = "NAME     CLIENT        SCOPE               TRANSPORT   SOURCE                     COMMAND/URL\n" +
		"fs       claude-code   global              stdio       /home/u/.claude.json       npx -y @scope/server-fs /data\n" +
		"remote   cursor        global              http        /home/u/.cursor/mcp.json   https://********@example.com/mcp?k=********\n" +
		"legacy   claude-code   project:/work/app   sse         /work/app/.mcp.json        https://sse.example.com/events\n"

	var sb strings.Builder
	if err := report.WriteServers(&sb, threeServers()); err != nil {
		t.Fatalf("WriteServers() error = %v, want nil", err)
	}
	if got := sb.String(); got != want {
		t.Errorf("WriteServers() =\n%q\nwant\n%q", got, want)
	}
}

func TestWriteServersEmpty(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		servers []discover.Server
	}{
		{name: "nil", servers: nil},
		{name: "empty slice", servers: []discover.Server{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var sb strings.Builder
			if err := report.WriteServers(&sb, tt.servers); err != nil {
				t.Fatalf("WriteServers() error = %v, want nil", err)
			}
			if got, want := sb.String(), "No MCP servers found.\n"; got != want {
				t.Errorf("WriteServers() = %q, want %q", got, want)
			}
		})
	}
}

func TestCommand(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		command string
		args    []string
		want    string
	}{
		{name: "plain", command: "npx", args: []string{"-y", "server"}, want: "npx -y server"},
		{name: "no args", command: "server", args: nil, want: "server"},
		{name: "empty args slice", command: "server", args: []string{}, want: "server"},
		{name: "arg with a space", command: "node", args: []string{"my dir/a.js"}, want: `node "my dir/a.js"`},
		{name: "command with a space", command: "my tool", args: []string{"x"}, want: `"my tool" x`},
		{name: "empty arg", command: "run", args: []string{"", "x"}, want: `run "" x`},
		{name: "only empty arg", command: "run", args: []string{""}, want: `run ""`},
		{name: "empty command", command: "", args: []string{"x"}, want: `"" x`},
		{name: "arg with ESC", command: "run", args: []string{"a\x1b[2Jb"}, want: `run "a\x1b[2Jb"`},
		{name: "arg with tab", command: "run", args: []string{"a\tb"}, want: `run "a\tb"`},
		{name: "arg with newline", command: "run", args: []string{"a\nb"}, want: `run "a\nb"`},
		{name: "arg with bidi override", command: "run", args: []string{"a\u202eb"}, want: `run "a\u202eb"`},
		{name: "arg with invalid UTF-8", command: "run", args: []string{"a\xffb"}, want: `run "a\xffb"`},
		{name: "command with ESC", command: "\x1b]0;x\a", args: []string{"y"}, want: `"\x1b]0;x\a" y`},
		{name: "unsafe arg with a space is quoted once", command: "run", args: []string{"a b\x1b"}, want: `run "a b\x1b"`},
		{name: "only the unsafe arg is quoted", command: "run", args: []string{"ok", "a\tb", "fine"}, want: `run ok "a\tb" fine`},
		{name: "quote in arg is kept as is", command: "run", args: []string{`say "hi"`}, want: `run "say \"hi\""`},
		{name: "safe quote without space is kept", command: "run", args: []string{`a"b`}, want: `run a"b`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := report.Command(tt.command, tt.args); got != tt.want {
				t.Errorf("Command(%q, %q) = %q, want %q", tt.command, tt.args, got, tt.want)
			}
		})
	}
}

// cellSplit splits one table line on runs of 3 or more spaces, which is the
// column padding.
var cellSplit = regexp.MustCompile(` {3,}`)

func TestWriteServersEscapesEveryCell(t *testing.T) {
	t.Parallel()

	// hostile values are written as Go escapes, never as raw characters.
	hostile := []struct {
		name  string
		value string
	}{
		{name: "ESC", value: "a\x1b[31mb"},
		{name: "bidi override", value: "a\u202eb"},
		{name: "tab", value: "a\tb"},
		{name: "newline", value: "a\nb"},
		{name: "invalid UTF-8", value: "a\xffb"},
		{name: "C1 control", value: "a\u0085b"},
		{name: "zero width space", value: "a\u200bb"},
	}

	cells := []struct {
		name string
		// set puts v into one cell of s and returns the exact text that the
		// cell must show.
		set func(s *discover.Server, v string) (shown string)
	}{
		{name: "Name", set: func(s *discover.Server, v string) string { s.Name = v; return strconv.Quote(v) }},
		{name: "Source", set: func(s *discover.Server, v string) string { s.Source = v; return strconv.Quote(v) }},
		{name: "ProjectPath", set: func(s *discover.Server, v string) string {
			s.Scope = discover.ScopeProject
			s.ProjectPath = v
			return strconv.Quote("project:" + v)
		}},
		{name: "Command", set: func(s *discover.Server, v string) string { s.Command = v; return strconv.Quote(v) }},
		{name: "Args", set: func(s *discover.Server, v string) string {
			s.Args = []string{v}
			return strconv.Quote(v)
		}},
	}

	for _, cell := range cells {
		for _, h := range hostile {
			t.Run(cell.name+"/"+h.name, func(t *testing.T) {
				t.Parallel()
				s := discover.Server{
					Name:      "srv",
					Client:    discover.ClientCodex,
					Scope:     discover.ScopeGlobal,
					Source:    "/c.toml",
					Transport: discover.TransportStdio,
					Command:   "run",
				}
				shown := cell.set(&s, h.value)

				var sb strings.Builder
				if err := report.WriteServers(&sb, []discover.Server{s}); err != nil {
					t.Fatalf("WriteServers() error = %v, want nil", err)
				}
				out := sb.String()

				if !strings.Contains(out, shown) {
					t.Errorf("output does not contain the quoted form %s:\n%q", shown, out)
				}
				for _, bad := range []string{"\x1b", "\u202e", "\t", "\xff", "\u0085", "\u200b"} {
					if strings.Contains(out, bad) {
						t.Errorf("output holds raw %q:\n%q", bad, out)
					}
				}

				// The table keeps its shape: a header and one row, each with 6 cells.
				lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
				if len(lines) != 2 {
					t.Fatalf("output has %d lines, want 2:\n%q", len(lines), out)
				}
				for i, line := range lines {
					if n := len(cellSplit.Split(line, -1)); n != 6 {
						t.Errorf("line %d has %d cells, want 6: %q", i, n, line)
					}
				}
			})
		}
	}
}

func TestWriteServersNoLeak(t *testing.T) {
	t.Parallel()

	var sb strings.Builder
	if err := report.WriteServers(&sb, threeServers()); err != nil {
		t.Fatalf("WriteServers() error = %v, want nil", err)
	}
	out := sb.String()

	// No secret value shows, in any form. With no secrets passed,
	// AssertNoLeak checks all canaries.
	discovertest.AssertNoLeak(t, "table", out)

	// The URL host stays, so the check above is not a pass on empty output.
	if !strings.Contains(out, "example.com") {
		t.Errorf("output does not show the URL host:\n%s", out)
	}
	// The table does not show the header value (it can hold "Bearer").
	if strings.Contains(out, "Bearer") {
		t.Errorf("output shows a header value:\n%s", out)
	}
}

// failingWriter accepts the first limit bytes, then every Write fails.
type failingWriter struct {
	limit int
	err   error
}

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.limit <= 0 {
		return 0, w.err
	}
	if len(p) > w.limit {
		n := w.limit
		w.limit = 0
		return n, w.err
	}
	w.limit -= len(p)
	return len(p), nil
}

func TestWriteServersWriteError(t *testing.T) {
	t.Parallel()

	errBoom := errors.New("boom")

	tests := []struct {
		name    string
		servers []discover.Server
		limit   int
	}{
		{name: "empty list, fails at once", servers: nil, limit: 0},
		{name: "empty list, fails after some bytes", servers: nil, limit: 5},
		{name: "table, fails at once", servers: threeServers(), limit: 0},
		{name: "table, fails after some bytes", servers: threeServers(), limit: 10},
		{name: "table, fails near the end", servers: threeServers(), limit: 100},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w := &failingWriter{limit: tt.limit, err: errBoom}
			err := report.WriteServers(w, tt.servers)
			if err == nil {
				t.Fatal("WriteServers() error = nil, want a write error")
			}
			if !errors.Is(err, errBoom) {
				t.Errorf("WriteServers() error = %v, want it to be %v", err, errBoom)
			}
		})
	}
}

// The caps of the padded columns. They repeat the unexported constants in
// servers.go, so a change there must change these tests on purpose.
const (
	maxNameRunes = 80  // NAME, CLIENT, TRANSPORT
	maxPathRunes = 256 // SCOPE, SOURCE
)

// firstCell returns the first cell (NAME) of line n of out, counting from 0.
func firstCell(t *testing.T, out string, n int) string {
	t.Helper()
	lines := strings.Split(out, "\n")
	if n >= len(lines) {
		t.Fatalf("output has %d lines, want line %d", len(lines), n)
	}
	return cellSplit.Split(lines[n], -1)[0]
}

// oneServer returns a small valid stdio server.
func oneServer(name string) discover.Server {
	return discover.Server{
		Name:      name,
		Client:    discover.ClientCodex,
		Scope:     discover.ScopeGlobal,
		Source:    "/c.toml",
		Transport: discover.TransportStdio,
		Command:   "run",
	}
}

func TestWriteServersPaddingAmplification(t *testing.T) {
	t.Parallel()

	// tabwriter pads every row to the widest cell. Without the caps, a 1 MiB name
	// plus a 1 MiB source path and 10,000 short rows (the most that one file can
	// hold) would make about 20 GiB of output.
	const shortRows = 10000
	long := oneServer(strings.Repeat("n", 1<<20))
	longPath := oneServer("p")
	longPath.Source = "/" + strings.Repeat("p", 1<<20)
	servers := []discover.Server{long, longPath}
	for range shortRows {
		servers = append(servers, oneServer("s"))
	}

	var sb strings.Builder
	if err := report.WriteServers(&sb, servers); err != nil {
		t.Fatalf("WriteServers() error = %v, want nil", err)
	}
	out := sb.String()
	t.Logf("output size: %d bytes for %d servers", len(out), len(servers))

	// A short row is about 81 + 3 + 5 + 3 + 6 + 3 + 5 + 3 + 257 + 3 + 3 + 1 = 373
	// bytes, so 10,002 rows give about 3.7 MB. Allow up to 8 MiB.
	if limit := 8 << 20; len(out) >= limit {
		t.Errorf("output is %d bytes, want less than %d", len(out), limit)
	}

	// The long name is cut, ends with the marker and has the cap plus the marker.
	cell := firstCell(t, out, 1)
	if !strings.HasSuffix(cell, "\u2026") {
		t.Errorf("long name cell does not end with the cut marker: %q", cell)
	}
	if n := utf8.RuneCountInString(cell); n != maxNameRunes+1 {
		t.Errorf("long name cell has %d runes, want %d", n, maxNameRunes+1)
	}
	// The long source path is cut at the path cap and ends with the marker.
	wantPath := "/" + strings.Repeat("p", maxPathRunes-1) + "\u2026"
	if !strings.Contains(out, wantPath+"   ") {
		t.Errorf("output does not hold the cut source path (%d runes + marker)", maxPathRunes)
	}
	// A short name is not touched.
	if got := firstCell(t, out, 3); got != "s" {
		t.Errorf("short name cell = %q, want %q", got, "s")
	}
}

func TestWriteServersCellCap(t *testing.T) {
	t.Parallel()

	const marker = "\u2026"

	// cases returns the cut cases for a column with the given cap.
	cases := func(limit int) []struct{ name, in, want string } {
		return []struct{ name, in, want string }{
			{name: "cap runes are kept", in: strings.Repeat("a", limit), want: strings.Repeat("a", limit)},
			{name: "cap+1 runes are cut", in: strings.Repeat("a", limit+1), want: strings.Repeat("a", limit) + marker},
			{name: "cap-1 runes are kept", in: strings.Repeat("a", limit-1), want: strings.Repeat("a", limit-1)},
			{name: "cap multi-byte runes are kept", in: strings.Repeat("\u00e9", limit), want: strings.Repeat("\u00e9", limit)},
			{name: "cap+1 multi-byte runes are cut on a rune boundary", in: strings.Repeat("\u00e9", limit+1), want: strings.Repeat("\u00e9", limit) + marker},
			{name: "cap+1 emoji are cut on a rune boundary", in: strings.Repeat("\U0001F680", limit+1), want: strings.Repeat("\U0001F680", limit) + marker},
			{
				name: "a cut cell with a control character is still escaped",
				in:   strings.Repeat("a", limit-1) + "\x1b[31m" + strings.Repeat("b", 50),
				want: strconv.Quote(strings.Repeat("a", limit-1)+"\x1b") + marker,
			},
			{
				name: "invalid UTF-8 is cut at the cap in bytes and quoted",
				in:   strings.Repeat("\xff", 1000),
				want: strconv.Quote(strings.Repeat("\xff", limit)) + marker,
			},
			{name: "short invalid UTF-8 is quoted, not cut", in: "a\xffb", want: `"a\xffb"`},
		}
	}

	columns := []struct {
		name  string
		limit int
		// set puts v into the column of s. The SCOPE cell starts with "project:",
		// so set returns the prefix that the cell shows before v.
		set func(s *discover.Server, v string) (prefix string)
	}{
		{name: "NAME", limit: maxNameRunes, set: func(s *discover.Server, v string) string { s.Name = v; return "" }},
		{name: "SOURCE", limit: maxPathRunes, set: func(s *discover.Server, v string) string { s.Source = v; return "" }},
		{name: "SCOPE", limit: maxPathRunes, set: func(s *discover.Server, v string) string {
			s.Scope = discover.ScopeProject
			s.ProjectPath = v
			return "project:"
		}},
	}

	for _, col := range columns {
		// The SCOPE cell holds "project:" before the value, and the cap counts it.
		// So the value gets a smaller cap, and the cases are built for it.
		prefixLen := 0
		if col.name == "SCOPE" {
			prefixLen = len("project:")
		}
		for _, tt := range cases(col.limit - prefixLen) {
			t.Run(col.name+"/"+tt.name, func(t *testing.T) {
				t.Parallel()

				s := oneServer("srv")
				prefix := col.set(&s, tt.in)

				var sb strings.Builder
				if err := report.WriteServers(&sb, []discover.Server{s}); err != nil {
					t.Fatalf("WriteServers() error = %v, want nil", err)
				}
				out := sb.String()
				if strings.ContainsRune(out, 0x1b) {
					t.Errorf("output holds a raw ESC: %q", out)
				}
				want := tt.want
				if prefix != "" {
					// Quote puts the quote before the prefix, so build the
					// expected cell from the plain or the quoted form.
					if strings.HasPrefix(want, `"`) {
						want = `"` + prefix + want[1:]
					} else {
						want = prefix + want
					}
				}
				if !strings.Contains(out, want) {
					t.Errorf("output does not hold %.100q (%d bytes):\n%.300q", want, len(want), out)
				}
			})
		}
	}
}

func TestWriteServersPathColumnsKeepRealPaths(t *testing.T) {
	t.Parallel()

	// A deep path of 150 runes is longer than the NAME cap and must show whole.
	path := "/Users/someone/" + strings.Repeat("deep/", 27) + "mcp.json"
	if n := len(path); n <= maxNameRunes || n >= maxPathRunes {
		t.Fatalf("test path has %d runes, want between %d and %d", n, maxNameRunes, maxPathRunes)
	}
	s := oneServer("srv")
	s.Source = path
	s.Scope = discover.ScopeProject
	s.ProjectPath = path

	var sb strings.Builder
	if err := report.WriteServers(&sb, []discover.Server{s}); err != nil {
		t.Fatalf("WriteServers() error = %v, want nil", err)
	}
	out := sb.String()
	if strings.Contains(out, "\u2026") {
		t.Errorf("output holds a cut marker, want none:\n%s", out)
	}
	if got := strings.Count(out, path); got != 2 {
		t.Errorf("output shows the path %d times, want 2 (SCOPE and SOURCE):\n%s", got, out)
	}
}

func TestWriteServersLastColumnIsNeverCut(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("x", 10000)

	stdio := oneServer("srv")
	stdio.Args = []string{"--flag", long}

	remote := oneServer("remote")
	remote.Transport = discover.TransportHTTP
	remote.Command = ""
	remote.URL = discover.NewURL("https://example.com/" + long)

	for _, s := range []discover.Server{stdio, remote} {
		var sb strings.Builder
		if err := report.WriteServers(&sb, []discover.Server{s}); err != nil {
			t.Fatalf("WriteServers() error = %v, want nil", err)
		}
		out := sb.String()
		if !strings.Contains(out, long) {
			t.Errorf("%s: the COMMAND/URL cell is cut:\n%.200q", s.Name, out)
		}
		if strings.Contains(out, "\u2026") {
			t.Errorf("%s: output holds a cut marker, want none", s.Name)
		}
	}
}
