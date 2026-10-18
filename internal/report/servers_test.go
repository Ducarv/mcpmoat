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
	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// writeTable returns the table that report.WriteServers writes for servers.
// It fails the test if WriteServers returns an error.
func writeTable(t *testing.T, servers ...discover.Server) string {
	t.Helper()
	var sb strings.Builder
	if err := report.WriteServers(&sb, servers); err != nil {
		t.Fatalf("WriteServers() error = %v, want nil", err)
	}
	return sb.String()
}

// threeServers returns one stdio, one http and one project-scope sse server.
// The sse server comes from a project file, so it is untrusted.
// The stdio server has a canary value in Args, the http server has canary
// values in the URL, and the stdio and http servers have canary values in Env
// and Headers.
func threeServers() []discover.Server {
	return []discover.Server{
		{
			Name:      "fs",
			Client:    discover.ClientClaudeCode,
			Scope:     discover.ScopeGlobal,
			Source:    "/home/u/.claude.json",
			Transport: discover.TransportStdio,
			Command:   "npx",
			Args: discover.NewArgs([]string{
				"-y", "@scope/server-fs", "--token", discovertest.CanaryArgs, "/data",
			}),
			Env: discover.SecretMap{"API_KEY": discover.NewSecret(discovertest.CanaryEnv)},
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
			Untrusted:   true,
			Transport:   discover.TransportSSE,
			URL:         discover.NewURL("https://sse.example.com/events"),
		},
	}
}

func TestWriteServersExactTable(t *testing.T) {
	t.Parallel()

	// Columns are padded to the widest cell plus 3 spaces. The last column has
	// no padding. Secrets and credentials never show: the args go through the
	// RedactArgs allowlist.
	const want = "NAME     CLIENT        SCOPE                           TRANSPORT   SOURCE                     COMMAND/URL\n" +
		"fs       claude-code   global                          stdio       /home/u/.claude.json       npx -y @scope/server-fs --token ******** /data\n" +
		"remote   cursor        global                          http        /home/u/.cursor/mcp.json   https://********@example.com/mcp?k=********\n" +
		"legacy   claude-code   project:/work/app (untrusted)   sse         /work/app/.mcp.json        https://sse.example.com/events\n"

	if got := writeTable(t, threeServers()...); got != want {
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
			// tt.servers... passes the slice itself, so nil stays nil.
			if got, want := writeTable(t, tt.servers...), "No MCP servers found.\n"; got != want {
				t.Errorf("WriteServers() = %q, want %q", got, want)
			}
		})
	}
}

func TestFormatCommand(t *testing.T) {
	t.Parallel()

	const (
		mask = discover.Mask
		c    = discovertest.CanaryArgs
	)
	tests := []struct {
		name    string
		command string
		args    []string
		want    string
	}{
		{name: "plain", command: "npx", args: []string{"-y", "server"}, want: "npx -y server"},
		{name: "npm scope and path are shown", command: "npx", args: []string{"-y", "@scope/server-fs", "/data"}, want: "npx -y @scope/server-fs /data"},
		{name: "no args", command: "server", args: nil, want: "server"},
		{name: "empty args slice", command: "server", args: []string{}, want: "server"},
		{name: "empty arg is quoted", command: "run", args: []string{"", "x"}, want: `run "" x`},
		{name: "only empty arg", command: "run", args: []string{""}, want: `run ""`},
		{name: "empty command is quoted", command: "", args: []string{"x"}, want: `"" x`},

		// The allowlist masks every part with a shape that is not known to be
		// safe. A space, a quote or a control character is not on the list.
		{name: "segment with a space is masked", command: "node", args: []string{"my dir/a.js"}, want: "node " + mask + "/a.js"},
		{name: "command with a space is masked", command: "my tool", args: []string{"x"}, want: mask + " x"},
		{name: "arg with ESC is masked", command: "run", args: []string{"a\x1b[2Jb"}, want: "run " + mask},
		{name: "arg with tab is masked", command: "run", args: []string{"a\tb"}, want: "run " + mask},
		{name: "arg with newline is masked", command: "run", args: []string{"a\nb"}, want: "run " + mask},
		{name: "arg with bidi override is masked", command: "run", args: []string{"a\u202eb"}, want: "run " + mask},
		{name: "arg with invalid UTF-8 is masked", command: "run", args: []string{"a\xffb"}, want: "run " + mask},
		{name: "command with ESC is masked", command: "\x1b]0;x\a", args: []string{"y"}, want: mask + " y"},
		{name: "arg with a quote is masked", command: "run", args: []string{`a"b`}, want: "run " + mask},

		// Secret-like args.
		{name: "value of a secret flag", command: "run", args: []string{"--token", c}, want: "run --token " + mask},
		{name: "secret flag with =", command: "run", args: []string{"--api-key=" + c}, want: "run --api-key=" + mask},
		{name: "secret env value", command: "docker", args: []string{"run", "-e", "GITHUB_TOKEN=" + c}, want: "docker run -e GITHUB_TOKEN=" + mask},
		{name: "header line", command: "run", args: []string{"-H", "Authorization: Bearer " + c}, want: "run -H " + mask},
		{name: "URL credentials", command: "run", args: []string{"postgres://u:" + c + "@h/db"}, want: "run postgres://" + mask + "@h/db"},
		{name: "URL query value", command: "run", args: []string{"https://h/sse?key=" + c}, want: "run https://h/sse?key=" + mask},
		{name: "JSON arg", command: "run", args: []string{`{"token":"` + c + `"}`}, want: "run " + mask},
		{name: "token in a path segment", command: "run", args: []string{"/data/" + c + "/x"}, want: "run /data/" + mask + "/x"},
		{name: "user and password", command: "run", args: []string{"admin:" + c}, want: "run " + mask},
		{name: "token glued to a short flag", command: "run", args: []string{"-p" + c}, want: "run " + mask},
		{name: "positional token", command: "run", args: []string{c}, want: "run " + mask},

		// The command goes through the allowlist too, as the first part.
		{name: "token as the command", command: "ghp_abcdefghijklmnopqrstuvwxyz0123456789", args: []string{"x"}, want: mask + " x"},
		{name: "canary as the command", command: c, args: []string{"x"}, want: mask + " x"},
		{name: "secret flag as the command masks the next part", command: "--token", args: []string{c}, want: "--token " + mask},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := report.FormatCommand(tt.command, discover.NewArgs(tt.args))
			if got != tt.want {
				t.Errorf("FormatCommand(%q, %q) = %q, want %q", tt.command, tt.args, got, tt.want)
			}
			discovertest.AssertNoLeak(t, "FormatCommand()", got)
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
		// The command and the args go through the RedactArgs allowlist, which
		// masks every part with an unsafe character.
		{name: "Command", set: func(s *discover.Server, v string) string { s.Command = v; return discover.Mask }},
		{name: "Args", set: func(s *discover.Server, v string) string {
			s.Args = discover.NewArgs([]string{v})
			return discover.Mask
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

				out := writeTable(t, s)

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

	out := writeTable(t, threeServers()...)

	// No secret value shows, in any form. With no secrets passed,
	// AssertNoLeak checks all canaries.
	discovertest.AssertNoLeak(t, "table", out)

	// The URL host and the safe args stay, so the check above is not a pass
	// on empty output.
	for _, want := range []string{"example.com", "npx -y @scope/server-fs --token "} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not show %q:\n%s", want, out)
		}
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
	maxShortCellRunes = 80  // NAME, CLIENT, TRANSPORT
	maxPathRunes      = 256 // SCOPE, SOURCE
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

	out := writeTable(t, servers...)
	t.Logf("output size: %d bytes for %d servers", len(out), len(servers))

	// A short row is about 83 + 3 + 5 + 3 + 6 + 3 + 5 + 3 + 259 + 3 + 3 + 1 = 377
	// bytes, so 10,002 rows give about 3.8 MB. Allow up to 8 MiB.
	if limit := 8 << 20; len(out) >= limit {
		t.Errorf("output is %d bytes, want less than %d", len(out), limit)
	}

	// The long name is cut, ends with the marker and has the cap plus the marker.
	cell := firstCell(t, out, 1)
	if !strings.HasSuffix(cell, termsafe.CutMarker) {
		t.Errorf("long name cell does not end with the cut marker: %q", cell)
	}
	if n, want := utf8.RuneCountInString(cell), maxShortCellRunes+len(termsafe.CutMarker); n != want {
		t.Errorf("long name cell has %d runes, want %d", n, want)
	}
	// The long source path is cut at the path cap and ends with the marker.
	wantPath := "/" + strings.Repeat("p", maxPathRunes-1) + termsafe.CutMarker
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

	const marker = termsafe.CutMarker

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
				// An invalid byte counts as one rune (termsafe.Cut).
				name: "invalid UTF-8 is cut at the cap and quoted",
				in:   strings.Repeat("\xff", 1000),
				want: strconv.Quote(strings.Repeat("\xff", limit)) + marker,
			},
			{
				// The valid runes before an invalid byte count as runes, not
				// as bytes, so the cell keeps the whole cap.
				name: "multi-byte runes and invalid UTF-8 are cut at the cap in runes",
				in:   strings.Repeat("\u00e9", limit-1) + "\xff" + strings.Repeat("z", 50),
				want: strconv.Quote(strings.Repeat("\u00e9", limit-1)+"\xff") + marker,
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
		{name: "NAME", limit: maxShortCellRunes, set: func(s *discover.Server, v string) string { s.Name = v; return "" }},
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

				out := writeTable(t, s)
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
	if n := len(path); n <= maxShortCellRunes || n >= maxPathRunes {
		t.Fatalf("test path has %d runes, want between %d and %d", n, maxShortCellRunes, maxPathRunes)
	}
	s := oneServer("srv")
	s.Source = path
	s.Scope = discover.ScopeProject
	s.ProjectPath = path

	out := writeTable(t, s)
	if strings.Contains(out, termsafe.CutMarker) {
		t.Errorf("output holds a cut marker, want none:\n%s", out)
	}
	if got := strings.Count(out, path); got != 2 {
		t.Errorf("output shows the path %d times, want 2 (SCOPE and SOURCE):\n%s", got, out)
	}
}

func TestWriteServersLastColumnIsNeverCut(t *testing.T) {
	t.Parallel()

	// A long path of short segments: RedactArgs shows it, and RedactURL
	// shows it in a URL path. A long random-looking word would be masked.
	long := strings.Repeat("abc/", 2500)

	stdio := oneServer("srv")
	stdio.Args = discover.NewArgs([]string{"--flag", long})

	remote := oneServer("remote")
	remote.Transport = discover.TransportHTTP
	remote.Command = ""
	remote.URL = discover.NewURL("https://example.com/" + long)

	for _, s := range []discover.Server{stdio, remote} {
		out := writeTable(t, s)
		if !strings.Contains(out, long) {
			t.Errorf("%s: the COMMAND/URL cell is cut:\n%.200q", s.Name, out)
		}
		if strings.Contains(out, termsafe.CutMarker) {
			t.Errorf("%s: output holds a cut marker, want none", s.Name)
		}
	}
}

// TestWriteServersUntrustedScope checks that the SCOPE cell of an untrusted
// server ends with " (untrusted)". The marker comes after the cut and after
// the closing quote, so it is never cut or escaped.
func TestWriteServersUntrustedScope(t *testing.T) {
	t.Parallel()

	const marker = " (untrusted)"
	long := strings.Repeat("p", 1000)
	tests := []struct {
		name      string
		scope     discover.Scope
		path      string
		untrusted bool
		want      string // the SCOPE cell, followed by the column gap
	}{
		{name: "trusted project", scope: discover.ScopeProject, path: "/w", want: "project:/w   "},
		{name: "untrusted project", scope: discover.ScopeProject, path: "/w", untrusted: true, want: "project:/w" + marker + "   "},
		{
			name: "untrusted long path is cut before the marker", scope: discover.ScopeProject, path: long, untrusted: true,
			want: "project:" + long[:maxPathRunes-len("project:")] + termsafe.CutMarker + marker + "   ",
		},
		{
			name: "untrusted quoted path", scope: discover.ScopeProject, path: "/w\x1b", untrusted: true,
			want: strconv.Quote("project:/w\x1b") + marker + "   ",
		},
		{
			name: "untrusted long quoted path", scope: discover.ScopeProject, path: strings.Repeat("\x1b", 1000), untrusted: true,
			want: strconv.Quote("project:"+strings.Repeat("\x1b", maxPathRunes-len("project:"))) + termsafe.CutMarker + marker + "   ",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := oneServer("srv")
			s.Scope = tt.scope
			s.ProjectPath = tt.path
			s.Untrusted = tt.untrusted

			out := writeTable(t, s)
			if !strings.Contains(out, tt.want) {
				t.Errorf("output does not hold the SCOPE cell %.120q:\n%.400q", tt.want, out)
			}
			if !tt.untrusted && strings.Contains(out, marker) {
				t.Errorf("output marks a trusted server as untrusted:\n%q", out)
			}
		})
	}
}

// TestWriteServersSpaceIsQuoted checks the report rule of cell: a padded cell
// that holds an ASCII space is quoted, so a space in a name or a path cannot
// look like the gap between two columns. The cut comes first, and the marker
// comes after the closing quote.
func TestWriteServersSpaceIsQuoted(t *testing.T) {
	t.Parallel()

	const marker = termsafe.CutMarker
	long := strings.Repeat("a b ", 100)
	tests := []struct {
		name string
		set  func(s *discover.Server)
		want string // the cell, followed by the column gap
	}{
		{name: "name without a space is kept", set: func(s *discover.Server) { s.Name = "my-srv" }, want: "my-srv   "},
		{name: "name with a space", set: func(s *discover.Server) { s.Name = "a b" }, want: `"a b"   `},
		{name: "name with three spaces", set: func(s *discover.Server) { s.Name = "a   b" }, want: `"a   b"   `},
		{name: "name that ends with a space", set: func(s *discover.Server) { s.Name = "a " }, want: `"a "   `},
		{name: "name with a space and a backslash", set: func(s *discover.Server) { s.Name = `a b\c` }, want: `"a b\\c"   `},
		{name: "name with a space and a quote", set: func(s *discover.Server) { s.Name = `a "b"` }, want: `"a \"b\""   `},
		{name: "name with a space and ESC", set: func(s *discover.Server) { s.Name = "a b\x1b" }, want: `"a b\x1b"   `},
		{name: "name that starts with a quote", set: func(s *discover.Server) { s.Name = `"x"` }, want: `"\"x\""   `},
		{
			name: "long name with spaces is cut, then quoted",
			set:  func(s *discover.Server) { s.Name = long },
			want: strconv.Quote(long[:maxShortCellRunes]) + marker + "   ",
		},
		{
			// The part after the cut is not shown, so its space does not make
			// the cell quoted.
			name: "space after the cut",
			set:  func(s *discover.Server) { s.Name = strings.Repeat("n", maxShortCellRunes) + " x" },
			want: strings.Repeat("n", maxShortCellRunes) + marker + "   ",
		},
		{
			name: "long name that ends with the marker text",
			set:  func(s *discover.Server) { s.Name = "a b..." + strings.Repeat("c", maxShortCellRunes) },
			want: strconv.Quote("a b..."+strings.Repeat("c", maxShortCellRunes-len("a b..."))) + marker + "   ",
		},
		{
			name: "project path with a space",
			set: func(s *discover.Server) {
				s.Scope, s.ProjectPath, s.Untrusted = discover.ScopeProject, "/my dir", true
			},
			want: `"project:/my dir" (untrusted)   `,
		},
		{
			name: "source path with a space",
			set:  func(s *discover.Server) { s.Source = `C:\My Files\.mcp.json` },
			want: `"C:\\My Files\\.mcp.json"   `,
		},
		{
			// termsafe.Quote keeps a Windows path without a space as it is.
			name: "source path without a space",
			set:  func(s *discover.Server) { s.Source = `C:\work\.mcp.json` },
			want: `C:\work\.mcp.json   `,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := oneServer("srv")
			tt.set(&s)

			out := writeTable(t, s)
			if !strings.Contains(out, tt.want) {
				t.Errorf("output does not hold the cell %.120q:\n%.400q", tt.want, out)
			}
			if strings.ContainsRune(out, 0x1b) {
				t.Errorf("output holds a raw ESC: %q", out)
			}
		})
	}
}

// TestWriteServersCellsMapBack checks that every padded cell maps back to its
// text in one way: a quoted cell unquotes to the text, and a cell that is not
// quoted is the text itself and has no space.
func TestWriteServersCellsMapBack(t *testing.T) {
	t.Parallel()

	for _, name := range []string{
		"plain", "a b", "a   b", `"a b"`, `"plain"`, `a"b`, `a\b`, `a b\`, "a\tb", "a\x1bb", "\u3164", "caf\u00e9 x", "",
	} {
		out := writeTable(t, oneServer(name))
		// The NAME cell is the start of the row, before the column gap and
		// the CLIENT cell.
		row := strings.Split(out, "\n")[1]
		got, _, ok := strings.Cut(row, "   "+string(discover.ClientCodex))
		if !ok {
			t.Fatalf("row %q has no CLIENT cell", row)
		}
		got = strings.TrimRight(got, " ")
		if strings.HasPrefix(got, `"`) {
			back, err := strconv.Unquote(got)
			if err != nil || back != name {
				t.Errorf("name %q: cell %q unquotes to %q, %v, want the name", name, got, back, err)
			}
			continue
		}
		if got != name || strings.Contains(got, " ") {
			t.Errorf("name %q: cell %q is not quoted, want the name with no space", name, got)
		}
	}
}
