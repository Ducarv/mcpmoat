package main

import (
	"fmt"
	"runtime/debug"
)

// Build information. Only the linker writes these variables. A release build
// sets them like this:
//
//	go build -ldflags "-X main.version=1.2.3 -X main.commit=abc -X main.date=2026-01-01T00:00:00Z"
//
// Without -ldflags the defaults stay, and resolveBuildInfo tries the data that
// the Go toolchain embeds in the binary.
//
// run() in cli.go is the only place that reads these variables. Everything
// else gets a buildInfo value, so tests never have to change a package variable.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// Default values of the build variables. resolveBuildInfo compares against
// them to know which fields the linker did not set.
const (
	defaultVersion = "dev"
	defaultCommit  = "none"
	defaultDate    = "unknown"

	// shortRevisionLen is how many characters of the VCS revision we show.
	shortRevisionLen = 12
)

// buildInfo describes the build of this binary.
type buildInfo struct {
	version, commit, date string
}

// resolveBuildInfo returns the build information. It starts with linked, the
// values that the linker injected. If the version is still the default, it
// asks read (normally debug.ReadBuildInfo) for the module version and VCS data.
// This covers "go install github.com/Ducarv/mcpmoat/cmd/mcpmoat@v0.1.0", where
// no -ldflags are used.
//
// The function takes linked and read as arguments, and does not read the
// package variables itself. So a test can pass any input and check the result
// without a change to global state.
func resolveBuildInfo(linked buildInfo, read func() (*debug.BuildInfo, bool)) buildInfo {
	b := linked
	if b.version != defaultVersion {
		return b
	}

	info, ok := read()
	if !ok || info == nil {
		return b
	}

	// "(devel)" is what Go reports for a build from a source checkout.
	if v := info.Main.Version; v != "" && v != "(devel)" {
		b.version = v
	}

	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			if b.commit == defaultCommit && s.Value != "" {
				b.commit = s.Value
				if len(b.commit) > shortRevisionLen {
					b.commit = b.commit[:shortRevisionLen]
				}
			}
		case "vcs.time":
			if b.date == defaultDate && s.Value != "" {
				b.date = s.Value
			}
		}
	}
	return b
}

// String formats the build information for "mcpmoat version". It prints the
// version exactly as it was injected.
func (b buildInfo) String() string {
	return fmt.Sprintf("mcpmoat %s (commit %s, built %s)", b.version, b.commit, b.date)
}

// runVersion implements "mcpmoat version".
func (c *cli) runVersion(_ options, args []string) int {
	if len(args) > 0 {
		fprintf(c.stderr, "mcpmoat version: unexpected arguments %q\n", args)
		return exitError
	}
	fprintf(c.stdout, "%s\n", c.build)
	return exitOK
}
