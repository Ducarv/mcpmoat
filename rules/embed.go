// Package rules holds the built-in detection rules as embedded YAML files.
// It also embeds the popular server list in data/popular-servers.txt.
//
// This package contains data only. The package internal/rules parses,
// validates and applies the rules. It cannot embed this folder itself,
// because go:embed does not accept ".." paths.
//
// Only rule files may use the .yaml extension in this folder: every *.yaml
// file here is loaded as a rule. Put other data in a subfolder or use another
// extension.
package rules

import "embed"

// FS holds every built-in rule file (rules/*.yaml). The pattern does not match
// the .yml extension: built-in rules use .yaml only.
//
// FS is a package-level variable because the go:embed directive requires it.
// An embed.FS is read-only, so it is not mutable global state.
//
//go:embed *.yaml
var FS embed.FS

// PopularServers is the curated list of popular MCP server package names that
// the typosquatting check (MOAT-T5-001) compares against. internal/rules
// parses it with ParsePopular.
//
//go:embed data/popular-servers.txt
var PopularServers []byte
