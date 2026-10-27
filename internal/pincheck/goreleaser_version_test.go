package main

import "testing"

// TestGoreleaserVersionInput covers rule 3 (#204): a goreleaser-action step
// must have with.version equal to ${{ env.GORELEASER_VERSION }}. Each case
// changes the first step of ci.yml in grGoodRepo (step on line 9, uses on
// line 10, with on line 11, version on line 13).
func TestGoreleaserVersionInput(t *testing.T) {
	t.Parallel()
	const (
		uses       = "uses: goreleaser/goreleaser-action@a4f02ab5355a589de60d917a659ce617ed19b3de"
		with       = "        with:\n          distribution: goreleaser\n          version: ${{ env.GORELEASER_VERSION }}\n"
		version    = "version: ${{ env.GORELEASER_VERSION }}"
		notInput   = "has a version input that is not ${{ env.GORELEASER_VERSION }}"
		checkLabel = `the goreleaser-action step "Check" `
		flowGood   = `        with: {distribution: goreleaser, version: "${{ env.GORELEASER_VERSION }}"}` + "\n"
	)
	replace := func(old, repl string) grMutation { return grReplace(grCIPath, old, repl) }
	tests := []grCase{
		// Positive controls.
		{name: "block with mapping"},
		{name: "flow with mapping", mutate: replace(with, flowGood)},
		{name: "single-quoted value", mutate: replace(version, "version: '${{ env.GORELEASER_VERSION }}'")},
		{name: "double-quoted value", mutate: replace(version, `version: "${{ env.GORELEASER_VERSION }}"`)},
		{name: "uses in other case", mutate: replace(uses, "uses: GoReleaser/GoReleaser-Action@v7")},
		{name: "uses with no ref", mutate: replace(uses, "uses: goreleaser/goreleaser-action")},
		// Negative cases.
		{
			name:   "flow with fixed version",
			mutate: replace(with, "        with: {distribution: goreleaser, version: v2.0.0}\n"),
			want:   []grMsg{{ciLine + "11: ", checkLabel + notInput}},
		},
		{
			name:   "latest",
			mutate: replace(version, "version: latest"),
			want:   []grMsg{{ciLine + "13: ", checkLabel + notInput}},
		},
		{
			name:   "version range",
			mutate: replace(version, "version: '~> v2'"),
			want:   []grMsg{{ciLine + "13: ", notInput}},
		},
		{
			name:   "fixed full version",
			mutate: replace(version, "version: v2.19.0"),
			want:   []grMsg{{ciLine + "13: ", notInput}},
		},
		{
			name:   "key in other case",
			mutate: replace(version, "Version: ${{ env.GORELEASER_VERSION }}"),
			want: []grMsg{
				{ciLine + "13: ", checkLabel + `has the key "Version" in its with mapping`},
				{ciLine + "13: ", grMsgMention},
			},
		},
		{
			name:   "with missing",
			mutate: replace(with, ""),
			want:   []grMsg{{ciLine + "9: ", checkLabel + "has no with mapping, so it has no version input"}},
		},
		{
			name:   "with is a scalar",
			mutate: replace(with, "        with: version\n"),
			want:   []grMsg{{ciLine + "11: ", `the value of "with" must be a mapping, found a scalar`}},
		},
		{
			name:   "with is empty",
			mutate: replace(with, "        with:\n"),
			want:   []grMsg{{ciLine + "11: ", `the value of "with" must be a mapping, found an empty value`}},
		},
		{
			name:   "with has no version key",
			mutate: replace("          "+version+"\n", ""),
			want:   []grMsg{{ciLine + "12: ", checkLabel + "has no version input in its with mapping"}},
		},
		{
			name:   "version is a number",
			mutate: replace(version, "version: 2"),
			want:   []grMsg{{ciLine + "13: ", notInput}},
		},
		{
			name:   "version is a sequence",
			mutate: replace(version, `version: ["${{ env.GORELEASER_VERSION }}"]`),
			want:   []grMsg{{ciLine + "13: ", notInput}},
		},
		{
			name:   "version is a block scalar",
			mutate: replace(version, "version: |\n            ${{ env.GORELEASER_VERSION }}"),
			want:   []grMsg{{ciLine + "13: ", notInput}},
		},
		{
			name:   "expression without spaces",
			mutate: replace(version, "version: ${{env.GORELEASER_VERSION}}"),
			want: []grMsg{
				{ciLine + "13: ", notInput},
				{ciLine + "13: ", `"${{env.GORELEASER_VERSION}}" ` + grMsgMention},
			},
		},
		{
			name:   "expression with a suffix",
			mutate: replace(version, "version: ${{ env.GORELEASER_VERSION }}x"),
			want:   []grMsg{{ciLine + "13: ", notInput}},
		},
		{
			name:   "expression with a trailing space",
			mutate: replace(version, `version: "${{ env.GORELEASER_VERSION }} "`),
			want:   []grMsg{{ciLine + "13: ", notInput}},
		},
		{
			name: "uses in other case is still checked",
			mutate: grAll(
				replace(uses, "uses: GoReleaser/GoReleaser-Action@v7"),
				replace(version, "version: latest"),
			),
			want: []grMsg{{ciLine + "13: ", checkLabel + notInput}},
		},
		{
			name: "uses with no ref is still checked",
			mutate: grAll(
				replace(uses, "uses: goreleaser/goreleaser-action"),
				replace(version, "version: latest"),
			),
			want: []grMsg{{ciLine + "13: ", checkLabel + notInput}},
		},
		{
			name: "step with no name is labelled by its uses value",
			mutate: grAll(
				replace("      - name: Check\n        "+uses, "      - "+uses),
				replace(version, "version: latest"),
			),
			want: []grMsg{{ciLine + "12: ", `the goreleaser-action step "goreleaser/goreleaser-action@a4f02ab5355a589de60d917a659ce617ed19b3de" ` + notInput}},
		},
		{
			name: "step with an empty name is labelled by its uses value",
			mutate: grAll(
				replace("- name: Check", `- name: ""`),
				replace(version, "version: latest"),
			),
			want: []grMsg{{ciLine + "13: ", `the goreleaser-action step "goreleaser/goreleaser-action@a4f02ab5355a589de60d917a659ce617ed19b3de" ` + notInput}},
		},
	}
	grRunCases(t, tests)
}
