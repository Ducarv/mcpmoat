package rules

import "testing"

// TestIsYesFlag checks isYesFlag on its own. TestCheckAutoInstall covers the
// walk and the whole check.
func TestIsYesFlag(t *testing.T) {
	t.Parallel()
	tests := []struct {
		arg, next string
		want      bool
	}{
		{"-y", "", true},
		{"-qy", "", true},
		{"-n", "", true}, // shorthand of --no-yes: fail closed
		{"-q", "", false},
		{"--yes", "false", true}, // npx puts "--" before "false"
		{"--ye", "", true},
		{"--y=false", "", true}, // npx moves the value to its own argument
		{"--qy", "", true},      // a group of one-letter shorthands
		{"--dd", "", false},
		{"--yes=false", "", false},
		{"--yes=0", "", true},
		{"--yes=null", "", true},
		{"--no-yes", "pkg", false},
		{"--no-yes", "true", false},
		{"--no-yes", "false", true},
		{"--NO-yes", "null", true},
		{"--no-yes=false", "", true},
		{"--no-no-yes", "", true},
		{"--no=null", "", true},
		{"--registry", "", false},
		{"--include", "", false},
		{"-", "", false},
	}
	for _, tt := range tests {
		if got := isYesFlag(tt.arg, tt.next); got != tt.want {
			t.Errorf("isYesFlag(%q, %q) = %v, want %v", tt.arg, tt.next, got, tt.want)
		}
	}
}

// TestWalkNPXFlags checks both results of walkNPXFlags.
func TestWalkNPXFlags(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		args      []string
		yes, runs bool
	}{
		{"yes flag and package", []string{"-y", "pkg"}, true, true},
		{"yes flag alone", []string{"-y"}, true, false},
		{"yes flags and --", []string{"-y", "-y", "--"}, true, false},
		{"-- after a flag, then a word", []string{"-y", "--", "--dy"}, true, true},
		{"package alone", []string{"pkg"}, false, true},
		{"-y after the command", []string{"pkg", "-y"}, false, true},
		{"value of -p, then -y", []string{"-p", "pkg", "-y"}, true, true},
		{"-y after the -p command", []string{"-p", "pkg", "bin", "-y"}, false, true},
		{"-y=pkg runs pkg", []string{"-y=pkg"}, true, true},
		{"other flag may add a command", []string{"--loglevel", "-q", "-y"}, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			yes, runs := walkNPXFlags(tt.args)
			if yes != tt.yes || runs != tt.runs {
				t.Errorf("walkNPXFlags(%q) = %v, %v, want %v, %v", tt.args, yes, runs, tt.yes, tt.runs)
			}
		})
	}
}
