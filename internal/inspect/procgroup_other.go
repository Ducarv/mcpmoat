//go:build !unix

package inspect

// killGroup does nothing on systems that are not Unix. Windows is a non-goal
// (PRD section 2.2); see the Unix version.
func killGroup(int) {}
