//go:build !unix

package inspect

import "syscall"

// detachSysProcAttr returns nil on systems that are not Unix. On those
// systems syscall.SysProcAttr has no Setsid field. Windows is a non-goal (PRD
// section 2.2). This file exists only so that the module still compiles
// there. See the Unix version for the behaviour that mcpmoat relies on.
func detachSysProcAttr() *syscall.SysProcAttr {
	return nil
}
