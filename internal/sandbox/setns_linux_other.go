//go:build linux && !amd64 && !386

package sandbox

import "syscall"

// sysSetns is setns(2).
const sysSetns = syscall.SYS_SETNS
