package main

// The strict tool profile's seccomp filter for x86-64 (confine_linux.go): EPERM for the
// interfaces the profile assigns to seccomp, the process killed for a call of another
// architecture or of the x32 ABI, everything else allowed. The numbers are the x86-64
// system call table's.

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// seccompData offsets (struct seccomp_data): nr, arch, instruction_pointer, args[6]; the
// low 32 bits of args[0] on this little-endian architecture.
const (
	offsetNr   = 0
	offsetArch = 4
	offsetArg0 = 16
	// x32 system calls carry this bit.
	x32Bit = 0x40000000
	// afVsock is AF_VSOCK.
	afVsock = 40
)

// deniedCalls are the system calls the filter refuses with EPERM, by the profile's
// interface: io_uring, bpf, userfaultfd, perf_event_open, kexec, module loading, ptrace.
var deniedCalls = []uint32{
	unix.SYS_IO_URING_SETUP, unix.SYS_IO_URING_ENTER, unix.SYS_IO_URING_REGISTER,
	unix.SYS_BPF,
	unix.SYS_USERFAULTFD,
	unix.SYS_PERF_EVENT_OPEN,
	unix.SYS_KEXEC_LOAD, unix.SYS_KEXEC_FILE_LOAD,
	unix.SYS_INIT_MODULE, unix.SYS_FINIT_MODULE,
	unix.SYS_PTRACE,
}

func statement(code uint16, k uint32) unix.SockFilter {
	return unix.SockFilter{Code: code, K: k}
}

func jump(code uint16, k uint32, whenTrue, whenFalse uint8) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: whenTrue, Jf: whenFalse, K: k}
}

// strictFilter is the program:
//
//	0      load arch; not x86-64: kill
//	3      load nr; the x32 bit set: kill
//	6..    nr is a denied call: EPERM
//	A      nr is socket: load args[0]; AF_VSOCK: EPERM
//	A+3    allow
//	A+4    EPERM
func strictFilter() []unix.SockFilter {
	const (
		load      = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
		equal     = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
		atOrAbove = unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K
		ret       = unix.BPF_RET | unix.BPF_K
	)
	denied := len(deniedCalls)
	refuse := uint32(unix.SECCOMP_RET_ERRNO) | (uint32(unix.EPERM) & unix.SECCOMP_RET_DATA)
	program := []unix.SockFilter{
		statement(load, offsetArch),
		jump(equal, unix.AUDIT_ARCH_X86_64, 1, 0),
		statement(ret, unix.SECCOMP_RET_KILL_PROCESS),
		statement(load, offsetNr),
		jump(atOrAbove, x32Bit, 0, 1),
		statement(ret, unix.SECCOMP_RET_KILL_PROCESS),
	}
	for index, number := range deniedCalls {
		// To the EPERM return at A+4, A being 6+denied.
		program = append(program, jump(equal, number, uint8(denied+3-index), 0))
	}
	program = append(program,
		jump(equal, unix.SYS_SOCKET, 0, 2),
		statement(load, offsetArg0),
		jump(equal, afVsock, 1, 0),
		statement(ret, unix.SECCOMP_RET_ALLOW),
		statement(ret, refuse),
	)
	return program
}

// installFilter installs `filter` on every thread of the process (TSYNC); no_new_privs is
// already set on all of them.
func installFilter(filter []unix.SockFilter) error {
	if len(filter) == 0 || len(filter) > 4096 {
		return fmt.Errorf("a filter of %d instructions", len(filter))
	}
	program := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	thread, _, errno := unix.RawSyscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER,
		unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&program)))
	runtime.KeepAlive(filter)
	if errno != 0 {
		return errno
	}
	if thread != 0 {
		return fmt.Errorf("thread %d could not take the filter", thread)
	}
	return nil
}
