package main

// The loopback interface (egress_linux.go's listeners live on 127.0.0.2 upward): a fresh
// kernel brings `lo` up only when userspace asks, and nothing else in this guest does, so
// without this step every connection to a loopback address fails with "network
// unreachable" (measured 30 October 2026 on the first disposable run of the egress path).

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// bringUpLoopback sets IFF_UP on `lo` through the interface flags ioctl.
func bringUpLoopback() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("socket: %w", err)
	}
	defer unix.Close(fd)
	var request ifreqFlags
	copy(request.name[:], "lo")
	if err := ioctl(fd, unix.SIOCGIFFLAGS, unsafe.Pointer(&request)); err != nil {
		return fmt.Errorf("read lo flags: %w", err)
	}
	request.flags |= unix.IFF_UP | unix.IFF_RUNNING
	if err := ioctl(fd, unix.SIOCSIFFLAGS, unsafe.Pointer(&request)); err != nil {
		return fmt.Errorf("set lo up: %w", err)
	}
	return nil
}

// ifreqFlags is `struct ifreq` as the flags ioctls read it: the name and the short flags
// at the start of the union, padded to the structure's 40 bytes.
type ifreqFlags struct {
	name  [unix.IFNAMSIZ]byte
	flags int16
	_     [22]byte
}

func ioctl(fd int, request uint, argument unsafe.Pointer) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(request), uintptr(argument))
	if errno != 0 {
		return errno
	}
	return nil
}
