//go:build linux && !amd64

package main

// The strict tool profile's filter exists for x86-64 only, the one guest architecture
// built; elsewhere the guest refuses to start rather than run unconfined.

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/unix"
)

func strictFilter() []unix.SockFilter { return nil }

func installFilter([]unix.SockFilter) error {
	return fmt.Errorf("no seccomp filter for %s", runtime.GOARCH)
}
