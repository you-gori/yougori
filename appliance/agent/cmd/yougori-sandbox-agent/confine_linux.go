package main

// The guest's inner confinement under the strict tool profile (V15, VM-W07, VM-CP-05;
// src-tauri/src/sandbox_contract/confinement/profile.rs, WorkloadProfile::StrictTool),
// applied by PID 1 once the guest is prepared and before the link starts, so every process
// of the guest inherits it:
//
//   - the capability bounding set is emptied on every thread of the agent: a terminal (uid
//     1000, no_new_privs) holds no capability and could never gain one (CapBnd 0);
//   - Yama's ptrace_scope is set to 3 where the kernel has Yama, the profile's LSM backup
//     for ptrace;
//   - one seccomp filter on every thread (TSYNC) refuses with EPERM the interfaces the
//     profile assigns to seccomp: io_uring (backup of the absent kernel option), bpf,
//     userfaultfd, perf_event_open, kexec, module loading, ptrace and AF_VSOCK sockets; a
//     call of another architecture or of the x32 ABI kills the process. The agent itself
//     needs none of them once its modules are loaded and fw_cfg is unloaded;
//   - the agent's own binary is copied to a read-only, executable tmpfs, where a terminal
//     runs it as the confinement probe (probe_linux.go): the guest's own report, which the
//     host never takes as host evidence.
//
// Each terminal also gets the profile's protected paths as read-only bind mounts in its
// directory (spawn_linux.go). Nothing here survives a guest kernel compromise; the host
// boundaries do (§1.2).

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	// probeDirectory holds the probe: a tmpfs of its own, read-only once the binary is in.
	probeDirectory = "/run/yougori/bin"
	// probePath is the probe a terminal runs: `yougori-probe probe-confinement <digest>`.
	probePath      = probeDirectory + "/yougori-probe"
	probeTmpfs     = "mode=0755,size=32m,nr_inodes=16"
	yamaPtrace     = "/proc/sys/kernel/yama/ptrace_scope"
	capLastCapFile = "/proc/sys/kernel/cap_last_cap"
)

// confinement is what confineGuest applied, for the kernel log.
type confinement struct {
	boundingDropped int
	yama            bool
	filterLength    int
}

// confineGuest applies the strict tool profile's inner confinement (see the file notes).
// Any failure is a boot error: a guest never runs with part of its confinement.
func confineGuest() (confinement, error) {
	var applied confinement
	if err := prepareProbe(); err != nil {
		return applied, fmt.Errorf("probe: %w", err)
	}
	dropped, err := dropBoundingSet()
	if err != nil {
		return applied, fmt.Errorf("capability bounding set: %w", err)
	}
	applied.boundingDropped = dropped
	yama, err := tightenPtraceScope()
	if err != nil {
		return applied, fmt.Errorf("yama ptrace_scope: %w", err)
	}
	applied.yama = yama
	filter := strictFilter()
	if err := installFilter(filter); err != nil {
		return applied, fmt.Errorf("seccomp: %w", err)
	}
	applied.filterLength = len(filter)
	return applied, nil
}

// prepareProbe copies the agent's own binary to a tmpfs of its own, executable and, once
// the copy is in, read-only.
func prepareProbe() error {
	if err := os.MkdirAll(probeDirectory, 0o755); err != nil {
		return err
	}
	if err := unix.Mount("tmpfs", probeDirectory, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, probeTmpfs); err != nil {
		return fmt.Errorf("mount: %w", err)
	}
	source, err := os.Open("/proc/self/exe")
	if err != nil {
		return err
	}
	defer source.Close()
	target, err := os.OpenFile(probePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o555)
	if err != nil {
		return err
	}
	if _, err := io.Copy(target, source); err != nil {
		target.Close()
		return err
	}
	if err := target.Close(); err != nil {
		return err
	}
	if err := os.Link(probePath, probeDirectory+"/yougori"); err != nil {
		return fmt.Errorf("grid tool: %w", err)
	}
	return unix.Mount("", probeDirectory, "", unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV, "")
}

// dropBoundingSet removes every capability from the bounding set of every thread of the
// agent; the agent's own effective set is unchanged, and it never executes again.
func dropBoundingSet() (int, error) {
	raw, err := os.ReadFile(capLastCapFile)
	if err != nil {
		return 0, err
	}
	last, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || last < 0 || last > 63 {
		return 0, fmt.Errorf("cap_last_cap %q", strings.TrimSpace(string(raw)))
	}
	for capability := 0; capability <= last; capability++ {
		if _, _, errno := syscall.AllThreadsSyscall(syscall.SYS_PRCTL, unix.PR_CAPBSET_DROP, uintptr(capability), 0); errno != 0 {
			return capability, fmt.Errorf("drop %d: %w", capability, errno)
		}
	}
	return last + 1, nil
}

// tightenPtraceScope sets Yama's ptrace_scope to 3 (no process may attach) when the kernel
// has Yama; false when it has none.
func tightenPtraceScope() (bool, error) {
	if _, err := os.Stat(yamaPtrace); err != nil {
		return false, nil
	}
	if err := os.WriteFile(yamaPtrace, []byte("3"), 0); err != nil {
		return false, err
	}
	return true, nil
}

// probeAvailable says whether the probe exists, for the kernel log.
func probeAvailable() bool {
	_, err := os.Stat(filepath.Clean(probePath))
	return err == nil
}
