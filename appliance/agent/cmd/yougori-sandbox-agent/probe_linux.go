package main

// The confinement probe (VM-CP-05 "inside the inner container"): a terminal runs the
// agent's own binary as `/run/yougori/bin/yougori-probe probe-confinement <profile digest>`
// (confine_linux.go). It attempts every interface the strict tool profile forbids and a
// write to every protected path, reads its own uid, no_new_privs and capability sets, and
// prints one GuestProbeDocument (src-tauri/src/sandbox_contract/confinement/evaluate.rs) as
// a JSON line, then one line of what it read of its seccomp state. Every result is the
// guest's word: the host evaluates it as a guest report and corroborates what it can
// itself (the booted image, the kernel build). The probes are harmless: each call is made
// so that it fails where the interface is allowed too (no ring, no program, no module,
// no tracee), and anything a call did open is closed at once.

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// probeCommand is the probe's first argument.
const probeCommand = "probe-confinement"

// probedPaths are the strict tool profile's protected paths, as the profile spells them.
var probedPaths = []string{"~/.bashrc", "~/.config/git/", "~/.gitconfig", ".git/", ".git/hooks/"}

// capabilityNames are the capability numbers' names as the contract spells them
// (LinuxCapability, snake_case), in kernel number order.
var capabilityNames = []string{
	"chown", "dac_override", "dac_read_search", "fowner", "fsetid", "kill", "setgid",
	"setuid", "setpcap", "linux_immutable", "net_bind_service", "net_broadcast",
	"net_admin", "net_raw", "ipc_lock", "ipc_owner", "sys_module", "sys_rawio",
	"sys_chroot", "sys_ptrace", "sys_pacct", "sys_admin", "sys_boot", "sys_nice",
	"sys_resource", "sys_time", "sys_tty_config", "mknod", "lease", "audit_write",
	"audit_control", "setfcap", "mac_override", "mac_admin", "syslog", "wake_alarm",
	"block_suspend", "audit_read", "perfmon", "bpf", "checkpoint_restore",
}

type probeOutcome struct {
	Outcome string  `json:"outcome"`
	Errno   *uint16 `json:"errno,omitempty"`
}

type interfaceProbe struct {
	Interface string       `json:"interface"`
	Outcome   probeOutcome `json:"outcome"`
}

type pathProbe struct {
	Path    string       `json:"path"`
	Outcome probeOutcome `json:"outcome"`
}

type observedCapabilities struct {
	Bounding  []string `json:"bounding"`
	Permitted []string `json:"permitted"`
	Effective []string `json:"effective"`
}

// probeDocument is GuestProbeDocument's wire form: every field, none more.
type probeDocument struct {
	Profile        string                `json:"profile"`
	Interfaces     []interfaceProbe      `json:"interfaces"`
	ProtectedPaths []pathProbe           `json:"protected_paths"`
	Capabilities   *observedCapabilities `json:"capabilities"`
	UID            *uint32               `json:"uid"`
	NoNewPrivs     *bool                 `json:"no_new_privs"`
	KernelSettings []struct{}            `json:"kernel_settings"`
	KernelOptions  []struct{}            `json:"kernel_options"`
	RootImage      *string               `json:"root_image"`
}

// seccompState is the second line: what /proc/self/status says of seccomp.
type seccompState struct {
	Seccomp        *int `json:"seccomp"`
	SeccompFilters *int `json:"seccomp_filters"`
}

func succeeded() probeOutcome { return probeOutcome{Outcome: "succeeded"} }

func failed(errno syscall.Errno) probeOutcome {
	code := uint16(errno)
	return probeOutcome{Outcome: "failed", Errno: &code}
}

// outcomeOf is the outcome of a raw call; a descriptor it opened is closed.
func outcomeOf(r1 uintptr, errno syscall.Errno, opens bool) probeOutcome {
	if errno != 0 {
		return failed(errno)
	}
	if opens {
		_ = unix.Close(int(r1))
	}
	return succeeded()
}

// probeInterfaces attempts each interface once. Where the interface is allowed each call
// still fails or opens nothing lasting: a ring of no entries, an unknown bpf command, an
// unknown ptrace request on no process, no image to load.
func probeInterfaces() []interfaceProbe {
	const (
		unknownCommand = 0x7fff
		userModeOnly   = 1 // UFFD_USER_MODE_ONLY
	)
	call := func(name string, trap uintptr, a1, a2, a3 uintptr, opens bool) interfaceProbe {
		r1, _, errno := unix.Syscall(trap, a1, a2, a3)
		return interfaceProbe{Interface: name, Outcome: outcomeOf(r1, errno, opens)}
	}
	return []interfaceProbe{
		call("io_uring", unix.SYS_IO_URING_SETUP, 0, 0, 0, true),
		call("bpf", unix.SYS_BPF, unknownCommand, 0, 0, true),
		call("userfaultfd", unix.SYS_USERFAULTFD, userModeOnly|unix.O_CLOEXEC, 0, 0, true),
		{Interface: "perf_event_open", Outcome: func() probeOutcome {
			// No attributes: EFAULT where the call is allowed.
			r1, _, errno := unix.Syscall6(unix.SYS_PERF_EVENT_OPEN, 0, 0, ^uintptr(0), ^uintptr(0), 0, 0)
			return outcomeOf(r1, errno, true)
		}()},
		call("kexec", unix.SYS_KEXEC_LOAD, 0, 0, 0, false),
		{Interface: "module_loading", Outcome: func() probeOutcome {
			empty := []byte{0}
			r1, _, errno := unix.Syscall(unix.SYS_INIT_MODULE, 0, 0, uintptr(unsafe.Pointer(&empty[0])))
			return outcomeOf(r1, errno, false)
		}()},
		call("ptrace", unix.SYS_PTRACE, unknownCommand, 0, 0, false),
		call("vsock_socket", unix.SYS_SOCKET, unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0, true),
	}
}

// probeProtectedPath tries one write the protected path refuses: appending to a file (no byte is
// written) or creating a file in a directory (removed again if it was made).
func probeProtectedPath(spec string) pathProbe {
	path := spec
	if strings.HasPrefix(spec, "~/") {
		home := os.Getenv("HOME")
		if home == "" {
			return pathProbe{Path: spec, Outcome: failed(unix.ENOENT)}
		}
		path = filepath.Join(home, spec[2:])
	}
	if strings.HasSuffix(spec, "/") {
		name := filepath.Join(path, ".yougori-probe-"+strconv.Itoa(os.Getpid()))
		fd, err := unix.Open(name, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_CLOEXEC, 0o600)
		if err != nil {
			return pathProbe{Path: spec, Outcome: failed(errnoOf(err))}
		}
		_ = unix.Close(fd)
		_ = unix.Unlink(name)
		return pathProbe{Path: spec, Outcome: succeeded()}
	}
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_APPEND|unix.O_CLOEXEC, 0)
	if err != nil {
		return pathProbe{Path: spec, Outcome: failed(errnoOf(err))}
	}
	_ = unix.Close(fd)
	return pathProbe{Path: spec, Outcome: succeeded()}
}

// errnoOf is the errno an error carries (0 for none, EIO for an error without one).
func errnoOf(err error) syscall.Errno {
	if err == nil {
		return 0
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno
	}
	return unix.EIO
}

// statusFields reads the named fields of /proc/self/status.
func statusFields(reader io.Reader, names ...string) map[string]string {
	wanted := map[string]bool{}
	for _, name := range names {
		wanted[name] = true
	}
	found := map[string]string{}
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		name, value, ok := strings.Cut(scanner.Text(), ":")
		if ok && wanted[name] {
			found[name] = strings.TrimSpace(value)
		}
	}
	return found
}

// capabilitySet names the bits of a /proc/self/status capability mask.
func capabilitySet(mask string) ([]string, error) {
	bits, err := strconv.ParseUint(mask, 16, 64)
	if err != nil {
		return nil, fmt.Errorf("capability mask %q", mask)
	}
	names := []string{}
	for bit := 0; bit < 64; bit++ {
		if bits&(1<<uint(bit)) == 0 {
			continue
		}
		if bit >= len(capabilityNames) {
			return nil, fmt.Errorf("capability %d has no name in the contract", bit)
		}
		names = append(names, capabilityNames[bit])
	}
	return names, nil
}

func optionalInt(text string, present bool) *int {
	if !present {
		return nil
	}
	value, err := strconv.Atoi(text)
	if err != nil {
		return nil
	}
	return &value
}

// runProbe is the probe's main: exit 0 with the two lines, 2 on a bad argument, 3 when
// its own state cannot be read.
func runProbe(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: yougori-probe probe-confinement <profile digest, 64 hex digits>")
		return 2
	}
	if raw, err := hex.DecodeString(args[0]); err != nil || len(raw) != 32 {
		fmt.Fprintln(os.Stderr, "the profile digest is not 64 hex digits")
		return 2
	}
	status, err := os.Open("/proc/self/status")
	if err != nil {
		fmt.Fprintln(os.Stderr, "probe:", err)
		return 3
	}
	fields := statusFields(status, "CapBnd", "CapPrm", "CapEff", "NoNewPrivs", "Seccomp", "Seccomp_filters")
	status.Close()
	sets := map[string][]string{}
	for _, name := range []string{"CapBnd", "CapPrm", "CapEff"} {
		set, err := capabilitySet(fields[name])
		if err != nil {
			fmt.Fprintln(os.Stderr, "probe:", err)
			return 3
		}
		sets[name] = set
	}
	uid := uint32(os.Getuid())
	noNewPrivs := fields["NoNewPrivs"] == "1"
	document := probeDocument{
		Profile:        strings.ToLower(args[0]),
		Interfaces:     probeInterfaces(),
		Capabilities:   &observedCapabilities{Bounding: sets["CapBnd"], Permitted: sets["CapPrm"], Effective: sets["CapEff"]},
		UID:            &uid,
		NoNewPrivs:     &noNewPrivs,
		KernelSettings: []struct{}{},
		KernelOptions:  []struct{}{},
	}
	for _, spec := range probedPaths {
		document.ProtectedPaths = append(document.ProtectedPaths, probeProtectedPath(spec))
	}
	seccomp, hasSeccomp := fields["Seccomp"]
	filters, hasFilters := fields["Seccomp_filters"]
	encoder := json.NewEncoder(os.Stdout)
	if err := encoder.Encode(document); err != nil {
		return 3
	}
	if err := encoder.Encode(seccompState{Seccomp: optionalInt(seccomp, hasSeccomp), SeccompFilters: optionalInt(filters, hasFilters)}); err != nil {
		return 3
	}
	return 0
}
