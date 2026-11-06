package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// filterHelperVariable makes the test binary, run again by TestTheStrictFilterRefusesEveryForbiddenInterface,
// install the strict filter on itself and print its probe results.
const filterHelperVariable = "YOUGORI_FILTER_HELPER"

// TestFilterHelper is the child half: no_new_privs on every thread, the strict filter,
// then every interface probe and one allowed call, printed as JSON.
func TestFilterHelper(t *testing.T) {
	if os.Getenv(filterHelperVariable) != "1" {
		t.Skip("run by TestTheStrictFilterRefusesEveryForbiddenInterface")
	}
	if err := setNoNewPrivileges(); err != nil {
		t.Fatalf("no_new_privs: %v", err)
	}
	if err := installFilter(strictFilter()); err != nil {
		t.Fatalf("install: %v", err)
	}
	result := map[string]any{"interfaces": probeInterfaces(), "getppid": syscall.Getppid() > 0}
	encoded, _ := json.Marshal(result)
	os.Stdout.Write(append([]byte("RESULT "), append(encoded, '\n')...))
}

// PROVES the strict filter, installed on a process, refuses every interface the profile
// assigns to seccomp with EPERM (io_uring, bpf, userfaultfd, perf_event_open, kexec,
// module loading, ptrace, AF_VSOCK sockets) and leaves an ordinary call working; the probe
// reports each as the contract's failed outcome with errno 1.
func TestTheStrictFilterRefusesEveryForbiddenInterface(t *testing.T) {
	command := exec.Command(os.Args[0], "-test.run=^TestFilterHelper$", "-test.v")
	command.Env = append(os.Environ(), filterHelperVariable+"=1")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("helper: %v\n%s", err, output)
	}
	var line string
	for _, candidate := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(candidate, "RESULT ") {
			line = strings.TrimPrefix(candidate, "RESULT ")
		}
	}
	if line == "" {
		t.Fatalf("no result:\n%s", output)
	}
	var result struct {
		Interfaces []interfaceProbe `json:"interfaces"`
		Getppid    bool             `json:"getppid"`
	}
	if err := json.Unmarshal([]byte(line), &result); err != nil {
		t.Fatalf("result %q: %v", line, err)
	}
	if !result.Getppid {
		t.Fatalf("an ordinary call failed under the filter")
	}
	want := []string{"io_uring", "bpf", "userfaultfd", "perf_event_open", "kexec", "module_loading", "ptrace", "vsock_socket"}
	var got []string
	for _, probe := range result.Interfaces {
		got = append(got, probe.Interface)
		if probe.Outcome.Outcome != "failed" || probe.Outcome.Errno == nil || *probe.Outcome.Errno != uint16(unix.EPERM) {
			t.Errorf("%s: %+v, want failed with EPERM", probe.Interface, probe.Outcome)
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("interfaces %v, want %v", got, want)
	}
}

// PROVES the program's shape: the architecture check first, every denied call jumping to
// the EPERM return, the socket rule last before allow, and every jump inside the program.
func TestTheStrictFilterProgramIsWellFormed(t *testing.T) {
	program := strictFilter()
	if len(program) != 6+len(deniedCalls)+5 {
		t.Fatalf("%d instructions", len(program))
	}
	last := program[len(program)-1]
	if last.Code != unix.BPF_RET|unix.BPF_K || last.K != uint32(unix.SECCOMP_RET_ERRNO)|uint32(unix.EPERM) {
		t.Fatalf("the last instruction is %+v, want the EPERM return", last)
	}
	if allow := program[len(program)-2]; allow.K != unix.SECCOMP_RET_ALLOW {
		t.Fatalf("the instruction before it is %+v, want allow", allow)
	}
	for index, instruction := range program {
		if instruction.Code&0x07 != unix.BPF_JMP {
			continue
		}
		for _, offset := range []uint8{instruction.Jt, instruction.Jf} {
			if target := index + 1 + int(offset); target >= len(program) {
				t.Fatalf("instruction %d jumps to %d of %d", index, target, len(program))
			}
		}
	}
	for index := range deniedCalls {
		instruction := program[6+index]
		if 6+index+1+int(instruction.Jt) != len(program)-1 {
			t.Fatalf("denied call %d does not reach the EPERM return", index)
		}
	}
}

// PROVES the probe document has exactly the contract's field names (GuestProbeDocument,
// which refuses unknown fields) and the outcome forms {"outcome":"failed","errno":N} and
// {"outcome":"succeeded"}.
func TestTheProbeDocumentHasTheContractsFields(t *testing.T) {
	uid := uint32(1000)
	yes := true
	document := probeDocument{
		Profile:        strings.Repeat("ab", 32),
		Interfaces:     []interfaceProbe{{Interface: "ptrace", Outcome: failed(unix.EPERM)}},
		ProtectedPaths: []pathProbe{{Path: "~/.bashrc", Outcome: succeeded()}},
		Capabilities:   &observedCapabilities{Bounding: []string{}, Permitted: []string{}, Effective: []string{}},
		UID:            &uid,
		NoNewPrivs:     &yes,
		KernelSettings: []struct{}{},
		KernelOptions:  []struct{}{},
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	var names []string
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	want := []string{"capabilities", "interfaces", "kernel_options", "kernel_settings", "no_new_privs", "profile", "protected_paths", "root_image", "uid"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("fields %v, want %v", names, want)
	}
	if !strings.Contains(string(encoded), `{"interface":"ptrace","outcome":{"outcome":"failed","errno":1}}`) ||
		!strings.Contains(string(encoded), `{"path":"~/.bashrc","outcome":{"outcome":"succeeded"}}`) {
		t.Fatalf("outcome forms: %s", encoded)
	}
}

// PROVES capability masks are named in the contract's spelling and a bit the contract
// cannot name is refused rather than dropped.
func TestCapabilityMasksAreNamedOrRefused(t *testing.T) {
	names, err := capabilitySet("0000000000000000")
	if err != nil || len(names) != 0 {
		t.Fatalf("empty mask: %v %v", names, err)
	}
	names, err = capabilitySet("0000000000200401")
	if err != nil || !reflect.DeepEqual(names, []string{"chown", "net_bind_service", "sys_admin"}) {
		t.Fatalf("mask: %v %v", names, err)
	}
	names, err = capabilitySet("000001ffffffffff")
	if err != nil || len(names) != 41 || names[40] != "checkpoint_restore" {
		t.Fatalf("full mask: %d names, %v", len(names), err)
	}
	if _, err := capabilitySet("0000020000000000"); err == nil {
		t.Fatalf("bit 41 was named")
	}
	fields := statusFields(strings.NewReader("Name:\tsh\nCapBnd:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n"), "CapBnd", "NoNewPrivs", "Seccomp", "Seccomp_filters")
	if fields["CapBnd"] != "0000000000000000" || fields["NoNewPrivs"] != "1" || fields["Seccomp"] != "2" {
		t.Fatalf("fields %v", fields)
	}
	if _, ok := fields["Seccomp_filters"]; ok {
		t.Fatalf("an absent field was read")
	}
}

// PROVES a protected path probe reports the errno of the refused write and, where the
// write succeeds, removes what it made: a directory it may write into reads succeeded and
// stays empty; a missing file reads ENOENT.
func TestProtectedPathProbesReportTheRefusal(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(home+"/.config/git", 0o755); err != nil {
		t.Fatal(err)
	}
	writable := probeProtectedPath("~/.config/git/")
	if writable.Outcome.Outcome != "succeeded" {
		t.Fatalf("writable directory: %+v", writable.Outcome)
	}
	entries, _ := os.ReadDir(home + "/.config/git")
	if len(entries) != 0 {
		t.Fatalf("the probe left %d entries", len(entries))
	}
	missing := probeProtectedPath("~/.bashrc")
	if missing.Outcome.Outcome != "failed" || *missing.Outcome.Errno != uint16(unix.ENOENT) {
		t.Fatalf("missing file: %+v", missing.Outcome)
	}
}
