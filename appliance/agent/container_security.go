package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	containers "github.com/containerd/containerd/api/services/containers/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

// Keep the capabilities needed by image entrypoints, package managers and
// development tools. Raw networking, device creation, namespace administration,
// tracing other sandboxes and changing the kernel are deliberately unavailable.
var containerCapabilities = []string{
	"CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "NET_BIND_SERVICE",
	"SETGID", "SETUID", "SETFCAP", "SYS_CHROOT", "AUDIT_WRITE",
}

const containerPIDsLimit = 4096

func containerSecurityArguments() []string {
	args := []string{
		"--security-opt", "no-new-privileges=true",
		"--security-opt", "seccomp=builtin",
		"--cap-drop", "ALL",
		"--cgroupns", "private",
		"--pids-limit", "4096",
		"--ulimit", "core=0:0",
	}
	for _, capability := range containerCapabilities {
		args = append(args, "--cap-add", capability)
	}
	return args
}

func containerNetworkSecurityArguments() []string {
	// Datagram ICMP permits ordinary ping diagnostics without CAP_NET_RAW,
	// which would also permit packet injection and spoofing on shared bridges.
	return []string{"--sysctl", "net.ipv4.ping_group_range=0 2147483647"}
}

func validWorkloadImage(image string) bool {
	return image != "" && len(image) <= 512 && !strings.HasPrefix(image, "-") &&
		!strings.ContainsAny(image, "\x00\r\n \t")
}

// PC shares are capabilities granted to one environment. A request must not
// borrow another environment's mounted slot, even if it knows that slot's name.
func validateWorkloadOwner(id string, options workloadOptions) error {
	if !safeID.MatchString(id) {
		return fmt.Errorf("invalid workload owner")
	}
	for _, bind := range options.Binds {
		if !validWorkloadSlot(id, bind.Source) {
			return fmt.Errorf("PC mount belongs to a different environment")
		}
	}
	return nil
}

func validWorkloadSlot(id, slot string) bool {
	if !safeID.MatchString(id) || !strings.HasPrefix(slot, id+"-") {
		return false
	}
	suffix := strings.TrimPrefix(slot, id+"-")
	if len(suffix) < 1 || len(suffix) > 2 || strings.Trim(suffix, "0123456789") != "" {
		return false
	}
	index, err := strconv.Atoi(suffix)
	return err == nil && index < 64 && strconv.Itoa(index) == suffix
}

// Upgrade saved OCI specifications before the next task is launched. Updating
// only security fields preserves files, image USER, GPU/CDI devices, mounts,
// working directory, environment and the saved startup command.
func hardenedContainerSpec(original []byte) ([]byte, error) {
	var spec map[string]json.RawMessage
	if json.Unmarshal(original, &spec) != nil || spec == nil {
		return nil, fmt.Errorf("cannot read the container security specification")
	}
	var process, linux, resources map[string]json.RawMessage
	if json.Unmarshal(spec["process"], &process) != nil || process == nil ||
		json.Unmarshal(spec["linux"], &linux) != nil || linux == nil {
		return nil, fmt.Errorf("container process or Linux security configuration is missing")
	}
	// A permissive or missing seccomp profile cannot be safely upgraded by
	// guessing an allowlist. New/reconfigured containers use nerdctl's profile.
	var seccomp struct {
		DefaultAction string `json:"defaultAction"`
	}
	if json.Unmarshal(linux["seccomp"], &seccomp) != nil ||
		(seccomp.DefaultAction != "SCMP_ACT_ERRNO" && seccomp.DefaultAction != "SCMP_ACT_KILL" &&
			seccomp.DefaultAction != "SCMP_ACT_KILL_PROCESS" && seccomp.DefaultAction != "SCMP_ACT_TRAP") {
		return nil, fmt.Errorf("container has no enforcing seccomp profile; stop it and save its configuration to apply the secure runtime profile")
	}
	restricted, err := restrictFileAttributes(linux["seccomp"])
	if err != nil {
		return nil, err
	}
	linux["seccomp"] = restricted
	process["noNewPrivileges"] = json.RawMessage("true")
	var capabilities map[string][]string
	if raw := process["capabilities"]; len(raw) > 0 && json.Unmarshal(raw, &capabilities) != nil {
		return nil, fmt.Errorf("invalid container capabilities")
	}
	allowed := make(map[string]bool, len(containerCapabilities))
	for _, capability := range containerCapabilities {
		allowed["CAP_"+capability] = true
	}
	for _, set := range []string{"bounding", "effective", "inheritable", "permitted", "ambient"} {
		filtered := make([]string, 0, len(capabilities[set]))
		for _, capability := range capabilities[set] {
			if allowed[capability] {
				filtered = append(filtered, capability)
			}
		}
		if capabilities == nil {
			capabilities = make(map[string][]string)
		}
		capabilities[set] = filtered
	}
	process["capabilities"], _ = json.Marshal(capabilities)
	var limits []map[string]json.RawMessage
	if raw := process["rlimits"]; len(raw) > 0 && json.Unmarshal(raw, &limits) != nil {
		return nil, fmt.Errorf("invalid container file limits")
	}
	coreFound := false
	for _, limit := range limits {
		if string(limit["type"]) == `"RLIMIT_CORE"` {
			limit["hard"], limit["soft"] = json.RawMessage("0"), json.RawMessage("0")
			coreFound = true
		}
	}
	if !coreFound {
		limits = append(limits, map[string]json.RawMessage{"type": json.RawMessage(`"RLIMIT_CORE"`), "hard": json.RawMessage("0"), "soft": json.RawMessage("0")})
	}
	process["rlimits"], _ = json.Marshal(limits)
	var namespaces []map[string]json.RawMessage
	if raw := linux["namespaces"]; len(raw) > 0 && json.Unmarshal(raw, &namespaces) != nil {
		return nil, fmt.Errorf("invalid container namespace configuration")
	}
	cgroupFound := false
	privateNetwork := false
	for _, entry := range namespaces {
		if string(entry["type"]) == `"cgroup"` {
			delete(entry, "path")
			cgroupFound = true
		}
		if string(entry["type"]) == `"network"` && (len(entry["path"]) == 0 || string(entry["path"]) == `""`) {
			privateNetwork = true
		}
	}
	if !cgroupFound {
		namespaces = append(namespaces, map[string]json.RawMessage{"type": json.RawMessage(`"cgroup"`)})
	}
	linux["namespaces"], _ = json.Marshal(namespaces)
	if privateNetwork {
		var sysctl map[string]string
		if raw := linux["sysctl"]; len(raw) > 0 && json.Unmarshal(raw, &sysctl) != nil {
			return nil, fmt.Errorf("invalid container network sysctls")
		}
		if sysctl == nil {
			sysctl = make(map[string]string)
		}
		sysctl["net.ipv4.ping_group_range"] = "0 2147483647"
		linux["sysctl"], _ = json.Marshal(sysctl)
	}
	if raw := linux["resources"]; len(raw) > 0 && string(raw) != "null" && json.Unmarshal(raw, &resources) != nil {
		return nil, fmt.Errorf("invalid container resource limits")
	}
	if resources == nil {
		resources = make(map[string]json.RawMessage)
	}
	var pids struct {
		Limit int64 `json:"limit"`
	}
	if raw := resources["pids"]; len(raw) > 0 && json.Unmarshal(raw, &pids) != nil {
		return nil, fmt.Errorf("invalid container process limit")
	}
	if pids.Limit <= 0 || pids.Limit > containerPIDsLimit {
		pids.Limit = containerPIDsLimit
	}
	resources["pids"], _ = json.Marshal(pids)
	var memory map[string]json.RawMessage
	if raw := resources["memory"]; len(raw) > 0 && string(raw) != "null" && json.Unmarshal(raw, &memory) != nil {
		return nil, fmt.Errorf("invalid container memory limit")
	}
	if memory != nil {
		var limit int64
		if raw := memory["limit"]; len(raw) > 0 && json.Unmarshal(raw, &limit) != nil {
			return nil, fmt.Errorf("invalid container memory allocation")
		}
		if limit > 0 {
			memory["swap"] = memory["limit"]
			resources["memory"], _ = json.Marshal(memory)
		}
	}
	linux["resources"], _ = json.Marshal(resources)
	spec["process"], _ = json.Marshal(process)
	spec["linux"], _ = json.Marshal(linux)
	return json.Marshal(spec)
}

// Storage limits are ext4 project quotas. Without a user namespace a
// container's root owns its files and could move them to the unlimited
// project 0 (chattr -p 0, or chattr -P on a directory) and fill the shared
// store. Changing file attributes is refused; reading them (lsattr) works.
var deniedAttributeIoctls = []uint32{
	0x401c5820, // FS_IOC_FSSETXATTR: project ID and inheritance
	0x40086602, // FS_IOC_SETFLAGS
	0x40046602, // FS_IOC32_SETFLAGS
}

// file_setattr (Linux 6.17) is the system-call form of FS_IOC_FSSETXATTR.
var deniedAttributeSyscalls = map[string]bool{"ioctl": true, "file_setattr": true}

// restrictFileAttributes rewrites the profile's ioctl permission so every
// command except the attribute setters is allowed. A seccomp rule cannot say
// "unless cmd is X or Y" (runc turns several conditions on one argument into
// separate rules that each allow), so the permitted commands are covered by
// masked prefix rules and the denied ones fall through to the errno default.
// The kernel truncates cmd to 32 bits; the masks ignore the upper half.
func restrictFileAttributes(raw json.RawMessage) (json.RawMessage, error) {
	var profile map[string]json.RawMessage
	if json.Unmarshal(raw, &profile) != nil || profile == nil {
		return nil, fmt.Errorf("cannot read the container seccomp profile")
	}
	var rules []map[string]json.RawMessage
	if existing := profile["syscalls"]; len(existing) > 0 && string(existing) != "null" && json.Unmarshal(existing, &rules) != nil {
		return nil, fmt.Errorf("cannot read the container seccomp rules")
	}
	kept := make([]any, 0, len(rules)+64)
	for _, rule := range rules {
		var action string
		var names []string
		if json.Unmarshal(rule["action"], &action) != nil || json.Unmarshal(rule["names"], &names) != nil {
			return nil, fmt.Errorf("invalid container seccomp rule")
		}
		if action == "SCMP_ACT_ALLOW" || action == "SCMP_ACT_LOG" {
			remaining := make([]string, 0, len(names))
			for _, name := range names {
				if !deniedAttributeSyscalls[name] {
					remaining = append(remaining, name)
				}
			}
			if len(remaining) == 0 {
				continue
			}
			rule["names"], _ = json.Marshal(remaining)
		}
		kept = append(kept, rule)
	}
	for _, prefix := range permittedIoctlPrefixes(deniedAttributeIoctls) {
		kept = append(kept, map[string]any{
			"names":  []string{"ioctl"},
			"action": "SCMP_ACT_ALLOW",
			"args":   []map[string]any{{"index": 1, "value": prefix[0], "valueTwo": prefix[1], "op": "SCMP_CMP_MASKED_EQ"}},
		})
	}
	profile["syscalls"], _ = json.Marshal(kept)
	return json.Marshal(profile)
}

// permittedIoctlPrefixes returns {mask, value} pairs whose union is every
// 32-bit command except the denied ones.
func permittedIoctlPrefixes(denied []uint32) [][2]uint32 {
	var prefixes [][2]uint32
	var cover func(value uint32, length uint, denied []uint32)
	cover = func(value uint32, length uint, denied []uint32) {
		if len(denied) == 0 {
			mask := uint32(0)
			if length > 0 {
				mask = ^uint32(0) << (32 - length)
			}
			prefixes = append(prefixes, [2]uint32{mask, value})
			return
		}
		if length == 32 {
			return
		}
		bit := uint32(1) << (31 - length)
		var clear, set []uint32
		for _, command := range denied {
			if command&bit == 0 {
				clear = append(clear, command)
			} else {
				set = append(set, command)
			}
		}
		cover(value, length+1, clear)
		cover(value|bit, length+1, set)
	}
	cover(0, 0, denied)
	return prefixes
}

func secureSavedContainer(ctx context.Context, containerNamespace, name string) error {
	output, err := run(ctx, "nerdctl", "--namespace", containerNamespace, "inspect", "--format", "{{.Id}}", name)
	if err != nil {
		return err
	}
	id := strings.TrimSpace(output.Stdout)
	if !safeID.MatchString(id) {
		return fmt.Errorf("cannot resolve container security identity")
	}
	connection, err := grpc.NewClient("unix://"+containerdSocket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer connection.Close()
	ctx = metadata.AppendToOutgoingContext(ctx, "containerd-namespace", containerNamespace)
	client := containers.NewContainersClient(connection)
	current, err := client.Get(ctx, &containers.GetContainerRequest{ID: id})
	if err != nil {
		return fmt.Errorf("read container security configuration: %w", err)
	}
	if current.GetContainer().GetSpec() == nil {
		return fmt.Errorf("saved container security configuration is missing")
	}
	spec := current.Container.Spec
	updated, err := hardenedContainerSpec(spec.Value)
	if err != nil {
		return err
	}
	if bytes.Equal(updated, spec.Value) {
		return nil
	}
	_, err = client.Update(ctx, &containers.UpdateContainerRequest{
		Container:  &containers.Container{ID: id, Spec: &anypb.Any{TypeUrl: spec.TypeUrl, Value: updated}},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec"}},
	})
	if err != nil {
		return fmt.Errorf("save container security configuration: %w", err)
	}
	return nil
}

// savedContainerResources reads a container's CPU and memory limits, or the
// smallest standard allocation when it has none or no longer exists.
func savedContainerResources(ctx context.Context, containerNamespace, name string) (float64, int64) {
	const fallbackCPUs, fallbackMemory = 1.0, int64(1 << 30)
	output, err := run(ctx, "nerdctl", "--namespace", containerNamespace, "inspect", "--format", "{{.Id}}", name)
	id := strings.TrimSpace(output.Stdout)
	if err != nil || !safeID.MatchString(id) {
		return fallbackCPUs, fallbackMemory
	}
	connection, err := grpc.NewClient("unix://"+containerdSocket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fallbackCPUs, fallbackMemory
	}
	defer connection.Close()
	ctx = metadata.AppendToOutgoingContext(ctx, "containerd-namespace", containerNamespace)
	current, err := containers.NewContainersClient(connection).Get(ctx, &containers.GetContainerRequest{ID: id})
	if err != nil || current.GetContainer().GetSpec() == nil {
		return fallbackCPUs, fallbackMemory
	}
	cpus, memory := specResources(current.Container.Spec.Value)
	if !validContainerResources(cpus, memory) {
		return fallbackCPUs, fallbackMemory
	}
	return cpus, memory
}

func specResources(spec []byte) (float64, int64) {
	var saved struct {
		Linux struct {
			Resources struct {
				CPU struct {
					Quota  int64  `json:"quota"`
					Period uint64 `json:"period"`
				} `json:"cpu"`
				Memory struct {
					Limit int64 `json:"limit"`
				} `json:"memory"`
			} `json:"resources"`
		} `json:"linux"`
	}
	if json.Unmarshal(spec, &saved) != nil || saved.Linux.Resources.CPU.Period == 0 || saved.Linux.Resources.CPU.Quota <= 0 {
		return 0, 0
	}
	return float64(saved.Linux.Resources.CPU.Quota) / float64(saved.Linux.Resources.CPU.Period), saved.Linux.Resources.Memory.Limit
}
