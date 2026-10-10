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
