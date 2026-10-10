package main

import (
	"context"
	"encoding/json"
	"math"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestImageCannotInjectNerdctlLaunchFlags(t *testing.T) {
	argv := []string{"alpine:3.24"}
	for _, image := range []string{"--privileged", "--security-opt=seccomp=unconfined", "-v", "image\n--privileged", "alpine image", ""} {
		if _, err := appendWorkload([]string{"create"}, image, "", workloadOptions{Args: &argv}); err == nil {
			t.Fatalf("accepted image flag injection %q", image)
		}
		if _, err := appendResolvedWorkload(context.Background(), namespace, nil, image, "", workloadOptions{Args: &argv}); err == nil {
			t.Fatalf("resolved injected image %q", image)
		}
	}
	for _, image := range []string{"alpine:3.24", "localhost:5000/project/image:dev", "repo/image@sha256:" + strings.Repeat("a", 64)} {
		if !validWorkloadImage(image) {
			t.Fatalf("rejected OCI image %q", image)
		}
	}
}

func TestProvisionRejectsImageInjectionBeforeLaunching(t *testing.T) {
	request := httptest.NewRequest("POST", "/v1/containers/provision", strings.NewReader(`{"id":"env-safe","image":"--privileged","cpus":1,"memoryBytes":1073741824,"options":{"args":["alpine"]}}`))
	response := httptest.NewRecorder()
	(&server{}).provision(response, request)
	if response.Code != 400 {
		t.Fatalf("injected provision status: %d %s", response.Code, response.Body.String())
	}
}

func TestWorkloadMountOwnershipCannotBorrowAPeerSlot(t *testing.T) {
	for _, slot := range []string{"env-peer-0", "env-safe-peer-0", "env-safe-../peer", "env-safe-64", "env-safe-00", "env-safe-0/other"} {
		if err := validateWorkloadOwner("env-safe", workloadOptions{Binds: []workloadVolume{{Source: slot, Target: "/data"}}}); err == nil {
			t.Fatalf("accepted foreign/ambiguous slot %q", slot)
		}
	}
	for _, slot := range []string{"env-safe-0", "env-safe-63"} {
		if err := validateWorkloadOwner("env-safe", workloadOptions{Binds: []workloadVolume{{Source: slot, Target: "/data"}}}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWorkloadPathsCannotHideReservedKernelOrDisplayMounts(t *testing.T) {
	for _, target := range []string{"//proc", "/proc//sys", "//sys/kernel", "/dev/../etc", "/tmp/.X11-unix", "/tmp//.X11-unix/X0", "/opendock/", "/data//nested"} {
		options := workloadOptions{Volumes: []workloadVolume{{Source: "project", Target: target}}}
		if _, err := options.arguments(); err == nil {
			t.Fatalf("accepted reserved/noncanonical path %q", target)
		}
	}
	options := workloadOptions{Binds: make([]workloadVolume, 65)}
	if _, err := options.arguments(); err == nil {
		t.Fatal("accepted unbounded PC mounts")
	}
}

func TestSavedSecurityUpgradePreservesWorkloadAndDropsDangerousCapabilities(t *testing.T) {
	original := []byte(`{"process":{"args":["python","train.py"],"cwd":"/project","env":["KEEP=yes"],"user":{"uid":1000,"additionalGids":[65532]},"capabilities":{"bounding":["CAP_CHOWN","CAP_NET_RAW","CAP_MKNOD","CAP_SYS_ADMIN"],"effective":["CAP_CHOWN","CAP_NET_RAW"],"permitted":["CAP_CHOWN","CAP_NET_RAW"],"ambient":["CAP_NET_RAW"]},"rlimits":[{"type":"RLIMIT_NOFILE","hard":65536,"soft":65536}]},"mounts":[{"source":"/volume","destination":"/data"}],"root":{"path":"rootfs"},"linux":{"seccomp":{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["read","write"],"action":"SCMP_ACT_ALLOW"}]},"namespaces":[{"type":"pid"},{"type":"network"}],"devices":[{"path":"/dev/dri/renderD128"}],"resources":{"memory":{"limit":4294967296},"cpu":{"quota":200000},"devices":[{"allow":true,"type":"c","major":226,"minor":128,"access":"rw"}]}},"annotations":{"keep":"yes"}}`)
	updated, err := hardenedContainerSpec(original)
	if err != nil {
		t.Fatal(err)
	}
	var before, after map[string]any
	json.Unmarshal(original, &before)
	json.Unmarshal(updated, &after)
	for _, field := range []string{"mounts", "root", "annotations"} {
		if !reflect.DeepEqual(before[field], after[field]) {
			t.Fatalf("security upgrade changed %s", field)
		}
	}
	bp, ap := before["process"].(map[string]any), after["process"].(map[string]any)
	for _, field := range []string{"args", "cwd", "env", "user"} {
		if !reflect.DeepEqual(bp[field], ap[field]) {
			t.Fatalf("security upgrade changed process %s", field)
		}
	}
	if ap["noNewPrivileges"] != true {
		t.Fatal("privilege escalation remains enabled")
	}
	if strings.Contains(string(updated), "CAP_NET_RAW") || strings.Contains(string(updated), "CAP_SYS_ADMIN") || strings.Contains(string(updated), "CAP_MKNOD") {
		t.Fatal("dangerous capabilities survived")
	}
	if !reflect.DeepEqual(ap["capabilities"].(map[string]any)["bounding"], []any{"CAP_CHOWN"}) {
		t.Fatal("upgrade added or lost safe capabilities")
	}
	bl, al := before["linux"].(map[string]any), after["linux"].(map[string]any)
	for _, field := range []string{"devices", "seccomp"} {
		if !reflect.DeepEqual(bl[field], al[field]) {
			t.Fatalf("security upgrade changed Linux %s", field)
		}
	}
	resources := al["resources"].(map[string]any)
	if resources["pids"].(map[string]any)["limit"] != float64(4096) || resources["memory"].(map[string]any)["swap"] != float64(4294967296) {
		t.Fatal("task or swap budget was not enforced")
	}
	if al["sysctl"].(map[string]any)["net.ipv4.ping_group_range"] != "0 2147483647" {
		t.Fatal("unprivileged ping diagnostics were not retained")
	}
	again, err := hardenedContainerSpec(updated)
	if err != nil || string(again) != string(updated) {
		t.Fatal("security upgrade is not idempotent", err)
	}
}

func TestSavedSecurityUpgradeFailsClosedForUnconfinedSpecifications(t *testing.T) {
	for _, spec := range []string{`null`, `{}`, `{"process":{},"linux":{}}`, `{"process":{},"linux":{"seccomp":{"defaultAction":"SCMP_ACT_ALLOW"}}}`, `{"process":{},"linux":{"seccomp":{"defaultAction":"SCMP_ACT_LOG"}}}`} {
		if _, err := hardenedContainerSpec([]byte(spec)); err == nil {
			t.Fatalf("accepted unconfined or malformed specification %s", spec)
		}
	}
	spec := []byte(`{"process":{},"linux":{"seccomp":{"defaultAction":"SCMP_ACT_ERRNO"},"resources":{"pids":{"limit":128}}}}`)
	updated, err := hardenedContainerSpec(spec)
	if err != nil || !strings.Contains(string(updated), `"limit":128`) {
		t.Fatal("a stricter process limit was relaxed", err)
	}
}

func TestContainerResourcesRejectNonFiniteAndOutOfRangeCPU(t *testing.T) {
	for _, cpus := range []float64{math.NaN(), math.Inf(1), math.Inf(-1), -1, 0, 0.001, 256} {
		if validContainerResources(cpus, 1<<30) {
			t.Fatalf("accepted invalid CPUs %v", cpus)
		}
	}
	if !validContainerResources(0.15, 64<<20) || validContainerResources(1, 63<<20) {
		t.Fatal("incorrect resource allocation bounds")
	}
}
