package main

import (
	"encoding/json"
	"strings"
	"testing"
)

const oldDriver = "/usr/lib/wsl/drivers/nvlti.inf_amd64_aaaa1111"
const newDriver = "/usr/lib/wsl/drivers/nvlti.inf_amd64_bbbb2222"

func gpuSpec(driver string, major, minor int) []byte {
	spec := map[string]any{
		"process": map[string]any{"args": []string{"sh"}},
		"mounts": []map[string]any{
			{"source": driver + "/libcuda.so.1.1", "destination": driver + "/libcuda.so.1.1"},
			{"source": "/data", "destination": "/models"},
		},
		"hooks": map[string]any{"createContainer": []map[string]any{{"path": "/usr/local/bin/nvidia-cdi-hook",
			"args": []string{"nvidia-cdi-hook", "create-symlinks", "--link", driver + "/nvidia-smi::/usr/bin/nvidia-smi"}}}},
		"linux": map[string]any{
			"devices":   []map[string]any{{"path": "/dev/dxg", "type": "c", "major": major, "minor": minor}},
			"resources": map[string]any{"devices": []map[string]any{{"allow": false, "access": "rwm"}, {"allow": true, "type": "c", "major": major, "minor": minor, "access": "rwm"}}},
		},
	}
	encoded, _ := json.Marshal(spec)
	return encoded
}

func TestGPUSandboxesFollowAWindowsDriverUpdate(t *testing.T) {
	cdi := []byte("hostPath: " + newDriver + "/libcuda.so.1.1\n  - --folder\n  - " + newDriver + "\n")
	all := func(string) bool { return true }
	updated, err := currentGPUDriver(gpuSpec(oldDriver, 10, 258), cdi, all)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(updated), oldDriver) || strings.Count(string(updated), newDriver) != 3 {
		t.Fatalf("mounts and hooks must name the current driver: %s", updated)
	}
	same, err := currentGPUDriver(gpuSpec(newDriver, 10, 258), cdi, all)
	if err != nil || string(same) != string(gpuSpec(newDriver, 10, 258)) {
		t.Fatalf("an up-to-date spec is left as it was: %v", err)
	}
	if _, err := currentGPUDriver(gpuSpec(oldDriver, 10, 258), cdi, func(path string) bool { return !strings.HasSuffix(path, "libcuda.so.1.1") }); err == nil || !strings.Contains(err.Error(), "save them") {
		t.Fatalf("a driver file missing from the new driver needs the settings saved again: %v", err)
	}
	two := append(append([]byte{}, cdi...), []byte(" /usr/lib/wsl/drivers/nvlti.inf_amd64_cccc3333/x\n")...)
	if kept, err := currentGPUDriver(gpuSpec(oldDriver, 10, 258), two, all); err != nil || !strings.Contains(string(kept), oldDriver) {
		t.Fatalf("two current folders of one package are not guessed between: %v", err)
	}
	if other, err := currentGPUDriver([]byte(`{"mounts":[]}`), cdi, all); err != nil || string(other) != `{"mounts":[]}` {
		t.Fatalf("a container without the driver is untouched: %v", err)
	}
}

func TestDxgKeepsItsCurrentDeviceNumbers(t *testing.T) {
	updated, err := currentDxg(gpuSpec(newDriver, 10, 258), 10, 61)
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Linux struct {
			Devices   []struct{ Major, Minor int64 } `json:"devices"`
			Resources struct {
				Devices []struct {
					Allow        bool
					Major, Minor *int64
				} `json:"devices"`
			} `json:"resources"`
		} `json:"linux"`
	}
	if err := json.Unmarshal(updated, &spec); err != nil {
		t.Fatal(err)
	}
	if spec.Linux.Devices[0].Major != 10 || spec.Linux.Devices[0].Minor != 61 {
		t.Fatalf("device: %+v", spec.Linux.Devices)
	}
	rule := spec.Linux.Resources.Devices[1]
	if !rule.Allow || *rule.Minor != 61 || spec.Linux.Resources.Devices[0].Major != nil {
		t.Fatalf("access rules: %s", updated)
	}
	unchanged := gpuSpec(newDriver, 10, 258)
	if same, err := currentDxg(unchanged, 10, 258); err != nil || string(same) != string(unchanged) {
		t.Fatalf("unchanged numbers leave the spec as it was: %v", err)
	}
}
