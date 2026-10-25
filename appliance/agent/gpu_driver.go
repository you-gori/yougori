package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"golang.org/x/sys/unix"
)

// In WSL the Windows NVIDIA driver is a folder /usr/lib/wsl/drivers/<package>_<hash> whose name
// changes with every driver update. A GPU container keeps the paths of the driver it was created
// with (its CDI devices are applied at create), so after an update it would no longer start, or
// would load the old driver's libraries. Before each start the paths follow the driver the
// runtime found this time (its CDI spec), and /dev/dxg keeps its current device numbers.

const (
	wslDrivers = "/usr/lib/wsl/drivers/"
	cdiSpec    = "/run/cdi/nvidia.yaml"
)

var wslDriverFolder = regexp.MustCompile(`/usr/lib/wsl/drivers/([A-Za-z0-9_.-]+)`)

const driverChanged = "the Windows NVIDIA driver changed since this sandbox was created, and its new files could not be matched. Open the sandbox's settings and save them to refresh its GPU access"

// driverPackage is a driver folder's name without its hash: nvlti.inf_amd64_ for
// nvlti.inf_amd64_bfa81f62470581d3.
func driverPackage(folder string) string {
	at := strings.LastIndex(folder, "_")
	if at <= 0 {
		return ""
	}
	return folder[:at+1]
}

// currentGPUDriver points the spec's driver folders at the current ones listed in `cdi`, one per
// driver package. Every driver path it then names must exist; otherwise the files of the new
// driver differ and the container must be configured again.
func currentGPUDriver(spec, cdi []byte, exists func(string) bool) ([]byte, error) {
	current := map[string]string{}
	ambiguous := map[string]bool{}
	for _, match := range wslDriverFolder.FindAllSubmatch(cdi, -1) {
		folder := string(match[1])
		pkg := driverPackage(folder)
		if pkg == "" {
			continue
		}
		if seen, ok := current[pkg]; ok && seen != folder {
			ambiguous[pkg] = true
		}
		current[pkg] = folder
	}
	changed := false
	updated := wslDriverFolder.ReplaceAllFunc(spec, func(path []byte) []byte {
		folder := string(path[len(wslDrivers):])
		pkg := driverPackage(folder)
		if now, ok := current[pkg]; ok && !ambiguous[pkg] && now != folder {
			changed = true
			return []byte(wslDrivers + now)
		}
		return path
	})
	if !changed {
		return spec, nil
	}
	var parsed struct {
		Mounts []struct {
			Source string `json:"source"`
		} `json:"mounts"`
	}
	if json.Unmarshal(updated, &parsed) != nil {
		return nil, fmt.Errorf("cannot read the container's GPU configuration")
	}
	for _, mount := range parsed.Mounts {
		if strings.HasPrefix(mount.Source, wslDrivers) && !exists(mount.Source) {
			return nil, fmt.Errorf("%s", driverChanged)
		}
	}
	return updated, nil
}

// currentDxg gives /dev/dxg its current device numbers in the spec's devices and in its device
// access rules. A spec without /dev/dxg is returned as it was.
func currentDxg(spec []byte, major, minor int64) ([]byte, error) {
	var root map[string]json.RawMessage
	if json.Unmarshal(spec, &root) != nil {
		return nil, fmt.Errorf("cannot read the container's GPU configuration")
	}
	var linux map[string]json.RawMessage
	if json.Unmarshal(root["linux"], &linux) != nil || linux == nil {
		return spec, nil
	}
	var devices []map[string]json.RawMessage
	if raw := linux["devices"]; len(raw) == 0 || json.Unmarshal(raw, &devices) != nil {
		return spec, nil
	}
	number := func(raw json.RawMessage) int64 {
		var value int64
		_ = json.Unmarshal(raw, &value)
		return value
	}
	oldMajor, oldMinor, found := int64(0), int64(0), false
	for _, device := range devices {
		var path string
		if json.Unmarshal(device["path"], &path) == nil && path == "/dev/dxg" {
			oldMajor, oldMinor, found = number(device["major"]), number(device["minor"]), true
			device["major"], device["minor"] = json.RawMessage(fmt.Sprint(major)), json.RawMessage(fmt.Sprint(minor))
		}
	}
	if !found || (oldMajor == major && oldMinor == minor) {
		return spec, nil
	}
	encoded, err := json.Marshal(devices)
	if err != nil {
		return nil, err
	}
	linux["devices"] = encoded
	var resources map[string]json.RawMessage
	if json.Unmarshal(linux["resources"], &resources) == nil && resources != nil {
		var rules []map[string]json.RawMessage
		if json.Unmarshal(resources["devices"], &rules) == nil {
			for _, rule := range rules {
				if number(rule["major"]) == oldMajor && number(rule["minor"]) == oldMinor {
					rule["major"], rule["minor"] = json.RawMessage(fmt.Sprint(major)), json.RawMessage(fmt.Sprint(minor))
				}
			}
			if resources["devices"], err = json.Marshal(rules); err != nil {
				return nil, err
			}
			if linux["resources"], err = json.Marshal(resources); err != nil {
				return nil, err
			}
		}
	}
	if root["linux"], err = json.Marshal(linux); err != nil {
		return nil, err
	}
	return json.Marshal(root)
}

// refreshGPUAccess applies both to a GPU container's spec in the GPU runtime. Other containers,
// and a runtime without the NVIDIA spec, are left as they are.
func refreshGPUAccess(spec []byte) ([]byte, error) {
	if !cudaMode() || !strings.Contains(string(spec), wslDrivers) {
		return spec, nil
	}
	cdi, err := os.ReadFile(cdiSpec)
	if err != nil {
		return spec, nil
	}
	updated, err := currentGPUDriver(spec, cdi, func(path string) bool {
		_, err := os.Stat(path)
		return err == nil
	})
	if err != nil {
		return nil, err
	}
	var info unix.Stat_t
	if unix.Stat("/dev/dxg", &info) != nil {
		return updated, nil
	}
	return currentDxg(updated, int64(unix.Major(uint64(info.Rdev))), int64(unix.Minor(uint64(info.Rdev))))
}
