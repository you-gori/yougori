package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

type memoryRange struct {
	Start uint64 `json:"start"`
	Size  uint64 `json:"size"`
}

// Verify the actual DIMM address ranges, not MemTotal: the latter excludes
// kernel reservations whose size grows with the amount of installed RAM.
func memoryRangesOnline(root string, ranges []memoryRange) (bool, error) {
	if len(ranges) == 0 {
		return true, nil
	}
	if len(ranges) > 64 {
		return false, fmt.Errorf("too many memory ranges")
	}
	data, err := os.ReadFile(filepath.Join(root, "block_size_bytes"))
	if err != nil {
		return false, err
	}
	block, err := strconv.ParseUint(strings.TrimSpace(string(data)), 16, 64)
	if err != nil || block == 0 {
		return false, fmt.Errorf("invalid memory block size")
	}
	var checked uint64
	for _, region := range ranges {
		if region.Size == 0 || region.Start > ^uint64(0)-region.Size || region.Start%block != 0 || region.Size%block != 0 {
			return false, fmt.Errorf("invalid hotplug memory range")
		}
		checked += region.Size / block
		if checked > 65536 {
			return false, fmt.Errorf("memory range is too large")
		}
		for address := region.Start; address < region.Start+region.Size; address += block {
			value, err := os.ReadFile(filepath.Join(root, fmt.Sprintf("memory%d", address/block), "online"))
			if os.IsNotExist(err) {
				return false, nil
			} // ACPI has not registered it yet.
			if err != nil {
				return false, err
			}
			if strings.TrimSpace(string(value)) != "1" {
				return false, nil
			}
		}
	}
	return true, nil
}

// Only the private QEMU appliance owns these memory devices. CUDA's WSL
// kernel is shared with other distributions and must not be changed here.
func (s *server) systemCapacity(w http.ResponseWriter, r *http.Request) {
	if s.microVM || os.Getenv("YOUGORI_CUDA_MODE") == "1" {
		writeError(w, http.StatusConflict, "live capacity growth is only available for the standard container runtime")
		return
	}
	var request struct {
		MemoryRanges []memoryRange `json:"memoryRanges"`
	}
	if !decodeRequest(w, r, &request) {
		return
	}
	entries, err := filepath.Glob("/sys/devices/system/memory/memory[0-9]*/online")
	if err == nil {
		for _, path := range entries {
			value, readErr := os.ReadFile(path)
			if readErr != nil {
				continue
			}
			if strings.TrimSpace(string(value)) == "0" {
				if err = os.WriteFile(path, []byte("1"), 0600); err != nil {
					break
				}
			}
		}
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "bring runtime memory online: "+err.Error())
		return
	}
	info, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	memory, err := capacityMemoryBytes(string(info))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	ready, err := memoryRangesOnline("/sys/devices/system/memory", request.MemoryRanges)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "verify runtime memory: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cpuCount": runtime.NumCPU(), "memoryBytes": memory, "memoryRangesOnline": ready})
}

func capacityMemoryBytes(info string) (uint64, error) {
	for _, line := range strings.Split(info, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "MemTotal:" && fields[2] == "kB" {
			value, err := strconv.ParseUint(fields[1], 10, 64)
			if err == nil && value > 0 && value <= ^uint64(0)/1024 {
				return value * 1024, nil
			}
		}
	}
	return 0, fmt.Errorf("runtime memory capacity is unavailable")
}
