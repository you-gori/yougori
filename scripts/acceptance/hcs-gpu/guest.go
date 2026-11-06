// A disposable HCS GPU-PV feasibility guest, not the production sandbox agent.
// It accepts no commands, paths or code from the host. Its only workload is the
// repository's fixed CUDA kernel probe. Results leave over one Hyper-V socket.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const port = 49151

func read(path string) string {
	b, _ := os.ReadFile(path)
	return strings.TrimSpace(string(b))
}

func probe() error {
	if os.Getpid() != 1 {
		return fmt.Errorf("this probe must be the init process of its own VM")
	}
	for _, m := range []struct{ path, kind string }{{"/proc", "proc"}, {"/sys", "sysfs"}, {"/dev", "devtmpfs"}} {
		if err := unix.Mount(m.kind, m.path, m.kind, unix.MS_NOSUID, ""); err != nil {
			return err
		}
	}
	if err := os.MkdirAll("/dev/shm", 01777); err != nil {
		return err
	}
	if err := unix.Mount("tmpfs", "/dev/shm", "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=1777,size=64m"); err != nil {
		return err
	}
	if err := unix.Chmod("/tmp", 01777); err != nil {
		return err
	}
	_ = unix.Sethostname([]byte("yougori-gpu-vm-probe"))
	var fd int
	var err error
	for deadline := time.Now().Add(60 * time.Second); time.Now().Before(deadline); {
		fd, err = unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err == nil {
			err = unix.Connect(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_HOST, Port: port})
			if err == nil {
				break
			}
			_ = unix.Close(fd)
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), "host-result-channel")
	defer f.Close()
	var request struct {
		Nonce string `json:"nonce"`
		GPU   bool   `json:"gpu"`
	}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024), 4096)
	if !scanner.Scan() || json.Unmarshal(scanner.Bytes(), &request) != nil || len(request.Nonce) != 64 {
		return fmt.Errorf("invalid fixed probe request")
	}
	result := map[string]any{"nonce": request.Nonce, "bootId": read("/proc/sys/kernel/random/boot_id"), "kernel": read("/proc/sys/kernel/osrelease"), "mounts": read("/proc/mounts"), "gpuRequested": request.GPU}
	var names []string
	entries, _ := os.ReadDir("/sys/class/net")
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	result["networkInterfaces"] = names
	if request.GPU {
		for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); {
			if _, err = os.Stat("/dev/dxg"); err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	_, dxgErr := os.Stat("/dev/dxg")
	result["dxg"] = dxgErr == nil
	if dxgErr == nil {
		// Device belongs only to this disposable guest. Run CUDA without root.
		if err = os.Chmod("/dev/dxg", 0666); err != nil {
			return err
		}
	}
	{
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "/usr/bin/strace", "-f", "-s", "160", "-o", "/tmp/cuda-trace", "/cuda-probe")
		cmd.Env = []string{"PATH=/bin", "LD_LIBRARY_PATH=/usr/lib/wsl/lib"}
		output, runErr := cmd.CombinedOutput()
		if len(output) > 16384 {
			output = output[:16384]
		}
		result["cudaOutput"] = string(output)
		result["cudaPassed"] = runErr == nil && strings.Contains(string(output), "CUDA KERNEL PASS:") && strings.Contains(string(output), "uid=65534")
		if runErr != nil {
			result["cudaError"] = runErr.Error()
			diagnostic, _ := exec.Command("/bin/busybox", "dmesg").Output()
			if len(diagnostic) > 16384 {
				diagnostic = diagnostic[len(diagnostic)-16384:]
			}
			result["kernelLogTail"] = string(diagnostic)
			trace, _ := os.ReadFile("/tmp/cuda-trace")
			if len(trace) > 24576 {
				trace = trace[len(trace)-24576:]
			}
			result["cudaTraceTail"] = string(trace)
		}
	}
	return json.NewEncoder(f).Encode(result)
}

func main() {
	if err := probe(); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	_ = unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF)
	for {
		time.Sleep(time.Hour)
	}
}
