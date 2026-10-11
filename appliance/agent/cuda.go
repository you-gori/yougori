package main

// CUDA is an opt-in, dedicated WSL 2 runtime, separate from QEMU graphics.
import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func cudaMode() bool { return os.Getenv("YOUGORI_CUDA_MODE") == "1" }

func cudaCapacity() (int, uint64) {
	var info syscall.Sysinfo_t
	if syscall.Sysinfo(&info) != nil {
		return 0, 0
	}
	return runtime.NumCPU(), info.Totalram * uint64(info.Unit)
}

// Do not detach a WSL disk while a container can still be writing to it.
// On failure keep the agent alive so the host can report/retry shutdown.
func shutdownCUDAContainers() error {
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	listed, err := run(ctx, "nerdctl", "--namespace", namespace, "ps", "--quiet")
	if err != nil {
		return err
	}
	ids := strings.Fields(listed.Stdout)
	if len(ids) != 0 {
		if _, err := run(ctx, "nerdctl", append([]string{"--namespace", namespace, "stop", "--time", "15"}, ids...)...); err != nil {
			return fmt.Errorf("stop CUDA containers: %w", err)
		}
	}
	_, err = run(ctx, "sync")
	if err != nil {
		log.Printf("CUDA shutdown sync: %v", err)
	}
	return err
}

func initializeAgentStorage() error {
	if cudaMode() {
		return nil
	}
	return growBundledRoot()
}

func cudaBootConfiguration() (bootConfiguration, error) {
	token := os.Getenv("YOUGORI_CUDA_TOKEN")
	if _, err := hex.DecodeString(token); err != nil || len(token) != 64 {
		return bootConfiguration{}, fmt.Errorf("invalid CUDA runtime token")
	}
	if _, err := os.Stat("/etc/yougori-cuda-runtime"); err != nil {
		return bootConfiguration{}, fmt.Errorf("not a Yougori CUDA distribution")
	}
	return bootConfiguration{token: token}, nil
}

func agentListenAddress() (string, error) {
	if !cudaMode() {
		return listenAddress, nil
	}
	address := os.Getenv("YOUGORI_CUDA_LISTEN")
	host, port, err := net.SplitHostPort(address)
	n, parseError := strconv.Atoi(port)
	if err != nil || parseError != nil || host != "127.0.0.1" || n < 1024 || n > 65535 {
		return "", fmt.Errorf("CUDA agent must listen on an unprivileged IPv4 loopback port")
	}
	return address, nil
}

func cudaDeviceArguments(enabled bool) ([]string, error) {
	// Override requests embedded in CUDA images. runc remains the default;
	// only explicit CDI injection grants a container the driver and devices.
	args := []string{"--env", "NVIDIA_VISIBLE_DEVICES=void", "--mount", "type=bind,src=/usr/local/sbin/yougori-cuda-probe,dst=/yougori/bin/cuda-check,ro"}
	if !enabled {
		return args, nil
	}
	if info, err := os.Stat("/dev/dxg"); err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return nil, fmt.Errorf("WSL GPU bridge unavailable; update the Windows NVIDIA driver and WSL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := run(ctx, "nvidia-ctk", "cdi", "list")
	if err != nil {
		return nil, fmt.Errorf("NVIDIA container device setup failed: %w", err)
	}
	for _, device := range strings.Fields(output.Stdout) {
		if device == "nvidia.com/gpu=all" {
			return append(args, "--device", device), nil
		}
	}
	return nil, fmt.Errorf("no NVIDIA CUDA devices available; restart the CUDA runtime after updating your Windows driver")
}

func (s *server) verifyCUDA(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ID string `json:"id"`
	}
	if !decodeRequest(w, r, &request) || !requireID(w, request.ID) {
		return
	}
	if !cudaMode() {
		writeError(w, 400, "This engine provides graphics, not native CUDA. Use the NVIDIA CUDA container engine.")
		return
	}
	unlock := s.locks.lock(containerLockKey(request.ID))
	defer unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if _, err := containerPID(ctx, request.ID); err != nil {
		writeError(w, 409, "Start the CUDA container before testing its GPU.")
		return
	}
	output, err := runAllowExit(ctx, "nerdctl", "--namespace", namespace, "exec", "--user", "65534:65534", request.ID, "/yougori/bin/cuda-check")
	if err != nil {
		writeError(w, 500, "Could not run the CUDA check: "+err.Error())
		return
	}
	writeJSON(w, 200, output)
}
