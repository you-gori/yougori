// Command yougori-sandbox-agent is PID 1 of the minimal sandbox guest: it prepares the
// guest (init_linux.go), speaks the guest link over the virtio-serial port
// org.yougori.link (session_linux.go) and powers the guest off when the link is lost,
// closed or shut down; there is no restart loop
// (docs/combined-gpu-memory-and-vm-sandbox-plan.md §3.2 lines 2059–2077, §3.3, §11.1
// step 3 line 2701, VM-W05 and VM-W06 lines 2590–2591; work items M01 and M06, guest
// side). It replaces nothing yet: the appliance agent and its control and boot tokens
// stay until parity.
package main

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"yougori.local/appliance-agent/gridkit"
	"yougori.local/appliance-agent/link"
	"yougori.local/appliance-agent/setupkit"
)

// hostConnectTimeout bounds the wait for the host to connect to the link socket.
const hostConnectTimeout = 60 * time.Second

func main() {
	if len(os.Args) > 1 && os.Args[1] == "setup" {
		if err := setupkit.Run(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "grid" {
		if err := gridkit.Run(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	// The same binary is the confinement probe a terminal runs (probe_linux.go) and the
	// normalizer of a throwaway sandbox (normalize_linux.go).
	if len(os.Args) > 1 && os.Args[1] == probeCommand {
		os.Exit(runProbe(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == normalizeCommand {
		os.Exit(runNormalize(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == ociTreeCommand {
		os.Exit(runOciTree(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == imageFailedCommand {
		os.Exit(runImageFailed(os.Args[2:]))
	}
	if os.Getpid() != 1 {
		fmt.Fprintln(os.Stderr, "yougori-sandbox-agent runs only as PID 1 of the sandbox guest")
		os.Exit(2)
	}
	logger := newKernelLogger()
	if err := run(logger); err != nil {
		logger.Printf("stopping: %v", err)
	}
	logger.Printf("powering off")
	powerOff()
}

func run(logger *log.Logger) error {
	reaper := newReaper()
	prepared, err := setUpGuest(logger.Printf)
	if err != nil {
		_ = reportHcsBoot(err)
		return err
	}
	if err := reportHcsBoot(nil); err != nil {
		return err
	}
	binding := prepared.bootstrap.Binding()
	vm, boot := binding.VM(), binding.Boot()
	port := prepared.port
	if port == nil {
		port, err = openPort(prepared.portPath)
		if err != nil {
			return err
		}
	}
	if err := port.waitForHost(hostConnectTimeout); err != nil {
		return err
	}
	// The endpoint, and with it the handshake timeout, starts when the host is there.
	endpoint, err := link.NewGuestEndpoint(binding, link.DefaultLimits(), link.SystemClock{})
	if err != nil {
		return err
	}
	logger.Printf("link connected on %s; agent build %s, boot %d", prepared.portPath, prepared.agentBuild.Hex(), boot)
	outcome := runSession(sessionConfig{
		endpoint:  endpoint,
		transport: port,
		spawner:   newGuestSpawner(reaper, terminalRoot, prepared.cgroupRoot),
		egress:    prepared.endpoints,
		workspace: true,
		image:     prepared.image,
		hello: link.Hello{
			GuestVersion: link.ProtocolVersion,
			AgentBuild:   prepared.agentBuild,
			ClaimedVM:    &vm,
			ClaimedBoot:  &boot,
		},
		logger: logger,
	})
	logger.Printf("session ended: %s (shutdown %v, transport lost %v)", outcome.cause, outcome.shutdown, outcome.lost)
	return nil
}

// kernelLog writes each message as one record to /dev/kmsg, opened on first use once
// devtmpfs is mounted; until then, and without it, messages are dropped.
type kernelLog struct {
	mu   sync.Mutex
	file *os.File
}

func (k *kernelLog) Write(p []byte) (int, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.file == nil {
		file, err := os.OpenFile("/dev/kmsg", os.O_WRONLY, 0)
		if err != nil {
			return len(p), nil
		}
		k.file = file
	}
	return k.file.Write(append([]byte("<5>yougori-sandbox-agent: "), p...))
}

func newKernelLogger() *log.Logger {
	return log.New(&kernelLog{}, "", 0)
}
