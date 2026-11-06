package main

// HCS uses a private Hyper-V socket instead of a virtio serial device. Open it
// before confinement, then keep the same authenticated link and file protocol.
// Workloads still cannot open AF_VSOCK sockets after the seccomp filter is set.
import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"yougori.local/appliance-agent/link"
)

const hcsLinkPort = 49151
const hcsBootMax = 1 << 20

var hcsGPUEnabled bool
var hcsBootstrapPort *virtioPort

// A bounded startup report precedes the normal authenticated link. The host
// cannot report a ready VM until its real guest setup and confinement succeeded.
func reportHcsBoot(problem error) error {
	if hcsBootstrapPort == nil {
		return nil
	}
	port := hcsBootstrapPort
	hcsBootstrapPort = nil
	report := struct {
		Ready bool   `json:"ready"`
		Error string `json:"error,omitempty"`
	}{Ready: problem == nil}
	if problem != nil {
		report.Error = problem.Error()
		if len(report.Error) > 4096 {
			report.Error = report.Error[:4096]
		}
	}
	data, err := json.Marshal(report)
	if err != nil {
		return err
	}
	timeout := unix.NsecToTimeval((5 * time.Second).Nanoseconds())
	if err = unix.SetsockoptTimeval(port.fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &timeout); err != nil {
		return err
	}
	if err = binary.Write(port, binary.BigEndian, uint32(len(data))); err != nil {
		return err
	}
	if _, err = port.Write(data); err != nil {
		return err
	}
	return unix.SetsockoptTimeval(port.fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &unix.Timeval{})
}

type hcsBoot struct {
	Version   int             `json:"version"`
	Bootstrap []byte          `json:"bootstrap"`
	Endpoints string          `json:"endpoints"`
	Workload  json.RawMessage `json:"workload"`
	GPU       bool            `json:"gpu"`
	Network   *internetConfig `json:"network,omitempty"`
}

func decodeHcsBoot(r io.Reader) (*hcsBoot, error) {
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	if length == 0 || length > hcsBootMax {
		return nil, fmt.Errorf("HCS bootstrap length refused: %d", length)
	}
	raw := make([]byte, length)
	if _, err := io.ReadFull(r, raw); err != nil {
		return nil, err
	}
	defer clear(raw)
	var boot hcsBoot
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&boot); err != nil {
		return nil, err
	}
	if d.Decode(new(any)) != io.EOF {
		return nil, fmt.Errorf("trailing HCS bootstrap data")
	}
	if boot.Version != 1 {
		return nil, fmt.Errorf("unsupported HCS bootstrap version")
	}
	return &boot, nil
}

func openHcsPort() (*virtioPort, *hcsBoot, error) {
	deadline := time.Now().Add(hostConnectTimeout)
	for time.Now().Before(deadline) {
		fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return nil, nil, err
		}
		err = unix.Connect(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_HOST, Port: hcsLinkPort})
		if err == nil {
			p := &virtioPort{fd: fd}
			timeout := unix.NsecToTimeval((30 * time.Second).Nanoseconds())
			if err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
				unix.Close(fd)
				return nil, nil, err
			}
			boot, err := decodeHcsBoot(p)
			if err != nil {
				unix.Close(fd)
				return nil, nil, err
			}
			if err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{}); err != nil {
				unix.Close(fd)
				return nil, nil, err
			}
			hcsBootstrapPort = p
			return p, boot, nil
		}
		unix.Close(fd)
		time.Sleep(100 * time.Millisecond)
	}
	return nil, nil, fmt.Errorf("HCS host did not open this VM's private link")
}

func mountHcsRoot() error {
	image, err := os.Open("/root.img")
	if err != nil {
		return err
	}
	defer image.Close()
	if err = unix.Mknod("/dev/loop0", unix.S_IFBLK|0600, int(unix.Mkdev(7, 0))); err != nil && !os.IsExist(err) {
		return err
	}
	loop, err := os.OpenFile("/dev/loop0", os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer loop.Close()
	if err = unix.IoctlSetInt(int(loop.Fd()), unix.LOOP_SET_FD, int(image.Fd())); err != nil {
		return err
	}
	if err = unix.IoctlLoopSetStatus64(int(loop.Fd()), &unix.LoopInfo64{Flags: unix.LO_FLAGS_READ_ONLY | unix.LO_FLAGS_AUTOCLEAR}); err != nil {
		return err
	}
	return unix.Mount("/dev/loop0", newRoot, rootFilesystem, unix.MS_RDONLY|unix.MS_NODEV|unix.MS_NOSUID, "")
}

func bindReadOnly(source, target string) error {
	if err := unix.Mount(source, target, "", unix.MS_BIND, ""); err != nil {
		return err
	}
	return unix.Mount("", target, "", unix.MS_REMOUNT|unix.MS_BIND|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV, "")
}

func mountHcsGPU() error {
	for _, path := range []string{"usr/lib/wsl", "lib/x86_64-linux-gnu", "lib64", "opt/yougori-gpu"} {
		if err := bindReadOnly(filepath.Join("/gpu", path), filepath.Join(newRoot, path)); err != nil {
			return fmt.Errorf("GPU runtime %s: %w", path, err)
		}
	}
	if err := waitForPath("/dev/dxg", deviceTimeout); err != nil {
		return err
	}
	if err := os.Chown("/dev/dxg", 0, 1000); err != nil {
		return err
	}
	if err := os.Chmod("/dev/dxg", 0660); err != nil {
		return err
	}
	hcsGPUEnabled = true
	return nil
}

func hcsGPUEnvironment(env []string) []string {
	if !hcsGPUEnabled {
		return env
	}
	result := make([]string, 0, len(env)+1)
	libPath := "LD_LIBRARY_PATH=/usr/lib/wsl/lib"
	for _, entry := range env {
		if strings.HasPrefix(entry, "LD_LIBRARY_PATH=") {
			libPath += ":" + strings.TrimPrefix(entry, "LD_LIBRARY_PATH=")
			continue
		}
		if strings.HasPrefix(entry, "PATH=") {
			entry += ":/opt/yougori-gpu"
		}
		result = append(result, entry)
	}
	return append(result, libPath)
}

func bindImageGPU(root string) error {
	if !hcsGPUEnabled {
		return nil
	}
	// An OCI application keeps its own glibc. Only the matching GPU driver and
	// tools are mounted; never overwrite the image's C runtime.
	for _, path := range []string{"usr/lib/wsl", "opt/yougori-gpu"} {
		target, err := imageDirectory(root, path)
		if err != nil {
			return err
		}
		if err := bindReadOnly("/"+path, target); err != nil {
			return err
		}
	}
	dev, err := imageDirectory(root, "dev")
	if err != nil {
		return err
	}
	target := filepath.Join(dev, "dxg")
	f, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return unix.Mount("/dev/dxg", target, "", unix.MS_BIND, "")
}

func hcsDeclarations(boot *hcsBoot) (*link.Bootstrap, []link.EgressEndpoint, *workloadImage, error) {
	bootstrap, err := link.ParseBootstrap(boot.Bootstrap)
	clear(boot.Bootstrap)
	if err != nil {
		return nil, nil, nil, err
	}
	endpoints, err := link.ParseEgressEndpoints([]byte(boot.Endpoints))
	if err != nil {
		return nil, nil, nil, err
	}
	var workload *workloadImage
	if len(boot.Workload) != 0 && string(boot.Workload) != "null" {
		workload, err = parseWorkload(boot.Workload)
	}
	return bootstrap, endpoints, workload, err
}
