package main

// PID 1 in the initrd (brief deliverable 4; plan §3.3 "keep PID 1/init small: mount
// verified images, establish the channel, set guest restrictions, spawn the agent/workload
// and reap children"): mount /proc, /sys and /dev, load only the kernel modules the
// profile needs from the pinned kernel's set, mount the root image read-only, switch into
// it, find the link's virtio port by name, read the bootstrap file, unload the fw_cfg
// driver that exposed it, and set no_new_privs for every thread before any workload runs.

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"yougori.local/appliance-agent/link"
)

const (
	// moduleListPath lists, in load order, the module files the build placed in the
	// initrd, relative to /lib/modules/<release>/ (written by scripts/build-guest.sh).
	moduleListPath = "/etc/yougori/modules.load"
	// maxModuleBytes bounds one decompressed module.
	maxModuleBytes = 16 << 20
	newRoot        = "/newroot"
	rootDevice     = "/dev/vda"
	rootFilesystem = "squashfs"
	terminalRoot   = "/run/yougori/terminal"
	cgroupRoot     = "/sys/fs/cgroup"
	// uidProcessLimit is RLIMIT_NPROC for every process the agent starts: all of uid
	// 1000's processes together, beside each terminal's pids.max.
	uidProcessLimit = 512
	linkPortName    = "org.yougori.link"
	virtioPorts     = "/sys/class/virtio-ports"
	fwCfgModule     = "qemu_fw_cfg"
	deviceTimeout   = 10 * time.Second
)

// guest is what the init prepared for the link.
type guest struct {
	port       *virtioPort
	portPath   string
	bootstrap  *link.Bootstrap
	agentBuild link.Digest
	// cgroupRoot holds the terminals' cgroups; empty when cgroup v2 could not be set up,
	// in which case no terminal starts.
	cgroupRoot string
	// endpoints are the egress endpoints the host declared at boot (egress_linux.go).
	endpoints []link.EgressEndpoint
	// image is the OCI image the host declared the sandbox runs (oci_image_linux.go).
	image *workloadImage
}

func setUpGuest(logf func(string, ...any)) (*guest, error) {
	if err := mountEarly(); err != nil {
		return nil, fmt.Errorf("early mounts: %w", err)
	}
	release, err := kernelRelease()
	if err != nil {
		return nil, err
	}
	_, hcsErr := os.Stat("/etc/yougori/hcs")
	hcs := hcsErr == nil
	var hcsPort *virtioPort
	var hcsConfig *hcsBoot
	if hcs {
		hcsPort, hcsConfig, err = openHcsPort()
		if err != nil {
			return nil, err
		}
	} else {
		loaded, err := loadModules(filepath.Join("/lib/modules", release), moduleListPath, initModule)
		if err != nil {
			return nil, fmt.Errorf("modules: %w", err)
		}
		logf("loaded modules: %s", strings.Join(loaded, " "))
	}
	agentBuild, err := contentKeyOfFile("/proc/self/exe")
	if err != nil {
		return nil, fmt.Errorf("agent build digest: %w", err)
	}
	if hcs {
		if err := mountHcsRoot(); err != nil {
			return nil, fmt.Errorf("HCS root: %w", err)
		}
		if hcsConfig.GPU {
			if err := mountHcsGPU(); err != nil {
				return nil, err
			}
		} else if _, err := os.Stat("/dev/dxg"); err == nil {
			if err := os.Chmod("/dev/dxg", 0600); err != nil {
				return nil, err
			}
		}
	} else {
		if err := waitForPath(rootDevice, deviceTimeout); err != nil {
			return nil, err
		}
		if err := unix.Mount(rootDevice, newRoot, rootFilesystem, unix.MS_RDONLY|unix.MS_NODEV|unix.MS_NOSUID, ""); err != nil {
			return nil, fmt.Errorf("mount the root image read-only: %w", err)
		}
	}
	if err := switchRoot(); err != nil {
		return nil, fmt.Errorf("switch root: %w", err)
	}
	if err := unix.Mount("tmpfs", "/run", "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "mode=0755,size=1m"); err != nil {
		return nil, fmt.Errorf("mount /run: %w", err)
	}
	if hcs {
		if err := os.MkdirAll("/dev/shm", 0755); err != nil {
			return nil, err
		}
		if err := unix.Mount("tmpfs", "/dev/shm", "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=1777,size=64m"); err != nil {
			return nil, err
		}
		if err := unix.Mount("tmpfs", "/tmp", "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=1777,size=64m"); err != nil {
			return nil, err
		}
	}
	// The loopback interface carries the egress endpoints' listeners; nothing else brings
	// it up in this guest.
	if err := bringUpLoopback(); err != nil {
		return nil, fmt.Errorf("loopback: %w", err)
	}
	if err := os.MkdirAll(terminalRoot, 0o755); err != nil {
		return nil, fmt.Errorf("terminal root: %w", err)
	}
	cgroups := cgroupRoot
	if err := setUpCgroups(); err != nil {
		logf("terminals disabled, no cgroup containment: %v", err)
		cgroups = ""
	}
	if err := unix.Setrlimit(unix.RLIMIT_NPROC, &unix.Rlimit{Cur: uidProcessLimit, Max: uidProcessLimit}); err != nil {
		return nil, fmt.Errorf("RLIMIT_NPROC: %w", err)
	}
	portPath := "hcs-vsock"
	var bootstrap *link.Bootstrap
	var endpoints []link.EgressEndpoint
	var image *workloadImage
	internet := false
	if hcs {
		bootstrap, endpoints, image, err = hcsDeclarations(hcsConfig)
		if err != nil {
			return nil, err
		}
	} else {
		portPath, err = findPort(virtioPorts, linkPortName, deviceTimeout)
		if err != nil {
			return nil, err
		}
		bootstrap, err = link.ReadBootstrap(link.BootstrapPath)
		if err != nil {
			return nil, err
		}
		// The egress endpoints, from the same device: a list the host did not hand over is
		// an empty one (the guest then reaches nothing by name); a refused list is a boot
		// error, so a guest never runs with part of its declaration.
		endpoints, err = link.ReadEgressEndpoints(link.EgressEndpointsPath)
		if err != nil {
			if err != link.ErrNoEndpoints {
				return nil, err
			}
			logf("no egress endpoint list from the host")
		}
		// The workload, from the same device: an OCI image the sandbox runs, or none. A
		// declaration that does not parse is a boot error, so a guest never runs another
		// workload than the one declared.
		image, err = readWorkload(workloadPath)
		if err != nil {
			return nil, err
		}
		if image != nil {
			logf("workload image %s: %d layers, a %d-byte root", image.Manifest, len(image.Layers), image.RootBytes)
		}
		internet, err = readInternetMode(internetModePath)
		if err != nil {
			return nil, err
		}
		// The secret now lives only in this process; the sysfs entry goes with the driver.
		if err := unix.DeleteModule(fwCfgModule, unix.O_NONBLOCK); err != nil {
			logf("fw_cfg driver not unloaded: %v", err)
		}
	}
	if err := installHosts(endpoints); err != nil {
		return nil, fmt.Errorf("hosts: %w", err)
	}
	if hcs {
		internet = hcsConfig.Network != nil
		err = installInternetConfig(hcsConfig.Network)
	} else {
		err = installInternet(internet)
	}
	if err != nil {
		return nil, fmt.Errorf("internet: %w", err)
	}
	logf("egress endpoints: %d; full internet: %v", len(endpoints), internet)
	if err := setNoNewPrivileges(); err != nil {
		return nil, err
	}
	// The strict tool profile's inner confinement for every process from here on
	// (confine_linux.go); a guest never runs with part of it.
	applied, err := confineGuest()
	if err != nil {
		return nil, fmt.Errorf("confinement: %w", err)
	}
	logf("confined: %d capabilities out of the bounding set, yama ptrace_scope 3 %v, seccomp filter of %d instructions, probe %v",
		applied.boundingDropped, applied.yama, applied.filterLength, probeAvailable())
	return &guest{port: hcsPort, portPath: portPath, bootstrap: bootstrap, agentBuild: agentBuild, cgroupRoot: cgroups, endpoints: endpoints, image: image}, nil
}

// setUpCgroups mounts cgroup v2 and enables the pids controller for the terminals'
// cgroups. The files belong to root, so a terminal can neither leave its cgroup nor raise
// its limits.
func setUpCgroups() error {
	if err := unix.Mount("cgroup2", cgroupRoot, "cgroup2", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("mount cgroup2: %w", err)
	}
	if err := os.WriteFile(filepath.Join(cgroupRoot, "cgroup.subtree_control"), []byte("+pids"), 0); err != nil {
		return fmt.Errorf("enable the pids controller: %w", err)
	}
	return nil
}

func mountEarly() error {
	for _, m := range []struct {
		source, target, fstype string
		flags                  uintptr
		data                   string
	}{
		{"proc", "/proc", "proc", unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC, "hidepid=invisible"},
		{"sysfs", "/sys", "sysfs", unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC | unix.MS_RDONLY, ""},
		{"devtmpfs", "/dev", "devtmpfs", unix.MS_NOSUID | unix.MS_NOEXEC, "mode=0755"},
	} {
		if err := unix.Mount(m.source, m.target, m.fstype, m.flags, m.data); err != nil {
			return fmt.Errorf("mount %s: %w", m.target, err)
		}
	}
	return nil
}

func kernelRelease() (string, error) {
	var name unix.Utsname
	if err := unix.Uname(&name); err != nil {
		return "", fmt.Errorf("uname: %w", err)
	}
	return string(bytes.TrimRight(name.Release[:], "\x00")), nil
}

func initModule(image []byte) error {
	err := unix.InitModule(image, "")
	if errors.Is(err, unix.EEXIST) {
		return nil
	}
	return err
}

// loadModules loads, in order, each module the list names under dir. A gzip-compressed
// module is decompressed here (the kernel has no in-kernel module decompression). A line
// that is absolute, climbs out of dir or names anything but a .ko or .ko.gz is refused.
func loadModules(dir, listPath string, load func([]byte) error) ([]string, error) {
	list, err := os.Open(listPath)
	if err != nil {
		return nil, err
	}
	defer list.Close()
	var loaded []string
	scanner := bufio.NewScanner(list)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if filepath.IsAbs(line) || strings.Contains(line, "..") || filepath.Clean(line) != line ||
			!(strings.HasSuffix(line, ".ko") || strings.HasSuffix(line, ".ko.gz")) {
			return loaded, fmt.Errorf("module list entry %q refused", line)
		}
		image, err := readModule(filepath.Join(dir, line))
		if err != nil {
			return loaded, fmt.Errorf("%s: %w", line, err)
		}
		if err := load(image); err != nil {
			return loaded, fmt.Errorf("load %s: %w", line, err)
		}
		loaded = append(loaded, moduleName(line))
	}
	return loaded, scanner.Err()
}

func readModule(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var reader io.Reader = file
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(file)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		reader = gz
	}
	image, err := io.ReadAll(io.LimitReader(reader, maxModuleBytes+1))
	if err != nil {
		return nil, err
	}
	if len(image) > maxModuleBytes {
		return nil, fmt.Errorf("larger than %d bytes", maxModuleBytes)
	}
	return image, nil
}

func moduleName(path string) string {
	base := filepath.Base(path)
	base = strings.TrimSuffix(base, ".gz")
	return strings.TrimSuffix(base, ".ko")
}

// contentKeyDomain is foundation::ids ContentKey::DOMAIN.
const contentKeyDomain = "yougori/content/v1"

// contentKeyOfFile is the content key digest of a file's bytes (ContentKey::of: the
// digest of the bytes as one part under contentKeyDomain), the agent build the Hello
// names and guest_image's AgentFeatures::build holds.
func contentKeyOfFile(path string) (link.Digest, error) {
	file, err := os.Open(path)
	if err != nil {
		return link.Digest{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return link.Digest{}, err
	}
	hash := sha256.New()
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(contentKeyDomain)))
	hash.Write(length[:])
	hash.Write([]byte(contentKeyDomain))
	binary.BigEndian.PutUint64(length[:], uint64(info.Size()))
	hash.Write(length[:])
	copied, err := io.Copy(hash, file)
	if err != nil {
		return link.Digest{}, err
	}
	if copied != info.Size() {
		return link.Digest{}, fmt.Errorf("%s changed while it was read", path)
	}
	var digest link.Digest
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

func waitForPath(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s did not appear within %s", path, timeout)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// switchRoot moves /dev, /proc and /sys under the new root, moves the new root over / and
// enters it, as switch_root does for an initramfs.
func switchRoot() error {
	for _, mount := range []string{"/dev", "/proc", "/sys"} {
		if err := unix.Mount(mount, newRoot+mount, "", unix.MS_MOVE, ""); err != nil {
			return fmt.Errorf("move %s: %w", mount, err)
		}
	}
	if err := os.Chdir(newRoot); err != nil {
		return err
	}
	if err := unix.Mount(newRoot, "/", "", unix.MS_MOVE, ""); err != nil {
		return fmt.Errorf("move the root: %w", err)
	}
	if err := unix.Chroot("."); err != nil {
		return fmt.Errorf("chroot: %w", err)
	}
	return os.Chdir("/")
}

var portDirectory = regexp.MustCompile(`^vport[0-9]+p[0-9]+$`)

// findPort finds the virtio-serial port whose name is name under the sysfs class
// directory and returns its device node.
func findPort(classDir, name string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	for {
		entries, _ := os.ReadDir(classDir)
		for _, entry := range entries {
			if !portDirectory.MatchString(entry.Name()) {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(classDir, entry.Name(), "name"))
			if err == nil && strings.TrimRight(string(raw), "\n") == name {
				return "/dev/" + entry.Name(), nil
			}
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("no virtio port named %s within %s", name, timeout)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// setNoNewPrivileges sets no_new_privs on every thread of the agent, so every process it
// starts inherits it.
func setNoNewPrivileges() error {
	if _, _, errno := syscall.AllThreadsSyscall(syscall.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); errno != 0 {
		return fmt.Errorf("no_new_privs: %w", errno)
	}
	return nil
}

// powerOff ends the guest: every other process is killed, nothing is synced (nothing is
// writable but tmpfs) and the kernel powers off, which QEMU's reboot/shutdown action turns
// into a process exit. PID 1 never returns.
func powerOff() {
	_ = syscall.Kill(-1, syscall.SIGKILL)
	_ = unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF)
	for {
		time.Sleep(time.Hour)
	}
}
