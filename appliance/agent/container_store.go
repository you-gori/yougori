package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const containerStoreRoot = "/var/lib/yougori-container-storage"
const containerStoreMount = containerStoreRoot + "/mount"
const containerStoreImage = containerStoreRoot + "/data.ext4"

var containerStoreTrees = []string{"containerd", "nerdctl", "yougori"}

type containerStoreState struct {
	Version  int    `json:"version"`
	Identity string `json:"identity"`
	Stage    string `json:"stage"`
}

func writeStorageJSON(path string, value any) error {
	bytes, err := json.Marshal(value)
	if err != nil {
		return err
	}
	parent := filepath.Dir(path)
	file, err := os.CreateTemp(parent, ".storage-state-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err = file.Write(bytes); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(parent)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func readContainerStoreState() (containerStoreState, error) {
	var state containerStoreState
	bytes, err := os.ReadFile(containerStoreRoot + "/state.json")
	if err != nil {
		return state, err
	}
	if len(bytes) > 4096 || json.Unmarshal(bytes, &state) != nil || state.Version != 1 || len(state.Identity) != 64 || strings.Trim(state.Identity, "0123456789abcdef") != "" {
		return state, errors.New("container storage ownership record is invalid; existing files were kept")
	}
	if state.Stage != "copying" && state.Stage != "prepared" && state.Stage != "installed" {
		return state, errors.New("container storage migration state is invalid")
	}
	return state, nil
}

func storageMountDevice(path string) (string, error) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		left, right, ok := strings.Cut(line, " - ")
		fields, details := strings.Fields(left), strings.Fields(right)
		if ok && len(fields) >= 5 && fields[4] == path && len(details) >= 2 {
			if details[0] != "ext4" {
				return "", errors.New("managed container storage has an unexpected filesystem")
			}
			return details[1], nil
		}
	}
	return "", os.ErrNotExist
}

func containerStoreDevice() (string, error) {
	state, err := readContainerStoreState()
	if err != nil || state.Stage != "installed" {
		return "", errors.New("individual storage limits need a container runtime update; existing files were kept")
	}
	return ownedContainerStoreDevice(state)
}

func ownedContainerStoreDevice(state containerStoreState) (string, error) {
	device, err := containerStoreLoopDevice()
	if err != nil {
		return "", err
	}
	identity, err := os.ReadFile(containerStoreMount + "/.yougori-storage-identity")
	if err != nil || string(identity) != state.Identity {
		return "", errors.New("container storage identity does not match its image")
	}
	return device, nil
}

func containerStoreLoopDevice() (string, error) {
	device, err := storageMountDevice(containerStoreMount)
	if err != nil || !strings.HasPrefix(device, "/dev/loop") || device == "/dev/loop" || strings.Trim(strings.TrimPrefix(device, "/dev/loop"), "0123456789") != "" {
		return "", errors.New("the owned container storage filesystem is not mounted")
	}
	backing, err := os.ReadFile("/sys/class/block/" + filepath.Base(device) + "/loop/backing_file")
	if err != nil || strings.TrimSpace(string(backing)) != containerStoreImage {
		return "", errors.New("container storage is attached to a different image")
	}
	return device, nil
}

func enableContainerStoreDirectIO() error {
	device, err := containerStoreLoopDevice()
	if err != nil {
		return err
	}
	file, err := os.OpenFile(device, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	// A loop image must bypass the outer page cache. Otherwise WSL can charge
	// both copies of dirty data to a small container and OOM during a large
	// write, even though reclaimable cache and disk space remain available.
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, file.Fd(), 0x4c08, 1) // LOOP_SET_DIRECT_IO
	if errno != 0 {
		return fmt.Errorf("enable bounded-memory container storage I/O: %w", errno)
	}
	return nil
}

func requireContainerStorePath(path string) error {
	if _, err := containerStoreDevice(); err != nil {
		return err
	}
	var root, entry unix.Stat_t
	if err := unix.Stat(containerStoreMount, &root); err != nil {
		return err
	}
	if err := unix.Stat(path, &entry); err != nil {
		return err
	}
	if root.Dev != entry.Dev {
		return errors.New("this container still uses legacy storage; restart the updated runtime to preserve and migrate it")
	}
	return nil
}

func containerStorageTool(ctx context.Context, name string, args ...string) error {
	if name != "mkfs.ext4" && name != "resize2fs" {
		return errors.New("unsupported container filesystem operation")
	}
	command := exec.CommandContext(ctx, name, args...)
	const tools = "/usr/local/lib/yougori-storage"
	if name == "resize2fs" {
		if _, err := os.Stat(tools + "/ld-musl-x86_64.so.1"); err == nil {
			command = exec.CommandContext(ctx, tools+"/ld-musl-x86_64.so.1", append([]string{"--library-path", tools, tools + "/" + name}, args...)...)
		}
	}
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s for container storage: %w: %s", name, err, output)
	}
	return nil
}

func mountContainerStore(ctx context.Context, state containerStoreState) error {
	info, err := os.Lstat(containerStoreImage)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("the container storage image is missing or redirected")
	}
	resolved, err := filepath.EvalSymlinks(containerStoreImage)
	if err != nil || resolved != containerStoreImage {
		return errors.New("the container storage image path was redirected")
	}
	if _, err := storageMountDevice(containerStoreMount); err == nil {
		_, err = ownedContainerStoreDevice(state)
		if err != nil {
			return err
		}
		return enableContainerStoreDirectIO()
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(containerStoreMount, 0700); err != nil {
		return err
	}
	entries, err := os.ReadDir(containerStoreMount)
	if err != nil || len(entries) != 0 {
		return errors.New("container storage mount directory is not empty")
	}
	output, err := exec.CommandContext(ctx, "mount", "-t", "ext4", "-o", "loop,prjquota,discard,noatime", containerStoreImage, containerStoreMount).CombinedOutput()
	if err != nil {
		return fmt.Errorf("mount container storage with enforced limits: %w: %s", err, output)
	}
	return enableContainerStoreDirectIO()
}

func growContainerStore(ctx context.Context, minimum uint64) error {
	device, err := containerStoreDevice()
	if err != nil {
		return err
	}
	image, err := os.OpenFile(containerStoreImage, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer image.Close()
	info, err := image.Stat()
	if err != nil {
		return err
	}
	// The image is sparse. Its virtual size is separate from each enforced
	// container quota and actual free space on the host.
	if minimum > 16384<<30 {
		return errors.New("container storage exceeds the supported filesystem capacity")
	}
	if uint64(info.Size()) < minimum {
		if err := image.Truncate(int64(minimum)); err != nil {
			return err
		}
	}
	superblock := make([]byte, 1024)
	if _, err := image.ReadAt(superblock, 1024); err != nil {
		return err
	}
	capacity, err := ext4Capacity(superblock)
	if err != nil {
		return err
	}
	if capacity >= minimum {
		return nil
	}
	if err := image.Sync(); err != nil {
		return err
	}
	file, err := os.OpenFile(device, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, file.Fd(), 0x4c07, 0) // LOOP_SET_CAPACITY
	file.Close()
	if errno != 0 {
		return errno
	}
	return containerStorageTool(ctx, "resize2fs", device)
}

func syncContainerStore() error {
	file, err := os.Open(containerStoreMount)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := unix.Syncfs(int(file.Fd())); err != nil {
		return err
	}
	image, err := os.Open(containerStoreImage)
	if err != nil {
		return err
	}
	defer image.Close()
	return image.Sync()
}

func containerStoreMountMatches(path, source string) bool {
	var left, right syscall.Stat_t
	return syscall.Stat(path, &left) == nil && syscall.Stat(source, &right) == nil && left.Dev == right.Dev && left.Ino == right.Ino
}

func prepareContainerStore() (err error) {
	log.Print("Yougori storage preparation started")
	defer func() {
		if err != nil {
			log.Printf("Yougori storage preparation failed: %v", err)
		} else {
			log.Print("Yougori storage preparation finished")
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	return prepareContainerStoreContext(ctx)
}
