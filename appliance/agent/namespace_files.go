package main

// Resolve configuration inside the pinned workload root. Absolute symlinks
// remain inside that root; procfs magic links cannot reach the appliance.
import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const maxNamespaceConfigBytes = 1024 * 1024

var namespaceConfigLocks keyedLocker

func openNamespaceConfig(root int, name string, flags int) (*os.File, error) {
	if name != "etc/hosts" && name != "etc/resolv.conf" {
		return nil, fmt.Errorf("unsupported environment configuration path")
	}
	fd, err := unix.Openat2(root, name, &unix.OpenHow{
		Flags:   uint64(flags | unix.O_CLOEXEC | unix.O_NONBLOCK),
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxNamespaceConfigBytes {
		file.Close()
		if err == nil {
			err = fmt.Errorf("environment configuration must be a bounded regular file")
		}
		return nil, err
	}
	return file, nil
}

func openContainerConfig(pid int, name string, flags int) (*os.File, error) {
	if pid <= 1 {
		return nil, fmt.Errorf("invalid environment process")
	}
	process, err := unix.Open("/proc/"+strconv.Itoa(pid), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(process)
	root, err := unix.Openat(process, "root", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(root)
	return openNamespaceConfig(root, name, flags)
}

func readNamespaceConfig(file *os.File) ([]byte, error) {
	contents, err := io.ReadAll(io.LimitReader(file, maxNamespaceConfigBytes+1))
	if err == nil && len(contents) > maxNamespaceConfigBytes {
		err = fmt.Errorf("environment configuration exceeds size limit")
	}
	return contents, err
}

func readContainerConfig(pid int, name string) ([]byte, error) {
	file, err := openContainerConfig(pid, name, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readNamespaceConfig(file)
}

func changeHostEntry(pid int, id, entry string) error {
	unlock := namespaceConfigLocks.lock(strconv.Itoa(pid))
	defer unlock()
	file, err := openContainerConfig(pid, "etc/hosts", os.O_RDWR)
	if err != nil {
		if entry == "" && errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer file.Close()
	contents, err := readNamespaceConfig(file)
	if err != nil {
		return err
	}
	marker := "# opendock:" + id
	filtered := make([]string, 0)
	for _, line := range strings.Split(string(contents), "\n") {
		if !strings.HasSuffix(strings.TrimSpace(line), marker) {
			filtered = append(filtered, line)
		}
	}
	updated := strings.Join(filtered, "\n")
	if entry != "" {
		updated = strings.TrimRight(updated, "\n") + "\n" + entry + "\n"
	}
	if len(updated) > maxNamespaceConfigBytes {
		return fmt.Errorf("environment hosts file exceeds size limit")
	}
	// Read and write the same pinned inode, including containerd bind-mounted
	// hosts files, without following a second workload-controlled pathname.
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err = file.Truncate(0); err != nil {
		return err
	}
	_, err = file.WriteString(updated)
	return err
}
