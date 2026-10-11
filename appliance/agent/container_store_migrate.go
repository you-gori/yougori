package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func prepareContainerStoreContext(ctx context.Context) error {
	if _, err := os.Stat("/etc/yougori-cuda-runtime"); err != nil {
		boot, err := readBootConfiguration()
		if err != nil {
			return errors.New("container storage preparation requires a Yougori container runtime")
		}
		// A dedicated microVM already owns its complete persistent root disk.
		// Its OCI runtime must not migrate that disk into the shared-appliance store.
		if boot.microVM {
			return nil
		}
	}
	if err := os.MkdirAll(containerStoreRoot, 0700); err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(containerStoreRoot)
	if err != nil || resolved != containerStoreRoot {
		return errors.New("container storage directory was redirected")
	}
	lock, err := os.OpenFile(containerStoreRoot+"/prepare.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return errors.New("another process is preparing container storage")
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	// Migration occurs before the daemon starts. Never copy live databases or
	// move storage out from under any container, even if the app lost its state.
	if connection, err := net.DialTimeout("unix", containerdSocket, time.Second); err == nil {
		connection.Close()
		return errors.New("containerd is running; its storage was not changed")
	}
	state, err := readContainerStoreState()
	if os.IsNotExist(err) {
		if _, diskErr := os.Lstat(containerStoreImage); !os.IsNotExist(diskErr) {
			return errors.New("unregistered container storage image exists; it was preserved")
		}
		identity := make([]byte, 32)
		if _, err := rand.Read(identity); err != nil {
			return err
		}
		state = containerStoreState{Version: 1, Identity: hex.EncodeToString(identity), Stage: "copying"}
		if err := writeStorageJSON(containerStoreRoot+"/state.json", state); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if state.Stage == "copying" {
		if err := createContainerStore(ctx, state); err != nil {
			return err
		}
		state.Stage = "prepared"
		if err := writeStorageJSON(containerStoreRoot+"/state.json", state); err != nil {
			return err
		}
	}
	if err := mountContainerStore(ctx, state); err != nil {
		return err
	}
	if _, err := ownedContainerStoreDevice(state); err != nil {
		return err
	}
	for _, name := range containerStoreTrees {
		source := filepath.Join("/var/lib", name)
		target := filepath.Join(containerStoreMount, name)
		legacy := filepath.Join(containerStoreRoot, "legacy-"+name)
		if containerStoreMountMatches(source, target) {
			continue
		}
		if state.Stage == "prepared" {
			if _, err := os.Lstat(legacy); os.IsNotExist(err) {
				if err := requireLegacyContainerTree(source); err != nil {
					return err
				}
				if err := os.Rename(source, legacy); err != nil {
					return err
				}
			} else if err != nil {
				return err
			}
		}
		if err := os.MkdirAll(source, 0700); err != nil {
			return err
		}
		if err := requireEmptyStorageDirectory(source); err != nil {
			return err
		}
		if err := unix.Mount(target, source, "", unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("attach private runtime storage: %w", err)
		}
	}
	if err := syncContainerStore(); err != nil {
		return err
	}
	parent, err := os.Open("/var/lib")
	if err != nil {
		return err
	}
	err = parent.Sync()
	parent.Close()
	if err != nil {
		return err
	}
	state.Stage = "installed"
	if err := writeStorageJSON(containerStoreRoot+"/state.json", state); err != nil {
		return err
	}
	// Originals are removed only after every verified copy is mounted and the
	// installation marker is durable. Interrupted cleanup is safe to retry.
	for _, name := range containerStoreTrees {
		if !containerStoreMountMatches(filepath.Join("/var/lib", name), filepath.Join(containerStoreMount, name)) {
			return errors.New("container storage detached before cleanup; recovery copies were kept")
		}
		legacy := filepath.Join(containerStoreRoot, "legacy-"+name)
		if info, err := os.Lstat(legacy); err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("container recovery directory was redirected")
			}
			if err := os.RemoveAll(legacy); err != nil {
				return fmt.Errorf("container storage is ready but its verified migration copy could not be reclaimed: %w", err)
			}
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	if err := trimRootStorage(); err != nil {
		log.Printf("container storage is ready; unused migration blocks can be reclaimed later: %v", err)
	}
	return nil
}

func requireEmptyStorageDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("container storage destination is not an owned directory")
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	// nerdctl creates this empty bookkeeping directory even for commands that
	// cannot reach containerd. Between boots it can therefore appear beneath
	// the unmounted bind destination. Only rmdir this exact empty scaffold:
	// rmdir refuses files, symlinks, mount points and nonempty directories.
	if filepath.Base(path) == "nerdctl" && len(entries) == 1 && entries[0].Name() == "filesystem-ops" {
		if err := unix.Rmdir(filepath.Join(path, "filesystem-ops")); err != nil {
			return fmt.Errorf("unexpected data at %s/filesystem-ops was preserved: %w", path, err)
		}
		entries, err = os.ReadDir(path)
		if err != nil {
			return err
		}
	}
	if len(entries) != 0 {
		return fmt.Errorf("unexpected files exist beside migrated container storage at %s; they were preserved", path)
	}
	return nil
}

func requireLegacyContainerTree(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("legacy container storage is missing or redirected")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return errors.New("legacy container storage path was redirected")
	}
	if _, err := storageMountDevice(path); !os.IsNotExist(err) {
		return errors.New("legacy container storage is still mounted; existing files were kept")
	}
	return nil
}

func createContainerStore(ctx context.Context, state containerStoreState) error {
	var sources []string
	for _, name := range containerStoreTrees {
		path := filepath.Join("/var/lib", name)
		if err := os.MkdirAll(path, 0700); err != nil {
			return err
		}
		if err := requireLegacyContainerTree(path); err != nil {
			return err
		}
		sources = append(sources, path)
	}
	used, err := allocatedStorageBytes(sources)
	if err != nil {
		return err
	}
	// An incomplete copy can be discarded because no original tree was moved.
	// The durable 'prepared' state is written only after copy verification.
	if device, err := storageMountDevice(containerStoreMount); err == nil {
		if !strings.HasPrefix(device, "/dev/loop") {
			return errors.New("unexpected mount at the container storage staging directory")
		}
		backing, err := os.ReadFile("/sys/class/block/" + filepath.Base(device) + "/loop/backing_file")
		if err != nil || strings.TrimSpace(string(backing)) != containerStoreImage {
			return errors.New("the staging mount belongs to another image")
		}
		if err := unix.Unmount(containerStoreMount, 0); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if info, err := os.Lstat(containerStoreImage); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("container storage image was redirected")
		}
		if err := os.Remove(containerStoreImage); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	var free unix.Statfs_t
	if err := unix.Statfs(containerStoreRoot, &free); err != nil {
		return err
	}
	if free.Bavail*uint64(free.Bsize) < used+(1<<30) {
		return fmt.Errorf("preparing independent storage needs %.1f GB of temporary runtime space to preserve existing files", float64(used+(1<<30))/(1<<30))
	}
	image, err := os.OpenFile(containerStoreImage, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	size := max(uint64(64<<30), ((used*2+(8<<30))/(1<<30)+1)*(1<<30))
	err = image.Truncate(int64(size))
	image.Close()
	if err != nil {
		return err
	}
	if err := containerStorageTool(ctx, "mkfs.ext4", "-q", "-F", "-m", "0", "-O", "project,quota", "-E", "quotatype=prjquota,lazy_itable_init=1,lazy_journal_init=1", containerStoreImage); err != nil {
		return err
	}
	if err := mountContainerStore(ctx, state); err != nil {
		return err
	}
	if err := os.WriteFile(containerStoreMount+"/.yougori-storage-identity", []byte(state.Identity), 0600); err != nil {
		return err
	}
	for _, name := range containerStoreTrees {
		if err := copyContainerStorage(ctx, filepath.Join("/var/lib", name), filepath.Join(containerStoreMount, name)); err != nil {
			return fmt.Errorf("preserve existing %s storage: %w", name, err)
		}
	}
	return syncContainerStore()
}
