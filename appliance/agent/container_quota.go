package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	containers "github.com/containerd/containerd/api/services/containers/v1"
	snapshots "github.com/containerd/containerd/api/services/snapshots/v1"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

const containerQuotaDirectory = dataRoot + "/container-quotas"
const defaultContainerStorage = uint64(20 << 30)

type containerStorageRequest struct {
	ID         string `json:"id"`
	LimitBytes uint64 `json:"limitBytes"`
}
type containerQuota struct {
	Version     int    `json:"version"`
	ID          string `json:"id"`
	ContainerID string `json:"containerId"`
	Project     uint32 `json:"project"`
	Limit       uint64 `json:"limit"`
	Complete    bool   `json:"complete"`
	Retired     bool   `json:"retired,omitempty"`
}
type containerStorageInfo struct {
	LimitBytes uint64 `json:"limitBytes"`
	UsedBytes  uint64 `json:"usedBytes"`
	Enforced   bool   `json:"enforced"`
}

// Linux's project quota ABI uses 1 KiB units for limits and bytes for usage.
// Project IDs are unrelated to the UID inside a container.
type diskQuota struct {
	BlockHard, BlockSoft, CurrentSpace  uint64
	InodeHard, InodeSoft, CurrentInodes uint64
	BlockTime, InodeTime                uint64
	Valid, Pad                          uint32
}
type projectAttributes struct {
	Flags, ExtentSize, Extents, Project, CowExtentSize uint32
	Pad                                                [8]byte
}

func kernelProjectQuota(device string, project uint32, limit *uint64) (diskQuota, error) {
	var quota diskQuota
	if project == 0 {
		return quota, errors.New("the runtime's unassigned storage cannot be limited")
	}
	name, err := unix.BytePtrFromString(device)
	if err != nil {
		return quota, err
	}
	command := uintptr((0x800007 << 8) | 2) // Q_GETQUOTA, PRJQUOTA
	if limit != nil {
		quota.BlockHard = (*limit + 1023) / 1024
		quota.Valid = 1               // QIF_BLIMITS; never overwrite usage or another limit.
		command = (0x800008 << 8) | 2 // Q_SETQUOTA, PRJQUOTA
	}
	_, _, errno := unix.Syscall6(unix.SYS_QUOTACTL, command, uintptr(unsafe.Pointer(name)), uintptr(project), uintptr(unsafe.Pointer(&quota)), 0, 0)
	if errno != 0 {
		return quota, fmt.Errorf("enforce container storage quota: %w", errno)
	}
	return quota, nil
}

func fileProject(path string, requested *uint32, directory, reassign bool) (uint32, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	var attrs projectAttributes
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), 0x801c581f, uintptr(unsafe.Pointer(&attrs))) // FS_IOC_FSGETXATTR
	if errno != 0 {
		return 0, errno
	}
	if requested != nil {
		if attrs.Project != 0 && attrs.Project != *requested && !reassign {
			return attrs.Project, errors.New("this storage already belongs to another container")
		}
		attrs.Project = *requested
		if directory {
			attrs.Flags |= 0x200 // FS_XFLAG_PROJINHERIT
		}
		_, _, errno = unix.Syscall(unix.SYS_IOCTL, uintptr(fd), 0x401c5820, uintptr(unsafe.Pointer(&attrs))) // FS_IOC_FSSETXATTR
		if errno != 0 {
			return 0, errno
		}
	}
	return attrs.Project, nil
}

// Assign directories before reading their children, so new files inherit the
// project. Initial adoption is allowed only while that container is stopped.
func assignContainerProject(roots []string, project uint32) error {
	return assignProject(roots, project, false)
}

func assignProject(roots []string, project uint32, reassign bool) error {
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if !entry.IsDir() && !entry.Type().IsRegular() {
				return nil // Never follow a guest symlink or open a FIFO/device.
			}
			_, err := fileProject(path, &project, entry.IsDir(), reassign)
			return err
		})
		if err != nil {
			return fmt.Errorf("assign private container storage: %w", err)
		}
	}
	return nil
}

// Folders a container can write outside its writable layer, such as its app
// display socket directory and connection shares, belong to the agent rather
// than to another container. Charge them to the owning environment's project,
// whatever project a file currently has, so they cannot fill shared storage.
func chargeOwnedStorage(directory, ownerID string) error {
	if _, err := os.Lstat(directory); os.IsNotExist(err) {
		return nil
	}
	config, err := loadContainerQuota(ownerID)
	if os.IsNotExist(err) {
		return nil // The owner has no individual storage limit yet.
	}
	if err != nil {
		return err
	}
	if !config.Complete || config.Retired {
		return nil
	}
	if err := requireContainerStorePath(directory); err != nil {
		return err
	}
	return assignProject([]string{directory}, config.Project, true)
}

type inspectedStorageContainer struct {
	ID    string `json:"Id"`
	State struct{ Running, Paused bool }
}

func privateContainerStorage(ctx context.Context, id string) (inspectedStorageContainer, []string, error) {
	var inspected []inspectedStorageContainer
	output, err := run(ctx, "nerdctl", "--namespace", namespace, "inspect", id)
	if err != nil {
		return inspectedStorageContainer{}, nil, err
	}
	if err := json.Unmarshal([]byte(output.Stdout), &inspected); err != nil || len(inspected) != 1 || len(inspected[0].ID) != 64 || strings.Trim(inspected[0].ID, "0123456789abcdef") != "" {
		return inspectedStorageContainer{}, nil, errors.New("cannot identify the container's private storage")
	}
	container := inspected[0]
	connection, err := grpc.NewClient("unix://"+containerdSocket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return container, nil, err
	}
	defer connection.Close()
	ctx = metadata.AppendToOutgoingContext(ctx, "containerd-namespace", namespace)
	current, err := containers.NewContainersClient(connection).Get(ctx, &containers.GetContainerRequest{ID: container.ID})
	if err != nil {
		return container, nil, err
	}
	config := current.GetContainer()
	if config.GetSnapshotter() != "overlayfs" || config.GetSnapshotKey() == "" {
		return container, nil, errors.New("this container's snapshotter does not support independent storage limits")
	}
	mounts, err := snapshots.NewSnapshotsClient(connection).Mounts(ctx, &snapshots.MountsRequest{Snapshotter: config.Snapshotter, Key: config.SnapshotKey})
	if err != nil {
		return container, nil, err
	}
	var roots []string
	for _, mount := range mounts.Mounts {
		for _, option := range mount.Options {
			key, path, ok := strings.Cut(option, "=")
			if ok && (key == "upperdir" || key == "workdir") {
				if !strings.HasPrefix(path, "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/") {
					return container, nil, errors.New("container writable storage is outside the managed snapshot directory")
				}
				roots = append(roots, path)
			}
		}
	}
	if len(roots) != 2 {
		return container, nil, errors.New("container writable layer is unavailable")
	}
	var spec struct {
		Mounts []struct{ Source, Type string }
	}
	if config.GetSpec() == nil || json.Unmarshal(config.Spec.Value, &spec) != nil {
		return container, nil, errors.New("cannot read private container volumes")
	}
	for _, mount := range spec.Mounts {
		// Image-declared anonymous volumes are private storage too. Explicit
		// host shares and node connections retain their own storage accounting.
		// nerdctl may express a bind as type "none" with an rbind option.
		// Identify its owned volume path rather than assuming type "bind".
		if isPrivateContainerVolume(mount.Source) {
			roots = append(roots, mount.Source)
		}
	}
	logs, err := filepath.Glob("/var/lib/nerdctl/*/containers/" + namespace + "/" + container.ID)
	if err != nil {
		return container, nil, err
	}
	roots = append(roots, logs...)
	for _, root := range roots {
		if filepath.Clean(root) != root {
			return container, nil, errors.New("private storage path is not canonical")
		}
		resolved, err := filepath.EvalSymlinks(root)
		if err != nil || resolved != root {
			return container, nil, errors.New("private storage path was redirected")
		}
		if err := requireContainerStorePath(root); err != nil {
			return container, nil, err
		}
	}
	return container, roots, nil
}

func isPrivateContainerVolume(path string) bool {
	if filepath.Clean(path) != path {
		return false
	}
	matched, _ := filepath.Match("/var/lib/nerdctl/*/volumes/"+namespace+"/*/_data", path)
	return matched
}

func loadContainerQuota(id string) (containerQuota, error) {
	var value containerQuota
	bytes, err := os.ReadFile(filepath.Join(containerQuotaDirectory, id+".json"))
	if err != nil {
		return value, err
	}
	if len(bytes) > 4096 || json.Unmarshal(bytes, &value) != nil || value.Version != 1 || value.ID != id || value.Project == 0 || value.Limit < 1<<30 || value.Limit > 16384<<30 {
		return value, errors.New("saved container storage allocation is invalid")
	}
	return value, nil
}

func newContainerQuota(id string, limit uint64) (containerQuota, error) {
	if err := os.MkdirAll(containerQuotaDirectory, 0700); err != nil {
		return containerQuota{}, err
	}
	entries, err := os.ReadDir(containerQuotaDirectory)
	if err != nil {
		return containerQuota{}, err
	}
	used := map[uint32]bool{0: true}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			other, err := loadContainerQuota(strings.TrimSuffix(entry.Name(), ".json"))
			if err != nil {
				return containerQuota{}, err
			}
			used[other.Project] = true
		}
	}
	digest := sha256.Sum256([]byte(id))
	project := binary.LittleEndian.Uint32(digest[:4]) & math.MaxInt32
	for used[project] {
		project = (project + 1) & math.MaxInt32
	}
	return containerQuota{Version: 1, ID: id, Project: project, Limit: limit}, nil
}

func (s *server) containerStorage(w http.ResponseWriter, r *http.Request) {
	var request containerStorageRequest
	if !decodeRequest(w, r, &request) || !requireID(w, request.ID) {
		return
	}
	if request.LimitBytes != 0 && (request.LimitBytes < 1<<30 || request.LimitBytes > 16384<<30 || request.LimitBytes%(1<<30) != 0) {
		writeError(w, http.StatusBadRequest, "storage must be a whole number between 1 and 16384 GB")
		return
	}
	unlock := s.locks.lock("storage-quotas", containerLockKey(request.ID))
	defer unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	info, err := configureContainerStorage(ctx, request.ID, request.LimitBytes, true)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func configureContainerStorage(ctx context.Context, id string, limit uint64, allowReduction bool) (containerStorageInfo, error) {
	var result containerStorageInfo
	device, err := containerStoreDevice()
	if err != nil {
		return result, err
	}
	container, roots, err := privateContainerStorage(ctx, id)
	if err != nil {
		return result, err
	}
	config, err := loadContainerQuota(id)
	if err != nil && !os.IsNotExist(err) {
		return result, err
	}
	if os.IsNotExist(err) {
		used, err := allocatedStorageBytes(roots)
		if err != nil {
			return result, err
		}
		suggested := max(defaultContainerStorage, (used/(1<<30)+1)*(1<<30))
		if limit == 0 {
			return containerStorageInfo{LimitBytes: suggested, UsedBytes: used}, nil
		}
		config, err = newContainerQuota(id, limit)
		if err != nil {
			return result, err
		}
	}
	if config.ContainerID != container.ID {
		config.Complete = false
	}
	if limit != 0 {
		if !config.Complete && (container.State.Running || container.State.Paused) {
			return result, errors.New("stop this container once to enable its individual storage limit")
		}
		// Lifecycle/configuration replay preserves the current limit. Only an
		// explicit storage edit may reduce it, after checking real quota usage.
		var quota diskQuota
		if config.Complete {
			quota, err = kernelProjectQuota(device, config.Project, nil)
			if err != nil {
				return result, err
			}
		}
		if !allowReduction {
			limit = max(limit, config.Limit, quota.BlockHard*1024)
		}
		used := quota.CurrentSpace
		if !config.Complete {
			used, err = allocatedStorageBytes(roots)
			if err != nil {
				return result, err
			}
		}
		if used >= limit && (!config.Complete || limit != quota.BlockHard*1024) {
			return result, fmt.Errorf("this container already uses %.2f GB; choose a storage limit above its current usage", float64(used)/(1<<30))
		}
		if err := ensureQuotaStoreCapacity(ctx, id, limit); err != nil {
			return result, err
		}
		if _, err := kernelProjectQuota(device, config.Project, &limit); err != nil {
			return result, err
		}
		config.Limit = limit
		config.ContainerID = container.ID
		config.Retired = false
		if err := writeStorageJSON(filepath.Join(containerQuotaDirectory, id+".json"), config); err != nil {
			return result, err
		}
		if !config.Complete {
			if err := assignContainerProject(roots, config.Project); err != nil {
				return result, err
			}
			config.Complete = true
			if err := writeStorageJSON(filepath.Join(containerQuotaDirectory, id+".json"), config); err != nil {
				return result, err
			}
		}
	}
	// Charge the display socket directory while the container cannot write
	// to it. Existing limits adopt it at their next stopped start.
	if config.Complete && !container.State.Running && !container.State.Paused {
		if err := chargeOwnedStorage(containerDisplayDirectory(id), id); err != nil {
			log.Printf("limit display storage for %s: %v", id, err)
		}
	}
	quota, err := kernelProjectQuota(device, config.Project, nil)
	if err != nil {
		return result, err
	}
	if !config.Complete {
		used, err := allocatedStorageBytes(roots)
		if err != nil {
			return result, err
		}
		return containerStorageInfo{LimitBytes: max(config.Limit, quota.BlockHard*1024), UsedBytes: used}, nil
	}
	return containerStorageInfo{LimitBytes: quota.BlockHard * 1024, UsedBytes: quota.CurrentSpace, Enforced: quota.BlockHard != 0}, nil
}

func ensureQuotaStoreCapacity(ctx context.Context, id string, limit uint64) error {
	entries, err := os.ReadDir(containerQuotaDirectory)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	minimum := limit + (4 << 30)
	if minimum > 16384<<30 {
		return errors.New("container storage limit exceeds available runtime capacity")
	}
	device, err := containerStoreDevice()
	if err != nil {
		return err
	}
	var assigned uint64
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		otherID := strings.TrimSuffix(entry.Name(), ".json")
		other, err := loadContainerQuota(otherID)
		if err != nil {
			return err
		}
		if other.Retired {
			continue
		}
		quota, err := kernelProjectQuota(device, other.Project, nil)
		if err != nil {
			return err
		}
		assigned += quota.CurrentSpace
		if otherID == id {
			continue
		}
		if other.Limit > (16384<<30)-minimum {
			return errors.New("the combined storage limits exceed the supported runtime capacity")
		}
		minimum += other.Limit
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(containerStoreMount, &fs); err != nil {
		return err
	}
	used := (fs.Blocks - fs.Bfree) * uint64(fs.Bsize)
	// Read-only images, snapshots and filesystem metadata need headroom too;
	// they must not silently consume capacity promised to writable quotas.
	if used > assigned {
		extra := used - assigned
		if extra > (16384<<30)-minimum {
			return errors.New("cached runtime data exceeds available filesystem capacity")
		}
		minimum += extra
	}
	return growContainerStore(ctx, minimum)
}

func (s *server) retireContainerStorage(id string) error {
	unlock := s.locks.lock("storage-quotas")
	defer unlock()
	config, err := loadContainerQuota(id)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	config.Retired = true
	// Keep the project ID reserved until any deferred snapshot cleanup has
	// released it. Deleted nodes no longer contribute to runtime capacity.
	return writeStorageJSON(filepath.Join(containerQuotaDirectory, id+".json"), config)
}

// Call with this container's lifecycle lock already held. The storage lock
// sorts after lifecycle/image locks and is never held during an image pull.
func (s *server) ensureContainerStorage(ctx context.Context, id string, limit uint64) error {
	unlock := s.locks.lock("storage-quotas")
	defer unlock()
	if limit == 0 {
		info, err := configureContainerStorage(ctx, id, 0, false)
		if err != nil {
			return err
		}
		if info.Enforced {
			return nil
		}
		limit = info.LimitBytes
	}
	_, err := configureContainerStorage(ctx, id, limit, false)
	return err
}

func allocatedStorageBytes(roots []string) (uint64, error) {
	seen := make(map[[2]uint64]bool)
	var total uint64
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			stat := info.Sys().(*syscall.Stat_t)
			key := [2]uint64{uint64(stat.Dev), stat.Ino}
			if !seen[key] {
				seen[key] = true
				total += uint64(stat.Blocks) * 512
			}
			return nil
		})
		if err != nil {
			return 0, err
		}
	}
	return total, nil
}
