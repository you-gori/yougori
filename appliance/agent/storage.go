package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func (s *server) growStorage(w http.ResponseWriter, r *http.Request) {
	if s.microVM {
		writeError(w, http.StatusConflict, "container storage cannot resize a microVM")
		return
	}
	unlock := s.locks.lock("storage-quotas")
	defer unlock()
	if err := growBundledRoot(); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ready": true})
}

// Only the bundled, whole-device ext4 root is eligible. Never guess partitions
// or operate on host shares, custom filesystems, or an arbitrary client path.
func growBundledRoot() error {
	mounts, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return err
	}
	eligible := false
	for _, line := range strings.Split(string(mounts), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "/dev/vda" && fields[1] == "/" && fields[2] == "ext4" {
			eligible = true
		}
	}
	if !eligible {
		return nil
	}
	device, err := os.Open("/dev/vda")
	if err != nil {
		return err
	}
	superblock := make([]byte, 1024)
	_, err = device.ReadAt(superblock, 1024)
	device.Close()
	if err != nil {
		return err
	}
	filesystemBytes, err := ext4Capacity(superblock)
	if err != nil {
		return err
	}
	size, err := os.ReadFile("/sys/class/block/vda/size")
	if err != nil {
		return err
	}
	sectors, err := strconv.ParseUint(strings.TrimSpace(string(size)), 10, 64)
	if err != nil || sectors > (1<<54) {
		return errors.New("invalid root disk capacity")
	}
	if sectors*512 <= filesystemBytes {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "resize2fs", "/dev/vda")
	const tools = "/usr/local/lib/yougori-storage"
	if _, err := os.Stat(tools + "/ld-musl-x86_64.so.1"); err == nil {
		command = exec.CommandContext(ctx, tools+"/ld-musl-x86_64.so.1", "--library-path", tools, tools+"/resize2fs", "/dev/vda")
	}
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("expand root filesystem: %w: %s", err, output)
	}
	return nil
}

func ext4Capacity(sb []byte) (uint64, error) {
	if len(sb) < 1024 || binary.LittleEndian.Uint16(sb[0x38:]) != 0xef53 {
		return 0, errors.New("root disk is not ext4")
	}
	shift := binary.LittleEndian.Uint32(sb[0x18:])
	if shift > 6 {
		return 0, errors.New("invalid ext4 block size")
	}
	blocks := uint64(binary.LittleEndian.Uint32(sb[4:]))
	if binary.LittleEndian.Uint32(sb[0x60:])&0x80 != 0 {
		blocks |= uint64(binary.LittleEndian.Uint32(sb[0x150:])) << 32
	}
	blockSize := uint64(1024) << shift
	if blocks == 0 || blocks > ^uint64(0)/blockSize {
		return 0, errors.New("invalid ext4 capacity")
	}
	return blocks * blockSize, nil
}
