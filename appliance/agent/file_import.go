package main

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// Only ordinary files and directories enter a fresh, private destination.
// Links, devices, traversal, repeated entries and truncated streams fail closed.
func unpackImport(reader io.Reader, destination string) (int64, error) {
	root, err := unix.Open(destination, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(root)
	return unpackImportOwned(reader, root, os.Getuid(), os.Getgid())
}

func unpackImportOwned(reader io.Reader, root, uid, gid int) (int64, error) {
	return unpackImportProgress(context.Background(), reader, root, uid, gid, nil)
}
func unpackImportProgress(ctx context.Context, reader io.Reader, root, uid, gid int, progress func(int64)) (int64, error) {
	stream := &importArchiveReader{reader: reader}
	archive := tar.NewReader(stream)
	var size int64
	for {
		if err := ctx.Err(); err != nil {
			return size, err
		}
		stream.beginHeader()
		header, err := archive.Next()
		stream.trackingHeader = false
		if err == io.EOF {
			// archive/tar also returns EOF after orphan PAX/GNU metadata. Count
			// actual zero header blocks, never metadata payload or file padding.
			if !stream.terminated {
				return size, fmt.Errorf("copy archive is missing its complete terminator")
			}
			// Consume the entire declared HTTP body before acknowledging it.
			// Extra tar record padding is allowed, but a second archive or junk
			// after the terminator is an ambiguous, invalid transfer.
			return size, finishImportArchive(ctx, stream)
		}
		if err != nil {
			return size, err
		}
		name := strings.TrimSuffix(header.Name, "/")
		if name == "" || name == "." || name == ".." || strings.HasPrefix(name, "../") || path.IsAbs(name) || path.Clean(name) != name || strings.ContainsAny(name, "\\\x00:") || strings.Count(name, "/") > 128 {
			return size, fmt.Errorf("invalid or repeated import path")
		}
		if header.Typeflag != tar.TypeDir && header.Typeflag != tar.TypeReg {
			return size, fmt.Errorf("only files and folders can be copied")
		}
		if header.Size < 0 || header.Size > math.MaxInt64-size {
			return size, fmt.Errorf("copy exceeds the filesystem's supported size")
		}
		parent, err := importParent(root, path.Dir(name))
		if err != nil {
			return size, fmt.Errorf("missing or invalid import parent")
		}
		// Exclusive creation rejects repeated entries on disk without retaining
		// a growing map of every filename in the agent's memory.
		if header.Typeflag == tar.TypeDir {
			// Give the destination owner access, but never widen group/other
			// visibility (for example a private .ssh directory must stay private).
			err := unix.Mkdirat(parent, path.Base(name), 0700|uint32(header.Mode)&0055)
			if err == nil {
				child, openErr := unix.Openat(parent, path.Base(name), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
				err = openErr
				if err == nil {
					err = unix.Fchown(child, uid, gid)
					unix.Close(child)
				}
			}
			unix.Close(parent)
			if err != nil {
				return size, err
			}
			continue
		}
		// Preserve private source files while continuing to strip special bits
		// and group/other writes. The importing owner can read and edit the copy.
		mode := os.FileMode(0600) | os.FileMode(header.Mode)&0155
		fd, err := unix.Openat(parent, path.Base(name), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(mode))
		unix.Close(parent)
		if err != nil {
			return size, err
		}
		file := os.NewFile(uintptr(fd), name)
		if err := unix.Fchown(fd, uid, gid); err != nil {
			file.Close()
			return size, err
		}
		n, copyErr := io.CopyN(importWriter{ctx, file, progress}, archive, header.Size)
		if copyErr == nil {
			copyErr = file.Sync()
		}
		closeErr := file.Close()
		size += n
		if copyErr != nil {
			return size, copyErr
		}
		if closeErr != nil {
			return size, closeErr
		}
	}
}

type importArchiveReader struct {
	reader         io.Reader
	read           int64
	trackingHeader bool
	padding        int64
	metadata       int64
	block          [512]byte
	blockBytes     int
	zeroHeaders    int
	terminated     bool
}

func (reader *importArchiveReader) Read(p []byte) (int, error) {
	n, err := reader.reader.Read(p)
	if reader.trackingHeader {
		reader.observeHeaders(p[:n])
	}
	reader.read += int64(n)
	return n, err
}

func (reader *importArchiveReader) beginHeader() {
	reader.trackingHeader = true
	reader.padding = (512 - reader.read%512) % 512
	reader.metadata = 0
	reader.blockBytes = 0
	reader.zeroHeaders = 0
	reader.terminated = false
}

// Next hides extended headers and consumes their payloads internally. Observe
// only its aligned header records; zero-filled long-name data is not an EOF.
func (reader *importArchiveReader) observeHeaders(data []byte) {
	for len(data) > 0 && !reader.terminated {
		if reader.padding > 0 || reader.metadata > 0 {
			remaining := &reader.padding
			if *remaining == 0 {
				remaining = &reader.metadata
			}
			n := int64(len(data))
			if n > *remaining {
				n = *remaining
			}
			*remaining -= n
			data = data[n:]
			continue
		}
		n := copy(reader.block[reader.blockBytes:], data)
		reader.blockBytes += n
		data = data[n:]
		if reader.blockBytes != len(reader.block) {
			continue
		}
		reader.blockBytes = 0
		zero := true
		for _, value := range reader.block {
			if value != 0 {
				zero = false
				break
			}
		}
		if zero {
			reader.zeroHeaders++
			reader.terminated = reader.zeroHeaders == 2
			continue
		}
		reader.zeroHeaders = 0
		switch reader.block[156] {
		case tar.TypeXHeader, tar.TypeXGlobalHeader, tar.TypeGNULongName, tar.TypeGNULongLink:
			size, valid := importMetadataSize(reader.block[124:136])
			if !valid || size > math.MaxInt64-511 {
				reader.trackingHeader = false
				return
			}
			reader.metadata = (size + 511) / 512 * 512
		}
	}
}

func importMetadataSize(field []byte) (int64, bool) {
	if field[0]&0x80 == 0 {
		value := strings.Trim(string(field), " \x00")
		if value == "" {
			return 0, true
		}
		size, err := strconv.ParseInt(value, 8, 64)
		return size, err == nil && size >= 0
	}
	// GNU's base-256 positive numeric fields; negative sizes are invalid.
	if field[0]&0x40 != 0 {
		return 0, false
	}
	var size int64
	for index, value := range field {
		if index == 0 {
			value &= 0x7f
		}
		if size > (math.MaxInt64-int64(value))/256 {
			return 0, false
		}
		size = size*256 + int64(value)
	}
	return size, true
}

func finishImportArchive(ctx context.Context, reader io.Reader) error {
	var padding [32 * 1024]byte
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := reader.Read(padding[:])
		for _, value := range padding[:n] {
			if value != 0 {
				return fmt.Errorf("copy archive has unexpected trailing data")
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// Resolve every ancestor relative to verified directory descriptors. A link
// swapped into a parent path cannot redirect this copy to another filesystem.
func importParent(root int, name string) (int, error) {
	fd, err := unix.Openat(root, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil || name == "." {
		return fd, err
	}
	for _, part := range strings.Split(name, "/") {
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if err != nil {
			return -1, err
		}
		fd = next
	}
	return fd, nil
}

func (s *server) importFiles(w http.ResponseWriter, r *http.Request) {
	id, transfer := r.URL.Query().Get("id"), r.URL.Query().Get("transfer")
	folder := r.URL.Query().Get("folder")
	if !requireID(w, id) {
		return
	}
	if len(transfer) != 32 || strings.Trim(transfer, "0123456789abcdef") != "" {
		writeError(w, 400, "invalid file copy request")
		return
	}
	unlock := s.locks.lock(containerLockKey(id))
	var release sync.Once
	defer release.Do(unlock)
	ctx, state, finish, err := s.beginImport(r.Context(), id, transfer, r.Body, importIdleTimeout)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	defer finish()
	guestRoot := "/"
	uid, gid := 0, 0
	process, err := s.filesProcess(ctx, id)
	if err != nil {
		writeError(w, 409, "Start this environment before copying files")
		return
	}
	if process != "" {
		var stat unix.Stat_t
		if err := unix.Stat(process, &stat); err != nil {
			writeError(w, 500, err.Error())
			return
		}
		uid, gid = int(stat.Uid), int(stat.Gid)
		// This is a kernel-provided process-root link, assembled only from the
		// verified task PID. All subsequent lookup uses anchored descriptors.
		guestRoot = process + "/root"
	}
	root, err := unix.Open(guestRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		writeError(w, 409, "The guest filesystem is unavailable")
		return
	}
	defer unix.Close(root)
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(root, &filesystem); err != nil || (filesystem.Type != unix.EXT4_SUPER_MAGIC && filesystem.Type != unix.OVERLAYFS_SUPER_MAGIC) {
		writeError(w, 409, "Copy requires the environment's own disk, not a mounted shared folder")
		return
	}
	parent := root
	if folder != "" {
		name, err := remoteName(strings.TrimPrefix(folder, "/"))
		if err != nil || !strings.HasPrefix(folder, "/") || name == "." {
			writeError(w, 400, "Choose a specific guest folder for this copy")
			return
		}
		parent, err = remoteOpen(root, name, unix.O_RDONLY|unix.O_DIRECTORY, 0)
		if err != nil {
			writeError(w, 409, "The selected shared folder is unavailable")
			return
		}
		defer unix.Close(parent)
		var selectedFilesystem unix.Statfs_t
		if err := unix.Fstatfs(parent, &selectedFilesystem); err != nil || (selectedFilesystem.Type != unix.EXT4_SUPER_MAGIC && selectedFilesystem.Type != unix.OVERLAYFS_SUPER_MAGIC) {
			writeError(w, 409, "Copy requires the selected folder to be on the environment's own disk")
			return
		}
	}
	name := "yougori-import-" + transfer
	destination := strings.TrimSuffix(folder, "/") + "/" + name
	if err := unix.Mkdirat(parent, name, 0755); err != nil {
		writeError(w, 409, "Could not create a new copy destination: "+err.Error())
		return
	}
	target, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		writeError(w, 409, "Copy destination became unavailable")
		return
	}
	defer unix.Close(target)
	if err := unix.Fchown(target, uid, gid); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	// The authenticated desktop supplies the staged archive's exact length.
	// Stream it without a global entry/data cap; actual guest disk space and
	// exclusive file creation remain enforced for every entry.
	if r.ContentLength <= 0 {
		writeError(w, 400, "A file copy must declare its archive size")
		return
	}
	// Only selecting the anchored root needs lifecycle coordination. Extraction
	// has an independent cancellation context and must not delay Stop or settings.
	release.Do(unlock)
	state.mu.Lock()
	state.phase = "extracting"
	state.mu.Unlock()
	bytes, err := unpackImportProgress(ctx, importReader{ctx, http.MaxBytesReader(w, r.Body, r.ContentLength), state}, target, uid, gid, func(n int64) { state.progress(0, n) })
	if err != nil {
		writeError(w, 400, "Copy incomplete at "+destination+": "+err.Error())
		return
	}
	state.mu.Lock()
	state.phase = "verifying"
	state.mu.Unlock()
	if err := unix.Fsync(target); err != nil {
		writeError(w, 500, "Copy receipt could not verify filesystem flush")
		return
	}
	state.mu.Lock()
	state.phase = "complete"
	state.status = "complete"
	state.mu.Unlock()
	writeJSON(w, 200, map[string]interface{}{"destination": destination, "bytes": bytes})
}
