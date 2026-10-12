package main

// File-only remote access never invokes a shell. openat2 confines every lookup
// to the selected directory and rejects links and nested mounts (including PC
// shares, procfs, devices and other environments).
import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
)

type remoteFileRequest struct {
	ID           string `json:"id"`
	Root         string `json:"root"`
	Operation    string `json:"operation"`
	Path         string `json:"path"`
	ReadOnly     bool   `json:"readOnly"`
	Offset       int64  `json:"offset"`
	Length       int64  `json:"length"`
	Data         string `json:"data"`
	ExpectedData string `json:"expectedData"`
}

var remoteFileMutations keyedLocker

func remoteOpen(root int, name string, flags int, mode uint64) (int, error) {
	return unix.Openat2(root, name, &unix.OpenHow{Flags: uint64(flags | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK), Mode: mode, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV})
}
func remoteName(name string) (string, error) {
	if name == "" || name == "." {
		return ".", nil
	}
	if len(name) > 4096 || strings.ContainsAny(name, "\\\x00:") || path.IsAbs(name) || path.Clean(name) != name || name == ".." || strings.HasPrefix(name, "../") {
		return "", fmt.Errorf("path must stay inside the shared folder")
	}
	return name, nil
}
func remoteFileOperation(root int, r remoteFileRequest) (interface{}, error) {
	name, err := remoteName(r.Path)
	if err != nil {
		return nil, err
	}
	writing := r.Operation != "list" && r.Operation != "stat" && r.Operation != "read"
	if writing && (r.ReadOnly || name == ".") {
		return nil, fmt.Errorf("file operation is not permitted")
	}
	if r.Offset < 0 || r.Length < 0 || r.Offset > 1<<40 || r.Length > 1<<40 {
		return nil, fmt.Errorf("invalid file range")
	}
	if writing {
		// Two remote editors saving the same expected version must not both
		// pass the comparison and replace one another. Identify the anchored
		// parent by filesystem/inode, rather than an fd which is reusable
		// and differs between requests. Overlapping shared roots then identify
		// the same file, while unrelated files remain independent.
		parent, err := remoteOpen(root, path.Dir(name), unix.O_RDONLY|unix.O_DIRECTORY, 0)
		if err != nil {
			return nil, err
		}
		var directory unix.Stat_t
		err = unix.Fstat(parent, &directory)
		unix.Close(parent)
		if err != nil {
			return nil, err
		}
		unlock := remoteFileMutations.lock(fmt.Sprintf("file:%d:%d:%s", directory.Dev, directory.Ino, path.Base(name)))
		defer unlock()
	}
	if r.Operation == "mkdir" || r.Operation == "remove" {
		parent, e := remoteOpen(root, path.Dir(name), unix.O_RDONLY|unix.O_DIRECTORY, 0)
		if e != nil {
			return nil, e
		}
		defer unix.Close(parent)
		if r.Operation == "mkdir" {
			return map[string]bool{"ok": true}, unix.Mkdirat(parent, path.Base(name), 0755)
		}
		var stat unix.Stat_t
		if e = unix.Fstatat(parent, path.Base(name), &stat, unix.AT_SYMLINK_NOFOLLOW); e != nil {
			return nil, e
		}
		flags := 0
		if stat.Mode&unix.S_IFMT == unix.S_IFDIR {
			flags = unix.AT_REMOVEDIR
		} else if stat.Mode&unix.S_IFMT != unix.S_IFREG {
			return nil, fmt.Errorf("only ordinary files can be removed")
		}
		return map[string]bool{"ok": true}, unix.Unlinkat(parent, path.Base(name), flags)
	}
	flags := unix.O_RDONLY
	var mode uint64
	if r.Operation == "create" {
		flags = unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL
		mode = 0644
	} else if r.Operation == "write" || r.Operation == "truncate" {
		flags = unix.O_WRONLY
	}
	fd, err := remoteOpen(root, name, flags, mode)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	m, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !m.IsDir() && !m.Mode().IsRegular() {
		return nil, fmt.Errorf("only ordinary files and folders are shared")
	}
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	if !m.IsDir() && stat.Nlink > 1 {
		return nil, fmt.Errorf("hard-linked files are not shared")
	}
	switch r.Operation {
	case "stat":
		return map[string]interface{}{"info": map[string]interface{}{"name": m.Name(), "directory": m.IsDir(), "size": m.Size()}}, nil
	case "list":
		// Readdir resolves entry metadata using File.Name(). This descriptor was
		// opened relative to the confined guest root, while File.Name() is only
		// the relative name passed to os.NewFile. Resolve each entry from the
		// opened directory descriptor instead, so host cwd cannot hide files.
		entries, e := f.Readdirnames(5001)
		if e != nil && e != io.EOF {
			return nil, e
		}
		if len(entries) > 5000 {
			return nil, fmt.Errorf("folder exceeds 5000 entries")
		}
		result := []map[string]interface{}{}
		for _, entry := range entries {
			var info unix.Stat_t
			if e := unix.Fstatat(fd, entry, &info, unix.AT_SYMLINK_NOFOLLOW); e != nil {
				return nil, e
			}
			kind := info.Mode & unix.S_IFMT
			if kind == unix.S_IFDIR || kind == unix.S_IFREG && info.Nlink <= 1 {
				result = append(result, map[string]interface{}{"name": entry, "directory": kind == unix.S_IFDIR, "size": info.Size})
			}
		}
		return map[string]interface{}{"entries": result}, nil
	case "read":
		if !m.Mode().IsRegular() {
			return nil, fmt.Errorf("choose a file")
		}
		size := r.Length
		if size == 0 || size > 65536 {
			size = 65536
		}
		b := make([]byte, size)
		n, e := f.ReadAt(b, r.Offset)
		if e != nil && e != io.EOF {
			return nil, e
		}
		return map[string]string{"data": base64.StdEncoding.EncodeToString(b[:n])}, nil
	case "replace":
		expected, e := base64.StdEncoding.DecodeString(r.ExpectedData)
		if e != nil || len(expected) > 65536 {
			return nil, fmt.Errorf("invalid previous file data")
		}
		data, e := base64.StdEncoding.DecodeString(r.Data)
		if e != nil || len(data) > 65536 {
			return nil, fmt.Errorf("text editing is limited to 64 KiB")
		}
		actual, e := io.ReadAll(io.LimitReader(f, 65537))
		if e != nil || !bytes.Equal(actual, expected) {
			return nil, fmt.Errorf("file changed; reopen it before saving")
		}
		parent, e := remoteOpen(root, path.Dir(name), unix.O_RDONLY|unix.O_DIRECTORY, 0)
		if e != nil {
			return nil, e
		}
		defer unix.Close(parent)
		random := make([]byte, 16)
		if _, e = rand.Read(random); e != nil {
			return nil, e
		}
		temp := fmt.Sprintf(".yougori-save-%x", random)
		fd, e := unix.Openat(parent, temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(m.Mode().Perm()))
		if e != nil {
			return nil, e
		}
		defer unix.Unlinkat(parent, temp, 0)
		output := os.NewFile(uintptr(fd), temp)
		defer output.Close()
		if _, e = output.Write(data); e != nil {
			return nil, e
		}
		if e = output.Sync(); e != nil {
			return nil, e
		}
		if e = unix.Fchown(fd, int(stat.Uid), int(stat.Gid)); e != nil {
			return nil, e
		}
		if e = unix.Renameat(parent, temp, parent, path.Base(name)); e != nil {
			return nil, e
		}
		return map[string]int{"count": len(data)}, nil
	case "create":
		return map[string]bool{"ok": true}, nil
	case "write":
		if !m.Mode().IsRegular() {
			return nil, fmt.Errorf("choose a file")
		}
		b, e := base64.StdEncoding.DecodeString(r.Data)
		if e != nil || len(b) > 65536 {
			return nil, fmt.Errorf("invalid or oversized file chunk")
		}
		n, e := f.WriteAt(b, r.Offset)
		return map[string]int{"count": n}, e
	case "truncate":
		if !m.Mode().IsRegular() {
			return nil, fmt.Errorf("choose a file")
		}
		return map[string]bool{"ok": true}, f.Truncate(r.Length)
	default:
		return nil, fmt.Errorf("unsupported file operation")
	}
}
func (s *server) remoteFiles(w http.ResponseWriter, r *http.Request) {
	var request remoteFileRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, 256*1024))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || !requireID(w, request.ID) {
		writeError(w, 400, "invalid file request")
		return
	}
	if !strings.HasPrefix(request.Root, "/") {
		writeError(w, 400, "choose an absolute guest folder")
		return
	}
	name, err := remoteName(strings.TrimPrefix(request.Root, "/"))
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	guestRoot := "/"
	process, err := s.filesProcess(ctx, request.ID)
	if err != nil {
		writeError(w, 409, "start the environment before accessing files")
		return
	}
	if process != "" {
		guestRoot = process + "/root"
	}
	root, err := unix.Open(guestRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		writeError(w, 409, "guest files unavailable")
		return
	}
	defer unix.Close(root)
	selected, err := remoteOpen(root, name, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		writeError(w, 403, "folder unavailable; links and mounted shares cannot be shared")
		return
	}
	defer unix.Close(selected)
	value, err := remoteFileOperation(selected, request)
	if err != nil {
		writeError(w, 403, err.Error())
		return
	}
	writeJSON(w, 200, value)
}
