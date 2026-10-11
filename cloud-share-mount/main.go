// Yougori's short-lived cloud filesystem mount. The cloud connector owns this
// process and unmounts it when the connection ends; the remote server never
// receives a PC folder path or a long-lived credential.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

type info struct {
	Name      string `json:"name"`
	Size      uint64 `json:"size"`
	Directory bool   `json:"directory"`
	Modified  uint64 `json:"modified"`
}
type reply struct {
	Info    info   `json:"info"`
	Entries []info `json:"entries"`
	Data    string `json:"data"`
	Count   uint32 `json:"count"`
}
type node struct {
	fs.Inode
	port       int
	connection string
	base       string
	relative   string
	readOnly   bool
	uid        uint32
	gid        uint32
}

var client = &http.Client{Timeout: 25 * time.Second}

func (n *node) call(ctx context.Context, operation string, fields map[string]interface{}) (reply, syscall.Errno) {
	if fields == nil {
		fields = map[string]interface{}{}
	}
	fields["operation"] = operation
	fields["connectionId"] = n.connection
	if _, found := fields["path"]; !found {
		fields["path"] = path.Join(n.base, n.relative)
	}
	encoded, err := json.Marshal(fields)
	if err != nil {
		return reply{}, syscall.EINVAL
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/api", n.port), bytes.NewReader(encoded))
	if err != nil {
		return reply{}, syscall.EIO
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return reply{}, syscall.EIO
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusNotFound:
		return reply{}, syscall.ENOENT
	case http.StatusForbidden:
		var failure struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&failure)
		message := strings.ToLower(failure.Error)
		if strings.Contains(message, "no such file or directory") {
			return reply{}, syscall.ENOENT
		}
		if strings.Contains(message, "file exists") {
			return reply{}, syscall.EEXIST
		}
		if strings.Contains(message, "directory not empty") {
			return reply{}, syscall.ENOTEMPTY
		}
		return reply{}, syscall.EACCES
	case http.StatusConflict:
		return reply{}, syscall.EEXIST
	case http.StatusOK:
	default:
		return reply{}, syscall.EIO
	}
	var result reply
	if err := json.NewDecoder(io.LimitReader(response.Body, 1024*1024)).Decode(&result); err != nil {
		return reply{}, syscall.EIO
	}
	return result, 0
}

// The mount is owned by the connecting account. With default_permissions the
// kernel enforces these owner-only modes, so other accounts on a shared
// server cannot read or change the PC folder.
func (n *node) attr(v info, out *fuse.Attr) {
	out.Size = v.Size
	out.Mode = syscall.S_IFREG | 0600
	if v.Directory {
		out.Mode = syscall.S_IFDIR | 0700
	}
	if n.readOnly {
		out.Mode &^= 0222
	}
	out.Mtime = v.Modified
	out.Ctime = v.Modified
	out.Nlink = 1
	out.Uid = n.uid
	out.Gid = n.gid
}
func (n *node) child(ctx context.Context, name string, v info) *fs.Inode {
	mode := uint32(syscall.S_IFREG)
	if v.Directory {
		mode = syscall.S_IFDIR
	}
	return n.NewInode(ctx, &node{port: n.port, connection: n.connection, base: n.base, relative: path.Join(n.relative, name), readOnly: n.readOnly, uid: n.uid, gid: n.gid}, fs.StableAttr{Mode: mode})
}
func (n *node) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	v, status := n.call(ctx, "stat", map[string]interface{}{"path": path.Join(n.base, n.relative, name)})
	if status != 0 {
		return nil, status
	}
	n.attr(v.Info, &out.Attr)
	return n.child(ctx, name, v.Info), 0
}
func (n *node) Getattr(ctx context.Context, _ fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	v, status := n.call(ctx, "stat", nil)
	if status == 0 {
		n.attr(v.Info, &out.Attr)
	}
	return status
}
func (n *node) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	v, status := n.call(ctx, "list", nil)
	if status != 0 {
		return nil, status
	}
	entries := make([]fuse.DirEntry, 0, len(v.Entries))
	for _, item := range v.Entries {
		mode := uint32(syscall.S_IFREG)
		if item.Directory {
			mode = syscall.S_IFDIR
		}
		entries = append(entries, fuse.DirEntry{Name: item.Name, Mode: mode})
	}
	return fs.NewListDirStream(entries), 0
}
func (n *node) Open(_ context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	if n.readOnly && flags&(syscall.O_WRONLY|syscall.O_RDWR) != 0 {
		return nil, 0, syscall.EROFS
	}
	return n, fuse.FOPEN_DIRECT_IO, 0
}
func (n *node) Read(ctx context.Context, _ fs.FileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	if off < 0 {
		return nil, syscall.EINVAL
	}
	v, status := n.call(ctx, "read", map[string]interface{}{"offset": off, "length": min(len(dest), 65536)})
	if status != 0 {
		return nil, status
	}
	data, err := base64.StdEncoding.DecodeString(v.Data)
	if err != nil {
		return nil, syscall.EIO
	}
	return fuse.ReadResultData(data), 0
}
func (n *node) Write(ctx context.Context, _ fs.FileHandle, data []byte, off int64) (uint32, syscall.Errno) {
	if n.readOnly {
		return 0, syscall.EROFS
	}
	if off < 0 {
		return 0, syscall.EINVAL
	}
	v, status := n.call(ctx, "write", map[string]interface{}{"offset": off, "data": base64.StdEncoding.EncodeToString(data[:min(len(data), 65536)])})
	return v.Count, status
}
func (n *node) Create(ctx context.Context, name string, _ uint32, _ uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	if n.readOnly {
		return nil, nil, 0, syscall.EROFS
	}
	childPath := path.Join(n.base, n.relative, name)
	_, status := n.call(ctx, "create", map[string]interface{}{"path": childPath})
	if status != 0 {
		return nil, nil, 0, status
	}
	v, status := n.call(ctx, "stat", map[string]interface{}{"path": childPath})
	if status != 0 {
		return nil, nil, 0, status
	}
	n.attr(v.Info, &out.Attr)
	return n.child(ctx, name, v.Info), nil, fuse.FOPEN_DIRECT_IO, 0
}
func (n *node) Mkdir(ctx context.Context, name string, _ uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if n.readOnly {
		return nil, syscall.EROFS
	}
	childPath := path.Join(n.base, n.relative, name)
	_, status := n.call(ctx, "mkdir", map[string]interface{}{"path": childPath})
	if status != 0 {
		return nil, status
	}
	v, status := n.call(ctx, "stat", map[string]interface{}{"path": childPath})
	if status != 0 {
		return nil, status
	}
	n.attr(v.Info, &out.Attr)
	return n.child(ctx, name, v.Info), 0
}
func (n *node) Unlink(ctx context.Context, name string) syscall.Errno {
	if n.readOnly {
		return syscall.EROFS
	}
	_, status := n.call(ctx, "remove", map[string]interface{}{"path": path.Join(n.base, n.relative, name)})
	return status
}
func (n *node) Rmdir(ctx context.Context, name string) syscall.Errno { return n.Unlink(ctx, name) }
func (n *node) Setattr(ctx context.Context, _ fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if n.readOnly {
		return syscall.EROFS
	}
	if size, ok := in.GetSize(); ok {
		if _, status := n.call(ctx, "truncate", map[string]interface{}{"length": size}); status != 0 {
			return status
		}
	}
	return n.Getattr(ctx, nil, out)
}

func main() {
	if len(os.Args) != 8 {
		panic("usage: yougori-cloud-share MOUNT PORT CONNECTION INDEX READ_ONLY UID GID")
	}
	mount := os.Args[1]
	port, err := strconv.Atoi(os.Args[2])
	if err != nil || port < 1 || port > 65535 {
		panic("invalid port")
	}
	connection := os.Args[3]
	if len(connection) == 0 || len(connection) > 128 {
		panic("invalid connection")
	}
	for _, c := range connection {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			panic("invalid connection")
		}
	}
	index, err := strconv.Atoi(os.Args[4])
	if err != nil || index < 0 || index > 7 {
		panic("invalid selected folder")
	}
	readOnly := os.Args[5] == "true"
	uid, err := strconv.ParseUint(os.Args[6], 10, 32)
	if err != nil {
		panic("invalid UID")
	}
	gid, err := strconv.ParseUint(os.Args[7], 10, 32)
	if err != nil {
		panic("invalid GID")
	}
	root := &node{port: port, connection: connection, base: fmt.Sprintf("_selected/%d", index), readOnly: readOnly, uid: uint32(uid), gid: uint32(gid)}
	if _, status := root.call(context.Background(), "stat", nil); status != 0 {
		panic(fmt.Sprintf("cannot access selected folder: %v", status))
	}
	// AllowOther lets the connecting account use a mount created through sudo;
	// default_permissions makes the kernel apply the owner-only modes above.
	server, err := fs.Mount(mount, root, &fs.Options{MountOptions: fuse.MountOptions{DirectMount: true, AllowOther: true, Options: []string{"default_permissions"}, FsName: "Yougori shared files", Name: "yougori", MaxWrite: 65536}, AttrTimeout: duration(time.Second), EntryTimeout: duration(time.Second)})
	if err != nil {
		panic(fmt.Sprintf("mount failed: %v", err))
	}
	fmt.Println("yougori-share-ready")
	server.Wait()
}

func duration(value time.Duration) *time.Duration { return &value }
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
