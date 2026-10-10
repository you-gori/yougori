package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

type hostFileInfo struct {
	Name      string `json:"name"`
	Size      uint64 `json:"size"`
	Directory bool   `json:"directory"`
	Modified  uint64 `json:"modified"`
}
type hostFileReply struct {
	Info    hostFileInfo   `json:"info"`
	Entries []hostFileInfo `json:"entries"`
	Data    string         `json:"data"`
	Count   uint32         `json:"count"`
	Error   string         `json:"error"`
}
type hostFileNode struct {
	fs.Inode
	endpoint string
	token    string
	relative string
	readOnly bool
}
type mountedHostShare struct {
	server      *fuse.Server
	pid         int
	destination string
	endpoint    string
	token       string
	readOnly    bool
}
type hostShareRequest struct {
	ID         string `json:"id"`
	ShareID    string `json:"shareId"`
	Endpoint   string `json:"endpoint"`
	Token      string `json:"token"`
	ReadOnly   bool   `json:"readOnly"`
	Connection bool   `json:"connection"`
}

func unmountHostShare(ctx context.Context, share *mountedHostShare) error {
	bounded, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	if _, err := run(bounded, "opendock-mount-helper", strconv.Itoa(share.pid), "--unmount", share.destination); err != nil {
		return err
	}
	return share.server.Unmount()
}

var hostFileClient = &http.Client{Timeout: 20 * time.Second}

func (n *hostFileNode) call(ctx context.Context, operation string, extra map[string]interface{}) (hostFileReply, syscall.Errno) {
	if extra == nil {
		extra = map[string]interface{}{}
	}
	extra["operation"] = operation
	if _, ok := extra["path"]; !ok {
		extra["path"] = n.relative
	}
	body, _ := json.Marshal(extra)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, n.endpoint+"/files", bytes.NewReader(body))
	if err != nil {
		return hostFileReply{}, syscall.EIO
	}
	request.Header.Set("Authorization", "Bearer "+n.token)
	request.Header.Set("Content-Type", "application/json")
	response, err := hostFileClient.Do(request)
	if err != nil {
		return hostFileReply{}, syscall.EIO
	}
	defer response.Body.Close()
	if response.StatusCode == 404 {
		return hostFileReply{}, syscall.ENOENT
	}
	if response.StatusCode == 403 {
		return hostFileReply{}, syscall.EACCES
	}
	if response.StatusCode == 409 {
		return hostFileReply{}, syscall.EEXIST
	}
	if response.StatusCode != 200 {
		return hostFileReply{}, syscall.EIO
	}
	var reply hostFileReply
	if json.NewDecoder(response.Body).Decode(&reply) != nil {
		return reply, syscall.EIO
	}
	return reply, 0
}
func fillHostAttr(info hostFileInfo, out *fuse.Attr, readOnly bool) {
	out.Size = info.Size
	out.Mode = syscall.S_IFREG | 0644
	if info.Directory {
		out.Mode = syscall.S_IFDIR | 0755
	}
	if readOnly {
		out.Mode &^= 0222
	}
	out.Mtime = info.Modified
	out.Ctime = info.Modified
	out.Nlink = 1
}
func (n *hostFileNode) child(ctx context.Context, name string, info hostFileInfo) *fs.Inode {
	mode := uint32(syscall.S_IFREG)
	if info.Directory {
		mode = syscall.S_IFDIR
	}
	return n.NewInode(ctx, &hostFileNode{endpoint: n.endpoint, token: n.token, relative: path.Join(n.relative, name), readOnly: n.readOnly}, fs.StableAttr{Mode: mode})
}
func (n *hostFileNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	reply, err := n.call(ctx, "stat", map[string]interface{}{"path": path.Join(n.relative, name)})
	if err != 0 {
		return nil, err
	}
	fillHostAttr(reply.Info, &out.Attr, n.readOnly)
	return n.child(ctx, name, reply.Info), 0
}
func (n *hostFileNode) Getattr(ctx context.Context, _ fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	reply, err := n.call(ctx, "stat", nil)
	if err == 0 {
		fillHostAttr(reply.Info, &out.Attr, n.readOnly)
	}
	return err
}
func (n *hostFileNode) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	reply, err := n.call(ctx, "list", nil)
	if err != 0 {
		return nil, err
	}
	entries := []fuse.DirEntry{}
	for _, info := range reply.Entries {
		mode := uint32(syscall.S_IFREG)
		if info.Directory {
			mode = syscall.S_IFDIR
		}
		entries = append(entries, fuse.DirEntry{Name: info.Name, Mode: mode})
	}
	return fs.NewListDirStream(entries), 0
}
func (n *hostFileNode) Open(_ context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	if n.readOnly && flags&(syscall.O_WRONLY|syscall.O_RDWR) != 0 {
		return nil, 0, syscall.EROFS
	}
	return n, fuse.FOPEN_DIRECT_IO, 0
}
func (n *hostFileNode) Read(ctx context.Context, _ fs.FileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	reply, err := n.call(ctx, "read", map[string]interface{}{"offset": off, "length": len(dest)})
	if err != 0 {
		return nil, err
	}
	data, e := base64.StdEncoding.DecodeString(reply.Data)
	if e != nil {
		return nil, syscall.EIO
	}
	return fuse.ReadResultData(data), 0
}
func (n *hostFileNode) Write(ctx context.Context, _ fs.FileHandle, data []byte, off int64) (uint32, syscall.Errno) {
	if n.readOnly {
		return 0, syscall.EROFS
	}
	reply, err := n.call(ctx, "write", map[string]interface{}{"offset": off, "data": base64.StdEncoding.EncodeToString(data)})
	return reply.Count, err
}
func (n *hostFileNode) Create(ctx context.Context, name string, _ uint32, _ uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	if n.readOnly {
		return nil, nil, 0, syscall.EROFS
	}
	reply, err := n.call(ctx, "create", map[string]interface{}{"path": path.Join(n.relative, name)})
	if err != 0 {
		return nil, nil, 0, err
	}
	fillHostAttr(reply.Info, &out.Attr, false)
	node := n.child(ctx, name, reply.Info)
	return node, nil, fuse.FOPEN_DIRECT_IO, 0
}
func (n *hostFileNode) Mkdir(ctx context.Context, name string, _ uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if n.readOnly {
		return nil, syscall.EROFS
	}
	reply, err := n.call(ctx, "mkdir", map[string]interface{}{"path": path.Join(n.relative, name)})
	if err != 0 {
		return nil, err
	}
	fillHostAttr(reply.Info, &out.Attr, false)
	return n.child(ctx, name, reply.Info), 0
}
func (n *hostFileNode) Unlink(ctx context.Context, name string) syscall.Errno {
	if n.readOnly {
		return syscall.EROFS
	}
	_, err := n.call(ctx, "remove", map[string]interface{}{"path": path.Join(n.relative, name)})
	return err
}
func (n *hostFileNode) Rmdir(ctx context.Context, name string) syscall.Errno {
	return n.Unlink(ctx, name)
}
func (n *hostFileNode) Rename(ctx context.Context, name string, parent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	if n.readOnly {
		return syscall.EROFS
	}
	other, ok := parent.(*hostFileNode)
	if !ok || other.token != n.token || flags != 0 {
		return syscall.EXDEV
	}
	_, err := n.call(ctx, "rename", map[string]interface{}{"path": path.Join(n.relative, name), "destination": path.Join(other.relative, newName)})
	return err
}
func (n *hostFileNode) Setattr(ctx context.Context, _ fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if n.readOnly {
		return syscall.EROFS
	}
	if size, ok := in.GetSize(); ok {
		if _, err := n.call(ctx, "truncate", map[string]interface{}{"length": size}); err != 0 {
			return err
		}
	}
	return n.Getattr(ctx, nil, out)
}

func (s *server) attachHostShare(w http.ResponseWriter, r *http.Request) {
	var request hostShareRequest
	if !decodeRequest(w, r, &request) || !requireID(w, request.ID) || !requireID(w, request.ShareID) {
		return
	}
	endpoint, endpointErr := url.Parse(request.Endpoint)
	if endpointErr != nil || endpoint.Scheme != "http" || (endpoint.Hostname() != "10.0.2.2" && !(cudaMode() && endpoint.Hostname() == "127.0.0.1")) || endpoint.Port() == "" || endpoint.User != nil || endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" || len(request.Token) != 64 || strings.Trim(request.Token, "0123456789abcdef") != "" {
		writeError(w, 400, "invalid host share endpoint")
		return
	}
	key := request.ID + ":" + request.ShareID
	unlock := s.locks.lock("hostshare:" + key)
	defer unlock()
	destination := "/opendock/shared/my-pc/" + request.ShareID
	if request.Connection {
		destination = "/opendock/shared/" + request.ShareID
	}
	pid, err := s.environmentPID(r.Context(), request.ID)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	if old, exists := s.hostShares.Load(key); exists {
		share := old.(*mountedHostShare)
		if !request.Connection {
			writeError(w, 409, "folder is already shared")
			return
		}
		if share.pid == pid && share.destination == destination && share.endpoint == request.Endpoint && share.token == request.Token && share.readOnly == request.ReadOnly {
			writeJSON(w, 200, map[string]string{"mountPath": share.destination})
			return
		}
		if err := unmountHostShare(r.Context(), share); err != nil {
			writeError(w, 500, "could not detach previous shared folder: "+err.Error())
			return
		}
		s.hostShares.Delete(key)
	}
	root := &hostFileNode{endpoint: request.Endpoint, token: request.Token, readOnly: request.ReadOnly}
	if _, errno := root.call(r.Context(), "stat", nil); errno != 0 {
		writeError(w, 502, "cannot reach the selected PC folder")
		return
	}
	_ = syscall.Mknod("/dev/fuse", syscall.S_IFCHR|0600, int(10<<8|229))
	_, _ = run(r.Context(), "modprobe", "fuse")
	source := path.Join(dataRoot, "shares", "host-"+request.ID+"-"+request.ShareID)
	if err = os.MkdirAll(source, 0700); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	ttl := time.Second
	mount, err := fs.Mount(source, root, &fs.Options{MountOptions: fuse.MountOptions{AllowOther: true, DirectMount: true, FsName: "Yougori shared files", Name: "yougori", MaxWrite: 128 * 1024}, AttrTimeout: &ttl, EntryTimeout: &ttl})
	if err != nil {
		writeError(w, 500, fmt.Sprintf("mount PC folder: %v", err))
		return
	}
	if err = bindMountIntoNamespace(source, destination, pid, request.ReadOnly); err != nil {
		mount.Unmount()
		writeError(w, 500, err.Error())
		return
	}
	if request.Connection {
		if err = ensureYougoriSharedAlias(pid); err != nil {
			_, _ = run(r.Context(), "opendock-mount-helper", strconv.Itoa(pid), "--unmount", destination)
			mount.Unmount()
			writeError(w, 500, "cannot make the Yougori shared folder visible: "+err.Error())
			return
		}
	}
	s.hostShares.Store(key, &mountedHostShare{server: mount, pid: pid, destination: destination, endpoint: request.Endpoint, token: request.Token, readOnly: request.ReadOnly})
	writeJSON(w, 200, map[string]string{"mountPath": destination})
}
func (s *server) detachHostShare(w http.ResponseWriter, r *http.Request) {
	var request hostShareRequest
	if !decodeRequest(w, r, &request) || !requireID(w, request.ID) || !requireID(w, request.ShareID) {
		return
	}
	key := request.ID + ":" + request.ShareID
	unlock := s.locks.lock("hostshare:" + key)
	defer unlock()
	if value, ok := s.hostShares.Load(key); ok {
		share := value.(*mountedHostShare)
		if err := unmountHostShare(r.Context(), share); err != nil {
			writeError(w, 500, "could not detach shared folder: "+err.Error())
			return
		}
		s.hostShares.Delete(key)
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
