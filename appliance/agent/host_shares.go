package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	"golang.org/x/sys/unix"
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

// PC folders mount at a name derived from both identifiers, outside the
// connection share directory. Joining them with "-" was ambiguous: "a-b"+"c"
// and "a"+"b-c" shared one mount point, and a connection named "host-…" could
// collide with a PC folder.
const hostShareRoot = dataRoot + "/host-shares"

func hostShareMountPath(id, shareID string) string {
	digest := sha256.Sum256([]byte(id + "\x00" + shareID))
	return path.Join(hostShareRoot, hex.EncodeToString(digest[:16]))
}

// Detach mount points left by an agent that used the ambiguous legacy names.
// Their FUSE servers ended with that agent, so the mounts are already dead.
func releaseLegacyHostShareMounts() {
	entries, err := os.ReadDir(path.Join(dataRoot, "shares"))
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "host-") {
			continue
		}
		legacy := path.Join(dataRoot, "shares", entry.Name())
		_ = unix.Unmount(legacy, unix.MNT_DETACH)
		_ = os.Remove(legacy)
	}
}

func unmountHostShare(ctx context.Context, share *mountedHostShare) error {
	bounded, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	if _, err := run(bounded, "yougori-mount-helper", strconv.Itoa(share.pid), "--unmount", share.destination); err != nil {
		return err
	}
	return share.server.Unmount()
}

var hostFileClient = &http.Client{
	Timeout: 20 * time.Second,
	Transport: &http.Transport{
		// These are scoped host endpoints, never an environment's proxy or redirect.
		Proxy: nil, DisableCompression: true,
		MaxConnsPerHost: 8, MaxIdleConns: 64, MaxIdleConnsPerHost: 4,
		IdleConnTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second,
	},
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
}

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

// hostShareRootIno is the number go-fuse reserves for a mount's root node. No
// derived number may take it.
const hostShareRootIno = uint64(1)

// hostShareInode derives the inode number a path keeps for the life of a
// mount. go-fuse hands out a fresh number to every node created without one,
// so after the 1 s EntryTimeout expires a re-Lookup of the same file used to
// report a different st_ino; a reader that compares the stat identity of a
// path before and after a slow read (a model runner's checksum check) then
// sees a file that was replaced under it and refuses the data.
//
// The number is FNV-1a (64 bit) of "endpoint\x00token\x00relative". endpoint
// and token identify the share: one mount namespace can hold several shares,
// each mounted separately with its own token, and their inode numbers must not
// collide for the same relative path. FNV-1a is enough here because the value
// only has to be stable and practically distinct, not unforgeable: with 64 bits
// a share would need on the order of a billion paths before a collision is
// likely, far beyond any shared folder. 0 is reserved by the kernel for "no
// inode" and 1 for the root, so both are folded away.
func hostShareInode(endpoint, token, relative string) uint64 {
	const offset, prime = uint64(14695981039346656037), uint64(1099511628211)
	sum := offset
	for _, b := range []byte(endpoint + "\x00" + token + "\x00" + relative) {
		sum ^= uint64(b)
		sum *= prime
	}
	if sum == 0 || sum == hostShareRootIno {
		sum = offset
	}
	return sum
}

func (n *hostFileNode) child(ctx context.Context, name string, info hostFileInfo) *fs.Inode {
	mode := uint32(syscall.S_IFREG)
	if info.Directory {
		mode = syscall.S_IFDIR
	}
	relative := path.Join(n.relative, name)
	return n.NewInode(ctx, &hostFileNode{endpoint: n.endpoint, token: n.token, relative: relative, readOnly: n.readOnly}, fs.StableAttr{Mode: mode, Ino: hostShareInode(n.endpoint, n.token, relative), Gen: 1})
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
	data, err := n.readBytes(ctx, dest, off)
	if err != 0 {
		return nil, err
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

// sharesPID is the process whose mount namespace receives an environment's
// shared folders: its container, the OCI workload that runs a microVM's tool,
// or a microVM without a workload. A stopped workload is an error, never the
// microVM's own guest.
func (s *server) sharesPID(ctx context.Context, id string) (int, error) {
	if s.microVM && microWorkloadExists() {
		return namespacedPID(ctx, microWorkloadNamespace, microWorkloadName)
	}
	return s.environmentPID(ctx, id)
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
	destination := "/yougori/shared/my-pc/" + request.ShareID
	if request.Connection {
		destination = "/yougori/shared/" + request.ShareID
	}
	pid, err := s.sharesPID(r.Context(), request.ID)
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
	source := hostShareMountPath(request.ID, request.ShareID)
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
			_, _ = run(r.Context(), "yougori-mount-helper", strconv.Itoa(pid), "--unmount", destination)
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
