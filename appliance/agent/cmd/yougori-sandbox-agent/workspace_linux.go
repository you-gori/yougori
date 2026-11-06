package main

// The staged workspace as a directory in the guest (VM part §5.1 "Quarantine output: writes
// remain isolated until exact promotion"; VM-W14): a FUSE mount at workspaceMount that the
// agent serves over the link's file channel (files_linux.go) on the workspace grant, so a
// program reads and writes the host's staged copy of the user's folder as ordinary files.
// Nothing of it is stored in the guest, and nothing reaches the user's folder until the user
// promotes it on the host. A small file (up to smallFileBytes) moves whole: it is read whole
// when a handle first reads or writes it and written back whole when a handle that changed
// it is flushed or released. A larger file moves in pieces of at most rangeBytes: it is read
// in ranges, one window at a time, and a handle that changes it writes an upload on the
// host (from the file's content, or empty after a truncation to zero) that is committed over
// the file in one atomic rename when the handle is flushed or released, so the guest holds
// at most a window and one chunk of it. A reader whose file is replaced between two ranges
// gets ESTALE rather than a mix of two versions. Links, devices and special files are not
// offered. Before the host attaches the grant every request is refused as not authorized
// (EACCES).

import (
	"context"
	"os"
	"path"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

const (
	// renameNoReplace is RENAME_NOREPLACE.
	renameNoReplace = 1
	// workspaceMount is where the guest sees its staged workspace.
	workspaceMount = "/run/yougori/workspace"
	// workspaceAttrTTL is how long the kernel keeps an entry or its attributes.
	workspaceAttrTTL = time.Second
	// smallFileBytes is the largest file a handle holds whole; a larger one moves in ranges
	// and uploads.
	smallFileBytes = 1 << 20
)

// rangeAnswer is what a ranged read returns: bytes, the file's size and its version.
type rangeAnswer struct {
	content []byte
	size    uint64
	version string
}

// workspaceFiles is what the mount asks of the host (filesClient in production).
type workspaceFiles interface {
	read(name string) ([]byte, error)
	list(name string) ([]listedEntry, error)
	create(name string, content []byte) error
	write(name string, content []byte) error
	createDirectory(name string) error
	remove(name string) error
	rename(from, to string) error
	setExecutable(name string, executable bool) error
	renameReplace(from, to string) error
	readRange(name string, offset uint64, max int, upload uint64) (rangeAnswer, error)
	uploadBegin(name string, fromExisting bool) (uint64, uint64, error)
	uploadWrite(name string, upload, offset uint64, content []byte) (uint64, error)
	uploadTruncate(name string, upload, length uint64) (uint64, error)
	uploadCommit(name string, upload uint64) (uint64, error)
	uploadAbort(name string, upload uint64) error
}

// workspaceShared is what every node of one mount shares: the execute bits programs set.
// A Windows host keeps none (its staged copy has no execute bit; executable types are
// flagged by name at review), so the bits set here last as long as the mount, and a host
// listing that reports one keeps it too.
type workspaceShared struct {
	mu         sync.Mutex
	executable map[string]bool
}

func (w *workspaceShared) setExecutable(name string, executable bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if executable {
		w.executable[name] = true
	} else {
		delete(w.executable, name)
	}
}

func (w *workspaceShared) isExecutable(name string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.executable[name]
}

// moved follows a rename: the bits of from and everything under it move to to.
func (w *workspaceShared) moved(from, to string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for name := range w.executable {
		if name == from || strings.HasPrefix(name, from+"/") {
			delete(w.executable, name)
			w.executable[to+strings.TrimPrefix(name, from)] = true
		}
	}
}

// workspaceNode is one entry of the workspace. Its guest name is its place in the
// mount's tree (guestName), which a rename moves, never a name kept from its creation: a
// handle flushed after its file was renamed writes the new name.
type workspaceNode struct {
	fs.Inode
	files  workspaceFiles
	shared *workspaceShared
	// root marks the mount's root, whose name is "".
	root bool
	// unmounted is the name of a node made outside a mount (the handle tests).
	unmounted string
	mu        sync.Mutex
	dir       bool
	size      uint64
	exec      bool
}

// guestName is the node's name in the workspace now; ESTALE once it left the tree (a file
// unlinked while open).
func (n *workspaceNode) guestName() (string, syscall.Errno) {
	switch {
	case n.root:
		return "", 0
	case n.unmounted != "":
		return n.unmounted, 0
	}
	if name := n.Path(nil); name != "" {
		return name, 0
	}
	return "", syscall.ESTALE
}

// childName is the name of the entry name beneath n.
func (n *workspaceNode) childName(name string) (string, syscall.Errno) {
	parent, errno := n.guestName()
	if errno != 0 {
		return "", errno
	}
	return path.Join(parent, name), 0
}

func (n *workspaceNode) attr(out *fuse.Attr) {
	n.mu.Lock()
	defer n.mu.Unlock()
	out.Uid, out.Gid = terminalUID, terminalGID
	out.Nlink = 1
	if n.dir || n.root {
		out.Mode = syscall.S_IFDIR | 0o755
		return
	}
	out.Mode = syscall.S_IFREG | 0o644
	if n.exec {
		out.Mode = syscall.S_IFREG | 0o755
	}
	out.Size = n.size
}

// child makes the node of entry, named name in the workspace.
func (n *workspaceNode) child(ctx context.Context, name string, entry listedEntry) *fs.Inode {
	node := &workspaceNode{files: n.files, shared: n.shared}
	node.update(entry, name)
	mode := uint32(syscall.S_IFREG)
	if node.dir {
		mode = syscall.S_IFDIR
	}
	return n.NewInode(ctx, node, fs.StableAttr{Mode: mode})
}

func (n *workspaceNode) update(entry listedEntry, name string) {
	executable := entry.Kind.Executable || n.shared.isExecutable(name)
	n.mu.Lock()
	defer n.mu.Unlock()
	n.dir = entry.Kind.Kind == "directory"
	n.size = entry.Kind.SizeBytes
	n.exec = executable
}

// offered says whether a listed entry is shown: files and directories only.
func offered(entry listedEntry) bool {
	return entry.Kind.Kind == "file" || entry.Kind.Kind == "directory"
}

func (n *workspaceNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	directory, errno := n.guestName()
	if errno != 0 {
		return nil, errno
	}
	entries, err := n.files.list(directory)
	if err != nil {
		return nil, errnoOf(err)
	}
	for _, entry := range entries {
		if entry.Name == name && offered(entry) {
			inode := n.child(ctx, path.Join(directory, name), entry)
			inode.Operations().(*workspaceNode).attr(&out.Attr)
			return inode, 0
		}
	}
	return nil, syscall.ENOENT
}

func (n *workspaceNode) Getattr(_ context.Context, handle fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	n.attr(&out.Attr)
	if h, ok := handle.(*workspaceHandle); ok {
		h.mu.Lock()
		switch {
		case h.ranged && (h.upload != 0 || len(h.pending) > 0):
			out.Attr.Size = h.seenSize()
		case h.loaded:
			out.Attr.Size = uint64(len(h.content))
		}
		h.mu.Unlock()
	}
	return 0
}

func (n *workspaceNode) Readdir(_ context.Context) (fs.DirStream, syscall.Errno) {
	directory, errno := n.guestName()
	if errno != 0 {
		return nil, errno
	}
	entries, err := n.files.list(directory)
	if err != nil {
		return nil, errnoOf(err)
	}
	listed := make([]fuse.DirEntry, 0, len(entries))
	for _, entry := range entries {
		if !offered(entry) {
			continue
		}
		mode := uint32(syscall.S_IFREG)
		if entry.Kind.Kind == "directory" {
			mode = syscall.S_IFDIR
		}
		listed = append(listed, fuse.DirEntry{Name: entry.Name, Mode: mode})
	}
	return fs.NewListDirStream(listed), 0
}

func (n *workspaceNode) Open(_ context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	handle := &workspaceHandle{node: n}
	if flags&syscall.O_TRUNC != 0 && flags&(syscall.O_WRONLY|syscall.O_RDWR) != 0 {
		// Emptied: whole until it grows past the small bound.
		handle.loaded, handle.dirty = true, true
		return handle, fuse.FOPEN_DIRECT_IO, 0
	}
	n.mu.Lock()
	handle.ranged = !n.dir && n.size > smallFileBytes
	n.mu.Unlock()
	return handle, fuse.FOPEN_DIRECT_IO, 0
}

func (n *workspaceNode) Create(ctx context.Context, name string, _ uint32, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	relative, errno := n.childName(name)
	if errno != 0 {
		return nil, nil, 0, errno
	}
	if err := n.files.create(relative, nil); err != nil {
		return nil, nil, 0, errnoOf(err)
	}
	var entry listedEntry
	entry.Kind.Kind = "file"
	if mode&0o111 != 0 {
		if err := n.files.setExecutable(relative, true); err == nil {
			n.shared.setExecutable(relative, true)
			entry.Kind.Executable = true
		}
	}
	inode := n.child(ctx, relative, entry)
	node := inode.Operations().(*workspaceNode)
	node.attr(&out.Attr)
	return inode, &workspaceHandle{node: node, loaded: true}, fuse.FOPEN_DIRECT_IO, 0
}

func (n *workspaceNode) Mkdir(ctx context.Context, name string, _ uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	relative, errno := n.childName(name)
	if errno != 0 {
		return nil, errno
	}
	if err := n.files.createDirectory(relative); err != nil {
		return nil, errnoOf(err)
	}
	var entry listedEntry
	entry.Kind.Kind = "directory"
	inode := n.child(ctx, relative, entry)
	inode.Operations().(*workspaceNode).attr(&out.Attr)
	return inode, 0
}

func (n *workspaceNode) Unlink(_ context.Context, name string) syscall.Errno {
	relative, errno := n.childName(name)
	if errno != 0 {
		return errno
	}
	if errno := errnoOf(n.files.remove(relative)); errno != 0 {
		return errno
	}
	n.shared.setExecutable(relative, false)
	return 0
}

func (n *workspaceNode) Rmdir(_ context.Context, name string) syscall.Errno {
	relative, errno := n.childName(name)
	if errno != 0 {
		return errno
	}
	return errnoOf(n.files.remove(relative))
}

// Rename moves name to newName. A file put over a taken name replaces it in one atomic
// step on the host, as POSIX rename does (an editor's or `sed -i`'s temporary file over
// the original); a directory moves only to a free name. RENAME_NOREPLACE is honoured;
// RENAME_EXCHANGE is not offered.
func (n *workspaceNode) Rename(_ context.Context, name string, parent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	other, ok := parent.(*workspaceNode)
	if !ok {
		return syscall.EXDEV
	}
	if flags&^renameNoReplace != 0 {
		return syscall.EINVAL
	}
	from, errno := n.childName(name)
	if errno != 0 {
		return errno
	}
	to, errno := other.childName(newName)
	if errno != 0 {
		return errno
	}
	if from == to {
		return 0
	}
	directory := false
	if child := n.GetChild(name); child != nil {
		if node, ok := child.Operations().(*workspaceNode); ok {
			node.mu.Lock()
			directory = node.dir
			node.mu.Unlock()
		}
	}
	var err error
	if flags&renameNoReplace == 0 && !directory {
		err = n.files.renameReplace(from, to)
	} else {
		err = n.files.rename(from, to)
	}
	if errno := errnoOf(err); errno != 0 {
		return errno
	}
	n.shared.setExecutable(to, false)
	n.shared.moved(from, to)
	return 0
}

func (n *workspaceNode) Setattr(ctx context.Context, handle fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if size, ok := in.GetSize(); ok {
		if h, ok := handle.(*workspaceHandle); ok {
			if errno := h.truncate(size); errno != 0 {
				return errno
			}
		} else {
			h := &workspaceHandle{node: n}
			if errno := h.truncate(size); errno != 0 {
				return errno
			}
			if errno := h.Flush(ctx); errno != 0 {
				return errno
			}
		}
	}
	if mode, ok := in.GetMode(); ok {
		executable := mode&0o111 != 0
		n.mu.Lock()
		changed := executable != n.exec && !n.dir
		n.mu.Unlock()
		if changed {
			name, errno := n.guestName()
			if errno != 0 {
				return errno
			}
			if err := n.files.setExecutable(name, executable); err != nil {
				return errnoOf(err)
			}
			n.shared.setExecutable(name, executable)
			n.mu.Lock()
			n.exec = executable
			n.mu.Unlock()
		}
	}
	return n.Getattr(ctx, handle, out)
}

// workspaceHandle is one open file. A small file's whole content is held while it is open
// (whole mode); a large one is read through a window of one range and written through an
// upload on the host, with the writes not yet sent held contiguous in pending (ranged mode).
type workspaceHandle struct {
	mu   sync.Mutex
	node *workspaceNode
	// Whole mode.
	content []byte
	loaded  bool
	dirty   bool
	// Ranged mode.
	ranged bool
	// upload is the open upload's number on the host, 0 for none.
	upload uint64
	// size is the file's size as this handle last saw or made it.
	size uint64
	// version is the version the handle's ranges came from, "" until the first.
	version  string
	window   []byte
	windowAt uint64
	// pending holds writes not yet sent, contiguous from pendingAt.
	pending   []byte
	pendingAt uint64
}

// goneIsStale reads a file that went from the host after its handle opened it (another
// program removed or replaced it) as the stale handle it now is, ESTALE as on NFS, not as
// a missing name: the host keeps no old content readable for a handle still open on it.
func goneIsStale(errno syscall.Errno) syscall.Errno {
	if errno == syscall.ENOENT {
		return syscall.ESTALE
	}
	return errno
}

// seenSize is the size the handle's writes made, sent or not.
func (h *workspaceHandle) seenSize() uint64 {
	size := h.size
	if end := h.pendingAt + uint64(len(h.pending)); len(h.pending) > 0 && end > size {
		size = end
	}
	return size
}

func (h *workspaceHandle) load() syscall.Errno {
	if h.loaded {
		return 0
	}
	name, errno := h.node.guestName()
	if errno != 0 {
		return errno
	}
	content, err := h.node.files.read(name)
	if err != nil {
		return goneIsStale(errnoOf(err))
	}
	h.content, h.loaded = content, true
	return 0
}

// whole loads a small file whole; false when the handle is (or now becomes) ranged, as a
// file that grew past the small bound since its listing does.
func (h *workspaceHandle) whole() (bool, syscall.Errno) {
	if h.ranged {
		return false, 0
	}
	errno := h.load()
	switch {
	case errno == 0 && uint64(len(h.content)) > smallFileBytes && !h.dirty:
		// Read whole, but large: from now on in ranges.
		h.content, h.loaded, h.ranged = nil, false, true
		return false, 0
	case errno == syscall.EFBIG:
		h.ranged = true
		return false, 0
	case errno != 0:
		return false, errno
	}
	return true, 0
}

// toRanged continues a whole handle whose file grows past the small bound as an upload of
// what it holds.
func (h *workspaceHandle) toRanged(name string) syscall.Errno {
	upload, _, err := h.node.files.uploadBegin(name, false)
	if err != nil {
		return errnoOf(err)
	}
	for at := 0; at < len(h.content); at += rangeBytes {
		end := at + rangeBytes
		if end > len(h.content) {
			end = len(h.content)
		}
		if _, err := h.node.files.uploadWrite(name, upload, uint64(at), h.content[at:end]); err != nil {
			_ = h.node.files.uploadAbort(name, upload)
			return errnoOf(err)
		}
	}
	h.upload, h.size = upload, uint64(len(h.content))
	h.content, h.loaded, h.dirty, h.ranged = nil, false, false, true
	h.window, h.version = nil, ""
	return 0
}

// ensureUpload opens the handle's upload from the file's content, or empty when empty.
func (h *workspaceHandle) ensureUpload(name string, empty bool) syscall.Errno {
	if h.upload != 0 {
		return 0
	}
	upload, size, err := h.node.files.uploadBegin(name, !empty)
	if err != nil {
		return goneIsStale(errnoOf(err))
	}
	h.upload, h.size, h.window = upload, size, nil
	return 0
}

// sendPending sends the writes held in pending as upload chunks of at most rangeBytes.
func (h *workspaceHandle) sendPending(name string) syscall.Errno {
	for len(h.pending) > 0 {
		chunk := h.pending
		if len(chunk) > rangeBytes {
			chunk = chunk[:rangeBytes]
		}
		size, err := h.node.files.uploadWrite(name, h.upload, h.pendingAt, chunk)
		if err != nil {
			return errnoOf(err)
		}
		h.size = size
		h.pendingAt += uint64(len(chunk))
		h.pending = h.pending[len(chunk):]
	}
	h.pending = nil
	return 0
}

func (h *workspaceHandle) Read(_ context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	h.mu.Lock()
	defer h.mu.Unlock()
	whole, errno := h.whole()
	if errno != 0 {
		return nil, errno
	}
	if whole {
		if off >= int64(len(h.content)) {
			return fuse.ReadResultData(nil), 0
		}
		end := off + int64(len(dest))
		if end > int64(len(h.content)) {
			end = int64(len(h.content))
		}
		return fuse.ReadResultData(append([]byte(nil), h.content[off:end]...)), 0
	}
	name, errno := h.node.guestName()
	if errno != 0 {
		return nil, errno
	}
	if h.upload != 0 {
		if errno := h.sendPending(name); errno != 0 {
			return nil, errno
		}
	}
	out := make([]byte, 0, len(dest))
	position := uint64(off)
	for len(out) < len(dest) {
		if h.window != nil && position >= h.windowAt && position < h.windowAt+uint64(len(h.window)) {
			take := h.window[position-h.windowAt:]
			if room := len(dest) - len(out); len(take) > room {
				take = take[:room]
			}
			out = append(out, take...)
			position += uint64(len(take))
			continue
		}
		answer, err := h.node.files.readRange(name, position, rangeBytes, h.upload)
		if err != nil {
			return nil, goneIsStale(errnoOf(err))
		}
		if h.upload == 0 {
			if h.version == "" {
				h.version = answer.version
			} else if answer.version != h.version {
				// The file was replaced between two ranges: never a mix of two versions.
				return nil, syscall.ESTALE
			}
		}
		h.size = answer.size
		if len(answer.content) == 0 {
			break
		}
		h.window, h.windowAt = answer.content, position
	}
	return fuse.ReadResultData(out), 0
}

func (h *workspaceHandle) Write(_ context.Context, data []byte, off int64) (uint32, syscall.Errno) {
	h.mu.Lock()
	defer h.mu.Unlock()
	end := uint64(off) + uint64(len(data))
	whole, errno := h.whole()
	if errno != 0 {
		return 0, errno
	}
	name, errno := h.node.guestName()
	if errno != 0 {
		return 0, errno
	}
	if whole && end <= smallFileBytes {
		if end > uint64(len(h.content)) {
			grown := make([]byte, end)
			copy(grown, h.content)
			h.content = grown
		}
		copy(h.content[off:end], data)
		h.dirty = true
		return uint32(len(data)), 0
	}
	if whole {
		if errno := h.toRanged(name); errno != 0 {
			return 0, errno
		}
	}
	if errno := h.ensureUpload(name, false); errno != 0 {
		return 0, errno
	}
	h.window = nil
	contiguous := len(h.pending) > 0 && uint64(off) == h.pendingAt+uint64(len(h.pending))
	if !contiguous || len(h.pending)+len(data) > rangeBytes {
		if errno := h.sendPending(name); errno != 0 {
			return 0, errno
		}
		h.pendingAt = uint64(off)
	}
	h.pending = append(h.pending, data...)
	if len(h.pending) >= rangeBytes {
		if errno := h.sendPending(name); errno != 0 {
			return 0, errno
		}
	}
	return uint32(len(data)), 0
}

func (h *workspaceHandle) truncate(size uint64) syscall.Errno {
	h.mu.Lock()
	defer h.mu.Unlock()
	if size == 0 && !h.ranged {
		h.content, h.loaded, h.dirty = nil, true, true
		return 0
	}
	whole, errno := h.whole()
	if errno != 0 {
		return errno
	}
	if whole && size <= smallFileBytes {
		if uint64(len(h.content)) != size {
			resized := make([]byte, size)
			copy(resized, h.content)
			h.content = resized
			h.dirty = true
		}
		return 0
	}
	name, errno := h.node.guestName()
	if errno != 0 {
		return errno
	}
	if whole {
		if errno := h.toRanged(name); errno != 0 {
			return errno
		}
	}
	if errno := h.ensureUpload(name, size == 0); errno != 0 {
		return errno
	}
	if errno := h.sendPending(name); errno != 0 {
		return errno
	}
	got, err := h.node.files.uploadTruncate(name, h.upload, size)
	if err != nil {
		return errnoOf(err)
	}
	h.size, h.window = got, nil
	return 0
}

// Flush writes a changed small file back whole, or commits a large file's upload over it
// in one atomic rename on the host.
func (h *workspaceHandle) Flush(_ context.Context) syscall.Errno {
	h.mu.Lock()
	defer h.mu.Unlock()
	name, errno := h.node.guestName()
	if h.ranged {
		if h.upload == 0 {
			return 0
		}
		if errno != 0 {
			return errno
		}
		if errno := h.sendPending(name); errno != 0 {
			return errno
		}
		size, err := h.node.files.uploadCommit(name, h.upload)
		// Committed or not, the upload is gone on the host.
		h.upload, h.version, h.window = 0, "", nil
		if err != nil {
			return errnoOf(err)
		}
		h.size = size
		h.node.mu.Lock()
		h.node.size = size
		h.node.mu.Unlock()
		return 0
	}
	if !h.dirty {
		return 0
	}
	if errno != 0 {
		return errno
	}
	if err := h.node.files.write(name, h.content); err != nil {
		return errnoOf(err)
	}
	h.dirty = false
	h.node.mu.Lock()
	h.node.size = uint64(len(h.content))
	h.node.mu.Unlock()
	return 0
}

func (h *workspaceHandle) Fsync(ctx context.Context, _ uint32) syscall.Errno {
	return h.Flush(ctx)
}

// Release flushes; an upload that could not be committed is given up, so nothing half
// written stays on the host.
func (h *workspaceHandle) Release(ctx context.Context) syscall.Errno {
	errno := h.Flush(ctx)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.upload != 0 {
		if name, nameErrno := h.node.guestName(); nameErrno == 0 {
			_ = h.node.files.uploadAbort(name, h.upload)
		}
		h.upload, h.pending = 0, nil
	}
	return errno
}

// mountWorkspace mounts the workspace for every guest user at workspaceMount.
func mountWorkspace(files workspaceFiles) (*fuse.Server, error) {
	return mountWorkspaceAt(workspaceMount, files)
}

// mountWorkspaceAt mounts the workspace at dir.
func mountWorkspaceAt(dir string, files workspaceFiles) (*fuse.Server, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	root := &workspaceNode{files: files, shared: &workspaceShared{executable: map[string]bool{}}, root: true, dir: true}
	ttl := workspaceAttrTTL
	return fs.Mount(dir, root, &fs.Options{
		MountOptions: fuse.MountOptions{
			AllowOther:        true,
			DirectMount:       true,
			DirectMountStrict: true,
			FsName:            "yougori-workspace",
			Name:              "yougori",
			MaxWrite:          128 * 1024,
		},
		AttrTimeout:  &ttl,
		EntryTimeout: &ttl,
		UID:          terminalUID,
		GID:          terminalGID,
	})
}
