package main

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
)

// PROVES the workspace mount returns and serves through the kernel (it needs root and
// /dev/fuse, as the guest agent has them): a listing, a read, a write back and a new file
// reach the workspace, and the mount comes off.
func TestTheWorkspaceMountReturnsAndServes(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("mounting needs root")
	}
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skip("no /dev/fuse")
	}
	dir := t.TempDir()
	files := &lockedFiles{files: map[string][]byte{"main.py": []byte("print(1)\n")}}
	type mounted struct {
		server *fuse.Server
		err    error
	}
	done := make(chan mounted, 1)
	go func() {
		server, err := mountWorkspaceAt(dir, files)
		done <- mounted{server, err}
	}()
	var server *fuse.Server
	select {
	case result := <-done:
		if result.err != nil {
			t.Fatalf("mount: %v", result.err)
		}
		server = result.server
	case <-time.After(15 * time.Second):
		t.Fatal("the mount did not return within 15 s")
	}
	defer server.Unmount()
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "main.py" {
		t.Fatalf("listing: %v %v", entries, err)
	}
	content, err := os.ReadFile(filepath.Join(dir, "main.py"))
	if err != nil || string(content) != "print(1)\n" {
		t.Fatalf("read: %q %v", content, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.py"), []byte("print(2)\n"), 0o644); err != nil {
		t.Fatalf("write back: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "new.txt"), []byte("new\n"), 0o644); err != nil {
		t.Fatalf("new file: %v", err)
	}
	if got, _ := files.read("main.py"); string(got) != "print(2)\n" {
		t.Fatalf("the write back did not reach the workspace: %q", got)
	}
	if got, _ := files.read("new.txt"); string(got) != "new\n" {
		t.Fatalf("the new file did not reach the workspace: %q", got)
	}
	// An editor's or sed -i's temporary file put over the original: POSIX rename replaces.
	if err := os.WriteFile(filepath.Join(dir, "main.py.tmp"), []byte("print(3)\n"), 0o644); err != nil {
		t.Fatalf("temporary file: %v", err)
	}
	if err := os.Rename(filepath.Join(dir, "main.py.tmp"), filepath.Join(dir, "main.py")); err != nil {
		t.Fatalf("rename over an existing file: %v", err)
	}
	if got, _ := files.read("main.py"); string(got) != "print(3)\n" {
		t.Fatalf("the rename did not replace the original: %q", got)
	}
	if _, err := files.read("main.py.tmp"); err == nil {
		t.Fatal("the temporary name is still there")
	}
	// The renamed node reads under its new name (sed -i then cat, 31 October 2026).
	if got, err := os.ReadFile(filepath.Join(dir, "main.py")); err != nil || string(got) != "print(3)\n" {
		t.Fatalf("read after the rename: %q %v", got, err)
	}
	// A file renamed while open is written back under its new name when it is closed.
	open, err := os.Create(filepath.Join(dir, "draft.txt"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := open.WriteString("final\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Rename(filepath.Join(dir, "draft.txt"), filepath.Join(dir, "final.txt")); err != nil {
		t.Fatalf("rename while open: %v", err)
	}
	if err := open.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got, _ := files.read("final.txt"); string(got) != "final\n" {
		t.Fatalf("the flush did not follow the rename: %q", got)
	}
	// A file past the small bound moves in ranges and uploads: written, read back and
	// edited in place through the kernel, it is exact on the host, and no upload is left.
	large := make([]byte, 5<<20+12345)
	for at := range large {
		large[at] = byte(at*7 + at>>11)
	}
	if err := os.WriteFile(filepath.Join(dir, "large.bin"), large, 0o644); err != nil {
		t.Fatalf("large write: %v", err)
	}
	if got, _ := files.read("large.bin"); !bytes.Equal(got, large) {
		t.Fatalf("the large file did not reach the workspace whole: %d bytes", len(got))
	}
	time.Sleep(workspaceAttrTTL + 500*time.Millisecond)
	read, err := os.ReadFile(filepath.Join(dir, "large.bin"))
	if err != nil || sha256.Sum256(read) != sha256.Sum256(large) {
		t.Fatalf("large read back: %d bytes, %v", len(read), err)
	}
	edit, err := os.OpenFile(filepath.Join(dir, "large.bin"), os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open for an edit: %v", err)
	}
	if _, err := edit.WriteAt([]byte("EDITED"), 3<<20); err != nil {
		t.Fatalf("edit: %v", err)
	}
	if err := edit.Close(); err != nil {
		t.Fatalf("close the edit: %v", err)
	}
	copy(large[3<<20:], "EDITED")
	if got, _ := files.read("large.bin"); !bytes.Equal(got, large) {
		t.Fatal("the edit in place did not reach the workspace exactly")
	}
	files.mu.Lock()
	left := len(files.uploads)
	largest := files.largestChunk
	files.mu.Unlock()
	if left != 0 || largest > rangeBytes {
		t.Fatalf("%d uploads left, largest chunk %d", left, largest)
	}
	// An execute bit set by a program stays for the mount, though the host keeps none.
	if err := os.Chmod(filepath.Join(dir, "new.txt"), 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	time.Sleep(workspaceAttrTTL + 500*time.Millisecond)
	info, err := os.Stat(filepath.Join(dir, "new.txt"))
	if err != nil || info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("the execute bit did not last: %v %v", info, err)
	}
}
