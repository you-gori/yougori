package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// A fake PC folder endpoint: one directory holding two files, served with the
// same JSON contract the agent's host file client speaks.
func fakeHostShare(t *testing.T) (endpoint string, token string) {
	t.Helper()
	files := map[string]hostFileInfo{
		"":            {Name: "", Directory: true, Modified: 1000},
		"model.bin":   {Name: "model.bin", Size: 4, Modified: 1001},
		"tokens.json": {Name: "tokens.json", Size: 2, Modified: 1002},
		"weights":     {Name: "weights", Directory: true, Modified: 1003},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Operation string `json:"operation"`
			Path      string `json:"path"`
			Length    int    `json:"length"`
		}
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			w.WriteHeader(400)
			return
		}
		info, ok := files[request.Path]
		if !ok {
			w.WriteHeader(404)
			return
		}
		reply := hostFileReply{Info: info}
		switch request.Operation {
		case "list":
			for name, entry := range files {
				if name != "" && !strings.Contains(name, "/") {
					reply.Entries = append(reply.Entries, entry)
				}
			}
		case "read":
			reply.Data = base64.StdEncoding.EncodeToString([]byte("data")[:min(request.Length, 4)])
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(reply)
	}))
	t.Cleanup(server.Close)
	return server.URL, strings.Repeat("b", 64)
}

// Mount the share through a real FUSE mount, as a model runner sees it.
// WSL and some CI hosts have no usable /dev/fuse; there the test skips and the
// inode derivation is covered by the tests below instead.
func mountFakeShare(t *testing.T) (dir string, endpoint string, token string) {
	t.Helper()
	endpoint, token = fakeHostShare(t)
	dir = t.TempDir()
	ttl := time.Second
	root := &hostFileNode{endpoint: endpoint, token: token, readOnly: true}
	server, err := fs.Mount(dir, root, &fs.Options{MountOptions: fuse.MountOptions{DirectMount: true, FsName: "Yougori shared files", Name: "yougori"}, AttrTimeout: &ttl, EntryTimeout: &ttl})
	if err != nil {
		t.Skipf("no usable FUSE mount here: %v", err)
	}
	t.Cleanup(func() { _ = server.Unmount() })
	return dir, endpoint, token
}

func statIno(t *testing.T, name string) uint64 {
	t.Helper()
	info, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("no stat for %s", name)
	}
	return stat.Ino
}

// The defect: st_ino of a path changed after the entry timeout expired, so a
// reader that hashed a large file saw a different file afterwards.
func TestHostShareInodeSurvivesEntryTimeout(t *testing.T) {
	dir, _, _ := mountFakeShare(t)
	for _, name := range []string{"model.bin", "weights"} {
		first := statIno(t, path.Join(dir, name))
		// Longer than the 1 s EntryTimeout, so the kernel looks the name up again.
		time.Sleep(1500 * time.Millisecond)
		second := statIno(t, path.Join(dir, name))
		if first != second {
			t.Fatalf("%s changed inode across re-lookup: %d then %d", name, first, second)
		}
		if first == 0 {
			t.Fatalf("%s has inode 0", name)
		}
	}
}

func TestHostShareRootAndChildrenHaveDistinctInodes(t *testing.T) {
	dir, endpoint, token := mountFakeShare(t)
	root := statIno(t, dir)
	model := statIno(t, path.Join(dir, "model.bin"))
	tokens := statIno(t, path.Join(dir, "tokens.json"))
	if model == tokens || model == root || tokens == root {
		t.Fatalf("inodes collide: root %d, model %d, tokens %d", root, model, tokens)
	}
	// The root is mounted by go-fuse itself, which keeps its own number for it;
	// no derived number may take it, and the root keeps it across a re-lookup.
	if hostShareInode(endpoint, token, "") == hostShareRootIno || hostShareInode(endpoint, token, "model.bin") == hostShareRootIno {
		t.Fatal("a derived inode number took the root's")
	}
	time.Sleep(1500 * time.Millisecond)
	if again := statIno(t, dir); again != root {
		t.Fatalf("root changed inode: %d then %d", root, again)
	}
}

// child() is what Lookup, Create and Mkdir build every node with: it must carry
// the derived number, not leave go-fuse to allocate a fresh one.
func TestHostShareChildCarriesTheDerivedInode(t *testing.T) {
	endpoint, token := fakeHostShare(t)
	dir := t.TempDir()
	ttl := time.Second
	root := &hostFileNode{endpoint: endpoint, token: token, readOnly: true}
	server, err := fs.Mount(dir, root, &fs.Options{MountOptions: fuse.MountOptions{DirectMount: true, Name: "yougori"}, AttrTimeout: &ttl, EntryTimeout: &ttl})
	if err != nil {
		t.Skipf("no usable FUSE mount here: %v", err)
	}
	defer func() { _ = server.Unmount() }()
	child := root.child(context.Background(), "model.bin", hostFileInfo{Name: "model.bin", Size: 4})
	want := hostShareInode(endpoint, token, "model.bin")
	if child.StableAttr().Ino != want {
		t.Fatalf("child inode %d, want %d", child.StableAttr().Ino, want)
	}
	if child.StableAttr().Gen != 1 {
		t.Fatalf("child generation %d, want 1", child.StableAttr().Gen)
	}
	again := root.child(context.Background(), "model.bin", hostFileInfo{Name: "model.bin", Size: 4})
	if again.StableAttr().Ino != want {
		t.Fatalf("second child inode %d, want %d", again.StableAttr().Ino, want)
	}
}

func TestHostShareInodeIsStableDistinctAndReserved(t *testing.T) {
	const endpoint, token = "http://10.0.2.2:7000", "a1b2"
	if hostShareInode(endpoint, token, "model.bin") != hostShareInode(endpoint, token, "model.bin") {
		t.Fatal("the same path gave two inode numbers")
	}
	if hostShareInode(endpoint, token, "model.bin") == hostShareInode(endpoint, token, "tokens.json") {
		t.Fatal("two paths in one share share an inode number")
	}
	// Two shares in one mount namespace: same relative path, different token.
	if hostShareInode(endpoint, token, "model.bin") == hostShareInode(endpoint, "c3d4", "model.bin") {
		t.Fatal("two shares give the same path the same inode number")
	}
	if hostShareInode(endpoint, token, "model.bin") == hostShareInode("http://10.0.2.2:7001", token, "model.bin") {
		t.Fatal("two endpoints give the same path the same inode number")
	}
	// The separator must not let a different split produce the same number.
	if hostShareInode("a", "b", "c") == hostShareInode("a\x00b", "", "c") {
		t.Fatal("the share identity and the path run together")
	}
	seen := map[uint64]string{}
	for i := 0; i < 20000; i++ {
		relative := fmt.Sprintf("weights/shard-%d.safetensors", i)
		ino := hostShareInode(endpoint, token, relative)
		if ino == 0 || ino == hostShareRootIno {
			t.Fatalf("%s got the reserved inode %d", relative, ino)
		}
		if other, clash := seen[ino]; clash {
			t.Fatalf("%s and %s collide on inode %d", relative, other, ino)
		}
		seen[ino] = relative
	}
}
