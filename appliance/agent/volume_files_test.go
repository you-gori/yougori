package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestVolumeAtOpensOnlyTheContainersOwnVolumes(t *testing.T) {
	data := "/var/lib/nerdctl/1935db59/volumes/" + namespace + "/setup-c063af37-data/_data"
	cache := "/var/lib/nerdctl/1935db59/volumes/" + namespace + "/models/_data"
	mounts := fmt.Sprintf(`[
		{"Type":"volume","Source":%q,"Destination":"/data"},
		{"Type":"volume","Source":%q,"Destination":"/data/cache"},
		{"Type":"bind","Source":"/run/yougori/host-shares/pc-1","Destination":"/mnt/pc"},
		{"Type":"bind","Source":"/var/lib/nerdctl/1935db59/volumes/other/x/_data","Destination":"/elsewhere"},
		{"Type":"volume","Source":%q,"Destination":"/"}
	]`, data, cache, data)
	var asked []string
	execute := func(_ context.Context, program string, args ...string) (commandOutput, error) {
		asked = append([]string{program}, args...)
		return commandOutput{Stdout: mounts}, nil
	}
	for _, check := range []struct {
		full, source, rest string
		found              bool
	}{
		{"/data", data, ".", true},
		{"/data/greeting.txt", data, "greeting.txt", true},
		{"/data/sub/file", data, "sub/file", true},
		// The longest mount wins: a volume mounted inside another is its own volume.
		{"/data/cache/model.bin", cache, "model.bin", true},
		{"/database", "", "", false},
		{"/mnt/pc/secret", "", "", false},
		{"/elsewhere/x", "", "", false},
		{"/etc/passwd", "", "", false},
	} {
		source, rest, found, err := volumeAt(context.Background(), "env-1", check.full, execute)
		if err != nil {
			t.Fatalf("%s: %v", check.full, err)
		}
		if source != check.source || rest != check.rest || found != check.found {
			t.Fatalf("%s: got (%q, %q, %v), want (%q, %q, %v)", check.full, source, rest, found, check.source, check.rest, check.found)
		}
	}
	if fmt.Sprint(asked) != fmt.Sprint([]string{"nerdctl", "--namespace", namespace, "inspect", "--format", "{{json .Mounts}}", "env-1"}) {
		t.Fatalf("asked containerd %v", asked)
	}
	for _, bad := range []string{"data", "/data/../etc", "/data/"} {
		if _, _, _, err := volumeAt(context.Background(), "env-1", bad, execute); err == nil {
			t.Fatalf("%q must be refused before containerd is asked", bad)
		}
	}
}

func TestOpenVolumeRefusesAnythingOutsideTheVolumeStore(t *testing.T) {
	folder := t.TempDir()
	if _, err := openVolume(folder); err == nil {
		t.Fatal("a folder outside the volume store must not open")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(folder, link); err != nil {
		t.Fatal(err)
	}
	if _, err := openVolume(link); err == nil {
		t.Fatal("a link must not open")
	}
}

// A volume opened at its own folder serves the ordinary file operations, and a mount below it is
// still refused, as everywhere else.
func TestRemoteFilesReadAVolumeFolderOpenedAtItsRoot(t *testing.T) {
	volume := t.TempDir()
	if err := os.WriteFile(filepath.Join(volume, "greeting.txt"), []byte("hello-a"), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := unix.Open(volume, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(root)
	stat, err := remoteFileOperation(root, remoteFileRequest{Operation: "stat", Path: ".", ReadOnly: true})
	if err != nil || stat.(map[string]interface{})["info"].(map[string]interface{})["directory"] != true {
		t.Fatalf("the volume itself reads as a folder: %v %v", stat, err)
	}
	read, err := remoteFileOperation(root, remoteFileRequest{Operation: "read", Path: "greeting.txt", ReadOnly: true})
	if err != nil || read.(map[string]string)["data"] != "aGVsbG8tYQ==" {
		t.Fatalf("read %v %v", read, err)
	}
	if _, err := remoteFileOperation(root, remoteFileRequest{Operation: "remove", Path: ".", ReadOnly: false}); err == nil {
		t.Fatal("the volume root itself is never removed")
	}
}
