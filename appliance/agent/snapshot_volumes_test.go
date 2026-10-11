package main

import (
	"archive/tar"
	"bytes"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestSnapshotIncludesPrivateVolumeDataHiddenFilesPermissionsAndLinks(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "crm.db"), []byte("actual database"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Setxattr(filepath.Join(directory, "crm.db"), "user.yougori-fixture", []byte("attribute-value"), 0); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, ".env"), []byte("SECRET=belongs-to-environment"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/shadow", filepath.Join(directory, "outside")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(directory, "crm.db"), filepath.Join(directory, "database-link")); err != nil {
		t.Fatal(err)
	}
	var original bytes.Buffer
	writer := tar.NewWriter(&original)
	for name, data := range map[string]string{"data/crm.db": "stale layer database", "data/old": "not in mounted volume", "app/code": "code"} {
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		_, _ = writer.Write([]byte(data))
	}
	_ = writer.Close()
	var output bytes.Buffer
	if err := mergeSnapshotVolumes(&output, &original, []snapshotVolume{{Source: directory, Destination: "/data"}}); err != nil {
		t.Fatal(err)
	}
	reader := tar.NewReader(&output)
	contents := make(map[string]string)
	headers := make(map[string]*tar.Header)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		contents[header.Name] = string(data)
		headers[header.Name] = header
	}
	if contents["data/crm.db"] != "actual database" || contents["data/.env"] != "SECRET=belongs-to-environment" || contents["app/code"] != "code" {
		t.Fatalf("missing complete copy: %v", contents)
	}
	if _, exists := contents["data/old"]; exists {
		t.Fatal("shadowed rootfs leaked into volume copy")
	}
	if headers["data/crm.db"].Mode != 0600 || headers["data/outside"].Typeflag != tar.TypeSymlink || headers["data/outside"].Linkname != "/etc/shadow" {
		t.Fatal("permissions or symlinks changed")
	}
	if headers["data/crm.db"].PAXRecords["SCHILY.xattr.user.yougori-fixture"] != "attribute-value" {
		t.Fatal("extended attributes were lost")
	}
	if headers["data/database-link"].Typeflag != tar.TypeLink || headers["data/database-link"].Linkname != "data/crm.db" {
		t.Fatal("hardlink identity was lost")
	}
}

func TestSnapshotDoesNotIncludeExternalMounts(t *testing.T) {
	volumes, err := privateSnapshotVolumes([]snapshotVolume{{Source: "/var/lib/yougori/shares/host", Destination: "/host"}, {Source: "/proc", Destination: "/proc"}})
	if err != nil || len(volumes) != 0 {
		t.Fatalf("external files were included: %v / %v", volumes, err)
	}
	if !underVolume("data/.env", []snapshotVolume{{Destination: "/data"}}) || underVolume("database/file", []snapshotVolume{{Destination: "/data"}}) {
		t.Fatal("invalid prefix confinement")
	}
}
