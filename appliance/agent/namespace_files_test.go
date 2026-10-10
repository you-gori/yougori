package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func namespaceFixture(t *testing.T) (string, int) {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "etc"), 0755); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	return root, fd
}

func TestNamespaceConfigurationAbsoluteLinksStayInsideWorkload(t *testing.T) {
	root, fd := namespaceFixture(t)
	if err := os.MkdirAll(filepath.Join(root, "run/resolve"), 0755); err != nil {
		t.Fatal(err)
	}
	wanted := []byte("nameserver 10.0.2.3\n")
	if err := os.WriteFile(filepath.Join(root, "run/resolve/resolv.conf"), wanted, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/run/resolve/resolv.conf", filepath.Join(root, "etc/resolv.conf")); err != nil {
		t.Fatal(err)
	}
	file, err := openNamespaceConfig(fd, "etc/resolv.conf", os.O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	got, err := readNamespaceConfig(file)
	if err != nil || string(got) != string(wanted) {
		t.Fatalf("read = %q, %v", got, err)
	}
}

func TestNamespaceConfigurationCannotOverwriteOutsideFile(t *testing.T) {
	for _, redirect := range []string{"leaf", "ancestor"} {
		t.Run(redirect, func(t *testing.T) {
			root, fd := namespaceFixture(t)
			outside := t.TempDir()
			marker := filepath.Join(outside, "hosts")
			wanted := []byte("private appliance file must stay unchanged")
			if err := os.WriteFile(marker, wanted, 0600); err != nil {
				t.Fatal(err)
			}
			if redirect == "leaf" {
				if err := os.Symlink(marker, filepath.Join(root, "etc/hosts")); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Remove(filepath.Join(root, "etc")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, filepath.Join(root, "etc")); err != nil {
					t.Fatal(err)
				}
			}
			if file, err := openNamespaceConfig(fd, "etc/hosts", os.O_RDWR); err == nil {
				file.Close()
				t.Fatal("outside configuration opened")
			}
			got, err := os.ReadFile(marker)
			if err != nil || string(got) != string(wanted) {
				t.Fatalf("outside changed: %q, %v", got, err)
			}
		})
	}
}

func TestNamespaceConfigurationRejectsDevicesPipesAndOversizedFiles(t *testing.T) {
	root, fd := namespaceFixture(t)
	name := filepath.Join(root, "etc/hosts")
	if err := unix.Mkfifo(name, 0600); err != nil {
		t.Fatal(err)
	}
	if file, err := openNamespaceConfig(fd, "etc/hosts", os.O_RDONLY); err == nil {
		file.Close()
		t.Fatal("FIFO accepted")
	}
	if err := os.Remove(name); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(strings.Repeat("x", maxNamespaceConfigBytes+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if file, err := openNamespaceConfig(fd, "etc/hosts", os.O_RDWR); err == nil {
		file.Close()
		t.Fatal("oversized configuration accepted")
	}
	if file, err := openNamespaceConfig(fd, "etc/shadow", os.O_RDONLY); err == nil {
		file.Close()
		t.Fatal("unexpected path accepted")
	}
}

func TestNamespaceConfigurationKeepsPinnedInodeWhenPathChanges(t *testing.T) {
	root, fd := namespaceFixture(t)
	name := filepath.Join(root, "etc/hosts")
	if err := os.WriteFile(name, []byte("initial\n"), 0644); err != nil {
		t.Fatal(err)
	}
	file, err := openNamespaceConfig(fd, "etc/hosts", os.O_RDWR)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	saved := filepath.Join(root, "etc/original-hosts")
	if err := os.Rename(name, saved); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte("replacement must stay unchanged\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte("updated"), 0); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(name)
	if err != nil || string(got) != "replacement must stay unchanged\n" {
		t.Fatalf("replacement changed: %q, %v", got, err)
	}
}
