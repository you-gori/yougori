package main

import (
	"context"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
)

func projectFixture(t *testing.T) (string, int, string, string) {
	t.Helper()
	root := t.TempDir()
	first := "/yougori/project-files/yougori-import-a/code"
	second := "/yougori/project-files/yougori-import-b/code"
	for _, source := range []string{first, second} {
		if err := os.MkdirAll(filepath.Join(root, source), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, source, "code.txt"), []byte("preserve source"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	return root, fd, first, second
}
func TestProjectActivationIsAtomicAndUnknownAcknowledgementIsAdopted(t *testing.T) {
	root, fd, first, second := projectFixture(t)
	request := projectActivationRequest{Target: "/app", Destination: first}
	result, err := activateProjectFiles(context.Background(), fd, request)
	if err != nil || !result["atomic"] {
		t.Fatalf("activation failed: %v", err)
	}
	result, err = activateProjectFiles(context.Background(), fd, request)
	if err != nil || !result["adopted"] {
		t.Fatalf("lost receipt was not adopted: %v", err)
	}
	request.Destination = second
	request.Previous = &first
	result, err = activateProjectFiles(context.Background(), fd, request)
	if err != nil || !result["atomic"] {
		t.Fatalf("replacement failed: %v", err)
	}
	target, err := os.Readlink(filepath.Join(root, "app"))
	if err != nil || target != second {
		t.Fatalf("wrong active link: %q / %v", target, err)
	}
	if _, err = os.Stat(filepath.Join(root, first, "code.txt")); err != nil {
		t.Fatal("previous source tree was removed")
	}
	request.Release = true
	result, err = activateProjectFiles(context.Background(), fd, request)
	if err != nil || !result["released"] {
		t.Fatalf("release failed: %v", err)
	}
	if _, err = os.Lstat(filepath.Join(root, "app")); !os.IsNotExist(err) {
		t.Fatal("owned link survived release")
	}
	if _, err = os.Stat(filepath.Join(root, second, "code.txt")); err != nil {
		t.Fatal("release removed source data")
	}
}
func TestProjectActivationPreservesUnrelatedPathsAndRefusesParentEscapes(t *testing.T) {
	root, fd, first, _ := projectFixture(t)
	os.WriteFile(filepath.Join(root, "app"), []byte("unrelated"), 0600)
	if _, err := activateProjectFiles(context.Background(), fd, projectActivationRequest{Target: "/app", Destination: first}); err == nil {
		t.Fatal("unrelated file replaced")
	}
	value, _ := os.ReadFile(filepath.Join(root, "app"))
	if string(value) != "unrelated" {
		t.Fatal("unrelated contents changed")
	}
	result, err := activateProjectFiles(context.Background(), fd, projectActivationRequest{Target: "/app", Destination: first, Release: true})
	if err != nil || !result["unrelatedPathPreserved"] {
		t.Fatal("release must preserve unrelated paths")
	}
	outside := t.TempDir()
	os.Symlink(outside, filepath.Join(root, "escape"))
	if _, err = activateProjectFiles(context.Background(), fd, projectActivationRequest{Target: "/escape/app", Destination: first}); err == nil {
		t.Fatal("symlink parent escape accepted")
	}
	if _, err = os.Lstat(filepath.Join(outside, "app")); !os.IsNotExist(err) {
		t.Fatal("activation escaped the selected root")
	}
}

// The runtime makes the working directory before the files arrive: an empty folder there takes
// the files; a folder with anything in it is kept, as any other existing path is.
func TestProjectActivationTakesTheEmptyWorkingDirectoryButKeepsOneWithContents(t *testing.T) {
	root, fd, first, _ := projectFixture(t)
	if err := os.Mkdir(filepath.Join(root, "app"), 0755); err != nil {
		t.Fatal(err)
	}
	result, err := activateProjectFiles(context.Background(), fd, projectActivationRequest{Target: "/app", Destination: first})
	if err != nil || !result["atomic"] {
		t.Fatalf("an empty working directory did not take the files: %v", err)
	}
	if target, err := os.Readlink(filepath.Join(root, "app")); err != nil || target != first {
		t.Fatalf("wrong active link: %q / %v", target, err)
	}
	if err := os.MkdirAll(filepath.Join(root, "work"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "work", "notes.txt"), []byte("the application's own"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := activateProjectFiles(context.Background(), fd, projectActivationRequest{Target: "/work", Destination: first}); err == nil {
		t.Fatal("a folder with contents was replaced")
	}
	if value, _ := os.ReadFile(filepath.Join(root, "work", "notes.txt")); string(value) != "the application's own" {
		t.Fatal("its contents changed")
	}
}

func TestProjectActivationCancellationAndMismatchedIdentityKeepBothSources(t *testing.T) {
	root, fd, first, second := projectFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := activateProjectFiles(ctx, fd, projectActivationRequest{Target: "/app", Destination: first}); err == nil {
		t.Fatal("cancelled activation changed state")
	}
	if _, err := os.Lstat(filepath.Join(root, "app")); !os.IsNotExist(err) {
		t.Fatal("cancelled activation installed a link")
	}
	os.Symlink(first, filepath.Join(root, "app"))
	wrong := "/yougori/project-files/yougori-import-unrelated/code"
	if _, err := activateProjectFiles(context.Background(), fd, projectActivationRequest{Target: "/app", Destination: second, Previous: &wrong}); err == nil {
		t.Fatal("wrong previous identity replaced")
	}
	link, _ := os.Readlink(filepath.Join(root, "app"))
	if link != first {
		t.Fatal("previous active link changed")
	}
	if _, err := activateProjectFiles(context.Background(), fd, projectActivationRequest{Target: "/app", Destination: "/etc/passwd"}); err == nil {
		t.Fatal("unprepared source accepted")
	}
}
