package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// A container whose writable layer is missing is incomplete, not redirected: found on a real
// runtime whose machine was stopped hard right after it made a container, which then failed every
// later change with "private storage path was redirected". Links stay refused as before.
func TestAMissingWritableLayerIsAnIncompleteContainerAndALinkIsStillARedirect(t *testing.T) {
	snapshots := t.TempDir() + "/snapshots/"
	present := snapshots + "1/fs"
	if err := os.MkdirAll(present, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := storageRootProblem(present, snapshots); err != nil {
		t.Fatalf("a present layer: %v", err)
	}
	if err := storageRootProblem(snapshots+"2/fs", snapshots); !errors.Is(err, errIncompleteContainer) {
		t.Fatalf("a missing layer: %v", err)
	}
	link := snapshots + "3"
	if err := os.Symlink(filepath.Dir(present), link); err != nil {
		t.Skip("links are not available here:", err)
	}
	if err := storageRootProblem(link+"/fs", snapshots); err == nil || errors.Is(err, errIncompleteContainer) {
		t.Fatalf("a link: %v", err)
	}
	if err := storageRootProblem(t.TempDir()+"/logs/missing", snapshots); err == nil || errors.Is(err, errIncompleteContainer) {
		t.Fatalf("a missing path outside the writable layer is not called incomplete: %v", err)
	}
	if err := storageRootProblem(snapshots+"1/../1/fs", snapshots); err == nil {
		t.Fatal("a path that is not canonical is refused")
	}
}
