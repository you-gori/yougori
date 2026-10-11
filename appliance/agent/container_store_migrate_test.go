package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStorageDestinationAcceptsEmptyNerdctlScaffold(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nerdctl")
	if err := os.MkdirAll(filepath.Join(path, "filesystem-ops"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := requireEmptyStorageDirectory(path); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 0 {
		t.Fatalf("destination not empty: %v, %v", entries, err)
	}
	if err := requireEmptyStorageDirectory(path); err != nil {
		t.Fatal("retry failed:", err)
	}
}

func TestStorageDestinationPreservesUnexpectedData(t *testing.T) {
	for _, kind := range []string{"file", "nonempty", "symlink", "unknown", "other-tree"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "nerdctl")
			if kind == "other-tree" {
				path = filepath.Join(root, "containerd")
			}
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			scaffold := filepath.Join(path, "filesystem-ops")
			switch kind {
			case "file":
				if err := os.WriteFile(scaffold, []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(root, scaffold); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.Mkdir(scaffold, 0700); err != nil {
					t.Fatal(err)
				}
				if kind == "nonempty" {
					if err := os.WriteFile(filepath.Join(scaffold, "keep"), []byte("keep"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if kind == "unknown" {
					if err := os.Mkdir(filepath.Join(path, "unknown"), 0700); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := requireEmptyStorageDirectory(path); err == nil {
				t.Fatal("unexpected data accepted")
			}
			if _, err := os.Lstat(scaffold); err != nil {
				t.Fatal("existing entry was removed:", err)
			}
			if kind == "nonempty" {
				if contents, err := os.ReadFile(filepath.Join(scaffold, "keep")); err != nil || string(contents) != "keep" {
					t.Fatal("existing data changed")
				}
			}
		})
	}
}

func TestLegacyTreeMovesOnceAndKeepsALink(t *testing.T) {
	parent := t.TempDir()
	if err := os.MkdirAll(filepath.Join(parent, "old", "volumes"), 0700); err != nil {
		t.Fatal(err)
	}
	// An empty directory left by an earlier failed start is replaced.
	if err := os.Mkdir(filepath.Join(parent, "new"), 0700); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := moveLegacyTree(parent, "old", "new", true); err != nil {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
	}
	if info, err := os.Stat(filepath.Join(parent, "new", "volumes")); err != nil || !info.IsDir() {
		t.Fatalf("data was not moved: %v", err)
	}
	if target, err := os.Readlink(filepath.Join(parent, "old")); err != nil || target != "new" {
		t.Fatalf("old path is not a link to the new tree: %q, %v", target, err)
	}
	if _, err := os.Stat(filepath.Join(parent, "old", "volumes")); err != nil {
		t.Fatalf("old path does not reach the data: %v", err)
	}
}

func TestLegacyTreeMovesWithoutLinkAndIgnoresMissingTrees(t *testing.T) {
	parent := t.TempDir()
	if err := moveLegacyTree(parent, "old", "new", false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(parent, "new")); !os.IsNotExist(err) {
		t.Fatalf("a missing tree created the new path: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(parent, "old", "containers"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := moveLegacyTree(parent, "old", "new", false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(parent, "old")); !os.IsNotExist(err) {
		t.Fatalf("old tree remains: %v", err)
	}
	if _, err := os.Stat(filepath.Join(parent, "new", "containers")); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyTreeNeverReplacesExistingData(t *testing.T) {
	for _, kind := range []string{"populated", "file"} {
		t.Run(kind, func(t *testing.T) {
			parent := t.TempDir()
			if err := os.MkdirAll(filepath.Join(parent, "old", "keep"), 0700); err != nil {
				t.Fatal(err)
			}
			next := filepath.Join(parent, "new")
			if kind == "file" {
				if err := os.WriteFile(next, []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.MkdirAll(filepath.Join(next, "keep"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := moveLegacyTree(parent, "old", "new", true); err == nil {
				t.Fatal("existing data at the new path was not reported")
			}
			if _, err := os.Stat(filepath.Join(parent, "old", "keep")); err != nil {
				t.Fatalf("old data was not kept: %v", err)
			}
			if _, err := os.Lstat(next); err != nil {
				t.Fatalf("new path was not kept: %v", err)
			}
		})
	}
}
