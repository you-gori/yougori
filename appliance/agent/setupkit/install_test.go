package setupkit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInstallIsOfflineAndRepeatable(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 2; i++ {
		if err := Install(root); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"yougori.py", "node_modules/yougori/index.mjs", "node_modules/yougori/index.d.ts", ".agents/skills/yougori-setup/SKILL.md"} {
		if info, err := os.Stat(filepath.Join(root, name)); err != nil || info.Size() == 0 {
			t.Fatalf("missing asset %s: %v", name, err)
		}
	}
}

func TestInstallRefusesConflictsAndLinkedDirectories(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "yougori.py"), []byte("author file"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Install(root); err == nil {
		t.Fatal("replaced an author's module")
	}
	data, _ := os.ReadFile(filepath.Join(root, "yougori.py"))
	if string(data) != "author file" {
		t.Fatal("changed the file")
	}
	root = t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "node_modules")); err != nil {
		t.Skip(err)
	}
	if err := Install(root); err == nil {
		t.Fatal("followed external directory link")
	}
	entries, _ := os.ReadDir(outside)
	if len(entries) != 0 {
		t.Fatal("wrote outside the workspace")
	}
}
