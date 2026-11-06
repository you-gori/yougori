package setupkit

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestApplicationOutputIsBoundedWithoutStoppingTheApplication(t *testing.T) {
	root := t.TempDir()
	if err := runApplication(root, []string{"sh", "-c", "head -c 800000 /dev/zero; printf final-marker; printf final-error >&2"}); err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, name := range []string{"application.log", "application.previous.log"} {
		info, err := os.Stat(filepath.Join(root, ".yougori", name))
		if err != nil {
			t.Fatal(err)
		}
		total += info.Size()
		if info.Size() > logLimit {
			t.Fatal("log exceeds its bound")
		}
	}
	data, _ := os.ReadFile(filepath.Join(root, ".yougori", "application.log"))
	if total > 2*logLimit || !bytes.Contains(data, []byte("final-marker")) || !bytes.Contains(data, []byte("final-error")) {
		t.Fatal("application stopped early or logs did not rotate")
	}
	if err := runApplication(root, []string{"sh", "-c", "exit 7"}); err == nil {
		t.Fatal("failed application reported success")
	}
}
