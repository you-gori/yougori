//go:build linux

package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestImageEntrypointKeepsArgvAsDataAndNeedsNoShell(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "bin"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bin", "tool"), []byte("fixture"), 0755); err != nil {
		t.Fatal(err)
	}
	process := workloadProcess{Entrypoint: []string{"tool", "--literal"}, Cmd: []string{"$(touch /bad)", "a b", "'\""}, Env: []string{"PATH=/bin"}}
	program, argv, err := imageCommand(root, process)
	if err != nil || program != "/bin/tool" {
		t.Fatalf("program %q: %v", program, err)
	}
	if !reflect.DeepEqual(argv, []string{"tool", "--literal", "$(touch /bad)", "a b", "'\""}) {
		t.Fatalf("argv changed: %q", argv)
	}
	if _, err := os.Stat(filepath.Join(root, "bin", "sh")); !os.IsNotExist(err) {
		t.Fatal("fixture must have no shell")
	}
	if _, _, err := imageCommand("", process); err == nil {
		t.Fatal("no image was accepted")
	}
	if _, _, err := imageCommand(root, workloadProcess{}); err == nil {
		t.Fatal("no command was accepted")
	}
}

func TestImageProcessRefusesPrivilegedIdentityAndMalformedEnvironment(t *testing.T) {
	for _, p := range []workloadProcess{{User: "0"}, {User: "root"}, {Env: []string{"=value"}}, {Env: []string{"KEY"}}, {WorkingDir: "relative"}, {Cmd: []string{"a\x00b"}}} {
		if validateImageProcess(p) == nil {
			t.Fatalf("accepted %+v", p)
		}
	}
	if err := validateImageProcess(workloadProcess{User: "1000:1000", Env: []string{"KEY=a=b"}, WorkingDir: "/app"}); err != nil {
		t.Fatal(err)
	}
}
