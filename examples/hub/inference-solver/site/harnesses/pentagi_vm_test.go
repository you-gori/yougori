package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"github.com/moby/moby/client"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testYougoriVM(t *testing.T) *vmClient {
	t.Helper()
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return &vmClient{root: root, workers: map[string]bool{"worker": true}, aliases: map[string]string{"worker": "worker", "alias": "worker"}, executions: map[string]*vmExecution{}}
}
func TestYougoriVMRunsInItsImageOrOnTheSharedBase(t *testing.T) {
	vm := map[string]string{"SOLVER_VM_RUNTIME": "1"}
	shared := map[string]string{"SOLVER_VM_RUNTIME": "1", "SOLVER_HARNESS": "pentagi"}
	cases := []struct {
		marker string
		vars   map[string]string
		want   bool
	}{
		{"pentagi\n", vm, true},
		{"yougori\n", shared, true},
		{"yougori\n", vm, false},
		{"yougori\n", map[string]string{"SOLVER_VM_RUNTIME": "1", "SOLVER_HARNESS": "strix"}, false},
		{"strix\n", shared, false},
		{"pentagi\n", map[string]string{"SOLVER_HARNESS": "pentagi"}, false},
	}
	for _, c := range cases {
		vars := c.vars
		if got := yougoriVMHere(c.marker, func(key string) string { return vars[key] }); got != c.want {
			t.Errorf("%q with %v: got %v, want %v", c.marker, c.vars, got, c.want)
		}
	}
}

func TestYougoriVMCommandsGetTheSecretAnswersAndNothingElse(t *testing.T) {
	env := vmCommandEnv([]string{"YOUGORI_SECRET_LOGIN_PASSWORD=pass word", "OPENAI_API_KEY=key", "PATH=/elsewhere", "YOUGORI_SECRETS=no", "HOME=/root"})
	want := []string{"PATH=/opt/solver/tool/bin:/usr/local/bin:/usr/bin:/bin", "HOME=/home/node", "LANG=C.UTF-8", "TERM=xterm-256color", "YOUGORI_SECRET_LOGIN_PASSWORD=pass word"}
	if strings.Join(env, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got %q, want %q", env, want)
	}
}

func TestYougoriVMFilesAndTraversal(t *testing.T) {
	v := testYougoriVM(t)
	ctx := context.Background()
	makeArchive := func(name string, kind byte) io.Reader {
		var b bytes.Buffer
		tw := tar.NewWriter(&b)
		h := &tar.Header{Name: name, Mode: 0600, Typeflag: kind}
		if kind == tar.TypeReg {
			h.Size = 5
		}
		if kind == tar.TypeSymlink {
			h.Linkname = "/etc/passwd"
		}
		tw.WriteHeader(h)
		if kind == tar.TypeReg {
			tw.Write([]byte("hello"))
		}
		tw.Close()
		return &b
	}
	for _, name := range []string{"../escape", "/absolute", "folder/../../escape"} {
		if v.CopyToContainer(ctx, "worker", "/work", makeArchive(name, tar.TypeReg), client.CopyToContainerOptions{}) == nil {
			t.Fatal("accepted escape", name)
		}
	}
	if v.CopyToContainer(ctx, "worker", "/work", makeArchive("link", tar.TypeSymlink), client.CopyToContainerOptions{}) == nil {
		t.Fatal("accepted link")
	}
	if err := v.CopyToContainer(ctx, "alias", "/work", makeArchive("folder/file", tar.TypeReg), client.CopyToContainerOptions{}); err != nil {
		t.Fatal(err)
	}
	got, stat, err := v.CopyFromContainer(ctx, "worker", "/work/folder/file")
	if err != nil {
		t.Fatal(err)
	}
	defer got.Close()
	if stat.Size != 5 {
		t.Fatal(stat)
	}
	tr := tar.NewReader(got)
	if _, err := tr.Next(); err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(tr)
	if string(data) != "hello" {
		t.Fatal(string(data))
	}
	if _, err := v.ContainerStatPath(ctx, "worker", "/etc/passwd"); err == nil {
		t.Fatal("accepted outside file")
	}
}
func TestYougoriVMExecIsRealAndAliasCancellation(t *testing.T) {
	v := testYougoriVM(t)
	ctx := context.Background()
	if err := os.MkdirAll("/work", 0700); err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp("/work", "runtime-check-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	made, err := v.ContainerExecCreate(ctx, "alias", client.ExecCreateOptions{Cmd: []string{"/bin/sh", "-c", "printf verified > result; cat result"}, WorkingDir: directory})
	if err != nil {
		t.Fatal(err)
	}
	response, err := v.ContainerExecAttach(ctx, made.ID, client.ExecAttachOptions{})
	if err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(response.Reader)
	response.Close()
	if err != nil || string(output) != "verified" {
		t.Fatal(string(output), err)
	}
	stored, err := os.ReadFile(filepath.Join(directory, "result"))
	if err != nil || string(stored) != "verified" {
		t.Fatal(err)
	}
	status, err := v.ContainerExecInspect(ctx, made.ID)
	if err != nil || status.Running || status.ExitCode != 0 {
		t.Fatal(status, err)
	}
	if _, err := v.ContainerExecAttach(ctx, made.ID, client.ExecAttachOptions{}); err == nil {
		t.Fatal("execution replayed")
	}
	waiting, err := v.ContainerExecCreate(ctx, "alias", client.ExecCreateOptions{Cmd: []string{"/bin/sh", "-c", "echo started; sleep 60"}, WorkingDir: directory})
	if err != nil {
		t.Fatal(err)
	}
	response, err = v.ContainerExecAttach(ctx, waiting.ID, client.ExecAttachOptions{})
	if err != nil {
		t.Fatal(err)
	}
	line, _ := response.Reader.ReadString('\n')
	if strings.TrimSpace(line) != "started" {
		t.Fatal(line)
	}
	if err = v.KillFlowCommands(ctx, "worker"); err != nil {
		t.Fatal(err)
	}
	io.ReadAll(response.Reader)
	response.Close()
	status, err = v.ContainerExecInspect(ctx, waiting.ID)
	if err != nil || status.Running || status.ExitCode == 0 {
		t.Fatal(status, err)
	}
}
