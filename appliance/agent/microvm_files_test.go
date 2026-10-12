package main

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// A disposable microVM whose tool runs in an OCI workload: the agent's saved
// workload record, a nerdctl adapter that logs each call and reports the
// workload's main PID, and that process's root inside a private /proc tree.
func useMicroWorkload(t *testing.T, pid string) (string, string) {
	t.Helper()
	record := filepath.Join(t.TempDir(), "microvm-workload.json")
	if err := os.WriteFile(record, []byte(`{"image":"ubuntu:24.04"}`), 0600); err != nil {
		t.Fatal(err)
	}
	previousRecord, previousProc := microWorkloadPath, procDirectory
	t.Cleanup(func() { microWorkloadPath, procDirectory = previousRecord, previousProc })
	microWorkloadPath, procDirectory = record, t.TempDir()
	root := filepath.Join(procDirectory, pid, "root")
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	calls := filepath.Join(bin, "calls")
	adapter := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '" + calls + "'\nprintf '%s\\n' '" + pid + "'\n"
	if err := os.WriteFile(filepath.Join(bin, "nerdctl"), []byte(adapter), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	return root, calls
}

const workloadInspection = "--namespace yougori-workload inspect --format {{.State.Pid}} app\n"

func TestFilesProcessChoosesTheContainerTheMicroVMWorkloadOrTheMicroVM(t *testing.T) {
	_, calls := useMicroWorkload(t, "4242")
	ctx := context.Background()
	for _, s := range []*server{{microVM: true}, {}} {
		if process, err := s.filesProcess(ctx, "env-fixture"); err != nil || process != procDirectory+"/4242" {
			t.Fatalf("microVM=%v: process %q, error %v", s.microVM, process, err)
		}
	}
	want := workloadInspection + "--namespace " + namespace + " inspect --format {{.State.Pid}} env-fixture\n"
	if logged, _ := os.ReadFile(calls); string(logged) != want {
		t.Fatalf("unexpected nerdctl calls:\n%s", logged)
	}
	// Without a workload, a microVM's files are in its own root.
	if err := os.Remove(microWorkloadPath); err != nil {
		t.Fatal(err)
	}
	if process, err := (&server{microVM: true}).filesProcess(ctx, "env-fixture"); err != nil || process != "" {
		t.Fatalf("microVM without a workload: process %q, error %v", process, err)
	}
	if logged, _ := os.ReadFile(calls); string(logged) != want {
		t.Fatal("a microVM without a workload inspected one")
	}
}

func TestMicroVMFileImportReachesTheWorkload(t *testing.T) {
	root, calls := useMicroWorkload(t, "4242")
	var filesystem unix.Statfs_t
	if err := unix.Statfs(root, &filesystem); err != nil || filesystem.Type != unix.EXT4_SUPER_MAGIC && filesystem.Type != unix.OVERLAYFS_SUPER_MAGIC {
		t.Skip("file import needs TMPDIR on ext4 or overlayfs, like a guest disk")
	}
	uid, gid := os.Getuid(), os.Getgid()
	if os.Geteuid() == 0 {
		// The workload's process owner, not the agent, owns the copy.
		uid, gid = 4321, 4322
		if err := os.Chown(filepath.Join(procDirectory, "4242"), uid, gid); err != nil {
			t.Fatal(err)
		}
	}
	// The private stage that credential import creates inside the tool's sandbox.
	stage := filepath.Join(root, "root", ".yougori-credentials-fixture")
	if err := os.MkdirAll(stage, 0700); err != nil {
		t.Fatal(err)
	}
	transfer := strings.Repeat("c", 32)
	archive := importArchive(t, &tar.Header{Name: "auth.json", Typeflag: tar.TypeReg, Size: 8, Mode: 0600})
	request := httptest.NewRequest("POST", "/v1/files/import?id=env-fixture&transfer="+transfer+"&folder=/root/.yougori-credentials-fixture", bytes.NewReader(archive))
	reply := httptest.NewRecorder()
	(&server{microVM: true}).importFiles(reply, request)
	if reply.Code != 200 {
		t.Fatal(reply.Code, reply.Body.String())
	}
	var result struct{ Destination string }
	if err := json.Unmarshal(reply.Body.Bytes(), &result); err != nil || result.Destination != "/root/.yougori-credentials-fixture/yougori-import-"+transfer {
		t.Fatalf("destination %q: %v", result.Destination, err)
	}
	copied := filepath.Join(stage, "yougori-import-"+transfer, "auth.json")
	data, err := os.ReadFile(copied)
	if err != nil || !bytes.Equal(data, bytes.Repeat([]byte{0x42}, 8)) {
		t.Fatal("the copy did not reach the workload's filesystem", err)
	}
	var stat unix.Stat_t
	if err := unix.Lstat(copied, &stat); err != nil || int(stat.Uid) != uid || int(stat.Gid) != gid {
		t.Fatalf("copy owned by %d:%d, want the workload process owner %d:%d", stat.Uid, stat.Gid, uid, gid)
	}
	if logged, _ := os.ReadFile(calls); string(logged) != workloadInspection {
		t.Fatalf("unexpected nerdctl calls:\n%s", logged)
	}
}

func TestMicroVMRemoteFilesReadAndEditTheWorkload(t *testing.T) {
	root, _ := useMicroWorkload(t, "4242")
	if err := os.MkdirAll(filepath.Join(root, "workspace"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "workspace", "report.txt"), []byte("from the workload"), 0644); err != nil {
		t.Fatal(err)
	}
	s := &server{microVM: true}
	call := func(request remoteFileRequest) map[string]interface{} {
		t.Helper()
		request.ID, request.Root = "env-fixture", "/workspace"
		body, _ := json.Marshal(request)
		reply := httptest.NewRecorder()
		s.remoteFiles(reply, httptest.NewRequest("POST", "/v1/remote/files", bytes.NewReader(body)))
		var value map[string]interface{}
		if reply.Code != 200 || json.Unmarshal(reply.Body.Bytes(), &value) != nil {
			t.Fatal(request.Operation, reply.Code, reply.Body.String())
		}
		return value
	}
	// Copying out (`yougori cp`) and shared folders read through this API.
	read := call(remoteFileRequest{Operation: "read", Path: "report.txt", ReadOnly: true, Length: 64})
	if read["data"] != base64.StdEncoding.EncodeToString([]byte("from the workload")) {
		t.Fatalf("read %v", read)
	}
	// An edit grant writes into the workload as well.
	call(remoteFileRequest{Operation: "create", Path: "notes.txt"})
	call(remoteFileRequest{Operation: "write", Path: "notes.txt", Data: base64.StdEncoding.EncodeToString([]byte("edited"))})
	if data, err := os.ReadFile(filepath.Join(root, "workspace", "notes.txt")); err != nil || string(data) != "edited" {
		t.Fatal("edit did not reach the workload's filesystem", err)
	}
}

func TestMicroVMProjectFilesActivateInTheWorkload(t *testing.T) {
	root, _ := useMicroWorkload(t, "4242")
	source := "/yougori/project-files/yougori-import-a/code"
	if err := os.MkdirAll(filepath.Join(root, source), 0700); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(projectActivationRequest{ID: "env-fixture", Target: "/app", Destination: source})
	reply := httptest.NewRecorder()
	(&server{microVM: true}).activateProjectFiles(reply, httptest.NewRequest("POST", "/v1/project-files/activate", bytes.NewReader(body)))
	if reply.Code != 200 {
		t.Fatal(reply.Code, reply.Body.String())
	}
	if target, err := os.Readlink(filepath.Join(root, "app")); err != nil || target != source {
		t.Fatalf("workload link %q: %v", target, err)
	}
}

func TestMicroVMFileAPIsNeverFallBackToTheOuterGuestWhenTheWorkloadIsStopped(t *testing.T) {
	useMicroWorkload(t, "0")
	s := &server{microVM: true}
	// A real folder of the microVM's own root, which a fallback would use.
	outer := t.TempDir()
	if err := os.WriteFile(filepath.Join(outer, "outer-only"), []byte("outer guest"), 0600); err != nil {
		t.Fatal(err)
	}
	refused := func(operation string, reply *httptest.ResponseRecorder, message string) {
		t.Helper()
		if reply.Code != 409 || !strings.Contains(reply.Body.String(), message) {
			t.Fatal(operation, reply.Code, reply.Body.String())
		}
	}
	archive := importArchive(t, &tar.Header{Name: "auth.json", Typeflag: tar.TypeReg, Size: 8, Mode: 0600})
	reply := httptest.NewRecorder()
	s.importFiles(reply, httptest.NewRequest("POST", "/v1/files/import?id=env-fixture&transfer="+strings.Repeat("d", 32)+"&folder="+outer, bytes.NewReader(archive)))
	refused("import", reply, "Start this environment before copying files")
	if entries, _ := os.ReadDir(outer); len(entries) != 1 {
		t.Fatal("import wrote into the microVM's own root")
	}
	body, _ := json.Marshal(remoteFileRequest{ID: "env-fixture", Root: outer, Operation: "read", Path: "outer-only", ReadOnly: true})
	reply = httptest.NewRecorder()
	s.remoteFiles(reply, httptest.NewRequest("POST", "/v1/remote/files", bytes.NewReader(body)))
	refused("remote files", reply, "start the environment before accessing files")
	body, _ = json.Marshal(projectActivationRequest{ID: "env-fixture", Target: "/app", Destination: "/yougori/project-files/yougori-import-a/code"})
	reply = httptest.NewRecorder()
	s.activateProjectFiles(reply, httptest.NewRequest("POST", "/v1/project-files/activate", bytes.NewReader(body)))
	refused("project files", reply, "Start the owned project before activating its verified files")
}
