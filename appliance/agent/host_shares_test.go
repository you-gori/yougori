package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path"
	"strings"
	"testing"
)

// yougori-mount-helper refuses sources outside its allowlist, so every folder
// the agent mounts from must be on it.
func TestMountHelperAcceptsEveryShareSource(t *testing.T) {
	helper, err := os.ReadFile("../mount-helper.c")
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{hostShareMountPath("env-fixture", "share-fixture"), path.Join(dataRoot, "shares", "connection-fixture"), path.Join(dataRoot, "secrets", "connection-fixture")} {
		if !bytes.Contains(helper, []byte(`starts_with(source, "`+path.Dir(source)+`/")`)) {
			t.Errorf("yougori-mount-helper refuses the share source %s", source)
		}
	}
}

func TestSharedFoldersMountWhereTheEnvironmentsToolRuns(t *testing.T) {
	_, calls := useMicroWorkload(t, "4242")
	ctx := context.Background()
	for _, s := range []*server{{microVM: true}, {}} {
		if pid, err := s.sharesPID(ctx, "env-fixture"); err != nil || pid != 4242 {
			t.Fatalf("microVM=%v: PID %d, error %v", s.microVM, pid, err)
		}
	}
	want := workloadInspection + "--namespace " + namespace + " inspect --format {{.State.Pid}} env-fixture\n"
	if logged, _ := os.ReadFile(calls); string(logged) != want {
		t.Fatalf("unexpected nerdctl calls:\n%s", logged)
	}
	// Without a workload, a microVM's shared folders mount in its own guest.
	if err := os.Remove(microWorkloadPath); err != nil {
		t.Fatal(err)
	}
	if pid, err := (&server{microVM: true}).sharesPID(ctx, "env-fixture"); err != nil || pid != os.Getpid() {
		t.Fatalf("microVM without a workload: PID %d, error %v", pid, err)
	}
	if logged, _ := os.ReadFile(calls); string(logged) != want {
		t.Fatal("a microVM without a workload inspected one")
	}
}

func TestMicroVMSharesNeverFallBackToTheOuterGuestWhenTheWorkloadIsStopped(t *testing.T) {
	_, calls := useMicroWorkload(t, "0")
	for _, connection := range []bool{false, true} {
		body, _ := json.Marshal(hostShareRequest{ID: "env-fixture", ShareID: "share-fixture", Endpoint: "http://10.0.2.2:9", Token: strings.Repeat("a", 64), Connection: connection})
		reply := httptest.NewRecorder()
		(&server{microVM: true}).attachHostShare(reply, httptest.NewRequest("POST", "/v1/shares/attach", bytes.NewReader(body)))
		// Refused before contacting the PC folder or mounting anything.
		if reply.Code != 409 || !strings.Contains(reply.Body.String(), "not running") {
			t.Fatal(connection, reply.Code, reply.Body.String())
		}
	}
	if logged, _ := os.ReadFile(calls); string(logged) != workloadInspection+workloadInspection {
		t.Fatalf("unexpected nerdctl calls:\n%s", logged)
	}
}
