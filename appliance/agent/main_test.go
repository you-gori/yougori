package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseMicroVMBootConfiguration(t *testing.T) {
	token := strings.Repeat("a1", 32)
	configuration, err := parseBootConfiguration("quiet opendock.mode=microvm opendock.token=" + token)
	if err != nil {
		t.Fatal(err)
	}
	if configuration.token != token || !configuration.microVM {
		t.Fatalf("unexpected boot configuration: %#v", configuration)
	}
	if _, err := parseBootConfiguration("opendock.mode=microvm"); err == nil {
		t.Fatal("a missing authentication token was accepted")
	}
	if _, err := parseBootConfiguration("opendock.token=invalid"); err == nil {
		t.Fatal("an invalid authentication token was accepted")
	}
}

func TestResourceUpdatePersistsExplicitCPUQuota(t *testing.T) {
	for _, test := range []struct {
		cpus  float64
		quota string
	}{{0.15, "15000"}, {4, "400000"}, {8, "800000"}} {
		args := resourceUpdateArguments(resourcesRequest{ID: "env-quota", CPUs: test.cpus, MemoryBytes: 4294967296})
		want := []string{"--namespace", namespace, "update", "--cpu-period", "100000", "--cpu-quota", test.quota, "--memory", "4294967296", "--memory-swap", "4294967296", "--pids-limit", "4096", "env-quota"}
		if !reflect.DeepEqual(args, want) {
			t.Fatalf("got %v, want %v", args, want)
		}
	}
}

func TestSnapshotDoesNotPauseStoppedOrAlreadyPausedContainers(t *testing.T) {
	for _, tc := range []struct{ state, want string }{
		{`{"Running":false,"Status":"created"}`, "--pause=false"},
		{`{"Running":false,"Status":"exited"}`, "--pause=false"},
		{`{"Running":true,"Paused":false}`, "--pause=true"},
		{`{"Running":true,"Paused":true}`, "--pause=false"},
		{`{"Running":false,"Paused":true,"Status":"paused"}`, "--pause=false"},
	} {
		got, err := snapshotPauseArgument(tc.state)
		if err != nil || got != tc.want {
			t.Fatalf("state %s: got %q, %v; want %q", tc.state, got, err, tc.want)
		}
	}
	for _, invalid := range []string{"", "{}", "null", `{"Running":"false"}`} {
		if _, err := snapshotPauseArgument(invalid); err == nil {
			t.Fatalf("accepted unknown state: %s", invalid)
		}
	}
}

func TestMicroVMSystemExecute(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/v1/system/exec", strings.NewReader(
		`{"command":"printf microvm; printf warning >&2; exit 7"}`,
	))
	response := httptest.NewRecorder()
	(&server{microVM: true}).systemExecute(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("unexpected status %d: %s", response.Code, response.Body.String())
	}
	var output commandOutput
	if err := json.Unmarshal(response.Body.Bytes(), &output); err != nil {
		t.Fatal(err)
	}
	if output.Stdout != "microvm" || output.Stderr != "warning" || output.ExitCode != 7 {
		t.Fatalf("unexpected command output: %#v", output)
	}

	request = httptest.NewRequest(http.MethodPost, "/v1/system/exec", strings.NewReader(`{"command":"true"}`))
	response = httptest.NewRecorder()
	(&server{}).systemExecute(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("normal appliance mode exposed system execution: %d", response.Code)
	}
}

func TestMicroVMHealthDoesNotRequireContainerd(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	response := httptest.NewRecorder()
	(&server{microVM: true}).health(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"runtime":"microvm"`) {
		t.Fatalf("unexpected microVM health response %d: %s", response.Code, response.Body.String())
	}
}

func TestRuntimeSocketReady(t *testing.T) {
	path := filepath.Join(t.TempDir(), "containerd.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := runtimeSocketReady(path); err != nil {
		t.Fatalf("live runtime socket was not ready: %v", err)
	}
	if err := runtimeSocketReady(filepath.Join(t.TempDir(), "missing.sock")); err == nil {
		t.Fatal("missing runtime socket was reported ready")
	}
}

func TestRunAllowExitReportsContextTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := runAllowExit(ctx, "/bin/sleep", "10"); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected a command timeout, got %v", err)
	}
}

func TestValidatedBatchIDs(t *testing.T) {
	ids, err := validatedBatchIDs([]string{"first", "second", "first"})
	if err != nil {
		t.Fatal(err)
	}
	if expected := []string{"first", "second"}; !reflect.DeepEqual(ids, expected) {
		t.Fatalf("unexpected identifiers: %#v", ids)
	}
	if _, err := validatedBatchIDs([]string{"invalid/id"}); err == nil {
		t.Fatal("an unsafe identifier was accepted")
	}
	tooMany := make([]string, 257)
	for index := range tooMany {
		tooMany[index] = "id"
	}
	if _, err := validatedBatchIDs(tooMany); err == nil {
		t.Fatal("an oversized batch was accepted")
	}
}

func TestParseInspectStates(t *testing.T) {
	states, err := parseInspectStates("/first\ttrue\r\nsecond\tfalse\n")
	if err != nil {
		t.Fatal(err)
	}
	if !states["first"] || states["second"] {
		t.Fatalf("unexpected states: %#v", states)
	}
	if _, err := parseInspectStates("malformed"); err == nil {
		t.Fatal("malformed inspect output was accepted")
	}
}

func TestParseNerdctlStats(t *testing.T) {
	stream := `{ "Name": "first", "CPUPerc": "1.5%", "MemUsage": "2MiB / 8MiB", "NetIO": "3kB / 4kB" }
{ "Name": "second", "CPUPerc": "0.0%", "MemUsage": "1MiB / 8MiB", "NetIO": "5kB / 6kB" }`
	records, err := parseNerdctlStats(stream)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].Name != "first" || records[1].Name != "second" {
		t.Fatalf("unexpected streamed records: %#v", records)
	}

	array, err := parseNerdctlStats(`[{"Name":`)
	if err == nil || len(array) != 0 {
		t.Fatal("malformed JSON array was accepted")
	}
	array, err = parseNerdctlStats(`[{"Name":"first"},{"Name":"second"}]`)
	if err != nil || len(array) != 2 {
		t.Fatalf("decode JSON array: %#v, %v", array, err)
	}
	partial, err := parseNerdctlStats(`{"Name":"first"}` + "\n{")
	if err == nil || len(partial) != 1 || partial[0].Name != "first" {
		t.Fatalf("partial nonzero-exit output was not preserved: %#v, %v", partial, err)
	}
}

func TestPrepareStatsEntriesToleratesMissingContainers(t *testing.T) {
	listed, err := parseNerdctlContainerList(`
{"ID":"full-first-id","Names":"first","State":"running","Status":"Up 2 seconds"}
{"ID":"full-exact-up-id","Names":"exact-up","Status":"Up"}
{"ID":"full-stopped-id","Names":"stopped","State":"exited","Status":"Exited (0)"}
`)
	if err != nil {
		t.Fatal(err)
	}
	entries, running := prepareStatsEntries([]string{"first", "exact-up", "deleted", "stopped"}, listed)
	if len(entries) != 4 || !entries[0].Running || !entries[1].Running || entries[2].Running || entries[3].Running {
		t.Fatalf("unexpected entries: %#v", entries)
	}
	if expected := []string{"first", "exact-up"}; !reflect.DeepEqual(running, expected) {
		t.Fatalf("unexpected running identifiers: %#v", running)
	}
}

func TestParseTelemetryQuantities(t *testing.T) {
	for _, test := range []struct {
		input string
		want  uint64
	}{
		{"1.5KiB / 8MiB", 1536},
		{"2.25MB / 1GB", 2_250_000},
		{"42B", 42},
		{"invalid", 0},
	} {
		if got := parseFirstByteQuantity(test.input); got != test.want {
			t.Errorf("parse %q: got %d, want %d", test.input, got, test.want)
		}
	}
	if got := parsePercentage("12.5%"); got != 12.5 {
		t.Fatalf("unexpected percentage: %v", got)
	}
}

func TestCommandReportsNotFound(t *testing.T) {
	missing := &commandError{
		Program: "nerdctl",
		Output: commandOutput{
			Stderr:   `FATA[0000] no such container "environment-one"`,
			ExitCode: 1,
		},
	}
	if !commandReportsNotFound(missing, "environment-one") {
		t.Fatal("a confirmed missing managed resource was not recognized")
	}
	if commandReportsNotFound(missing, "environment-two") {
		t.Fatal("an unrelated missing resource was accepted")
	}
	permission := &commandError{
		Program: "nerdctl",
		Output: commandOutput{
			Stderr:   `failed to delete environment-one: permission denied`,
			ExitCode: 1,
		},
	}
	if commandReportsNotFound(permission, "environment-one") {
		t.Fatal("a non-idempotent deletion error was swallowed")
	}
	wrongExit := &commandError{
		Program: "nerdctl",
		Output: commandOutput{
			Stderr:   `environment-one not found`,
			ExitCode: 2,
		},
	}
	if commandReportsNotFound(wrongExit, "environment-one") {
		t.Fatal("an unexpected exit status was accepted")
	}
}

func TestFileSHA256(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.tar")
	if err := os.WriteFile(path, []byte("Yougori snapshot"), 0600); err != nil {
		t.Fatal(err)
	}
	digest, err := fileSHA256(path)
	if err != nil {
		t.Fatal(err)
	}
	if digest != "66f624a5469f654087083f29ff7c58f711b4b84abe45c3d8cc77d4865d1f0678" {
		t.Fatalf("unexpected digest %s", digest)
	}
}

func TestKeyedLockerAllowsIndependentResources(t *testing.T) {
	var locker keyedLocker
	releaseFirst := locker.lock(containerLockKey("first"))
	t.Cleanup(releaseFirst)

	acquired := make(chan struct{})
	go func() {
		releaseSecond := locker.lock(containerLockKey("second"))
		close(acquired)
		releaseSecond()
	}()

	select {
	case <-acquired:
	case <-time.After(time.Second):
		t.Fatal("an independent resource was blocked")
	}
}

func TestKeyedLockerSerializesSameResource(t *testing.T) {
	var locker keyedLocker
	releaseFirst := locker.lock(containerLockKey("shared"))

	started := make(chan struct{})
	acquired := make(chan struct{})
	go func() {
		close(started)
		releaseSecond := locker.lock(containerLockKey("shared"))
		close(acquired)
		releaseSecond()
	}()
	<-started

	select {
	case <-acquired:
		releaseFirst()
		t.Fatal("a conflicting operation acquired the resource early")
	case <-time.After(25 * time.Millisecond):
	}

	releaseFirst()
	select {
	case <-acquired:
	case <-time.After(time.Second):
		t.Fatal("a conflicting operation remained blocked after release")
	}
}

func TestKeyedLockerOrdersMultiResourceRequests(t *testing.T) {
	var locker keyedLocker
	start := make(chan struct{})
	var completed sync.WaitGroup
	completed.Add(2)

	for _, keys := range [][]string{
		{containerLockKey("source"), containerLockKey("target")},
		{containerLockKey("target"), containerLockKey("source")},
	} {
		keys := keys
		go func() {
			defer completed.Done()
			<-start
			release := locker.lock(keys...)
			release()
		}()
	}

	close(start)
	done := make(chan struct{})
	go func() {
		completed.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("reverse endpoint ordering deadlocked")
	}
}

func TestKeyedLockerReclaimsEntries(t *testing.T) {
	var locker keyedLocker
	release := locker.lock("", "duplicate", "duplicate", "second")
	release()

	locker.mu.Lock()
	defer locker.mu.Unlock()
	if len(locker.entries) != 0 {
		t.Fatalf("idle lock entries were retained: %d", len(locker.entries))
	}
}

func BenchmarkKeyedLockerUncontended(b *testing.B) {
	var locker keyedLocker
	for index := 0; index < b.N; index++ {
		release := locker.lock(containerLockKey("warm"))
		release()
	}
}
