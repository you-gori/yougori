package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestAsyncOutputRingNeverStopsProducerAndReportsDroppedBytes(t *testing.T) {
	var ring execRing
	text := bytes.Repeat([]byte("x"), asyncOutputLimit*3)
	n, err := ring.Write(text)
	if err != nil || n != len(text) {
		t.Fatal(n, err)
	}
	chunk, next, truncated, err := ring.read(0, asyncReadLimit)
	if err != nil || !truncated || len(chunk) != asyncReadLimit || next != uint64(len(text)-asyncOutputLimit+asyncReadLimit) {
		t.Fatal(next, truncated, err)
	}
	if len(ring.data) > asyncOutputLimit {
		t.Fatal("unbounded ring")
	}
	if _, _, _, err := ring.read(uint64(len(text)+1), 1); err == nil {
		t.Fatal("future cursor accepted")
	}
}

func TestAsyncCommandOverflowStillCompletesWithRealExitCode(t *testing.T) {
	s := &server{microVM: true}
	item, err := s.startAsyncCommand(asyncExecRequest{ID: "microvm", ExecutionID: "exec-overflow", Command: "head -c 1600000 /dev/zero; printf 'stderr marker' >&2; exit 7"})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-item.stopped:
	case <-time.After(5 * time.Second):
		item.stop()
		t.Fatal("process did not complete")
	}
	item.mu.Lock()
	code := item.exitCode
	done := item.done
	item.mu.Unlock()
	if !done || code != 7 || item.stdout.length() != 1600000 {
		t.Fatal(done, code, item.stdout.length())
	}
	text, _, dropped, err := item.stderr.read(0, asyncReadLimit)
	if err != nil || dropped || text != "stderr marker" {
		t.Fatal(text, dropped, err)
	}
}

func TestAsyncCancellationIsIndependentAndBounded(t *testing.T) {
	s := &server{microVM: true}
	manager := s.asyncManager()
	item, err := s.startAsyncCommand(asyncExecRequest{ID: "microvm", ExecutionID: "exec-cancel", Command: "sleep 120 & wait"})
	if err != nil {
		t.Fatal(err)
	}
	manager.entries[item.execution] = item
	request := httptest.NewRequest("POST", "/v1/exec/cancel", strings.NewReader(`{"id":"microvm","executionId":"exec-cancel"}`))
	reply := httptest.NewRecorder()
	start := time.Now()
	s.asyncExecCancel(reply, request)
	if reply.Code != 200 || time.Since(start) > 5*time.Second {
		t.Fatal(reply.Code, reply.Body.String())
	}
	item.mu.Lock()
	done := item.done
	cancelled := item.cancelled
	item.mu.Unlock()
	if !done || !cancelled {
		t.Fatal("accepted cancellation without stopping the process group")
	}
}

func TestAsyncReadTargetsExactEnvironmentAndHasSeparateCursors(t *testing.T) {
	s := &server{microVM: true}
	item := &asyncExecution{environment: "one", execution: "exec-read", done: true, exitCode: 0}
	_, _ = item.stdout.Write([]byte("abc"))
	_, _ = item.stderr.Write([]byte("errors"))
	s.asyncManager().entries[item.execution] = item
	read := func(body string) *httptest.ResponseRecorder {
		reply := httptest.NewRecorder()
		s.asyncExecRead(reply, httptest.NewRequest("POST", "/v1/exec/read", strings.NewReader(body)))
		return reply
	}
	reply := read(`{"id":"two","executionId":"exec-read"}`)
	if reply.Code != 404 {
		t.Fatal(reply.Code)
	}
	reply = read(`{"id":"one","executionId":"exec-read","stdoutCursor":1,"stderrCursor":2,"limit":2}`)
	var value map[string]any
	if err := json.Unmarshal(reply.Body.Bytes(), &value); err != nil {
		t.Fatal(err)
	}
	if value["stdout"] != "bc" || value["stderr"] != "ro" || value["stdoutCursor"] != float64(3) || value["stderrCursor"] != float64(4) {
		t.Fatal(value)
	}
}

func TestAsyncStartReturnsPromptlyAndRejectsUnknownPreviousOutcome(t *testing.T) {
	s := &server{microVM: true}
	body := `{"id":"microvm","executionId":"exec-one","command":"sleep 120"}`
	reply := httptest.NewRecorder()
	begin := time.Now()
	s.asyncExecStart(reply, httptest.NewRequest("POST", "/v1/exec/start", strings.NewReader(body)))
	if reply.Code != 202 || time.Since(begin) > time.Second {
		t.Fatal(reply.Code, reply.Body.String())
	}
	item, _ := s.execution(asyncExecRequest{ID: "microvm", ExecutionID: "exec-one"})
	defer item.stop()
	reply = httptest.NewRecorder()
	s.asyncExecStart(reply, httptest.NewRequest("POST", "/v1/exec/start", strings.NewReader(body)))
	if reply.Code != 409 {
		t.Fatal("ambiguous retry launched another command")
	}
}

func TestAsyncContainerWrapperAndCancellationUseOnlyItsMarkedGroup(t *testing.T) {
	// A disposable nerdctl adapter executes the exact container wrapper in a
	// local child. This exercises quoting, marker propagation and guest cleanup
	// without entering any user environment or needing a container daemon.
	root := t.TempDir()
	fake := filepath.Join(root, "nerdctl")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nshift 4\nexec \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	// Older Alpine BusyBox has no setsid -w. Reject flags in this adapter so
	// portability is enforced in the ordinary race suite as well as real OCI.
	setsid, err := exec.LookPath("setsid")
	if err != nil {
		t.Fatal(err)
	}
	oldSetsid := "#!/bin/sh\ncase \"$1\" in -*) exit 1;; esac\nexec '" + strings.ReplaceAll(setsid, "'", "'\"'\"'") + "' \"$@\"\n"
	if err := os.WriteFile(filepath.Join(root, "setsid"), []byte(oldSetsid), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", root+":"+os.Getenv("PATH"))
	execution := "exec-test-" + strings.ReplaceAll(t.Name(), "/", "-")
	pidfile := "/tmp/.yougori-" + execution + ".pid"
	defer os.Remove(pidfile)
	s := &server{}
	item, err := s.startAsyncCommand(asyncExecRequest{ID: "container", ExecutionID: execution, Command: "printf 'started'; sleep 120 & wait"})
	if err != nil {
		t.Fatal(err)
	}
	s.asyncManager().entries[execution] = item
	// Cancel immediately: cleanup also covers the PID-file startup race.
	reply := httptest.NewRecorder()
	s.asyncExecCancel(reply, httptest.NewRequest("POST", "/v1/exec/cancel", strings.NewReader(`{"id":"container","executionId":"`+execution+`"}`)))
	if reply.Code != 200 {
		t.Fatal(reply.Code, reply.Body.String())
	}
	select {
	case <-item.stopped:
	case <-time.After(7 * time.Second):
		t.Fatal("container exec client remained alive")
	}
	if _, err := os.Stat(pidfile); !os.IsNotExist(err) {
		t.Fatal("owned group PID marker was not removed", err)
	}
}

func TestAsyncContainerCancellationStopsChildAfterLeaderExits(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "nerdctl"), []byte("#!/bin/sh\nshift 4\nexec \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", root+":"+os.Getenv("PATH"))
	execution := "exec-test-descendant"
	pidfile := "/tmp/.yougori-" + execution + ".pid"
	defer os.Remove(pidfile)
	s := &server{}
	item, err := s.startAsyncCommand(asyncExecRequest{ID: "container", ExecutionID: execution, Command: `/bin/sh -c 'trap "" TERM; printf "child:%s\n" "$$"; while :; do sleep 1; done' & wait`})
	if err != nil {
		t.Fatal(err)
	}
	defer item.stop()
	s.asyncManager().entries[execution] = item
	var child int
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		text, _, _, _ := item.stdout.read(0, asyncReadLimit)
		if strings.HasPrefix(text, "child:") {
			child, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(text, "child:")))
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if child <= 1 {
		t.Fatal("marked child did not start")
	}
	defer syscall.Kill(child, syscall.SIGKILL)
	reply := httptest.NewRecorder()
	s.asyncExecCancel(reply, httptest.NewRequest("POST", "/v1/exec/cancel", strings.NewReader(`{"id":"container","executionId":"`+execution+`"}`)))
	var value map[string]any
	if err := json.Unmarshal(reply.Body.Bytes(), &value); err != nil {
		t.Fatal(err)
	}
	if reply.Code != 200 || value["ownershipReleased"] != true {
		t.Fatal(reply.Code, value)
	}
	if stat, err := os.ReadFile("/proc/" + strconv.Itoa(child) + "/stat"); err == nil {
		fields := strings.Fields(string(stat[strings.LastIndex(string(stat), ") ")+2:]))
		if len(fields) > 0 && fields[0] != "Z" {
			t.Fatal("TERM-ignoring child survived group cancellation", string(stat))
		}
	}
}

func TestAsyncCompletedExecutionDoesNotBecomeCancelled(t *testing.T) {
	s := &server{microVM: true}
	item := &asyncExecution{environment: "one", execution: "exec-finished", done: true, exitCode: 7, cleanupVerified: true}
	s.asyncManager().entries[item.execution] = item
	reply := httptest.NewRecorder()
	s.asyncExecCancel(reply, httptest.NewRequest("POST", "/v1/exec/cancel", strings.NewReader(`{"id":"one","executionId":"exec-finished"}`)))
	var value map[string]any
	if err := json.Unmarshal(reply.Body.Bytes(), &value); err != nil {
		t.Fatal(err)
	}
	if reply.Code != 200 || value["cancelled"] != false || value["outcome"] != "complete" || value["exitCode"] != float64(7) {
		t.Fatal(reply.Code, value)
	}
}

func TestAsyncContainerPreservesGuestStatusDespiteLegacyNerdctlTransport(t *testing.T) {
	root := t.TempDir()
	// Simulate the older real nerdctl observed in OCI: every nonzero child
	// status becomes transport exit 1 and adds a fatal log. Guest status must
	// travel separately, with the wrapper's transport status remaining zero.
	adapter := "#!/bin/sh\nshift 4\n\"$@\"\nstatus=$?\nif [ \"$status\" != 0 ]; then printf 'transport-fatal' >&2; exit 1; fi\n"
	if err := os.WriteFile(filepath.Join(root, "nerdctl"), []byte(adapter), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", root+":"+os.Getenv("PATH"))
	execution := "exec-status-fixture"
	pidfile := "/tmp/.yougori-" + execution + ".pid"
	defer os.Remove(pidfile)
	defer os.Remove(pidfile + ".exit")
	s := &server{}
	item, err := s.startAsyncCommand(asyncExecRequest{ID: "one", ExecutionID: execution, Command: "printf actual-output; printf actual-error >&2; exit 7"})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-item.stopped:
	case <-time.After(5 * time.Second):
		item.stop()
		t.Fatal("completion status did not settle")
	}
	item.mu.Lock()
	code := item.exitCode
	errorCode := item.errorCode
	item.mu.Unlock()
	stderr, _, _, _ := item.stderr.read(0, asyncReadLimit)
	if code != 7 || errorCode != "" || stderr != "actual-error" {
		t.Fatal(code, errorCode, stderr)
	}
	if _, err := os.Stat(pidfile + ".exit"); !os.IsNotExist(err) {
		t.Fatal("completion record retained", err)
	}
}

// useWorkloadExec saves the record of a microVM whose tool runs in an OCI
// workload and installs a nerdctl adapter that logs the container each call
// selects. A running workload runs the rest of the call locally with a marker
// and, like the guest's older nerdctl, maps every nonzero status to transport
// exit 1. A stopped workload refuses every call.
func useWorkloadExec(t *testing.T, running bool) string {
	t.Helper()
	record := filepath.Join(t.TempDir(), "microvm-workload.json")
	if err := os.WriteFile(record, []byte(`{"image":"ubuntu:24.04"}`), 0600); err != nil {
		t.Fatal(err)
	}
	previous := microWorkloadPath
	t.Cleanup(func() { microWorkloadPath = previous })
	microWorkloadPath = record
	bin := t.TempDir()
	calls := filepath.Join(bin, "calls")
	adapter := "#!/bin/sh\nprintf '%s\\n' \"$1 $2 $3 $4\" >> '" + calls + "'\nshift 4\n"
	if running {
		adapter += "YOUGORI_TEST_RUNNER=workload \"$@\"\nstatus=$?\nif [ \"$status\" != 0 ]; then printf 'transport-fatal' >&2; exit 1; fi\n"
	} else {
		adapter += "printf 'container app is not running' >&2\nexit 1\n"
	}
	if err := os.WriteFile(filepath.Join(bin, "nerdctl"), []byte(adapter), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	return calls
}

const workloadExec = "--namespace yougori-workload exec app\n"

func finishedExecution(t *testing.T, item *asyncExecution) (int, string, string, string) {
	t.Helper()
	select {
	case <-item.stopped:
	case <-time.After(5 * time.Second):
		item.stop()
		t.Fatal("execution did not complete")
	}
	item.mu.Lock()
	code, failure := item.exitCode, item.errorCode
	item.mu.Unlock()
	stdout, _, _, _ := item.stdout.read(0, asyncReadLimit)
	stderr, _, _, _ := item.stderr.read(0, asyncReadLimit)
	return code, failure, stdout, stderr
}

func TestAsyncMicroVMRunsCommandsInItsToolWorkload(t *testing.T) {
	calls := useWorkloadExec(t, true)
	execution := "exec-workload-status"
	pidfile := "/tmp/.yougori-" + execution + ".pid"
	defer os.Remove(pidfile)
	defer os.Remove(pidfile + ".exit")
	s := &server{microVM: true}
	command := `printf '%s' "${YOUGORI_TEST_RUNNER-outer guest}"; printf actual-error >&2; exit 7`
	item, err := s.startAsyncCommand(asyncExecRequest{ID: "microvm", ExecutionID: execution, Command: command})
	if err != nil {
		t.Fatal(err)
	}
	// The guest status arrives through the workload's private receipt, not the
	// provider's transport status.
	if code, failure, stdout, stderr := finishedExecution(t, item); code != 7 || failure != "" || stdout != "workload" || stderr != "actual-error" {
		t.Fatal(code, failure, stdout, stderr)
	}
	if logged, _ := os.ReadFile(calls); string(logged) != workloadExec+workloadExec {
		t.Fatalf("the command or its receipt left the workload:\n%s", logged)
	}
	if _, err := os.Stat(pidfile + ".exit"); !os.IsNotExist(err) {
		t.Fatal("completion record retained", err)
	}
	// A microVM without a workload still runs commands in its own guest.
	if err := os.Remove(microWorkloadPath); err != nil {
		t.Fatal(err)
	}
	item, err = s.startAsyncCommand(asyncExecRequest{ID: "microvm", ExecutionID: "exec-outer-guest", Command: command})
	if err != nil {
		t.Fatal(err)
	}
	if code, failure, stdout, stderr := finishedExecution(t, item); code != 7 || failure != "" || stdout != "outer guest" || stderr != "actual-error" {
		t.Fatal(code, failure, stdout, stderr)
	}
	if logged, _ := os.ReadFile(calls); string(logged) != workloadExec+workloadExec {
		t.Fatalf("a microVM without a workload used one:\n%s", logged)
	}
}

func TestAsyncMicroVMNeverFallsBackToItsOwnGuestWhenTheWorkloadIsStopped(t *testing.T) {
	calls := useWorkloadExec(t, false)
	marker := filepath.Join(t.TempDir(), "ran")
	s := &server{microVM: true}
	item, err := s.startAsyncCommand(asyncExecRequest{ID: "microvm", ExecutionID: "exec-workload-stopped", Command: "touch '" + marker + "'"})
	if err != nil {
		t.Fatal(err)
	}
	if code, _, stdout, stderr := finishedExecution(t, item); code != 1 || stdout != "" || stderr != "container app is not running" {
		t.Fatal(code, stdout, stderr)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("the command ran outside the stopped workload", err)
	}
	if logged, _ := os.ReadFile(calls); string(logged) != workloadExec {
		t.Fatalf("unexpected nerdctl calls:\n%s", logged)
	}
}

func TestAsyncMicroVMWorkloadCancellationStopsItsMarkedGroup(t *testing.T) {
	calls := useWorkloadExec(t, true)
	execution := "exec-workload-cancel"
	pidfile := "/tmp/.yougori-" + execution + ".pid"
	defer os.Remove(pidfile)
	s := &server{microVM: true}
	item, err := s.startAsyncCommand(asyncExecRequest{ID: "microvm", ExecutionID: execution, Command: `/bin/sh -c 'trap "" TERM; printf "child:%s\n" "$$"; while :; do sleep 1; done' & wait`})
	if err != nil {
		t.Fatal(err)
	}
	defer item.stop()
	s.asyncManager().entries[execution] = item
	var child int
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		text, _, _, _ := item.stdout.read(0, asyncReadLimit)
		if strings.HasPrefix(text, "child:") {
			child, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(text, "child:")))
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if child <= 1 {
		t.Fatal("marked child did not start")
	}
	defer syscall.Kill(child, syscall.SIGKILL)
	reply := httptest.NewRecorder()
	s.asyncExecCancel(reply, httptest.NewRequest("POST", "/v1/exec/cancel", strings.NewReader(`{"id":"microvm","executionId":"`+execution+`"}`)))
	var value map[string]any
	if err := json.Unmarshal(reply.Body.Bytes(), &value); err != nil {
		t.Fatal(err)
	}
	if reply.Code != 200 || value["ownershipReleased"] != true {
		t.Fatal(reply.Code, value)
	}
	if stat, err := os.ReadFile("/proc/" + strconv.Itoa(child) + "/stat"); err == nil {
		fields := strings.Fields(string(stat[strings.LastIndex(string(stat), ") ")+2:]))
		if len(fields) > 0 && fields[0] != "Z" {
			t.Fatal("TERM-ignoring child survived workload cancellation", string(stat))
		}
	}
	// The cleanup that verified the group's marker ran in the workload too.
	if logged, _ := os.ReadFile(calls); string(logged) != workloadExec+workloadExec {
		t.Fatalf("unexpected nerdctl calls:\n%s", logged)
	}
}

func TestAsyncTimeoutDoesNotRewriteCompletedProcessWhileReadingReceipt(t *testing.T) {
	root := t.TempDir()
	// The command finishes immediately, but the provider takes time to fetch
	// its private completion receipt. That delivery delay is not execution.
	adapter := "#!/bin/sh\nshift 4\ncase \"$3\" in 'test -f '*) sleep 3;; esac\nexec \"$@\"\n"
	if err := os.WriteFile(filepath.Join(root, "nerdctl"), []byte(adapter), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", root+":"+os.Getenv("PATH"))
	execution := "exec-delayed-receipt"
	pidfile := "/tmp/.yougori-" + execution + ".pid"
	defer os.Remove(pidfile)
	defer os.Remove(pidfile + ".exit")
	s := &server{}
	reply := httptest.NewRecorder()
	s.asyncExecStart(reply, httptest.NewRequest("POST", "/v1/exec/start", strings.NewReader(`{"id":"one","executionId":"`+execution+`","command":"printf finished; exit 7","timeoutSeconds":1}`)))
	if reply.Code != 202 {
		t.Fatal(reply.Code, reply.Body.String())
	}
	item, err := s.execution(asyncExecRequest{ID: "one", ExecutionID: execution})
	if err != nil {
		t.Fatal(err)
	}
	defer item.stop()
	select {
	case <-item.stopped:
	case <-time.After(6 * time.Second):
		t.Fatal("completion receipt did not arrive")
	}
	item.mu.Lock()
	code, failure := item.exitCode, item.errorCode
	item.mu.Unlock()
	if code != 7 || failure != "" {
		t.Fatalf("receipt delay rewrote an already completed execution: exit=%d error=%q", code, failure)
	}
}
