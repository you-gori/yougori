package main

// Non-interactive execution is an asynchronous, leased operation. HTTP reads
// never wait for the command, and bounded writers keep draining both pipes even
// when older output is discarded. Output delivery cannot turn a successful
// command into a failed execution.
import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const asyncOutputLimit = 512 * 1024
const asyncReadLimit = 64 * 1024
const asyncMaxSessions = 32

// Finished executions stay readable for a while, but never block new work:
// only running ones count toward asyncMaxSessions, and the oldest finished
// ones make room once this many are retained.
const asyncMaxRetained = 64
const asyncLease = 90 * time.Second

type execRing struct {
	mu   sync.Mutex
	data []byte
	base uint64
	end  uint64
}

func (ring *execRing) Write(bytes []byte) (int, error) {
	ring.mu.Lock()
	defer ring.mu.Unlock()
	n := len(bytes)
	ring.end += uint64(n)
	if n >= asyncOutputLimit {
		ring.data = append(ring.data[:0], bytes[n-asyncOutputLimit:]...)
	} else {
		ring.data = append(ring.data, bytes...)
		if len(ring.data) > asyncOutputLimit {
			ring.data = append(ring.data[:0], ring.data[len(ring.data)-asyncOutputLimit:]...)
		}
	}
	ring.base = ring.end - uint64(len(ring.data))
	return n, nil
}
func (ring *execRing) read(cursor uint64, limit int) (string, uint64, bool, error) {
	bytes, next, truncated, err := ring.readBytes(cursor, limit)
	return string(bytes), next, truncated, err
}
func (ring *execRing) readBytes(cursor uint64, limit int) ([]byte, uint64, bool, error) {
	ring.mu.Lock()
	defer ring.mu.Unlock()
	if cursor > ring.end {
		return nil, cursor, false, fmt.Errorf("output cursor exceeds available bytes")
	}
	truncated := cursor < ring.base
	if truncated {
		cursor = ring.base
	}
	end := cursor + uint64(limit)
	if end > ring.end {
		end = ring.end
	}
	text := append([]byte(nil), ring.data[cursor-ring.base:end-ring.base]...)
	return text, end, truncated, nil
}
func (ring *execRing) length() uint64 { ring.mu.Lock(); defer ring.mu.Unlock(); return ring.end }

type asyncExecution struct {
	environment     string
	execution       string
	command         *exec.Cmd
	stdout          execRing
	stderr          execRing
	mu              sync.Mutex
	done            bool
	cancelled       bool
	timedOut        bool
	exitCode        int
	errorCode       string
	cleanupVerified bool
	processEnded    bool
	lastLease       time.Time
	completed       time.Time
	stop            context.CancelFunc
	stopped         chan struct{}
}
type asyncExecRequest struct {
	ID             string `json:"id"`
	ExecutionID    string `json:"executionId"`
	Command        string `json:"command"`
	TimeoutSeconds uint64 `json:"timeoutSeconds"`
	StdoutCursor   uint64 `json:"stdoutCursor"`
	StderrCursor   uint64 `json:"stderrCursor"`
	Limit          uint64 `json:"limit"`
}

// Different test/server instances never share credentials or execution IDs.
var asyncManagers sync.Map // map[*server]*asyncManager
type asyncManager struct {
	mu      sync.Mutex
	entries map[string]*asyncExecution
}

func (s *server) asyncManager() *asyncManager {
	manager, _ := asyncManagers.LoadOrStore(s, &asyncManager{entries: make(map[string]*asyncExecution)})
	return manager.(*asyncManager)
}

// admit reports whether another execution may start, evicting the oldest
// finished executions when too many are retained. Call with manager.mu held.
func (manager *asyncManager) admit() bool {
	running := 0
	var finished []*asyncExecution
	for _, item := range manager.entries {
		item.mu.Lock()
		if item.done {
			finished = append(finished, item)
		} else {
			running++
		}
		item.mu.Unlock()
	}
	if running >= asyncMaxSessions {
		return false
	}
	sort.Slice(finished, func(a, b int) bool { return finished[a].completedAt().Before(finished[b].completedAt()) })
	for len(manager.entries) >= asyncMaxRetained && len(finished) > 0 {
		delete(manager.entries, finished[0].execution)
		finished = finished[1:]
	}
	return len(manager.entries) < asyncMaxRetained
}

func (item *asyncExecution) completedAt() time.Time {
	item.mu.Lock()
	defer item.mu.Unlock()
	return item.completed
}

func (s *server) registerAsyncExecRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/v1/exec/start", s.auth(method(http.MethodPost, s.asyncExecStart)))
	mux.HandleFunc("/v1/exec/read", s.auth(method(http.MethodPost, s.asyncExecRead)))
	mux.HandleFunc("/v1/exec/cancel", s.auth(method(http.MethodPost, s.asyncExecCancel)))
	mux.HandleFunc("/v1/exec/release", s.auth(method(http.MethodPost, s.asyncExecRelease)))
}
func validExecutionID(id string) bool {
	return safeID.MatchString(id) && strings.HasPrefix(id, "exec-")
}
func (s *server) execution(request asyncExecRequest) (*asyncExecution, error) {
	if !validExecutionID(request.ExecutionID) {
		return nil, fmt.Errorf("invalid execution ID")
	}
	manager := s.asyncManager()
	manager.mu.Lock()
	item := manager.entries[request.ExecutionID]
	manager.mu.Unlock()
	if item == nil || item.environment != request.ID {
		return nil, fmt.Errorf("execution not found for this environment")
	}
	return item, nil
}
func (s *server) asyncExecStart(w http.ResponseWriter, r *http.Request) {
	var request asyncExecRequest
	if !decodeRequest(w, r, &request) || !requireID(w, request.ID) {
		return
	}
	if !validExecutionID(request.ExecutionID) || strings.TrimSpace(request.Command) == "" || len(request.Command) > 32768 {
		writeError(w, 400, "invalid execution ID or command")
		return
	}
	if request.TimeoutSeconds == 0 {
		request.TimeoutSeconds = 86400
	}
	if request.TimeoutSeconds > 7*86400 {
		writeError(w, 400, "execution timeout must be at most seven days")
		return
	}
	manager := s.asyncManager()
	manager.mu.Lock()
	if old := manager.entries[request.ExecutionID]; old != nil {
		manager.mu.Unlock()
		writeError(w, 409, "execution ID already exists; inspect it instead of repeating a command")
		return
	}
	if !manager.admit() {
		manager.mu.Unlock()
		writeError(w, 429, "execution capacity reached; wait for or cancel running executions")
		return
	}
	item, err := s.startAsyncCommand(request)
	if err != nil {
		manager.mu.Unlock()
		writeError(w, 500, err.Error())
		return
	}
	manager.entries[request.ExecutionID] = item
	manager.mu.Unlock()
	go s.watchAsyncExecution(item, time.Duration(request.TimeoutSeconds)*time.Second)
	writeJSON(w, 202, map[string]any{"executionId": request.ExecutionID, "status": "running", "leaseSeconds": uint64(asyncLease.Seconds()), "outputLimitBytes": asyncOutputLimit})
}

func (s *server) startAsyncCommand(request asyncExecRequest) (*asyncExecution, error) {
	ctx, stop := context.WithCancel(context.Background())
	item := &asyncExecution{environment: request.ID, execution: request.ExecutionID, lastLease: time.Now(), stop: stop, stopped: make(chan struct{}), cleanupVerified: true}
	var command *exec.Cmd
	if s.microVM {
		command = exec.CommandContext(ctx, "/bin/sh", "-lc", request.Command)
	} else {
		// The guest PID file is private and the process group carries an initial
		// environment marker. Cancellation verifies both before signalling it.
		pidfile := "/tmp/.yougori-" + request.ExecutionID + ".pid"
		// A non-interactive shell forks the setsid child before waiting. Its PID
		// cannot already be its inherited process-group ID, so even older BusyBox
		// setsid succeeds without forking away from our waiter (-w is not portable).
		wrapper := `command -v setsid >/dev/null || { printf '%s\n' 'async execution requires setsid in this image' >&2; exit 126; }; env YOUGORI_EXEC_ID="$3" setsid /bin/sh -c 'umask 077; printf "%s" "$$" > "$1"; /bin/sh -lc "$2"; status=$?; printf "%s" "$status" > "$1.exit"; rm -f "$1"; exit 0' yougori "$1" "$2" & child=$!; wait "$child"`
		command = exec.CommandContext(ctx, "nerdctl", "--namespace", namespace, "exec", request.ID, "/bin/sh", "-c", wrapper, "yougori", pidfile, request.Command, request.ExecutionID)
	}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Stdout = &item.stdout
	command.Stderr = &item.stderr
	command.Cancel = func() error { s.stopAsyncProcesses(item); return nil }
	command.WaitDelay = 3 * time.Second
	item.command = command
	if err := command.Start(); err != nil {
		stop()
		return nil, fmt.Errorf("execution could not start: %w", err)
	}
	go func() {
		err := command.Wait()
		defer stop()
		item.mu.Lock()
		item.processEnded = true
		cancelled := item.cancelled || item.timedOut
		item.mu.Unlock()
		exitCode := command.ProcessState.ExitCode()
		outcomeUnknown := false
		if !s.microVM && !cancelled && exitCode == 0 {
			// Older nerdctl releases return 1 for every nonzero guest exit and
			// append a fatal log to stderr. Our guest wrapper instead reports
			// status through a private bounded file and exits its transport 0.
			var statusErr error
			exitCode, statusErr = s.asyncGuestExitCode(item)
			outcomeUnknown = statusErr != nil
		}
		item.mu.Lock()
		item.done = true
		item.completed = time.Now()
		item.exitCode = exitCode
		if item.exitCode < 0 {
			if item.timedOut {
				item.exitCode = 124
			} else if item.cancelled {
				item.exitCode = 130
			} else if status, ok := command.ProcessState.Sys().(syscall.WaitStatus); ok && status.Signaled() {
				item.exitCode = 128 + int(status.Signal())
			}
		}
		if item.cancelled {
			item.errorCode = "EXECUTION_CANCELLED"
			if !item.cleanupVerified {
				item.errorCode = "EXECUTION_CANCEL_UNVERIFIED"
			}
		} else if item.timedOut {
			item.errorCode = "EXECUTION_TIMEOUT"
			if !item.cleanupVerified {
				item.errorCode = "EXECUTION_TIMEOUT_UNVERIFIED"
			}
		} else if outcomeUnknown {
			item.errorCode = "EXECUTION_OUTCOME_UNKNOWN"
		} else if err != nil && item.exitCode < 0 {
			item.errorCode = "EXECUTION_IO_FAILED"
		}
		item.mu.Unlock()
		close(item.stopped)
	}()
	return item, nil
}
func (s *server) asyncGuestExitCode(item *asyncExecution) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.guestReceiptTimeout())
	defer cancel()
	return guestExitCode(ctx, item.environment, "/tmp/.yougori-"+item.execution+".pid.exit")
}
func (s *server) stopAsyncProcesses(item *asyncExecution) {
	if item.command == nil || item.command.Process == nil {
		return
	}
	if !s.microVM {
		// Only the group created for this exact execution ID may be killed. Never
		// stop the whole container or use a caller-provided PID/host path.
		script := `pidfile=$1; execution=$2
for n in 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19; do test -s "$pidfile" && break; sleep 0.1; done
p=$(cat "$pidfile" 2>/dev/null) || exit 2
case "$p" in ''|*[!0-9]*) exit 1;; esac
test "$p" -gt 1 || exit 1
tr '\000' '\n' < "/proc/$p/environ" 2>/dev/null | grep -Fx "YOUGORI_EXEC_ID=$execution" >/dev/null || exit 2
# Inspect all group members because TERM can remove the leader while a child
# ignores it. Never send KILL to a recycled or unverified process group.
group_members() {
  found=0; marked=0
  for stat in /proc/[0-9]*/stat; do
    IFS= read -r row < "$stat" 2>/dev/null || continue
    rest=${row##*) }; set -- $rest
    test "$3" = "$p" || continue
    test "$1" = Z && continue
    found=1
    member=${stat%/stat}; member=${member##*/}
    if tr '\000' '\n' < "/proc/$member/environ" 2>/dev/null | grep -Fx "YOUGORI_EXEC_ID=$execution" >/dev/null; then marked=1; fi
  done
}
kill -TERM "-$p" 2>/dev/null
sleep 0.2
group_members
if test "$found" = 1; then
  test "$marked" = 1 || exit 3
  kill -KILL "-$p" 2>/dev/null || exit 3
fi
for n in 0 1 2 3 4; do group_members; test "$found" = 0 && { rm -f "$pidfile"; exit 0; }; sleep 0.1; done
exit 3`
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		cleanup := exec.CommandContext(ctx, "nerdctl", "--namespace", namespace, "exec", item.environment, "/bin/sh", "-c", script, "yougori", "/tmp/.yougori-"+item.execution+".pid", item.execution)
		err := cleanup.Run()
		item.mu.Lock()
		item.cleanupVerified = err == nil
		item.mu.Unlock()
		cancel()
	}
	// This group belongs to the agent's own exec child, not to another owner.
	if err := syscall.Kill(-item.command.Process.Pid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
		item.mu.Lock()
		item.cleanupVerified = false
		item.mu.Unlock()
	}
}
func (s *server) watchAsyncExecution(item *asyncExecution, total time.Duration) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	deadline := time.Now().Add(total)
	for {
		select {
		case <-item.stopped:
			time.Sleep(30 * time.Minute)
			manager := s.asyncManager()
			manager.mu.Lock()
			if manager.entries[item.execution] == item {
				delete(manager.entries, item.execution)
			}
			manager.mu.Unlock()
			return
		case now := <-ticker.C:
			item.mu.Lock()
			pending := !item.processEnded && !item.done
			abandoned := now.Sub(item.lastLease) > asyncLease
			expired := now.After(deadline)
			if pending && (abandoned || expired) {
				item.cancelled = abandoned && !expired
				item.timedOut = expired
			}
			item.mu.Unlock()
			if pending && (abandoned || expired) {
				item.stop()
			}
		}
	}
}
func (s *server) asyncExecRead(w http.ResponseWriter, r *http.Request) {
	var request asyncExecRequest
	if !decodeRequest(w, r, &request) || !requireID(w, request.ID) {
		return
	}
	item, err := s.execution(request)
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	limit := int(request.Limit)
	if limit == 0 {
		limit = asyncReadLimit
	}
	if limit < 1 || limit > asyncReadLimit {
		writeError(w, 400, "limit must be 1–65536 bytes per stream")
		return
	}
	stdout, nextOut, outDropped, err := item.stdout.readBytes(request.StdoutCursor, limit)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	stderr, nextErr, errDropped, err := item.stderr.readBytes(request.StderrCursor, limit)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	item.mu.Lock()
	item.lastLease = time.Now()
	done := item.done
	exitCode := item.exitCode
	errorCode := item.errorCode
	item.mu.Unlock()
	writeJSON(w, 200, map[string]any{"executionId": item.execution, "stdout": string(stdout), "stderr": string(stderr), "stdoutBase64": base64.StdEncoding.EncodeToString(stdout), "stderrBase64": base64.StdEncoding.EncodeToString(stderr), "stdoutCursor": nextOut, "stderrCursor": nextErr, "stdoutBytes": item.stdout.length(), "stderrBytes": item.stderr.length(), "stdoutTruncated": outDropped, "stderrTruncated": errDropped, "done": done, "exitCode": exitCode, "errorCode": errorCode, "encoding": "utf8-lossy"})
}
func (s *server) asyncExecCancel(w http.ResponseWriter, r *http.Request) {
	var request asyncExecRequest
	if !decodeRequest(w, r, &request) || !requireID(w, request.ID) {
		return
	}
	item, err := s.execution(request)
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	item.mu.Lock()
	done := item.done
	ended := item.processEnded
	exitCode := item.exitCode
	if !done && !ended {
		item.cancelled = true
	}
	item.mu.Unlock()
	if done {
		writeJSON(w, 200, map[string]any{"executionId": item.execution, "cancelled": false, "done": true, "ownershipReleased": true, "outcome": "complete", "exitCode": exitCode})
		return
	}
	if ended {
		writeJSON(w, 202, map[string]any{"executionId": item.execution, "cancelled": false, "done": false, "outcome": "completionPending"})
		return
	}
	if !done {
		item.stop()
	}
	select {
	case <-item.stopped:
		item.mu.Lock()
		verified := item.cleanupVerified
		item.mu.Unlock()
		writeJSON(w, 200, map[string]any{"executionId": item.execution, "cancelled": true, "done": verified, "ownershipReleased": verified, "outcome": map[bool]string{true: "cancelled", false: "reconciliationRequired"}[verified]})
	case <-time.After(6 * time.Second):
		writeJSON(w, 202, map[string]any{"executionId": item.execution, "cancelled": true, "done": false, "outcome": "cancellationPending"})
	}
}
func (s *server) asyncExecRelease(w http.ResponseWriter, r *http.Request) {
	var request asyncExecRequest
	if !decodeRequest(w, r, &request) || !requireID(w, request.ID) {
		return
	}
	item, err := s.execution(request)
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	item.mu.Lock()
	done := item.done
	item.mu.Unlock()
	if !done {
		writeError(w, 409, "cancel running execution before releasing output")
		return
	}
	manager := s.asyncManager()
	manager.mu.Lock()
	delete(manager.entries, item.execution)
	manager.mu.Unlock()
	writeJSON(w, 200, map[string]any{"released": true, "executionId": request.ExecutionID})
}
