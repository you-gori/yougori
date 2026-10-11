package main

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCommandOutputKeepsOnlyTheMostRecentBytes(t *testing.T) {
	var output boundedOutput
	chunk := bytes.Repeat([]byte("a"), 64*1024)
	for written := 0; written < 3*commandOutputLimit; written += len(chunk) {
		output.Write(chunk)
	}
	output.Write([]byte("final result"))
	text := output.String()
	if len(text) > commandOutputLimit+64 || !strings.HasSuffix(text, "final result") || !strings.HasPrefix(text, "[") || !strings.Contains(text, "earlier bytes of output omitted") {
		t.Fatalf("unbounded or misleading output: %d bytes, prefix %q", len(text), text[:40])
	}
	if cap(output.data) > 2*commandOutputLimit+len(chunk) {
		t.Fatalf("buffer grew to %d bytes", cap(output.data))
	}
	var large boundedOutput
	large.Write(bytes.Repeat([]byte("b"), commandOutputLimit+10))
	if len(large.String()) > commandOutputLimit+64 {
		t.Fatal("a single large write was retained")
	}
	var small boundedOutput
	small.Write([]byte("ok\n"))
	if small.String() != "ok\n" {
		t.Fatalf("small output changed: %q", small.String())
	}
}

func TestDNSExceptionsComeFromTheApplianceResolver(t *testing.T) {
	got := parseNameservers("# generated\nnameserver 10.0.2.3\nnameserver 127.0.0.53\nnameserver 10.0.2.3\nnameserver fe80::1\nnameserver 0.0.0.0\nnameserver 1.1.1.1\nnameserver 8.8.8.8\nnameserver 9.9.9.9\nsearch lan\n")
	if strings.Join(got, ",") != "10.0.2.3,1.1.1.1,8.8.8.8" {
		t.Fatalf("unexpected DNS exceptions: %v", got)
	}
}

func TestWorkloadMountReleaseMatchesOnlyThatEnvironment(t *testing.T) {
	s := &server{}
	// Releasing "web" must not reach "web-2" slots. A matched entry would call
	// Unmount on this placeholder and fail the test.
	s.hostShares.Store("workload:web-2-0", &mountedHostShare{})
	s.hostShares.Store("workload:webapp-0", &mountedHostShare{})
	s.releaseWorkloadMounts("web")
	for _, key := range []string{"workload:web-2-0", "workload:webapp-0"} {
		if _, ok := s.hostShares.Load(key); !ok {
			t.Fatalf("released another environment's mount %s", key)
		}
	}
	if !validWorkloadSlot("web-2", "web-2-0") || validWorkloadSlot("web", "web-2-0") {
		t.Fatal("slot ownership is ambiguous")
	}
}

func TestHostShareMountPointsAreUnambiguous(t *testing.T) {
	if hostShareMountPath("a-b", "c") == hostShareMountPath("a", "b-c") {
		t.Fatal("different shares use one mount point")
	}
	if !strings.HasPrefix(hostShareMountPath("env", "share"), hostShareRoot+"/") || hostShareMountPath("env", "share") != hostShareMountPath("env", "share") {
		t.Fatal("mount point is not stable under the host share root")
	}
}

func TestFinishedExecutionsDoNotBlockNewWork(t *testing.T) {
	manager := &asyncManager{entries: map[string]*asyncExecution{}}
	for index := 0; index < asyncMaxRetained; index++ {
		item := &asyncExecution{execution: "exec-" + strings.Repeat("x", index+1), done: true, completed: time.Unix(int64(index), 0)}
		manager.entries[item.execution] = item
	}
	if !manager.admit() || len(manager.entries) >= asyncMaxRetained {
		t.Fatal("finished executions blocked a new one")
	}
	if _, ok := manager.entries["exec-x"]; ok {
		t.Fatal("the oldest finished execution was kept instead of the newest")
	}
	running := &asyncManager{entries: map[string]*asyncExecution{}}
	for index := 0; index < asyncMaxSessions; index++ {
		item := &asyncExecution{execution: "exec-" + strings.Repeat("r", index+1)}
		running.entries[item.execution] = item
	}
	if running.admit() {
		t.Fatal("running executions exceeded the limit")
	}
}

func TestExitedTerminalsDoNotCountTowardTheLimit(t *testing.T) {
	s := &server{}
	now := time.Now()
	for index := 0; index < terminalLimit; index++ {
		s.terminals.Store("term-done-"+strings.Repeat("d", index+1), &terminalSession{done: true, doneAt: now})
	}
	s.terminals.Store("term-old", &terminalSession{done: true, doneAt: now.Add(-2 * exitedTerminalRetention)})
	s.terminals.Store("term-live", &terminalSession{})
	if live := s.liveTerminals(now); live != 1 {
		t.Fatalf("counted %d live terminals", live)
	}
	if _, ok := s.terminals.Load("term-old"); ok {
		t.Fatal("abandoned exited terminal was kept")
	}
	if _, ok := s.terminals.Load("term-done-d"); !ok {
		t.Fatal("recently exited terminal output was discarded")
	}
}

func TestStartupRejectsAnImageThatLooksLikeAFlag(t *testing.T) {
	s := &server{}
	reply := httptest.NewRecorder()
	s.startup(reply, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"id":"env-test","command":"","image":"--help"}`)))
	if reply.Code != http.StatusBadRequest {
		t.Fatalf("flag-like image reached nerdctl: %d %s", reply.Code, reply.Body.String())
	}
}

func TestTerminalInputDeadlineWorks(t *testing.T) {
	master, slave, err := openPTY(80, 24)
	if err != nil {
		t.Skipf("pseudo-terminals unavailable: %v", err)
	}
	defer master.Close()
	defer slave.Close()
	resizePTY(master, 100, 30)
	// Raw mode: canonical input discards an overlong line instead of filling.
	termios, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	termios.Lflag &^= unix.ICANON | unix.ECHO
	if err := unix.IoctlSetTermios(int(slave.Fd()), unix.TCSETS, termios); err != nil {
		t.Fatal(err)
	}
	// Nobody reads the terminal, so input eventually fills its queue. A master
	// left in blocking mode would ignore the deadline and hang here.
	if err := master.SetWriteDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() {
		chunk := bytes.Repeat([]byte("x"), 4096)
		for {
			if _, err := master.Write(chunk); err != nil {
				finished <- err
				return
			}
		}
	}()
	select {
	case err := <-finished:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("unexpected write failure: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("terminal write ignored its deadline")
	}
}
