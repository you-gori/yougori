package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestTerminalStreamRealPTYTypingAndResize(t *testing.T) {
	s := &server{token: "test-secret", microVM: true}
	request := httptest.NewRequest("POST", "/", strings.NewReader(`{"id":"env-stream-test","sessionId":"term-test","cols":80,"rows":24}`))
	reply := httptest.NewRecorder()
	s.terminalCreate(reply, request)
	if reply.Code != 201 {
		t.Fatalf("create PTY: %s", reply.Body.String())
	}
	t.Cleanup(func() {
		s.terminalClose(httptest.NewRecorder(), httptest.NewRequest("POST", "/", strings.NewReader(`{"id":"env-stream-test","sessionId":"term-test"}`)))
	})
	mux := http.NewServeMux()
	s.registerWorkspaceRoutes(mux)
	server := httptest.NewServer(mux)
	defer server.Close()
	conn := openTestTerminalStream(t, server, "env-stream-test", 0)
	var ready map[string]int
	if err := conn.ReadJSON(&ready); err != nil {
		t.Fatal(err)
	}
	resize := []byte{2, 0, 140, 0, 50}
	if err := conn.WriteMessage(websocket.BinaryMessage, resize); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := conn.WriteMessage(websocket.BinaryMessage, append([]byte{1}, []byte("stty size; printf 'terminal-output-%s\\n' ok\r")...)); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var output []byte
	for !bytes.Contains(output, []byte("terminal-output-ok")) {
		kind, frame, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("PTY output: %q %v", output, err)
		}
		if kind != websocket.BinaryMessage || len(frame) < 9 || frame[0] != 3 {
			t.Fatalf("invalid PTY frame: %x", frame)
		}
		output = append(output, frame[9:]...)
	}
	if !bytes.Contains(output, []byte("50 140")) {
		t.Fatalf("resize: %q", output)
	}
	t.Logf("real PTY command-to-output: %s", time.Since(start))
}

func streamFixture(t *testing.T, id string, session *terminalSession) *httptest.Server {
	t.Helper()
	s := &server{token: "test-secret"}
	s.terminals.Store(id, session)
	mux := http.NewServeMux()
	s.registerWorkspaceRoutes(mux)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func openTestTerminalStream(t *testing.T, server *httptest.Server, env string, offset uint64) *websocket.Conn {
	t.Helper()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/v1/terminal/stream", http.Header{"Authorization": []string{"Bearer test-secret"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if err = conn.WriteJSON(terminalRequest{ID: env, SessionID: "term-test", Offset: offset}); err != nil {
		t.Fatal(err)
	}
	return conn
}

func TestTerminalStreamDuplexNotificationsAndExit(t *testing.T) {
	input, master, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer master.Close()
	session := &terminalSession{environment: "env-test", master: master, changed: make(chan struct{})}
	server := streamFixture(t, "term-test", session)
	conn := openTestTerminalStream(t, server, "env-test", 0)
	var ready map[string]int
	if err := conn.ReadJSON(&ready); err != nil || ready["terminalStreamVersion"] != 1 {
		t.Fatalf("ready: %v, %v", ready, err)
	}
	if err := conn.WriteMessage(websocket.BinaryMessage, append([]byte{1}, []byte("hello\x00\x1b[A")...)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 9)
	if _, err := io.ReadFull(input, got); err != nil || string(got) != "hello\x00\x1b[A" {
		t.Fatalf("input: %q %v", got, err)
	}
	// Notify output with no client read request or polling delay.
	session.mu.Lock()
	session.output = []byte{0xff, 0, 27, 'x'}
	session.notifyLocked()
	session.mu.Unlock()
	conn.SetReadDeadline(time.Now().Add(time.Second))
	kind, frame, err := conn.ReadMessage()
	if err != nil || kind != websocket.BinaryMessage || len(frame) != 13 || frame[0] != 3 || binary.BigEndian.Uint64(frame[1:9]) != 4 || !bytes.Equal(frame[9:], session.output) {
		t.Fatalf("output: %v %x %v", kind, frame, err)
	}
	session.mu.Lock()
	session.done = true
	session.notifyLocked()
	session.mu.Unlock()
	_, frame, err = conn.ReadMessage()
	if err != nil || !bytes.Equal(frame, []byte{4}) {
		t.Fatalf("exit: %x %v", frame, err)
	}
}

func TestTerminalStreamOutputContinuesWhileInputIsBlocked(t *testing.T) {
	input, master, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer master.Close()
	session := &terminalSession{environment: "env-test", master: master, changed: make(chan struct{})}
	server := streamFixture(t, "term-test", session)
	conn := openTestTerminalStream(t, server, "env-test", 0)
	var ready map[string]int
	if err := conn.ReadJSON(&ready); err != nil {
		t.Fatal(err)
	}
	// Nobody reads the pipe: a write exceeds its capacity and stalls.
	if err := conn.WriteMessage(websocket.BinaryMessage, append([]byte{1}, make([]byte, 16*1024)...)); err != nil {
		t.Fatal(err)
	}
	session.mu.Lock()
	session.output = []byte("still responsive")
	session.notifyLocked()
	session.mu.Unlock()
	conn.SetReadDeadline(time.Now().Add(time.Second))
	_, frame, err := conn.ReadMessage()
	if err != nil || string(frame[9:]) != "still responsive" {
		t.Fatalf("blocked input delayed output: %x %v", frame, err)
	}
}

func TestTerminalStreamRejectsWrongEnvironmentAndExpiredCursor(t *testing.T) {
	session := &terminalSession{environment: "env-test", base: 100, output: []byte("hello"), done: true}
	server := streamFixture(t, "term-test", session)
	conn := openTestTerminalStream(t, server, "env-other", 100)
	_, frame, err := conn.ReadMessage()
	if err != nil || len(frame) < 2 || frame[0] != 5 || !strings.Contains(string(frame), "another environment") {
		t.Fatalf("ownership: %x %v", frame, err)
	}
	conn = openTestTerminalStream(t, server, "env-test", 0)
	var ready map[string]int
	if err := conn.ReadJSON(&ready); err != nil {
		t.Fatal(err)
	}
	_, frame, err = conn.ReadMessage()
	if err != nil || frame[0] != 5 || !strings.Contains(string(frame), "cursor expired") {
		t.Fatalf("cursor: %x %v", frame, err)
	}
}

func TestTerminalStreamRequiresAuthAndRejectsBrowserOrigins(t *testing.T) {
	server := streamFixture(t, "term-test", &terminalSession{environment: "env-test"})
	for _, headers := range []http.Header{{}, {"Authorization": []string{"Bearer test-secret"}, "Origin": []string{"https://example.com"}}} {
		conn, response, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/v1/terminal/stream", headers)
		if conn != nil {
			conn.Close()
			t.Fatal("unauthorized upgrade")
		}
		if err == nil || response == nil || (response.StatusCode != 401 && response.StatusCode != 403) {
			t.Fatalf("expected denial, %v %v", response, err)
		}
	}
}

func TestTerminalStreamBackpressurePreservesUnreadOutputAndReleasesOnClose(t *testing.T) {
	progress := uint64(0)
	session := &terminalSession{output: bytes.Repeat([]byte{'a'}, 1024*1024), changed: make(chan struct{}), streamOffset: &progress}
	appended := make(chan bool, 1)
	go func() { appended <- session.appendOutput([]byte("tail")) }()
	select {
	case <-appended:
		t.Fatal("producer overwrote unread bytes")
	case <-time.After(20 * time.Millisecond):
	}
	session.mu.Lock()
	progress = 512 * 1024
	session.notifyLocked()
	session.mu.Unlock()
	select {
	case ok := <-appended:
		if !ok {
			t.Fatal("append stopped")
		}
	case <-time.After(time.Second):
		t.Fatal("producer did not resume")
	}
	session.mu.Lock()
	if session.base != 512*1024 || len(session.output) > 1024*1024 || !bytes.HasSuffix(session.output, []byte("tail")) {
		t.Fatal("bounded output was lost")
	}
	session.output = bytes.Repeat([]byte{'b'}, 1024*1024)
	progress = session.base
	session.mu.Unlock()
	go func() { appended <- session.appendOutput([]byte("more")) }()
	select {
	case <-appended:
		t.Fatal("producer was not blocked")
	case <-time.After(20 * time.Millisecond):
	}
	session.mu.Lock()
	session.done = true
	session.notifyLocked()
	session.mu.Unlock()
	select {
	case ok := <-appended:
		if ok {
			t.Fatal("append continued after close")
		}
	case <-time.After(time.Second):
		t.Fatal("close did not release producer")
	}
}
