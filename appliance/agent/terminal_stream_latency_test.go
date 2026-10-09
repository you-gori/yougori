package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// Impose 50 ms in each direction on real TCP traffic. Both old HTTP polling
// and the new WebSocket reach the same real PTY through this listener.
type terminalLatencyConn struct{ net.Conn }

func (c terminalLatencyConn) Read(p []byte) (int, error) {
	n, e := c.Conn.Read(p)
	if n > 0 {
		time.Sleep(50 * time.Millisecond)
	}
	return n, e
}
func (c terminalLatencyConn) Write(p []byte) (int, error) {
	time.Sleep(50 * time.Millisecond)
	return c.Conn.Write(p)
}

type terminalLatencyListener struct{ net.Listener }

func (l terminalLatencyListener) Accept() (net.Conn, error) {
	c, e := l.Listener.Accept()
	if e != nil {
		return nil, e
	}
	return terminalLatencyConn{c}, nil
}

func TestTerminalStreamLatencyComparedWithSequentialPolling(t *testing.T) {
	if testing.Short() {
		t.Skip("controlled 100 ms network latency")
	}
	s := &server{token: "test-secret", microVM: true}
	create := httptest.NewRecorder()
	s.terminalCreate(create, httptest.NewRequest("POST", "/", strings.NewReader(`{"id":"env-latency","sessionId":"term-test","cols":80,"rows":24}`)))
	if create.Code != 201 {
		t.Fatal(create.Body.String())
	}
	defer s.terminalClose(httptest.NewRecorder(), httptest.NewRequest("POST", "/", strings.NewReader(`{"id":"env-latency","sessionId":"term-test"}`)))
	mux := http.NewServeMux()
	s.registerWorkspaceRoutes(mux)
	server := httptest.NewUnstartedServer(mux)
	server.Listener = terminalLatencyListener{server.Listener}
	server.Start()
	defer server.Close()
	var offset uint64
	rpc := func(action string, data string) []byte {
		t.Helper()
		body, _ := json.Marshal(terminalRequest{ID: "env-latency", SessionID: "term-test", Data: data, Offset: offset})
		request, _ := http.NewRequest("POST", server.URL+"/v1/terminal/"+action, bytes.NewReader(body))
		request.Header.Set("Authorization", "Bearer test-secret")
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var value struct {
			Data   string
			Offset uint64
		}
		if err = json.NewDecoder(response.Body).Decode(&value); err != nil || response.StatusCode != 200 {
			t.Fatalf("RPC: %v %v", response.StatusCode, err)
		}
		if action == "read" {
			offset = value.Offset
		}
		output, _ := base64.StdEncoding.DecodeString(value.Data)
		return output
	}
	rpc("read", "") // Consume the initial shell prompt.
	var legacy, streamed []time.Duration
	for i := 0; i < 10; i++ {
		marker := fmt.Sprintf("poll-result-%d", i)
		start := time.Now()
		rpc("read", "") // Current CLI waits here before collecting input.
		command := fmt.Sprintf("printf 'poll-result-%%s\\n' %d\r", i)
		rpc("write", base64.StdEncoding.EncodeToString([]byte(command)))
		var output []byte
		for !bytes.Contains(output, []byte(marker)) {
			output = append(output, rpc("read", "")...)
		}
		legacy = append(legacy, time.Since(start))
	}
	conn := openTestTerminalStream(t, server, "env-latency", offset)
	var ready map[string]int
	if err := conn.ReadJSON(&ready); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		marker := fmt.Sprintf("stream-result-%d", i)
		command := fmt.Sprintf("printf 'stream-result-%%s\\n' %d\r", i)
		start := time.Now()
		if err := conn.WriteMessage(websocket.BinaryMessage, append([]byte{1}, []byte(command)...)); err != nil {
			t.Fatal(err)
		}
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		var output []byte
		for !bytes.Contains(output, []byte(marker)) {
			_, frame, err := conn.ReadMessage()
			if err != nil || len(frame) < 9 || frame[0] != 3 {
				t.Fatalf("stream: %x %v", frame, err)
			}
			output = append(output, frame[9:]...)
		}
		streamed = append(streamed, time.Since(start))
	}
	sort.Slice(legacy, func(i, j int) bool { return legacy[i] < legacy[j] })
	sort.Slice(streamed, func(i, j int) bool { return streamed[i] < streamed[j] })
	t.Logf("controlled 100ms RTT, 10 real PTY commands: polling median=%s p95=%s; streaming median=%s p95=%s; median speedup=%.2fx", legacy[5], legacy[9], streamed[5], streamed[9], float64(legacy[5])/float64(streamed[5]))
	if streamed[5] >= legacy[5]*7/10 {
		t.Fatalf("streaming did not remove sequential network waits")
	}
}
