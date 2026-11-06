package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestHostShareBinaryReadsReuseAuthenticatedConnection(t *testing.T) {
	var connections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer private-test-capability" || r.Header.Get("Accept") != "application/octet-stream" {
			w.WriteHeader(403)
			return
		}
		var request struct {
			Operation, Path string
			Offset, Length  int
		}
		if json.NewDecoder(r.Body).Decode(&request) != nil || request.Operation != "read" || request.Path != "weights.bin" {
			w.WriteHeader(400)
			return
		}
		value := strings.Repeat("x", 131072)
		if request.Offset > len(value) {
			request.Offset = len(value)
		}
		value = value[request.Offset:min(len(value), request.Offset+request.Length)]
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(value)))
		fmt.Fprint(w, value)
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.Start()
	defer server.Close()
	node := &hostFileNode{endpoint: server.URL, token: "private-test-capability", relative: "weights.bin"}
	for _, offset := range []int64{0, 65536, 131072, 0} {
		data, errno := node.readBytes(context.Background(), make([]byte, 131072), offset)
		if errno != 0 || string(data) != strings.Repeat("x", 131072-int(offset)) {
			t.Fatalf("offset %d: bytes=%d errno=%v", offset, len(data), errno)
		}
	}
	if connections.Load() != 1 {
		t.Fatalf("reads opened %d connections", connections.Load())
	}
}

func TestHostShareReadKeepsLegacyCompatibilityAndRefusesBadBodiesWithoutRetry(t *testing.T) {
	for _, test := range []struct {
		name, kind, body string
		status           int
		want             syscall.Errno
	}{
		{"legacy", "application/json", `{"data":"` + base64.StdEncoding.EncodeToString([]byte("abc")) + `"}`, 200, 0},
		{"legacy-too-long", "application/json", `{"data":"YWJjZA=="}`, 200, syscall.EIO},
		{"legacy-trailing", "application/json", `{"data":"YWJj"}{}`, 200, syscall.EIO},
		{"legacy-error", "application/json", `{"data":"YWJj","error":"denied"}`, 200, syscall.EIO},
		{"binary-too-long", "application/octet-stream", "abcd", 200, syscall.EIO},
		{"binary", "application/octet-stream", "abc", 200, 0},
		{"unrecognised", "text/html", "abc", 200, syscall.EIO},
		{"denied", "application/json", `{"data":"YWJj"}`, 403, syscall.EACCES},
		{"missing", "application/json", `{}`, 404, syscall.ENOENT},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", test.kind)
				w.Header().Set("Content-Length", strconv.Itoa(len(test.body)))
				w.WriteHeader(test.status)
				fmt.Fprint(w, test.body)
			}))
			defer server.Close()
			node := &hostFileNode{endpoint: server.URL}
			data, errno := node.readBytes(context.Background(), make([]byte, 3), 0)
			if errno != test.want || (errno == 0 && string(data) != "abc") || calls.Load() != 1 {
				t.Fatalf("data=%q errno=%v calls=%d", data, errno, calls.Load())
			}
		})
	}
}

func TestHostShareReadRefusesTruncationChunkingAndRedirect(t *testing.T) {
	for _, mode := range []string{"truncated", "chunked", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			var forwarded atomic.Int32
			destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				forwarded.Add(1)
				w.WriteHeader(200)
			}))
			defer destination.Close()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/octet-stream")
				switch mode {
				case "truncated":
					w.Header().Set("Content-Length", "8")
					fmt.Fprint(w, "abc")
				case "chunked":
					w.(http.Flusher).Flush()
					fmt.Fprint(w, "abc")
				case "redirect":
					http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
				}
			}))
			defer server.Close()
			node := &hostFileNode{endpoint: server.URL}
			_, errno := node.readBytes(context.Background(), make([]byte, 8), 0)
			if errno != syscall.EIO || forwarded.Load() != 0 {
				t.Fatalf("errno=%v forwarded=%d", errno, forwarded.Load())
			}
		})
	}
}

func TestHostShareReadCancellationEndsPendingBody(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", "100")
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	node := &hostFileNode{endpoint: server.URL}
	result := make(chan syscall.Errno, 1)
	go func() { _, errno := node.readBytes(ctx, make([]byte, 100), 0); result <- errno }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("request never arrived")
	}
	cancel()
	select {
	case errno := <-result:
		if errno != syscall.EIO {
			t.Fatalf("cancelled read succeeded: %v", errno)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled read kept waiting for the body")
	}
}
