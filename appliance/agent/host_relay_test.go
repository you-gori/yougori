package main

import (
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func readRelayFrame(t *testing.T, c net.Conn) (byte, uint32, []byte) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	var header [9]byte
	if _, err := io.ReadFull(c, header[:]); err != nil {
		t.Fatal(err)
	}
	size := binary.BigEndian.Uint32(header[5:])
	if size > relayMaxPayload {
		t.Fatal("oversized frame")
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(c, payload); err != nil {
		t.Fatal(err)
	}
	return header[0], binary.BigEndian.Uint32(header[1:5]), payload
}

func TestHostRelayBidirectionalAndRevocation(t *testing.T) {
	relay, host := net.Pipe()
	defer relay.Close()
	defer host.Close()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() { serveHostRelay(relay, listener); close(done) }()
	client, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	kind, id, _ := readRelayFrame(t, host)
	if kind != 1 || id == 0 {
		t.Fatal("missing open frame")
	}
	if _, err = client.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	kind, responseID, payload := readRelayFrame(t, host)
	if kind != 2 || responseID != id || string(payload) != "request" {
		t.Fatal("wrong request frame")
	}
	if err = (&relayWriter{connection: host}).frame(2, id, []byte("response")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 8)
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err = io.ReadFull(client, reply); err != nil || string(reply) != "response" {
		t.Fatal("missing response", err)
	}
	host.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("relay survived revocation")
	}
	if _, err = client.Read(reply); err == nil {
		t.Fatal("guest connection survived revocation")
	}
}

func TestHostRelayRejectsMalformedFrames(t *testing.T) {
	for _, value := range []struct {
		kind     byte
		id, size uint32
	}{{2, 0, 1}, {2, 1, 65537}, {1, 1, 0}, {3, 1, 1}, {99, 1, 0}} {
		relay, host := net.Pipe()
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() { serveHostRelay(relay, listener); relay.Close(); close(done) }()
		var header [9]byte
		header[0] = value.kind
		binary.BigEndian.PutUint32(header[1:5], value.id)
		binary.BigEndian.PutUint32(header[5:], value.size)
		host.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err = host.Write(header[:]); err != nil {
			t.Fatal(err)
		}
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("malformed relay stayed open")
		}
		host.Close()
		listener.Close()
	}
}

func TestCUDAStreamsRequireAuthentication(t *testing.T) {
	t.Setenv("YOUGORI_CUDA_MODE", "1")
	s := &server{token: strings.Repeat("a", 64)}
	for _, handler := range []http.HandlerFunc{s.hostRelay, s.fabricStream, s.verifyCUDA, s.localServicePorts} {
		reply := httptest.NewRecorder()
		s.auth(method(http.MethodPost, handler))(reply, httptest.NewRequest("POST", "/", strings.NewReader(`{"id":"env-test"}`)))
		if reply.Code != 401 {
			t.Fatalf("unauthorized stream status %d", reply.Code)
		}
	}
}

func TestCUDALocalPublishingRejectsUntrustedDestinations(t *testing.T) {
	t.Setenv("YOUGORI_CUDA_MODE", "1")
	localPorts.Lock()
	beforePorts, beforeAddress := localPorts.ports, localPorts.hostAddress
	localPorts.Unlock()
	defer func() {
		localPorts.Lock()
		localPorts.ports, localPorts.hostAddress = beforePorts, beforeAddress
		localPorts.Unlock()
	}()
	s := &server{}
	for _, address := range []string{"8.8.8.8", "127.0.0.1", "::1", "fc00::1", "0.0.0.0", "host.example", "192.168.1.1/24", "192.168.1.1:7443"} {
		reply := httptest.NewRecorder()
		s.localServicePorts(reply, httptest.NewRequest("POST", "/", strings.NewReader(`{"ids":[],"ports":[3000],"hostAddress":"`+address+`"}`)))
		if reply.Code != 400 {
			t.Fatalf("untrusted destination %s accepted: %d", address, reply.Code)
		}
	}
	for _, address := range []string{"192.168.1.2", "10.1.2.3", "172.16.1.2", ""} {
		reply := httptest.NewRecorder()
		s.localServicePorts(reply, httptest.NewRequest("POST", "/", strings.NewReader(`{"ids":[],"ports":[3000],"hostAddress":"`+address+`"}`)))
		if reply.Code != 200 {
			t.Fatalf("private destination %s rejected: %d", address, reply.Code)
		}
	}
	t.Setenv("YOUGORI_CUDA_MODE", "0")
	reply := httptest.NewRecorder()
	s.localServicePorts(reply, httptest.NewRequest("POST", "/", strings.NewReader(`{"ids":[],"ports":[3000],"hostAddress":"192.168.1.2"}`)))
	if reply.Code != 400 {
		t.Fatal("the legacy QEMU gateway was allowed to change")
	}
}
