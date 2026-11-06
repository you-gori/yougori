package main

import (
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"yougori.local/appliance-agent/link"
)

// PROVES only `port-` and a port number from 1 to 65535, written plainly, names a listener.
func TestAListenerNameNamesOneGuestPort(t *testing.T) {
	for name, want := range map[string]int{"port-1": 1, "port-8080": 8080, "port-65535": 65535} {
		if port, ok := ingressPort(name); !ok || port != want {
			t.Fatalf("%q: %d %v", name, port, ok)
		}
	}
	for _, name := range []string{"web", "port-", "port-0", "port-08", "port-65536", "port--1", "port-+80", "port-80 ", "port-1e3", "PORT-80", "port-99999999"} {
		if port, ok := ingressPort(name); ok {
			t.Fatalf("%q was taken as port %d", name, port)
		}
	}
}

// serviceOnLoopback is a guest service's listener on an ephemeral port, accepting one
// connection onto the channel.
func serviceOnLoopback(t *testing.T) (int, <-chan net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port, accepted
}

func acceptedWithin(t *testing.T, accepted <-chan net.Conn) net.Conn {
	t.Helper()
	select {
	case conn := <-accepted:
		t.Cleanup(func() { conn.Close() })
		return conn
	case <-time.After(5 * time.Second):
		t.Fatal("the service was never dialed")
	}
	return nil
}

func ingressAnswer(stream uint32) func(link.Message) bool {
	return func(m link.Message) bool {
		switch answer := m.(type) {
		case link.Opened:
			return answer.Chan == link.ChannelIngress && answer.Stream == stream
		case link.OpenRefused:
			return answer.Chan == link.ChannelIngress && answer.Stream == stream
		}
		return false
	}
}

// PROVES the host's ingress stream to `port-N` reaches the guest service listening on
// 127.0.0.1:N, answered `Opened` once the service accepted: the host's bytes reach the
// service, the service's reach the host, the host's end closes the service's read side, and
// the service's close ends the guest's direction.
func TestAnIngressStreamReachesAGuestServiceAndCarriesBothDirections(t *testing.T) {
	port, accepted := serviceOnLoopback(t)
	h := startSession(t, link.DefaultLimits(), true)
	h.handshake(t)
	h.host.send(link.OpenIngress{Stream: 2, Listener: "port-" + strconv.Itoa(port)})
	if _, ok := h.host.waitMessage(ingressAnswer(2), 5*time.Second).(link.Opened); !ok {
		t.Fatal("the open was refused")
	}
	conn := acceptedWithin(t, accepted)
	const request = "GET / HTTP/1.1\r\nhost: preview\r\n\r\n"
	h.host.send(link.Data{Chan: link.ChannelIngress, Stream: 2, Bytes: []byte(request)})
	got := make([]byte, len(request))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != request {
		t.Fatalf("the service read %q (%v)", got, err)
	}
	const response = "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nhi"
	if _, err := conn.Write([]byte(response)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for h.host.output(2) != response && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if out := h.host.output(2); out != response {
		t.Fatalf("the host received %q", out)
	}
	h.host.send(link.EndOfStream{Chan: link.ChannelIngress, Stream: 2})
	if n, err := conn.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("the service's read side stayed open: %d %v", n, err)
	}
	conn.Close()
	h.host.waitMessage(func(m link.Message) bool {
		end, ok := m.(link.EndOfStream)
		return ok && end.Chan == link.ChannelIngress && end.Stream == 2
	}, 5*time.Second)
}

// PROVES an ingress open is refused, and nothing dialed, for a port nothing listens on
// (`RefuseUnavailable`) and for a name of another form (`RefuseUnsupported`).
func TestAnIngressOpenToNoServiceOrAnUnknownNameIsRefused(t *testing.T) {
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := closed.Addr().(*net.TCPAddr).Port
	closed.Close()
	h := startSession(t, link.DefaultLimits(), true)
	h.handshake(t)
	h.host.send(link.OpenIngress{Stream: 2, Listener: "port-" + strconv.Itoa(port)})
	refused, ok := h.host.waitMessage(ingressAnswer(2), 10*time.Second).(link.OpenRefused)
	if !ok || refused.Cause != link.RefuseUnavailable {
		t.Fatalf("%+v", refused)
	}
	// In order: a host's stream ids only rise.
	for index, name := range []string{"web", "port-0", "port-65536"} {
		stream := uint32(4 + 2*index)
		h.host.send(link.OpenIngress{Stream: stream, Listener: name})
		refused, ok := h.host.waitMessage(ingressAnswer(stream), 5*time.Second).(link.OpenRefused)
		if !ok || refused.Cause != link.RefuseUnsupported {
			t.Fatalf("%q: %+v", name, refused)
		}
	}
}

// PROVES a revocation cancels every ingress stream (told to the host) and closes the
// service's connection, and that an open after it is refused.
func TestRevokeCancelsIngressStreamsAndRefusesLaterOpens(t *testing.T) {
	port, accepted := serviceOnLoopback(t)
	h := startSession(t, link.DefaultLimits(), true)
	h.handshake(t)
	listener := "port-" + strconv.Itoa(port)
	h.host.send(link.OpenIngress{Stream: 2, Listener: listener})
	if _, ok := h.host.waitMessage(ingressAnswer(2), 5*time.Second).(link.Opened); !ok {
		t.Fatal("the open was refused")
	}
	conn := acceptedWithin(t, accepted)
	h.host.send(link.Revoke{Reason: link.RevokedSecurityEvent, AuthorizationEpoch: 9})
	cancel := h.host.waitMessage(func(m link.Message) bool {
		c, ok := m.(link.Cancel)
		return ok && c.Chan == link.ChannelIngress
	}, 5*time.Second).(link.Cancel)
	if cancel.Stream != 2 || cancel.Cause != link.CancelRevoked {
		t.Fatalf("cancel %+v", cancel)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("the service's connection stayed open after the revocation")
	}
	h.host.send(link.OpenIngress{Stream: 4, Listener: listener})
	refused, ok := h.host.waitMessage(ingressAnswer(4), 5*time.Second).(link.OpenRefused)
	if !ok || refused.Cause != link.RefuseUnavailable {
		t.Fatalf("an open after the revocation: %+v", refused)
	}
}
