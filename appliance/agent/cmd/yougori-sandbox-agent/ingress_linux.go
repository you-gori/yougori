package main

// The guest's side of ingress (M14; VM part §4.7, VM-W13): once the host admitted a caller
// to a service the sandbox published, it opens an ingress stream to a listener named
// `port-N`. The agent dials the guest's own loopback address on port N and answers `Opened`
// once the service accepted, or `OpenRefused`: `RefuseUnsupported` for a name of any other
// form, `RefuseUnavailable` when nothing listens there or no stream may open now (before the
// welcome, after a revocation, during a shutdown, past the stream bound). The connection is
// then relayed as relay_linux.go describes. Which services are published, to whom and for how
// long is the host's to decide; the agent dials nothing but 127.0.0.1.

import (
	"net"
	"strconv"
	"strings"
	"time"

	"yougori.local/appliance-agent/link"
)

const (
	// ingressListenerPrefix starts the name of a listener on a guest port.
	ingressListenerPrefix = "port-"
	// maxIngressStreams bounds the ingress connections open at once.
	maxIngressStreams = 128
	// ingressDialTimeout bounds how long a dial to a guest service may take.
	ingressDialTimeout = 5 * time.Second
)

// ingressPort is the guest port a listener name names: `port-` and a number from 1 to
// 65535 in decimal, with no sign and no leading zero.
func ingressPort(listener string) (int, bool) {
	digits, ok := strings.CutPrefix(listener, ingressListenerPrefix)
	if !ok || digits == "" || len(digits) > 5 || digits[0] == '0' {
		return 0, false
	}
	for _, r := range digits {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	port, err := strconv.Atoi(digits)
	if err != nil || port < 1 || port > 65535 {
		return 0, false
	}
	return port, true
}

// ingressDialed is a dial for an ingress stream, done.
type ingressDialed struct {
	stream uint32
	conn   net.Conn
	err    error
}

// openIngress takes the host's open of an ingress stream: refused at once, or dialed in the
// background and answered when the dial is done.
func (s *session) openIngress(m link.OpenIngress) {
	refuse := func(cause link.OpenRefusalCause) {
		_ = s.ep.Send(link.OpenRefused{Chan: link.ChannelIngress, Stream: m.Stream, Cause: cause})
	}
	port, ok := ingressPort(m.Listener)
	if !ok {
		refuse(link.RefuseUnsupported)
		return
	}
	if !s.welcomed || s.revoked || s.shutdownAt != nil || s.outcome != nil || len(s.ingress) >= maxIngressStreams || s.ingress[m.Stream] != nil {
		refuse(link.RefuseUnavailable)
		return
	}
	st := newRelayStream(link.ChannelIngress, m.Stream, m.Listener, nil)
	s.ingress[m.Stream] = st
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	go func() {
		conn, err := net.DialTimeout("tcp", address, ingressDialTimeout)
		select {
		case s.events <- ingressDialed{stream: m.Stream, conn: conn, err: err}:
		case <-st.stop:
			if conn != nil {
				conn.Close()
			}
		}
	}()
}

// ingressDone answers a dialed ingress stream: opened and relayed, or refused when nothing
// listens. A stream cancelled while it was dialed closes the connection.
func (s *session) ingressDone(e ingressDialed) {
	st := s.ingress[e.stream]
	if st == nil || st.cancelled || st.conn != nil {
		if e.conn != nil {
			e.conn.Close()
		}
		return
	}
	if e.err != nil {
		s.logf("ingress %d to %s refused: %v", e.stream, st.name, e.err)
		_ = s.ep.Send(link.OpenRefused{Chan: link.ChannelIngress, Stream: e.stream, Cause: link.RefuseUnavailable})
		st.cancelled = true
		s.teardownRelay(st)
		return
	}
	if err := s.ep.Send(link.Opened{Chan: link.ChannelIngress, Stream: e.stream}); err != nil {
		s.logf("ingress %d to %s not answered: %v", e.stream, st.name, err)
		e.conn.Close()
		st.cancelled = true
		s.teardownRelay(st)
		return
	}
	st.conn = e.conn
	s.startRelay(st)
}

// endAllIngress ends every ingress stream: one still being dialed is refused, an open one
// cancelled; tell says whether the host is told.
func (s *session) endAllIngress(tell bool, cause link.CancelCause) {
	for _, st := range s.sortedRelays(link.ChannelIngress) {
		if !st.opened {
			if tell {
				_ = s.ep.Send(link.OpenRefused{Chan: link.ChannelIngress, Stream: st.key.stream, Cause: link.RefuseUnavailable})
			}
			st.cancelled = true
			s.teardownRelay(st)
			continue
		}
		s.cancelRelay(st, tell, cause)
	}
}

// handleIngressEvent handles a finished dial; false when the event is not one.
func (s *session) handleIngressEvent(event any) bool {
	dialed, ok := event.(ingressDialed)
	if ok {
		s.ingressDone(dialed)
	}
	return ok
}
