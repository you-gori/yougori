package main

// The guest's egress client (M06 guest side, VM part §3.1): each endpoint the host declared
// at boot (link.EgressEndpointsPath) gets a loopback address of its own in the guest,
// `127.0.0.2` for the first, on port 80, and a line in /etc/hosts mapping the destination
// host name to it, so a guest program that asks for `http://api.example.com/...` reaches
// the agent's listener for that endpoint. Every accepted connection becomes one egress
// stream on the link (`OpenEgress` with the endpoint's name; the host's relay parses the
// bytes, the broker authorizes them), relayed as relay_linux.go describes. A sandbox
// connection endpoint (M14) listens on its own port instead, for any TCP protocol: its
// stream goes through the host's connection gate to the service of another sandbox it was
// granted, or is cancelled. The agent parses nothing of the bytes.

import (
	"fmt"
	"net"
	"os"
	"strings"

	"golang.org/x/sys/unix"

	"yougori.local/appliance-agent/link"
)

const (
	// hostsPath is where the guest's resolver reads names; the root is read-only, so the
	// agent's own file is bind-mounted over it.
	hostsPath = "/etc/hosts"
	// runHostsPath holds the agent's hosts file on /run.
	runHostsPath = "/run/yougori/hosts"
	// maxEgressStreams bounds the connections open at once over all endpoints.
	maxEgressStreams = 128
	// connChunkBytes is the most handed to one write to a guest connection.
	connChunkBytes = 32 << 10
)

// egressAddress is the loopback address of endpoint `index` in the production guest: on
// port 80 for a relay route (the relay takes plain HTTP from the guest), on the endpoint's
// own port for a sandbox connection endpoint.
func egressAddress(index int, endpoint link.EgressEndpoint) string {
	port := uint16(80)
	if endpoint.Connection {
		port = endpoint.Port
	}
	return fmt.Sprintf("127.0.0.%d:%d", 2+index, port)
}

// hostsFile is the guest's /etc/hosts for `endpoints`: localhost, then each destination
// host at its endpoint's loopback address.
func hostsFile(endpoints []link.EgressEndpoint) string {
	var text strings.Builder
	text.WriteString("127.0.0.1 localhost\n::1 localhost\n")
	for index, endpoint := range endpoints {
		fmt.Fprintf(&text, "127.0.0.%d %s\n", 2+index, endpoint.Host)
	}
	return text.String()
}

// installHosts writes the hosts file on /run and bind-mounts it read-only over /etc/hosts.
func installHosts(endpoints []link.EgressEndpoint) error {
	if err := os.WriteFile(runHostsPath, []byte(hostsFile(endpoints)), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", runHostsPath, err)
	}
	if err := unix.Mount(runHostsPath, hostsPath, "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind %s over %s: %w", runHostsPath, hostsPath, err)
	}
	if err := unix.Mount("", hostsPath, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("make %s read-only: %w", hostsPath, err)
	}
	return nil
}

// egressBound tells a test where an endpoint's listener is.
type egressBound struct {
	name    string
	address net.Addr
}

// egressAccepted is a guest program's connection to an endpoint's listener.
type egressAccepted struct {
	name string
	conn net.Conn
}

// listenEgress binds one listener per endpoint at `address(index, endpoint)` and feeds every
// accepted connection to `events`; each bound address is told on `bound` when given.
func listenEgress(endpoints []link.EgressEndpoint, address func(int, link.EgressEndpoint) string, events chan<- any, bound chan<- egressBound) ([]net.Listener, error) {
	var listeners []net.Listener
	for index, endpoint := range endpoints {
		listener, err := net.Listen("tcp", address(index, endpoint))
		if err != nil {
			for _, open := range listeners {
				open.Close()
			}
			return nil, fmt.Errorf("listen for %s at %s: %w", endpoint.Name, address(index, endpoint), err)
		}
		listeners = append(listeners, listener)
		if bound != nil {
			bound <- egressBound{name: endpoint.Name, address: listener.Addr()}
		}
		go func(name string, listener net.Listener) {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				events <- egressAccepted{name: name, conn: conn}
			}
		}(endpoint.Name, listener)
	}
	return listeners, nil
}

func (s *session) closeListeners() {
	for _, listener := range s.listeners {
		listener.Close()
	}
	s.listeners = nil
}

// acceptEgress opens an egress stream for a connection, or closes it when the guest may
// not open one now.
func (s *session) acceptEgress(e egressAccepted) {
	if !s.welcomed || s.revoked || s.shutdownAt != nil || s.outcome != nil || len(s.egress) >= maxEgressStreams {
		e.conn.Close()
		return
	}
	stream := s.nextEgress
	s.nextEgress += 2
	if err := s.ep.Send(link.OpenEgress{Stream: stream, Destination: e.name}); err != nil {
		s.logf("egress %d to %s not opened: %v", stream, e.name, err)
		e.conn.Close()
		return
	}
	s.egress[stream] = newRelayStream(link.ChannelEgress, stream, e.name, e.conn)
}

func (s *session) egressOpened(m link.Opened) {
	st := s.egress[m.Stream]
	if st == nil || st.opened {
		return
	}
	s.startRelay(st)
}

func (s *session) egressRefused(m link.OpenRefused) {
	if st := s.egress[m.Stream]; st != nil {
		s.logf("egress %d to %s refused by the host (cause %d)", st.key.stream, st.name, m.Cause)
		s.teardownRelay(st)
	}
}

// handleEgressEvent handles a program's new connection to an endpoint's listener; false when
// the event is not one.
func (s *session) handleEgressEvent(event any) bool {
	accepted, ok := event.(egressAccepted)
	if ok {
		s.acceptEgress(accepted)
	}
	return ok
}
