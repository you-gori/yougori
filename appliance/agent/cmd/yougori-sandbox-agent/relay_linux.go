package main

// The connections the agent relays over the link, one stream each: a guest program's
// connection to a declared endpoint's listener on the egress channel (egress_linux.go, the
// guest opens the stream), and the host's caller of a published guest service on the ingress
// channel (ingress_linux.go, the host opens the stream and the agent dials the service).
// Bytes the connection's program writes go to the host within the host's credit for that
// stream, one chunk in flight at a time; bytes the host sends go to the program and are
// credited back to their stream once written (protocol version 3: each stream has a window
// of its own, so a program or a host reader that stops holds back only its own stream); the
// program's end of writing ends the guest's direction, the host's end closes the program's
// read side, and a cancel or a revocation closes the connection. The agent parses nothing
// of the bytes.

import (
	"net"
	"sort"

	"yougori.local/appliance-agent/link"
)

// relayKey names one relayed stream: its channel and its id there.
type relayKey struct {
	channel link.Channel
	stream  uint32
}

// relayInbound is the next chunk the connection's program wrote; the reader waits for its
// ack.
type relayInbound struct {
	key   relayKey
	bytes []byte
}

// relayInboundEnd says the program ended its writing (or its connection failed).
type relayInboundEnd struct{ key relayKey }

// relayWritten says the writer handed the host's bytes to the program.
type relayWritten struct {
	key   relayKey
	bytes int
}

// relayWriteEnd says the writer closed the program's read side (the host's direction
// ended), or failed, in which case the connection is gone.
type relayWriteEnd struct {
	key    relayKey
	failed bool
}

type relayStream struct {
	key       relayKey
	name      string
	conn      net.Conn
	opened    bool
	toConn    chan []byte
	inBuf     []byte
	inBusy    bool
	hostEnd   bool
	endQueue  bool
	writeDone bool
	outPend   []byte
	outAck    chan struct{}
	readDone  bool
	endSent   bool
	stop      chan struct{}
	cancelled bool
}

func newRelayStream(channel link.Channel, stream uint32, name string, conn net.Conn) *relayStream {
	return &relayStream{
		key:    relayKey{channel: channel, stream: stream},
		name:   name,
		conn:   conn,
		toConn: make(chan []byte, 1),
		outAck: make(chan struct{}, 1),
		stop:   make(chan struct{}),
	}
}

// relays is the table of `channel`'s relayed streams.
func (s *session) relays(channel link.Channel) map[uint32]*relayStream {
	if channel == link.ChannelIngress {
		return s.ingress
	}
	return s.egress
}

func (s *session) relay(key relayKey) *relayStream {
	return s.relays(key.channel)[key.stream]
}

// startRelay starts moving bytes once the stream is open both ways. The stream's program is
// expected to read as fast as the host sends, so it is granted its grown window at once
// (within the channel's growth quota): a relayed download is not held to the first window
// while the relay's bytes wait on the host.
func (s *session) startRelay(st *relayStream) {
	st.opened = true
	if err := s.ep.GrowStream(st.key.channel, st.key.stream); err != nil {
		s.logf("%s stream %d not grown: %v", st.key.channel, st.key.stream, err)
	}
	go s.relayReadLoop(st, s.ep.MaxDataBytes(st.key.channel))
	go s.relayWriteLoop(st)
}

// relayReadLoop reads what the program writes, one chunk in flight at a time.
func (s *session) relayReadLoop(st *relayStream, chunkBytes int) {
	buffer := make([]byte, chunkBytes)
	for {
		n, err := st.conn.Read(buffer)
		if n > 0 {
			select {
			case s.events <- relayInbound{key: st.key, bytes: append([]byte(nil), buffer[:n]...)}:
			case <-st.stop:
				return
			}
			select {
			case <-st.outAck:
			case <-st.stop:
				return
			}
		}
		if err != nil {
			select {
			case s.events <- relayInboundEnd{key: st.key}:
			case <-st.stop:
			}
			return
		}
	}
}

// relayWriteLoop hands the host's bytes to the program; a nil chunk ends its read side.
func (s *session) relayWriteLoop(st *relayStream) {
	for chunk := range st.toConn {
		if chunk == nil {
			failed := false
			if half, ok := st.conn.(interface{ CloseWrite() error }); ok {
				failed = half.CloseWrite() != nil
			}
			select {
			case s.events <- relayWriteEnd{key: st.key, failed: failed}:
			case <-st.stop:
			}
			continue
		}
		written := len(chunk)
		if _, err := st.conn.Write(chunk); err != nil {
			select {
			case s.events <- relayWriteEnd{key: st.key, failed: true}:
			case <-st.stop:
			}
			return
		}
		select {
		case s.events <- relayWritten{key: st.key, bytes: written}:
		case <-st.stop:
			return
		}
	}
}

// relayData queues the host's bytes for the program; bytes for a stream nobody reads any
// more are credited at once (until the stream's cancel lands).
func (s *session) relayData(m link.Data) {
	st := s.relay(relayKey{channel: m.Chan, stream: m.Stream})
	if st == nil || st.cancelled || st.hostEnd {
		_ = s.ep.ConsumeStream(m.Chan, m.Stream, uint32(len(m.Bytes)))
		return
	}
	st.inBuf = append(st.inBuf, m.Bytes...)
	s.feedConn(st)
}

// relayHostEnded takes the host's end of its direction of a stream.
func (s *session) relayHostEnded(key relayKey) {
	if st := s.relay(key); st != nil {
		st.hostEnd = true
		s.feedConn(st)
	}
}

func (s *session) feedConn(st *relayStream) {
	if st.inBusy || st.cancelled || !st.opened || st.endQueue {
		return
	}
	if len(st.inBuf) > 0 {
		take := len(st.inBuf)
		if take > connChunkBytes {
			take = connChunkBytes
		}
		chunk := append([]byte(nil), st.inBuf[:take]...)
		st.inBuf = st.inBuf[take:]
		st.inBusy = true
		st.toConn <- chunk
		return
	}
	if st.hostEnd {
		st.endQueue = true
		st.toConn <- nil
	}
}

// flushRelays turns what programs wrote into data frames as far as the host's credit for
// each stream allows, in stream order (a stream without credit waits, the others go on),
// and ends a stream's guest direction once its program ended writing and every byte went
// out.
func (s *session) flushRelays() {
	if s.outcome != nil {
		return
	}
	for _, channel := range []link.Channel{link.ChannelEgress, link.ChannelIngress} {
		s.flushRelaysOn(channel)
	}
}

func (s *session) flushRelaysOn(channel link.Channel) {
	maxData := s.ep.MaxDataBytes(channel)
	for _, st := range s.sortedRelays(channel) {
		if !st.opened || st.cancelled {
			continue
		}
		for len(st.outPend) > 0 {
			credit := s.ep.StreamSendCredit(channel, st.key.stream)
			if credit == 0 {
				break
			}
			n := len(st.outPend)
			if n > maxData {
				n = maxData
			}
			if uint64(n) > credit {
				n = int(credit)
			}
			if err := s.ep.Send(link.Data{Chan: channel, Stream: st.key.stream, Bytes: st.outPend[:n]}); err != nil {
				if refusal, ok := err.(*link.SendRefusal); ok && refusal.Code == "queue_full" {
					return
				}
				break
			}
			st.outPend = st.outPend[n:]
			if len(st.outPend) == 0 {
				st.outPend = nil
				st.outAck <- struct{}{}
			}
		}
		s.maybeEndRelay(st)
	}
}

// maybeEndRelay ends the guest's direction once the program ended writing and every byte
// went out, and tears the stream down once both directions ended.
func (s *session) maybeEndRelay(st *relayStream) {
	if st.cancelled || s.relay(st.key) == nil {
		return
	}
	if st.readDone && len(st.outPend) == 0 && !st.endSent {
		if err := s.ep.Send(link.EndOfStream{Chan: st.key.channel, Stream: st.key.stream}); err != nil {
			if refusal, ok := err.(*link.SendRefusal); ok && refusal.Code == "queue_full" {
				return
			}
			s.logf("%s stream %d end not sent: %v", st.key.channel, st.key.stream, err)
			s.cancelRelay(st, true, link.CancelFailed)
			return
		}
		st.endSent = true
	}
	if st.endSent && st.writeDone {
		s.teardownRelay(st)
	}
}

// cancelRelay closes the program's connection; tell sends the cancel to the host.
func (s *session) cancelRelay(st *relayStream, tell bool, cause link.CancelCause) {
	if st.cancelled {
		return
	}
	st.cancelled = true
	if tell {
		_ = s.ep.Send(link.Cancel{Chan: st.key.channel, Stream: st.key.stream, Cause: cause})
	}
	s.teardownRelay(st)
}

// teardownRelay releases a stream: its stop signal and its connection. Its unread bytes
// need no credit: the stream's window goes with it.
func (s *session) teardownRelay(st *relayStream) {
	table := s.relays(st.key.channel)
	if table[st.key.stream] == nil {
		return
	}
	delete(table, st.key.stream)
	close(st.stop)
	if st.conn != nil {
		st.conn.Close()
	}
	st.inBuf = nil
	close(st.toConn)
}

// cancelAllRelays cancels every stream of `channel`.
func (s *session) cancelAllRelays(channel link.Channel, tell bool, cause link.CancelCause) {
	for _, st := range s.sortedRelays(channel) {
		s.cancelRelay(st, tell, cause)
	}
}

func (s *session) sortedRelays(channel link.Channel) []*relayStream {
	table := s.relays(channel)
	ids := make([]uint32, 0, len(table))
	for id := range table {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	streams := make([]*relayStream, 0, len(ids))
	for _, id := range ids {
		streams = append(streams, table[id])
	}
	return streams
}

// handleRelayEvent handles the relay helpers' events; false when the event is not one.
func (s *session) handleRelayEvent(event any) bool {
	switch e := event.(type) {
	case relayInbound:
		if st := s.relay(e.key); st != nil && !st.cancelled {
			st.outPend = e.bytes
		}
	case relayInboundEnd:
		if st := s.relay(e.key); st != nil {
			st.readDone = true
			s.maybeEndRelay(st)
		}
	case relayWritten:
		_ = s.ep.ConsumeStream(e.key.channel, e.key.stream, uint32(e.bytes))
		if st := s.relay(e.key); st != nil {
			st.inBusy = false
			s.feedConn(st)
		}
	case relayWriteEnd:
		if st := s.relay(e.key); st != nil {
			st.writeDone = true
			if e.failed && !st.endSent {
				// The program's connection is gone; the host's stream ends with it.
				s.cancelRelay(st, true, link.CancelFailed)
				return true
			}
			s.maybeEndRelay(st)
		}
	default:
		return false
	}
	return true
}
