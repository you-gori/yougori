package main

// The guest's link session (brief deliverables 1 and 3, M06 guest side): one goroutine
// owns the link endpoint; a reader, a writer and per-terminal helpers feed it events, so
// no endpoint state is shared. The session says hello once the host's challenge bound the
// connection, grants terminal, egress, ingress and file credit after the welcome, answers
// pings, keeps the host's idle timer alive, runs terminal streams, serves the egress
// endpoints' listeners (egress_linux.go), dials published guest services for the host's
// ingress streams (ingress_linux.go) and serves the workspace mount's file requests (files_linux.go,
// workspace_linux.go), cancels every stream on Cancel or Revoke, refuses new opens after a
// revocation or during a shutdown, and ends on a close, a lost transport, a link
// violation or a completed shutdown. The caller powers the guest off afterwards; nothing
// restarts.

import (
	"io"
	"log"
	"net"
	"sort"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"

	"yougori.local/appliance-agent/link"
)

const (
	// defaultTerminalGrant is the credit the guest opens for host stdin data on the
	// terminal channel, shared by every terminal stream (at most the channel's 1 MiB).
	defaultTerminalGrant = 256 << 10
	// stdinChunkBytes is the most handed to one stdin write.
	stdinChunkBytes = 32 << 10
	// drainTimeout bounds how long the session waits to write its last frames.
	drainTimeout = 2 * time.Second
)

type sessionConfig struct {
	endpoint      *link.Endpoint
	transport     io.ReadWriter
	spawner       spawner
	hello         link.Hello
	terminalGrant uint32
	tickInterval  time.Duration
	logger        *log.Logger
	// egress lists the endpoints the host declared; each gets a listener at
	// egressAddress(index) (the production loopback addresses when nil). egressBound,
	// when given, is told each listener's address (tests). The host's egress and ingress
	// data needs no grant: each stream opens with a window of its own (protocol 3).
	egress        []link.EgressEndpoint
	egressAddress func(index int, endpoint link.EgressEndpoint) string
	egressBound   chan<- egressBound
	// workspace mounts the staged workspace at workspaceMount (workspace_linux.go);
	// filesClient, when given, receives the workspace grant's file client (tests).
	workspace   bool
	filesClient chan<- *filesClient
	// image is the OCI image the sandbox runs (oci_image_linux.go), or nil.
	image *workloadImage
}

// sessionOutcome is how the session ended.
type sessionOutcome struct {
	cause    link.CloseCause
	shutdown bool
	lost     bool
}

type inboundBytes struct{ bytes []byte }
type inboundEnd struct{ err error }
type writeFailed struct{ err error }
type stdinWritten struct {
	stream uint32
	bytes  int
}
type terminalOutput struct {
	stream uint32
	bytes  []byte
}
type terminalOutputEnd struct{ stream uint32 }
type terminalExited struct {
	stream uint32
	code   int32
}

type terminal struct {
	stream     uint32
	process    terminalProcess
	stdinBuf   []byte
	stdinBusy  bool
	stdinEOF   bool
	stdinShut  bool
	stdinCh    chan []byte
	outPending []byte
	outAck     chan struct{}
	stop       chan struct{}
	outputDone bool
	exited     bool
	code       int32
	cancelled  bool
}

type session struct {
	config      sessionConfig
	ep          *link.Endpoint
	events      chan any
	out         chan []byte
	writerReady chan struct{}
	terminals   map[uint32]*terminal
	egress      map[uint32]*relayStream
	// nextEgress is the next guest-opened egress stream id (odd, rising).
	nextEgress uint32
	// ingress are the host-opened ingress streams, dialing or relayed (ingress_linux.go).
	ingress map[uint32]*relayStream
	// files are the file requests in flight (files_linux.go), fileQueue those waiting for
	// a stream, nextFile the next guest-opened file stream id (odd, rising).
	files     map[uint32]*fileStream
	fileQueue []fileCall
	nextFile  uint32
	// workspaceServer serves the workspace mount, when there is one.
	workspaceServer *fuse.Server
	listeners       []net.Listener
	welcomed        bool
	revoked         bool
	shutdownAt      *time.Time
	lastSent        time.Time
	pingNonce       uint64
	outcome         *sessionOutcome
	lost            bool
	// The image's materialization: started, ready or failed (with why), and the terminals
	// opened before it ended.
	imageStarted     bool
	imageIsReady     bool
	imageFailure     string
	pendingTerminals []link.OpenTerminal
}

func runSession(config sessionConfig) sessionOutcome {
	if config.terminalGrant == 0 {
		config.terminalGrant = defaultTerminalGrant
	}
	if config.tickInterval == 0 {
		config.tickInterval = time.Second
	}
	if config.egressAddress == nil {
		config.egressAddress = egressAddress
	}
	s := &session{
		config:      config,
		ep:          config.endpoint,
		events:      make(chan any, 64),
		out:         make(chan []byte, 64),
		writerReady: make(chan struct{}, 1),
		terminals:   map[uint32]*terminal{},
		egress:      map[uint32]*relayStream{},
		nextEgress:  1,
		ingress:     map[uint32]*relayStream{},
		files:       map[uint32]*fileStream{},
		nextFile:    1,
		lastSent:    time.Now(),
	}
	if len(config.egress) > 0 {
		listeners, err := listenEgress(config.egress, config.egressAddress, s.events, config.egressBound)
		if err != nil {
			s.logf("egress endpoints not served: %v", err)
		}
		s.listeners = listeners
	}
	client := &filesClient{events: s.events, grant: workspaceGrant, messageRoom: s.ep.MaxDataBytes(link.ChannelFile)}
	if config.filesClient != nil {
		config.filesClient <- client
	}
	if config.workspace {
		server, err := mountWorkspace(client)
		if err != nil {
			s.logf("the workspace is not mounted: %v", err)
		} else {
			s.workspaceServer = server
			s.logf("the workspace is mounted at %s", workspaceMount)
		}
	}
	go s.readLoop()
	go s.writeLoop()
	ticker := time.NewTicker(config.tickInterval)
	defer ticker.Stop()
	for s.outcome == nil {
		select {
		case event := <-s.events:
			s.handle(event)
		case <-s.writerReady:
		case <-ticker.C:
			s.handleLink(s.ep.Tick())
			s.keepAlive()
			s.shutdownProgress()
		}
		s.flushOutput()
		s.flushRelays()
		s.flushFiles()
		s.flush()
	}
	s.closeListeners()
	s.failAllFiles(errFileChannelClosed, false, 0)
	if s.workspaceServer != nil {
		_ = s.workspaceServer.Unmount()
	}
	s.killAll()
	if !s.lost {
		s.drain()
	}
	return *s.outcome
}

func (s *session) logf(format string, args ...any) {
	if s.config.logger != nil {
		s.config.logger.Printf(format, args...)
	}
}

func (s *session) readLoop() {
	buffer := make([]byte, 64<<10)
	for {
		n, err := s.config.transport.Read(buffer)
		if n > 0 {
			s.events <- inboundBytes{bytes: append([]byte(nil), buffer[:n]...)}
		}
		if err != nil {
			s.events <- inboundEnd{err: err}
			return
		}
	}
}

func (s *session) writeLoop() {
	for frame := range s.out {
		for len(frame) > 0 {
			n, err := s.config.transport.Write(frame)
			if err != nil {
				s.events <- writeFailed{err: err}
				return
			}
			frame = frame[n:]
		}
		select {
		case s.writerReady <- struct{}{}:
		default:
		}
	}
}

// flush moves the endpoint's queued frames to the writer while it has room.
func (s *session) flush() {
	for len(s.out) < cap(s.out) {
		frame := s.ep.NextOutbound()
		if frame == nil {
			return
		}
		s.out <- frame
		s.lastSent = time.Now()
	}
}

// drain gives the writer a bounded time to write the last frames, the close included.
func (s *session) drain() {
	deadline := time.Now().Add(drainTimeout)
	for time.Now().Before(deadline) {
		s.flush()
		if len(s.out) == 0 && s.ep.QueuedFrames() == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(s.out)
	// Let the writer finish the frame it holds.
	time.Sleep(50 * time.Millisecond)
}

func (s *session) handle(event any) {
	if s.handleEgressEvent(event) || s.handleRelayEvent(event) || s.handleIngressEvent(event) || s.handleFileEvent(event) {
		return
	}
	switch e := event.(type) {
	case imageReady:
		s.imageMaterialized(e)
	case inboundBytes:
		s.handleLink(s.ep.Receive(e.bytes))
	case inboundEnd:
		s.logf("the link transport ended: %v", e.err)
		s.lost = true
		s.handleLink(s.ep.PeerClosed())
		if s.outcome == nil {
			s.finish(sessionOutcome{cause: s.ep.Cause(), lost: true})
		}
	case writeFailed:
		s.logf("writing the link failed: %v", e.err)
		s.lost = true
		s.handleLink(s.ep.PeerClosed())
		if s.outcome == nil {
			s.finish(sessionOutcome{cause: s.ep.Cause(), lost: true})
		}
	case stdinWritten:
		_ = s.ep.Consume(link.ChannelTerminal, uint32(e.bytes))
		if t := s.terminals[e.stream]; t != nil {
			t.stdinBusy = false
			s.feedStdin(t)
		}
	case terminalOutput:
		if t := s.terminals[e.stream]; t != nil && !t.cancelled {
			t.outPending = e.bytes
		}
	case terminalOutputEnd:
		if t := s.terminals[e.stream]; t != nil {
			t.outputDone = true
			s.maybeFinish(t)
		}
	case terminalExited:
		if t := s.terminals[e.stream]; t != nil {
			t.exited = true
			t.code = e.code
			// The shell is gone; nothing it left behind may keep the output open.
			t.process.Kill()
			s.maybeFinish(t)
		}
	}
}

func (s *session) handleLink(events []link.Event) {
	for _, event := range events {
		switch e := event.(type) {
		case link.MessageEvent:
			s.dispatch(e.Message)
		case link.RefusedEvent:
			s.logf("refused a host frame: %s (%s)", e.Refusal.Reason.Code, e.Refusal.Reason.Detail)
		case link.ClosedEvent:
			s.logf("the link closed: %s", e.Cause)
			s.finish(sessionOutcome{cause: e.Cause, shutdown: s.shutdownAt != nil, lost: s.lost})
		case link.ChannelClosedEvent:
			s.logf("the %s channel closed: %s", e.Channel, e.Reason.Code)
			if e.Channel == link.ChannelTerminal {
				for _, t := range s.sortedTerminals() {
					s.cancelTerminal(t, false, link.CancelFailed)
				}
			}
			if e.Channel == link.ChannelEgress {
				s.cancelAllRelays(link.ChannelEgress, false, link.CancelFailed)
			}
			if e.Channel == link.ChannelIngress {
				s.endAllIngress(false, link.CancelFailed)
			}
			if e.Channel == link.ChannelFile {
				s.failAllFiles(errFileChannelClosed, false, 0)
			}
		case link.StreamTimedOutEvent:
			if e.Channel == link.ChannelTerminal {
				s.removePendingTerminal(e.Stream)
			}
			if t := s.terminals[e.Stream]; t != nil && e.Channel == link.ChannelTerminal {
				s.cancelTerminal(t, false, link.CancelTimedOut)
			}
			if e.Channel == link.ChannelEgress || e.Channel == link.ChannelIngress {
				if st := s.relay(relayKey{channel: e.Channel, stream: e.Stream}); st != nil {
					s.cancelRelay(st, false, link.CancelTimedOut)
				}
			}
			if st := s.files[e.Stream]; st != nil && e.Channel == link.ChannelFile {
				s.endFile(st, fileReply{err: syscall.ETIMEDOUT})
			}
		}
	}
}

func (s *session) dispatch(message link.Message) {
	switch m := message.(type) {
	case link.Challenge:
		if err := s.ep.Send(s.config.hello); err != nil {
			s.logf("hello refused locally: %v", err)
			_ = s.ep.Send(link.Close{Reason: link.CloseProtocolViolation})
			s.finish(sessionOutcome{cause: s.ep.Cause()})
		}
	case link.Welcome:
		s.logf("welcomed: frames up to %d bytes, idle timeout %d s", m.MaxFrameBytes, m.IdleTimeoutSeconds)
		s.welcomed = true
		if err := s.ep.Grant(link.ChannelTerminal, s.config.terminalGrant); err != nil {
			s.logf("terminal credit not granted: %v", err)
		}
		// Egress and ingress streams open with windows of their own (protocol 3).
		fileGrant := uint32(defaultFileGrant)
		if window := s.ep.Limits().File.MaxBufferedBytes; uint64(fileGrant) > window {
			fileGrant = uint32(window)
		}
		if err := s.ep.Grant(link.ChannelFile, fileGrant); err != nil {
			s.logf("file credit not granted: %v", err)
		}
	case link.Ping:
		_ = s.ep.Send(link.Pong{Nonce: m.Nonce})
	case link.Revoke:
		s.pendingTerminals = nil
		s.logf("authority revoked (reason %d, epoch %d)", m.Reason, m.AuthorizationEpoch)
		s.revoked = true
		for _, t := range s.sortedTerminals() {
			s.cancelTerminal(t, true, link.CancelRevoked)
		}
		s.cancelAllRelays(link.ChannelEgress, true, link.CancelRevoked)
		s.endAllIngress(true, link.CancelRevoked)
		s.failAllFiles(syscall.EACCES, true, link.CancelRevoked)
	case link.Shutdown:
		s.pendingTerminals = nil
		if s.shutdownAt == nil {
			deadline := time.Now().Add(time.Duration(m.GraceSeconds) * time.Second)
			s.shutdownAt = &deadline
			s.logf("shutdown requested with %d s grace", m.GraceSeconds)
			for _, t := range s.terminals {
				t.process.Terminate()
			}
			s.shutdownProgress()
		}
	case link.OpenTerminal:
		s.openTerminal(m)
	case link.OpenIngress:
		s.openIngress(m)
	case link.OpenFile:
		_ = s.ep.Send(link.OpenRefused{Chan: link.ChannelFile, Stream: m.Stream, Cause: link.RefuseUnsupported})
	case link.Opened:
		switch m.Chan {
		case link.ChannelEgress:
			s.egressOpened(m)
		case link.ChannelFile:
			s.fileOpened(m)
		}
	case link.OpenRefused:
		switch m.Chan {
		case link.ChannelEgress:
			s.egressRefused(m)
		case link.ChannelFile:
			s.fileRefused(m)
		}
	case link.Data:
		switch m.Chan {
		case link.ChannelEgress, link.ChannelIngress:
			s.relayData(m)
		case link.ChannelFile:
			s.fileData(m)
		default:
			s.stdinData(m)
		}
	case link.EndOfStream:
		if t := s.terminals[m.Stream]; t != nil && m.Chan == link.ChannelTerminal {
			t.stdinEOF = true
			s.feedStdin(t)
		}
		if m.Chan == link.ChannelEgress || m.Chan == link.ChannelIngress {
			s.relayHostEnded(relayKey{channel: m.Chan, stream: m.Stream})
		}
		if m.Chan == link.ChannelFile {
			s.fileEnded(m)
		}
	case link.Cancel:
		if m.Chan == link.ChannelTerminal {
			s.removePendingTerminal(m.Stream)
		}
		if t := s.terminals[m.Stream]; t != nil && m.Chan == link.ChannelTerminal {
			// The endpoint already forgot the stream; nothing more is sent for it.
			s.cancelTerminal(t, false, m.Cause)
		}
		if m.Chan == link.ChannelEgress || m.Chan == link.ChannelIngress {
			if st := s.relay(relayKey{channel: m.Chan, stream: m.Stream}); st != nil {
				s.cancelRelay(st, false, m.Cause)
			}
		}
		if m.Chan == link.ChannelFile {
			s.fileCancelled(m)
		}
	case link.Resize:
		// No pty in this slice: the size is accepted and ignored.
	}
}

func (s *session) openTerminal(m link.OpenTerminal) {
	refuse := func(cause link.OpenRefusalCause) {
		_ = s.ep.Send(link.OpenRefused{Chan: link.ChannelTerminal, Stream: m.Stream, Cause: cause})
	}
	if s.revoked {
		refuse(link.RefuseNotAuthorized)
		return
	}
	if s.shutdownAt != nil {
		refuse(link.RefuseUnavailable)
		return
	}
	if s.config.image != nil && !s.imageIsReady && s.imageFailure == "" {
		// The host attaches the read-only image grant after the handshake, before it
		// opens a terminal. Waiting for this first open avoids racing that attachment.
		s.pendingTerminals = append(s.pendingTerminals, m)
		s.startImage()
		return
	}
	var process terminalProcess
	var err error
	if m.ImageEntrypoint {
		spawner, ok := s.config.spawner.(interface {
			SpawnImage(uint32) (terminalProcess, error)
		})
		if !ok || s.config.image == nil {
			refuse(link.RefuseNotAuthorized)
			return
		}
		process, err = spawner.SpawnImage(m.Stream)
	} else {
		process, err = s.config.spawner.Spawn(m.Stream)
	}
	if err != nil {
		s.logf("terminal %d did not start: %v", m.Stream, err)
		refuse(link.RefuseUnavailable)
		return
	}
	if err := s.ep.Send(link.Opened{Chan: link.ChannelTerminal, Stream: m.Stream}); err != nil {
		s.logf("terminal %d could not be answered: %v", m.Stream, err)
		process.Kill()
		process.Release()
		return
	}
	t := &terminal{
		stream:  m.Stream,
		process: process,
		stdinCh: make(chan []byte, 1),
		outAck:  make(chan struct{}, 1),
		stop:    make(chan struct{}),
	}
	s.terminals[m.Stream] = t
	go s.stdinLoop(t)
	go s.outputLoop(t, s.ep.MaxDataBytes(link.ChannelTerminal))
	go func() { s.events <- terminalExited{stream: t.stream, code: <-process.Exited()} }()
}

func (s *session) removePendingTerminal(stream uint32) {
	for i, pending := range s.pendingTerminals {
		if pending.Stream == stream {
			s.pendingTerminals = append(s.pendingTerminals[:i], s.pendingTerminals[i+1:]...)
			return
		}
	}
}

// stdinLoop writes chunks to the shell's stdin; a nil chunk closes it.
func (s *session) stdinLoop(t *terminal) {
	stdin := t.process.Stdin()
	for chunk := range t.stdinCh {
		if chunk == nil {
			_ = stdin.Close()
			continue
		}
		written := len(chunk)
		_, _ = stdin.Write(chunk)
		s.events <- stdinWritten{stream: t.stream, bytes: written}
	}
	_ = stdin.Close()
}

// outputLoop reads the merged output in chunks the link can carry and waits until the
// session has sent each chunk before reading on, so at most one chunk is held.
func (s *session) outputLoop(t *terminal, chunkBytes int) {
	output := t.process.Output()
	defer output.Close()
	buffer := make([]byte, chunkBytes)
	for {
		n, err := output.Read(buffer)
		if n > 0 {
			select {
			case s.events <- terminalOutput{stream: t.stream, bytes: append([]byte(nil), buffer[:n]...)}:
			case <-t.stop:
				return
			}
			select {
			case <-t.outAck:
			case <-t.stop:
				return
			}
		}
		if err != nil {
			select {
			case s.events <- terminalOutputEnd{stream: t.stream}:
			case <-t.stop:
			}
			return
		}
	}
}

func (s *session) stdinData(m link.Data) {
	t := s.terminals[m.Stream]
	if m.Chan != link.ChannelTerminal || t == nil || t.cancelled || t.stdinShut {
		// Nobody reads it any more: return the credit at once.
		_ = s.ep.Consume(m.Chan, uint32(len(m.Bytes)))
		return
	}
	t.stdinBuf = append(t.stdinBuf, m.Bytes...)
	s.feedStdin(t)
}

func (s *session) feedStdin(t *terminal) {
	if t.stdinBusy || t.stdinShut || t.cancelled {
		return
	}
	if len(t.stdinBuf) > 0 {
		take := len(t.stdinBuf)
		if take > stdinChunkBytes {
			take = stdinChunkBytes
		}
		chunk := append([]byte(nil), t.stdinBuf[:take]...)
		t.stdinBuf = t.stdinBuf[take:]
		t.stdinBusy = true
		t.stdinCh <- chunk
		return
	}
	if t.stdinEOF {
		t.stdinShut = true
		t.stdinCh <- nil
	}
}

// flushOutput turns pending terminal output into data frames as far as the host's credit
// allows, in stream order.
func (s *session) flushOutput() {
	if s.outcome != nil {
		return
	}
	maxData := s.ep.MaxDataBytes(link.ChannelTerminal)
	for _, t := range s.sortedTerminals() {
		for len(t.outPending) > 0 {
			credit := s.ep.Channel(link.ChannelTerminal).SendCredit
			if credit == 0 {
				return
			}
			n := len(t.outPending)
			if n > maxData {
				n = maxData
			}
			if uint64(n) > credit {
				n = int(credit)
			}
			if err := s.ep.Send(link.Data{Chan: link.ChannelTerminal, Stream: t.stream, Bytes: t.outPending[:n]}); err != nil {
				return
			}
			t.outPending = t.outPending[n:]
			if len(t.outPending) == 0 {
				t.outPending = nil
				t.outAck <- struct{}{}
			}
		}
		s.maybeFinish(t)
	}
}

// maybeFinish sends the exit once the shell exited and every output byte went out; the
// exit ends the guest's direction of the stream.
func (s *session) maybeFinish(t *terminal) {
	if t.cancelled || !t.exited || !t.outputDone || len(t.outPending) > 0 || s.terminals[t.stream] == nil {
		return
	}
	if err := s.ep.Send(link.Exit{Stream: t.stream, Code: t.code}); err != nil {
		if refusal, ok := err.(*link.SendRefusal); ok && refusal.Code == "queue_full" {
			return
		}
		s.logf("terminal %d exit not sent: %v", t.stream, err)
	}
	s.teardown(t)
}

// cancelTerminal kills every process of a terminal; tell sends a cancel to the host.
func (s *session) cancelTerminal(t *terminal, tell bool, cause link.CancelCause) {
	if t.cancelled {
		return
	}
	t.cancelled = true
	t.process.Kill()
	if tell {
		_ = s.ep.Send(link.Cancel{Chan: link.ChannelTerminal, Stream: t.stream, Cause: cause})
	}
	s.teardown(t)
}

// teardown releases a terminal: its stop signal, its stdin, its unread credit and its
// working directory.
func (s *session) teardown(t *terminal) {
	if s.terminals[t.stream] == nil {
		return
	}
	delete(s.terminals, t.stream)
	close(t.stop)
	if len(t.stdinBuf) > 0 {
		_ = s.ep.Consume(link.ChannelTerminal, uint32(len(t.stdinBuf)))
		t.stdinBuf = nil
	}
	close(t.stdinCh)
	t.process.Release()
}

func (s *session) sortedTerminals() []*terminal {
	ids := make([]uint32, 0, len(s.terminals))
	for id := range s.terminals {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	terminals := make([]*terminal, 0, len(ids))
	for _, id := range ids {
		terminals = append(terminals, s.terminals[id])
	}
	return terminals
}

// keepAlive pings when nothing went out for a third of the host's idle timeout, so the
// host does not close an idle but healthy link.
func (s *session) keepAlive() {
	terms := s.ep.Terms()
	if terms == nil || s.ep.IsClosed() {
		return
	}
	interval := time.Duration(terms.IdleTimeoutSeconds) * time.Second / 3
	if interval < time.Second {
		interval = time.Second
	}
	if time.Since(s.lastSent) >= interval {
		s.pingNonce++
		_ = s.ep.Send(link.Ping{Nonce: s.pingNonce})
	}
}

// shutdownProgress ends a requested shutdown once every terminal is gone or the grace
// ran out: what is left is killed and the link closes with the shutdown reason.
func (s *session) shutdownProgress() {
	if s.shutdownAt == nil || s.outcome != nil {
		return
	}
	if len(s.terminals) > 0 && time.Now().Before(*s.shutdownAt) {
		return
	}
	for _, t := range s.sortedTerminals() {
		s.cancelTerminal(t, false, link.CancelRequested)
	}
	s.cancelAllRelays(link.ChannelEgress, false, link.CancelRequested)
	s.endAllIngress(false, link.CancelRequested)
	_ = s.ep.Send(link.Close{Reason: link.CloseShutdown})
	s.finish(sessionOutcome{cause: s.ep.Cause(), shutdown: true})
}

func (s *session) finish(outcome sessionOutcome) {
	if s.outcome == nil {
		s.outcome = &outcome
	}
}

func (s *session) killAll() {
	for _, t := range s.sortedTerminals() {
		s.cancelTerminal(t, false, link.CancelRequested)
	}
	s.cancelAllRelays(link.ChannelEgress, false, link.CancelRequested)
	s.endAllIngress(false, link.CancelRequested)
}
