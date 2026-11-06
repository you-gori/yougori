package link

// One end of a link (host: src-tauri/src/sandbox/link/link.rs, HostLink). The same state
// machine runs as either role: as the guest it is the agent's link; as the host it replays
// the conformance corpus and drives the host-side test client. Every rule the host applies
// to the guest's frames is applied here to the peer's frames, mirrored by role.
//
// Order of checks on every received frame: framing, tag, boot generation, connection,
// sequence, operation, direction, channel state, message size, handshake phase, payload
// fields (stream id first), then stream and window state. A failure of the first five
// closes the link; every later refusal drops the frame and counts against the refusal
// budget, whose exhaustion closes the link; a window overrun closes the channel. Nothing
// is acted on before its tag verified.
//
// Every link is one connection (M06-LC): the host's first frame is a challenge carrying
// the nonce it drew for the connection, and every frame of either end carries that nonce
// in its header under the tag, with sequences from 1. The host end is made with its nonce
// (NewHostEndpoint) and queues the challenge first. The guest end (NewGuestEndpoint)
// accepts as its first frame only an authentic challenge at sequence 1 whose field equals
// its header's connection and is not one repeated byte; anything else closes the link.
// It then binds the connection, says hello, and refuses any frame naming another
// connection as stale_connection.
//
// Role differences, each mirroring the host:
//   - The handshake message is Hello for the host to receive and Welcome for the guest.
//     Before it, the guest accepts only the host's urgent frames (Welcome, Revoke,
//     Shutdown, Close), which are the only ones the host may send before the hello.
//   - Windows: the host's receive window starts at the channel's buffered-byte limit and
//     its send credit at zero, so the guest may send that much before any credit and must
//     grant credit (Grant) before the host can send. The guest's start is the mirror.
//   - The idle timeout closes the host's end when the guest is silent. The guest does not
//     close on host silence: it keeps the host's timer alive with pings, and a lost host is
//     seen by the transport.
//
// Credit survives cancellation on both ends: a cancel returns the credit of the data
// frames it drops from the queue, and data for a recently cancelled stream (in flight when
// the cancel crossed it) still counts against the receive window and is credited back at
// once with a window update. A cancel for a stream this end recently completed (it crossed
// the last end-of-stream or exit) is benign: dropped without a refusal.
//
// The ingress and egress channels are flow-controlled per stream (version 3; the host's
// link.rs module docs): each direction of each stream starts with StreamWindowBytes, data
// is charged to its stream's window alone, StreamWindowUpdate credits it, and a peer that
// sends more than a stream's window closes the channel (stream_window_exceeded). This end
// credits a stream as its bytes are consumed (ConsumeStream), keeping what the peer may send
// plus what this end holds at the stream's window: its first window, or MaxStreamWindowBytes
// once it consumed a whole first window while the channel's growth stays within its
// buffered-byte quota. A stream whose reader stops stops only itself. Credit for a stream
// both ends finished is dropped quietly; data for a cancelled one is dropped with nothing
// to credit.

import (
	"fmt"
	"sort"
	"time"
)

// Stable reason codes. Those shared with the host are the corpus codes.
const (
	ReasonUnauthenticated          = "unauthenticated"
	ReasonStaleGeneration          = "stale_generation"
	ReasonStaleConnection          = "stale_connection"
	ReasonLinkAlreadyClosed        = "link_already_closed"
	ReasonUnknownOperation         = "unknown_operation"
	ReasonWrongDirection           = "wrong_direction"
	ReasonChannelClosed            = "channel_closed"
	ReasonMessageTooLarge          = "message_too_large"
	ReasonHandshakeIncomplete      = "handshake_incomplete"
	ReasonHandshakeRepeated        = "handshake_repeated"
	ReasonUnsupportedGuestVersion  = "unsupported_guest_version"
	ReasonClaimedIdentityDisagrees = "claimed_identity_disagrees"
	ReasonStreamParity             = "stream_parity"
	ReasonStreamIDNotIncreasing    = "stream_id_not_increasing"
	ReasonStreamQuotaExceeded      = "stream_quota_exceeded"
	ReasonStreamNotOpen            = "stream_not_open"
	ReasonStreamNotOpening         = "stream_not_opening"
	ReasonStreamCancelled          = "stream_cancelled"
	ReasonHalfClosed               = "half_closed"
	ReasonWindowExceeded           = "window_exceeded"
	ReasonStreamWindowExceeded     = "stream_window_exceeded"
	// ReasonUnsupportedHostVersion is the guest's refusal of a Welcome of another version.
	ReasonUnsupportedHostVersion = "unsupported_host_version"
	// ReasonWelcomeTermsRefused is the guest's refusal of terms it cannot honour.
	ReasonWelcomeTermsRefused = "welcome_terms_refused"
	// ReasonChallengeMissing is the guest's refusal of a first host frame that is not a
	// challenge.
	ReasonChallengeMissing = "challenge_missing"
	// ReasonChallengeRefused is the guest's refusal of a challenge whose field differs
	// from its header's connection or is one repeated byte.
	ReasonChallengeRefused = "challenge_refused"
)

// Reason is why a received frame was refused: its stable code and a description.
type Reason struct {
	Code   string
	Detail string
}

func (r Reason) Error() string { return r.Code + ": " + r.Detail }

func reasonOf(err interface {
	error
	Code() string
}) Reason {
	return Reason{Code: err.Code(), Detail: err.Error()}
}

// Effect is what a refusal did beyond dropping the frame.
type Effect uint8

const (
	EffectFrameDropped Effect = iota + 1
	EffectChannelClosed
	EffectLinkClosed
)

// Refusal is a refused frame.
type Refusal struct {
	Reason Reason
	Effect Effect
}

// CloseKind names why a link closed.
type CloseKind uint8

const (
	CloseViolation CloseKind = iota + 1
	ClosePeerClosed
	CloseLocalClosed
	CloseHandshakeTimedOut
	CloseIdleTimedOut
	CloseFrameTimedOut
	ClosePeerDisconnected
	CloseRefusalBudgetExhausted
	CloseSequenceExhausted
)

// CloseCause is why the link closed.
type CloseCause struct {
	Kind CloseKind
	// Violation holds the refusal of a CloseViolation.
	Violation Reason
	// Reason is the close reason of ClosePeerClosed and CloseLocalClosed.
	Reason CloseReason
}

// FrameReason is the reason the final close frame carries.
func (c CloseCause) FrameReason() CloseReason {
	switch c.Kind {
	case CloseViolation, CloseRefusalBudgetExhausted:
		return CloseProtocolViolation
	case ClosePeerClosed, ClosePeerDisconnected, CloseSequenceExhausted:
		return CloseOrderly
	case CloseLocalClosed:
		return c.Reason
	}
	return CloseTimedOut
}

func (c CloseCause) String() string {
	switch c.Kind {
	case CloseViolation:
		return "protocol violation: " + c.Violation.Error()
	case ClosePeerClosed:
		return fmt.Sprintf("the peer closed the link (reason %d)", c.Reason)
	case CloseLocalClosed:
		return fmt.Sprintf("this end closed the link (reason %d)", c.Reason)
	case CloseHandshakeTimedOut:
		return "the handshake did not complete in time"
	case CloseIdleTimedOut:
		return "the link stayed idle too long"
	case CloseFrameTimedOut:
		return "a frame stayed incomplete too long"
	case ClosePeerDisconnected:
		return "the peer disconnected"
	case CloseRefusalBudgetExhausted:
		return "too many frames were refused"
	}
	return "the sequence space is used up"
}

// Event is what receiving bytes, a tick or a disconnect produced.
type Event interface{ isEvent() }

// MessageEvent is an accepted message for the application.
type MessageEvent struct {
	Message  Message
	Sequence uint64
}

// RefusedEvent is a refused frame.
type RefusedEvent struct{ Refusal Refusal }

// ClosedEvent says the link closed.
type ClosedEvent struct{ Cause CloseCause }

// ChannelClosedEvent says one bulk channel closed while the link stayed up.
type ChannelClosedEvent struct {
	Channel Channel
	Reason  Reason
}

// StreamTimedOutEvent says a stream stayed half-opened past the open timeout and was
// dropped; CancelSent says whether a cancel frame was queued for the peer.
type StreamTimedOutEvent struct {
	Channel    Channel
	Stream     uint32
	CancelSent bool
}

func (MessageEvent) isEvent()        {}
func (RefusedEvent) isEvent()        {}
func (ClosedEvent) isEvent()         {}
func (ChannelClosedEvent) isEvent()  {}
func (StreamTimedOutEvent) isEvent() {}

// SendRefusal is why this end could not send or credit something.
type SendRefusal struct {
	Code   string
	Detail string
}

func (r *SendRefusal) Error() string { return r.Code + ": " + r.Detail }

func sendRefusal(code string, format string, args ...any) *SendRefusal {
	return &SendRefusal{Code: code, Detail: fmt.Sprintf(format, args...)}
}

// Phase is the link's phase.
type Phase uint8

const (
	// PhaseChallenge: the guest awaits the host's challenge; its connection is unbound.
	PhaseChallenge Phase = iota + 1
	// PhaseHandshake: the host awaits the hello, the guest the welcome.
	PhaseHandshake
	PhaseOpen
	PhaseClosed
)

// Clock supplies the time.
type Clock interface{ Now() time.Time }

// SystemClock reads the system's monotonic clock.
type SystemClock struct{}

// Now is time.Now.
func (SystemClock) Now() time.Time { return time.Now() }

type queuedFrame struct {
	channel Channel
	op      Operation
	stream  uint32
	payload []byte
	// credit is the send credit a data frame was charged, or the credit a window update
	// grants.
	credit uint64
}

type streamState struct {
	opener     Sender
	open       bool
	peerEnded  bool
	localEnded bool
	since      time.Time
	// Ingress and egress (version 3): what this end may still send on the stream, what the
	// peer may still send, the peer's bytes held and not consumed, what this end keeps the
	// peer's window plus its held bytes at, and the peer's bytes consumed since the open.
	sendWindow    uint64
	receiveWindow uint64
	buffered      uint64
	window        uint64
	consumed      uint64
}

func newStreamState(opener Sender, since time.Time) *streamState {
	return &streamState{
		opener:        opener,
		since:         since,
		sendWindow:    StreamWindowBytes,
		receiveWindow: StreamWindowBytes,
		window:        StreamWindowBytes,
	}
}

type channelState struct {
	channel       Channel
	quota         ChannelQuota
	streams       map[uint32]*streamState
	highestPeer   uint32
	highestLocal  uint32
	receiveWindow uint64
	buffered      uint64
	sendCredit    uint64
	queue         []queuedFrame
	closed        *Reason
	cancelled     []uint32
	ended         []uint32
	// grown is how far the streams' windows grew past their first windows, in all;
	// grantsDue are the streams whose credit found the queue full.
	grown     uint64
	grantsDue map[uint32]bool
}

func contains(ids []uint32, stream uint32) bool {
	for _, id := range ids {
		if id == stream {
			return true
		}
	}
	return false
}

func (c *channelState) wasCancelled(stream uint32) bool { return contains(c.cancelled, stream) }

func (c *channelState) wasEnded(stream uint32) bool { return contains(c.ended, stream) }

// remember appends stream to a set bounded by the stream quota, oldest first out.
func (c *channelState) remember(ids []uint32, stream uint32) []uint32 {
	ids = append(ids, stream)
	bound := int(c.quota.MaxStreams)
	if bound < 1 {
		bound = 1
	}
	for len(ids) > bound {
		ids = ids[1:]
	}
	return ids
}

// remove drops a stream; what its window grew goes back to the channel.
func (c *channelState) remove(stream uint32) {
	if entry, ok := c.streams[stream]; ok && entry.window > StreamWindowBytes {
		grown := entry.window - StreamWindowBytes
		if grown > c.grown {
			grown = c.grown
		}
		c.grown -= grown
	}
	delete(c.streams, stream)
	delete(c.grantsDue, stream)
}

// forget drops a stream and its queued frames, returns the send credit of the data frames
// it drops, and remembers the stream as cancelled.
func (c *channelState) forget(stream uint32) {
	c.remove(stream)
	kept := c.queue[:0]
	for _, frame := range c.queue {
		if frame.stream != stream {
			kept = append(kept, frame)
		} else if frame.op == OpData {
			c.sendCredit = saturatingAdd(c.sendCredit, frame.credit)
		}
	}
	c.queue = kept
	c.cancelled = c.remember(c.cancelled, stream)
}

// complete drops a stream both ends finished (or whose open was refused) and remembers
// it as ended, so a cancel that crossed the finish is benign.
func (c *channelState) complete(stream uint32) {
	c.remove(stream)
	c.ended = c.remember(c.ended, stream)
}

func saturatingAdd(a, b uint64) uint64 {
	if sum := a + b; sum >= a {
		return sum
	}
	return ^uint64(0)
}

func (c *channelState) clear() {
	c.streams = map[uint32]*streamState{}
	c.queue = nil
	c.grown = 0
	c.grantsDue = map[uint32]bool{}
}

// ChannelSummary is a view of one channel's state.
type ChannelSummary struct {
	Channel       Channel
	Streams       int
	Buffered      uint64
	ReceiveWindow uint64
	SendCredit    uint64
	QueuedFrames  int
	Closed        bool
}

// StreamSummary is a view of one stream's state.
type StreamSummary struct {
	Opener     Sender
	Open       bool
	PeerEnded  bool
	LocalEnded bool
}

// Endpoint is one end of a guest link.
type Endpoint struct {
	role           Sender
	binding        *Binding
	limits         Limits
	clock          Clock
	decoder        *FrameDecoder
	inbound        SequenceState
	outbound       SequenceState
	phase          Phase
	cause          CloseCause
	startedAt      time.Time
	lastReceivedAt time.Time
	refusals       uint32
	channels       [5]*channelState
	urgent         []queuedFrame
	nextBulk       int
	helloSent      bool
	terms          *Welcome
	connection     Connection
	bound          bool
}

// NewGuestEndpoint makes the guest end of a link bound to binding under limits, started
// now on clock; it awaits the host's challenge before anything else. The limits are
// validated first.
func NewGuestEndpoint(binding *Binding, limits Limits, clock Clock) (*Endpoint, error) {
	e, err := newEndpoint(SenderGuest, binding, limits, clock)
	if err != nil {
		return nil, err
	}
	e.phase = PhaseChallenge
	return e, nil
}

// NewHostEndpoint makes the host end of one connection, bound to binding and to nonce,
// which the host drew for this connection alone (NewConnection checks it), under limits,
// started now on clock. Its first outbound frame is the challenge.
func NewHostEndpoint(binding *Binding, nonce Connection, limits Limits, clock Clock) (*Endpoint, error) {
	if _, err := NewConnection(nonce[:]); err != nil {
		return nil, err
	}
	e, err := newEndpoint(SenderHost, binding, limits, clock)
	if err != nil {
		return nil, err
	}
	e.connection = nonce
	e.bound = true
	if err := e.enqueueInternal(Challenge{Connection: nonce}); err != nil {
		return nil, err
	}
	return e, nil
}

func newEndpoint(role Sender, binding *Binding, limits Limits, clock Clock) (*Endpoint, error) {
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	now := clock.Now()
	e := &Endpoint{
		role:           role,
		binding:        binding,
		limits:         limits,
		clock:          clock,
		decoder:        NewFrameDecoder(limits.MaxFrameBytes),
		phase:          PhaseHandshake,
		startedAt:      now,
		lastReceivedAt: now,
	}
	for _, channel := range AllChannels {
		quota := *limits.Quota(channel)
		state := &channelState{channel: channel, quota: quota, streams: map[uint32]*streamState{}, grantsDue: map[uint32]bool{}}
		if role == SenderHost {
			state.receiveWindow = quota.MaxBufferedBytes
		} else {
			state.sendCredit = quota.MaxBufferedBytes
		}
		e.channels[channel] = state
	}
	return e, nil
}

// Role is this end.
func (e *Endpoint) Role() Sender { return e.role }

// Binding is the link's binding.
func (e *Endpoint) Binding() *Binding { return e.binding }

// Limits are the link's limits.
func (e *Endpoint) Limits() Limits { return e.limits }

// Phase is the link's phase.
func (e *Endpoint) Phase() Phase { return e.phase }

// IsClosed reports whether the link closed.
func (e *Endpoint) IsClosed() bool { return e.phase == PhaseClosed }

// Cause is why the link closed; meaningful once closed.
func (e *Endpoint) Cause() CloseCause { return e.cause }

// Refusals counts frames refused and charged to the budget.
func (e *Endpoint) Refusals() uint32 { return e.refusals }

// Terms are the host's terms once the guest received the welcome.
func (e *Endpoint) Terms() *Welcome { return e.terms }

// Connection is the connection every frame carries; false while the guest awaits the
// challenge.
func (e *Endpoint) Connection() (Connection, bool) { return e.connection, e.bound }

// DecoderBufferedBytes is what the decoder holds for an incomplete frame.
func (e *Endpoint) DecoderBufferedBytes() int { return e.decoder.BufferedBytes() }

// LastReceivedSequence is the last peer sequence accepted.
func (e *Endpoint) LastReceivedSequence() uint64 { return e.inbound.LastAccepted() }

// Channel summarizes one channel; on the ingress and egress channels the byte counts are
// the sums over the channel's streams.
func (e *Endpoint) Channel(channel Channel) ChannelSummary {
	state := e.state(channel)
	buffered, receive, send := state.buffered, state.receiveWindow, state.sendCredit
	if channel.HasStreamWindows() {
		buffered, receive, send = 0, 0, 0
		for _, stream := range state.streams {
			buffered = saturatingAdd(buffered, stream.buffered)
			receive = saturatingAdd(receive, stream.receiveWindow)
			send = saturatingAdd(send, stream.sendWindow)
		}
	}
	return ChannelSummary{
		Channel:       channel,
		Streams:       len(state.streams),
		Buffered:      buffered,
		ReceiveWindow: receive,
		SendCredit:    send,
		QueuedFrames:  len(state.queue),
		Closed:        state.closed != nil,
	}
}

// Stream summarizes one stream; false when the channel holds no such stream.
func (e *Endpoint) Stream(channel Channel, stream uint32) (StreamSummary, bool) {
	entry, ok := e.state(channel).streams[stream]
	if !ok {
		return StreamSummary{}, false
	}
	return StreamSummary{Opener: entry.opener, Open: entry.open, PeerEnded: entry.peerEnded, LocalEnded: entry.localEnded}, true
}

// QueuedFrames counts the frames waiting to go out, urgent ones included.
func (e *Endpoint) QueuedFrames() int {
	total := len(e.urgent)
	for _, state := range e.channels {
		total += len(state.queue)
	}
	return total
}

// MaxDataBytes is the largest data chunk one frame on channel can carry from this end.
func (e *Endpoint) MaxDataBytes(channel Channel) int {
	return int(e.sendLimit(channel)) - FieldOverheadBytes
}

func (e *Endpoint) sendLimit(channel Channel) uint32 {
	limit := e.limits.Quota(channel).MaxMessageBytes
	if e.terms != nil {
		room := e.terms.MaxFrameBytes - FrameOverheadBytes
		if room < limit {
			limit = room
		}
	}
	return limit
}

func (e *Endpoint) state(channel Channel) *channelState { return e.channels[channel] }

func (e *Endpoint) handshakeOp() Operation {
	if e.role == SenderHost {
		return OpHello
	}
	return OpWelcome
}

// Receive feeds bytes from the peer and returns the events in order; after the link
// closes, every later non-empty push yields one refusal.
func (e *Endpoint) Receive(bytes []byte) []Event {
	var events []Event
	if e.IsClosed() {
		if len(bytes) > 0 {
			events = append(events, RefusedEvent{Refusal{Reason: Reason{Code: ReasonLinkAlreadyClosed, Detail: "the link is closed"}, Effect: EffectFrameDropped}})
		}
		return events
	}
	now := e.clock.Now()
	frames, refusal := e.decoder.Push(bytes, now)
	for _, raw := range frames {
		e.acceptFrame(raw, now, &events)
		if e.IsClosed() {
			return events
		}
	}
	if refusal != nil {
		e.violation(reasonOf(refusal), &events)
	}
	return events
}

// PeerClosed says the transport reported the peer gone; a partial frame is a truncation.
func (e *Endpoint) PeerClosed() []Event {
	var events []Event
	if e.IsClosed() {
		return events
	}
	if truncated := e.decoder.Finish(); truncated != nil {
		e.violation(reasonOf(truncated), &events)
		return events
	}
	cause := CloseCause{Kind: ClosePeerDisconnected}
	e.closeLink(cause)
	return append(events, ClosedEvent{cause})
}

// Tick applies the timeouts at the clock's time: an incomplete frame past the completion
// timeout, a handshake past the handshake timeout, (host) silence past the idle timeout,
// and streams half-opened past the open timeout. A duration equal to a timeout is still
// within it.
func (e *Endpoint) Tick() []Event {
	var events []Event
	if e.IsClosed() {
		return events
	}
	now := e.clock.Now()
	if since, ok := e.decoder.PartialSince(); ok && now.Sub(since) > e.limits.FrameCompletionTimeout {
		cause := CloseCause{Kind: CloseFrameTimedOut}
		e.closeLink(cause)
		return append(events, ClosedEvent{cause})
	}
	var timedOut *CloseCause
	switch {
	case (e.phase == PhaseChallenge || e.phase == PhaseHandshake) && now.Sub(e.startedAt) > e.limits.HandshakeTimeout:
		timedOut = &CloseCause{Kind: CloseHandshakeTimedOut}
	case e.phase == PhaseOpen && e.role == SenderHost && now.Sub(e.lastReceivedAt) > e.limits.IdleTimeout:
		timedOut = &CloseCause{Kind: CloseIdleTimedOut}
	}
	if timedOut != nil {
		e.closeLink(*timedOut)
		return append(events, ClosedEvent{*timedOut})
	}
	for _, channel := range BulkChannels {
		state := e.state(channel)
		var expired []uint32
		for id, stream := range state.streams {
			if !stream.open && now.Sub(stream.since) > e.limits.OpenTimeout {
				expired = append(expired, id)
			}
		}
		sort.Slice(expired, func(i, j int) bool { return expired[i] < expired[j] })
		for _, id := range expired {
			state.forget(id)
			sent := e.enqueueInternal(Cancel{Chan: channel, Stream: id, Cause: CancelTimedOut}) == nil
			events = append(events, StreamTimedOutEvent{Channel: channel, Stream: id, CancelSent: sent})
		}
	}
	return events
}

// Send queues a message for the peer after checking it against the direction table, the
// handshake, the channel's quota, stream state and the peer's credit. Urgent operations go
// to the urgent queue, which drains first; a close also closes the link.
func (e *Endpoint) Send(message Message) error {
	if e.IsClosed() {
		return sendRefusal("link_closed", "the link is closed")
	}
	channel, op := message.Channel(), message.Operation()
	if direction, ok := op.Direction(channel); !ok || !direction.Allows(e.role) {
		return sendRefusal("wrong_channel", "the %s may not send %s on the %s channel", e.role, op, channel)
	}
	if e.phase == PhaseChallenge {
		return sendRefusal("handshake_incomplete", "the host has not challenged the guest; nothing may be sent")
	}
	if e.phase == PhaseHandshake {
		if e.role == SenderHost && !op.IsUrgent() {
			return sendRefusal("handshake_incomplete", "the guest has not said hello; only control may be sent")
		}
		if e.role == SenderGuest && op != OpHello && op != OpClose {
			return sendRefusal("handshake_incomplete", "the host has not welcomed the guest; only the hello or a close may be sent")
		}
	}
	if op == OpHello && e.helloSent {
		return sendRefusal("handshake_repeated", "the hello was already sent")
	}
	if e.state(channel).closed != nil {
		return sendRefusal("channel_closed", "the %s channel is closed", channel)
	}
	payload, err := EncodePayload(message)
	if err != nil {
		return sendRefusal("encode", "%v", err)
	}
	if limit := e.sendLimit(channel); uint64(len(payload)) > uint64(limit) {
		return sendRefusal("message_too_large", "a %d-byte message exceeds the %d bytes of the %s channel", len(payload), limit, channel)
	}
	quota := e.limits.Quota(channel)
	queued := len(e.state(channel).queue)
	if op.IsUrgent() {
		queued = len(e.urgent)
	}
	if queued >= int(quota.MaxQueuedFrames) {
		return sendRefusal("queue_full", "the %s channel already has %d frames queued", channel, quota.MaxQueuedFrames)
	}
	if closing, ok := message.(Close); ok {
		e.closeLink(CloseCause{Kind: CloseLocalClosed, Reason: closing.Reason})
		return nil
	}
	if err := e.applyLocalStreamRules(message, e.clock.Now()); err != nil {
		return err
	}
	if op == OpHello {
		e.helloSent = true
	}
	frame := queuedFrame{channel: channel, op: op, stream: message.StreamID(), payload: payload}
	if data, ok := message.(Data); ok && !channel.HasStreamWindows() {
		frame.credit = uint64(len(data.Bytes))
	}
	if op.IsUrgent() {
		e.urgent = append(e.urgent, frame)
	} else {
		state := e.state(channel)
		state.queue = append(state.queue, frame)
	}
	return nil
}

func (e *Endpoint) applyLocalStreamRules(message Message, now time.Time) error {
	channel := message.Channel()
	stream := message.StreamID()
	state := e.state(channel)
	switch m := message.(type) {
	case OpenTerminal, OpenFile, OpenIngress, OpenEgress:
		if openerOf(stream) != e.role {
			return sendRefusal("stream_parity", "stream %d has %s parity", stream, e.role.Peer())
		}
		if stream <= state.highestLocal {
			return sendRefusal("stream_id_not_increasing", "stream %d is not above the highest %s stream %d", stream, e.role, state.highestLocal)
		}
		if len(state.streams) >= int(state.quota.MaxStreams) {
			return sendRefusal("stream_quota_exceeded", "the %s channel already has %d streams", channel, state.quota.MaxStreams)
		}
		state.highestLocal = stream
		state.streams[stream] = newStreamState(e.role, now)
	case Opened, OpenRefused:
		entry, ok := state.streams[stream]
		if !ok {
			return sendRefusal("stream_not_open", "%s stream %d is not open", channel, stream)
		}
		if entry.opener != e.role.Peer() || entry.open {
			return sendRefusal("stream_not_opening", "%s stream %d is not awaiting this end's answer", channel, stream)
		}
		if _, opened := m.(Opened); opened {
			entry.open = true
		} else {
			state.complete(stream)
		}
	case Data:
		entry, ok := state.streams[stream]
		if !ok || !entry.open {
			return sendRefusal("stream_not_open", "%s stream %d is not open", channel, stream)
		}
		if entry.localEnded {
			return sendRefusal("half_closed", "this end already ended %s stream %d", channel, stream)
		}
		needed := uint64(len(m.Bytes))
		if channel.HasStreamWindows() {
			if needed > entry.sendWindow {
				return sendRefusal("no_stream_credit", "%d bytes exceed the %d bytes of credit the peer granted %s stream %d", needed, entry.sendWindow, channel, stream)
			}
			entry.sendWindow -= needed
			return nil
		}
		if needed > state.sendCredit {
			return sendRefusal("no_credit", "%d bytes exceed the %d bytes of %s credit the peer granted", needed, state.sendCredit, channel)
		}
		state.sendCredit -= needed
	case EndOfStream, Exit:
		entry, ok := state.streams[stream]
		if !ok || !entry.open {
			return sendRefusal("stream_not_open", "%s stream %d is not open", channel, stream)
		}
		if entry.localEnded {
			return sendRefusal("half_closed", "this end already ended %s stream %d", channel, stream)
		}
		if entry.peerEnded {
			state.complete(stream)
		} else {
			entry.localEnded = true
		}
	case Cancel:
		if _, ok := state.streams[stream]; !ok {
			return sendRefusal("stream_not_open", "%s stream %d is not open", channel, stream)
		}
		state.forget(stream)
	case Resize:
		entry, ok := state.streams[stream]
		if !ok || !entry.open {
			return sendRefusal("stream_not_open", "%s stream %d is not open", channel, stream)
		}
	}
	return nil
}

func openerOf(stream uint32) Sender {
	if stream%2 == 1 {
		return SenderGuest
	}
	return SenderHost
}

// enqueueInternal queues a frame the link itself issues (welcome, close, window updates,
// timeout cancels); urgent operations bypass the queue budget.
func (e *Endpoint) enqueueInternal(message Message) error {
	if update, ok := message.(WindowUpdate); ok {
		return e.queueWindowUpdate(update.Chan, update.CreditBytes, false)
	}
	if update, ok := message.(StreamWindowUpdate); ok {
		return e.queueStreamWindowUpdate(update)
	}
	payload, err := EncodePayload(message)
	if err != nil {
		return sendRefusal("encode", "%v", err)
	}
	channel, op := message.Channel(), message.Operation()
	frame := queuedFrame{channel: channel, op: op, stream: message.StreamID(), payload: payload}
	if op.IsUrgent() {
		e.urgent = append(e.urgent, frame)
		return nil
	}
	state := e.state(channel)
	if len(state.queue) >= int(state.quota.MaxQueuedFrames) {
		return sendRefusal("queue_full", "the %s channel already has %d frames queued", channel, state.quota.MaxQueuedFrames)
	}
	state.queue = append(state.queue, frame)
	return nil
}

// queueWindowUpdate queues credit for the peer ahead of the channel's data, merged into a
// window update already at the front when the sum fits, so the queue holds at most one
// in the usual case. force queues it even on a full queue: a refund must not be lost, and
// later refunds merge into it.
func (e *Endpoint) queueWindowUpdate(channel Channel, credit uint32, force bool) error {
	state := e.state(channel)
	if len(state.queue) > 0 && state.queue[0].op == OpWindowUpdate {
		if merged := state.queue[0].credit + uint64(credit); merged <= 0xffffffff {
			payload, err := EncodePayload(WindowUpdate{Chan: channel, CreditBytes: uint32(merged)})
			if err != nil {
				return sendRefusal("encode", "%v", err)
			}
			state.queue[0].credit = merged
			state.queue[0].payload = payload
			return nil
		}
	}
	if !force && len(state.queue) >= int(state.quota.MaxQueuedFrames) {
		return sendRefusal("queue_full", "the %s channel already has %d frames queued", channel, state.quota.MaxQueuedFrames)
	}
	payload, err := EncodePayload(WindowUpdate{Chan: channel, CreditBytes: credit})
	if err != nil {
		return sendRefusal("encode", "%v", err)
	}
	frame := queuedFrame{channel: channel, op: OpWindowUpdate, payload: payload, credit: uint64(credit)}
	state.queue = append([]queuedFrame{frame}, state.queue...)
	return nil
}

// queueStreamWindowUpdate queues a stream's credit ahead of the channel's data.
func (e *Endpoint) queueStreamWindowUpdate(update StreamWindowUpdate) error {
	state := e.state(update.Chan)
	if len(state.queue) >= int(state.quota.MaxQueuedFrames) {
		return sendRefusal("queue_full", "the %s channel already has %d frames queued", update.Chan, state.quota.MaxQueuedFrames)
	}
	payload, err := EncodePayload(update)
	if err != nil {
		return sendRefusal("encode", "%v", err)
	}
	frame := queuedFrame{channel: update.Chan, op: OpStreamWindowUpdate, stream: update.Stream, payload: payload, credit: uint64(update.CreditBytes)}
	state.queue = append([]queuedFrame{frame}, state.queue...)
	return nil
}

// NextOutbound is the next frame to write, sealed with the next sequence of this end: the
// urgent queue first, then control, then the bulk channels in turn. Nil when none.
func (e *Endpoint) NextOutbound() []byte {
	frame, ok := e.dequeue()
	if !ok {
		return nil
	}
	// Taking a frame made room: streams' credit that found the queue full goes out.
	for _, channel := range BulkChannels {
		state := e.state(channel)
		if len(state.grantsDue) == 0 {
			continue
		}
		due := make([]uint32, 0, len(state.grantsDue))
		for stream := range state.grantsDue {
			due = append(due, stream)
		}
		sort.Slice(due, func(i, j int) bool { return due[i] < due[j] })
		for _, stream := range due {
			e.grantStream(channel, stream)
		}
	}
	sequence, refusal := e.outbound.NextForSend()
	if refusal != nil {
		if !e.IsClosed() {
			e.phase = PhaseClosed
			e.cause = CloseCause{Kind: CloseSequenceExhausted}
			e.decoder.Close(&FramingRefusal{Kind: FramingDecoderClosed})
			e.urgent = nil
			for _, state := range e.channels {
				state.clear()
			}
		}
		return nil
	}
	header := Header{
		Channel:        frame.channel,
		OperationCode:  uint8(frame.op),
		Stream:         frame.stream,
		Sequence:       sequence,
		BootGeneration: e.binding.Boot(),
		PayloadBytes:   uint32(len(frame.payload)),
		Connection:     e.connection,
	}
	return e.binding.Seal(e.role, header, frame.payload)
}

func (e *Endpoint) dequeue() (queuedFrame, bool) {
	if len(e.urgent) > 0 {
		frame := e.urgent[0]
		e.urgent = e.urgent[1:]
		return frame, true
	}
	if control := e.state(ChannelControl); len(control.queue) > 0 {
		frame := control.queue[0]
		control.queue = control.queue[1:]
		return frame, true
	}
	for offset := range BulkChannels {
		index := (e.nextBulk + offset) % len(BulkChannels)
		state := e.state(BulkChannels[index])
		if len(state.queue) > 0 {
			frame := state.queue[0]
			state.queue = state.queue[1:]
			e.nextBulk = (index + 1) % len(BulkChannels)
			return frame, true
		}
	}
	return queuedFrame{}, false
}

// Consume says this end consumed bytes it buffered on channel: the receive window grows
// back and a window update is queued ahead of that channel's data.
func (e *Endpoint) Consume(channel Channel, bytes uint32) error {
	if e.IsClosed() {
		return sendRefusal("link_closed", "the link is closed")
	}
	if !channel.IsBulk() {
		return sendRefusal("not_bulk", "the %s channel buffers nothing", channel)
	}
	if channel.HasStreamWindows() {
		return sendRefusal("per_stream", "the %s channel is credited per stream", channel)
	}
	state := e.state(channel)
	if state.closed != nil {
		return sendRefusal("channel_closed", "the %s channel is closed", channel)
	}
	if uint64(bytes) > state.buffered {
		return sendRefusal("more_than_buffered", "%d bytes consumed but only %d are buffered on %s", bytes, state.buffered, channel)
	}
	if err := e.queueWindowUpdate(channel, bytes, false); err != nil {
		return err
	}
	state.buffered -= uint64(bytes)
	state.receiveWindow += uint64(bytes)
	return nil
}

// Grant gives the peer fresh credit on channel without consuming anything: the window the
// guest opens before the host may send. Window plus buffered bytes never exceed the
// channel's buffered-byte limit.
func (e *Endpoint) Grant(channel Channel, bytes uint32) error {
	if e.IsClosed() {
		return sendRefusal("link_closed", "the link is closed")
	}
	if !channel.IsBulk() {
		return sendRefusal("not_bulk", "the %s channel buffers nothing", channel)
	}
	if channel.HasStreamWindows() {
		return sendRefusal("per_stream", "the %s channel's streams open with their own windows", channel)
	}
	state := e.state(channel)
	if state.closed != nil {
		return sendRefusal("channel_closed", "the %s channel is closed", channel)
	}
	if state.receiveWindow+state.buffered+uint64(bytes) > state.quota.MaxBufferedBytes {
		return sendRefusal("window_full", "%d more bytes of credit exceed the %d bytes %s may buffer", bytes, state.quota.MaxBufferedBytes, channel)
	}
	if err := e.queueWindowUpdate(channel, bytes, false); err != nil {
		return err
	}
	state.receiveWindow += uint64(bytes)
	return nil
}

// ConsumeStream says this end consumed bytes the peer sent on ingress or egress stream: the
// stream is credited back to its window (its first window, or grown once it consumed a whole
// first window while the channel's growth stays within its quota), in one update once a
// quarter of the window is due. Nothing is credited for a stream the peer ended its
// direction of, and bytes of a stream this end no longer holds need no credit.
func (e *Endpoint) ConsumeStream(channel Channel, stream uint32, bytes uint32) error {
	if e.IsClosed() {
		return sendRefusal("link_closed", "the link is closed")
	}
	if !channel.HasStreamWindows() {
		return sendRefusal("not_per_stream", "the %s channel is credited as a whole", channel)
	}
	state := e.state(channel)
	if state.closed != nil {
		return sendRefusal("channel_closed", "the %s channel is closed", channel)
	}
	entry, ok := state.streams[stream]
	if !ok {
		return nil
	}
	if uint64(bytes) > entry.buffered {
		return sendRefusal("more_than_buffered", "%d bytes consumed but only %d are buffered on %s stream %d", bytes, entry.buffered, channel, stream)
	}
	entry.buffered -= uint64(bytes)
	entry.consumed = saturatingAdd(entry.consumed, uint64(bytes))
	if entry.window < MaxStreamWindowBytes && entry.consumed >= StreamWindowBytes {
		growth := MaxStreamWindowBytes - entry.window
		if state.grown+growth <= state.quota.MaxBufferedBytes {
			entry.window = MaxStreamWindowBytes
			state.grown += growth
		}
	}
	e.grantStream(channel, stream)
	return nil
}

// GrowStream grants the peer stream's grown window at once, for a stream this end expects to
// read as fast as it comes (a relayed connection's program), within the channel's growth
// quota as any growth; nothing when the quota has no room or the stream grew already.
func (e *Endpoint) GrowStream(channel Channel, stream uint32) error {
	if e.IsClosed() {
		return sendRefusal("link_closed", "the link is closed")
	}
	if !channel.HasStreamWindows() {
		return sendRefusal("not_per_stream", "the %s channel is credited as a whole", channel)
	}
	state := e.state(channel)
	if state.closed != nil {
		return sendRefusal("channel_closed", "the %s channel is closed", channel)
	}
	entry, ok := state.streams[stream]
	if !ok || !entry.open {
		return sendRefusal("stream_not_open", "%s stream %d is not open", channel, stream)
	}
	if entry.window >= MaxStreamWindowBytes {
		return nil
	}
	growth := MaxStreamWindowBytes - entry.window
	if state.grown+growth > state.quota.MaxBufferedBytes {
		return nil
	}
	entry.window = MaxStreamWindowBytes
	state.grown += growth
	e.grantStream(channel, stream)
	return nil
}

// StreamSendCredit is what this end may send on ingress or egress stream now: the peer's
// credit for it. Zero for a stream not open, or of another channel.
func (e *Endpoint) StreamSendCredit(channel Channel, stream uint32) uint64 {
	if !channel.HasStreamWindows() {
		return 0
	}
	entry, ok := e.state(channel).streams[stream]
	if !ok || !entry.open {
		return 0
	}
	return entry.sendWindow
}

// grantStream queues the credit due to stream (its window less what the peer may send and
// what this end holds) once it is a quarter of the window; a full queue leaves it due for
// the next frame.
func (e *Endpoint) grantStream(channel Channel, stream uint32) {
	state := e.state(channel)
	entry, ok := state.streams[stream]
	if !ok {
		delete(state.grantsDue, stream)
		return
	}
	held := saturatingAdd(entry.receiveWindow, entry.buffered)
	var due uint64
	if entry.window > held {
		due = entry.window - held
	}
	if entry.peerEnded || due == 0 || due < entry.window/4 {
		delete(state.grantsDue, stream)
		return
	}
	if due > 0xffffffff {
		due = 0xffffffff
	}
	if err := e.queueStreamWindowUpdate(StreamWindowUpdate{Chan: channel, Stream: stream, CreditBytes: uint32(due)}); err != nil {
		state.grantsDue[stream] = true
		return
	}
	delete(state.grantsDue, stream)
	entry.receiveWindow += due
}

func (e *Endpoint) acceptFrame(raw RawFrame, now time.Time, events *[]Event) {
	header := raw.Header
	peer := e.role.Peer()
	if !e.binding.Verify(peer, raw.HeaderBytes[:], raw.Payload, raw.Tag) {
		e.violation(Reason{Code: ReasonUnauthenticated, Detail: "the frame's tag is not the bound peer's"}, events)
		return
	}
	if header.BootGeneration != e.binding.Boot() {
		e.violation(Reason{Code: ReasonStaleGeneration, Detail: fmt.Sprintf("the frame is bound to boot generation %d, the link to %d", header.BootGeneration, e.binding.Boot())}, events)
		return
	}
	if e.phase == PhaseChallenge {
		e.acceptChallenge(raw, now, events)
		return
	}
	if header.Connection != e.connection {
		e.violation(Reason{Code: ReasonStaleConnection, Detail: fmt.Sprintf("the frame is bound to connection %s, the link to %s", header.Connection.Hex(), e.connection.Hex())}, events)
		return
	}
	if refusal := e.inbound.Accept(header.Sequence); refusal != nil {
		e.violation(reasonOf(refusal), events)
		return
	}
	e.lastReceivedAt = now
	channel := header.Channel
	op, ok := DecodeOperation(channel, header.OperationCode)
	if !ok {
		e.budgeted(Reason{Code: ReasonUnknownOperation, Detail: fmt.Sprintf("operation %#02x is unknown on the %s channel", header.OperationCode, channel)}, events)
		return
	}
	if direction, _ := op.Direction(channel); !direction.Allows(peer) {
		e.budgeted(Reason{Code: ReasonWrongDirection, Detail: fmt.Sprintf("the %s may not send %s on the %s channel", peer, op, channel)}, events)
		return
	}
	if e.state(channel).closed != nil {
		e.budgeted(Reason{Code: ReasonChannelClosed, Detail: fmt.Sprintf("the %s channel is closed", channel)}, events)
		return
	}
	if op == OpChallenge {
		e.budgeted(Reason{Code: ReasonHandshakeRepeated, Detail: "a second challenge arrived on a bound connection"}, events)
		return
	}
	maxMessage := e.limits.Quota(channel).MaxMessageBytes
	if uint64(len(raw.Payload)) > uint64(maxMessage) {
		e.budgeted(Reason{Code: ReasonMessageTooLarge, Detail: fmt.Sprintf("a %d-byte message exceeds the %d bytes of the %s channel", len(raw.Payload), maxMessage, channel)}, events)
		return
	}
	if e.phase == PhaseHandshake && !e.allowedInHandshake(op) {
		e.budgeted(Reason{Code: ReasonHandshakeIncomplete, Detail: fmt.Sprintf("%s arrived before the handshake", op)}, events)
		return
	}
	if e.phase == PhaseOpen && op == e.handshakeOp() {
		e.budgeted(Reason{Code: ReasonHandshakeRepeated, Detail: fmt.Sprintf("a second %s arrived", op)}, events)
		return
	}
	message, err := DecodeMessage(channel, op, header.Stream, raw.Payload, int(maxMessage))
	if err != nil {
		if refusal, ok := err.(*PayloadRefusal); ok {
			e.budgeted(reasonOf(refusal), events)
		} else {
			e.budgeted(Reason{Code: "payload.unknown", Detail: err.Error()}, events)
		}
		return
	}
	e.apply(message, header.Sequence, now, events)
}

// acceptChallenge takes the guest's first authenticated frame: only a challenge at
// sequence 1 whose field equals its header's connection, not one repeated byte, binds
// the connection; anything else closes the link.
func (e *Endpoint) acceptChallenge(raw RawFrame, now time.Time, events *[]Event) {
	header := raw.Header
	if refusal := e.inbound.Accept(header.Sequence); refusal != nil {
		e.violation(reasonOf(refusal), events)
		return
	}
	e.lastReceivedAt = now
	op, ok := DecodeOperation(header.Channel, header.OperationCode)
	if !ok || op != OpChallenge {
		e.violation(Reason{Code: ReasonChallengeMissing, Detail: fmt.Sprintf("the host's first frame is operation %#02x on the %s channel, not a challenge", header.OperationCode, header.Channel)}, events)
		return
	}
	maxMessage := e.limits.Quota(ChannelControl).MaxMessageBytes
	if uint64(len(raw.Payload)) > uint64(maxMessage) {
		e.violation(Reason{Code: ReasonMessageTooLarge, Detail: fmt.Sprintf("a %d-byte challenge exceeds the %d bytes of the control channel", len(raw.Payload), maxMessage)}, events)
		return
	}
	message, err := DecodeMessage(ChannelControl, OpChallenge, header.Stream, raw.Payload, int(maxMessage))
	if err != nil {
		if refusal, ok := err.(*PayloadRefusal); ok {
			e.violation(reasonOf(refusal), events)
		} else {
			e.violation(Reason{Code: ReasonChallengeRefused, Detail: err.Error()}, events)
		}
		return
	}
	challenge, _ := message.(Challenge)
	if challenge.Connection != header.Connection {
		e.violation(Reason{Code: ReasonChallengeRefused, Detail: "the challenge's field is not its header's connection"}, events)
		return
	}
	if _, err := NewConnection(challenge.Connection[:]); err != nil {
		e.violation(Reason{Code: ReasonChallengeRefused, Detail: err.Error()}, events)
		return
	}
	e.connection = challenge.Connection
	e.bound = true
	e.phase = PhaseHandshake
	e.deliver(challenge, header.Sequence, events)
}

func (e *Endpoint) allowedInHandshake(op Operation) bool {
	if e.role == SenderHost {
		return op == OpHello
	}
	return op == OpWelcome || op == OpRevoke || op == OpShutdown || op == OpClose
}

func (e *Endpoint) deliver(message Message, sequence uint64, events *[]Event) {
	*events = append(*events, MessageEvent{Message: message, Sequence: sequence})
}

func (e *Endpoint) apply(message Message, sequence uint64, now time.Time, events *[]Event) {
	peer := e.role.Peer()
	switch m := message.(type) {
	case Hello:
		if m.GuestVersion != ProtocolVersion {
			e.violation(Reason{Code: ReasonUnsupportedGuestVersion, Detail: fmt.Sprintf("the guest speaks protocol version %d, the host %d", m.GuestVersion, ProtocolVersion)}, events)
			return
		}
		if m.ClaimedVM != nil && *m.ClaimedVM != e.binding.VM() {
			e.violation(Reason{Code: ReasonClaimedIdentityDisagrees, Detail: "the guest's claimed VM is not the one the host bound"}, events)
			return
		}
		if m.ClaimedBoot != nil && *m.ClaimedBoot != e.binding.Boot() {
			e.violation(Reason{Code: ReasonClaimedIdentityDisagrees, Detail: "the guest's claimed boot generation is not the one the host bound"}, events)
			return
		}
		e.phase = PhaseOpen
		idle := uint32(0xffffffff)
		if seconds := int64(e.limits.IdleTimeout / time.Second); seconds < int64(idle) {
			idle = uint32(seconds)
		}
		_ = e.enqueueInternal(Welcome{Version: ProtocolVersion, MaxFrameBytes: e.limits.MaxFrameBytes, IdleTimeoutSeconds: idle})
		e.deliver(m, sequence, events)
	case Welcome:
		if m.Version != ProtocolVersion {
			e.violation(Reason{Code: ReasonUnsupportedHostVersion, Detail: fmt.Sprintf("the host speaks protocol version %d, the guest %d", m.Version, ProtocolVersion)}, events)
			return
		}
		if m.MaxFrameBytes < FrameOverheadBytes+1 || m.IdleTimeoutSeconds == 0 {
			e.violation(Reason{Code: ReasonWelcomeTermsRefused, Detail: fmt.Sprintf("frames of %d bytes or an idle timeout of %d seconds cannot carry the link", m.MaxFrameBytes, m.IdleTimeoutSeconds)}, events)
			return
		}
		terms := m
		e.terms = &terms
		e.phase = PhaseOpen
		e.deliver(m, sequence, events)
	case InitReport:
		if m.ClaimedVM != nil && *m.ClaimedVM != e.binding.VM() {
			e.violation(Reason{Code: ReasonClaimedIdentityDisagrees, Detail: "the guest's claimed VM is not the one the host bound"}, events)
			return
		}
		e.deliver(m, sequence, events)
	case Close:
		e.deliver(m, sequence, events)
		cause := CloseCause{Kind: ClosePeerClosed, Reason: m.Reason}
		e.closeLink(cause)
		*events = append(*events, ClosedEvent{cause})
	case WindowUpdate:
		state := e.state(m.Chan)
		credit := state.sendCredit + uint64(m.CreditBytes)
		if credit < state.sendCredit {
			credit = ^uint64(0)
		}
		state.sendCredit = credit
		e.deliver(m, sequence, events)
	case StreamWindowUpdate:
		state := e.state(m.Chan)
		entry, ok := state.streams[m.Stream]
		if !ok {
			if state.wasEnded(m.Stream) {
				// Credit that crossed the stream's finish: nothing is left to credit.
				return
			}
			e.missingStream(m.Chan, m.Stream, events)
			return
		}
		entry.sendWindow = saturatingAdd(entry.sendWindow, uint64(m.CreditBytes))
		e.deliver(m, sequence, events)
	case OpenTerminal, OpenFile, OpenIngress, OpenEgress:
		e.applyOpen(message, sequence, now, events)
	case Opened, OpenRefused:
		channel, stream := message.Channel(), message.StreamID()
		state := e.state(channel)
		entry, ok := state.streams[stream]
		if !ok {
			e.missingStream(channel, stream, events)
			return
		}
		if entry.opener != e.role || entry.open {
			e.budgeted(Reason{Code: ReasonStreamNotOpening, Detail: fmt.Sprintf("%s stream %d is not awaiting the %s's answer", channel, stream, peer)}, events)
			return
		}
		if _, opened := m.(Opened); opened {
			entry.open = true
		} else {
			state.complete(stream)
		}
		e.deliver(m, sequence, events)
	case Data:
		state := e.state(m.Chan)
		entry, ok := state.streams[m.Stream]
		if !ok {
			if state.wasCancelled(m.Stream) && !m.Chan.HasStreamWindows() {
				// In flight when the cancel crossed it: the peer was charged for it, so it
				// counts against the window and its credit goes straight back. On the
				// ingress and egress channels the stream's window went with the stream.
				needed := uint64(len(m.Bytes))
				if needed > state.receiveWindow {
					e.channelViolation(m.Chan, Reason{Code: ReasonWindowExceeded, Detail: fmt.Sprintf("%d bytes exceed the %d bytes of %s window left", needed, state.receiveWindow, m.Chan)}, events)
					return
				}
				if needed > 0 {
					_ = e.queueWindowUpdate(m.Chan, uint32(needed), true)
				}
			}
			e.missingStream(m.Chan, m.Stream, events)
			return
		}
		if !entry.open {
			e.budgeted(Reason{Code: ReasonStreamNotOpen, Detail: fmt.Sprintf("%s stream %d is not open", m.Chan, m.Stream)}, events)
			return
		}
		if entry.peerEnded {
			e.budgeted(Reason{Code: ReasonHalfClosed, Detail: fmt.Sprintf("the %s already ended %s stream %d", peer, m.Chan, m.Stream)}, events)
			return
		}
		needed := uint64(len(m.Bytes))
		if m.Chan.HasStreamWindows() {
			if needed > entry.receiveWindow {
				e.channelViolation(m.Chan, Reason{Code: ReasonStreamWindowExceeded, Detail: fmt.Sprintf("%d bytes exceed the %d bytes of %s stream %d's window left", needed, entry.receiveWindow, m.Chan, m.Stream)}, events)
				return
			}
			entry.receiveWindow -= needed
			entry.buffered += needed
			e.deliver(m, sequence, events)
			return
		}
		if needed > state.receiveWindow {
			e.channelViolation(m.Chan, Reason{Code: ReasonWindowExceeded, Detail: fmt.Sprintf("%d bytes exceed the %d bytes of %s window left", needed, state.receiveWindow, m.Chan)}, events)
			return
		}
		state.receiveWindow -= needed
		state.buffered += needed
		e.deliver(m, sequence, events)
	case EndOfStream:
		if !e.peerEnd(m.Chan, m.Stream, events) {
			return
		}
		e.deliver(m, sequence, events)
	case Exit:
		if !e.peerEnd(ChannelTerminal, m.Stream, events) {
			return
		}
		e.deliver(m, sequence, events)
	case Cancel:
		state := e.state(m.Chan)
		if _, ok := state.streams[m.Stream]; !ok {
			if state.wasEnded(m.Stream) {
				return
			}
			e.missingStream(m.Chan, m.Stream, events)
			return
		}
		state.forget(m.Stream)
		e.deliver(m, sequence, events)
	case Resize:
		state := e.state(ChannelTerminal)
		entry, ok := state.streams[m.Stream]
		if !ok {
			e.missingStream(ChannelTerminal, m.Stream, events)
			return
		}
		if !entry.open {
			e.budgeted(Reason{Code: ReasonStreamNotOpen, Detail: fmt.Sprintf("terminal stream %d is not open", m.Stream)}, events)
			return
		}
		e.deliver(m, sequence, events)
	default:
		// Ping, Pong, Revoke, Shutdown, ProbeResult, AllProbesPassed: the direction table
		// already admitted them for the peer.
		e.deliver(message, sequence, events)
	}
}

func (e *Endpoint) applyOpen(message Message, sequence uint64, now time.Time, events *[]Event) {
	channel, stream := message.Channel(), message.StreamID()
	peer := e.role.Peer()
	if openerOf(stream) != peer {
		e.budgeted(Reason{Code: ReasonStreamParity, Detail: fmt.Sprintf("stream %d has %s parity", stream, e.role)}, events)
		return
	}
	state := e.state(channel)
	if stream <= state.highestPeer {
		e.budgeted(Reason{Code: ReasonStreamIDNotIncreasing, Detail: fmt.Sprintf("stream %d is not above the highest %s stream %d", stream, peer, state.highestPeer)}, events)
		return
	}
	if len(state.streams) >= int(state.quota.MaxStreams) {
		e.budgeted(Reason{Code: ReasonStreamQuotaExceeded, Detail: fmt.Sprintf("the %s channel already has %d streams", channel, state.quota.MaxStreams)}, events)
		return
	}
	state.highestPeer = stream
	state.streams[stream] = newStreamState(peer, now)
	e.deliver(message, sequence, events)
}

// peerEnd marks the peer's direction of a stream ended; false after a refusal.
func (e *Endpoint) peerEnd(channel Channel, stream uint32, events *[]Event) bool {
	state := e.state(channel)
	entry, ok := state.streams[stream]
	if !ok {
		e.missingStream(channel, stream, events)
		return false
	}
	if !entry.open {
		e.budgeted(Reason{Code: ReasonStreamNotOpen, Detail: fmt.Sprintf("%s stream %d is not open", channel, stream)}, events)
		return false
	}
	if entry.peerEnded {
		e.budgeted(Reason{Code: ReasonHalfClosed, Detail: fmt.Sprintf("the %s already ended %s stream %d", e.role.Peer(), channel, stream)}, events)
		return false
	}
	if entry.localEnded {
		state.complete(stream)
	} else {
		entry.peerEnded = true
	}
	return true
}

// missingStream refuses a frame for a stream the channel does not hold: a cancelled
// stream's late frames are refused without charging the budget, since they may have been
// in flight.
func (e *Endpoint) missingStream(channel Channel, stream uint32, events *[]Event) {
	if e.state(channel).wasCancelled(stream) {
		*events = append(*events, RefusedEvent{Refusal{Reason: Reason{Code: ReasonStreamCancelled, Detail: fmt.Sprintf("%s stream %d was cancelled", channel, stream)}, Effect: EffectFrameDropped}})
		return
	}
	e.budgeted(Reason{Code: ReasonStreamNotOpen, Detail: fmt.Sprintf("%s stream %d is not open", channel, stream)}, events)
}

// violation is a refusal that closes the link.
func (e *Endpoint) violation(reason Reason, events *[]Event) {
	*events = append(*events, RefusedEvent{Refusal{Reason: reason, Effect: EffectLinkClosed}})
	cause := CloseCause{Kind: CloseViolation, Violation: reason}
	e.closeLink(cause)
	*events = append(*events, ClosedEvent{cause})
}

// budgeted is a refusal charged to the budget; exhausting it closes the link.
func (e *Endpoint) budgeted(reason Reason, events *[]Event) {
	if e.refusals < ^uint32(0) {
		e.refusals++
	}
	if e.refusals >= e.limits.MaxRefusals {
		*events = append(*events, RefusedEvent{Refusal{Reason: reason, Effect: EffectLinkClosed}})
		cause := CloseCause{Kind: CloseRefusalBudgetExhausted}
		e.closeLink(cause)
		*events = append(*events, ClosedEvent{cause})
		return
	}
	*events = append(*events, RefusedEvent{Refusal{Reason: reason, Effect: EffectFrameDropped}})
}

// channelViolation is a refusal that closes one bulk channel: its streams and queue drop.
func (e *Endpoint) channelViolation(channel Channel, reason Reason, events *[]Event) {
	state := e.state(channel)
	closed := reason
	state.closed = &closed
	state.clear()
	*events = append(*events, RefusedEvent{Refusal{Reason: reason, Effect: EffectChannelClosed}}, ChannelClosedEvent{Channel: channel, Reason: reason})
}

// closeLink closes the link: no frame is read again, every queue is dropped and one close
// frame is queued for the peer.
func (e *Endpoint) closeLink(cause CloseCause) {
	if e.IsClosed() {
		return
	}
	e.phase = PhaseClosed
	e.cause = cause
	e.decoder.Close(&FramingRefusal{Kind: FramingDecoderClosed})
	e.urgent = nil
	for _, state := range e.channels {
		state.clear()
	}
	// A guest that was never challenged has no connection to send a close on.
	if e.bound {
		_ = e.enqueueInternal(Close{Reason: cause.FrameReason()})
	}
}
