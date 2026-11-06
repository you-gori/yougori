package link

// The wire format, protocol version 3 (host: src-tauri/src/sandbox/link/wire.rs with the
// connection binding of M06-LC, as published in its wire marker). Frame layout, all
// integers big-endian:
//
//	bytes  0–3   magic "YGLK"
//	byte   4     protocol version, ProtocolVersion
//	byte   5     channel code
//	byte   6     operation code
//	byte   7     flags, reserved and zero
//	bytes  8–11  stream id, zero for channel-level operations
//	bytes 12–19  sequence, per direction and connection, starting at 1
//	bytes 20–27  boot generation the frame is bound to
//	bytes 28–31  payload length in bytes
//	bytes 32–47  connection: the nonce of the host's challenge
//
// The payload follows the header and the HMAC-SHA256 tag over header and payload follows
// the payload, so a frame is FrameOverheadBytes plus the payload length. Version 1 had
// only the first 32 bytes and bound a link to the boot generation alone; its frames are
// refused as framing.retired_version. Version 2 had this layout and one window per bulk
// channel, so on the ingress and egress channels a stream whose reader stopped stalled the
// channel's other streams; version 3 flow-controls those two channels per stream
// (OpStreamWindowUpdate, HasStreamWindows), and a version 2 frame is an unsupported
// version.

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// Magic is the first four bytes of every frame.
var Magic = [4]byte{'Y', 'G', 'L', 'K'}

const (
	// ProtocolVersion is the only protocol version this side speaks.
	ProtocolVersion uint8 = 3
	// RetiredProtocolVersion is the version before the connection binding, refused by name.
	RetiredProtocolVersion uint8 = 1
	// ConnectionBytes is the length of the header's connection field and of the nonce.
	ConnectionBytes = 16
	// HeaderBytes is the fixed header length.
	HeaderBytes = 32 + ConnectionBytes
	// TagBytes is the HMAC-SHA256 tag length.
	TagBytes = 32
	// FrameOverheadBytes is header plus tag: what a frame costs beyond its payload.
	FrameOverheadBytes = HeaderBytes + TagBytes
)

// Channel is one of the five channels; control carries the handshake, liveness,
// revocation, lifecycle and guest reports, the other four carry streams.
type Channel uint8

const (
	ChannelControl  Channel = 0
	ChannelTerminal Channel = 1
	ChannelFile     Channel = 2
	ChannelIngress  Channel = 3
	ChannelEgress   Channel = 4
)

// AllChannels lists every channel in code order.
var AllChannels = [5]Channel{ChannelControl, ChannelTerminal, ChannelFile, ChannelIngress, ChannelEgress}

// BulkChannels lists the channels over which control has priority.
var BulkChannels = [4]Channel{ChannelTerminal, ChannelFile, ChannelIngress, ChannelEgress}

// ChannelFromCode resolves a channel code.
func ChannelFromCode(code uint8) (Channel, bool) {
	if code <= uint8(ChannelEgress) {
		return Channel(code), true
	}
	return 0, false
}

// IsBulk reports whether the channel carries streams rather than control.
func (c Channel) IsBulk() bool { return c != ChannelControl }

// HasStreamWindows reports whether the channel's data is flow-controlled per stream
// (version 3: ingress and egress, whose streams are independent connections).
func (c Channel) HasStreamWindows() bool { return c == ChannelIngress || c == ChannelEgress }

func (c Channel) String() string {
	switch c {
	case ChannelControl:
		return "control"
	case ChannelTerminal:
		return "terminal"
	case ChannelFile:
		return "file"
	case ChannelIngress:
		return "ingress"
	case ChannelEgress:
		return "egress"
	}
	return fmt.Sprintf("channel(%d)", uint8(c))
}

// Sender is the end of the link that sent or may send a frame.
type Sender uint8

const (
	SenderHost  Sender = 1
	SenderGuest Sender = 2
)

// Peer is the other end.
func (s Sender) Peer() Sender {
	if s == SenderHost {
		return SenderGuest
	}
	return SenderHost
}

func (s Sender) String() string {
	if s == SenderHost {
		return "host"
	}
	return "guest"
}

// Direction is the directionality of one operation on one channel.
type Direction uint8

const (
	DirectionHostToGuest Direction = 1
	DirectionGuestToHost Direction = 2
	DirectionBoth        Direction = 3
)

// Allows reports whether sender may send in this direction.
func (d Direction) Allows(sender Sender) bool {
	switch d {
	case DirectionBoth:
		return true
	case DirectionHostToGuest:
		return sender == SenderHost
	case DirectionGuestToHost:
		return sender == SenderGuest
	}
	return false
}

// Operation is an operation code of the closed set.
type Operation uint8

const (
	OpHello           Operation = 0x01
	OpWelcome         Operation = 0x02
	OpPing            Operation = 0x03
	OpPong            Operation = 0x04
	OpRevoke          Operation = 0x05
	OpShutdown        Operation = 0x06
	OpInitReport      Operation = 0x07
	OpProbeResult     Operation = 0x08
	OpAllProbesPassed Operation = 0x09
	OpClose           Operation = 0x0a
	OpWindowUpdate    Operation = 0x0b
	OpChallenge       Operation = 0x0c
	OpOpen            Operation = 0x10
	OpOpened          Operation = 0x11
	OpOpenRefused     Operation = 0x12
	OpData            Operation = 0x13
	OpEndOfStream     Operation = 0x14
	OpCancel          Operation = 0x15
	OpResize          Operation = 0x16
	OpExit            Operation = 0x17
	// OpStreamWindowUpdate credits one ingress or egress stream (version 3).
	OpStreamWindowUpdate Operation = 0x18
)

// AllOperations lists the closed operation set.
var AllOperations = [21]Operation{
	OpChallenge, OpHello, OpWelcome, OpPing, OpPong, OpRevoke, OpShutdown, OpInitReport, OpProbeResult,
	OpAllProbesPassed, OpClose, OpWindowUpdate, OpStreamWindowUpdate, OpOpen, OpOpened, OpOpenRefused,
	OpData, OpEndOfStream, OpCancel, OpResize, OpExit,
}

// DecodeOperation resolves code on channel; false when no operation of the closed set has
// that code there.
func DecodeOperation(channel Channel, code uint8) (Operation, bool) {
	op := Operation(code)
	if _, ok := op.Direction(channel); ok {
		return op, true
	}
	return 0, false
}

// Direction is the direction the operation may travel on channel; false when it does not
// exist there. This table is the whole protocol surface.
func (op Operation) Direction(channel Channel) (Direction, bool) {
	control := channel == ChannelControl
	bulk := channel.IsBulk() && channel <= ChannelEgress
	switch op {
	case OpChallenge:
		return DirectionHostToGuest, control
	case OpHello:
		return DirectionGuestToHost, control
	case OpWelcome:
		return DirectionHostToGuest, control
	case OpPing, OpPong:
		return DirectionBoth, control
	case OpRevoke, OpShutdown:
		return DirectionHostToGuest, control
	case OpInitReport, OpProbeResult, OpAllProbesPassed:
		return DirectionGuestToHost, control
	case OpClose:
		return DirectionBoth, control
	case OpWindowUpdate:
		return DirectionBoth, channel == ChannelTerminal || channel == ChannelFile
	case OpStreamWindowUpdate:
		return DirectionBoth, channel.HasStreamWindows()
	case OpOpen:
		switch channel {
		case ChannelTerminal, ChannelIngress:
			return DirectionHostToGuest, true
		case ChannelEgress:
			return DirectionGuestToHost, true
		case ChannelFile:
			return DirectionBoth, true
		}
	case OpOpened, OpOpenRefused:
		switch channel {
		case ChannelTerminal, ChannelIngress:
			return DirectionGuestToHost, true
		case ChannelEgress:
			return DirectionHostToGuest, true
		case ChannelFile:
			return DirectionBoth, true
		}
	case OpData, OpEndOfStream, OpCancel:
		return DirectionBoth, bulk
	case OpResize:
		return DirectionHostToGuest, channel == ChannelTerminal
	case OpExit:
		return DirectionGuestToHost, channel == ChannelTerminal
	}
	return 0, false
}

// RequiresStream reports whether the operation names a stream in the header (non-zero id)
// rather than none (zero id).
func (op Operation) RequiresStream() bool {
	switch op {
	case OpStreamWindowUpdate, OpOpen, OpOpened, OpOpenRefused, OpData, OpEndOfStream, OpCancel, OpResize, OpExit:
		return true
	}
	return false
}

// IsUrgent reports revocation and lifecycle control, sent before everything else queued.
func (op Operation) IsUrgent() bool {
	switch op {
	case OpRevoke, OpShutdown, OpClose, OpWelcome, OpChallenge:
		return true
	}
	return false
}

func (op Operation) String() string {
	switch op {
	case OpChallenge:
		return "challenge"
	case OpHello:
		return "hello"
	case OpWelcome:
		return "welcome"
	case OpPing:
		return "ping"
	case OpPong:
		return "pong"
	case OpRevoke:
		return "revoke"
	case OpShutdown:
		return "shutdown"
	case OpInitReport:
		return "init_report"
	case OpProbeResult:
		return "probe_result"
	case OpAllProbesPassed:
		return "all_probes_passed"
	case OpClose:
		return "close"
	case OpWindowUpdate:
		return "window_update"
	case OpStreamWindowUpdate:
		return "stream_window_update"
	case OpOpen:
		return "open"
	case OpOpened:
		return "opened"
	case OpOpenRefused:
		return "open_refused"
	case OpData:
		return "data"
	case OpEndOfStream:
		return "end_of_stream"
	case OpCancel:
		return "cancel"
	case OpResize:
		return "resize"
	case OpExit:
		return "exit"
	}
	return fmt.Sprintf("operation(%#02x)", uint8(op))
}

// FramingKind names a framing refusal.
type FramingKind uint8

const (
	FramingBadMagic FramingKind = iota + 1
	FramingRetiredVersion
	FramingUnsupportedVersion
	FramingUnknownChannel
	FramingReservedFlags
	FramingOversized
	FramingTruncated
	FramingDecoderClosed
)

// FramingRefusal is why the framing layer refused bytes. Every one ends the link: a byte
// stream whose framing is wrong cannot be resynchronised.
type FramingRefusal struct {
	Kind          FramingKind
	Found         uint8
	FrameBytes    uint64
	MaxFrameBytes uint32
	HaveBytes     int
	NeedBytes     int
}

// Code is the stable name used by the conformance corpus.
func (r *FramingRefusal) Code() string {
	switch r.Kind {
	case FramingBadMagic:
		return "framing.bad_magic"
	case FramingRetiredVersion:
		return "framing.retired_version"
	case FramingUnsupportedVersion:
		return "framing.unsupported_version"
	case FramingUnknownChannel:
		return "framing.unknown_channel"
	case FramingReservedFlags:
		return "framing.reserved_flags"
	case FramingOversized:
		return "framing.oversized"
	case FramingTruncated:
		return "framing.truncated"
	case FramingDecoderClosed:
		return "framing.decoder_closed"
	}
	return "framing.unknown"
}

func (r *FramingRefusal) Error() string {
	switch r.Kind {
	case FramingBadMagic:
		return "the frame does not start with the link magic"
	case FramingRetiredVersion:
		return fmt.Sprintf("protocol version %d is retired: it binds no connection; this side speaks %d", r.Found, ProtocolVersion)
	case FramingUnsupportedVersion:
		return fmt.Sprintf("protocol version %d is not %d", r.Found, ProtocolVersion)
	case FramingUnknownChannel:
		return fmt.Sprintf("channel code %d is unknown", r.Found)
	case FramingReservedFlags:
		return fmt.Sprintf("flags %#02x are reserved and must be zero", r.Found)
	case FramingOversized:
		return fmt.Sprintf("the frame is %d bytes, larger than %d", r.FrameBytes, r.MaxFrameBytes)
	case FramingTruncated:
		return fmt.Sprintf("the peer closed after %d of %d bytes of a frame", r.HaveBytes, r.NeedBytes)
	case FramingDecoderClosed:
		return "bytes arrived after the decoder closed"
	}
	return "framing refused"
}

// Header is the decoded fixed header of one frame. The operation stays a raw code until
// the frame is authenticated.
type Header struct {
	Channel        Channel
	OperationCode  uint8
	Stream         uint32
	Sequence       uint64
	BootGeneration uint64
	PayloadBytes   uint32
	Connection     Connection
}

// Encode writes the header bytes.
func (h Header) Encode() [HeaderBytes]byte {
	var b [HeaderBytes]byte
	copy(b[0:4], Magic[:])
	b[4] = ProtocolVersion
	b[5] = uint8(h.Channel)
	b[6] = h.OperationCode
	b[7] = 0
	binary.BigEndian.PutUint32(b[8:12], h.Stream)
	binary.BigEndian.PutUint64(b[12:20], h.Sequence)
	binary.BigEndian.PutUint64(b[20:28], h.BootGeneration)
	binary.BigEndian.PutUint32(b[28:32], h.PayloadBytes)
	copy(b[32:HeaderBytes], h.Connection[:])
	return b
}

// DecodeHeader decodes a header, refusing a bad magic, the retired or another version, an
// unknown channel, reserved flags and a frame longer than maxFrameBytes (header, payload
// and tag together), in that order. The connection field is read as carried.
func DecodeHeader(b *[HeaderBytes]byte, maxFrameBytes uint32) (Header, *FramingRefusal) {
	if [4]byte(b[0:4]) != Magic {
		return Header{}, &FramingRefusal{Kind: FramingBadMagic}
	}
	if b[4] == RetiredProtocolVersion {
		return Header{}, &FramingRefusal{Kind: FramingRetiredVersion, Found: b[4]}
	}
	if b[4] != ProtocolVersion {
		return Header{}, &FramingRefusal{Kind: FramingUnsupportedVersion, Found: b[4]}
	}
	channel, ok := ChannelFromCode(b[5])
	if !ok {
		return Header{}, &FramingRefusal{Kind: FramingUnknownChannel, Found: b[5]}
	}
	if b[7] != 0 {
		return Header{}, &FramingRefusal{Kind: FramingReservedFlags, Found: b[7]}
	}
	payload := binary.BigEndian.Uint32(b[28:32])
	frame := uint64(payload) + FrameOverheadBytes
	if frame > uint64(maxFrameBytes) {
		return Header{}, &FramingRefusal{Kind: FramingOversized, FrameBytes: frame, MaxFrameBytes: maxFrameBytes}
	}
	return Header{
		Channel:        channel,
		OperationCode:  b[6],
		Stream:         binary.BigEndian.Uint32(b[8:12]),
		Sequence:       binary.BigEndian.Uint64(b[12:20]),
		BootGeneration: binary.BigEndian.Uint64(b[20:28]),
		PayloadBytes:   payload,
		Connection:     Connection(b[32:HeaderBytes]),
	}, nil
}

// FrameBytes is the whole frame length this header announces.
func (h Header) FrameBytes() int { return int(h.PayloadBytes) + FrameOverheadBytes }

// Connection is the header's connection field: the nonce the host drew for one connection
// and sent in its challenge. It is not secret.
type Connection [ConnectionBytes]byte

// Hex is the lowercase hexadecimal form.
func (c Connection) Hex() string { return hex.EncodeToString(c[:]) }

// NonceRefusal is why connection nonce material was refused.
type NonceRefusal struct {
	FoundBytes int
	Degenerate bool
}

func (r *NonceRefusal) Error() string {
	if r.Degenerate {
		return "connection nonce material is one repeated byte"
	}
	return fmt.Sprintf("connection nonce material is %d bytes, not %d", r.FoundBytes, ConnectionBytes)
}

// NewConnection checks nonce material as ConnectionNonce::new does: exactly
// ConnectionBytes long and not one repeated byte (all zero included: the field of an
// unchallenged link).
func NewConnection(material []byte) (Connection, error) {
	if len(material) != ConnectionBytes {
		return Connection{}, &NonceRefusal{FoundBytes: len(material)}
	}
	for _, b := range material {
		if b != material[0] {
			return Connection(material), nil
		}
	}
	return Connection{}, &NonceRefusal{Degenerate: true}
}
