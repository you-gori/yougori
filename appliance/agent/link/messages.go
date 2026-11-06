package link

// The typed message of every operation, its payload schema and codec (host:
// src-tauri/src/sandbox/link/messages.rs). No message carries a path, an executable, a URL
// or an address: files are named by a host-issued grant and one entry name, destinations
// and listeners by a link name.

import "fmt"

// CloseReason is why a link closes.
type CloseReason uint8

const (
	CloseOrderly           CloseReason = 1
	CloseProtocolViolation CloseReason = 2
	CloseTimedOut          CloseReason = 3
	CloseRevoked           CloseReason = 4
	CloseShutdown          CloseReason = 5
)

func validCloseReason(code uint8) bool { return code >= 1 && code <= 5 }

// InitStage is one init stage of §3.3.
type InitStage uint8

const (
	StageMounts       InitStage = 1
	StageChannel      InitStage = 2
	StageRestrictions InitStage = 3
	StageAgent        InitStage = 4
	StageWorkload     InitStage = 5
)

func validInitStage(code uint8) bool { return code >= 1 && code <= 5 }

// ProbeOutcome is what a guest says about a probe or stage; the guest's word.
type ProbeOutcome uint8

const (
	OutcomePassed       ProbeOutcome = 1
	OutcomeFailed       ProbeOutcome = 2
	OutcomeSkipped      ProbeOutcome = 3
	OutcomeInconclusive ProbeOutcome = 4
)

func validProbeOutcome(code uint8) bool { return code >= 1 && code <= 4 }

// FileMode is how a file stream is used.
type FileMode uint8

const (
	FileRead  FileMode = 1
	FileWrite FileMode = 2
)

func validFileMode(code uint8) bool { return code == 1 || code == 2 }

// OpenRefusalCause is why an open was refused by the other end.
type OpenRefusalCause uint8

const (
	RefuseNotAuthorized OpenRefusalCause = 1
	RefuseUnavailable   OpenRefusalCause = 2
	RefuseQuotaExceeded OpenRefusalCause = 3
	RefuseUnsupported   OpenRefusalCause = 4
)

func validOpenRefusalCause(code uint8) bool { return code >= 1 && code <= 4 }

// CancelCause is why a stream was cancelled.
type CancelCause uint8

const (
	CancelRequested     CancelCause = 1
	CancelTimedOut      CancelCause = 2
	CancelRevoked       CancelCause = 3
	CancelQuotaExceeded CancelCause = 4
	CancelFailed        CancelCause = 5
)

func validCancelCause(code uint8) bool { return code >= 1 && code <= 5 }

// RevocationReason is the wire code of a CORE-06 revocation reason.
type RevocationReason uint8

const (
	RevokedUserRequested        RevocationReason = 1
	RevokedPolicyChanged        RevocationReason = 2
	RevokedAuthorizationExpired RevocationReason = 3
	RevokedSecurityEvent        RevocationReason = 4
	RevokedOwnerReclaimed       RevocationReason = 5
)

func validRevocationReason(code uint8) bool { return code >= 1 && code <= 5 }

// Message is the typed message of one operation.
type Message interface {
	Operation() Operation
	Channel() Channel
	// StreamID is the header's stream id: zero for channel-level operations.
	StreamID() uint32
	encode(w *FieldWriter)
}

type controlMessage struct{}

func (controlMessage) Channel() Channel { return ChannelControl }
func (controlMessage) StreamID() uint32 { return 0 }

// Challenge is the host's first frame on a connection: the nonce every later frame of
// the connection carries in its header. Its single field must equal the header's.
type Challenge struct {
	controlMessage
	Connection Connection
}

// Hello is the guest's first message. The claims are what the guest believes it was
// given; the host checks them against its binding and never uses them as identity.
type Hello struct {
	controlMessage
	GuestVersion uint8
	AgentBuild   Digest
	ClaimedVM    *Digest
	ClaimedBoot  *uint64
}

// Welcome is the host's terms, sent after an accepted hello.
type Welcome struct {
	controlMessage
	Version            uint8
	MaxFrameBytes      uint32
	IdleTimeoutSeconds uint32
}

// Ping asks for liveness.
type Ping struct {
	controlMessage
	Nonce uint64
}

// Pong answers a ping.
type Pong struct {
	controlMessage
	Nonce uint64
}

// Revoke says authority was revoked.
type Revoke struct {
	controlMessage
	Reason             RevocationReason
	AuthorizationEpoch uint64
}

// Shutdown asks the guest to stop within a grace period.
type Shutdown struct {
	controlMessage
	GraceSeconds uint32
}

// InitReport is a guest report about one init stage.
type InitReport struct {
	controlMessage
	Stage     InitStage
	Outcome   ProbeOutcome
	Detail    string
	ClaimedVM *Digest
}

// ProbeResult is a guest report about one probe.
type ProbeResult struct {
	controlMessage
	Probe   string
	Outcome ProbeOutcome
	Detail  string
}

// AllProbesPassed is a guest report that every probe passed.
type AllProbesPassed struct {
	controlMessage
	ProbeCount uint32
}

// Close ends the link.
type Close struct {
	controlMessage
	Reason CloseReason
}

// WindowUpdate grants receive credit on the terminal or file channel.
type WindowUpdate struct {
	Chan        Channel
	CreditBytes uint32
}

// StreamWindowUpdate grants receive credit on one ingress or egress stream (version 3).
type StreamWindowUpdate struct {
	Chan        Channel
	Stream      uint32
	CreditBytes uint32
}

// OpenTerminal opens a terminal stream (host to guest).
type OpenTerminal struct {
	ImageEntrypoint bool
	Stream          uint32
	Columns         uint16
	Rows            uint16
}

// OpenFile opens a file stream by grant and entry name.
type OpenFile struct {
	Stream uint32
	Grant  uint64
	Entry  string
	Mode   FileMode
}

// OpenIngress opens a stream to a published listener inside the guest (host to guest).
type OpenIngress struct {
	Stream   uint32
	Listener string
}

// OpenEgress asks the host for a stream to a named destination (guest to host).
type OpenEgress struct {
	Stream      uint32
	Destination string
}

// Opened accepts an open.
type Opened struct {
	Chan   Channel
	Stream uint32
}

// OpenRefused refuses an open.
type OpenRefused struct {
	Chan   Channel
	Stream uint32
	Cause  OpenRefusalCause
}

// Data carries opaque bytes on an open stream.
type Data struct {
	Chan   Channel
	Stream uint32
	Bytes  []byte
}

// EndOfStream half-closes the sender's direction of a stream.
type EndOfStream struct {
	Chan   Channel
	Stream uint32
}

// Cancel cancels a stream in both directions.
type Cancel struct {
	Chan   Channel
	Stream uint32
	Cause  CancelCause
}

// Resize changes a terminal's size.
type Resize struct {
	Stream  uint32
	Columns uint16
	Rows    uint16
}

// Exit reports that a terminal's process exited; it ends the guest's direction of the
// terminal stream.
type Exit struct {
	Stream uint32
	Code   int32
}

func (Challenge) Operation() Operation       { return OpChallenge }
func (Hello) Operation() Operation           { return OpHello }
func (Welcome) Operation() Operation         { return OpWelcome }
func (Ping) Operation() Operation            { return OpPing }
func (Pong) Operation() Operation            { return OpPong }
func (Revoke) Operation() Operation          { return OpRevoke }
func (Shutdown) Operation() Operation        { return OpShutdown }
func (InitReport) Operation() Operation      { return OpInitReport }
func (ProbeResult) Operation() Operation     { return OpProbeResult }
func (AllProbesPassed) Operation() Operation { return OpAllProbesPassed }
func (Close) Operation() Operation           { return OpClose }
func (WindowUpdate) Operation() Operation    { return OpWindowUpdate }
func (StreamWindowUpdate) Operation() Operation {
	return OpStreamWindowUpdate
}
func (OpenTerminal) Operation() Operation { return OpOpen }
func (OpenFile) Operation() Operation     { return OpOpen }
func (OpenIngress) Operation() Operation  { return OpOpen }
func (OpenEgress) Operation() Operation   { return OpOpen }
func (Opened) Operation() Operation       { return OpOpened }
func (OpenRefused) Operation() Operation  { return OpOpenRefused }
func (Data) Operation() Operation         { return OpData }
func (EndOfStream) Operation() Operation  { return OpEndOfStream }
func (Cancel) Operation() Operation       { return OpCancel }
func (Resize) Operation() Operation       { return OpResize }
func (Exit) Operation() Operation         { return OpExit }

func (m WindowUpdate) Channel() Channel { return m.Chan }
func (m StreamWindowUpdate) Channel() Channel {
	return m.Chan
}
func (OpenTerminal) Channel() Channel  { return ChannelTerminal }
func (OpenFile) Channel() Channel      { return ChannelFile }
func (OpenIngress) Channel() Channel   { return ChannelIngress }
func (OpenEgress) Channel() Channel    { return ChannelEgress }
func (m Opened) Channel() Channel      { return m.Chan }
func (m OpenRefused) Channel() Channel { return m.Chan }
func (m Data) Channel() Channel        { return m.Chan }
func (m EndOfStream) Channel() Channel { return m.Chan }
func (m Cancel) Channel() Channel      { return m.Chan }
func (Resize) Channel() Channel        { return ChannelTerminal }
func (Exit) Channel() Channel          { return ChannelTerminal }

func (WindowUpdate) StreamID() uint32 { return 0 }
func (m StreamWindowUpdate) StreamID() uint32 {
	return m.Stream
}
func (m OpenTerminal) StreamID() uint32 { return m.Stream }
func (m OpenFile) StreamID() uint32     { return m.Stream }
func (m OpenIngress) StreamID() uint32  { return m.Stream }
func (m OpenEgress) StreamID() uint32   { return m.Stream }
func (m Opened) StreamID() uint32       { return m.Stream }
func (m OpenRefused) StreamID() uint32  { return m.Stream }
func (m Data) StreamID() uint32         { return m.Stream }
func (m EndOfStream) StreamID() uint32  { return m.Stream }
func (m Cancel) StreamID() uint32       { return m.Stream }
func (m Resize) StreamID() uint32       { return m.Stream }
func (m Exit) StreamID() uint32         { return m.Stream }

func (m Challenge) encode(w *FieldWriter) { w.Bytes(1, m.Connection[:]) }
func (m Hello) encode(w *FieldWriter) {
	w.U8(1, m.GuestVersion).Digest(2, m.AgentBuild)
	if m.ClaimedVM != nil {
		w.Digest(3, *m.ClaimedVM)
	}
	if m.ClaimedBoot != nil {
		w.U64(4, *m.ClaimedBoot)
	}
}
func (m Welcome) encode(w *FieldWriter) {
	w.U8(1, m.Version).U32(2, m.MaxFrameBytes).U32(3, m.IdleTimeoutSeconds)
}
func (m Ping) encode(w *FieldWriter)     { w.U64(1, m.Nonce) }
func (m Pong) encode(w *FieldWriter)     { w.U64(1, m.Nonce) }
func (m Revoke) encode(w *FieldWriter)   { w.U8(1, uint8(m.Reason)).U64(2, m.AuthorizationEpoch) }
func (m Shutdown) encode(w *FieldWriter) { w.U32(1, m.GraceSeconds) }
func (m InitReport) encode(w *FieldWriter) {
	w.U8(1, uint8(m.Stage)).U8(2, uint8(m.Outcome)).Text(3, m.Detail)
	if m.ClaimedVM != nil {
		w.Digest(4, *m.ClaimedVM)
	}
}
func (m ProbeResult) encode(w *FieldWriter) {
	w.Text(1, m.Probe).U8(2, uint8(m.Outcome)).Text(3, m.Detail)
}
func (m AllProbesPassed) encode(w *FieldWriter) { w.U32(1, m.ProbeCount) }
func (m Close) encode(w *FieldWriter)           { w.U8(1, uint8(m.Reason)) }
func (m WindowUpdate) encode(w *FieldWriter)    { w.U32(1, m.CreditBytes) }
func (m StreamWindowUpdate) encode(w *FieldWriter) {
	w.U32(1, m.CreditBytes)
}
func (m OpenTerminal) encode(w *FieldWriter) {
	w.U16(1, m.Columns).U16(2, m.Rows)
	if m.ImageEntrypoint {
		w.U8(3, 1)
	}
}
func (m OpenFile) encode(w *FieldWriter)    { w.U64(1, m.Grant).Text(2, m.Entry).U8(3, uint8(m.Mode)) }
func (m OpenIngress) encode(w *FieldWriter) { w.Text(1, m.Listener) }
func (m OpenEgress) encode(w *FieldWriter)  { w.Text(1, m.Destination) }
func (Opened) encode(*FieldWriter)          {}
func (m OpenRefused) encode(w *FieldWriter) { w.U8(1, uint8(m.Cause)) }
func (m Data) encode(w *FieldWriter)        { w.Bytes(1, m.Bytes) }
func (EndOfStream) encode(*FieldWriter)     {}
func (m Cancel) encode(w *FieldWriter)      { w.U8(1, uint8(m.Cause)) }
func (m Resize) encode(w *FieldWriter)      { w.U16(1, m.Columns).U16(2, m.Rows) }
func (m Exit) encode(w *FieldWriter)        { w.I32(1, m.Code) }

// EncodePayload is the payload bytes of message.
func EncodePayload(message Message) ([]byte, error) {
	w := &FieldWriter{}
	message.encode(w)
	return w.Finish()
}

// PayloadRefusal is why a payload was refused after the frame was authenticated.
type PayloadRefusal struct {
	// Field is set for a field refusal.
	Field *FieldRefusal
	// StreamRequired: a stream operation with stream id zero.
	StreamRequired bool
	// ForbiddenStream: a channel-level operation naming this non-zero stream.
	ForbiddenStream uint32
}

// Code is the stable name used by the conformance corpus.
func (r *PayloadRefusal) Code() string {
	switch {
	case r.Field != nil:
		return r.Field.Code()
	case r.StreamRequired:
		return "stream_id_required"
	}
	return "stream_id_forbidden"
}

func (r *PayloadRefusal) Error() string {
	switch {
	case r.Field != nil:
		return r.Field.Error()
	case r.StreamRequired:
		return "the operation needs a stream id"
	}
	return fmt.Sprintf("the operation is channel-level but names stream %d", r.ForbiddenStream)
}

var (
	schemaNone       = []FieldSpec{}
	schemaHello      = []FieldSpec{{1, true}, {2, true}, {3, false}, {4, false}}
	schemaOne        = []FieldSpec{{1, true}}
	schemaTwo        = []FieldSpec{{1, true}, {2, true}}
	schemaThree      = []FieldSpec{{1, true}, {2, true}, {3, true}}
	schemaInitReport = []FieldSpec{{1, true}, {2, true}, {3, true}, {4, false}}
)

// DecodeMessage decodes the payload of op on channel with header stream id stream;
// maxDataBytes bounds a data chunk. The operation must exist on the channel (callers
// resolve it with DecodeOperation first).
func DecodeMessage(channel Channel, op Operation, stream uint32, payload []byte, maxDataBytes int) (Message, error) {
	switch {
	case !op.RequiresStream() && stream != 0:
		return nil, &PayloadRefusal{ForbiddenStream: stream}
	case op.RequiresStream() && stream == 0:
		return nil, &PayloadRefusal{StreamRequired: true}
	}
	message, err := decodeFields(channel, op, stream, payload, maxDataBytes)
	if err != nil {
		if field, ok := err.(*FieldRefusal); ok {
			return nil, &PayloadRefusal{Field: field}
		}
		return nil, err
	}
	return message, nil
}

func decodeFields(channel Channel, op Operation, stream uint32, payload []byte, maxDataBytes int) (Message, error) {
	parse := func(schema []FieldSpec) (*Fields, error) { return ParseFields(payload, schema) }
	switch op {
	case OpChallenge:
		f, err := parse(schemaOne)
		if err != nil {
			return nil, err
		}
		value, err := f.Bytes(1, ConnectionBytes)
		if err != nil {
			return nil, err
		}
		if len(value) != ConnectionBytes {
			return nil, &FieldRefusal{Kind: FieldWrongLength, Tag: 1, ExpectedBytes: ConnectionBytes, FoundBytes: len(value)}
		}
		return Challenge{Connection: Connection(value)}, nil
	case OpHello:
		f, err := parse(schemaHello)
		if err != nil {
			return nil, err
		}
		var m Hello
		if m.GuestVersion, err = f.U8(1); err != nil {
			return nil, err
		}
		if m.AgentBuild, err = f.Digest(2); err != nil {
			return nil, err
		}
		if m.ClaimedVM, err = f.OptionalDigest(3); err != nil {
			return nil, err
		}
		if m.ClaimedBoot, err = f.OptionalU64(4); err != nil {
			return nil, err
		}
		return m, nil
	case OpWelcome:
		f, err := parse(schemaThree)
		if err != nil {
			return nil, err
		}
		var m Welcome
		if m.Version, err = f.U8(1); err != nil {
			return nil, err
		}
		if m.MaxFrameBytes, err = f.U32(2); err != nil {
			return nil, err
		}
		if m.IdleTimeoutSeconds, err = f.U32(3); err != nil {
			return nil, err
		}
		return m, nil
	case OpPing, OpPong:
		f, err := parse(schemaOne)
		if err != nil {
			return nil, err
		}
		nonce, err := f.U64(1)
		if err != nil {
			return nil, err
		}
		if op == OpPing {
			return Ping{Nonce: nonce}, nil
		}
		return Pong{Nonce: nonce}, nil
	case OpRevoke:
		f, err := parse(schemaTwo)
		if err != nil {
			return nil, err
		}
		reason, err := f.Code(1, validRevocationReason)
		if err != nil {
			return nil, err
		}
		epoch, err := f.U64(2)
		if err != nil {
			return nil, err
		}
		return Revoke{Reason: RevocationReason(reason), AuthorizationEpoch: epoch}, nil
	case OpShutdown:
		f, err := parse(schemaOne)
		if err != nil {
			return nil, err
		}
		grace, err := f.U32(1)
		if err != nil {
			return nil, err
		}
		return Shutdown{GraceSeconds: grace}, nil
	case OpInitReport:
		f, err := parse(schemaInitReport)
		if err != nil {
			return nil, err
		}
		stage, err := f.Code(1, validInitStage)
		if err != nil {
			return nil, err
		}
		outcome, err := f.Code(2, validProbeOutcome)
		if err != nil {
			return nil, err
		}
		detail, err := f.Text(3, MaxTextBytes)
		if err != nil {
			return nil, err
		}
		claimed, err := f.OptionalDigest(4)
		if err != nil {
			return nil, err
		}
		return InitReport{Stage: InitStage(stage), Outcome: ProbeOutcome(outcome), Detail: detail, ClaimedVM: claimed}, nil
	case OpProbeResult:
		f, err := parse(schemaThree)
		if err != nil {
			return nil, err
		}
		probe, err := f.Name(1)
		if err != nil {
			return nil, err
		}
		outcome, err := f.Code(2, validProbeOutcome)
		if err != nil {
			return nil, err
		}
		detail, err := f.Text(3, MaxTextBytes)
		if err != nil {
			return nil, err
		}
		return ProbeResult{Probe: probe, Outcome: ProbeOutcome(outcome), Detail: detail}, nil
	case OpAllProbesPassed:
		f, err := parse(schemaOne)
		if err != nil {
			return nil, err
		}
		count, err := f.U32(1)
		if err != nil {
			return nil, err
		}
		return AllProbesPassed{ProbeCount: count}, nil
	case OpClose:
		f, err := parse(schemaOne)
		if err != nil {
			return nil, err
		}
		reason, err := f.Code(1, validCloseReason)
		if err != nil {
			return nil, err
		}
		return Close{Reason: CloseReason(reason)}, nil
	case OpWindowUpdate:
		f, err := parse(schemaOne)
		if err != nil {
			return nil, err
		}
		credit, err := f.U32(1)
		if err != nil {
			return nil, err
		}
		return WindowUpdate{Chan: channel, CreditBytes: credit}, nil
	case OpStreamWindowUpdate:
		f, err := parse(schemaOne)
		if err != nil {
			return nil, err
		}
		credit, err := f.U32(1)
		if err != nil {
			return nil, err
		}
		return StreamWindowUpdate{Chan: channel, Stream: stream, CreditBytes: credit}, nil
	case OpOpen:
		return decodeOpen(channel, stream, payload)
	case OpOpened:
		if _, err := parse(schemaNone); err != nil {
			return nil, err
		}
		return Opened{Chan: channel, Stream: stream}, nil
	case OpOpenRefused:
		f, err := parse(schemaOne)
		if err != nil {
			return nil, err
		}
		cause, err := f.Code(1, validOpenRefusalCause)
		if err != nil {
			return nil, err
		}
		return OpenRefused{Chan: channel, Stream: stream, Cause: OpenRefusalCause(cause)}, nil
	case OpData:
		f, err := parse(schemaOne)
		if err != nil {
			return nil, err
		}
		bytes, err := f.Bytes(1, maxDataBytes)
		if err != nil {
			return nil, err
		}
		return Data{Chan: channel, Stream: stream, Bytes: append([]byte(nil), bytes...)}, nil
	case OpEndOfStream:
		if _, err := parse(schemaNone); err != nil {
			return nil, err
		}
		return EndOfStream{Chan: channel, Stream: stream}, nil
	case OpCancel:
		f, err := parse(schemaOne)
		if err != nil {
			return nil, err
		}
		cause, err := f.Code(1, validCancelCause)
		if err != nil {
			return nil, err
		}
		return Cancel{Chan: channel, Stream: stream, Cause: CancelCause(cause)}, nil
	case OpResize:
		f, err := parse(schemaTwo)
		if err != nil {
			return nil, err
		}
		columns, err := f.U16(1)
		if err != nil {
			return nil, err
		}
		rows, err := f.U16(2)
		if err != nil {
			return nil, err
		}
		return Resize{Stream: stream, Columns: columns, Rows: rows}, nil
	case OpExit:
		f, err := parse(schemaOne)
		if err != nil {
			return nil, err
		}
		code, err := f.I32(1)
		if err != nil {
			return nil, err
		}
		return Exit{Stream: stream, Code: code}, nil
	}
	return nil, fmt.Errorf("operation %s has no codec", op)
}

func decodeOpen(channel Channel, stream uint32, payload []byte) (Message, error) {
	switch channel {
	case ChannelTerminal:
		f, err := ParseFields(payload, []FieldSpec{{1, true}, {2, true}, {3, false}})
		if err != nil {
			return nil, err
		}
		columns, err := f.U16(1)
		if err != nil {
			return nil, err
		}
		rows, err := f.U16(2)
		if err != nil {
			return nil, err
		}
		image := false
		if f.Has(3) {
			value, err := f.U8(3)
			if err != nil {
				return nil, err
			}
			if value != 1 || columns != 0 || rows != 0 {
				return nil, fmt.Errorf("invalid image entrypoint open")
			}
			image = true
		}
		return OpenTerminal{Stream: stream, Columns: columns, Rows: rows, ImageEntrypoint: image}, nil
	case ChannelFile:
		f, err := ParseFields(payload, schemaThree)
		if err != nil {
			return nil, err
		}
		grant, err := f.U64(1)
		if err != nil {
			return nil, err
		}
		entry, err := f.Name(2)
		if err != nil {
			return nil, err
		}
		mode, err := f.Code(3, validFileMode)
		if err != nil {
			return nil, err
		}
		return OpenFile{Stream: stream, Grant: grant, Entry: entry, Mode: FileMode(mode)}, nil
	case ChannelIngress:
		f, err := ParseFields(payload, schemaOne)
		if err != nil {
			return nil, err
		}
		listener, err := f.Name(1)
		if err != nil {
			return nil, err
		}
		return OpenIngress{Stream: stream, Listener: listener}, nil
	}
	f, err := ParseFields(payload, schemaOne)
	if err != nil {
		return nil, err
	}
	destination, err := f.Name(1)
	if err != nil {
		return nil, err
	}
	return OpenEgress{Stream: stream, Destination: destination}, nil
}
