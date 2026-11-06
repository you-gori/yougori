package link

// Conformance with the host: the shared corpus (src-tauri/src/sandbox/link/corpus.json,
// format yougori-link-corpus/v2, protocol version 2 with the connection binding of
// M06-LC) replayed against this package's endpoint in the host role, every case and the
// VM-CP-25 mutations of every valid frame, with the host test's assertions (corpus.rs
// replay, tests.rs the_vm_cp_25_mutations_...). Each case runs on a fresh host endpoint
// challenged with the corpus connection, whose first frame must be the corpus's challenge
// byte for byte. YOUGORI_LINK_CORPUS overrides the path (until M06-LC's corpus is in the
// tree, it names agent L1's corpus).

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const corpusFormat = "yougori-link-corpus/v2"

type corpusFile struct {
	Format          string       `json:"format"`
	ProtocolVersion uint8        `json:"protocol_version"`
	SecretHex       string       `json:"secret_hex"`
	VMHex           string       `json:"vm_hex"`
	BootGeneration  uint64       `json:"boot_generation"`
	ConnectionHex   string       `json:"connection_hex"`
	ChallengeHex    string       `json:"challenge_hex"`
	Cases           []corpusCase `json:"cases"`
}

type corpusCase struct {
	Name   string            `json:"name"`
	Kind   string            `json:"kind"`
	Notes  string            `json:"notes"`
	Steps  []json.RawMessage `json:"steps"`
	Expect corpusExpect      `json:"expect"`
}

type corpusExpect struct {
	Outcome string  `json:"outcome"`
	Reason  *string `json:"reason,omitempty"`
	Link    string  `json:"link"`
}

type corpusStep struct {
	Kind     string          `json:"kind"`
	FrameHex string          `json:"frame_hex,omitempty"`
	Action   json.RawMessage `json:"action,omitempty"`
}

type hostAction struct {
	Action   string  `json:"action"`
	Channel  *string `json:"channel,omitempty"`
	Stream   uint32  `json:"stream"`
	Cause    *string `json:"cause,omitempty"`
	Columns  uint16  `json:"columns,omitempty"`
	Rows     uint16  `json:"rows,omitempty"`
	Listener string  `json:"listener,omitempty"`
	Grant    uint64  `json:"grant,omitempty"`
	Entry    string  `json:"entry,omitempty"`
	Mode     string  `json:"mode,omitempty"`
	Reason   string  `json:"reason,omitempty"`
}

func strictDecode(raw []byte, into any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(into)
}

func corpusPath() string {
	if path := os.Getenv("YOUGORI_LINK_CORPUS"); path != "" {
		return path
	}
	return filepath.Join("..", "..", "..", "src-tauri", "src", "sandbox", "link", "corpus.json")
}

func loadCorpus(t *testing.T) *corpusFile {
	t.Helper()
	raw, err := os.ReadFile(corpusPath())
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var corpus corpusFile
	if err := strictDecode(raw, &corpus); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	if corpus.Format != corpusFormat {
		t.Fatalf("%s is corpus format %q; this side speaks %q (protocol version %d): the corpus must be M06-LC's (YOUGORI_LINK_CORPUS names another path)", corpusPath(), corpus.Format, corpusFormat, ProtocolVersion)
	}
	if corpus.ProtocolVersion != ProtocolVersion {
		t.Fatalf("corpus protocol version %d, this side %d", corpus.ProtocolVersion, ProtocolVersion)
	}
	return &corpus
}

func (c *corpusFile) binding(t *testing.T) *Binding {
	t.Helper()
	material, err := hex.DecodeString(c.SecretHex)
	if err != nil {
		t.Fatalf("secret_hex: %v", err)
	}
	secret, err := NewBootstrapSecret(material)
	if err != nil {
		t.Fatalf("secret: %v", err)
	}
	vm, err := DigestFromHex(c.VMHex)
	if err != nil {
		t.Fatalf("vm_hex: %v", err)
	}
	return NewBinding(vm, c.BootGeneration, secret)
}

func (c *corpusFile) connection(t *testing.T) Connection {
	t.Helper()
	material, err := hex.DecodeString(c.ConnectionHex)
	if err != nil {
		t.Fatalf("connection_hex: %v", err)
	}
	connection, err := NewConnection(material)
	if err != nil {
		t.Fatalf("connection: %v", err)
	}
	return connection
}

func channelNamed(name string) (Channel, error) {
	for _, channel := range AllChannels {
		if channel.String() == name {
			return channel, nil
		}
	}
	return 0, fmt.Errorf("unknown channel %q", name)
}

func codeNamed(name string, names map[string]uint8) (uint8, error) {
	code, ok := names[name]
	if !ok {
		return 0, fmt.Errorf("unknown code %q", name)
	}
	return code, nil
}

var (
	openRefusalNames = map[string]uint8{"not_authorized": 1, "unavailable": 2, "quota_exceeded": 3, "unsupported": 4}
	cancelNames      = map[string]uint8{"requested": 1, "timed_out": 2, "revoked": 3, "quota_exceeded": 4, "failed": 5}
	closeNames       = map[string]uint8{"orderly": 1, "protocol_violation": 2, "timed_out": 3, "revoked": 4, "shutdown": 5}
	fileModeNames    = map[string]uint8{"read": 1, "write": 2}
)

func (a *hostAction) message() (Message, error) {
	channel := ChannelControl
	if a.Channel != nil {
		named, err := channelNamed(*a.Channel)
		if err != nil {
			return nil, err
		}
		channel = named
	}
	cause := ""
	if a.Cause != nil {
		cause = *a.Cause
	}
	switch a.Action {
	case "opened":
		return Opened{Chan: channel, Stream: a.Stream}, nil
	case "open_refused":
		code, err := codeNamed(cause, openRefusalNames)
		return OpenRefused{Chan: channel, Stream: a.Stream, Cause: OpenRefusalCause(code)}, err
	case "open_terminal":
		return OpenTerminal{Stream: a.Stream, Columns: a.Columns, Rows: a.Rows}, nil
	case "open_ingress":
		return OpenIngress{Stream: a.Stream, Listener: a.Listener}, nil
	case "open_file":
		mode, err := codeNamed(a.Mode, fileModeNames)
		return OpenFile{Stream: a.Stream, Grant: a.Grant, Entry: a.Entry, Mode: FileMode(mode)}, err
	case "cancel":
		code, err := codeNamed(cause, cancelNames)
		return Cancel{Chan: channel, Stream: a.Stream, Cause: CancelCause(code)}, err
	case "end_of_stream":
		return EndOfStream{Chan: channel, Stream: a.Stream}, nil
	case "close":
		code, err := codeNamed(a.Reason, closeNames)
		return Close{Reason: CloseReason(code)}, err
	}
	return nil, fmt.Errorf("unknown host action %q", a.Action)
}

type feed int

const (
	feedWhole feed = iota
	feedOneByteAtATime
	feedWholeThenDisconnect
)

type replayOutcome struct {
	lastCode     string // empty when the last guest frame was accepted
	linkOpen     bool
	peakDecoder  int
	peakBuffered uint64
}

func (o replayOutcome) matches(expect corpusExpect) bool {
	outcomeOK := false
	switch expect.Outcome {
	case "accepted":
		outcomeOK = o.lastCode == ""
	case "refused":
		outcomeOK = o.lastCode != "" && expect.Reason != nil && *expect.Reason == o.lastCode
	}
	linkOK := (expect.Link == "open") == o.linkOpen
	return outcomeOK && linkOK && (expect.Link == "open" || expect.Link == "closed")
}

// replay drives one case against a fresh host endpoint with the default limits and a
// clock that never moves; lastFrames replaces the last guest frame (a mutation).
func replay(t *testing.T, corpus *corpusFile, c corpusCase, lastFrames [][]byte, mode feed) replayOutcome {
	t.Helper()
	endpoint, err := NewHostEndpoint(corpus.binding(t), corpus.connection(t), DefaultLimits(), newClock())
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := hex.DecodeString(corpus.ChallengeHex)
	if err != nil {
		t.Fatalf("challenge_hex: %v", err)
	}
	if first := endpoint.NextOutbound(); !bytes.Equal(first, challenge) {
		t.Fatalf("%s: the host's first frame is not the corpus challenge:\n got %x\nwant %x", c.Name, first, challenge)
	}
	steps := make([]corpusStep, len(c.Steps))
	lastGuest := -1
	for i, raw := range c.Steps {
		if err := strictDecode(raw, &steps[i]); err != nil {
			t.Fatalf("%s step %d: %v", c.Name, i, err)
		}
		if steps[i].Kind == "guest" {
			lastGuest = i
		}
	}
	if lastGuest < 0 {
		t.Fatalf("%s has no guest frame", c.Name)
	}
	outcome := replayOutcome{}
	record := func() {
		if n := endpoint.DecoderBufferedBytes(); n > outcome.peakDecoder {
			outcome.peakDecoder = n
		}
		for _, channel := range AllChannels {
			if b := endpoint.Channel(channel).Buffered; b > outcome.peakBuffered {
				outcome.peakBuffered = b
			}
		}
	}
	for i, step := range steps {
		switch step.Kind {
		case "host":
			var action hostAction
			if err := strictDecode(step.Action, &action); err != nil {
				t.Fatalf("%s step %d action: %v", c.Name, i, err)
			}
			message, err := action.message()
			if err != nil {
				t.Fatalf("%s step %d: %v", c.Name, i, err)
			}
			if err := endpoint.Send(message); err != nil {
				t.Fatalf("%s host step %d refused: %v", c.Name, i, err)
			}
			for endpoint.NextOutbound() != nil {
			}
		case "guest":
			frame, err := hex.DecodeString(step.FrameHex)
			if err != nil {
				t.Fatalf("%s step %d frame_hex: %v", c.Name, i, err)
			}
			isLast := i == lastGuest
			frames := [][]byte{frame}
			if isLast && lastFrames != nil {
				frames = lastFrames
			}
			var events []Event
			for _, f := range frames {
				if isLast && mode == feedOneByteAtATime {
					for j := range f {
						events = append(events, endpoint.Receive(f[j:j+1])...)
						record()
					}
					continue
				}
				events = append(events, endpoint.Receive(f)...)
				record()
			}
			if isLast && mode == feedWholeThenDisconnect {
				events = append(events, endpoint.PeerClosed()...)
			}
			codes := refusalCodes(events)
			switch {
			case !isLast && len(codes) > 0:
				t.Fatalf("%s guest frame %d refused before the last: %s", c.Name, i, codes[0])
			case isLast && len(codes) > 0:
				outcome.lastCode = codes[0]
			}
		default:
			t.Fatalf("%s step %d kind %q", c.Name, i, step.Kind)
		}
	}
	outcome.linkOpen = !endpoint.IsClosed()
	return outcome
}

func TestEveryCorpusCaseReplaysAsItExpects(t *testing.T) {
	corpus := loadCorpus(t)
	valid, hostile := 0, 0
	names := map[string]bool{}
	for _, c := range corpus.Cases {
		if names[c.Name] {
			t.Fatalf("case name %s repeats", c.Name)
		}
		names[c.Name] = true
		outcome := replay(t, corpus, c, nil, feedWhole)
		if !outcome.matches(c.Expect) {
			t.Errorf("%s: got code %q open %v, expected %+v reason %v", c.Name, outcome.lastCode, outcome.linkOpen, c.Expect, deref(c.Expect.Reason))
		}
		if outcome.peakDecoder > int(DefaultMaxFrameBytes) {
			t.Errorf("%s: decoder held %d bytes", c.Name, outcome.peakDecoder)
		}
		switch c.Kind {
		case "valid":
			valid++
			if outcome.lastCode != "" {
				t.Errorf("%s: a valid case was refused: %s", c.Name, outcome.lastCode)
			}
		case "hostile":
			hostile++
		default:
			t.Errorf("%s: kind %q", c.Name, c.Kind)
		}
	}
	if valid < 20 || hostile < 50 {
		t.Fatalf("corpus has %d valid and %d hostile cases", valid, hostile)
	}
}

func deref(s *string) string {
	if s == nil {
		return "<none>"
	}
	return *s
}

// splitFrame takes a sealed frame apart; false when it is too short or its header does
// not decode.
func splitFrame(frame []byte) (Header, []byte, bool) {
	if len(frame) < HeaderBytes {
		return Header{}, nil, false
	}
	head := [HeaderBytes]byte(frame[:HeaderBytes])
	header, refusal := DecodeHeader(&head, ^uint32(0))
	if refusal != nil {
		return Header{}, nil, false
	}
	end := HeaderBytes + int(header.PayloadBytes)
	if len(frame) < end+TagBytes {
		return Header{}, nil, false
	}
	return header, frame[HeaderBytes:end], true
}

// TestTheEncoderProducesEveryValidFrameByteForByte decodes every guest frame of every
// valid case with this package and seals it again: the bytes must be identical, so the
// guest's encoder is the host's.
func TestTheEncoderProducesEveryValidFrameByteForByte(t *testing.T) {
	corpus := loadCorpus(t)
	binding := corpus.binding(t)
	frames := 0
	for _, c := range corpus.Cases {
		if c.Kind != "valid" {
			continue
		}
		for i, raw := range c.Steps {
			var step corpusStep
			if err := strictDecode(raw, &step); err != nil {
				t.Fatal(err)
			}
			if step.Kind != "guest" {
				continue
			}
			frame, _ := hex.DecodeString(step.FrameHex)
			header, payload, ok := splitFrame(frame)
			if !ok {
				t.Fatalf("%s step %d does not split", c.Name, i)
			}
			op, ok := DecodeOperation(header.Channel, header.OperationCode)
			if !ok {
				t.Fatalf("%s step %d: unknown operation", c.Name, i)
			}
			limits := DefaultLimits()
			message, err := DecodeMessage(header.Channel, op, header.Stream, payload, int(limits.Quota(header.Channel).MaxMessageBytes))
			if err != nil {
				t.Fatalf("%s step %d: %v", c.Name, i, err)
			}
			again, err := binding.EncodeFrame(SenderGuest, header.Connection, header.Sequence, message)
			if err != nil {
				t.Fatalf("%s step %d: %v", c.Name, i, err)
			}
			if !bytes.Equal(again, frame) {
				t.Errorf("%s step %d: re-encoded frame differs\n got %x\nwant %x", c.Name, i, again, frame)
			}
			frames++
		}
	}
	if frames < 30 {
		t.Fatalf("only %d valid frames", frames)
	}
}

type mutation int

const (
	mutationOversized mutation = iota
	mutationTruncated
	mutationSlow
	mutationRecursive
	mutationDuplicateField
	mutationCancelled
)

var allMutations = []mutation{mutationOversized, mutationTruncated, mutationSlow, mutationRecursive, mutationDuplicateField, mutationCancelled}

func (m mutation) String() string {
	return [...]string{"oversized", "truncated", "slow", "recursive", "duplicate_field", "cancelled"}[m]
}

func reseal(binding *Binding, header Header, sequence uint64, payload []byte) []byte {
	header.Sequence = sequence
	header.PayloadBytes = uint32(len(payload))
	return binding.Seal(SenderGuest, header, payload)
}

// mutate is corpus.rs mutate: the frames that replace a valid frame, sealed as the guest
// would (guest root holds the bootstrap material, so a mutated frame can be authentic).
func mutate(t *testing.T, binding *Binding, limits Limits, frame []byte, m mutation) [][]byte {
	t.Helper()
	header, payload, ok := splitFrame(frame)
	if !ok {
		t.Fatal("frame does not split")
	}
	sequence := header.Sequence
	switch m {
	case mutationOversized:
		mutated := append([]byte(nil), frame...)
		mutated[28], mutated[29], mutated[30], mutated[31] = byte(limits.MaxFrameBytes>>24), byte(limits.MaxFrameBytes>>16), byte(limits.MaxFrameBytes>>8), byte(limits.MaxFrameBytes)
		return [][]byte{mutated}
	case mutationTruncated:
		return [][]byte{append([]byte(nil), frame[:len(frame)-1]...)}
	case mutationSlow:
		return [][]byte{append([]byte(nil), frame...)}
	case mutationRecursive:
		max := int(limits.Quota(header.Channel).MaxMessageBytes)
		nested := append([]byte(nil), payload...)
		for len(nested)+FieldOverheadBytes <= max && len(nested)+FieldOverheadBytes <= MaxFieldValueBytes {
			w := &FieldWriter{}
			next, err := w.Bytes(1, nested).Finish()
			if err != nil {
				t.Fatal(err)
			}
			nested = next
		}
		return [][]byte{reseal(binding, header, sequence, nested)}
	case mutationDuplicateField:
		duplicated := append([]byte(nil), payload...)
		firstLen := -1
		if len(payload) >= 3 {
			firstLen = int(payload[1])<<8 | int(payload[2]) + FieldOverheadBytes
		}
		if firstLen >= 0 && firstLen <= len(payload) {
			duplicated = append(duplicated, payload[:firstLen]...)
		} else {
			field, _ := (&FieldWriter{}).U8(1, 1).Finish()
			duplicated = append(duplicated, field...)
			duplicated = append(duplicated, field...)
		}
		return [][]byte{reseal(binding, header, sequence, duplicated)}
	case mutationCancelled:
		var cancel Message = Close{Reason: CloseOrderly}
		if header.Stream != 0 && header.Channel.IsBulk() {
			cancel = Cancel{Chan: header.Channel, Stream: header.Stream, Cause: CancelRequested}
		}
		cancelFrame, err := binding.EncodeFrame(SenderGuest, header.Connection, sequence, cancel)
		if err != nil {
			t.Fatal(err)
		}
		return [][]byte{cancelFrame, reseal(binding, header, sequence+1, payload)}
	}
	t.Fatalf("mutation %d", m)
	return nil
}

func TestTheVMCP25MutationsOfEveryValidFrameAreBoundedRefusals(t *testing.T) {
	corpus := loadCorpus(t)
	limits := DefaultLimits()
	binding := corpus.binding(t)
	mutated := 0
	for _, c := range corpus.Cases {
		if c.Kind != "valid" {
			continue
		}
		var last []byte
		for _, raw := range c.Steps {
			var step corpusStep
			if err := strictDecode(raw, &step); err != nil {
				t.Fatal(err)
			}
			if step.Kind == "guest" {
				last, _ = hex.DecodeString(step.FrameHex)
			}
		}
		header, _, _ := splitFrame(last)
		op, _ := DecodeOperation(header.Channel, header.OperationCode)
		baseline := replay(t, corpus, c, nil, feedWhole)
		for _, m := range allMutations {
			frames := mutate(t, binding, limits, last, m)
			mode := feedWhole
			switch m {
			case mutationSlow:
				mode = feedOneByteAtATime
			case mutationTruncated:
				mode = feedWholeThenDisconnect
			}
			outcome := replay(t, corpus, c, frames, mode)
			label := c.Name + " " + m.String()
			if outcome.peakDecoder > int(limits.MaxFrameBytes) {
				t.Errorf("%s: decoder held %d bytes", label, outcome.peakDecoder)
			}
			if outcome.peakBuffered > 8<<20 {
				t.Errorf("%s: buffered %d bytes", label, outcome.peakBuffered)
			}
			code := outcome.lastCode
			switch m {
			case mutationOversized:
				if code != "framing.oversized" || outcome.linkOpen {
					t.Errorf("%s: %q open %v", label, code, outcome.linkOpen)
				}
			case mutationTruncated:
				if code != "framing.truncated" || outcome.linkOpen {
					t.Errorf("%s: %q open %v", label, code, outcome.linkOpen)
				}
			case mutationSlow:
				if code != baseline.lastCode || outcome.linkOpen != baseline.linkOpen {
					t.Errorf("%s: %q open %v, baseline %q open %v", label, code, outcome.linkOpen, baseline.lastCode, baseline.linkOpen)
				}
			case mutationRecursive:
				if op == OpData {
					if code != "" && !strings.HasPrefix(code, "payload.") {
						t.Errorf("%s: %q", label, code)
					}
				} else if !strings.HasPrefix(code, "payload.") {
					t.Errorf("%s: %q", label, code)
				}
			case mutationDuplicateField:
				if code != "payload.duplicate_field" && code != "payload.unknown_field" && code != "message_too_large" {
					t.Errorf("%s: %q", label, code)
				}
			case mutationCancelled:
				switch code {
				case "stream_cancelled", "stream_not_open", "link_already_closed", "handshake_incomplete":
				case "":
					// A cancel and a credit that both cross a finished stream are benign here
					// (a cancel for a stream this end completed is dropped without a refusal).
					if c.Name != "stream-window-update-after-both-ends" {
						t.Errorf("%s: %q", label, code)
					}
				default:
					t.Errorf("%s: %q", label, code)
				}
			}
			mutated++
		}
	}
	if mutated < 120 {
		t.Fatalf("only %d mutations", mutated)
	}
}

// TestASlowFrameTimesOutAndAnIdleGuestIsClosed checks the host-role timeouts the corpus
// replay (whose clock never moves) cannot.
func TestASlowFrameTimesOutAndAnIdleGuestIsClosed(t *testing.T) {
	p := newPair()
	p.handshake()
	frame, err := p.guest.Binding().EncodeFrame(SenderGuest, p.nonce, 2, Ping{Nonce: 1})
	if err != nil {
		t.Fatal(err)
	}
	p.host.Receive(frame[:10])
	p.clock.advance(5 * time.Second)
	if events := p.host.Tick(); len(events) != 0 {
		t.Fatalf("closed at the limit: %v", events)
	}
	p.clock.advance(time.Millisecond)
	events := p.host.Tick()
	if len(events) != 1 || events[0].(ClosedEvent).Cause.Kind != CloseFrameTimedOut {
		t.Fatalf("%v", events)
	}

	q := newPair()
	q.handshake()
	q.clock.advance(61 * time.Second)
	if events := q.guest.Tick(); len(events) != 0 {
		t.Fatalf("the guest closed on host silence: %v", events)
	}
	events = q.host.Tick()
	if len(events) != 1 || events[0].(ClosedEvent).Cause.Kind != CloseIdleTimedOut {
		t.Fatalf("%v", events)
	}
}
