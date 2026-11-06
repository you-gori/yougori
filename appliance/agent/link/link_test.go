package link

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTheHeaderRoundTripsAndIs48Bytes(t *testing.T) {
	header := Header{Channel: ChannelEgress, OperationCode: uint8(OpData), Stream: 7, Sequence: 99, BootGeneration: 3, PayloadBytes: 10, Connection: testNonce}
	encoded := header.Encode()
	if string(encoded[0:4]) != "YGLK" || len(encoded) != 48 || encoded[4] != 3 || string(encoded[32:48]) != "connection-nonce" {
		t.Fatalf("%x", encoded)
	}
	decoded, refusal := DecodeHeader(&encoded, 65552)
	if refusal != nil || decoded != header || header.FrameBytes() != 90 {
		t.Fatalf("%+v %v", decoded, refusal)
	}
	for _, c := range []struct {
		offset int
		value  byte
		code   string
	}{
		{0, 'X', "framing.bad_magic"},
		{4, 1, "framing.retired_version"},
		{4, 2, "framing.unsupported_version"},
		{4, 4, "framing.unsupported_version"},
		{4, 0, "framing.unsupported_version"},
		{5, 9, "framing.unknown_channel"},
		{7, 1, "framing.reserved_flags"},
	} {
		bad := encoded
		bad[c.offset] = c.value
		if _, refusal := DecodeHeader(&bad, 65552); refusal == nil || refusal.Code() != c.code {
			t.Errorf("offset %d: %v", c.offset, refusal)
		}
	}
	big := encoded
	big[28], big[29], big[30], big[31] = 0, 0, 0xff, 0xc1
	if _, refusal := DecodeHeader(&big, 65552); refusal == nil || refusal.Code() != "framing.oversized" {
		t.Fatalf("%v", refusal)
	}
}

func TestEveryCodeDecodesOnlyWhereTheTableAllows(t *testing.T) {
	seen := map[Operation]bool{}
	for _, op := range AllOperations {
		if seen[op] {
			t.Fatalf("code %d repeats", op)
		}
		seen[op] = true
	}
	for _, channel := range AllChannels {
		for code := 0; code < 256; code++ {
			op, ok := DecodeOperation(channel, uint8(code))
			_, exists := Operation(code).Direction(channel)
			if ok != exists || (ok && op != Operation(code)) {
				t.Fatalf("%s %#x", channel, code)
			}
			if ok && !seen[op] {
				t.Fatalf("%s %#x decodes outside the closed set", channel, code)
			}
		}
	}
	// Spot checks of the directionality table (wire.rs Operation::direction).
	for _, c := range []struct {
		op      Operation
		channel Channel
		want    Direction
	}{
		{OpChallenge, ChannelControl, DirectionHostToGuest},
		{OpHello, ChannelControl, DirectionGuestToHost},
		{OpWelcome, ChannelControl, DirectionHostToGuest},
		{OpOpen, ChannelTerminal, DirectionHostToGuest},
		{OpOpen, ChannelEgress, DirectionGuestToHost},
		{OpOpen, ChannelFile, DirectionBoth},
		{OpOpened, ChannelEgress, DirectionHostToGuest},
		{OpExit, ChannelTerminal, DirectionGuestToHost},
		{OpResize, ChannelTerminal, DirectionHostToGuest},
		{OpWindowUpdate, ChannelFile, DirectionBoth},
		{OpStreamWindowUpdate, ChannelIngress, DirectionBoth},
		{OpStreamWindowUpdate, ChannelEgress, DirectionBoth},
	} {
		if got, ok := c.op.Direction(c.channel); !ok || got != c.want {
			t.Errorf("%s on %s: %v %v", c.op, c.channel, got, ok)
		}
	}
	if _, ok := OpData.Direction(ChannelControl); ok {
		t.Fatal("data on control")
	}
	// Version 3: ingress and egress are credited per stream, terminal and file per channel.
	if _, ok := OpWindowUpdate.Direction(ChannelEgress); ok {
		t.Fatal("channel credit on egress")
	}
	if _, ok := OpStreamWindowUpdate.Direction(ChannelTerminal); ok {
		t.Fatal("stream credit on the terminal channel")
	}
	if _, ok := OpExit.Direction(ChannelFile); ok {
		t.Fatal("exit on file")
	}
}

func TestFieldsRefuseEveryMalformationWithItsReason(t *testing.T) {
	schema := []FieldSpec{{1, true}, {2, false}, {3, true}}
	good, _ := (&FieldWriter{}).U64(1, 1).U8(3, 2).Finish()
	if _, err := ParseFields(good, schema); err != nil {
		t.Fatal(err)
	}
	extra, _ := (&FieldWriter{}).U64(1, 1).Finish()
	cases := []struct {
		payload []byte
		code    string
	}{
		{append(append([]byte(nil), good...), extra...), "payload.duplicate_field"},
		{append(append([]byte(nil), good...), 9, 0, 1, 1), "payload.unknown_field"},
		{[]byte{0, 0, 0}, "payload.unknown_field"},
		{[]byte{17, 0, 0}, "payload.unknown_field"},
		{extra, "payload.missing_field"},
		{[]byte{1, 0}, "payload.truncated_header"},
		{[]byte{1, 0, 8, 1, 2, 3}, "payload.truncated_value"},
	}
	for _, c := range cases {
		_, err := ParseFields(c.payload, schema)
		refusal, ok := err.(*FieldRefusal)
		if !ok || refusal.Code() != c.code {
			t.Errorf("%x: %v", c.payload, err)
		}
	}
	fields, _ := ParseFields(good, schema)
	if _, err := fields.U32(1); err.(*FieldRefusal).Code() != "payload.wrong_length" {
		t.Fatal(err)
	}
	if _, err := fields.Bytes(1, 4); err.(*FieldRefusal).Code() != "payload.too_long" {
		t.Fatal(err)
	}
	if _, err := fields.Code(3, func(uint8) bool { return false }); err.(*FieldRefusal).Code() != "payload.invalid_value" {
		t.Fatal(err)
	}
	texts, _ := (&FieldWriter{}).Bytes(1, []byte{0xff, 0xfe}).Text(2, "tab\there").Text(3, "../etc").Finish()
	fields, _ = ParseFields(texts, schema)
	if _, err := fields.Text(1, 16); err.(*FieldRefusal).Code() != "payload.not_text" {
		t.Fatal(err)
	}
	if _, err := fields.Text(2, 16); err.(*FieldRefusal).Code() != "payload.not_text" {
		t.Fatal(err)
	}
	if _, err := fields.Name(3); err.(*FieldRefusal).Code() != "payload.not_name" {
		t.Fatal(err)
	}
	if _, err := (&FieldWriter{}).Bytes(1, make([]byte, MaxFieldValueBytes+1)).Finish(); err == nil {
		t.Fatal("an oversized field was written")
	}
}

func TestLinkNamesAreNeverPathsURLsOrAddresses(t *testing.T) {
	for _, bad := range []string{"", "a/b", "..", "http://x", "10.0.0.1:22", "169.254.169.254", "host:22", "_x", "a b", "/etc/passwd", "C:\\Windows", "é", strings.Repeat("a", 129)} {
		if ValidateLinkName(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	for _, good := range []string{"dest-1", "api.primary_v2", "web", strings.Repeat("a", 128)} {
		if err := ValidateLinkName(good); err != nil {
			t.Errorf("%q: %v", good, err)
		}
	}
}

func TestSequencesAcceptOnlyTheNextAndNeverWrap(t *testing.T) {
	var state SequenceState
	if state.Accept(1) != nil || state.Accept(2) != nil {
		t.Fatal("in order refused")
	}
	for _, c := range []struct {
		sequence uint64
		code     string
	}{{2, "sequence.replayed"}, {1, "sequence.replayed"}, {0, "sequence.replayed"}, {4, "sequence.reordered"}} {
		if refusal := state.Accept(c.sequence); refusal == nil || refusal.Code() != c.code {
			t.Errorf("%d: %v", c.sequence, refusal)
		}
	}
	full := SequenceState{lastAccepted: ^uint64(0) - 1}
	if next, refusal := full.NextForSend(); refusal != nil || next != ^uint64(0) {
		t.Fatal("last sequence refused")
	}
	if _, refusal := full.NextForSend(); refusal == nil || refusal.Code() != "sequence.exhausted" {
		t.Fatal("the space wrapped")
	}
	if refusal := full.Accept(0); refusal == nil || refusal.Code() != "sequence.exhausted" {
		t.Fatal("accepted after exhaustion")
	}
}

// pinnedGuestKeyHex is secret.rs PINNED_GUEST_KEY_HEX: the guest-to-host key of the test
// instance (material index*7+1, VM digest("yougori/test/vm/v1", "vm-a"), boot 3).
const pinnedGuestKeyHex = "706aa5514609f956ca5ad747f523cff0ab3415ccad3c92215644c82d9dec73bc"

func TestKeyDerivationMatchesTheHostsPinnedVector(t *testing.T) {
	secret, err := NewBootstrapSecret(secretMaterial())
	if err != nil {
		t.Fatal(err)
	}
	key := secret.derive(SenderGuest, testVM(), 3)
	if got := hex.EncodeToString(key.bytes[:]); got != pinnedGuestKeyHex {
		t.Fatalf("guest key %s", got)
	}
	host := secret.derive(SenderHost, testVM(), 3)
	otherBoot := secret.derive(SenderGuest, testVM(), 4)
	otherVM := secret.derive(SenderGuest, testDigest("yougori/test/vm/v1", []byte("vm-b")), 3)
	for _, other := range []*linkKey{host, otherBoot, otherVM} {
		if other.bytes == key.bytes {
			t.Fatal("keys collide across direction, boot or instance")
		}
	}
}

func TestSecretsAreCheckedAndNeverPrinted(t *testing.T) {
	if _, err := NewBootstrapSecret(make([]byte, 31)); err == nil {
		t.Fatal("31 bytes accepted")
	}
	if _, err := NewBootstrapSecret(bytes.Repeat([]byte{7}, 32)); err == nil || !err.(*SecretRefusal).Degenerate {
		t.Fatal("degenerate accepted")
	}
	material := secretMaterial()
	secret, _ := NewBootstrapSecret(material)
	hexMaterial := hex.EncodeToString(material)
	binding := NewBinding(testVM(), 3, secret)
	guestKey := hex.EncodeToString(binding.guestToHost.bytes[:])
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%X", "%q", "%d"} {
		for _, value := range []any{secret, binding, binding.guestToHost, *binding} {
			text := strings.ToLower(fmt.Sprintf(verb, value))
			if strings.Contains(text, hexMaterial[:16]) || strings.Contains(text, guestKey[:16]) {
				t.Fatalf("%s printed key material: %s", verb, text)
			}
		}
	}
	if secret.bytes != [32]byte{} {
		t.Fatal("the secret was not wiped after deriving")
	}
	if _, err := secret.MarshalText(); err == nil {
		t.Fatal("the secret serialized")
	}
	tag := binding.Tag(SenderGuest, []byte("header"), []byte("payload"))
	if !binding.Verify(SenderGuest, []byte("header"), []byte("payload"), tag) ||
		binding.Verify(SenderHost, []byte("header"), []byte("payload"), tag) ||
		binding.Verify(SenderGuest, []byte("header"), []byte("payloae"), tag) {
		t.Fatal("tags verify for the wrong direction or bytes")
	}
}

func TestTheBootstrapFileIsReadExactly(t *testing.T) {
	vm := testVM()
	file, err := EncodeBootstrap(secretMaterial(), vm, 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(file) != 77 || string(file[:4]) != "YGLB" || file[4] != 1 {
		t.Fatalf("%x", file)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "raw")
	if err := os.WriteFile(path, file, 0o600); err != nil {
		t.Fatal(err)
	}
	parsed, err := ReadBootstrap(path)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.VM != vm || parsed.BootGeneration != 7 || parsed.Secret.bytes != [32]byte(secretMaterial()) {
		t.Fatal("fields differ")
	}
	binding := parsed.Binding()
	if binding.Boot() != 7 || binding.VM() != vm || parsed.Secret.bytes != [32]byte{} {
		t.Fatal("binding wrong or secret kept")
	}
	mutate := func(edit func([]byte) []byte) []byte {
		return edit(append([]byte(nil), file...))
	}
	for _, c := range []struct {
		name string
		raw  []byte
		kind BootstrapKind
	}{
		{"short", file[:76], BootstrapWrongLength},
		{"long", append(append([]byte(nil), file...), 0), BootstrapWrongLength},
		{"empty", nil, BootstrapWrongLength},
		{"magic", mutate(func(b []byte) []byte { b[0] = 'X'; return b }), BootstrapBadMagic},
		{"version", mutate(func(b []byte) []byte { b[4] = 2; return b }), BootstrapUnsupportedVersion},
		{"degenerate", mutate(func(b []byte) []byte {
			for i := 5; i < 37; i++ {
				b[i] = 0x42
			}
			return b
		}), BootstrapDegenerateSecret},
	} {
		raw := append([]byte(nil), c.raw...)
		_, err := ParseBootstrap(raw)
		refusal, ok := err.(*BootstrapRefusal)
		if !ok || refusal.Kind != c.kind {
			t.Errorf("%s: %v", c.name, err)
		}
		if strings.Contains(fmt.Sprint(err), hex.EncodeToString(secretMaterial())[:8]) {
			t.Errorf("%s: the refusal shows material", c.name)
		}
		for _, b := range raw {
			if b != 0 {
				t.Errorf("%s: the input was not wiped", c.name)
				break
			}
		}
	}
	long := filepath.Join(dir, "long")
	if err := os.WriteFile(long, append(append([]byte(nil), file...), make([]byte, 4096)...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBootstrap(long); err == nil || err.(*BootstrapRefusal).Kind != BootstrapWrongLength {
		t.Fatalf("%v", err)
	}
	if _, err := ReadBootstrap(filepath.Join(dir, "missing")); err == nil || err.(*BootstrapRefusal).Kind != BootstrapUnavailable {
		t.Fatalf("%v", err)
	}
}

func TestTheDecoderHoldsAtMostOneFrameAndSplitsAnywhere(t *testing.T) {
	binding := testBinding(3)
	var stream []byte
	for i, payload := range [][]byte{[]byte("abc"), nil, bytes.Repeat([]byte{7}, 100)} {
		frame, _ := binding.EncodeFrame(SenderGuest, testNonce, uint64(i+1), Data{Chan: ChannelEgress, Stream: 1, Bytes: payload})
		stream = append(stream, frame...)
	}
	whole := NewFrameDecoder(256)
	all, refusal := whole.Push(stream, time.Unix(0, 0))
	if refusal != nil || len(all) != 3 {
		t.Fatalf("%d %v", len(all), refusal)
	}
	slow := NewFrameDecoder(256)
	var collected []RawFrame
	peak := 0
	for i := range stream {
		frames, refusal := slow.Push(stream[i:i+1], time.Unix(0, 0))
		if refusal != nil {
			t.Fatal(refusal)
		}
		collected = append(collected, frames...)
		if slow.BufferedBytes() > peak {
			peak = slow.BufferedBytes()
		}
	}
	if len(collected) != 3 || peak > 256 {
		t.Fatalf("%d frames, peak %d", len(collected), peak)
	}
	for i := range all {
		if !bytes.Equal(all[i].Payload, collected[i].Payload) || all[i].Tag != collected[i].Tag {
			t.Fatalf("frame %d differs", i)
		}
	}
	truncated := NewFrameDecoder(256)
	truncated.Push(stream[:HeaderBytes+3], time.Unix(0, 0))
	if refusal := truncated.Finish(); refusal == nil || refusal.Code() != "framing.truncated" {
		t.Fatalf("%v", refusal)
	}
	if _, refusal := truncated.Push([]byte("x"), time.Unix(0, 0)); refusal == nil || refusal.Code() != "framing.decoder_closed" {
		t.Fatalf("%v", refusal)
	}
}

func TestTheDefaultLimitsAreTheHostsAndValidate(t *testing.T) {
	limits := DefaultLimits()
	if err := limits.Validate(); err != nil {
		t.Fatal(err)
	}
	if limits.MaxFrameBytes != 65552 || limits.Control.MaxMessageBytes != 4096 || limits.Terminal.MaxMessageBytes != 16384 ||
		limits.File.MaxMessageBytes != 65472 || limits.Egress.MaxStreams != 256 || limits.File.MaxBufferedBytes != 8<<20 ||
		limits.HandshakeTimeout != 10*time.Second || limits.IdleTimeout != 60*time.Second ||
		limits.FrameCompletionTimeout != 5*time.Second || limits.OpenTimeout != 30*time.Second || limits.MaxRefusals != 64 {
		t.Fatalf("%+v", limits)
	}
	bad := DefaultLimits()
	bad.Terminal.MaxMessageBytes = 65473
	if bad.Validate() == nil {
		t.Fatal("an oversized message limit validated")
	}
	bad = DefaultLimits()
	bad.Control.MaxStreams = 1
	if bad.Validate() == nil {
		t.Fatal("control streams validated")
	}
}

// --- The guest role: what the guest refuses from the host, mirrored. ---

func TestTheGuestHandshakeAndTerms(t *testing.T) {
	p := newPair()
	if err := p.guest.Send(Ping{Nonce: 1}); err == nil {
		t.Fatal("the guest sent a ping before the hello")
	}
	p.handshake()
	if p.guest.Terms() == nil || p.guest.Terms().MaxFrameBytes != 65552 || p.guest.Terms().IdleTimeoutSeconds != 60 || p.guest.Terms().Version != ProtocolVersion {
		t.Fatalf("%+v", p.guest.Terms())
	}
	if err := p.guest.Send(Hello{GuestVersion: 1}); err == nil {
		t.Fatal("a second hello was sent")
	}
	// A second welcome is refused as repeated, from authentic host bytes.
	frame, _ := p.host.Binding().EncodeFrame(SenderHost, p.nonce, p.guest.LastReceivedSequence()+1, Welcome{Version: ProtocolVersion, MaxFrameBytes: 65552, IdleTimeoutSeconds: 60})
	if codes := refusalCodes(p.guest.Receive(frame)); len(codes) != 1 || codes[0] != ReasonHandshakeRepeated || p.guest.IsClosed() {
		t.Fatalf("%v", codes)
	}
}

func TestTheGuestRefusesAWelcomeOfAnotherVersionOrUnusableTerms(t *testing.T) {
	for _, welcome := range []Welcome{
		{Version: 1, MaxFrameBytes: 65552, IdleTimeoutSeconds: 60},
		{Version: 2, MaxFrameBytes: 65552, IdleTimeoutSeconds: 60},
		{Version: 4, MaxFrameBytes: 65552, IdleTimeoutSeconds: 60},
		{Version: ProtocolVersion, MaxFrameBytes: 80, IdleTimeoutSeconds: 60},
		{Version: ProtocolVersion, MaxFrameBytes: 65552, IdleTimeoutSeconds: 0},
	} {
		p := newPair()
		p.challenge()
		_ = p.guest.Send(Hello{GuestVersion: ProtocolVersion})
		frame, _ := p.host.Binding().EncodeFrame(SenderHost, p.nonce, 2, welcome)
		events := p.guest.Receive(frame)
		codes := refusalCodes(events)
		if len(codes) != 1 || !p.guest.IsClosed() {
			t.Fatalf("%+v: %v", welcome, codes)
		}
	}
}

func TestTheGuestNeverActsOnUnauthenticatedOrStaleFrames(t *testing.T) {
	challenge := Challenge{Connection: testNonce}
	p := newPair()
	forged := testBindingWith([]byte("another secret material 01234567"), 3)
	frame, _ := forged.EncodeFrame(SenderHost, testNonce, 1, challenge)
	events := p.guest.Receive(frame)
	if len(messagesOf(events)) != 0 || refusalCodes(events)[0] != ReasonUnauthenticated || !p.guest.IsClosed() {
		t.Fatalf("%v", events)
	}
	if p.guest.NextOutbound() != nil {
		t.Fatal("an unchallenged guest sent a frame")
	}
	// The guest's own key does not authenticate a host frame (direction binding).
	q := newPair()
	mirrored, _ := q.guest.Binding().EncodeFrame(SenderGuest, testNonce, 1, challenge)
	if codes := refusalCodes(q.guest.Receive(mirrored)); codes[0] != ReasonUnauthenticated {
		t.Fatalf("%v", codes)
	}
	r := newPair()
	stale, _ := testBinding(2).EncodeFrame(SenderHost, testNonce, 1, challenge)
	if codes := refusalCodes(r.guest.Receive(stale)); codes[0] != ReasonUnauthenticated {
		t.Fatalf("a frame keyed for another boot: %v", codes)
	}
	// Same key, header bound to another generation.
	s := newPair()
	payload, _ := EncodePayload(challenge)
	header := Header{Channel: ChannelControl, OperationCode: uint8(OpChallenge), Sequence: 1, BootGeneration: 4, PayloadBytes: uint32(len(payload)), Connection: testNonce}
	if codes := refusalCodes(s.guest.Receive(s.host.Binding().Seal(SenderHost, header, payload))); codes[0] != ReasonStaleGeneration {
		t.Fatalf("%v", codes)
	}
}

func testBindingWith(material []byte, boot uint64) *Binding {
	secret, err := NewBootstrapSecret(material)
	if err != nil {
		panic(err)
	}
	return NewBinding(testVM(), boot, secret)
}

func TestTheGuestAcceptsOnlyUrgentHostFramesBeforeTheWelcome(t *testing.T) {
	p := newPair()
	p.challenge()
	_ = p.guest.Send(Hello{GuestVersion: ProtocolVersion})
	host := p.host.Binding()
	ping, _ := host.EncodeFrame(SenderHost, p.nonce, 2, Ping{Nonce: 1})
	if codes := refusalCodes(p.guest.Receive(ping)); len(codes) != 1 || codes[0] != ReasonHandshakeIncomplete || p.guest.IsClosed() {
		t.Fatalf("%v", codes)
	}
	revoke, _ := host.EncodeFrame(SenderHost, p.nonce, 3, Revoke{Reason: RevokedPolicyChanged, AuthorizationEpoch: 4})
	if events := p.guest.Receive(revoke); len(refusalCodes(events)) != 0 || len(messagesOf(events)) != 1 {
		t.Fatalf("%v", events)
	}
}

func TestTheGuestRefusesGuestOnlyOperationsFromTheHost(t *testing.T) {
	for _, message := range []Message{
		Hello{GuestVersion: 1},
		InitReport{Stage: StageAgent, Outcome: OutcomePassed},
		ProbeResult{Probe: "p", Outcome: OutcomePassed},
		AllProbesPassed{ProbeCount: 1},
		Exit{Stream: 2, Code: 0},
		OpenEgress{Stream: 2, Destination: "x"},
		Opened{Chan: ChannelTerminal, Stream: 2},
	} {
		p := newPair()
		p.handshake()
		frame, _ := p.host.Binding().EncodeFrame(SenderHost, p.nonce, p.guest.LastReceivedSequence()+1, message)
		if codes := refusalCodes(p.guest.Receive(frame)); len(codes) != 1 || codes[0] != ReasonWrongDirection {
			t.Errorf("%T: %v", message, codes)
		}
	}
}

func TestTheTerminalStreamFlowsWithCreditAndHalfClose(t *testing.T) {
	p := newPair()
	p.handshake()
	if err := p.host.Send(OpenTerminal{Stream: 2, Columns: 80, Rows: 24}); err != nil {
		t.Fatal(err)
	}
	_, guestEvents := p.pump()
	if open, ok := messagesOf(guestEvents)[0].(OpenTerminal); !ok || open.Stream != 2 {
		t.Fatalf("%v", guestEvents)
	}
	if err := p.guest.Send(Opened{Chan: ChannelTerminal, Stream: 2}); err != nil {
		t.Fatal(err)
	}
	p.pump()
	// The host has no credit until the guest grants it.
	if err := p.host.Send(Data{Chan: ChannelTerminal, Stream: 2, Bytes: []byte("echo hi\n")}); err == nil {
		t.Fatal("the host sent without credit")
	}
	if err := p.guest.Grant(ChannelTerminal, 8); err != nil {
		t.Fatal(err)
	}
	p.pump()
	if err := p.host.Send(Data{Chan: ChannelTerminal, Stream: 2, Bytes: []byte("echo hi\n")}); err != nil {
		t.Fatal(err)
	}
	if err := p.host.Send(EndOfStream{Chan: ChannelTerminal, Stream: 2}); err != nil {
		t.Fatal(err)
	}
	_, guestEvents = p.pump()
	if len(messagesOf(guestEvents)) != 2 || p.guest.Channel(ChannelTerminal).Buffered != 8 {
		t.Fatalf("%v", guestEvents)
	}
	if err := p.guest.Consume(ChannelTerminal, 8); err != nil {
		t.Fatal(err)
	}
	if err := p.guest.Send(Data{Chan: ChannelTerminal, Stream: 2, Bytes: []byte("hi\n")}); err != nil {
		t.Fatal(err)
	}
	if err := p.guest.Send(Exit{Stream: 2, Code: 3}); err != nil {
		t.Fatal(err)
	}
	hostEvents, _ := p.pump()
	if codes := refusalCodes(hostEvents); len(codes) != 0 {
		t.Fatalf("host refused %v", codes)
	}
	if _, ok := p.guest.Stream(ChannelTerminal, 2); ok {
		t.Fatal("the stream outlived both ends")
	}
	// After the exit the guest's direction is over; an EndOfStream after it is refused
	// locally, as the host would refuse it.
	if err := p.guest.Send(EndOfStream{Chan: ChannelTerminal, Stream: 2}); err == nil {
		t.Fatal("end of stream after exit was sent")
	}
	if p.host.Channel(ChannelTerminal).SendCredit != 8 {
		t.Fatalf("host credit %d", p.host.Channel(ChannelTerminal).SendCredit)
	}
}

func TestAHostOverrunningTheGuestsWindowClosesTheChannel(t *testing.T) {
	p := newPair()
	p.handshake()
	_ = p.host.Send(OpenTerminal{Stream: 2, Columns: 80, Rows: 24})
	p.pump()
	_ = p.guest.Send(Opened{Chan: ChannelTerminal, Stream: 2})
	p.pump()
	_ = p.guest.Grant(ChannelTerminal, 4)
	p.pump()
	// An authentic frame the host's own accounting would not let out: 5 bytes on 4 credit.
	frame, _ := p.host.Binding().EncodeFrame(SenderHost, p.nonce, p.guest.LastReceivedSequence()+1, Data{Chan: ChannelTerminal, Stream: 2, Bytes: []byte("12345")})
	events := p.guest.Receive(frame)
	codes := refusalCodes(events)
	if len(codes) != 1 || codes[0] != ReasonWindowExceeded || !p.guest.Channel(ChannelTerminal).Closed || p.guest.IsClosed() {
		t.Fatalf("%v", events)
	}
	if err := p.guest.Grant(ChannelTerminal, 1); err == nil {
		t.Fatal("credit granted on a closed channel")
	}
}

func TestTheGuestRefusesHostStreamMisuse(t *testing.T) {
	p := newPair()
	p.handshake()
	host := p.host.Binding()
	send := func(message Message) []string {
		frame, _ := host.EncodeFrame(SenderHost, p.nonce, p.guest.LastReceivedSequence()+1, message)
		return refusalCodes(p.guest.Receive(frame))
	}
	if codes := send(OpenTerminal{Stream: 3, Columns: 1, Rows: 1}); codes[0] != ReasonStreamParity {
		t.Fatalf("%v", codes)
	}
	if codes := send(OpenTerminal{Stream: 4, Columns: 1, Rows: 1}); len(codes) != 0 {
		t.Fatalf("%v", codes)
	}
	if codes := send(OpenTerminal{Stream: 2, Columns: 1, Rows: 1}); codes[0] != ReasonStreamIDNotIncreasing {
		t.Fatalf("%v", codes)
	}
	if codes := send(Data{Chan: ChannelTerminal, Stream: 4, Bytes: []byte("x")}); codes[0] != ReasonStreamNotOpen {
		t.Fatalf("data before opened: %v", codes)
	}
	if codes := send(Resize{Stream: 4, Columns: 1, Rows: 1}); codes[0] != ReasonStreamNotOpen {
		t.Fatalf("resize before opened: %v", codes)
	}
	if codes := send(Cancel{Chan: ChannelTerminal, Stream: 4, Cause: CancelRequested}); len(codes) != 0 {
		t.Fatalf("%v", codes)
	}
	// Late data of a cancelled stream still needs credit; with none granted it overruns.
	if err := p.guest.Grant(ChannelTerminal, 1); err != nil {
		t.Fatal(err)
	}
	if codes := send(Data{Chan: ChannelTerminal, Stream: 4, Bytes: []byte("x")}); codes[0] != ReasonStreamCancelled {
		t.Fatalf("late data after cancel: %v", codes)
	}
	refusalsBefore := p.guest.Refusals()
	if codes := send(Data{Chan: ChannelTerminal, Stream: 6, Bytes: []byte("x")}); codes[0] != ReasonStreamNotOpen || p.guest.Refusals() != refusalsBefore+1 {
		t.Fatalf("%v", codes)
	}
	for i := 0; i < 70 && !p.guest.IsClosed(); i++ {
		send(Data{Chan: ChannelTerminal, Stream: 6, Bytes: []byte("x")})
	}
	if !p.guest.IsClosed() || p.guest.Cause().Kind != CloseRefusalBudgetExhausted {
		t.Fatalf("the refusal budget did not close the link: %v", p.guest.Cause())
	}
}

func TestStreamQuotaAndOpenTimeoutOnTheGuest(t *testing.T) {
	p := newPair()
	p.handshake()
	for id := uint32(2); id <= 32; id += 2 {
		if err := p.host.Send(OpenTerminal{Stream: id, Columns: 1, Rows: 1}); err != nil {
			t.Fatal(err)
		}
	}
	_, guestEvents := p.pump()
	if len(messagesOf(guestEvents)) != 16 {
		t.Fatalf("%d", len(messagesOf(guestEvents)))
	}
	frame, _ := p.host.Binding().EncodeFrame(SenderHost, p.nonce, p.guest.LastReceivedSequence()+1, OpenTerminal{Stream: 34, Columns: 1, Rows: 1})
	if codes := refusalCodes(p.guest.Receive(frame)); codes[0] != ReasonStreamQuotaExceeded {
		t.Fatalf("%v", codes)
	}
	p.clock.advance(31 * time.Second)
	events := p.guest.Tick()
	if len(events) != 16 {
		t.Fatalf("%d timed out", len(events))
	}
	if timed := events[0].(StreamTimedOutEvent); timed.Stream != 2 || !timed.CancelSent {
		t.Fatalf("%+v", timed)
	}
}

func TestAHostCloseOrDisconnectEndsTheGuestLink(t *testing.T) {
	p := newPair()
	p.handshake()
	if err := p.host.Send(Close{Reason: CloseShutdown}); err != nil {
		t.Fatal(err)
	}
	_, guestEvents := p.pump()
	if !p.guest.IsClosed() || p.guest.Cause().Kind != ClosePeerClosed || p.guest.Cause().Reason != CloseShutdown {
		t.Fatalf("%v", guestEvents)
	}
	q := newPair()
	q.handshake()
	events := q.guest.PeerClosed()
	if len(events) != 1 || q.guest.Cause().Kind != ClosePeerDisconnected {
		t.Fatalf("%v", events)
	}
	r := newPair()
	r.handshake()
	frame, _ := r.host.Binding().EncodeFrame(SenderHost, r.nonce, 3, Ping{Nonce: 9})
	r.guest.Receive(frame[:20])
	if events := r.guest.PeerClosed(); refusalCodes(events)[0] != "framing.truncated" {
		t.Fatalf("%v", events)
	}
}

func TestAGuestThatNeverHearsTheWelcomeTimesOut(t *testing.T) {
	p := newPair()
	p.challenge()
	_ = p.guest.Send(Hello{GuestVersion: ProtocolVersion})
	p.guest.NextOutbound()
	p.clock.advance(10 * time.Second)
	if len(p.guest.Tick()) != 0 {
		t.Fatal("closed at the limit")
	}
	p.clock.advance(time.Millisecond)
	if events := p.guest.Tick(); len(events) != 1 || p.guest.Cause().Kind != CloseHandshakeTimedOut {
		t.Fatalf("%v", events)
	}
}

func TestUrgentFramesGoFirstAndSequencesRiseInWriteOrder(t *testing.T) {
	p := newPair()
	p.handshake()
	_ = p.host.Send(OpenTerminal{Stream: 2, Columns: 1, Rows: 1})
	p.pump()
	_ = p.guest.Send(Opened{Chan: ChannelTerminal, Stream: 2})
	p.pump()
	for i := 0; i < 3; i++ {
		_ = p.guest.Send(Data{Chan: ChannelTerminal, Stream: 2, Bytes: []byte{byte(i)}})
	}
	_ = p.guest.Send(Ping{Nonce: 5})
	_ = p.guest.Send(Close{Reason: CloseShutdown})
	first := p.guest.NextOutbound()
	header, payload, _ := splitFrame(first)
	if header.OperationCode != uint8(OpClose) || !bytes.Equal(payload, []byte{1, 0, 1, 5}) {
		t.Fatalf("the close did not go first: %+v", header)
	}
	if p.guest.NextOutbound() != nil {
		t.Fatal("frames went out after the close")
	}
	events := p.host.Receive(first)
	if codes := refusalCodes(events); len(codes) != 0 || !p.host.IsClosed() {
		t.Fatalf("%v", events)
	}
}

// --- Protocol version 2: the challenge and the connection (M06-LC). ---

func challengeFrame(binding *Binding, header Connection, field []byte, sequence uint64) []byte {
	payload, _ := (&FieldWriter{}).Bytes(1, field).Finish()
	return binding.Seal(SenderHost, Header{Channel: ChannelControl, OperationCode: uint8(OpChallenge), Sequence: sequence, BootGeneration: 3, PayloadBytes: uint32(len(payload)), Connection: header}, payload)
}

func TestTheHostsChallengeIsItsFirstFrameAndIsUrgent(t *testing.T) {
	p := newPair()
	frame := p.host.NextOutbound()
	header, payload, ok := splitFrame(frame)
	if !ok || header.OperationCode != uint8(OpChallenge) || header.Sequence != 1 || header.Connection != testNonce ||
		!bytes.Equal(payload, append([]byte{1, 0, 16}, testNonce[:]...)) || len(frame) != 99 {
		t.Fatalf("%+v %x", header, frame)
	}
	if _, err := NewHostEndpoint(testBinding(3), Connection{}, DefaultLimits(), newClock()); err == nil {
		t.Fatal("an all-zero nonce made a host endpoint")
	}
	if _, err := NewConnection(bytes.Repeat([]byte{9}, 16)); err == nil {
		t.Fatal("a repeated-byte nonce was accepted")
	}
	if _, err := NewConnection(make([]byte, 15)); err == nil {
		t.Fatal("a 15-byte nonce was accepted")
	}
}

func TestTheGuestAcceptsOnlyAValidChallengeFirst(t *testing.T) {
	host := testBinding(3)
	other := Connection([]byte("other-connection"))
	welcome, _ := host.EncodeFrame(SenderHost, testNonce, 1, Welcome{Version: ProtocolVersion, MaxFrameBytes: 65552, IdleTimeoutSeconds: 60})
	revoke, _ := host.EncodeFrame(SenderHost, testNonce, 1, Revoke{Reason: RevokedPolicyChanged, AuthorizationEpoch: 1})
	for _, c := range []struct {
		name  string
		frame []byte
		code  string
	}{
		{"welcome first", welcome, ReasonChallengeMissing},
		{"revoke first", revoke, ReasonChallengeMissing},
		{"field differs from header", challengeFrame(host, testNonce, other[:], 1), ReasonChallengeRefused},
		{"all-zero nonce", challengeFrame(host, Connection{}, make([]byte, 16), 1), ReasonChallengeRefused},
		{"repeated-byte nonce", challengeFrame(host, Connection(bytes.Repeat([]byte{7}, 16)), bytes.Repeat([]byte{7}, 16), 1), ReasonChallengeRefused},
		{"sequence 2", challengeFrame(host, testNonce, testNonce[:], 2), "sequence.reordered"},
		{"short field", challengeFrame(host, testNonce, testNonce[:15], 1), "payload.wrong_length"},
		{"long field", challengeFrame(host, testNonce, append(testNonce[:], 0), 1), "payload.too_long"},
	} {
		p := newPair()
		events := p.guest.Receive(c.frame)
		codes := refusalCodes(events)
		if len(codes) != 1 || codes[0] != c.code || !p.guest.IsClosed() || len(messagesOf(events)) != 0 {
			t.Errorf("%s: %v", c.name, events)
		}
		if p.guest.NextOutbound() != nil {
			t.Errorf("%s: an unchallenged guest sent a frame", c.name)
		}
		if _, bound := p.guest.Connection(); bound {
			t.Errorf("%s: the connection was bound", c.name)
		}
	}
	p := newPair()
	if err := p.guest.Send(Hello{GuestVersion: ProtocolVersion}); err == nil {
		t.Fatal("the guest said hello before the challenge")
	}
	p.challenge()
	if connection, bound := p.guest.Connection(); !bound || connection != testNonce {
		t.Fatal("the challenge did not bind the connection")
	}
	if err := p.guest.Send(Hello{GuestVersion: ProtocolVersion}); err != nil {
		t.Fatal(err)
	}
	header, _, _ := splitFrame(p.guest.NextOutbound())
	if header.Connection != testNonce || header.Sequence != 1 {
		t.Fatalf("the hello is not on the connection: %+v", header)
	}
}

func TestFramesOfAnotherConnectionAreStaleAndASecondChallengeIsRefused(t *testing.T) {
	p := newPair()
	p.handshake()
	again := challengeFrame(p.host.Binding(), testNonce, testNonce[:], p.guest.LastReceivedSequence()+1)
	if codes := refusalCodes(p.guest.Receive(again)); len(codes) != 1 || codes[0] != ReasonHandshakeRepeated || p.guest.IsClosed() {
		t.Fatalf("%v", codes)
	}
	earlier := Connection([]byte("earlier-connect!"))
	ping, _ := p.host.Binding().EncodeFrame(SenderHost, earlier, p.guest.LastReceivedSequence()+1, Ping{Nonce: 1})
	if codes := refusalCodes(p.guest.Receive(ping)); len(codes) != 1 || codes[0] != ReasonStaleConnection || !p.guest.IsClosed() {
		t.Fatalf("%v", codes)
	}
	// The host refuses the guest's frames of another connection the same way.
	q := newPair()
	q.handshake()
	stale, _ := q.guest.Binding().EncodeFrame(SenderGuest, earlier, q.host.LastReceivedSequence()+1, Ping{Nonce: 2})
	if codes := refusalCodes(q.host.Receive(stale)); len(codes) != 1 || codes[0] != ReasonStaleConnection || !q.host.IsClosed() {
		t.Fatalf("%v", codes)
	}
	// A frame moved to this connection by rewriting its field fails the tag.
	r := newPair()
	r.handshake()
	moved, _ := r.guest.Binding().EncodeFrame(SenderGuest, earlier, r.host.LastReceivedSequence()+1, Ping{Nonce: 3})
	copy(moved[32:48], testNonce[:])
	if codes := refusalCodes(r.host.Receive(moved)); len(codes) != 1 || codes[0] != ReasonUnauthenticated {
		t.Fatalf("%v", codes)
	}
}

func TestAChallengeFieldOfAnotherLengthIsRefusedByTheReader(t *testing.T) {
	for length, code := range map[int]string{0: "payload.wrong_length", 15: "payload.wrong_length", 17: "payload.too_long"} {
		payload, _ := (&FieldWriter{}).Bytes(1, bytes.Repeat([]byte{7}, length)).Finish()
		_, err := DecodeMessage(ChannelControl, OpChallenge, 0, payload, 4096)
		if refusal, ok := err.(*PayloadRefusal); !ok || refusal.Code() != code {
			t.Errorf("%d: %v", length, err)
		}
	}
}

// --- Credit across cancellation and the benign crossing cancel (review items 1 and 8). ---

// openTerminal opens host stream id on the pair and has the guest accept it.
func (p *pair) openTerminal(t *testing.T, id uint32) {
	t.Helper()
	if err := p.host.Send(OpenTerminal{Stream: id, Columns: 80, Rows: 24}); err != nil {
		t.Fatal(err)
	}
	p.pump()
	if err := p.guest.Send(Opened{Chan: ChannelTerminal, Stream: id}); err != nil {
		t.Fatal(err)
	}
	p.pump()
}

// deliverHost moves the host's queued frames to the guest only.
func (p *pair) deliverHost() []Event {
	var events []Event
	for frame := p.host.NextOutbound(); frame != nil; frame = p.host.NextOutbound() {
		events = append(events, p.guest.Receive(frame)...)
	}
	return events
}

func TestACancelReturnsTheCreditOfQueuedData(t *testing.T) {
	p := newPair()
	p.handshake()
	p.openTerminal(t, 2)
	window := p.guest.Channel(ChannelTerminal).SendCredit
	for i := 0; i < 3; i++ {
		if err := p.guest.Send(Data{Chan: ChannelTerminal, Stream: 2, Bytes: make([]byte, 1000)}); err != nil {
			t.Fatal(err)
		}
	}
	if got := p.guest.Channel(ChannelTerminal).SendCredit; got != window-3000 {
		t.Fatalf("credit %d", got)
	}
	if err := p.host.Send(Cancel{Chan: ChannelTerminal, Stream: 2, Cause: CancelRequested}); err != nil {
		t.Fatal(err)
	}
	if codes := refusalCodes(p.deliverHost()); len(codes) != 0 {
		t.Fatal(codes)
	}
	if got := p.guest.Channel(ChannelTerminal); got.SendCredit != window || got.QueuedFrames != 0 {
		t.Fatalf("the dropped data kept its credit: %+v", got)
	}
}

func TestDataInFlightAcrossACancelIsCreditedBackOnBothEnds(t *testing.T) {
	// Guest data crossing the host's cancel: the host refunds it.
	p := newPair()
	p.handshake()
	p.openTerminal(t, 2)
	window := p.guest.Channel(ChannelTerminal).SendCredit
	_ = p.guest.Send(Data{Chan: ChannelTerminal, Stream: 2, Bytes: make([]byte, 5000)})
	inFlight := p.guest.NextOutbound()
	_ = p.host.Send(Cancel{Chan: ChannelTerminal, Stream: 2, Cause: CancelRequested})
	refusalsBefore := p.host.Refusals()
	events := p.host.Receive(inFlight)
	if codes := refusalCodes(events); len(codes) != 1 || codes[0] != ReasonStreamCancelled || p.host.Refusals() != refusalsBefore {
		t.Fatalf("%v", events)
	}
	if got := p.host.Channel(ChannelTerminal); got.Buffered != 0 || got.ReceiveWindow != window {
		t.Fatalf("host %+v", got)
	}
	p.pump()
	if got := p.guest.Channel(ChannelTerminal).SendCredit; got != window {
		t.Fatalf("guest credit %d of %d", got, window)
	}

	// Host data crossing the guest's cancel: the guest refunds it.
	q := newPair()
	q.handshake()
	q.openTerminal(t, 2)
	_ = q.guest.Grant(ChannelTerminal, 10_000)
	q.pump()
	_ = q.host.Send(Data{Chan: ChannelTerminal, Stream: 2, Bytes: make([]byte, 4000)})
	hostData := q.host.NextOutbound()
	if err := q.guest.Send(Cancel{Chan: ChannelTerminal, Stream: 2, Cause: CancelRevoked}); err != nil {
		t.Fatal(err)
	}
	if codes := refusalCodes(q.guest.Receive(hostData)); len(codes) != 1 || codes[0] != ReasonStreamCancelled {
		t.Fatal(codes)
	}
	q.pump()
	if got := q.host.Channel(ChannelTerminal).SendCredit; got != 10_000 {
		t.Fatalf("host credit %d", got)
	}
	if got := q.guest.Channel(ChannelTerminal); got.ReceiveWindow != 10_000 || got.Buffered != 0 {
		t.Fatalf("guest %+v", got)
	}
}

// TestManyOutputLimitedCommandsInARowKeepTheirCredit runs 200 streams whose output the
// host cuts off with a cancel while some of it is queued and some in flight; the guest's
// credit must come back whole every time.
func TestManyOutputLimitedCommandsInARowKeepTheirCredit(t *testing.T) {
	p := newPair()
	p.handshake()
	window := p.guest.Channel(ChannelTerminal).SendCredit
	chunk := p.guest.MaxDataBytes(ChannelTerminal)
	for round := uint32(0); round < 200; round++ {
		id := 2 + 2*round
		p.openTerminal(t, id)
		for i := 0; i < 4; i++ {
			if err := p.guest.Send(Data{Chan: ChannelTerminal, Stream: id, Bytes: make([]byte, chunk)}); err != nil {
				t.Fatalf("round %d: %v", round, err)
			}
		}
		// The host accepts the first chunk and consumes it, the second is in flight when
		// it cancels, the rest is still queued on the guest.
		first := p.guest.NextOutbound()
		second := p.guest.NextOutbound()
		if codes := refusalCodes(p.host.Receive(first)); len(codes) != 0 {
			t.Fatalf("round %d: %v", round, codes)
		}
		if err := p.host.Consume(ChannelTerminal, uint32(chunk)); err != nil {
			t.Fatal(err)
		}
		if err := p.host.Send(Cancel{Chan: ChannelTerminal, Stream: id, Cause: CancelQuotaExceeded}); err != nil {
			t.Fatal(err)
		}
		if codes := refusalCodes(p.host.Receive(second)); len(codes) != 1 || codes[0] != ReasonStreamCancelled {
			t.Fatalf("round %d: %v", round, codes)
		}
		// The cancel reaches the guest before its queued chunks leave: they are dropped
		// there and their credit returned; the host's refund arrives with it.
		if codes := refusalCodes(p.deliverHost()); len(codes) != 0 {
			t.Fatalf("round %d: %v", round, codes)
		}
		hostEvents, guestEvents := p.pump()
		if codes := append(refusalCodes(hostEvents), refusalCodes(guestEvents)...); len(codes) != 0 {
			t.Fatalf("round %d: %v", round, codes)
		}
		guest, host := p.guest.Channel(ChannelTerminal), p.host.Channel(ChannelTerminal)
		if guest.SendCredit != window || host.ReceiveWindow != window || host.Buffered != 0 {
			t.Fatalf("round %d: credit leaked: guest %+v host %+v", round, guest, host)
		}
	}
	if p.host.Refusals() != 0 || p.guest.Refusals() != 0 {
		t.Fatalf("budget charged: host %d guest %d", p.host.Refusals(), p.guest.Refusals())
	}
}

func TestCancelledStreamDataStillRespectsTheWindow(t *testing.T) {
	p := newPair()
	p.handshake()
	p.openTerminal(t, 2)
	_ = p.guest.Grant(ChannelTerminal, 100)
	p.pump()
	_ = p.guest.Send(Cancel{Chan: ChannelTerminal, Stream: 2, Cause: CancelRequested})
	p.pump()
	frame, _ := p.host.Binding().EncodeFrame(SenderHost, p.nonce, p.guest.LastReceivedSequence()+1, Data{Chan: ChannelTerminal, Stream: 2, Bytes: make([]byte, 101)})
	if codes := refusalCodes(p.guest.Receive(frame)); len(codes) != 1 || codes[0] != ReasonWindowExceeded || !p.guest.Channel(ChannelTerminal).Closed {
		t.Fatalf("%v", codes)
	}
}

func TestWindowUpdatesMergeAheadOfData(t *testing.T) {
	p := newPair()
	p.handshake()
	for _, credit := range []uint32{100, 200, 300} {
		if err := p.guest.Grant(ChannelTerminal, credit); err != nil {
			t.Fatal(err)
		}
	}
	if queued := p.guest.Channel(ChannelTerminal).QueuedFrames; queued != 1 {
		t.Fatalf("%d window updates queued", queued)
	}
	hostEvents, _ := p.pump()
	updates := 0
	for _, m := range messagesOf(hostEvents) {
		if update, ok := m.(WindowUpdate); ok {
			updates++
			if update.CreditBytes != 600 {
				t.Fatalf("%+v", update)
			}
		}
	}
	if updates != 1 || p.host.Channel(ChannelTerminal).SendCredit != 600 {
		t.Fatalf("%d updates, credit %d", updates, p.host.Channel(ChannelTerminal).SendCredit)
	}
}

func TestACancelCrossingTheGuestsExitIsBenign(t *testing.T) {
	p := newPair()
	p.handshake()
	p.openTerminal(t, 2)
	_ = p.host.Send(EndOfStream{Chan: ChannelTerminal, Stream: 2})
	p.deliverHost()
	if err := p.guest.Send(Exit{Stream: 2, Code: 0}); err != nil {
		t.Fatal(err)
	}
	exit := p.guest.NextOutbound()
	if _, ok := p.guest.Stream(ChannelTerminal, 2); ok {
		t.Fatal("the finished stream is still held")
	}
	// The host cancels before it sees the exit; the cancel crosses it.
	if err := p.host.Send(Cancel{Chan: ChannelTerminal, Stream: 2, Cause: CancelQuotaExceeded}); err != nil {
		t.Fatal(err)
	}
	events := p.deliverHost()
	if len(events) != 0 || p.guest.Refusals() != 0 || p.guest.IsClosed() {
		t.Fatalf("the crossing cancel was refused: %v", events)
	}
	// On the host the exit is a late frame of a cancelled stream: unbudgeted.
	if codes := refusalCodes(p.host.Receive(exit)); len(codes) != 1 || codes[0] != ReasonStreamCancelled || p.host.Refusals() != 0 {
		t.Fatalf("%v", codes)
	}
	// A cancel for a stream that never existed still costs the budget.
	frame, _ := p.host.Binding().EncodeFrame(SenderHost, p.nonce, p.guest.LastReceivedSequence()+1, Cancel{Chan: ChannelTerminal, Stream: 40, Cause: CancelRequested})
	if codes := refusalCodes(p.guest.Receive(frame)); len(codes) != 1 || codes[0] != ReasonStreamNotOpen || p.guest.Refusals() != 1 {
		t.Fatalf("%v", codes)
	}
}

// TestTheSharedBootstrapVector pins the 77-byte bootstrap file v1 for the corpus's test
// instance (secret_hex, vm_hex and boot_generation 7 of corpus.json), in
// testdata/bootstrap-v1.hex for the Rust launcher's writer to share.
func TestTheSharedBootstrapVector(t *testing.T) {
	const (
		secretHex = "05121f2c394653606d7a8794a1aebbc8d5e2effc091623303d4a5764717e8b98"
		vmHex     = "7128e9939fe4488875e7ae9dd1393ce59240fc57d463f3145b2504ab8c7489ea"
		boot      = uint64(7)
	)
	raw, err := os.ReadFile(filepath.Join("testdata", "bootstrap-v1.hex"))
	if err != nil {
		t.Fatal(err)
	}
	file, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(file) != BootstrapFileBytes {
		t.Fatalf("%d bytes, %v", len(file), err)
	}
	secret, _ := hex.DecodeString(secretHex)
	vm, _ := DigestFromHex(vmHex)
	encoded, err := EncodeBootstrap(secret, vm, boot)
	if err != nil || !bytes.Equal(encoded, file) {
		t.Fatalf("encoder disagrees with the vector: %x %v", encoded, err)
	}
	parsed, err := ParseBootstrap(append([]byte(nil), file...))
	if err != nil || parsed.VM != vm || parsed.BootGeneration != boot || parsed.Secret.bytes != [32]byte(secret) {
		t.Fatalf("%v", err)
	}
	if !strings.HasPrefix(hex.EncodeToString(file), "59474c4201") || !strings.HasSuffix(hex.EncodeToString(file), "0000000000000007") {
		t.Fatal("layout")
	}
}
