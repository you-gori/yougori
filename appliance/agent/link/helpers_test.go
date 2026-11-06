package link

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"
)

// manualClock is a clock the test moves by hand.
type manualClock struct{ now time.Time }

func (c *manualClock) Now() time.Time { return c.now }

func (c *manualClock) advance(d time.Duration) { c.now = c.now.Add(d) }

func newClock() *manualClock { return &manualClock{now: time.Unix(1_000_000, 0)} }

// testDigest is ids.rs digest(domain, parts): SHA-256 over each input with a big-endian
// u64 length prefix.
func testDigest(domain string, parts ...[]byte) Digest {
	h := sha256.New()
	write := func(part []byte) {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(part)))
		h.Write(length[:])
		h.Write(part)
	}
	write([]byte(domain))
	for _, part := range parts {
		write(part)
	}
	var d Digest
	copy(d[:], h.Sum(nil))
	return d
}

// secretMaterial is the material of secret.rs's tests: index * 7 + 1.
func secretMaterial() []byte {
	material := make([]byte, BootstrapSecretBytes)
	for i := range material {
		material[i] = byte(i*7 + 1)
	}
	return material
}

func testVM() Digest { return testDigest("yougori/test/vm/v1", []byte("vm-a")) }

func testBinding(boot uint64) *Binding {
	secret, err := NewBootstrapSecret(secretMaterial())
	if err != nil {
		panic(err)
	}
	return NewBinding(testVM(), boot, secret)
}

// testNonce is the connection of the test pairs.
var testNonce = Connection([]byte("connection-nonce"))

// pair is a host and a guest endpoint over the same binding, on connection testNonce.
type pair struct {
	clock *manualClock
	host  *Endpoint
	guest *Endpoint
	nonce Connection
}

func newPair() *pair {
	clock := newClock()
	host, err := NewHostEndpoint(testBinding(3), testNonce, DefaultLimits(), clock)
	if err != nil {
		panic(err)
	}
	guest, err := NewGuestEndpoint(testBinding(3), DefaultLimits(), clock)
	if err != nil {
		panic(err)
	}
	return &pair{clock: clock, host: host, guest: guest, nonce: testNonce}
}

// challenge delivers the host's challenge, its first frame, to the guest.
func (p *pair) challenge() {
	frame := p.host.NextOutbound()
	events := p.guest.Receive(frame)
	if p.guest.Phase() != PhaseHandshake || len(refusalCodes(events)) != 0 {
		panic(fmt.Sprintf("the challenge was not accepted: %v", events))
	}
}

// pump moves every queued frame from one end to the other and returns the events each
// side produced, until both are quiet.
func (p *pair) pump() (hostEvents, guestEvents []Event) {
	for {
		moved := false
		for frame := p.guest.NextOutbound(); frame != nil; frame = p.guest.NextOutbound() {
			hostEvents = append(hostEvents, p.host.Receive(frame)...)
			moved = true
		}
		for frame := p.host.NextOutbound(); frame != nil; frame = p.host.NextOutbound() {
			guestEvents = append(guestEvents, p.guest.Receive(frame)...)
			moved = true
		}
		if !moved {
			return hostEvents, guestEvents
		}
	}
}

func (p *pair) handshake() {
	p.challenge()
	agent := testDigest("yougori/test/build/v1", []byte("agent"))
	vm := testVM()
	boot := uint64(3)
	if err := p.guest.Send(Hello{GuestVersion: ProtocolVersion, AgentBuild: agent, ClaimedVM: &vm, ClaimedBoot: &boot}); err != nil {
		panic(err)
	}
	p.pump()
	if p.host.Phase() != PhaseOpen || p.guest.Phase() != PhaseOpen {
		panic("handshake did not complete")
	}
}

func refusalCodes(events []Event) []string {
	var codes []string
	for _, event := range events {
		if refused, ok := event.(RefusedEvent); ok {
			codes = append(codes, refused.Refusal.Reason.Code)
		}
	}
	return codes
}

func messagesOf(events []Event) []Message {
	var messages []Message
	for _, event := range events {
		if m, ok := event.(MessageEvent); ok {
			messages = append(messages, m.Message)
		}
	}
	return messages
}
