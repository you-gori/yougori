package link

// Host-authoritative identity (host: src-tauri/src/sandbox/link/secret.rs): the bootstrap
// secret of one VM instance, the per-direction keys derived from it, and the binding of a
// link to the VM instance and boot generation the host launched. The secret and the keys
// print as "not shown" under every fmt verb and have no exported field, so no log, record
// or error message can carry them.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

const (
	// BootstrapSecretBytes is the exact length of a bootstrap secret.
	BootstrapSecretBytes = 32
	// KeyDomain is the domain under which link keys are derived.
	KeyDomain = "yougori/link/key/v1"
)

// Digest is a 32-byte digest as the host's ids.rs carries it.
type Digest [32]byte

// Hex is the lowercase hexadecimal form.
func (d Digest) Hex() string { return hex.EncodeToString(d[:]) }

// DigestFromHex parses 64 hexadecimal digits.
func DigestFromHex(text string) (Digest, error) {
	var d Digest
	raw, err := hex.DecodeString(text)
	if err != nil || len(raw) != len(d) {
		return d, fmt.Errorf("not a 32-byte hexadecimal digest")
	}
	copy(d[:], raw)
	return d, nil
}

// SecretRefusal is why bootstrap material was refused.
type SecretRefusal struct {
	// FoundBytes is set when the length is wrong; zero with Degenerate.
	FoundBytes int
	Degenerate bool
}

func (r *SecretRefusal) Error() string {
	if r.Degenerate {
		return "bootstrap material is one repeated byte"
	}
	return fmt.Sprintf("bootstrap material is %d bytes, not %d", r.FoundBytes, BootstrapSecretBytes)
}

// BootstrapSecret is the per-instance secret the host delivered at launch. It only derives
// keys; Wipe clears it.
type BootstrapSecret struct {
	bytes [BootstrapSecretBytes]byte
}

// NewBootstrapSecret takes a copy of material; it refuses any length but
// BootstrapSecretBytes and material made of one repeated byte.
func NewBootstrapSecret(material []byte) (*BootstrapSecret, error) {
	if len(material) != BootstrapSecretBytes {
		return nil, &SecretRefusal{FoundBytes: len(material)}
	}
	degenerate := true
	for _, b := range material {
		if b != material[0] {
			degenerate = false
			break
		}
	}
	if degenerate {
		return nil, &SecretRefusal{Degenerate: true}
	}
	secret := &BootstrapSecret{}
	copy(secret.bytes[:], material)
	return secret, nil
}

// Wipe overwrites the secret.
func (s *BootstrapSecret) Wipe() {
	for i := range s.bytes {
		s.bytes[i] = 0
	}
}

func (s *BootstrapSecret) String() string   { return "BootstrapSecret(not shown)" }
func (s *BootstrapSecret) GoString() string { return s.String() }

// Format prints "not shown" under every verb.
func (s *BootstrapSecret) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(s.String())) }

// MarshalText refuses, so no encoder can serialize the secret.
func (s *BootstrapSecret) MarshalText() ([]byte, error) {
	return nil, fmt.Errorf("a bootstrap secret is never serialized")
}

// derive is BootstrapSecret::derive: HMAC-SHA256 keyed by the secret over the domain,
// the direction label, the VM digest and the boot generation, each with a big-endian u64
// length prefix.
func (s *BootstrapSecret) derive(direction Sender, vm Digest, boot uint64) *linkKey {
	label := []byte("host-to-guest")
	if direction == SenderGuest {
		label = []byte("guest-to-host")
	}
	var bootBytes [8]byte
	binary.BigEndian.PutUint64(bootBytes[:], boot)
	message := make([]byte, 0, 96)
	for _, part := range [][]byte{[]byte(KeyDomain), label, vm[:], bootBytes[:]} {
		message = binary.BigEndian.AppendUint64(message, uint64(len(part)))
		message = append(message, part...)
	}
	mac := hmac.New(sha256.New, s.bytes[:])
	mac.Write(message)
	key := &linkKey{}
	copy(key.bytes[:], mac.Sum(nil))
	return key
}

// linkKey is one direction's key; same discipline as the secret.
type linkKey struct {
	bytes [32]byte
}

func (k *linkKey) tag(header, payload []byte) [TagBytes]byte {
	mac := hmac.New(sha256.New, k.bytes[:])
	mac.Write(header)
	mac.Write(payload)
	var tag [TagBytes]byte
	copy(tag[:], mac.Sum(nil))
	return tag
}

func (k *linkKey) String() string             { return "Key(not shown)" }
func (k *linkKey) GoString() string           { return k.String() }
func (k *linkKey) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(k.String())) }

// Binding is one link's binding: the VM instance digest and boot generation the host
// launched and the keys derived from that instance's bootstrap secret.
type Binding struct {
	vm          Digest
	boot        uint64
	guestToHost *linkKey
	hostToGuest *linkKey
}

// NewBinding binds secret to the instance vm at boot; the secret is wiped afterwards and
// only the derived keys are kept.
func NewBinding(vm Digest, boot uint64, secret *BootstrapSecret) *Binding {
	binding := &Binding{
		vm:          vm,
		boot:        boot,
		guestToHost: secret.derive(SenderGuest, vm, boot),
		hostToGuest: secret.derive(SenderHost, vm, boot),
	}
	secret.Wipe()
	return binding
}

// VM is the bound VM instance digest.
func (b *Binding) VM() Digest { return b.vm }

// Boot is the bound boot generation.
func (b *Binding) Boot() uint64 { return b.boot }

// Tag is the tag a frame from sender with these header bytes and payload must carry.
func (b *Binding) Tag(sender Sender, header, payload []byte) [TagBytes]byte {
	if sender == SenderGuest {
		return b.guestToHost.tag(header, payload)
	}
	return b.hostToGuest.tag(header, payload)
}

// Verify reports, in constant time, whether tag authenticates a frame from sender.
func (b *Binding) Verify(sender Sender, header, payload []byte, tag [TagBytes]byte) bool {
	expected := b.Tag(sender, header, payload)
	return hmac.Equal(expected[:], tag[:])
}

func (b *Binding) String() string {
	return fmt.Sprintf("Binding{vm: %s, boot: %d, keys: not shown}", b.vm.Hex(), b.boot)
}
func (b *Binding) GoString() string           { return b.String() }
func (b *Binding) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(b.String())) }

// Seal writes a whole frame: header bytes, payload and sender's tag over both.
func (b *Binding) Seal(sender Sender, header Header, payload []byte) []byte {
	head := header.Encode()
	tag := b.Tag(sender, head[:], payload)
	frame := make([]byte, 0, len(head)+len(payload)+len(tag))
	frame = append(frame, head[:]...)
	frame = append(frame, payload...)
	return append(frame, tag[:]...)
}

// EncodeFrame encodes message from sender with sequence, bound to the binding's boot
// generation and to connection, as link::encode_frame_on does.
func (b *Binding) EncodeFrame(sender Sender, connection Connection, sequence uint64, message Message) ([]byte, error) {
	payload, err := EncodePayload(message)
	if err != nil {
		return nil, err
	}
	header := Header{
		Channel:        message.Channel(),
		OperationCode:  uint8(message.Operation()),
		Stream:         message.StreamID(),
		Sequence:       sequence,
		BootGeneration: b.boot,
		PayloadBytes:   uint32(len(payload)),
		Connection:     connection,
	}
	return b.Seal(sender, header, payload), nil
}
