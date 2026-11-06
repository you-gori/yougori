package link

// The bootstrap file v1 (decided by Manager 2; the host launcher writes it and QEMU hands
// it to the guest through fw_cfg as opt/yougori/link-secret, §3.2 line 2075). Exactly 77
// bytes: ASCII "YGLB", version byte 1, the 32-byte secret, the 32-byte VM instance digest
// (VmInstanceId::digest()) and the boot generation as a big-endian u64. Any other length,
// magic or version, or a secret of one repeated byte, is refused. The secret is copied
// into a BootstrapSecret and the bytes read are overwritten, so it is held only there.

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

const (
	// BootstrapPath is where the guest kernel's qemu_fw_cfg driver exposes the file.
	BootstrapPath = "/sys/firmware/qemu_fw_cfg/by_name/opt/yougori/link-secret/raw"
	// BootstrapFileBytes is the exact length of a version 1 file.
	BootstrapFileBytes = 4 + 1 + BootstrapSecretBytes + 32 + 8
	// BootstrapVersion is the only file version this side reads.
	BootstrapVersion uint8 = 1
)

// BootstrapMagic is the first four bytes of the file.
var BootstrapMagic = [4]byte{'Y', 'G', 'L', 'B'}

// BootstrapKind names a bootstrap refusal.
type BootstrapKind uint8

const (
	BootstrapUnavailable BootstrapKind = iota + 1
	BootstrapWrongLength
	BootstrapBadMagic
	BootstrapUnsupportedVersion
	BootstrapDegenerateSecret
)

// BootstrapRefusal is why the bootstrap file was refused. It never carries file bytes.
type BootstrapRefusal struct {
	Kind       BootstrapKind
	FoundBytes int
	Found      uint8
}

func (r *BootstrapRefusal) Error() string {
	switch r.Kind {
	case BootstrapUnavailable:
		return "the link bootstrap file is unavailable"
	case BootstrapWrongLength:
		return fmt.Sprintf("the link bootstrap file is %d bytes or more, not %d", r.FoundBytes, BootstrapFileBytes)
	case BootstrapBadMagic:
		return "the link bootstrap file does not start with YGLB"
	case BootstrapUnsupportedVersion:
		return fmt.Sprintf("link bootstrap file version %d is not %d", r.Found, BootstrapVersion)
	}
	return "the link bootstrap secret is one repeated byte"
}

// Bootstrap is the parsed file: the secret and the binding it is for.
type Bootstrap struct {
	Secret         *BootstrapSecret
	VM             Digest
	BootGeneration uint64
}

// Binding derives the link keys and wipes the secret.
func (b *Bootstrap) Binding() *Binding {
	return NewBinding(b.VM, b.BootGeneration, b.Secret)
}

// EncodeBootstrap writes a version 1 file; the host launcher's format, used by tests and
// the host-side test client.
func EncodeBootstrap(secret []byte, vm Digest, boot uint64) ([]byte, error) {
	if _, err := NewBootstrapSecret(secret); err != nil {
		return nil, err
	}
	file := make([]byte, 0, BootstrapFileBytes)
	file = append(file, BootstrapMagic[:]...)
	file = append(file, BootstrapVersion)
	file = append(file, secret...)
	file = append(file, vm[:]...)
	return binary.BigEndian.AppendUint64(file, boot), nil
}

// ParseBootstrap parses a version 1 file and overwrites raw's secret bytes, whatever the
// outcome.
func ParseBootstrap(raw []byte) (*Bootstrap, error) {
	defer wipe(raw)
	if len(raw) != BootstrapFileBytes {
		return nil, &BootstrapRefusal{Kind: BootstrapWrongLength, FoundBytes: len(raw)}
	}
	if [4]byte(raw[0:4]) != BootstrapMagic {
		return nil, &BootstrapRefusal{Kind: BootstrapBadMagic}
	}
	if raw[4] != BootstrapVersion {
		return nil, &BootstrapRefusal{Kind: BootstrapUnsupportedVersion, Found: raw[4]}
	}
	secret, err := NewBootstrapSecret(raw[5 : 5+BootstrapSecretBytes])
	if err != nil {
		return nil, &BootstrapRefusal{Kind: BootstrapDegenerateSecret}
	}
	var vm Digest
	copy(vm[:], raw[5+BootstrapSecretBytes:5+BootstrapSecretBytes+32])
	boot := binary.BigEndian.Uint64(raw[BootstrapFileBytes-8:])
	return &Bootstrap{Secret: secret, VM: vm, BootGeneration: boot}, nil
}

// ReadBootstrap reads and parses the file at path, reading at most one byte more than a
// valid file so an oversized one is refused without being held.
func ReadBootstrap(path string) (*Bootstrap, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, &BootstrapRefusal{Kind: BootstrapUnavailable}
	}
	defer file.Close()
	var buffer [BootstrapFileBytes + 1]byte
	n, err := io.ReadFull(file, buffer[:])
	defer wipe(buffer[:])
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, &BootstrapRefusal{Kind: BootstrapUnavailable}
	}
	return ParseBootstrap(buffer[:n])
}

func wipe(bytes []byte) {
	for i := range bytes {
		bytes[i] = 0
	}
}
