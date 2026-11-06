package link

// Payload fields (host: src-tauri/src/sandbox/link/fields.rs): a flat tag-length-value
// list read by one linear pass with no recursion and no nesting. Each field is a one-byte
// tag in 1–16, a two-byte big-endian length and that many value bytes. Every operation
// names its closed schema; a tag outside it, a repeated tag, a missing required tag, a
// value of the wrong length or over its bound is refused with its typed reason.

import (
	"encoding/binary"
	"fmt"
	"unicode"
	"unicode/utf8"
)

const (
	// MaxFieldTag is the highest field tag; tags are 1 to this value.
	MaxFieldTag = 16
	// FieldOverheadBytes is the tag and length bytes of one field.
	FieldOverheadBytes = 3
	// MaxTextBytes is the longest text field.
	MaxTextBytes = 256
	// MaxFieldValueBytes is the longest value one field can carry.
	MaxFieldValueBytes = 0xffff
	// maxIdentifierBytes is the shared ids.rs identifier bound.
	maxIdentifierBytes = 128
)

// FieldKind names a field refusal.
type FieldKind uint8

const (
	FieldTruncatedHeader FieldKind = iota + 1
	FieldTruncatedValue
	FieldUnknown
	FieldDuplicate
	FieldMissing
	FieldWrongLength
	FieldTooLong
	FieldNotText
	FieldNotName
	FieldInvalidValue
)

// FieldRefusal is why the field reader refused a payload.
type FieldRefusal struct {
	Kind           FieldKind
	Tag            uint8
	AtByte         int
	DeclaredBytes  int
	RemainingBytes int
	ExpectedBytes  int
	FoundBytes     int
	MaxBytes       int
	Value          uint64
	Detail         string
}

// Code is the stable name used by the conformance corpus.
func (r *FieldRefusal) Code() string {
	switch r.Kind {
	case FieldTruncatedHeader:
		return "payload.truncated_header"
	case FieldTruncatedValue:
		return "payload.truncated_value"
	case FieldUnknown:
		return "payload.unknown_field"
	case FieldDuplicate:
		return "payload.duplicate_field"
	case FieldMissing:
		return "payload.missing_field"
	case FieldWrongLength:
		return "payload.wrong_length"
	case FieldTooLong:
		return "payload.too_long"
	case FieldNotText:
		return "payload.not_text"
	case FieldNotName:
		return "payload.not_name"
	case FieldInvalidValue:
		return "payload.invalid_value"
	}
	return "payload.unknown"
}

func (r *FieldRefusal) Error() string {
	switch r.Kind {
	case FieldTruncatedHeader:
		return fmt.Sprintf("the payload ends inside a field header at byte %d", r.AtByte)
	case FieldTruncatedValue:
		return fmt.Sprintf("field %d declares %d bytes but %d remain", r.Tag, r.DeclaredBytes, r.RemainingBytes)
	case FieldUnknown:
		return fmt.Sprintf("field %d is not part of the operation", r.Tag)
	case FieldDuplicate:
		return fmt.Sprintf("field %d appears twice", r.Tag)
	case FieldMissing:
		return fmt.Sprintf("required field %d is missing", r.Tag)
	case FieldWrongLength:
		return fmt.Sprintf("field %d is %d bytes, expected %d", r.Tag, r.FoundBytes, r.ExpectedBytes)
	case FieldTooLong:
		return fmt.Sprintf("field %d is %d bytes, more than %d", r.Tag, r.FoundBytes, r.MaxBytes)
	case FieldNotText:
		return fmt.Sprintf("field %d is not plain text", r.Tag)
	case FieldNotName:
		return fmt.Sprintf("field %d is not a name: %s", r.Tag, r.Detail)
	case FieldInvalidValue:
		return fmt.Sprintf("field %d holds %d, outside its enumeration", r.Tag, r.Value)
	}
	return "field refused"
}

// EncodeRefusal is why a payload could not be encoded.
type EncodeRefusal struct {
	Tag        uint8
	FoundBytes int
	MaxBytes   int
}

func (r *EncodeRefusal) Error() string {
	return fmt.Sprintf("field %d is %d bytes, more than the %d a field holds", r.Tag, r.FoundBytes, r.MaxBytes)
}

// ValidateLinkName checks a name carried on the link: the shared ids.rs identifier grammar
// (1–128 letters, digits, '.', '_', ':' or '-', starting with a letter or digit) narrowed
// to names that start with a letter and contain no ':', so it can never be a path, a URL,
// an address literal, a host:port or free text.
func ValidateLinkName(value string) error {
	if value == "" {
		return fmt.Errorf("the identifier is empty")
	}
	if len(value) > maxIdentifierBytes {
		return fmt.Errorf("the identifier is longer than %d bytes", maxIdentifierBytes)
	}
	for _, r := range value {
		alnum := r < utf8.RuneSelf && (('a' <= r && r <= 'z') || ('A' <= r && r <= 'Z') || ('0' <= r && r <= '9'))
		if !(alnum || r == '.' || r == '_' || r == ':' || r == '-') {
			return fmt.Errorf("the identifier contains %q", r)
		}
	}
	first := value[0]
	if !(('a' <= first && first <= 'z') || ('A' <= first && first <= 'Z') || ('0' <= first && first <= '9')) {
		return fmt.Errorf("the identifier must start with a letter or digit")
	}
	for _, r := range value {
		if r == ':' {
			return fmt.Errorf("the identifier contains %q", r)
		}
	}
	if !(('a' <= first && first <= 'z') || ('A' <= first && first <= 'Z')) {
		return fmt.Errorf("the identifier must start with a letter")
	}
	return nil
}

// FieldSpec is one entry of an operation's field schema.
type FieldSpec struct {
	Tag      uint8
	Required bool
}

// FieldWriter writes a payload field by field. The first value too long for a field is
// remembered and returned by Finish.
type FieldWriter struct {
	bytes []byte
	err   error
}

func (w *FieldWriter) push(tag uint8, value []byte) {
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(value)))
	w.bytes = append(w.bytes, tag)
	w.bytes = append(w.bytes, length[:]...)
	w.bytes = append(w.bytes, value...)
}

// U8 writes a one-byte field.
func (w *FieldWriter) U8(tag uint8, value uint8) *FieldWriter {
	w.push(tag, []byte{value})
	return w
}

// U16 writes a two-byte big-endian field.
func (w *FieldWriter) U16(tag uint8, value uint16) *FieldWriter {
	w.push(tag, binary.BigEndian.AppendUint16(nil, value))
	return w
}

// U32 writes a four-byte big-endian field.
func (w *FieldWriter) U32(tag uint8, value uint32) *FieldWriter {
	w.push(tag, binary.BigEndian.AppendUint32(nil, value))
	return w
}

// U64 writes an eight-byte big-endian field.
func (w *FieldWriter) U64(tag uint8, value uint64) *FieldWriter {
	w.push(tag, binary.BigEndian.AppendUint64(nil, value))
	return w
}

// I32 writes a four-byte big-endian two's-complement field.
func (w *FieldWriter) I32(tag uint8, value int32) *FieldWriter {
	w.push(tag, binary.BigEndian.AppendUint32(nil, uint32(value)))
	return w
}

// Digest writes a 32-byte digest field.
func (w *FieldWriter) Digest(tag uint8, value Digest) *FieldWriter {
	w.push(tag, value[:])
	return w
}

// Bytes writes a variable-length field; a value above MaxFieldValueBytes is refused.
func (w *FieldWriter) Bytes(tag uint8, value []byte) *FieldWriter {
	if len(value) > MaxFieldValueBytes {
		if w.err == nil {
			w.err = &EncodeRefusal{Tag: tag, FoundBytes: len(value), MaxBytes: MaxFieldValueBytes}
		}
		return w
	}
	w.push(tag, value)
	return w
}

// Text writes a text field.
func (w *FieldWriter) Text(tag uint8, value string) *FieldWriter {
	return w.Bytes(tag, []byte(value))
}

// Finish returns the payload, or the first encode refusal.
func (w *FieldWriter) Finish() ([]byte, error) {
	if w.err != nil {
		return nil, w.err
	}
	if w.bytes == nil {
		return []byte{}, nil
	}
	return w.bytes, nil
}

// Fields are the fields of one payload read against a schema; at most one slice per tag.
type Fields struct {
	values  [MaxFieldTag][]byte
	present [MaxFieldTag]bool
}

// ParseFields makes one linear pass over payload. It refuses, in the order met, a
// truncated field header or value, a tag outside the schema, a repeated tag, and finally
// any required tag that is absent.
func ParseFields(payload []byte, schema []FieldSpec) (*Fields, error) {
	fields := &Fields{}
	cursor := 0
	for cursor < len(payload) {
		if len(payload)-cursor < FieldOverheadBytes {
			return nil, &FieldRefusal{Kind: FieldTruncatedHeader, AtByte: cursor}
		}
		tag := payload[cursor]
		declared := int(binary.BigEndian.Uint16(payload[cursor+1 : cursor+3]))
		cursor += FieldOverheadBytes
		remaining := len(payload) - cursor
		if declared > remaining {
			return nil, &FieldRefusal{Kind: FieldTruncatedValue, Tag: tag, DeclaredBytes: declared, RemainingBytes: remaining}
		}
		value := payload[cursor : cursor+declared]
		cursor += declared
		if tag == 0 || tag > MaxFieldTag || !inSchema(schema, tag) {
			return nil, &FieldRefusal{Kind: FieldUnknown, Tag: tag}
		}
		if fields.present[tag-1] {
			return nil, &FieldRefusal{Kind: FieldDuplicate, Tag: tag}
		}
		fields.present[tag-1] = true
		fields.values[tag-1] = value
	}
	for _, spec := range schema {
		if spec.Required && spec.Tag >= 1 && spec.Tag <= MaxFieldTag && !fields.present[spec.Tag-1] {
			return nil, &FieldRefusal{Kind: FieldMissing, Tag: spec.Tag}
		}
	}
	return fields, nil
}

func inSchema(schema []FieldSpec, tag uint8) bool {
	for _, spec := range schema {
		if spec.Tag == tag {
			return true
		}
	}
	return false
}

// Has reports whether tag is present.
func (f *Fields) Has(tag uint8) bool {
	return tag >= 1 && tag <= MaxFieldTag && f.present[tag-1]
}

func (f *Fields) raw(tag uint8) ([]byte, error) {
	if !f.Has(tag) {
		return nil, &FieldRefusal{Kind: FieldMissing, Tag: tag}
	}
	return f.values[tag-1], nil
}

func (f *Fields) fixed(tag uint8, n int) ([]byte, error) {
	value, err := f.raw(tag)
	if err != nil {
		return nil, err
	}
	if len(value) != n {
		return nil, &FieldRefusal{Kind: FieldWrongLength, Tag: tag, ExpectedBytes: n, FoundBytes: len(value)}
	}
	return value, nil
}

// U8 reads a one-byte field.
func (f *Fields) U8(tag uint8) (uint8, error) {
	value, err := f.fixed(tag, 1)
	if err != nil {
		return 0, err
	}
	return value[0], nil
}

// U16 reads a two-byte field.
func (f *Fields) U16(tag uint8) (uint16, error) {
	value, err := f.fixed(tag, 2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(value), nil
}

// U32 reads a four-byte field.
func (f *Fields) U32(tag uint8) (uint32, error) {
	value, err := f.fixed(tag, 4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(value), nil
}

// U64 reads an eight-byte field.
func (f *Fields) U64(tag uint8) (uint64, error) {
	value, err := f.fixed(tag, 8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(value), nil
}

// I32 reads a four-byte signed field.
func (f *Fields) I32(tag uint8) (int32, error) {
	value, err := f.U32(tag)
	return int32(value), err
}

// Digest reads a 32-byte digest field.
func (f *Fields) Digest(tag uint8) (Digest, error) {
	value, err := f.fixed(tag, len(Digest{}))
	if err != nil {
		return Digest{}, err
	}
	return Digest(value), nil
}

// OptionalU64 reads an eight-byte field when present.
func (f *Fields) OptionalU64(tag uint8) (*uint64, error) {
	if !f.Has(tag) {
		return nil, nil
	}
	value, err := f.U64(tag)
	if err != nil {
		return nil, err
	}
	return &value, nil
}

// OptionalDigest reads a digest field when present.
func (f *Fields) OptionalDigest(tag uint8) (*Digest, error) {
	if !f.Has(tag) {
		return nil, nil
	}
	value, err := f.Digest(tag)
	if err != nil {
		return nil, err
	}
	return &value, nil
}

// Bytes reads opaque bytes, at most maxBytes long. The slice aliases the payload.
func (f *Fields) Bytes(tag uint8, maxBytes int) ([]byte, error) {
	value, err := f.raw(tag)
	if err != nil {
		return nil, err
	}
	if len(value) > maxBytes {
		return nil, &FieldRefusal{Kind: FieldTooLong, Tag: tag, MaxBytes: maxBytes, FoundBytes: len(value)}
	}
	return value, nil
}

// Text reads UTF-8 text without control characters, at most maxBytes long.
func (f *Fields) Text(tag uint8, maxBytes int) (string, error) {
	value, err := f.Bytes(tag, maxBytes)
	if err != nil {
		return "", err
	}
	if !utf8.Valid(value) {
		return "", &FieldRefusal{Kind: FieldNotText, Tag: tag}
	}
	text := string(value)
	for _, r := range text {
		if unicode.IsControl(r) {
			return "", &FieldRefusal{Kind: FieldNotText, Tag: tag}
		}
	}
	return text, nil
}

// Name reads a link name (ValidateLinkName).
func (f *Fields) Name(tag uint8) (string, error) {
	text, err := f.Text(tag, MaxTextBytes)
	if err != nil {
		return "", err
	}
	if err := ValidateLinkName(text); err != nil {
		return "", &FieldRefusal{Kind: FieldNotName, Tag: tag, Detail: err.Error()}
	}
	return text, nil
}

// Code reads a one-byte code of a closed enumeration.
func (f *Fields) Code(tag uint8, valid func(uint8) bool) (uint8, error) {
	value, err := f.U8(tag)
	if err != nil {
		return 0, err
	}
	if !valid(value) {
		return 0, &FieldRefusal{Kind: FieldInvalidValue, Tag: tag, Value: uint64(value)}
	}
	return value, nil
}
