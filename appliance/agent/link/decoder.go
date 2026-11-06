package link

// The frame decoder (host: src-tauri/src/sandbox/link/decoder.rs): fed bytes
// incrementally, holding at most one frame, so memory stays bounded whatever the peer
// sends. The first framing refusal closes it.

import "time"

// RawFrame is one frame as the decoder delimited it: the header, its exact bytes (the tag
// covers them), the payload and the tag. Nothing in it is authenticated yet.
type RawFrame struct {
	Header      Header
	HeaderBytes [HeaderBytes]byte
	Payload     []byte
	Tag         [TagBytes]byte
}

// FrameDecoder is the frame decoder of one direction.
type FrameDecoder struct {
	maxFrameBytes uint32
	buffer        []byte
	header        *Header
	needBytes     int
	startedAt     time.Time
	closed        *FramingRefusal
}

// NewFrameDecoder makes a decoder refusing frames above maxFrameBytes.
func NewFrameDecoder(maxFrameBytes uint32) *FrameDecoder {
	return &FrameDecoder{maxFrameBytes: maxFrameBytes, buffer: make([]byte, 0, HeaderBytes), needBytes: HeaderBytes}
}

// IsClosed reports whether the decoder closed.
func (d *FrameDecoder) IsClosed() bool { return d.closed != nil }

// BufferedBytes is the bytes held right now; never above the frame limit.
func (d *FrameDecoder) BufferedBytes() int { return len(d.buffer) }

// PartialSince is when the partial frame being collected started; false when none is.
func (d *FrameDecoder) PartialSince() (time.Time, bool) {
	if len(d.buffer) == 0 {
		return time.Time{}, false
	}
	return d.startedAt, true
}

// Push feeds bytes received at now. Complete frames come out in order; a framing refusal
// closes the decoder and ends the push.
func (d *FrameDecoder) Push(bytes []byte, now time.Time) ([]RawFrame, *FramingRefusal) {
	if d.closed != nil {
		if len(bytes) > 0 {
			return nil, &FramingRefusal{Kind: FramingDecoderClosed}
		}
		return nil, nil
	}
	var frames []RawFrame
	cursor := 0
	for cursor < len(bytes) {
		if len(d.buffer) == 0 {
			d.startedAt = now
		}
		take := d.needBytes - len(d.buffer)
		if rest := len(bytes) - cursor; take > rest {
			take = rest
		}
		d.buffer = append(d.buffer, bytes[cursor:cursor+take]...)
		cursor += take
		if len(d.buffer) < d.needBytes {
			continue
		}
		if d.header == nil {
			var head [HeaderBytes]byte
			copy(head[:], d.buffer)
			header, refusal := DecodeHeader(&head, d.maxFrameBytes)
			if refusal != nil {
				d.Close(refusal)
				return frames, refusal
			}
			d.header = &header
			d.needBytes = header.FrameBytes()
			// Exactly one frame's room, so the allocation never exceeds the frame limit.
			body := make([]byte, len(d.buffer), d.needBytes)
			copy(body, d.buffer)
			d.buffer = body
			if len(d.buffer) >= d.needBytes {
				frames = append(frames, d.takeFrame())
			}
			continue
		}
		frames = append(frames, d.takeFrame())
	}
	return frames, nil
}

// Finish says the peer went away. A partial frame is a truncation; nothing pending is
// fine. Either way the decoder closes.
func (d *FrameDecoder) Finish() *FramingRefusal {
	if d.closed != nil {
		return nil
	}
	var refusal *FramingRefusal
	if len(d.buffer) > 0 {
		refusal = &FramingRefusal{Kind: FramingTruncated, HaveBytes: len(d.buffer), NeedBytes: d.needBytes}
	}
	if refusal != nil {
		d.Close(refusal)
	} else {
		d.Close(&FramingRefusal{Kind: FramingDecoderClosed})
	}
	return refusal
}

// Close closes the decoder; later bytes are refused.
func (d *FrameDecoder) Close(refusal *FramingRefusal) {
	d.closed = refusal
	d.buffer = nil
	d.header = nil
	d.needBytes = HeaderBytes
	d.startedAt = time.Time{}
}

func (d *FrameDecoder) takeFrame() RawFrame {
	header := *d.header
	frame := d.buffer
	payloadEnd := HeaderBytes + int(header.PayloadBytes)
	var raw RawFrame
	raw.Header = header
	copy(raw.HeaderBytes[:], frame[:HeaderBytes])
	raw.Payload = append([]byte(nil), frame[HeaderBytes:payloadEnd]...)
	copy(raw.Tag[:], frame[payloadEnd:payloadEnd+TagBytes])
	d.header = nil
	d.needBytes = HeaderBytes
	d.startedAt = time.Time{}
	d.buffer = make([]byte, 0, HeaderBytes)
	return raw
}
