package main

// Decoders are used only inside importer/consumer VMs. Frame boundaries are kept
// explicit: a second member, skippable frame, dictionary or trailing bytes cannot
// silently become part of an image. The caller meters every expanded byte.
import (
	"bufio"
	"compress/gzip"
	"errors"
	"io"

	"github.com/klauspost/compress/zstd"
)

const imageZstdWindow = 128 << 20 // production ImportLimits::max_zstd_window_log = 27

func supportedImageLayer(media string) bool {
	return media == mediaLayerTar || media == mediaLayerTarGzip || media == mediaDockerGzip || media == mediaLayerTarZstd
}

func imageLayerDecoder(input *bufio.Reader, media string) (io.ReadCloser, error) {
	switch media {
	case mediaLayerTar:
		return io.NopCloser(input), nil
	case mediaLayerTarGzip, mediaDockerGzip:
		reader, err := gzip.NewReader(input)
		if err != nil {
			return nil, err
		}
		reader.Multistream(false)
		return reader, nil
	case mediaLayerTarZstd:
		prefix, _ := input.Peek(zstd.HeaderMaxSize)
		var header zstd.Header
		if err := header.Decode(prefix); err != nil {
			return nil, err
		}
		if header.Skippable || header.DictionaryID != 0 {
			return nil, errors.New("skippable frames and external dictionaries are refused")
		}
		frame := &singleZstdFrame{input: input, remaining: header.HeaderSize, checksum: header.HasCheckSum}
		reader, err := zstd.NewReader(frame, zstd.WithDecoderConcurrency(1),
			zstd.WithDecoderLowmem(true), zstd.WithDecoderMaxWindow(imageZstdWindow),
			zstd.WithDecoderMaxMemory(imageZstdWindow), zstd.WithDecodeBuffersBelow(0))
		if err != nil {
			return nil, err
		}
		return reader.IOReadCloser(), nil
	default:
		return nil, errors.New("unsupported image layer media type")
	}
}

// A framing reader, not a codec: the upstream decoder verifies the frame and its
// checksum. Supplying only one frame prevents its multi-frame decoder from
// consuming an otherwise valid trailing frame. No compressed payload is buffered
// here, and each upstream read is limited to the remaining header/block extent.
type singleZstdFrame struct {
	input     *bufio.Reader
	remaining int
	checksum  bool
	last      bool
}

func (f *singleZstdFrame) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if f.remaining == 0 {
		if f.last {
			return 0, io.EOF
		}
		header, err := f.input.Peek(3)
		if err != nil {
			return 0, io.ErrUnexpectedEOF
		}
		bits := uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16
		kind, size := (bits>>1)&3, int(bits>>3)
		if kind == 3 || size > 128<<10 {
			return 0, errors.New("invalid zstd block")
		}
		if kind == 1 {
			size = 1
		} // RLE: one compressed byte, size expanded bytes.
		f.last = bits&1 != 0
		f.remaining = 3 + size
		if f.last && f.checksum {
			f.remaining += 4
		}
	}
	if len(p) > f.remaining {
		p = p[:f.remaining]
	}
	n, err := f.input.Read(p)
	f.remaining -= n
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}
