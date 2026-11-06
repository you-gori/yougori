package link

// Fixed maximum frame, message, stream and buffered-byte counts, the per-channel quotas
// and the timeouts (host: src-tauri/src/sandbox/link/limits.rs). The defaults are the
// host's documented defaults; the Welcome carries only the frame limit and the idle
// timeout, so both ends must run these defaults for the windows to agree.

import (
	"fmt"
	"time"
)

// ChannelQuota is the quota of one channel, independent of every other channel's.
type ChannelQuota struct {
	// MaxMessageBytes is the longest payload of one frame on this channel.
	MaxMessageBytes uint32
	// MaxStreams is the number of streams open at once; zero on control.
	MaxStreams uint32
	// MaxBufferedBytes is the receive window: bytes held before the peer must wait for
	// credit. Zero on control. On the ingress and egress channels, flow-controlled per
	// stream, it bounds the growth of the channel's stream windows over StreamWindowBytes.
	MaxBufferedBytes uint64
	// MaxQueuedFrames is the number of frames queued for sending at most.
	MaxQueuedFrames uint32
}

// Limits are the link's limits.
type Limits struct {
	MaxFrameBytes          uint32
	HandshakeTimeout       time.Duration
	IdleTimeout            time.Duration
	FrameCompletionTimeout time.Duration
	OpenTimeout            time.Duration
	MaxRefusals            uint32
	Control                ChannelQuota
	Terminal               ChannelQuota
	File                   ChannelQuota
	Ingress                ChannelQuota
	Egress                 ChannelQuota
}

const (
	// StreamWindowBytes is the window each direction of an ingress or egress stream starts
	// with (version 3), which every stream keeps whatever the channel's other streams do.
	// Both ends assume it; the welcome does not carry it.
	StreamWindowBytes uint64 = 64 << 10
	// MaxStreamWindowBytes is the most a receiver lets one stream's window grow to (the
	// receiver's choice): a stream that consumed its first window whole grows to it while
	// the channel's growth stays within the channel's MaxBufferedBytes.
	MaxStreamWindowBytes uint64 = 1 << 20
	// DefaultMaxMessageBytes is the largest payload of a default frame.
	DefaultMaxMessageBytes uint32 = 65472
	// DefaultMaxFrameBytes is the default frame limit: the largest payload plus header and
	// tag (65 552 in version 2).
	DefaultMaxFrameBytes = DefaultMaxMessageBytes + FrameOverheadBytes
)

// DefaultLimits are the documented defaults, identical to LinkLimits::default().
func DefaultLimits() Limits {
	return Limits{
		MaxFrameBytes:          DefaultMaxFrameBytes,
		HandshakeTimeout:       10 * time.Second,
		IdleTimeout:            60 * time.Second,
		FrameCompletionTimeout: 5 * time.Second,
		OpenTimeout:            30 * time.Second,
		MaxRefusals:            64,
		Control:                ChannelQuota{MaxMessageBytes: 4096, MaxStreams: 0, MaxBufferedBytes: 0, MaxQueuedFrames: 256},
		Terminal:               ChannelQuota{MaxMessageBytes: 16384, MaxStreams: 16, MaxBufferedBytes: 1 << 20, MaxQueuedFrames: 1024},
		File:                   ChannelQuota{MaxMessageBytes: DefaultMaxMessageBytes, MaxStreams: 64, MaxBufferedBytes: 8 << 20, MaxQueuedFrames: 1024},
		Ingress:                ChannelQuota{MaxMessageBytes: DefaultMaxMessageBytes, MaxStreams: 256, MaxBufferedBytes: 8 << 20, MaxQueuedFrames: 4096},
		Egress:                 ChannelQuota{MaxMessageBytes: DefaultMaxMessageBytes, MaxStreams: 256, MaxBufferedBytes: 8 << 20, MaxQueuedFrames: 4096},
	}
}

// Quota is the quota of channel.
func (l *Limits) Quota(channel Channel) *ChannelQuota {
	switch channel {
	case ChannelTerminal:
		return &l.Terminal
	case ChannelFile:
		return &l.File
	case ChannelIngress:
		return &l.Ingress
	case ChannelEgress:
		return &l.Egress
	}
	return &l.Control
}

// LimitsError is why a limits configuration was refused.
type LimitsError struct {
	Setting string
	Detail  string
}

func (e *LimitsError) Error() string { return e.Setting + ": " + e.Detail }

// Validate checks the configuration as LinkLimits::validate does.
func (l *Limits) Validate() error {
	minimum := uint32(FrameOverheadBytes + 1)
	if l.MaxFrameBytes < minimum {
		return &LimitsError{Setting: "max_frame_bytes", Detail: fmt.Sprintf("%d is below the %d a frame needs", l.MaxFrameBytes, minimum)}
	}
	room := l.MaxFrameBytes - FrameOverheadBytes
	for _, channel := range AllChannels {
		quota := l.Quota(channel)
		if quota.MaxMessageBytes == 0 {
			return &LimitsError{Setting: channel.String(), Detail: "messages may not be limited to zero bytes"}
		}
		if quota.MaxMessageBytes > room {
			return &LimitsError{Setting: channel.String(), Detail: fmt.Sprintf("messages of %d bytes do not fit the %d bytes a frame leaves", quota.MaxMessageBytes, room)}
		}
		if channel.IsBulk() != (quota.MaxStreams >= 1) {
			return &LimitsError{Setting: channel.String(), Detail: "control has no streams and bulk channels need at least one"}
		}
		bufferedOK := quota.MaxBufferedBytes == 0
		if channel.IsBulk() {
			bufferedOK = quota.MaxBufferedBytes >= uint64(quota.MaxMessageBytes)
		}
		if !bufferedOK {
			return &LimitsError{Setting: channel.String(), Detail: "control buffers nothing and a bulk channel must hold one message"}
		}
		if quota.MaxQueuedFrames == 0 {
			return &LimitsError{Setting: channel.String(), Detail: "must be able to queue at least one frame"}
		}
	}
	for _, timeout := range []struct {
		name  string
		value time.Duration
	}{
		{"handshake_timeout", l.HandshakeTimeout},
		{"idle_timeout", l.IdleTimeout},
		{"frame_completion_timeout", l.FrameCompletionTimeout},
		{"open_timeout", l.OpenTimeout},
	} {
		if timeout.value <= 0 {
			return &LimitsError{Setting: timeout.name, Detail: "may not be zero"}
		}
	}
	if l.MaxRefusals == 0 {
		return &LimitsError{Setting: "max_refusals", Detail: "may not be zero"}
	}
	return nil
}
