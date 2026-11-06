//! Fixed maximum frame, message, stream and buffered-byte counts, the per-channel quotas
//! and the timeouts, as configuration with documented defaults (§3.2 lines 2064 "fixed
//! maximum frame, message, stream and buffered-byte counts", 1894 "independent quotas for
//! control, terminal, file, ingress and egress channels" and 1892 "timeout").

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::wire::{Channel, FRAME_OVERHEAD_BYTES};

/// The quota of one channel, independent of every other channel's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelQuota {
    /// The longest payload of one frame on this channel.
    pub max_message_bytes: u32,
    /// Streams open at once; zero on the control channel, which has none.
    pub max_streams: u32,
    /// Bytes the host will hold for this channel before the guest must wait for credit:
    /// the receive window (backpressure). Zero on the control channel, whose messages are
    /// delivered as events and never buffered. On the ingress and egress channels, which
    /// are flow-controlled per stream, it bounds the growth of the channel's stream windows
    /// over [`STREAM_WINDOW_BYTES`] instead.
    pub max_buffered_bytes: u64,
    /// Frames queued for sending to the guest at most.
    pub max_queued_frames: u32,
}

/// The link's limits. `Default` holds the documented defaults; [`LinkLimits::validate`]
/// checks a configuration before it is used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkLimits {
    /// The longest frame, header and tag included: 65 552 bytes, which leaves the
    /// default message bound of 65 472 bytes.
    pub max_frame_bytes: u32,
    /// How long the host waits for the guest's hello: 10 seconds.
    pub handshake_timeout: Duration,
    /// How long the link may carry no authenticated frame once open: 60 seconds.
    pub idle_timeout: Duration,
    /// How long a started frame may stay incomplete (a slow peer): 5 seconds.
    pub frame_completion_timeout: Duration,
    /// How long a stream may stay half-opened without the other end's answer: 30 seconds.
    pub open_timeout: Duration,
    /// Refused frames the link tolerates from an authenticated guest before closing: 64.
    pub max_refusals: u32,
    pub control: ChannelQuota,
    pub terminal: ChannelQuota,
    pub file: ChannelQuota,
    pub ingress: ChannelQuota,
    pub egress: ChannelQuota,
}

/// The window each direction of an ingress or egress stream starts with (version 3): what
/// its sender may send before the receiver credits the stream, and what every stream keeps
/// whatever the channel's other streams do. Both ends assume it; the welcome does not carry
/// it. Larger than the default message bound, so a fresh stream takes a whole message.
pub const STREAM_WINDOW_BYTES: u64 = 64 << 10;

/// The most a receiver lets one ingress or egress stream's window grow to (a receiver's
/// choice, not the protocol's): a stream that consumed its first window whole may grow to
/// this while the channel's growth over [`STREAM_WINDOW_BYTES`] stays within the channel's
/// buffered-byte quota, so a fast stream is not held to the first window and the receiver
/// holds at most `max_streams` first windows and that quota.
pub const MAX_STREAM_WINDOW_BYTES: u64 = 1 << 20;

/// The largest payload that fits a default frame: 65 472 bytes, as in version 1.
pub const DEFAULT_MAX_MESSAGE_BYTES: u32 = 65_472;
/// The default frame limit: the default message bound plus a frame's overhead, 65 552
/// bytes. Version 1's header had no connection field and its limit was 65 536 bytes for
/// the same message bound.
pub const DEFAULT_MAX_FRAME_BYTES: u32 = DEFAULT_MAX_MESSAGE_BYTES + FRAME_OVERHEAD_BYTES as u32;

impl Default for LinkLimits {
    fn default() -> Self {
        Self {
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
            handshake_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(60),
            frame_completion_timeout: Duration::from_secs(5),
            open_timeout: Duration::from_secs(30),
            max_refusals: 64,
            control: ChannelQuota {
                max_message_bytes: 4_096,
                max_streams: 0,
                max_buffered_bytes: 0,
                max_queued_frames: 256,
            },
            terminal: ChannelQuota {
                max_message_bytes: 16_384,
                max_streams: 16,
                max_buffered_bytes: 1 << 20,
                max_queued_frames: 1_024,
            },
            file: ChannelQuota {
                max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
                max_streams: 64,
                max_buffered_bytes: 8 << 20,
                max_queued_frames: 1_024,
            },
            ingress: ChannelQuota {
                max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
                max_streams: 256,
                max_buffered_bytes: 8 << 20,
                max_queued_frames: 4_096,
            },
            egress: ChannelQuota {
                max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
                max_streams: 256,
                max_buffered_bytes: 8 << 20,
                max_queued_frames: 4_096,
            },
        }
    }
}

/// Why a limits configuration was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "limits_error", rename_all = "snake_case")]
pub enum LimitsError {
    /// The frame limit does not leave room for header, tag and one payload byte.
    FrameTooSmall {
        max_frame_bytes: u32,
        minimum: u32,
    },
    /// A channel's message limit does not fit the frame limit.
    MessageExceedsFrame {
        channel: Channel,
        max_message_bytes: u32,
        room_bytes: u32,
    },
    ZeroMessageBytes {
        channel: Channel,
    },
    /// A bulk channel needs at least one stream; the control channel has none.
    Streams {
        channel: Channel,
        max_streams: u32,
    },
    /// A bulk channel's window must hold at least one message; control has no window.
    BufferedBytes {
        channel: Channel,
        max_buffered_bytes: u64,
        max_message_bytes: u32,
    },
    ZeroQueuedFrames {
        channel: Channel,
    },
    ZeroTimeout {
        setting: &'static str,
    },
    ZeroRefusals,
}

impl fmt::Display for LimitsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameTooSmall {
                max_frame_bytes,
                minimum,
            } => write!(
                f,
                "max_frame_bytes {max_frame_bytes} is below the {minimum} a frame needs"
            ),
            Self::MessageExceedsFrame {
                channel,
                max_message_bytes,
                room_bytes,
            } => write!(
                f,
                "{channel} messages of {max_message_bytes} bytes do not fit the {room_bytes} bytes a frame leaves"
            ),
            Self::ZeroMessageBytes { channel } => {
                write!(f, "{channel} messages may not be limited to zero bytes")
            }
            Self::Streams {
                channel,
                max_streams,
            } => write!(
                f,
                "{channel} allows {max_streams} streams; control has none and bulk channels need at least one"
            ),
            Self::BufferedBytes {
                channel,
                max_buffered_bytes,
                max_message_bytes,
            } => write!(
                f,
                "{channel} buffers {max_buffered_bytes} bytes; control buffers none and a bulk channel must hold one message of {max_message_bytes}"
            ),
            Self::ZeroQueuedFrames { channel } => {
                write!(f, "{channel} must be able to queue at least one frame")
            }
            Self::ZeroTimeout { setting } => write!(f, "{setting} may not be zero"),
            Self::ZeroRefusals => f.write_str("max_refusals may not be zero"),
        }
    }
}

impl std::error::Error for LimitsError {}

impl LinkLimits {
    pub fn quota(&self, channel: Channel) -> &ChannelQuota {
        match channel {
            Channel::Control => &self.control,
            Channel::Terminal => &self.terminal,
            Channel::File => &self.file,
            Channel::Ingress => &self.ingress,
            Channel::Egress => &self.egress,
        }
    }

    /// Checks the configuration: the frame holds a payload, every message fits a frame,
    /// bulk channels have streams and a window for at least one message, every queue has
    /// room, and no timeout or refusal budget is zero.
    pub fn validate(&self) -> Result<(), LimitsError> {
        let minimum = FRAME_OVERHEAD_BYTES as u32 + 1;
        if self.max_frame_bytes < minimum {
            return Err(LimitsError::FrameTooSmall {
                max_frame_bytes: self.max_frame_bytes,
                minimum,
            });
        }
        let room_bytes = self.max_frame_bytes - FRAME_OVERHEAD_BYTES as u32;
        for channel in Channel::ALL {
            let quota = self.quota(channel);
            if quota.max_message_bytes == 0 {
                return Err(LimitsError::ZeroMessageBytes { channel });
            }
            if quota.max_message_bytes > room_bytes {
                return Err(LimitsError::MessageExceedsFrame {
                    channel,
                    max_message_bytes: quota.max_message_bytes,
                    room_bytes,
                });
            }
            let streams_ok = if channel.is_bulk() {
                quota.max_streams >= 1
            } else {
                quota.max_streams == 0
            };
            if !streams_ok {
                return Err(LimitsError::Streams {
                    channel,
                    max_streams: quota.max_streams,
                });
            }
            let buffered_ok = if channel.is_bulk() {
                quota.max_buffered_bytes >= u64::from(quota.max_message_bytes)
            } else {
                quota.max_buffered_bytes == 0
            };
            if !buffered_ok {
                return Err(LimitsError::BufferedBytes {
                    channel,
                    max_buffered_bytes: quota.max_buffered_bytes,
                    max_message_bytes: quota.max_message_bytes,
                });
            }
            if quota.max_queued_frames == 0 {
                return Err(LimitsError::ZeroQueuedFrames { channel });
            }
        }
        for (setting, timeout) in [
            ("handshake_timeout", self.handshake_timeout),
            ("idle_timeout", self.idle_timeout),
            ("frame_completion_timeout", self.frame_completion_timeout),
            ("open_timeout", self.open_timeout),
        ] {
            if timeout.is_zero() {
                return Err(LimitsError::ZeroTimeout { setting });
            }
        }
        if self.max_refusals == 0 {
            return Err(LimitsError::ZeroRefusals);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_are_the_documented_ones_and_validate() {
        let limits = LinkLimits::default();
        assert_eq!(limits.validate(), Ok(()));
        assert_eq!(limits.max_frame_bytes, 65_552);
        assert_eq!(limits.control.max_message_bytes, 4_096);
        assert_eq!(limits.terminal.max_message_bytes, 16_384);
        assert_eq!(limits.file.max_message_bytes, 65_472);
        assert_eq!(limits.egress.max_streams, 256);
        assert_eq!(limits.file.max_buffered_bytes, 8 << 20);
        assert_eq!(limits.handshake_timeout, Duration::from_secs(10));
        assert_eq!(limits.idle_timeout, Duration::from_secs(60));
        assert_eq!(limits.frame_completion_timeout, Duration::from_secs(5));
        assert_eq!(limits.open_timeout, Duration::from_secs(30));
        assert_eq!(limits.max_refusals, 64);
    }

    #[test]
    fn each_bound_is_checked() {
        let mut limits = LinkLimits::default();
        limits.max_frame_bytes = 64;
        assert!(matches!(
            limits.validate(),
            Err(LimitsError::FrameTooSmall { minimum: 81, .. })
        ));

        let mut limits = LinkLimits::default();
        limits.terminal.max_message_bytes = 65_473;
        assert_eq!(
            limits.validate(),
            Err(LimitsError::MessageExceedsFrame {
                channel: Channel::Terminal,
                max_message_bytes: 65_473,
                room_bytes: 65_472
            })
        );

        let mut limits = LinkLimits::default();
        limits.control.max_streams = 1;
        assert!(matches!(
            limits.validate(),
            Err(LimitsError::Streams {
                channel: Channel::Control,
                ..
            })
        ));
        let mut limits = LinkLimits::default();
        limits.file.max_streams = 0;
        assert!(matches!(
            limits.validate(),
            Err(LimitsError::Streams {
                channel: Channel::File,
                ..
            })
        ));

        let mut limits = LinkLimits::default();
        limits.egress.max_buffered_bytes = 100;
        assert!(matches!(
            limits.validate(),
            Err(LimitsError::BufferedBytes {
                channel: Channel::Egress,
                ..
            })
        ));
        let mut limits = LinkLimits::default();
        limits.control.max_buffered_bytes = 1;
        assert!(matches!(
            limits.validate(),
            Err(LimitsError::BufferedBytes {
                channel: Channel::Control,
                ..
            })
        ));

        let mut limits = LinkLimits::default();
        limits.ingress.max_queued_frames = 0;
        assert_eq!(
            limits.validate(),
            Err(LimitsError::ZeroQueuedFrames {
                channel: Channel::Ingress
            })
        );
        let mut limits = LinkLimits::default();
        limits.control.max_message_bytes = 0;
        assert_eq!(
            limits.validate(),
            Err(LimitsError::ZeroMessageBytes {
                channel: Channel::Control
            })
        );
        let mut limits = LinkLimits::default();
        limits.idle_timeout = Duration::ZERO;
        assert_eq!(
            limits.validate(),
            Err(LimitsError::ZeroTimeout {
                setting: "idle_timeout"
            })
        );
        let mut limits = LinkLimits::default();
        limits.max_refusals = 0;
        assert_eq!(limits.validate(), Err(LimitsError::ZeroRefusals));
    }

    #[test]
    fn limits_are_strict_on_input() {
        let json = serde_json::to_value(LinkLimits::default()).unwrap();
        assert_eq!(
            serde_json::from_value::<LinkLimits>(json.clone()).unwrap(),
            LinkLimits::default()
        );
        let mut extra = json;
        extra["unlimited"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<LinkLimits>(extra).is_err());
    }
}
