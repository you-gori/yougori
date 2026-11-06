//! The authenticated control session between the home host and one remote host (CORE-05
//! endpoint identity and HMAC-SHA256 authentication; VM-W39 "loss of control
//! connection", "stale identities"; VM-W41 "remote reconnect cannot revive expired
//! authority"; VM part §6.3 replay protection).
//!
//! A session is opened only for a [`RemoteIdentity`] the host enrolled: the host, its key
//! fingerprint and the enrollment generation. Every frame names the session and the
//! identity, carries a sequence number and is sealed with HMAC-SHA256 under the session
//! key ([`hmac_sha256`], compared with [`tags_equal`]). A frame for another session, a
//! stale identity, a replayed sequence or a changed byte is refused. A lost session stays
//! lost: reconnecting opens a new session, and authority is judged afresh by the host,
//! never carried over by the connection.
//!
//! The SSH transport and the key exchange that yields the session key are outside Tier 0;
//! here the key is an input.

use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::ssh::{
    EnrollmentGeneration, HostEnrollment, HostKeyFingerprint, RemoteHostId, TrustAssumption,
};
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{AuthorizationEpoch, Digest, DigestBuilder, LeaseId, MonotonicTime};
use crate::foundation::transfer::{hmac_sha256, tags_equal, Endpoint, HMAC_SHA256_TAG_BYTES};
use crate::sandbox_contract::files::RemoteExpiry;

/// Domain of [`ControlFrame::digest`], which names the field layout below.
pub const CONTROL_FRAME_DOMAIN: &str = "yougori/remote/control-frame/v1";

/// The enrolled identity of one remote host: the CORE-05 endpoint a session and a
/// transfer are bound to, with the trust assumptions of its enrollment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteIdentity {
    pub host: RemoteHostId,
    pub fingerprint: HostKeyFingerprint,
    pub enrollment: EnrollmentGeneration,
    pub assumptions: BTreeSet<TrustAssumption>,
}

impl RemoteIdentity {
    /// Domain of [`RemoteIdentity::digest`].
    pub const DOMAIN: &'static str = "yougori/remote/identity/v1";

    /// The identity an enrollment establishes, with its trust assumptions.
    pub fn from_enrollment(enrollment: &HostEnrollment) -> Self {
        Self {
            host: enrollment.host,
            fingerprint: enrollment.fingerprint,
            enrollment: enrollment.generation,
            assumptions: enrollment.assumptions.clone(),
        }
    }

    /// Host, key fingerprint and enrollment generation; another enrollment of the same
    /// host is another identity.
    pub fn digest(&self) -> Digest {
        DigestBuilder::new(Self::DOMAIN)
            .digest(self.host.digest())
            .digest(self.fingerprint.digest())
            .u64(self.enrollment.get())
            .finish()
    }

    /// The CORE-05 endpoint for the host, named by the digest of its enrolled key.
    pub fn endpoint(&self) -> Endpoint {
        Endpoint::PeerHost {
            host: *self.fingerprint.digest(),
        }
    }
}

/// The session key that authenticates control frames. `Debug` never shows it.
#[derive(Clone)]
pub struct ControlKey(Vec<u8>);

impl ControlKey {
    /// The shortest accepted key: one HMAC-SHA256 output.
    pub const MIN_BYTES: usize = HMAC_SHA256_TAG_BYTES;

    /// Accepts a key of at least [`ControlKey::MIN_BYTES`].
    pub fn new(secret: Vec<u8>) -> Result<Self, ControlRefusal> {
        if secret.len() < Self::MIN_BYTES {
            return Err(ControlRefusal::KeyTooShort {
                min_bytes: u64::try_from(Self::MIN_BYTES).unwrap_or(u64::MAX),
            });
        }
        Ok(Self(secret))
    }

    fn tag(&self, frame: &ControlFrame) -> FrameTag {
        FrameTag(hmac_sha256(&self.0, frame.digest().as_bytes()))
    }
}

impl fmt::Debug for ControlKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ControlKey(redacted)")
    }
}

/// One control session, by the digest of its transport session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ControlSessionId(Digest);

impl ControlSessionId {
    pub const fn new(digest: Digest) -> Self {
        Self(digest)
    }

    pub const fn digest(&self) -> &Digest {
        &self.0
    }
}

strict_remote_enum! {
    /// The host authority a delegation stands on (CORE-04): a service lease under a VM
    /// sandbox parent, or a labelled runtime's authority record under its epoch (VM-D5).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum GrantRef tag "authority" {
        Lease { lease: LeaseId },
        Labelled { epoch: AuthorizationEpoch },
    }
}

impl GrantRef {
    fn feed(&self, builder: DigestBuilder) -> DigestBuilder {
        match self {
            Self::Lease { lease } => builder.str("lease").u64(lease.get()),
            Self::Labelled { epoch } => builder.str("labelled").u64(epoch.get()),
        }
    }
}

/// A delegation as the remote side receives it: the host authority it stands on, the
/// host clock session that authority belongs to, and a time to live the remote counts
/// from receipt on its own clock. The remote has no way to extend it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseGrant {
    pub authority: GrantRef,
    pub clock: ClockSession,
    pub ttl_nanos: u64,
}

strict_remote_enum! {
    /// What a control frame says.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ControlBody tag "body" {
        /// The remote is alive.
        Heartbeat,
        /// The remote asks the host to renew its delegation; only the host decides.
        RenewalRequest { authority: GrantRef, clock: ClockSession },
        /// The remote states its view of its delegation, on its own wall clock (§6.2).
        StatusReport { expiry: RemoteExpiry },
        /// The host delegates or renews.
        Grant { grant: LeaseGrant },
        /// The host tells the remote to stop.
        Stop,
    }
}

impl ControlBody {
    fn feed(&self, builder: DigestBuilder) -> DigestBuilder {
        match self {
            Self::Heartbeat => builder.str("heartbeat"),
            Self::RenewalRequest { authority, clock } => authority
                .feed(builder.str("renewal_request"))
                .bytes(clock.as_uuid().as_bytes()),
            Self::StatusReport { expiry } => builder
                .str("status_report")
                .digest(&expiry.right)
                .bytes(&expiry.issued_unix_seconds.to_be_bytes())
                .bytes(&expiry.expires_unix_seconds.to_be_bytes())
                .bytes(&expiry.remote_now_unix_seconds.to_be_bytes()),
            Self::Grant { grant } => grant
                .authority
                .feed(builder.str("grant"))
                .bytes(grant.clock.as_uuid().as_bytes())
                .u64(grant.ttl_nanos),
            Self::Stop => builder.str("stop"),
        }
    }
}

/// One control frame before sealing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlFrame {
    pub session: ControlSessionId,
    /// [`RemoteIdentity::digest`] of the identity the sender was enrolled as.
    pub identity: Digest,
    pub sequence: u64,
    pub body: ControlBody,
}

impl ControlFrame {
    /// Every field under [`CONTROL_FRAME_DOMAIN`]; the seal authenticates this digest.
    pub fn digest(&self) -> Digest {
        self.body
            .feed(
                DigestBuilder::new(CONTROL_FRAME_DOMAIN)
                    .digest(self.session.digest())
                    .digest(&self.identity)
                    .u64(self.sequence),
            )
            .finish()
    }

    /// Seals the frame under `key`; both ends seal this way.
    pub fn seal(self, key: &ControlKey) -> SealedFrame {
        let tag = key.tag(&self);
        SealedFrame { frame: self, tag }
    }
}

/// An HMAC-SHA256 tag, serialized as lowercase hexadecimal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameTag([u8; HMAC_SHA256_TAG_BYTES]);

impl Serialize for FrameTag {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for FrameTag {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let mut bytes = [0u8; HMAC_SHA256_TAG_BYTES];
        hex::decode_to_slice(text, &mut bytes).map_err(serde::de::Error::custom)?;
        Ok(Self(bytes))
    }
}

/// A frame and its seal as it travels; untrusted until a session accepts it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedFrame {
    pub frame: ControlFrame,
    pub tag: FrameTag,
}

strict_remote_enum! {
    /// Why a control step was refused.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum ControlRefusal tag "refusal" {
        KeyTooShort { min_bytes: u64 },
        /// The seal does not match: a byte changed, or another key sealed it.
        Tampered,
        /// The frame belongs to another session, such as one from before a reconnect.
        OtherSession,
        /// The frame names another identity than the session's enrolled one.
        StaleIdentity,
        Replayed { sequence: u64, next_expected: u64 },
        /// The session was lost; a reconnect opens a new one.
        Lost,
        Closed,
        SequenceExhausted,
        /// The remote accepts only a sealed heartbeat at sequence zero as its opening.
        NotOpeningHeartbeat,
    }
}

impl fmt::Display for ControlRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyTooShort { min_bytes } => {
                write!(f, "a control key is at least {min_bytes} bytes")
            }
            Self::Tampered => f.write_str("the control frame's seal does not match"),
            Self::OtherSession => f.write_str("the control frame belongs to another session"),
            Self::StaleIdentity => {
                f.write_str("the control frame names another identity than the enrolled one")
            }
            Self::Replayed {
                sequence,
                next_expected,
            } => write!(
                f,
                "control frame {sequence} was replayed; the next is {next_expected}"
            ),
            Self::Lost => f.write_str("the control session was lost; reconnect opens a new one"),
            Self::Closed => f.write_str("the control session is closed"),
            Self::SequenceExhausted => f.write_str("the control session used every sequence"),
            Self::NotOpeningHeartbeat => {
                f.write_str("a remote control session must open with heartbeat zero")
            }
        }
    }
}

impl std::error::Error for ControlRefusal {}

/// One verifier for both ends of the existing control wire. Authentication precedes
/// all identity and sequence decisions. A refused frame never advances the receiver.
fn accept_bound(
    key: &ControlKey,
    session: ControlSessionId,
    identity: Digest,
    next: &mut u64,
    sealed: &SealedFrame,
) -> Result<ControlBody, ControlRefusal> {
    if !tags_equal(&key.tag(&sealed.frame).0, &sealed.tag.0) {
        return Err(ControlRefusal::Tampered);
    }
    let frame = &sealed.frame;
    if frame.session != session {
        return Err(ControlRefusal::OtherSession);
    }
    if frame.identity != identity {
        return Err(ControlRefusal::StaleIdentity);
    }
    if frame.sequence < *next {
        return Err(ControlRefusal::Replayed {
            sequence: frame.sequence,
            next_expected: *next,
        });
    }
    let after = frame
        .sequence
        .checked_add(1)
        .ok_or(ControlRefusal::SequenceExhausted)?;
    *next = after;
    Ok(frame.body)
}

fn seal_bound(
    key: &ControlKey,
    session: ControlSessionId,
    identity: Digest,
    next: &mut u64,
    body: ControlBody,
) -> Result<SealedFrame, ControlRefusal> {
    let sequence = *next;
    *next = sequence
        .checked_add(1)
        .ok_or(ControlRefusal::SequenceExhausted)?;
    Ok(ControlFrame {
        session,
        identity,
        sequence,
        body,
    }
    .seal(key))
}

/// The remote end of the existing SSH control wire. The opening authenticates the
/// enrolled identity's digest; it does not invent a host enrollment or claim to have
/// verified an attestation. Keys arrive only through the authenticated management
/// channel. This type verifies frames, not delegation or work authority.
#[derive(Debug)]
pub struct ControlPeer {
    key: ControlKey,
    session: ControlSessionId,
    identity: Digest,
    next_inbound: u64,
    next_outbound: u64,
    closed: bool,
}

impl ControlPeer {
    pub fn open(key: ControlKey, opening: &SealedFrame) -> Result<Self, ControlRefusal> {
        let mut peer = Self {
            key,
            session: opening.frame.session,
            identity: opening.frame.identity,
            next_inbound: 0,
            next_outbound: 0,
            closed: false,
        };
        let body = peer.accept(opening)?;
        if opening.frame.sequence != 0 || body != ControlBody::Heartbeat {
            return Err(ControlRefusal::NotOpeningHeartbeat);
        }
        Ok(peer)
    }

    pub fn id(&self) -> ControlSessionId {
        self.session
    }
    pub fn identity_digest(&self) -> Digest {
        self.identity
    }

    pub fn accept(&mut self, frame: &SealedFrame) -> Result<ControlBody, ControlRefusal> {
        if self.closed {
            return Err(ControlRefusal::Closed);
        }
        accept_bound(
            &self.key,
            self.session,
            self.identity,
            &mut self.next_inbound,
            frame,
        )
    }

    pub fn seal_outbound(&mut self, body: ControlBody) -> Result<SealedFrame, ControlRefusal> {
        if self.closed {
            return Err(ControlRefusal::Closed);
        }
        seal_bound(
            &self.key,
            self.session,
            self.identity,
            &mut self.next_outbound,
            body,
        )
    }

    pub fn close(&mut self) {
        self.closed = true;
    }
}

strict_remote_enum! {
    /// Where a control session is.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SessionState tag "state" {
        Live,
        Lost { at: MonotonicTime },
        Closed { at: MonotonicTime },
    }
}

/// The host's end of one authenticated control session.
#[derive(Clone, Debug)]
pub struct ControlSession {
    identity: RemoteIdentity,
    session: ControlSessionId,
    session_key: Digest,
    key: ControlKey,
    opened_at: MonotonicTime,
    last_heard: MonotonicTime,
    next_inbound: u64,
    next_outbound: u64,
    state: SessionState,
}

impl ControlSession {
    /// Opens a session for an enrolled `identity`. `session_key` is the public binding
    /// of the transport session (such as the digest of its key-exchange output) that an
    /// attestation report must name.
    pub fn open(
        identity: RemoteIdentity,
        session: ControlSessionId,
        session_key: Digest,
        key: ControlKey,
        now: MonotonicTime,
    ) -> Self {
        Self {
            identity,
            session,
            session_key,
            key,
            opened_at: now,
            last_heard: now,
            next_inbound: 0,
            next_outbound: 0,
            state: SessionState::Live,
        }
    }

    pub fn identity(&self) -> &RemoteIdentity {
        &self.identity
    }

    pub fn id(&self) -> ControlSessionId {
        self.session
    }

    pub fn session_key(&self) -> Digest {
        self.session_key
    }

    pub fn state(&self) -> SessionState {
        self.state
    }

    pub fn opened_at(&self) -> MonotonicTime {
        self.opened_at
    }

    pub fn last_heard(&self) -> MonotonicTime {
        self.last_heard
    }

    /// Accepts an inbound frame: the seal, the session, the identity and a sequence
    /// above every one seen, in that order.
    pub fn accept(
        &mut self,
        sealed: &SealedFrame,
        now: MonotonicTime,
    ) -> Result<ControlBody, ControlRefusal> {
        self.require_live()?;
        let body = accept_bound(
            &self.key,
            self.session,
            self.identity.digest(),
            &mut self.next_inbound,
            sealed,
        )?;
        self.last_heard = self.last_heard.max(now);
        Ok(body)
    }

    /// Seals an outbound frame on this session.
    pub fn seal_outbound(&mut self, body: ControlBody) -> Result<SealedFrame, ControlRefusal> {
        self.require_live()?;
        seal_bound(
            &self.key,
            self.session,
            self.identity.digest(),
            &mut self.next_outbound,
            body,
        )
    }

    /// How long nothing authenticated has arrived.
    pub fn silent_for(&self, now: MonotonicTime) -> Duration {
        now.saturating_duration_since(self.last_heard)
    }

    /// Live, and heard from within `max_silence`.
    pub fn is_live(&self, now: MonotonicTime, max_silence: Duration) -> bool {
        self.state == SessionState::Live && self.silent_for(now) <= max_silence
    }

    /// The transport is gone; the session never becomes live again.
    pub fn mark_lost(&mut self, now: MonotonicTime) {
        if self.state == SessionState::Live {
            self.state = SessionState::Lost { at: now };
        }
    }

    /// The host closed the session.
    pub fn close(&mut self, now: MonotonicTime) {
        if !matches!(self.state, SessionState::Closed { .. }) {
            self.state = SessionState::Closed { at: now };
        }
    }

    fn require_live(&self) -> Result<(), ControlRefusal> {
        match self.state {
            SessionState::Live => Ok(()),
            SessionState::Lost { .. } => Err(ControlRefusal::Lost),
            SessionState::Closed { .. } => Err(ControlRefusal::Closed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::digest;
    use crate::sandbox_contract::remote::fakes::{control_key, identity, session_id, SECOND};

    fn at(seconds: u64) -> MonotonicTime {
        MonotonicTime::from_nanos(seconds * 1_000_000_000)
    }

    fn remote_frame(sequence: u64, body: ControlBody) -> SealedFrame {
        ControlFrame {
            session: session_id(1),
            identity: identity(1).digest(),
            sequence,
            body,
        }
        .seal(&control_key(1))
    }

    fn open() -> ControlSession {
        ControlSession::open(
            identity(1),
            session_id(1),
            digest("yougori/test/session-key/v1", &[b"1"]),
            control_key(1),
            at(0),
        )
    }

    #[test]
    fn a_sealed_frame_is_accepted_once_and_in_order() {
        let mut session = open();
        assert_eq!(
            session.accept(&remote_frame(0, ControlBody::Heartbeat), at(1)),
            Ok(ControlBody::Heartbeat)
        );
        assert_eq!(session.last_heard(), at(1));
        assert_eq!(
            session.accept(&remote_frame(0, ControlBody::Heartbeat), at(2)),
            Err(ControlRefusal::Replayed {
                sequence: 0,
                next_expected: 1
            })
        );
        assert!(session
            .accept(&remote_frame(5, ControlBody::Heartbeat), at(3))
            .is_ok());
        assert!(matches!(
            session.accept(&remote_frame(4, ControlBody::Heartbeat), at(4)),
            Err(ControlRefusal::Replayed { .. })
        ));
    }

    #[test]
    fn a_changed_byte_another_key_session_or_identity_is_refused() {
        let mut session = open();
        let mut tampered = remote_frame(0, ControlBody::Heartbeat);
        tampered.frame.body = ControlBody::Stop;
        assert_eq!(
            session.accept(&tampered, at(1)),
            Err(ControlRefusal::Tampered)
        );
        let forged = ControlFrame {
            session: session_id(1),
            identity: identity(1).digest(),
            sequence: 0,
            body: ControlBody::Heartbeat,
        }
        .seal(&control_key(2));
        assert_eq!(
            session.accept(&forged, at(1)),
            Err(ControlRefusal::Tampered)
        );
        let other_session = ControlFrame {
            session: session_id(2),
            identity: identity(1).digest(),
            sequence: 0,
            body: ControlBody::Heartbeat,
        }
        .seal(&control_key(1));
        assert_eq!(
            session.accept(&other_session, at(1)),
            Err(ControlRefusal::OtherSession)
        );
        let stale = ControlFrame {
            session: session_id(1),
            identity: identity(2).digest(),
            sequence: 0,
            body: ControlBody::Heartbeat,
        }
        .seal(&control_key(1));
        assert_eq!(
            session.accept(&stale, at(1)),
            Err(ControlRefusal::StaleIdentity)
        );
    }

    #[test]
    fn silence_and_loss_end_liveness_and_a_lost_session_stays_lost() {
        let mut session = open();
        assert!(session.is_live(at(10), 10 * SECOND));
        assert!(!session.is_live(at(11), 10 * SECOND));
        session.mark_lost(at(11));
        assert_eq!(session.state(), SessionState::Lost { at: at(11) });
        assert_eq!(
            session.accept(&remote_frame(0, ControlBody::Heartbeat), at(12)),
            Err(ControlRefusal::Lost)
        );
        assert_eq!(
            session.seal_outbound(ControlBody::Stop),
            Err(ControlRefusal::Lost)
        );
        assert!(!session.is_live(at(11), 10 * SECOND));
        session.close(at(13));
        assert_eq!(
            session.accept(&remote_frame(0, ControlBody::Heartbeat), at(14)),
            Err(ControlRefusal::Closed)
        );
    }

    #[test]
    fn outbound_frames_verify_under_the_same_key() {
        let mut session = open();
        let sealed = session.seal_outbound(ControlBody::Stop).unwrap();
        assert_eq!(sealed.frame.sequence, 0);
        assert_eq!(sealed, sealed.frame.seal(&control_key(1)));
        let json = serde_json::to_value(sealed).unwrap();
        let back: SealedFrame = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(back, sealed);
        let mut extra = json;
        extra["note"] = serde_json::json!("x");
        assert!(serde_json::from_value::<SealedFrame>(extra).is_err());
    }

    #[test]
    fn keys_are_long_enough_and_never_shown() {
        assert!(matches!(
            ControlKey::new(vec![1; 31]),
            Err(ControlRefusal::KeyTooShort { min_bytes: 32 })
        ));
        assert_eq!(format!("{:?}", control_key(1)), "ControlKey(redacted)");
    }

    #[test]
    fn identity_digest_and_endpoint_follow_the_enrollment() {
        let one = identity(1);
        let mut later = one.clone();
        later.enrollment = later.enrollment.next().unwrap();
        assert_ne!(one.digest(), later.digest());
        assert_eq!(
            one.endpoint(),
            Endpoint::PeerHost {
                host: *one.fingerprint.digest()
            }
        );
    }

    #[test]
    fn real_host_and_remote_peer_exchange_existing_wire_frames_without_inventing_an_identity() {
        let mut host = open();
        let opening = host.seal_outbound(ControlBody::Heartbeat).unwrap();
        let mut peer = ControlPeer::open(control_key(1), &opening).unwrap();
        assert_eq!(peer.identity_digest(), host.identity().digest());
        assert_eq!(peer.id(), host.id());
        let hello = peer.seal_outbound(ControlBody::Heartbeat).unwrap();
        assert_eq!(host.accept(&hello, at(1)), Ok(ControlBody::Heartbeat));
        let stop = host.seal_outbound(ControlBody::Stop).unwrap();
        assert_eq!(peer.accept(&stop), Ok(ControlBody::Stop));
        assert!(matches!(
            peer.accept(&stop),
            Err(ControlRefusal::Replayed { .. })
        ));
        peer.close();
        assert_eq!(peer.accept(&stop), Err(ControlRefusal::Closed));
        assert_eq!(
            peer.seal_outbound(ControlBody::Heartbeat),
            Err(ControlRefusal::Closed)
        );
    }

    #[test]
    fn remote_opening_and_subsequent_frames_share_constant_time_mac_and_identity_checks() {
        let opening = remote_frame(0, ControlBody::Heartbeat);
        assert!(matches!(
            ControlPeer::open(control_key(2), &opening),
            Err(ControlRefusal::Tampered)
        ));
        for frame in [
            remote_frame(1, ControlBody::Heartbeat),
            remote_frame(0, ControlBody::Stop),
        ] {
            assert!(matches!(
                ControlPeer::open(control_key(1), &frame),
                Err(ControlRefusal::NotOpeningHeartbeat)
            ));
        }
        let mut peer = ControlPeer::open(control_key(1), &opening).unwrap();
        let mut tampered = remote_frame(1, ControlBody::Heartbeat);
        tampered.frame.body = ControlBody::Stop;
        assert_eq!(peer.accept(&tampered), Err(ControlRefusal::Tampered));
        let foreign = ControlFrame {
            session: session_id(2),
            identity: identity(1).digest(),
            sequence: 1,
            body: ControlBody::Heartbeat,
        }
        .seal(&control_key(1));
        assert_eq!(peer.accept(&foreign), Err(ControlRefusal::OtherSession));
        let stale = ControlFrame {
            session: session_id(1),
            identity: identity(2).digest(),
            sequence: 1,
            body: ControlBody::Heartbeat,
        }
        .seal(&control_key(1));
        assert_eq!(peer.accept(&stale), Err(ControlRefusal::StaleIdentity));
        // Refused traffic consumed neither the sequence nor the next valid frame.
        assert_eq!(
            peer.accept(&remote_frame(1, ControlBody::Heartbeat)),
            Ok(ControlBody::Heartbeat)
        );
    }
}
