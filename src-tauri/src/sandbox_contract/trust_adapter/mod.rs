//! The real signature scheme, configured roots and publisher signatures for the sandbox
//! trust paths (docs/combined-gpu-memory-and-vm-sandbox-plan.md, §8.3 lines 2451–2457,
//! §10.6 rows VM-W45 line 2668, VM-W46 line 2669 and VM-W48 line 2671, the update
//! threat-model paragraph line 2677, VM-P23 line 2798, VM-P48 line 2823, VM-D13 line 3207,
//! §19 line 3217; the first part of M18, M18B, M18D and M18E in
//! docs/combined-plan-leftover-tasks.md, lines 106, 214–218, 292 and 346–350).
//!
//! The trust client in `sandbox::trust` verifies signatures only through its
//! [`SignatureScheme`](crate::sandbox::trust::SignatureScheme) port and starts from a
//! root the caller supplies; the OCI importer checks publisher signatures only through
//! its [`PublisherSignatures`](crate::sandbox_contract::oci::PublisherSignatures) port.
//! This module supplies all three for production over `foundation::signing`, the one
//! Ed25519 verification and the one trust-root file format. Synchronous library code: it
//! reads no environment, opens no connection, ships no key and calls no cryptographic
//! library itself, and the only files it touches are the persisted client's own durable
//! stream. The one exception is the HTTPS source ([`HttpsSource`]), which connects to the
//! configured metadata location over the engine's `reqwest` on the caller's Tokio runtime.
//!
//! What is real now:
//!
//! - **Ed25519 verification** ([`Ed25519Scheme`]): the port for
//!   [`SchemeKind::Ed25519`](crate::sandbox::trust::SchemeKind::Ed25519) over the
//!   foundation's `verify_ed25519`, each refusal mapped onto the port's own rejection.
//! - **The production registry** ([`production_registry`]): Ed25519 only, so keys of the
//!   HMAC test scheme are refused, and [`check_production_registry`] refuses a registry
//!   built elsewhere that holds a test scheme.
//! - **Configured roots** ([`PinnedRoots`]): the trust roots in force and a strict
//!   [`UpdateTrustConfig`] (root threshold and release-metadata location). At each
//!   bootstrap the keys allowed runtime updates are pinned, one per rotation chain and
//!   only while valid and unrevoked, into the trust client's own types ([`PublicKey`],
//!   [`KeyId`], [`RoleKeys`]); the client starts from a root file the threshold of those
//!   keys signed. One key has one publisher identity in the catalog and here.
//! - **OCI publisher signatures** ([`TrustRootSignatures`]): the importer's port answered
//!   by the trust roots in force, for OCI layers, at the calendar's time.
//! - **Persisted trusted metadata** ([`PersistedUpdateClient`]): every metadata file the
//!   client accepted, kept exactly as verified on a CORE-06 durable stream with one owner
//!   ([`TrustStream`], [`TrustRecord`]) before the update returns, and replayed through
//!   the client's own update calls on restart. Stored files expired since become floors;
//!   rollback, truncation, damage and any other refusal on replay fail closed
//!   ([`RecoveryRefusal`]); revocations survive and only accumulate. A torn tail the log
//!   found past its synced mark held nothing acknowledged: the open records it
//!   ([`TornTailPastMark`]) and the replay resumes from the records before it, then and
//!   after every restart; any other torn tail fails closed, as a truncation does.
//! - **Reloaded trust roots reaching the running client**
//!   ([`PersistedUpdateClient::reload`]): after the trust-root file is reloaded, the
//!   client is bootstrapped again and the stream replayed into it, without the signatures
//!   of update-root keys an earlier bootstrap pinned and the roots no longer pin (revoked,
//!   expired or replaced). What no longer verifies is dropped, by role, and keeps a
//!   floor; revoked releases stay revoked; a failed reload leaves the client trusted for
//!   nothing ([`Halt`]). The distrust holds across restarts, since the stream records
//!   every pinned key set ([`PinnedKeys`]). This closes the gap `roots` leaves open for
//!   the persisted client.
//! - **Revocation reaching running launches** ([`RunningLaunches`]): the admissions of
//!   running launches by execution, so an applied revocation list names every running
//!   launch whose artifact it newly revokes ([`RevocationReport`]), a host trust event
//!   for the lifecycle and never a guest violation signal.
//! - **One launch, one release of its pinned row** ([`check_launch_set`],
//!   [`PersistedUpdateClient::admit_launch_set`]; M18D, from S08's note): a launch's
//!   components are admitted only if they are exactly the components its row pins (content
//!   key and length per kind, nothing missing, duplicated or unpinned), verified under one
//!   snapshot and one targets version, unrevoked, and under one assurance profile; every
//!   problem is typed ([`LaunchSetProblem`]). Through the persisted client every component
//!   is verified, opened and admitted at one time against one trusted state, and the
//!   admissions are registered together under the execution, so revoking any component
//!   names the launch. Metadata versions, not file digests, bind targets verified apart;
//!   the limit is in `launch_set`.
//! - **The HTTPS source of the release metadata** ([`HttpsSource`]; M18E): role files and
//!   artifacts fetched from the configured `metadata_location` under one documented layout
//!   whose names come only from typed values ([`SourceItem`]), HTTPS only, redirects only
//!   within the location's scheme, host and port, no cookies, credentials or proxy, a
//!   connect and a per-request timeout, and a blocking reader over a bounded channel that
//!   takes at most one byte past the caller's bound, waits no longer than the deadline and
//!   cancels the transfer when dropped; failures are typed ([`SourceError`]). It is the
//!   update cycle's `FetchPort` (`sandbox::trust`, VT3); it has not fetched from a real
//!   server (E05).
//!
//! What remains of M18: scheduling the update cycle in the engine, live validation of the
//! source (E05),
//! compacting the trust stream, the lifecycle's policy for a running launch whose
//! artifact is revoked (an owner decision; the plan states none), vulnerability scanning,
//! dependency and image gates, expiring exceptions on real findings, deliberately
//! vulnerable fixtures (VM-W47), and artifact-class publisher policy on the actual import
//! and update paths (VM-W48).
//!
//! [`PublicKey`]: crate::sandbox::trust::PublicKey
//! [`KeyId`]: crate::sandbox::trust::KeyId
//! [`RoleKeys`]: crate::sandbox::trust::RoleKeys

mod config;
mod https_source;
mod launch_set;
mod persisted;
mod publisher;
mod registry;
mod replay;
mod roots;
mod running;
mod scheme;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_https_source;
#[cfg(test)]
mod tests_launch_set;
#[cfg(test)]
mod tests_persisted;
#[cfg(test)]
mod tests_publisher;
#[cfg(test)]
mod tests_roots;
#[cfg(test)]
mod tests_scheme;

pub use config::{
    UpdateTrustConfig, UpdateTrustConfigError, MAX_UPDATE_TRUST_BYTES, UPDATE_TRUST_FORMAT,
};
pub use https_source::{
    HttpsSource, HttpsSourceError, SourceError, SourceItem, SourceTimeouts, CHANNEL_CHUNKS,
    DEFAULT_CONNECT_TIMEOUT, DEFAULT_REQUEST_TIMEOUT, MAX_REDIRECTS, MAX_REQUEST_TIMEOUT,
};
pub use launch_set::{
    check_launch_set, AdmittedLaunchSet, ComponentBasis, ComponentProfile, LaunchComponent,
    LaunchSetAdmission, LaunchSetError, LaunchSetProblem, LaunchSetRefusal, ReleaseBasis,
};
pub use persisted::{
    AcceptedMetadata, Halt, NoRoom, PersistedUpdateClient, PersistedUpdateError, PinnedKeys,
    RecordProblem, RecoveredTrust, RecoveryRefusal, ReloadReport, TornTailPastMark, TrustRecord,
    TrustRefusal, TrustStream,
};
pub use publisher::TrustRootSignatures;
pub use registry::{check_production_registry, production_registry, TestSchemeRegistered};
pub use roots::{
    scheme_for, BootstrapRefusal, PinnedKey, PinnedRoots, RootSet, RootsRefusal, UPDATE_ROOT_CLASS,
};
pub use running::{AlreadyRunning, RevocationReport, RevokedLaunch, RunningLaunches};
pub use scheme::Ed25519Scheme;
