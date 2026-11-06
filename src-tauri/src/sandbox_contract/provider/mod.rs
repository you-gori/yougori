//! V07: typed provider executors, conservative provider spend and the sign-in
//! compatibility matrix (docs/combined-gpu-memory-and-vm-sandbox-plan.md: VM part §2.5
//! line 1815, §4.5 lines 1991–2010, §4.6 lines 2012–2028, §9.2 VM-N2, VM-W12, VM-W28,
//! VM-W30; scenarios VM-P12, VM-P30–VM-P33 and VM-P40; VM-D12 and line 57).
//!
//! Tier 0 only (§12.1): pure, synchronous library code. The provider transport and the
//! vault are traits; the tests drive fakes, so they prove the contract and nothing about
//! a real provider, vault, TLS stack or network.
//!
//! This module extends `sandbox_contract::effects` and reuses its effect description,
//! sealed one-use capability, durable state machine, narrow-executor verification
//! ([`NarrowExecutor`](crate::sandbox_contract::effects::NarrowExecutor)), secret classes
//! and opaque credential handles. It adds:
//!
//! - [`ProviderOperation`]: an operation family as a typed contract, not an HTTP verb
//!   (§4.6 line 2024): request schema, one V02 operation route, intent, body encoding,
//!   cost model and response policy. A GET with side effects and a POST that only reads
//!   are both expressible; a GraphQL document with more than one operation and a batch
//!   with an untyped member are refused.
//! - [`ProviderExecutor`]: the executor of §4.5 line 2004. It receives a typed
//!   operation and an opaque credential reference, independently re-verifies delegation,
//!   generations, resource, payload and quota against the effect records, builds the
//!   upstream request itself, has the vault authenticate and send it within an
//!   operation-scoped grant ([`GrantTable`], VM-W28) and returns only the permitted
//!   response representation. It never follows a redirect or broadens a failed request.
//! - [`ResponsePolicy`]: schema validation, and refusal of any response that reflects
//!   the credential, an authorization value or a known fixture secret in a header or the
//!   body (§4.5 line 2008). The scan's coverage is limited and stated in
//!   [`SCAN_COVERAGE`].
//! - [`SpendLedger`]: central, conservative money reservations per provider account
//!   (§2.5 line 1815), kept apart from wire-byte release budgets and model-transfer
//!   budgets (line 57).
//! - [`SignInMatrix`]: typed provider/tool sign-in records (VM-W30, §4.5 line 2010).
//!
//! Claims: a typed operation's contract never hands the credential to the guest and
//! refuses responses that reflect it in the scanned encodings. That is the whole of
//! [`CredentialClaim::NotDeliveredToGuest`]; it says nothing about copies in TLS
//! libraries, the OS, crash dumps or swap (§4.5 line 2006). A credentialed passthrough
//! is a separate, weaker profile and is never labelled zero-exposure.

/// Declares an internally tagged enum whose every variant refuses unknown fields when
/// read. Serde ignores fields after the tag of a unit variant even with
/// `deny_unknown_fields`, so reading goes through a strict twin enum whose unit variants
/// are empty struct variants; the written form is unchanged. This is the pattern of
/// `strict_policy_enum!` in `sandbox_contract/policy/mod.rs`, kept local.
macro_rules! strict_provider_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident tag $tag:literal {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident $({
                    $(
                        $(#[$field_meta:meta])*
                        $field:ident : $ty:ty
                    ),* $(,)?
                })?
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(serde::Serialize)]
        #[serde(tag = $tag, rename_all = "snake_case")]
        $vis enum $name {
            $(
                $(#[$variant_meta])*
                $variant $({ $($(#[$field_meta])* $field : $ty),* })?
            ),*
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                #[derive(serde::Deserialize)]
                #[serde(tag = $tag, rename_all = "snake_case", deny_unknown_fields)]
                enum Strict {
                    $($variant { $($($field : $ty),*)? }),*
                }
                let record = crate::foundation::strict_serde::read_tagged(deserializer, $tag)?;
                let strict = <Strict as serde::Deserialize>::deserialize(record)
                    .map_err(serde::de::Error::custom)?;
                Ok(match strict {
                    $(Strict::$variant { $($($field),*)? } => Self::$variant $({ $($field),* })?),*
                })
            }
        }
    };
}

/// Declares a name type checked against the ids.rs identifier grammar.
macro_rules! provider_name {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Accepts the ids.rs identifier grammar: 1–128 letters, digits, '.', '_', ':'
            /// or '-', starting with a letter or digit.
            pub fn new(
                value: impl Into<String>,
            ) -> Result<Self, crate::foundation::ids::IdError> {
                let value = value.into();
                crate::foundation::ids::validate_identifier(&value)?;
                Ok(Self(value))
            }

            /// The name as text.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self, D::Error> {
                Self::new(<String as serde::Deserialize>::deserialize(deserializer)?)
                    .map_err(serde::de::Error::custom)
            }
        }
    };
}

mod batch;
mod executor;
mod graphql;
mod operation;
mod records;
mod request;
mod response;
mod scan;
mod signin;
mod spend;
mod vault;

#[cfg(test)]
/// The scripted vault and transport the provider tests use; the sandbox vault's tests
/// drive their `CredentialVault` through the same transport.
pub(crate) mod fakes;
#[cfg(test)]
mod tests;

pub use batch::{BatchDocument, BatchMember, BatchRefusal, RawBatch, RawBatchMember};
pub use executor::{
    ExecutionOutcome, ExecutorParts, ProviderExecution, ProviderExecutor, ProviderRefusal,
    UnknownReason,
};
pub use graphql::{
    summarize_document, GraphQlOperationHead, GraphQlParsedKind, GraphQlRefusal, GraphQlSummary,
    MAX_GRAPHQL_DEPTH, MAX_GRAPHQL_DOCUMENT_BYTES,
};
pub use operation::{
    BatchSpec, BodyEncoding, ClaimRefusal, CostModel, CostRefusal, CredentialClaim,
    DestinationBinding, GraphQlKind, GraphQlOperation, MeteredParam, OperationCatalog,
    OperationDraft, OperationFamily, OperationIntent, OperationRefusal, ProviderOperation,
    PROVIDER_ROUTE_DOMAIN,
};
pub use records::{EffectRecordsPort, RecordsSnapshot};
pub use request::{build_upstream, RequestRefusal, UpstreamRequest};
pub use response::{
    evaluate_response, CostReport, FieldSchema, ResponsePolicy, ResponseProfile, ResponseRefusal,
    ResponseSchema, ResponseVerdict, PASSTHROUGH_BODY_FIELD,
};
pub use scan::{
    find_encoded, KnownSecrets, LeakFinding, LeakLocation, LeakReport, LeakSource, ScanEncoding,
    ScanRefusal, MIN_SCANNED_SECRET_BYTES, SCAN_COVERAGE,
};
pub use signin::{
    AccessKind, FlowKind, FlowMechanism, FlowSupport, GuestCredentialAuthorization, ProductId,
    SignInDecision, SignInMatrix, SignInRecord, SignInRefusal, SignInRequest, ToolId,
};
pub use spend::{
    SharedSpendLedger, SpendAccount, SpendHold, SpendHoldState, SpendLedger, SpendRefusal,
    SpendSettlement, SpendStatus,
};
pub use vault::{
    AuthenticatedRequest, CredentialVault, GrantTable, GrantWidening, LookupResult, SecretValue,
    TransportResult, UpstreamReply, UpstreamTransport, VaultFacts, VaultGrant, VaultRefusal,
    VaultScope,
};
