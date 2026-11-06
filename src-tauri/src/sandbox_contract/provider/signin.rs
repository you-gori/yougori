//! The provider/tool sign-in compatibility matrix (VM part §4.5 line 2010; VM-W30).
//!
//! Each record states, for one provider, tool and kind of access (an API key or a
//! subscription, with its product), the credential class of the §4.5 table and how each
//! login, refresh and request flow works and in which sandbox profiles. Decisions follow
//! four rules:
//!
//! - access is preserved: a subscription request never falls back to an API product, or
//!   the reverse, even when a record for the other exists;
//! - a flow that needs a real credential inside the guest refuses the strict
//!   (zero-exposure) profile, and in the standard profile needs a separate explicit
//!   authorization; a long-lived credential is never placed in the guest, so it needs a
//!   precisely scoped alternative;
//! - a brokered flow runs only through named typed operations: there is no generic OAuth
//!   rewriting, and an unverified flow is refused;
//! - an unknown provider, tool, access or flow is refused.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::operation::{CredentialClaim, OperationCatalog};
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{Digest, MonotonicTime};
use crate::sandbox_contract::effects::{
    ExposureProfile, GuestExposure, OperationKey, ProviderId, SecretClass,
};

provider_name!(
    /// A tool that signs in to a provider, such as a coding agent's CLI.
    ToolId
);
provider_name!(
    /// A provider product: a paid API product or a subscription plan.
    ProductId
);

strict_provider_enum! {
    /// How a user has access to a provider (VM-W30: API versus subscription).
    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum AccessKind tag "access" {
        ApiKey { product: ProductId },
        Subscription { product: ProductId },
    }
}

/// A sign-in flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowKind {
    Login,
    Refresh,
    Request,
}

/// How a flow handles the credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowMechanism {
    /// The vault holds the credential and typed executor operations use it.
    BrokeredByExecutor,
    /// The user completes the flow on the host and the result goes to the vault.
    HostInteractive,
    /// The tool inside the guest needs the real credential.
    GuestHeldCredential,
}

/// How one flow is supported.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowSupport {
    pub mechanism: FlowMechanism,
    pub credential_class: SecretClass,
    /// The typed operations a brokered flow runs through; required for one.
    pub operations: BTreeSet<OperationKey>,
    /// The sandbox profiles the flow supports.
    pub profiles: BTreeSet<ExposureProfile>,
    /// Evidence that the flow was verified with the real tool and provider, by digest.
    pub verified: Option<Digest>,
}

/// One provider/tool/access record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignInRecord {
    pub provider: ProviderId,
    pub tool: ToolId,
    pub access: AccessKind,
    /// The class of the credential the access rests on (§4.5 table).
    pub credential_class: SecretClass,
    pub flows: BTreeMap<FlowKind, FlowSupport>,
}

/// The separate explicit authorization a guest-held credential needs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestCredentialAuthorization {
    pub provider: ProviderId,
    pub tool: ToolId,
    pub access: AccessKind,
    pub flow: FlowKind,
    pub class: SecretClass,
    /// The user's decision, by digest.
    pub decision: Digest,
    pub clock: ClockSession,
    pub expires_at: MonotonicTime,
}

/// A sign-in to decide.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignInRequest {
    pub provider: ProviderId,
    pub tool: ToolId,
    /// The access the user has; it is never substituted.
    pub access: AccessKind,
    pub flow: FlowKind,
    pub profile: ExposureProfile,
    pub authorization: Option<GuestCredentialAuthorization>,
}

/// An accepted sign-in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignInDecision {
    pub provider: ProviderId,
    pub tool: ToolId,
    /// Always the access requested.
    pub access: AccessKind,
    pub flow: FlowKind,
    pub mechanism: FlowMechanism,
    pub profile: ExposureProfile,
    pub claim: CredentialClaim,
    pub operations: BTreeSet<OperationKey>,
}

strict_provider_enum! {
    /// Why a record or a sign-in was refused.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum SignInRefusal tag "refusal" {
        UnknownProvider,
        UnknownTool,
        /// No record for this access; another access is never substituted for it.
        AccessNotSupported { requested: AccessKind, substitution_refused: bool },
        UnsupportedFlow { flow: FlowKind },
        UnverifiedFlow { flow: FlowKind },
        /// The flow needs a real credential in the guest, which the strict profile refuses.
        ZeroExposureUnsupported { flow: FlowKind },
        /// A long-lived credential is never placed in the guest; a precisely scoped
        /// alternative is needed.
        NeedsScopedAlternative { flow: FlowKind },
        ProfileNotSupported { flow: FlowKind, profile: ExposureProfile },
        NeedsSeparateAuthorization { flow: FlowKind },
        AuthorizationMismatch,
        AuthorizationExpired,
        ClassNotExternal { class: SecretClass },
        NoFlows,
        MechanismNotForFlow { flow: FlowKind },
        /// A brokered flow must name typed operations; generic OAuth rewriting is refused.
        GenericRewriteRefused { flow: FlowKind },
        OperationOtherProvider { flow: FlowKind },
        ProfileClaimUnsupported { flow: FlowKind, profile: ExposureProfile },
        DuplicateRecord,
        UnknownOperation { operation: OperationKey },
    }
}

impl fmt::Display for SignInRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownProvider => f.write_str("the provider is not in the sign-in matrix"),
            Self::UnknownTool => {
                f.write_str("the tool is not in the sign-in matrix for this provider")
            }
            Self::AccessNotSupported {
                requested,
                substitution_refused,
            } => {
                write!(f, "no supported sign-in for {requested:?}")?;
                if *substitution_refused {
                    f.write_str("; another access kind exists but is never substituted")?;
                }
                Ok(())
            }
            Self::UnsupportedFlow { flow } => write!(f, "the {flow:?} flow is not supported"),
            Self::UnverifiedFlow { flow } => write!(f, "the {flow:?} flow is not verified"),
            Self::ZeroExposureUnsupported { flow } => write!(
                f,
                "the {flow:?} flow needs a real credential in the guest; the strict \
                 zero-exposure profile refuses it"
            ),
            Self::NeedsScopedAlternative { flow } => write!(
                f,
                "the {flow:?} flow would place a long-lived credential in the guest; use a \
                 precisely scoped alternative"
            ),
            Self::ProfileNotSupported { flow, profile } => {
                write!(
                    f,
                    "the {flow:?} flow does not support the {profile:?} profile"
                )
            }
            Self::NeedsSeparateAuthorization { flow } => write!(
                f,
                "the {flow:?} flow places a credential in the guest and needs a separate \
                 explicit authorization"
            ),
            Self::AuthorizationMismatch => f.write_str("the authorization is for another sign-in"),
            Self::AuthorizationExpired => f.write_str("the authorization expired"),
            Self::ClassNotExternal { class } => {
                write!(f, "a {class:?} is not a provider credential")
            }
            Self::NoFlows => f.write_str("the record supports no flow"),
            Self::MechanismNotForFlow { flow } => {
                write!(f, "the mechanism does not fit the {flow:?} flow")
            }
            Self::GenericRewriteRefused { flow } => write!(
                f,
                "the {flow:?} flow must run through named typed operations; generic OAuth \
                 rewriting is refused"
            ),
            Self::OperationOtherProvider { flow } => {
                write!(f, "the {flow:?} flow names another provider's operation")
            }
            Self::ProfileClaimUnsupported { flow, profile } => write!(
                f,
                "the {flow:?} flow cannot support the {profile:?} profile with its mechanism \
                 and credential class"
            ),
            Self::DuplicateRecord => f.write_str("the record already exists"),
            Self::UnknownOperation { .. } => f.write_str("a flow names an unregistered operation"),
        }
    }
}

impl std::error::Error for SignInRefusal {}

/// The profiles a flow can support given its mechanism and credential class.
fn possible_profiles(mechanism: FlowMechanism, class: SecretClass) -> BTreeSet<ExposureProfile> {
    [ExposureProfile::Strict, ExposureProfile::Standard]
        .into_iter()
        .filter(|profile| match mechanism {
            FlowMechanism::BrokeredByExecutor | FlowMechanism::HostInteractive => true,
            FlowMechanism::GuestHeldCredential => matches!(
                class.guest_exposure(*profile),
                GuestExposure::WithExplicitTerms | GuestExposure::Allowed
            ),
        })
        .collect()
}

impl SignInRecord {
    fn check(&self) -> Result<(), SignInRefusal> {
        if !self.credential_class.is_external_credential() {
            return Err(SignInRefusal::ClassNotExternal {
                class: self.credential_class,
            });
        }
        if self.flows.is_empty() {
            return Err(SignInRefusal::NoFlows);
        }
        for (flow, support) in &self.flows {
            let flow = *flow;
            if !support.credential_class.is_external_credential() {
                return Err(SignInRefusal::ClassNotExternal {
                    class: support.credential_class,
                });
            }
            match support.mechanism {
                FlowMechanism::HostInteractive if flow == FlowKind::Request => {
                    return Err(SignInRefusal::MechanismNotForFlow { flow })
                }
                FlowMechanism::BrokeredByExecutor if support.operations.is_empty() => {
                    return Err(SignInRefusal::GenericRewriteRefused { flow })
                }
                _ => {}
            }
            if support
                .operations
                .iter()
                .any(|operation| operation.provider != self.provider)
            {
                return Err(SignInRefusal::OperationOtherProvider { flow });
            }
            if support.profiles.is_empty() {
                return Err(SignInRefusal::NoFlows);
            }
            let possible = possible_profiles(support.mechanism, support.credential_class);
            if let Some(profile) = support
                .profiles
                .iter()
                .find(|profile| !possible.contains(profile))
            {
                return Err(SignInRefusal::ProfileClaimUnsupported {
                    flow,
                    profile: *profile,
                });
            }
        }
        Ok(())
    }
}

type RecordKey = (ProviderId, ToolId, AccessKind);

/// The sign-in compatibility matrix (VM-W30).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignInMatrix {
    records: BTreeMap<RecordKey, SignInRecord>,
}

impl SignInMatrix {
    /// An empty matrix.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a checked record.
    pub fn insert(&mut self, record: SignInRecord) -> Result<(), SignInRefusal> {
        record.check()?;
        let key = (
            record.provider.clone(),
            record.tool.clone(),
            record.access.clone(),
        );
        if self.records.contains_key(&key) {
            return Err(SignInRefusal::DuplicateRecord);
        }
        self.records.insert(key, record);
        Ok(())
    }

    /// Every record, in key order.
    pub fn records(&self) -> impl Iterator<Item = &SignInRecord> {
        self.records.values()
    }

    /// Checks that every brokered flow names registered typed operations, none of them a
    /// credentialed passthrough.
    pub fn check_against(&self, catalog: &OperationCatalog) -> Result<(), SignInRefusal> {
        for record in self.records.values() {
            for (flow, support) in &record.flows {
                for operation in &support.operations {
                    let found =
                        catalog
                            .get(operation)
                            .map_err(|_| SignInRefusal::UnknownOperation {
                                operation: operation.clone(),
                            })?;
                    if found.claim() != CredentialClaim::NotDeliveredToGuest {
                        return Err(SignInRefusal::GenericRewriteRefused { flow: *flow });
                    }
                }
            }
        }
        Ok(())
    }

    /// Decides a sign-in at `now` on `session`.
    pub fn decide(
        &self,
        request: &SignInRequest,
        now: MonotonicTime,
        session: ClockSession,
    ) -> Result<SignInDecision, SignInRefusal> {
        if !self
            .records
            .keys()
            .any(|(provider, _, _)| provider == &request.provider)
        {
            return Err(SignInRefusal::UnknownProvider);
        }
        if !self
            .records
            .keys()
            .any(|(provider, tool, _)| provider == &request.provider && tool == &request.tool)
        {
            return Err(SignInRefusal::UnknownTool);
        }
        let key = (
            request.provider.clone(),
            request.tool.clone(),
            request.access.clone(),
        );
        let record = self
            .records
            .get(&key)
            .ok_or_else(|| SignInRefusal::AccessNotSupported {
                requested: request.access.clone(),
                substitution_refused: true,
            })?;
        let flow = request.flow;
        let support = record
            .flows
            .get(&flow)
            .ok_or(SignInRefusal::UnsupportedFlow { flow })?;
        if support.verified.is_none() {
            return Err(SignInRefusal::UnverifiedFlow { flow });
        }
        let guest_held = support.mechanism == FlowMechanism::GuestHeldCredential;
        if guest_held
            && support
                .credential_class
                .guest_exposure(ExposureProfile::Standard)
                == GuestExposure::Never
        {
            return Err(SignInRefusal::NeedsScopedAlternative { flow });
        }
        if !support.profiles.contains(&request.profile) {
            return Err(
                if guest_held && request.profile == ExposureProfile::Strict {
                    SignInRefusal::ZeroExposureUnsupported { flow }
                } else {
                    SignInRefusal::ProfileNotSupported {
                        flow,
                        profile: request.profile,
                    }
                },
            );
        }
        let claim = if guest_held {
            let authorization = request
                .authorization
                .as_ref()
                .ok_or(SignInRefusal::NeedsSeparateAuthorization { flow })?;
            if authorization.provider != request.provider
                || authorization.tool != request.tool
                || authorization.access != request.access
                || authorization.flow != flow
                || authorization.class != support.credential_class
            {
                return Err(SignInRefusal::AuthorizationMismatch);
            }
            if authorization.clock != session || now >= authorization.expires_at {
                return Err(SignInRefusal::AuthorizationExpired);
            }
            CredentialClaim::GuestHeld {
                authorization: authorization.decision,
            }
        } else {
            CredentialClaim::NotDeliveredToGuest
        };
        Ok(SignInDecision {
            provider: request.provider.clone(),
            tool: request.tool.clone(),
            access: request.access.clone(),
            flow,
            mechanism: support.mechanism,
            profile: request.profile,
            claim,
            operations: support.operations.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::digest;
    use crate::sandbox_contract::effects::OperationName;

    const SESSION: ClockSession = ClockSession::from_uuid(uuid::Uuid::from_u128(0x5160));
    const NOW: MonotonicTime = MonotonicTime::from_nanos(1_000);

    fn provider() -> ProviderId {
        ProviderId::new("modelco").unwrap()
    }

    fn tool() -> ToolId {
        ToolId::new("agent-cli").unwrap()
    }

    fn api() -> AccessKind {
        AccessKind::ApiKey {
            product: ProductId::new("modelco-api").unwrap(),
        }
    }

    fn subscription() -> AccessKind {
        AccessKind::Subscription {
            product: ProductId::new("modelco-pro").unwrap(),
        }
    }

    fn operation(name: &str) -> OperationKey {
        OperationKey {
            provider: provider(),
            operation: OperationName::new(name).unwrap(),
            contract_version: 1,
        }
    }

    fn evidence() -> Option<Digest> {
        Some(digest("yougori/test/signin-evidence/v1", &[b"verified"]))
    }

    fn brokered(class: SecretClass) -> FlowSupport {
        FlowSupport {
            mechanism: FlowMechanism::BrokeredByExecutor,
            credential_class: class,
            operations: BTreeSet::from([operation("create_message")]),
            profiles: BTreeSet::from([ExposureProfile::Strict, ExposureProfile::Standard]),
            verified: evidence(),
        }
    }

    fn guest_held(class: SecretClass, profiles: &[ExposureProfile]) -> FlowSupport {
        FlowSupport {
            mechanism: FlowMechanism::GuestHeldCredential,
            credential_class: class,
            operations: BTreeSet::new(),
            profiles: profiles.iter().copied().collect(),
            verified: evidence(),
        }
    }

    fn host_login(class: SecretClass) -> FlowSupport {
        FlowSupport {
            mechanism: FlowMechanism::HostInteractive,
            credential_class: class,
            operations: BTreeSet::new(),
            profiles: BTreeSet::from([ExposureProfile::Strict, ExposureProfile::Standard]),
            verified: evidence(),
        }
    }

    /// API access is fully brokered; the subscription logs in on the host, refreshes on
    /// the host, and its tool needs a short-lived token inside the guest for requests.
    fn matrix() -> SignInMatrix {
        let mut matrix = SignInMatrix::new();
        matrix
            .insert(SignInRecord {
                provider: provider(),
                tool: tool(),
                access: api(),
                credential_class: SecretClass::LongLivedProviderCredential,
                flows: BTreeMap::from([(
                    FlowKind::Request,
                    brokered(SecretClass::LongLivedProviderCredential),
                )]),
            })
            .unwrap();
        matrix
            .insert(SignInRecord {
                provider: provider(),
                tool: tool(),
                access: subscription(),
                credential_class: SecretClass::ShortLivedCapability,
                flows: BTreeMap::from([
                    (
                        FlowKind::Login,
                        host_login(SecretClass::LongLivedProviderCredential),
                    ),
                    (
                        FlowKind::Refresh,
                        host_login(SecretClass::LongLivedProviderCredential),
                    ),
                    (
                        FlowKind::Request,
                        guest_held(
                            SecretClass::ShortLivedCapability,
                            &[ExposureProfile::Standard],
                        ),
                    ),
                ]),
            })
            .unwrap();
        matrix
    }

    fn request(access: AccessKind, flow: FlowKind, profile: ExposureProfile) -> SignInRequest {
        SignInRequest {
            provider: provider(),
            tool: tool(),
            access,
            flow,
            profile,
            authorization: None,
        }
    }

    fn authorization() -> GuestCredentialAuthorization {
        GuestCredentialAuthorization {
            provider: provider(),
            tool: tool(),
            access: subscription(),
            flow: FlowKind::Request,
            class: SecretClass::ShortLivedCapability,
            decision: digest("yougori/test/decision/v1", &[b"user said yes"]),
            clock: SESSION,
            expires_at: MonotonicTime::from_nanos(5_000),
        }
    }

    #[test]
    fn api_access_is_brokered_in_the_strict_profile_and_keeps_its_product() {
        let decision = matrix()
            .decide(
                &request(api(), FlowKind::Request, ExposureProfile::Strict),
                NOW,
                SESSION,
            )
            .unwrap();
        assert_eq!(decision.access, api());
        assert_eq!(decision.mechanism, FlowMechanism::BrokeredByExecutor);
        assert_eq!(decision.claim, CredentialClaim::NotDeliveredToGuest);
        assert!(decision.claim.zero_exposure_label().is_ok());
        assert_eq!(
            decision.operations,
            BTreeSet::from([operation("create_message")])
        );
    }

    #[test]
    fn a_subscription_is_never_replaced_by_the_paid_api_product() {
        let matrix = matrix();
        // The subscription's request flow needs a guest credential: in the strict
        // profile it is refused, and the API record that would work is not used.
        assert_eq!(
            matrix.decide(
                &request(subscription(), FlowKind::Request, ExposureProfile::Strict),
                NOW,
                SESSION
            ),
            Err(SignInRefusal::ZeroExposureUnsupported {
                flow: FlowKind::Request
            })
        );
        // A subscription with no record at all is refused, never mapped to the API one.
        let other_plan = AccessKind::Subscription {
            product: ProductId::new("modelco-team").unwrap(),
        };
        assert_eq!(
            matrix.decide(
                &request(
                    other_plan.clone(),
                    FlowKind::Request,
                    ExposureProfile::Strict
                ),
                NOW,
                SESSION
            ),
            Err(SignInRefusal::AccessNotSupported {
                requested: other_plan,
                substitution_refused: true
            })
        );
        // Host login of the subscription works in the strict profile and stays a
        // subscription.
        let login = matrix
            .decide(
                &request(subscription(), FlowKind::Login, ExposureProfile::Strict),
                NOW,
                SESSION,
            )
            .unwrap();
        assert_eq!(login.access, subscription());
        assert_eq!(login.claim, CredentialClaim::NotDeliveredToGuest);
        // And the API record has no login flow: refused, not borrowed.
        assert_eq!(
            matrix.decide(
                &request(api(), FlowKind::Login, ExposureProfile::Standard),
                NOW,
                SESSION
            ),
            Err(SignInRefusal::UnsupportedFlow {
                flow: FlowKind::Login
            })
        );
    }

    #[test]
    fn a_guest_credential_needs_a_separate_explicit_authorization() {
        let matrix = matrix();
        let mut standard = request(subscription(), FlowKind::Request, ExposureProfile::Standard);
        assert_eq!(
            matrix.decide(&standard, NOW, SESSION),
            Err(SignInRefusal::NeedsSeparateAuthorization {
                flow: FlowKind::Request
            })
        );
        standard.authorization = Some(authorization());
        let decision = matrix.decide(&standard, NOW, SESSION).unwrap();
        assert_eq!(
            decision.claim,
            CredentialClaim::GuestHeld {
                authorization: authorization().decision
            }
        );
        assert!(decision.claim.zero_exposure_label().is_err());
        assert!(!decision.claim.allowed_in(ExposureProfile::Strict));
        // An authorization for another flow, class or access does not carry over.
        let mut other = authorization();
        other.class = SecretClass::SignedDownloadUrl;
        standard.authorization = Some(other);
        assert_eq!(
            matrix.decide(&standard, NOW, SESSION),
            Err(SignInRefusal::AuthorizationMismatch)
        );
        standard.authorization = Some(authorization());
        assert_eq!(
            matrix.decide(&standard, MonotonicTime::from_nanos(5_000), SESSION),
            Err(SignInRefusal::AuthorizationExpired)
        );
    }

    #[test]
    fn a_long_lived_credential_is_never_placed_in_the_guest() {
        // Declaring guest support for a long-lived key is refused when the record is
        // added, in either profile.
        for profile in [ExposureProfile::Strict, ExposureProfile::Standard] {
            let mut matrix = SignInMatrix::new();
            assert_eq!(
                matrix.insert(SignInRecord {
                    provider: provider(),
                    tool: ToolId::new("raw-cli").unwrap(),
                    access: api(),
                    credential_class: SecretClass::LongLivedProviderCredential,
                    flows: BTreeMap::from([(
                        FlowKind::Request,
                        guest_held(SecretClass::LongLivedProviderCredential, &[profile]),
                    )]),
                }),
                Err(SignInRefusal::ProfileClaimUnsupported {
                    flow: FlowKind::Request,
                    profile
                })
            );
        }
        // A strict-profile claim for a guest-held short-lived token is refused too.
        let mut matrix = SignInMatrix::new();
        assert_eq!(
            matrix.insert(SignInRecord {
                provider: provider(),
                tool: tool(),
                access: subscription(),
                credential_class: SecretClass::ShortLivedCapability,
                flows: BTreeMap::from([(
                    FlowKind::Request,
                    guest_held(
                        SecretClass::ShortLivedCapability,
                        &[ExposureProfile::Strict]
                    ),
                )]),
            }),
            Err(SignInRefusal::ProfileClaimUnsupported {
                flow: FlowKind::Request,
                profile: ExposureProfile::Strict
            })
        );
        // A signed download URL is a bearer credential: never in the guest in the strict
        // profile either.
        assert_eq!(
            matrix.insert(SignInRecord {
                provider: provider(),
                tool: tool(),
                access: subscription(),
                credential_class: SecretClass::SignedDownloadUrl,
                flows: BTreeMap::from([(
                    FlowKind::Request,
                    guest_held(SecretClass::SignedDownloadUrl, &[ExposureProfile::Strict]),
                )]),
            }),
            Err(SignInRefusal::ProfileClaimUnsupported {
                flow: FlowKind::Request,
                profile: ExposureProfile::Strict
            })
        );
    }

    #[test]
    fn generic_oauth_rewriting_and_unverified_flows_are_refused() {
        let mut matrix = SignInMatrix::new();
        let mut generic = brokered(SecretClass::ShortLivedCapability);
        generic.operations.clear();
        assert_eq!(
            matrix.insert(SignInRecord {
                provider: provider(),
                tool: tool(),
                access: subscription(),
                credential_class: SecretClass::ShortLivedCapability,
                flows: BTreeMap::from([(FlowKind::Refresh, generic)]),
            }),
            Err(SignInRefusal::GenericRewriteRefused {
                flow: FlowKind::Refresh
            })
        );
        let mut unverified = brokered(SecretClass::LongLivedProviderCredential);
        unverified.verified = None;
        matrix
            .insert(SignInRecord {
                provider: provider(),
                tool: tool(),
                access: api(),
                credential_class: SecretClass::LongLivedProviderCredential,
                flows: BTreeMap::from([(FlowKind::Request, unverified)]),
            })
            .unwrap();
        assert_eq!(
            matrix.decide(
                &request(api(), FlowKind::Request, ExposureProfile::Strict),
                NOW,
                SESSION
            ),
            Err(SignInRefusal::UnverifiedFlow {
                flow: FlowKind::Request
            })
        );
        // A brokered flow naming an operation the catalog lacks is refused.
        assert_eq!(
            matrix.check_against(&OperationCatalog::new()),
            Err(SignInRefusal::UnknownOperation {
                operation: operation("create_message")
            })
        );
    }

    #[test]
    fn unknown_providers_tools_and_bad_records_are_refused() {
        let matrix = matrix();
        let mut unknown = request(api(), FlowKind::Request, ExposureProfile::Strict);
        unknown.provider = ProviderId::new("elsewhere").unwrap();
        assert_eq!(
            matrix.decide(&unknown, NOW, SESSION),
            Err(SignInRefusal::UnknownProvider)
        );
        let mut unknown = request(api(), FlowKind::Request, ExposureProfile::Strict);
        unknown.tool = ToolId::new("other-tool").unwrap();
        assert_eq!(
            matrix.decide(&unknown, NOW, SESSION),
            Err(SignInRefusal::UnknownTool)
        );
        let mut matrix = matrix.clone();
        let existing = matrix.records().next().unwrap().clone();
        assert_eq!(matrix.insert(existing), Err(SignInRefusal::DuplicateRecord));
        let record = |class, flows| SignInRecord {
            provider: provider(),
            tool: ToolId::new("t2").unwrap(),
            access: api(),
            credential_class: class,
            flows,
        };
        assert_eq!(
            matrix.insert(record(SecretClass::SandboxLocalSecret, BTreeMap::new())),
            Err(SignInRefusal::ClassNotExternal {
                class: SecretClass::SandboxLocalSecret
            })
        );
        assert_eq!(
            matrix.insert(record(
                SecretClass::LongLivedProviderCredential,
                BTreeMap::new()
            )),
            Err(SignInRefusal::NoFlows)
        );
        assert_eq!(
            matrix.insert(record(
                SecretClass::LongLivedProviderCredential,
                BTreeMap::from([(
                    FlowKind::Request,
                    host_login(SecretClass::LongLivedProviderCredential)
                )])
            )),
            Err(SignInRefusal::MechanismNotForFlow {
                flow: FlowKind::Request
            })
        );
        let mut foreign = brokered(SecretClass::LongLivedProviderCredential);
        foreign.operations = BTreeSet::from([OperationKey {
            provider: ProviderId::new("elsewhere").unwrap(),
            operation: OperationName::new("create_message").unwrap(),
            contract_version: 1,
        }]);
        assert_eq!(
            matrix.insert(record(
                SecretClass::LongLivedProviderCredential,
                BTreeMap::from([(FlowKind::Request, foreign)])
            )),
            Err(SignInRefusal::OperationOtherProvider {
                flow: FlowKind::Request
            })
        );
    }

    #[test]
    fn records_and_decisions_round_trip_strictly() {
        let matrix = matrix();
        for record in matrix.records() {
            let json = serde_json::to_string(record).unwrap();
            assert_eq!(
                &serde_json::from_str::<SignInRecord>(&json).unwrap(),
                record
            );
        }
        let decision = matrix
            .decide(
                &request(api(), FlowKind::Request, ExposureProfile::Strict),
                NOW,
                SESSION,
            )
            .unwrap();
        let json = serde_json::to_string(&decision).unwrap();
        assert_eq!(
            serde_json::from_str::<SignInDecision>(&json).unwrap(),
            decision
        );
        assert!(serde_json::from_str::<AccessKind>(
            r#"{"access":"api_key","product":"p","extra":1}"#
        )
        .is_err());
    }
}
