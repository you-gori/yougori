//! The separately typed shared-subgraph state contract (GPU §4.16 line 894).
//!
//! A [`SubgraphState`] holds the exact output of the leading operators of one variant for
//! one request. It is produced only at a profitable branch boundary ([`produce_state`])
//! and consumed only through [`reuse_state`], which:
//!
//! - runs the §3.9 session identity check: the request's session must be a session of
//!   the consuming variant (execution identity, unmerged adapter, positional encoding,
//!   tenant and authority), so a shared prefix never stands in for the full model;
//! - shares only inside one trust scope, and outside the producing parent execution only
//!   under T07's scoped grant (S3.3);
//! - recomputes the consumer's own state keys and accepts the state only for the
//!   operators whose keys are equal; a state that claims more is refused whole, so an
//!   incompatible state is never relabelled as reusable.
//!
//! Nothing here produces or accepts session KV: full-model KV reuse stays with
//! [`crate::model_memory::adapters::kv::check_kv_reuse`] (§3.9 line 636), and a
//! [`SharedPrefixReuse`] cannot become a KV reuse grant.

use crate::foundation::ids::{Clock, ContentKey, MonotonicTime, TenantId, TrustScope};
use crate::model_memory::identity::{
    check_grant, ArtifactIdentity, AuthorityBinding, FidelityConfiguration, GrantNeed, GrantedUse,
    ScopedGrant, SessionSpec,
};

use super::eligibility::{
    check_state_reuse, ExactnessCriterion, ReuseMode, ReuseRefusal, SessionComponent,
};
use super::key::{ExactInput, RuntimeChoices, StateKeySpec, SubgraphStateKey};
use super::profit::ProfitableBoundary;
use super::variant::{ImmutableVariant, VariantIdentity};

/// One request to run a variant, with the authority it runs under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubgraphRequest {
    pub input: ExactInput,
    pub runtime: RuntimeChoices,
    pub exactness: ExactnessCriterion,
    pub fidelity: FidelityConfiguration,
    pub tenant: TenantId,
    /// The parent execution and authorization epoch the request runs under (S3.1).
    pub authority: AuthorityBinding,
    pub trust_scope: TrustScope,
    /// The request's session (§3.2 item 6), checked against the variant (§3.9).
    pub session: SessionSpec,
}

/// §3.9 and line 894: the request's session must be a session of `variant`.
pub fn check_session(
    variant: &ImmutableVariant,
    request: &SubgraphRequest,
) -> Result<(), ReuseRefusal> {
    let session = &request.session;
    let mismatch = [
        (
            SessionComponent::Execution,
            session.execution != variant.execution(),
        ),
        (
            SessionComponent::Adapter,
            session.adapter != variant.adapter(),
        ),
        (
            SessionComponent::PositionalEncoding,
            session.positional_encoding != *variant.position(),
        ),
        (SessionComponent::Tenant, session.tenant != request.tenant),
        (
            SessionComponent::Authority,
            session.authority != request.authority,
        ),
    ]
    .into_iter()
    .find_map(|(component, differs)| differs.then_some(component));
    match mismatch {
        Some(component) => Err(ReuseRefusal::SessionMismatch { component }),
        None => Ok(()),
    }
}

/// The exact output of a variant's leading operators for one request (line 894). Made
/// only by [`produce_state`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubgraphState {
    specs: Vec<StateKeySpec>,
    keys: Vec<SubgraphStateKey>,
    producer: VariantIdentity,
    producer_artifact: ArtifactIdentity,
    owner: TenantId,
    authority: AuthorityBinding,
    trust_scope: TrustScope,
    activation: ContentKey,
}

impl SubgraphState {
    /// How many leading operators the state covers.
    pub fn operators(&self) -> usize {
        self.keys.len()
    }

    /// The state key of each covered operator.
    pub fn keys(&self) -> &[SubgraphStateKey] {
        &self.keys
    }

    /// The key at the boundary: the last covered operator's output.
    pub fn boundary_key(&self) -> Option<SubgraphStateKey> {
        self.keys.last().copied()
    }

    pub fn producer(&self) -> VariantIdentity {
        self.producer
    }

    pub fn owner(&self) -> &TenantId {
        &self.owner
    }

    pub fn authority(&self) -> &AuthorityBinding {
        &self.authority
    }

    pub fn trust_scope(&self) -> &TrustScope {
        &self.trust_scope
    }

    /// The content key of the boundary activation as produced.
    pub fn activation(&self) -> ContentKey {
        self.activation
    }
}

/// Records the exact state `variant` produced for `request` up to the profitable branch
/// boundary `boundary` (line 890), with `activation` the content key of the boundary
/// output. Refused unless the boundary was planned for this variant, the request's
/// session is the variant's (§3.9), the request runs in the variant's trust scope and
/// every eligibility rule holds.
pub fn produce_state(
    variant: &ImmutableVariant,
    request: &SubgraphRequest,
    boundary: &ProfitableBoundary,
    activation: ContentKey,
) -> Result<SubgraphState, ReuseRefusal> {
    let mode = ReuseMode::new(&request.exactness, &request.fidelity)?;
    let producer = variant.identity();
    if !boundary.variants().contains(&producer)
        || boundary.operators() == 0
        || boundary.operators() > variant.operators().len()
    {
        return Err(ReuseRefusal::NotAPlannedBoundary);
    }
    check_session(variant, request)?;
    if request.trust_scope != *variant.trust_scope() {
        return Err(ReuseRefusal::DifferentTrustScope);
    }
    let specs = variant.state_key_specs(
        &request.input,
        &request.runtime,
        &mode,
        boundary.operators(),
    )?;
    let keys = specs.iter().map(StateKeySpec::key).collect();
    Ok(SubgraphState {
        specs,
        keys,
        producer,
        producer_artifact: variant.artifact(),
        owner: request.tenant.clone(),
        authority: request.authority.clone(),
        trust_scope: request.trust_scope,
        activation,
    })
}

/// Permission to start a consumer after a shared prefix: the operators it may skip and
/// the activation it starts from. Made only by [`reuse_state`]; it carries no KV and no
/// session identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedPrefixReuse {
    operators: usize,
    boundary_key: SubgraphStateKey,
    activation: ContentKey,
    /// The grant's expiry when a grant authorized the reuse.
    valid_until: Option<MonotonicTime>,
}

impl SharedPrefixReuse {
    /// The leading operators the consumer skips; it runs the rest itself.
    pub fn operators(&self) -> usize {
        self.operators
    }

    pub fn boundary_key(&self) -> SubgraphStateKey {
        self.boundary_key
    }

    pub fn activation(&self) -> ContentKey {
        self.activation
    }

    pub fn valid_until(&self) -> Option<MonotonicTime> {
        self.valid_until
    }

    /// Checks a received activation against the one the state names.
    pub fn verify_received(&self, received: &ContentKey) -> Result<(), ReuseRefusal> {
        if *received == self.activation {
            Ok(())
        } else {
            Err(ReuseRefusal::ActivationMismatch)
        }
    }
}

/// Authorizes `request` to use a state produced under another authority (S3.3, S3.1).
fn authorize(
    state: &SubgraphState,
    request: &SubgraphRequest,
    grant: Option<&ScopedGrant>,
    now: MonotonicTime,
) -> Result<Option<MonotonicTime>, ReuseRefusal> {
    if state.authority == request.authority && state.owner == request.tenant {
        return Ok(None);
    }
    if state.authority.parent() == request.authority.parent() {
        return Err(ReuseRefusal::AuthorityChanged);
    }
    let need = GrantNeed {
        owner: &state.owner,
        grantee: &request.tenant,
        artifact: &state.producer_artifact,
        scope: &state.trust_scope,
        granted_use: GrantedUse::ShareIntermediateState,
    };
    check_grant(grant, &need, now)
        .map(Some)
        .map_err(ReuseRefusal::Unauthorized)
}

/// Lets `consumer` reuse `state` for `request` (line 894). In order: the request must
/// ask for exact reuse; its session must be the consumer's (§3.9); the state, request
/// and consumer must share one trust scope; the request must run under the producing
/// authority or hold the owner's scoped grant to share intermediate state of the
/// producing artifact (S3.3; sharing the state is not sharing device memory); and the consumer's own state keys must equal the state's for every
/// operator it covers. A state covering more operators than are provably equal is
/// refused whole.
pub fn reuse_state(
    state: &SubgraphState,
    consumer: &ImmutableVariant,
    request: &SubgraphRequest,
    grant: Option<&ScopedGrant>,
    clock: &dyn Clock,
) -> Result<SharedPrefixReuse, ReuseRefusal> {
    let mode = ReuseMode::new(&request.exactness, &request.fidelity)?;
    check_session(consumer, request)?;
    if state.trust_scope != request.trust_scope || request.trust_scope != *consumer.trust_scope() {
        return Err(ReuseRefusal::DifferentTrustScope);
    }
    let valid_until = authorize(state, request, grant, clock.now())?;
    let claimed = state.operators();
    let mine = consumer.state_key_specs(&request.input, &request.runtime, &mode, claimed)?;
    for (index, stored) in state.specs.iter().enumerate() {
        let refusal = match mine.get(index) {
            Some(spec) => match check_state_reuse(stored, spec, index) {
                Ok(_) => continue,
                Err(refusal) => refusal,
            },
            None => ReuseRefusal::KeyMismatch {
                operator: index,
                components: Vec::new(),
            },
        };
        return Err(if index == 0 {
            refusal
        } else {
            ReuseRefusal::ClaimsBeyondSharedPrefix {
                claimed,
                provable: index,
                first_mismatch: Box::new(refusal),
            }
        });
    }
    let boundary_key = state
        .boundary_key()
        .ok_or(ReuseRefusal::NotAPlannedBoundary)?;
    Ok(SharedPrefixReuse {
        operators: claimed,
        boundary_key,
        activation: state.activation,
        valid_until,
    })
}
