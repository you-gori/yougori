//! The shared-subgraph state key (GPU §4.16 lines 882–886):
//!
//! ```text
//! operator/kernel ABI + exact parameter identities + parent state identities
//! + exact inputs + attention/position semantics + dtype/layout
//! + adapter effects + deterministic execution profile + trust scope
//! ```
//!
//! plus the bound runtime seed or operator state of line 888. The key is a
//! domain-separated digest of these typed fields; equal keys are the only route to
//! reuse, and [`StateKeySpec::differences`] names every component two specs disagree on.

use std::collections::BTreeMap;
use std::fmt;

use crate::foundation::ids::{Digest, TrustScope};
use crate::model_memory::identity::{PositionalEncoding, TokenPrefix, VersionedName};

use super::canon::Canon;
use super::parameters::ParameterIdentity;
use super::variant::{
    AdapterEffect, AttentionSemantics, ExecutionProfile, OperatorAbi, SubgraphError, TensorFormat,
};

/// Domain of [`SubgraphStateKey`].
pub const STATE_KEY_DOMAIN: &str = "yougori/model-memory/subgraph/state-key/v1";

/// The exact input of a computation (line 885 "exact inputs"; line 888): the tokens it
/// covers and every token before them, from position 0, plus the digest of any other
/// request input such as an image. A fragment is never identified without its preceding
/// context, so equal text under a different context is a different input.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ExactInput {
    context: TokenPrefix,
    span: TokenPrefix,
    extra: Option<Digest>,
}

impl ExactInput {
    /// `context` is every token before the span, `span` the tokens computed now (at
    /// least one), `extra` the digest of non-token inputs.
    pub fn new(
        context: &[u32],
        span: &[u32],
        extra: Option<Digest>,
    ) -> Result<Self, SubgraphError> {
        if span.is_empty() {
            return Err(SubgraphError::EmptySpan);
        }
        Ok(Self {
            context: TokenPrefix::from_token_ids(context),
            span: TokenPrefix::from_token_ids(span),
            extra,
        })
    }

    /// The whole request as one span: no preceding context.
    pub fn whole(tokens: &[u32]) -> Result<Self, SubgraphError> {
        Self::new(&[], tokens, None)
    }

    pub fn context(&self) -> &TokenPrefix {
        &self.context
    }

    pub fn span(&self) -> &TokenPrefix {
        &self.span
    }

    pub fn extra(&self) -> Option<&Digest> {
        self.extra.as_ref()
    }

    /// The position of the span's first token.
    pub fn first_position(&self) -> u64 {
        self.context.token_count()
    }

    pub fn span_tokens(&self) -> u64 {
        self.span.token_count()
    }

    pub(super) fn write(&self, canon: Canon) -> Canon {
        canon
            .digest(self.context.digest())
            .u64(self.context.token_count())
            .digest(self.span.digest())
            .u64(self.span.token_count())
            .optional_digest(self.extra.as_ref())
    }
}

/// What the runtime actually chose for one request (line 892): the kernel set, and the
/// seed or state of each seeded or stateful operator by operator index (line 888).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeChoices {
    pub kernels: VersionedName,
    pub seeds: BTreeMap<usize, u64>,
    pub operator_states: BTreeMap<usize, Digest>,
}

impl RuntimeChoices {
    /// The declared kernel set, with no seeds or operator states.
    pub fn pinned(kernels: VersionedName) -> Self {
        Self {
            kernels,
            seeds: BTreeMap::new(),
            operator_states: BTreeMap::new(),
        }
    }
}

/// A seed or operator state bound into the key (line 888: "enter the identity").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BoundRuntime {
    Stateless,
    Seed(u64),
    State(Digest),
}

impl BoundRuntime {
    fn write(&self, canon: Canon) -> Canon {
        match self {
            Self::Stateless => canon.tag("stateless"),
            Self::Seed(seed) => canon.tag("seed").u64(*seed),
            Self::State(state) => canon.tag("state").digest(state),
        }
    }
}

/// The typed components of one operator's state key (lines 882–886, 888).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateKeySpec {
    pub operator: OperatorAbi,
    pub parameters: Vec<ParameterIdentity>,
    /// The keys of the states this operator consumes, in order; empty for the first.
    pub parents: Vec<SubgraphStateKey>,
    pub input: ExactInput,
    pub attention: AttentionSemantics,
    pub position: PositionalEncoding,
    pub output: TensorFormat,
    pub adapter_effects: Vec<AdapterEffect>,
    pub profile: ExecutionProfile,
    pub runtime: BoundRuntime,
    pub trust_scope: TrustScope,
}

/// One component of a [`StateKeySpec`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StateKeyComponent {
    OperatorAbi,
    Parameters,
    ParentStates,
    Inputs,
    AttentionSemantics,
    PositionSemantics,
    DtypeLayout,
    AdapterEffects,
    ExecutionProfile,
    /// The bound runtime seed or operator state (line 888).
    RuntimeState,
    TrustScope,
}

impl StateKeyComponent {
    pub const ALL: [Self; 11] = [
        Self::OperatorAbi,
        Self::Parameters,
        Self::ParentStates,
        Self::Inputs,
        Self::AttentionSemantics,
        Self::PositionSemantics,
        Self::DtypeLayout,
        Self::AdapterEffects,
        Self::ExecutionProfile,
        Self::RuntimeState,
        Self::TrustScope,
    ];
}

/// The identity of one exact intermediate state (lines 882–886). Built only by
/// [`StateKeySpec::key`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubgraphStateKey(Digest);

impl SubgraphStateKey {
    pub const fn digest(&self) -> &Digest {
        &self.0
    }
}

impl fmt::Debug for SubgraphStateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SubgraphStateKey({})", self.0.to_hex())
    }
}

impl fmt::Display for SubgraphStateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.to_hex())
    }
}

impl StateKeySpec {
    /// The key: every component in a fixed order under [`STATE_KEY_DOMAIN`].
    pub fn key(&self) -> SubgraphStateKey {
        let canon = self
            .operator
            .write(Canon::new(STATE_KEY_DOMAIN))
            .count(self.parameters.len());
        let canon = self
            .parameters
            .iter()
            .fold(canon, |canon, parameter| canon.digest(parameter.digest()))
            .count(self.parents.len());
        let canon = self
            .parents
            .iter()
            .fold(canon, |canon, parent| canon.digest(parent.digest()));
        let canon = self.input.write(canon);
        let canon = self.attention.write(canon).positional(&self.position);
        let canon = self.output.write(canon).count(self.adapter_effects.len());
        let canon = self
            .adapter_effects
            .iter()
            .fold(canon, |canon, effect| effect.write(canon));
        let canon = self.runtime.write(self.profile.write(canon));
        SubgraphStateKey(canon.scope(&self.trust_scope).finish())
    }

    /// Every component in which `self` and `other` differ, in [`StateKeyComponent::ALL`]
    /// order.
    pub fn differences(&self, other: &Self) -> Vec<StateKeyComponent> {
        [
            (
                StateKeyComponent::OperatorAbi,
                self.operator != other.operator,
            ),
            (
                StateKeyComponent::Parameters,
                self.parameters != other.parameters,
            ),
            (
                StateKeyComponent::ParentStates,
                self.parents != other.parents,
            ),
            (StateKeyComponent::Inputs, self.input != other.input),
            (
                StateKeyComponent::AttentionSemantics,
                self.attention != other.attention,
            ),
            (
                StateKeyComponent::PositionSemantics,
                self.position != other.position,
            ),
            (StateKeyComponent::DtypeLayout, self.output != other.output),
            (
                StateKeyComponent::AdapterEffects,
                self.adapter_effects != other.adapter_effects,
            ),
            (
                StateKeyComponent::ExecutionProfile,
                self.profile != other.profile,
            ),
            (
                StateKeyComponent::RuntimeState,
                self.runtime != other.runtime,
            ),
            (
                StateKeyComponent::TrustScope,
                self.trust_scope != other.trust_scope,
            ),
        ]
        .into_iter()
        .filter_map(|(component, differs)| differs.then_some(component))
        .collect()
    }
}
