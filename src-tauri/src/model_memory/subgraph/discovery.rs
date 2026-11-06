//! Discovery of the longest provably identical executable prefix of two immutable
//! variants (GPU §4.16 lines 880 and 890), from manifest-derived parameter identities,
//! the operator ABI and the variant-wide semantics, profile and trust scope.
//!
//! Discovery stops at the first difference. Every later operator receives a different
//! parent state, so it is never counted, however equal its own parameters (line 888).

use super::key::StateKeyComponent;
use super::variant::{ImmutableVariant, Operator, VariantIdentity};

/// Where discovery stopped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrefixStop {
    /// The operator at `operator` differs in `components`.
    Difference {
        operator: usize,
        components: Vec<StateKeyComponent>,
    },
    /// One variant has no operator at `operator`; the other continues, so the two branch
    /// there.
    EndOfVariant { operator: usize },
    /// Both variants end together with every operator equal: there is no branch.
    Identical,
}

/// The longest provably identical executable prefix of two variants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedPrefix {
    variants: [VariantIdentity; 2],
    shared_operators: usize,
    stop: PrefixStop,
}

impl SharedPrefix {
    /// The two variants, in the order given to [`discover_shared_prefix`].
    pub fn variants(&self) -> &[VariantIdentity; 2] {
        &self.variants
    }

    /// How many leading operators are provably identical.
    pub fn shared_operators(&self) -> usize {
        self.shared_operators
    }

    pub fn stop(&self) -> &PrefixStop {
        &self.stop
    }

    /// The branch boundary: the operator count after which the variants diverge. `None`
    /// when they share nothing or never branch.
    pub fn branch_boundary(&self) -> Option<usize> {
        (self.shared_operators > 0 && self.stop != PrefixStop::Identical)
            .then_some(self.shared_operators)
    }
}

/// Variant-wide components that enter every operator's key.
fn variant_differences(a: &ImmutableVariant, b: &ImmutableVariant) -> Vec<StateKeyComponent> {
    [
        (
            StateKeyComponent::AttentionSemantics,
            a.attention() != b.attention(),
        ),
        (
            StateKeyComponent::PositionSemantics,
            a.position() != b.position(),
        ),
        (
            StateKeyComponent::ExecutionProfile,
            a.profile() != b.profile(),
        ),
        (
            StateKeyComponent::TrustScope,
            a.trust_scope() != b.trust_scope(),
        ),
    ]
    .into_iter()
    .filter_map(|(component, differs)| differs.then_some(component))
    .collect()
}

fn operator_differences(a: &Operator, b: &Operator) -> Vec<StateKeyComponent> {
    [
        (StateKeyComponent::OperatorAbi, a.abi() != b.abi()),
        (
            StateKeyComponent::Parameters,
            a.parameters() != b.parameters(),
        ),
        (StateKeyComponent::DtypeLayout, a.output() != b.output()),
        (
            StateKeyComponent::AdapterEffects,
            a.adapter_effects() != b.adapter_effects(),
        ),
        (StateKeyComponent::RuntimeState, a.runtime() != b.runtime()),
    ]
    .into_iter()
    .filter_map(|(component, differs)| differs.then_some(component))
    .collect()
}

/// Finds the longest provably identical executable prefix of `a` and `b` and stops at
/// the first difference. A difference in attention or position semantics, profile or
/// trust scope stops discovery at the first operator, so equal weights under another
/// positional configuration share nothing.
pub fn discover_shared_prefix(a: &ImmutableVariant, b: &ImmutableVariant) -> SharedPrefix {
    let variants = [a.identity(), b.identity()];
    let global = variant_differences(a, b);
    if !global.is_empty() {
        return SharedPrefix {
            variants,
            shared_operators: 0,
            stop: PrefixStop::Difference {
                operator: 0,
                components: global,
            },
        };
    }
    let mut shared_operators = 0;
    for (left, right) in a.operators().iter().zip(b.operators()) {
        let components = operator_differences(left, right);
        if !components.is_empty() {
            return SharedPrefix {
                variants,
                shared_operators,
                stop: PrefixStop::Difference {
                    operator: shared_operators,
                    components,
                },
            };
        }
        shared_operators += 1;
    }
    let stop = if a.operators().len() == b.operators().len() {
        PrefixStop::Identical
    } else {
        PrefixStop::EndOfVariant {
            operator: shared_operators,
        }
    };
    SharedPrefix {
        variants,
        shared_operators,
        stop,
    }
}
