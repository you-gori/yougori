//! The Transformers row's critical boundary: "Rematerialize buffers and preserve tied
//! weights correctly" (GPU part §3.8).
//!
//! After meta construction or a bulk indexed load every tensor is filled explicitly:
//! parameters and persistent buffers from the checkpoint, non-persistent buffers by
//! computing them again, and each group of tied weights as one loaded tensor that every
//! other member shares. Nothing is left on the meta device.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

/// A tensor's name in the model's state, such as `lm_head.weight`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TensorName(String);

impl TensorName {
    /// A non-empty name.
    pub fn new(name: impl Into<String>) -> Result<Self, InventoryError> {
        let name = name.into();
        if name.is_empty() {
            return Err(InventoryError::EmptyName);
        }
        Ok(Self(name))
    }

    /// The name as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for TensorName {
    type Error = InventoryError;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        Self::new(name)
    }
}

impl From<TensorName> for String {
    fn from(name: TensorName) -> Self {
        name.0
    }
}

impl fmt::Display for TensorName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What a tensor is to the checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TensorRole {
    /// A parameter, stored in the checkpoint.
    Parameter,
    /// A buffer stored in the checkpoint, such as running statistics.
    PersistentBuffer,
    /// A buffer the checkpoint does not store, such as rotary inverse frequencies, which
    /// the module computes when it is constructed.
    NonPersistentBuffer,
}

/// Why an inventory is malformed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum InventoryError {
    /// A tensor name is empty.
    EmptyName,
    /// A tied group needs at least two members.
    TiedGroupTooSmall { group: BTreeSet<TensorName> },
    /// A tied group names a tensor the model does not have.
    TiedTensorUnknown { tensor: TensorName },
    /// Only parameters are tied.
    TiedTensorNotParameter { tensor: TensorName },
    /// A tensor is in two tied groups.
    TiedInTwoGroups { tensor: TensorName },
}

impl fmt::Display for InventoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyName => f.write_str("a tensor name is empty"),
            Self::TiedGroupTooSmall { group } => {
                write!(f, "the tied group {group:?} has fewer than two members")
            }
            Self::TiedTensorUnknown { tensor } => {
                write!(f, "the tied tensor {tensor} is not in the model")
            }
            Self::TiedTensorNotParameter { tensor } => {
                write!(f, "the tied tensor {tensor} is not a parameter")
            }
            Self::TiedInTwoGroups { tensor } => {
                write!(f, "the tensor {tensor} is in two tied groups")
            }
        }
    }
}

impl std::error::Error for InventoryError {}

/// A model's tensors and its groups of tied weights, such as an input embedding shared
/// with the output head.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ModelInventory {
    roles: BTreeMap<TensorName, TensorRole>,
    tied_groups: Vec<BTreeSet<TensorName>>,
}

impl ModelInventory {
    /// An inventory whose tied groups each have two or more known parameters, with no
    /// tensor in two groups.
    pub fn new(
        roles: BTreeMap<TensorName, TensorRole>,
        tied_groups: Vec<BTreeSet<TensorName>>,
    ) -> Result<Self, InventoryError> {
        let mut seen = BTreeSet::new();
        for group in &tied_groups {
            if group.len() < 2 {
                return Err(InventoryError::TiedGroupTooSmall {
                    group: group.clone(),
                });
            }
            for tensor in group {
                match roles.get(tensor) {
                    None => {
                        return Err(InventoryError::TiedTensorUnknown {
                            tensor: tensor.clone(),
                        })
                    }
                    Some(TensorRole::Parameter) => {}
                    Some(_) => {
                        return Err(InventoryError::TiedTensorNotParameter {
                            tensor: tensor.clone(),
                        })
                    }
                }
                if !seen.insert(tensor) {
                    return Err(InventoryError::TiedInTwoGroups {
                        tensor: tensor.clone(),
                    });
                }
            }
        }
        Ok(Self { roles, tied_groups })
    }

    fn group_of(&self, tensor: &TensorName) -> Option<&BTreeSet<TensorName>> {
        self.tied_groups.iter().find(|group| group.contains(tensor))
    }
}

/// How one tensor gets its value after meta construction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Materialization {
    /// Read from the checkpoint.
    LoadFromCheckpoint,
    /// Computed again by the module, as construction would have.
    Rematerialize,
    /// Share the storage of `tensor`, a tied member loaded from the checkpoint.
    TieTo { tensor: TensorName },
}

/// How every tensor of a model gets its value after meta construction.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaterializationPlan {
    pub tensors: BTreeMap<TensorName, Materialization>,
}

/// Why a materialization plan breaks the Transformers boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum MaterializationRefusal {
    /// The plan names a tensor the model does not have.
    UnknownTensor { tensor: TensorName },
    /// The plan leaves a tensor on the meta device.
    LeftOnMeta { tensor: TensorName },
    /// A non-persistent buffer must be computed again; the checkpoint does not have it.
    BufferNotRematerialized { tensor: TensorName },
    /// A parameter or persistent buffer must come from the checkpoint; computing it again
    /// would give freshly initialized values.
    NotLoadedFromCheckpoint { tensor: TensorName },
    /// The tensor is tied to one outside its tied group, or is not tied at all.
    TieOutsideGroup {
        tensor: TensorName,
        target: TensorName,
    },
    /// A tied group must be one loaded tensor that every other member shares; loading
    /// several copies or none breaks the tie.
    TiedWeightsNotPreserved { group: BTreeSet<TensorName> },
}

impl fmt::Display for MaterializationRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownTensor { tensor } => write!(f, "{tensor} is not in the model"),
            Self::LeftOnMeta { tensor } => write!(f, "{tensor} would be left on the meta device"),
            Self::BufferNotRematerialized { tensor } => write!(
                f,
                "the buffer {tensor} is not in the checkpoint and must be rematerialized"
            ),
            Self::NotLoadedFromCheckpoint { tensor } => {
                write!(f, "{tensor} must be loaded from the checkpoint")
            }
            Self::TieOutsideGroup { tensor, target } => {
                write!(
                    f,
                    "{tensor} is tied to {target}, which is not in its tied group"
                )
            }
            Self::TiedWeightsNotPreserved { group } => write!(
                f,
                "the tied weights {group:?} must be one loaded tensor shared by every member"
            ),
        }
    }
}

impl std::error::Error for MaterializationRefusal {}

/// Checks `plan` against the Transformers boundary: every tensor of `inventory` is
/// materialized, non-persistent buffers are computed again, parameters and persistent
/// buffers come from the checkpoint, and each tied group is exactly one loaded tensor
/// that every other member shares (GPU part §3.8).
pub fn check_materialization(
    inventory: &ModelInventory,
    plan: &MaterializationPlan,
) -> Result<(), MaterializationRefusal> {
    if let Some(tensor) = plan
        .tensors
        .keys()
        .find(|tensor| !inventory.roles.contains_key(*tensor))
    {
        return Err(MaterializationRefusal::UnknownTensor {
            tensor: tensor.clone(),
        });
    }
    for (tensor, role) in &inventory.roles {
        let materialization =
            plan.tensors
                .get(tensor)
                .ok_or_else(|| MaterializationRefusal::LeftOnMeta {
                    tensor: tensor.clone(),
                })?;
        match (role, materialization) {
            (TensorRole::NonPersistentBuffer, Materialization::Rematerialize) => {}
            (TensorRole::NonPersistentBuffer, _) => {
                return Err(MaterializationRefusal::BufferNotRematerialized {
                    tensor: tensor.clone(),
                })
            }
            (_, Materialization::Rematerialize) => {
                return Err(MaterializationRefusal::NotLoadedFromCheckpoint {
                    tensor: tensor.clone(),
                })
            }
            (_, Materialization::TieTo { tensor: target }) => {
                let inside = inventory
                    .group_of(tensor)
                    .is_some_and(|group| target != tensor && group.contains(target));
                if !inside {
                    return Err(MaterializationRefusal::TieOutsideGroup {
                        tensor: tensor.clone(),
                        target: target.clone(),
                    });
                }
            }
            (_, Materialization::LoadFromCheckpoint) => {}
        }
    }
    for group in &inventory.tied_groups {
        let mut loaded = group.iter().filter(|tensor| {
            plan.tensors.get(*tensor) == Some(&Materialization::LoadFromCheckpoint)
        });
        let preserved = match (loaded.next(), loaded.next()) {
            (Some(source), None) => group
                .iter()
                .filter(|tensor| *tensor != source)
                .all(|tensor| {
                    plan.tensors.get(tensor)
                        == Some(&Materialization::TieTo {
                            tensor: source.clone(),
                        })
                }),
            _ => false,
        };
        if !preserved {
            return Err(MaterializationRefusal::TiedWeightsNotPreserved {
                group: group.clone(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(text: &str) -> TensorName {
        TensorName::new(text).unwrap()
    }

    /// A small decoder: tied embedding and head, a layer weight, a persistent norm
    /// statistic and non-persistent rotary frequencies.
    fn inventory() -> ModelInventory {
        ModelInventory::new(
            BTreeMap::from([
                (name("embed.weight"), TensorRole::Parameter),
                (name("lm_head.weight"), TensorRole::Parameter),
                (name("layer.weight"), TensorRole::Parameter),
                (name("norm.running_mean"), TensorRole::PersistentBuffer),
                (name("rotary.inv_freq"), TensorRole::NonPersistentBuffer),
            ]),
            vec![BTreeSet::from([
                name("embed.weight"),
                name("lm_head.weight"),
            ])],
        )
        .unwrap()
    }

    fn correct() -> MaterializationPlan {
        MaterializationPlan {
            tensors: BTreeMap::from([
                (name("embed.weight"), Materialization::LoadFromCheckpoint),
                (
                    name("lm_head.weight"),
                    Materialization::TieTo {
                        tensor: name("embed.weight"),
                    },
                ),
                (name("layer.weight"), Materialization::LoadFromCheckpoint),
                (
                    name("norm.running_mean"),
                    Materialization::LoadFromCheckpoint,
                ),
                (name("rotary.inv_freq"), Materialization::Rematerialize),
            ]),
        }
    }

    fn with(tensor: &str, materialization: Materialization) -> MaterializationPlan {
        let mut plan = correct();
        plan.tensors.insert(name(tensor), materialization);
        plan
    }

    #[test]
    fn buffers_are_rematerialized() {
        assert_eq!(check_materialization(&inventory(), &correct()), Ok(()));
        assert_eq!(
            check_materialization(
                &inventory(),
                &with("rotary.inv_freq", Materialization::LoadFromCheckpoint)
            ),
            Err(MaterializationRefusal::BufferNotRematerialized {
                tensor: name("rotary.inv_freq")
            })
        );
        let mut left = correct();
        left.tensors.remove(&name("rotary.inv_freq"));
        assert_eq!(
            check_materialization(&inventory(), &left),
            Err(MaterializationRefusal::LeftOnMeta {
                tensor: name("rotary.inv_freq")
            })
        );
        for tensor in ["layer.weight", "norm.running_mean"] {
            assert_eq!(
                check_materialization(&inventory(), &with(tensor, Materialization::Rematerialize)),
                Err(MaterializationRefusal::NotLoadedFromCheckpoint {
                    tensor: name(tensor)
                })
            );
        }
        assert_eq!(
            check_materialization(
                &inventory(),
                &with("extra.weight", Materialization::LoadFromCheckpoint)
            ),
            Err(MaterializationRefusal::UnknownTensor {
                tensor: name("extra.weight")
            })
        );
    }

    #[test]
    fn tied_weights_stay_one_shared_tensor() {
        let group = BTreeSet::from([name("embed.weight"), name("lm_head.weight")]);
        let split = with("lm_head.weight", Materialization::LoadFromCheckpoint);
        assert_eq!(
            check_materialization(&inventory(), &split),
            Err(MaterializationRefusal::TiedWeightsNotPreserved {
                group: group.clone()
            })
        );
        let mut circular = with(
            "embed.weight",
            Materialization::TieTo {
                tensor: name("lm_head.weight"),
            },
        );
        assert_eq!(
            check_materialization(&inventory(), &circular),
            Err(MaterializationRefusal::TiedWeightsNotPreserved { group })
        );
        circular.tensors.insert(
            name("lm_head.weight"),
            Materialization::TieTo {
                tensor: name("lm_head.weight"),
            },
        );
        assert!(matches!(
            check_materialization(&inventory(), &circular),
            Err(MaterializationRefusal::TieOutsideGroup { .. })
        ));
        assert_eq!(
            check_materialization(
                &inventory(),
                &with(
                    "layer.weight",
                    Materialization::TieTo {
                        tensor: name("embed.weight")
                    }
                )
            ),
            Err(MaterializationRefusal::TieOutsideGroup {
                tensor: name("layer.weight"),
                target: name("embed.weight")
            })
        );
        assert_eq!(
            check_materialization(
                &inventory(),
                &with(
                    "lm_head.weight",
                    Materialization::TieTo {
                        tensor: name("layer.weight")
                    }
                )
            ),
            Err(MaterializationRefusal::TieOutsideGroup {
                tensor: name("lm_head.weight"),
                target: name("layer.weight")
            })
        );
        // Either member may be the loaded one.
        let mut reversed = with(
            "embed.weight",
            Materialization::TieTo {
                tensor: name("lm_head.weight"),
            },
        );
        reversed
            .tensors
            .insert(name("lm_head.weight"), Materialization::LoadFromCheckpoint);
        assert_eq!(check_materialization(&inventory(), &reversed), Ok(()));
    }

    #[test]
    fn inventories_are_validated() {
        let roles = BTreeMap::from([
            (name("a"), TensorRole::Parameter),
            (name("b"), TensorRole::Parameter),
            (name("c"), TensorRole::Parameter),
            (name("buffer"), TensorRole::PersistentBuffer),
        ]);
        let group = |names: &[&str]| -> BTreeSet<TensorName> {
            names.iter().map(|text| name(text)).collect()
        };
        assert!(matches!(
            ModelInventory::new(roles.clone(), vec![group(&["a"])]),
            Err(InventoryError::TiedGroupTooSmall { .. })
        ));
        assert_eq!(
            ModelInventory::new(roles.clone(), vec![group(&["a", "missing"])]),
            Err(InventoryError::TiedTensorUnknown {
                tensor: name("missing")
            })
        );
        assert_eq!(
            ModelInventory::new(roles.clone(), vec![group(&["a", "buffer"])]),
            Err(InventoryError::TiedTensorNotParameter {
                tensor: name("buffer")
            })
        );
        assert_eq!(
            ModelInventory::new(roles.clone(), vec![group(&["a", "b"]), group(&["b", "c"])]),
            Err(InventoryError::TiedInTwoGroups { tensor: name("b") })
        );
        assert!(ModelInventory::new(roles, vec![group(&["a", "b", "c"])]).is_ok());
        assert_eq!(TensorName::new(""), Err(InventoryError::EmptyName));
    }

    #[test]
    fn plans_read_from_json_refuse_unknown_fields() {
        let json = serde_json::to_value(correct()).unwrap();
        assert_eq!(json["tensors"]["rotary.inv_freq"], "rematerialize");
        assert_eq!(
            json["tensors"]["lm_head.weight"],
            serde_json::json!({"tie_to": {"tensor": "embed.weight"}})
        );
        assert_eq!(
            serde_json::from_value::<MaterializationPlan>(json.clone()).unwrap(),
            correct()
        );
        let mut extra = json.clone();
        extra["tensors"]["lm_head.weight"]["tie_to"]["copy"] = true.into();
        assert!(serde_json::from_value::<MaterializationPlan>(extra).is_err());
        let mut second_key = json;
        second_key["tensors"]["lm_head.weight"]["rematerialize"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<MaterializationPlan>(second_key).is_err());
        assert!(serde_json::from_str::<TensorName>("\"\"").is_err());
    }
}
