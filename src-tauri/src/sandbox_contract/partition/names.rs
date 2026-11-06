//! Validated names of steps, data items, retained volumes, contracts and label tags
//! (VM part §9.1). Every name follows the shared identifier grammar of
//! [`crate::foundation::ids::validate_identifier`].

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use crate::foundation::ids::{validate_identifier, IdError};

macro_rules! name_type {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Accepts 1–128 letters, digits, '.', '_', ':' or '-', starting with a
            /// letter or digit.
            pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
                let value = value.into();
                validate_identifier(&value)?;
                Ok(Self(value))
            }

            /// The name as text.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
            }
        }
    };
}

name_type!(
    /// One step of a workflow DAG (VM part §9.1).
    StepId
);
name_type!(
    /// One data item: a workflow source or a step output (VM part §9.1).
    DataId
);
name_type!(
    /// A retained volume: state a compartment keeps across generations (VM part §1.4,
    /// §9.1 "persistent state").
    VolumeId
);
name_type!(
    /// An explicit release contract (VM part §9.1 "data crossing a boundary uses an
    /// explicit release contract").
    ContractId
);
name_type!(
    /// A label tag: a private source, a provenance source, a credential, a policy rule or
    /// a release target, as named by trusted policy (line 2320).
    LabelTag
);
