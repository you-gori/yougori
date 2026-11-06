//! The accelerator a VM actually runs on (VM-W22 row, line 2620: record the actual
//! accelerator, not just the requested flag; VM-P01 line 2781; VM-P42 line 2812).

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::foundation::evidence::HypervisorKind;
use crate::foundation::ids::DigestBuilder;

/// A software emulator. Emulation is never a production sandbox accelerator (§1.3 line
/// 1735; VM-P42): if a backend offers it at all, it is the separate developer facility of
/// [`DeveloperEmulation`](super::DeveloperEmulation).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Emulator {
    /// QEMU's Tiny Code Generator.
    Tcg,
}

impl Emulator {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Tcg => "tcg",
        }
    }
}

impl fmt::Display for Emulator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Tcg => "TCG emulation",
        })
    }
}

/// What executes the guest: a hardware hypervisor interface, or an emulator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Accelerator {
    Hardware { hypervisor: HypervisorKind },
    Emulation { emulator: Emulator },
}

impl Accelerator {
    /// Whether the guest runs under hardware virtualization, as every production launch
    /// requires (VM-W22).
    pub const fn is_hardware_virtualized(self) -> bool {
        matches!(self, Self::Hardware { .. })
    }

    /// The hypervisor, for a hardware accelerator.
    pub const fn hypervisor(self) -> Option<HypervisorKind> {
        match self {
            Self::Hardware { hypervisor } => Some(hypervisor),
            Self::Emulation { .. } => None,
        }
    }

    /// Writes the accelerator into an identity digest.
    pub fn bind(self, builder: DigestBuilder) -> DigestBuilder {
        match self {
            Self::Hardware { hypervisor } => builder.str("hardware").str(hypervisor.tag()),
            Self::Emulation { emulator } => builder.str("emulation").str(emulator.tag()),
        }
    }
}

impl fmt::Display for Accelerator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hardware { hypervisor } => write!(f, "{hypervisor} (hardware virtualization)"),
            Self::Emulation { emulator } => write!(f, "{emulator} (no hardware virtualization)"),
        }
    }
}

/// A hardware virtualization failure the backend met while launching (VM-W22 row: a
/// forced hardware failure refuses the launch, with no retry into emulation).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HardwareFailure {
    pub hypervisor: HypervisorKind,
    /// The backend's own description, kept as reported.
    pub detail: String,
}

impl fmt::Display for HardwareFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} failed: {}", self.hypervisor, self.detail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_hardware_counts_as_virtualized() {
        let kvm = Accelerator::Hardware {
            hypervisor: HypervisorKind::Kvm,
        };
        let tcg = Accelerator::Emulation {
            emulator: Emulator::Tcg,
        };
        assert!(kvm.is_hardware_virtualized());
        assert!(!tcg.is_hardware_virtualized());
        assert_eq!(kvm.hypervisor(), Some(HypervisorKind::Kvm));
        assert_eq!(tcg.hypervisor(), None);
        assert!(tcg.to_string().contains("no hardware virtualization"));
        assert_ne!(
            kvm.bind(DigestBuilder::new("yougori/test/v1")).finish(),
            tcg.bind(DigestBuilder::new("yougori/test/v1")).finish()
        );
        assert_ne!(
            kvm.bind(DigestBuilder::new("yougori/test/v1")).finish(),
            Accelerator::Hardware {
                hypervisor: HypervisorKind::Whpx
            }
            .bind(DigestBuilder::new("yougori/test/v1"))
            .finish()
        );
    }

    #[test]
    fn accelerators_round_trip_and_refuse_unknown_fields() {
        let kvm = Accelerator::Hardware {
            hypervisor: HypervisorKind::Kvm,
        };
        let json = serde_json::to_value(kvm).unwrap();
        assert_eq!(json["hardware"]["hypervisor"], "kvm");
        assert_eq!(serde_json::from_value::<Accelerator>(json).unwrap(), kvm);
        assert!(serde_json::from_value::<Accelerator>(serde_json::json!({
            "hardware": {"hypervisor": "kvm", "requested": true}
        }))
        .is_err());
        assert_eq!(
            serde_json::to_string(&Accelerator::Emulation {
                emulator: Emulator::Tcg
            })
            .unwrap(),
            r#"{"emulation":{"emulator":"tcg"}}"#
        );
        let failure = HardwareFailure {
            hypervisor: HypervisorKind::Whpx,
            detail: "WHvCreatePartition returned E_ACCESSDENIED".to_owned(),
        };
        assert!(failure
            .to_string()
            .starts_with("Windows Hypervisor Platform failed"));
    }
}
