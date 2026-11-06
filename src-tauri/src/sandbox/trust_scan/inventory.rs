//! The component inventory: which packages each pinned component of one configuration
//! contains, and the applicability of a scanner finding that follows from it (VM-W47,
//! line 2670: "Gate by applicability"; VM-W46, line 2669: pinned configurations; M18:
//! "applicable dependency/image gates").
//!
//! A scanner reads a lockfile or an image, which can list more than the build ships
//! (development dependencies, crates of other targets). The inventory is the release's
//! own list of what a pinned component contains, bound to that component's exact
//! version and content key. It states the ecosystems it lists completely; only for those
//! does a package it does not list make a finding not applicable. A finding in another
//! ecosystem, or for a component without an inventory, stays undetermined, which trust
//! counts as applicable (the VT1 decision).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::package::{Ecosystem, PackageRef, PackageVersion};
use crate::foundation::evidence::ConfigurationFingerprint;
use crate::foundation::ids::{ContentKey, Digest, DigestBuilder};
use crate::sandbox::trust::{
    Applicability, ComponentKind, ComponentVersion, PinRefusal, PinnedConfiguration,
};

/// Most packages one component inventory lists.
pub const MAX_INVENTORY_PACKAGES: usize = 20_000;
/// Domain of [`ConfigurationInventory::digest`].
pub const INVENTORY_DOMAIN: &str = "yougori/sandbox/trust-scan/inventory/v1";

/// The packages of one pinned component, as the release states them. Input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentInventory {
    pub component: ComponentKind,
    /// Must equal the pinned version.
    pub version: ComponentVersion,
    /// Must equal the pinned content key, so the list belongs to these exact bytes.
    pub content_key: ContentKey,
    /// The ecosystems whose packages are all listed.
    pub complete_for: BTreeSet<Ecosystem>,
    pub packages: Vec<PackageRef>,
}

/// Why an inventory was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum InventoryRefusal {
    /// The configuration itself does not pass trust's row check.
    Configuration {
        row: PinRefusal,
    },
    Fingerprint {
        detail: String,
    },
    /// The configuration pins no such component.
    NotPinned {
        component: ComponentKind,
    },
    OtherVersion {
        component: ComponentKind,
        pinned: ComponentVersion,
        listed: ComponentVersion,
    },
    OtherContent {
        component: ComponentKind,
    },
    DuplicateComponent {
        component: ComponentKind,
    },
    DuplicatePackage {
        component: ComponentKind,
        package: PackageRef,
    },
    /// A package of an ecosystem the inventory does not declare complete.
    UndeclaredEcosystem {
        component: ComponentKind,
        ecosystem: Ecosystem,
    },
    TooManyPackages {
        component: ComponentKind,
        count: usize,
        max: usize,
    },
}

impl fmt::Display for InventoryRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration { row } => write!(f, "{row}"),
            Self::Fingerprint { detail } => {
                write!(f, "the configuration cannot be fingerprinted: {detail}")
            }
            Self::NotPinned { component } => {
                write!(f, "the configuration pins no {component} to list packages for")
            }
            Self::OtherVersion {
                component,
                pinned,
                listed,
            } => write!(
                f,
                "{component} is pinned at {pinned}, and the inventory lists {listed}"
            ),
            Self::OtherContent { component } => write!(
                f,
                "the {component} inventory names other content than the pinned one"
            ),
            Self::DuplicateComponent { component } => {
                write!(f, "{component} has two inventories")
            }
            Self::DuplicatePackage { component, package } => {
                write!(f, "the {component} inventory lists {package} twice")
            }
            Self::UndeclaredEcosystem {
                component,
                ecosystem,
            } => write!(
                f,
                "the {component} inventory lists a {ecosystem} package without declaring {ecosystem} complete"
            ),
            Self::TooManyPackages {
                component,
                count,
                max,
            } => write!(
                f,
                "the {component} inventory lists {count} packages; at most {max} are read"
            ),
        }
    }
}

impl std::error::Error for InventoryRefusal {}

#[derive(Debug)]
struct Listed {
    version: ComponentVersion,
    complete_for: BTreeSet<Ecosystem>,
    /// Versions per ecosystem and compared name.
    packages: BTreeMap<(Ecosystem, String), BTreeSet<PackageVersion>>,
    /// Every listed package as the inventory writes it.
    listed: BTreeSet<PackageRef>,
}

/// One checked configuration with the inventories of its components (VM-W46, line 2669;
/// VM-W47, line 2670 "applicability").
#[derive(Debug)]
pub struct ConfigurationInventory {
    configuration: PinnedConfiguration,
    fingerprint: ConfigurationFingerprint,
    components: BTreeMap<ComponentKind, Listed>,
    digest: Digest,
}

impl ConfigurationInventory {
    /// Checks the configuration (trust's row check) and binds each inventory to a pinned
    /// component at its exact version and content key. A component may go without an
    /// inventory; its findings then stay undetermined.
    pub fn new(
        configuration: PinnedConfiguration,
        inventories: Vec<ComponentInventory>,
    ) -> Result<Self, InventoryRefusal> {
        configuration
            .check()
            .map_err(|row| InventoryRefusal::Configuration { row })?;
        let fingerprint =
            configuration
                .fingerprint()
                .map_err(|error| InventoryRefusal::Fingerprint {
                    detail: error.to_string(),
                })?;
        let mut components = BTreeMap::new();
        for inventory in inventories {
            let component = inventory.component;
            let pin = configuration
                .component(component)
                .ok_or(InventoryRefusal::NotPinned { component })?;
            if pin.version != inventory.version {
                return Err(InventoryRefusal::OtherVersion {
                    component,
                    pinned: pin.version.clone(),
                    listed: inventory.version,
                });
            }
            if pin.content_key != inventory.content_key {
                return Err(InventoryRefusal::OtherContent { component });
            }
            if components.contains_key(&component) {
                return Err(InventoryRefusal::DuplicateComponent { component });
            }
            if inventory.packages.len() > MAX_INVENTORY_PACKAGES {
                return Err(InventoryRefusal::TooManyPackages {
                    component,
                    count: inventory.packages.len(),
                    max: MAX_INVENTORY_PACKAGES,
                });
            }
            let mut packages: BTreeMap<(Ecosystem, String), BTreeSet<PackageVersion>> =
                BTreeMap::new();
            let mut listed = BTreeSet::new();
            for package in inventory.packages {
                if !inventory.complete_for.contains(&package.ecosystem) {
                    return Err(InventoryRefusal::UndeclaredEcosystem {
                        component,
                        ecosystem: package.ecosystem,
                    });
                }
                let versions = packages
                    .entry((package.ecosystem, package.name_key()))
                    .or_default();
                if !versions.insert(package.version.clone()) {
                    return Err(InventoryRefusal::DuplicatePackage { component, package });
                }
                listed.insert(package);
            }
            components.insert(
                component,
                Listed {
                    version: inventory.version,
                    complete_for: inventory.complete_for,
                    packages,
                    listed,
                },
            );
        }
        let digest = inventory_digest(fingerprint, &components);
        Ok(Self {
            configuration,
            fingerprint,
            components,
            digest,
        })
    }

    pub fn configuration(&self) -> &PinnedConfiguration {
        &self.configuration
    }

    /// The CORE-01 fingerprint of the configuration row.
    pub fn fingerprint(&self) -> ConfigurationFingerprint {
        self.fingerprint
    }

    /// The identity of what this inventory states, under [`INVENTORY_DOMAIN`]: the
    /// configuration's fingerprint and, per component, its version, the ecosystems listed
    /// completely and every package, in order. Equal digests mean the same statements,
    /// whatever order the inventories were given in.
    pub fn digest(&self) -> Digest {
        self.digest
    }

    pub fn has_inventory(&self, component: ComponentKind) -> bool {
        self.components.contains_key(&component)
    }

    /// The packages the inventory lists for `component` at its pinned version, or `None`
    /// when the component has no inventory. Two packages are the same when their
    /// ecosystem, compared name ([`PackageRef::name_key`]) and exact version are.
    pub fn packages(&self, component: ComponentKind) -> Option<&BTreeSet<PackageRef>> {
        self.components.get(&component).map(|listed| &listed.listed)
    }

    /// The applicability of a finding about `package` inside `component` at `version`:
    /// applicable when the inventory lists the package at that exact version; not
    /// applicable, with the reason, when the inventory is complete for the package's
    /// ecosystem and does not list it; undetermined otherwise (no inventory for that
    /// component and version, or an ecosystem it does not list completely).
    pub fn applicability(
        &self,
        component: ComponentKind,
        version: &ComponentVersion,
        package: &PackageRef,
    ) -> Applicability {
        let Some(listed) = self
            .components
            .get(&component)
            .filter(|listed| listed.version == *version)
        else {
            return Applicability::Undetermined;
        };
        if !listed.complete_for.contains(&package.ecosystem) {
            return Applicability::Undetermined;
        }
        let versions = listed
            .packages
            .get(&(package.ecosystem, package.name_key()));
        if versions.is_some_and(|versions| versions.contains(&package.version)) {
            return Applicability::Applicable;
        }
        let mut reason = format!(
            "the inventory of {component} {version} lists no {} {} {}",
            package.ecosystem, package.name, package.version
        );
        if let Some(versions) = versions {
            let listed: Vec<&str> = versions.iter().map(PackageVersion::as_str).collect();
            reason.push_str(&format!("; it lists {}", listed.join(", ")));
        }
        Applicability::NotApplicable { reason }
    }
}

fn inventory_digest(
    fingerprint: ConfigurationFingerprint,
    components: &BTreeMap<ComponentKind, Listed>,
) -> Digest {
    let length = |count: usize| u64::try_from(count).unwrap_or(u64::MAX);
    let mut builder = DigestBuilder::new(INVENTORY_DOMAIN)
        .digest(&fingerprint.digest())
        .u64(length(components.len()));
    for (component, listed) in components {
        builder = builder
            .str(component.tag())
            .str(listed.version.as_str())
            .u64(length(listed.complete_for.len()));
        for ecosystem in &listed.complete_for {
            builder = builder.str(ecosystem.tag());
        }
        builder = builder.u64(length(listed.listed.len()));
        for package in &listed.listed {
            builder = builder
                .str(package.ecosystem.tag())
                .str(package.name.as_str())
                .str(package.version.as_str());
        }
    }
    builder.finish()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::foundation::evidence::OsKind;
    use crate::foundation::ids::digest;
    use crate::foundation::report::CommitHash;
    use crate::sandbox::trust::{
        Architecture, BootMethod, BuildInputs, ComponentPin, ConfigurationKey, DeviceModel,
        SandboxBackend,
    };
    use crate::sandbox::trust_scan::package::{PackageName, PackageVersion};

    pub(crate) fn pin(kind: ComponentKind, version: &str) -> ComponentPin {
        ComponentPin {
            kind,
            version: ComponentVersion::new(version).unwrap(),
            content_key: ContentKey::of(version.as_bytes()),
            length_bytes: version.len() as u64,
            build: BuildInputs {
                source: CommitHash::new("b".repeat(40)).unwrap(),
                toolchain: digest("yougori/test/toolchain/v1", &[version.as_bytes()]),
                configuration: digest("yougori/test/config/v1", &[version.as_bytes()]),
                builder: digest("yougori/test/builder/v1", &[version.as_bytes()]),
            },
        }
    }

    pub(crate) fn configuration() -> PinnedConfiguration {
        PinnedConfiguration {
            key: ConfigurationKey {
                os: OsKind::Linux,
                architecture: Architecture::X86_64,
                backend: SandboxBackend::Firecracker,
            },
            boot: BootMethod::DirectKernel,
            components: BTreeMap::from([
                (
                    ComponentKind::Runtime,
                    pin(ComponentKind::Runtime, "rt-1.0.0"),
                ),
                (
                    ComponentKind::GuestKernel,
                    pin(ComponentKind::GuestKernel, "6.6.52"),
                ),
                (
                    ComponentKind::GuestImage,
                    pin(ComponentKind::GuestImage, "img-2026.10"),
                ),
            ]),
            devices: BTreeSet::from([DeviceModel::VirtioVsock]),
        }
    }

    pub(crate) fn package(ecosystem: Ecosystem, name: &str, version: &str) -> PackageRef {
        PackageRef {
            ecosystem,
            name: PackageName::new(name).unwrap(),
            version: PackageVersion::new(version).unwrap(),
        }
    }

    pub(crate) fn runtime_inventory() -> ComponentInventory {
        ComponentInventory {
            component: ComponentKind::Runtime,
            version: ComponentVersion::new("rt-1.0.0").unwrap(),
            content_key: ContentKey::of(b"rt-1.0.0"),
            complete_for: BTreeSet::from([Ecosystem::CratesIo]),
            packages: vec![
                package(Ecosystem::CratesIo, "fixture-codec", "2.1.0"),
                package(Ecosystem::CratesIo, "fixture_codec", "1.0.0"),
                package(Ecosystem::CratesIo, "serde", "1.0.210"),
            ],
        }
    }

    fn rt() -> ComponentVersion {
        ComponentVersion::new("rt-1.0.0").unwrap()
    }

    #[test]
    fn applicability_follows_the_inventory() {
        let inventory =
            ConfigurationInventory::new(configuration(), vec![runtime_inventory()]).unwrap();
        let runtime = ComponentKind::Runtime;
        assert_eq!(
            inventory.applicability(
                runtime,
                &rt(),
                &package(Ecosystem::CratesIo, "Fixture_Codec", "2.1.0")
            ),
            Applicability::Applicable
        );
        assert_eq!(
            inventory.applicability(
                runtime,
                &rt(),
                &package(Ecosystem::CratesIo, "fixture-build-helper", "0.3.0")
            ),
            Applicability::NotApplicable {
                reason: "the inventory of runtime rt-1.0.0 lists no crates_io fixture-build-helper 0.3.0"
                    .to_owned()
            }
        );
        assert_eq!(
            inventory.applicability(
                runtime,
                &rt(),
                &package(Ecosystem::CratesIo, "fixture-codec", "2.0.9")
            ),
            Applicability::NotApplicable {
                reason: "the inventory of runtime rt-1.0.0 lists no crates_io fixture-codec 2.0.9; it lists 1.0.0, 2.1.0"
                    .to_owned()
            }
        );
        // An ecosystem the inventory does not list completely stays undetermined.
        assert_eq!(
            inventory.applicability(runtime, &rt(), &package(Ecosystem::Go, "x", "v1.0.0")),
            Applicability::Undetermined
        );
        // So does a component without an inventory, or another version of the component.
        assert_eq!(
            inventory.applicability(
                ComponentKind::GuestImage,
                &ComponentVersion::new("img-2026.10").unwrap(),
                &package(Ecosystem::Debian, "libssl3", "3.0.15-1~deb12u1")
            ),
            Applicability::Undetermined
        );
        assert_eq!(
            inventory.applicability(
                runtime,
                &ComponentVersion::new("rt-0.9.0").unwrap(),
                &package(Ecosystem::CratesIo, "fixture-build-helper", "0.3.0")
            ),
            Applicability::Undetermined
        );
        assert!(inventory.has_inventory(runtime));
        assert!(!inventory.has_inventory(ComponentKind::GuestKernel));
        assert_eq!(
            Some(inventory.fingerprint()),
            configuration().fingerprint().ok()
        );
    }

    #[test]
    fn inventories_must_belong_to_the_pinned_components() {
        let refuse = |inventory: ComponentInventory| {
            ConfigurationInventory::new(configuration(), vec![inventory]).err()
        };
        let mut firmware = runtime_inventory();
        firmware.component = ComponentKind::Firmware;
        assert_eq!(
            refuse(firmware),
            Some(InventoryRefusal::NotPinned {
                component: ComponentKind::Firmware
            })
        );
        let mut other_version = runtime_inventory();
        other_version.version = ComponentVersion::new("rt-0.9.0").unwrap();
        assert!(matches!(
            refuse(other_version),
            Some(InventoryRefusal::OtherVersion { .. })
        ));
        let mut other_content = runtime_inventory();
        other_content.content_key = ContentKey::of(b"another build");
        assert_eq!(
            refuse(other_content),
            Some(InventoryRefusal::OtherContent {
                component: ComponentKind::Runtime
            })
        );
        let mut duplicate_package = runtime_inventory();
        duplicate_package
            .packages
            .push(package(Ecosystem::CratesIo, "Serde", "1.0.210"));
        assert!(matches!(
            refuse(duplicate_package),
            Some(InventoryRefusal::DuplicatePackage { .. })
        ));
        let mut undeclared = runtime_inventory();
        undeclared
            .packages
            .push(package(Ecosystem::Go, "golang.org/x/net", "v0.30.0"));
        assert_eq!(
            refuse(undeclared),
            Some(InventoryRefusal::UndeclaredEcosystem {
                component: ComponentKind::Runtime,
                ecosystem: Ecosystem::Go
            })
        );
        let mut too_many = runtime_inventory();
        too_many.packages = (0..=MAX_INVENTORY_PACKAGES)
            .map(|n| package(Ecosystem::CratesIo, &format!("c{n}"), "1.0.0"))
            .collect();
        assert!(matches!(
            refuse(too_many),
            Some(InventoryRefusal::TooManyPackages { .. })
        ));
        assert_eq!(
            ConfigurationInventory::new(
                configuration(),
                vec![runtime_inventory(), runtime_inventory()]
            )
            .err(),
            Some(InventoryRefusal::DuplicateComponent {
                component: ComponentKind::Runtime
            })
        );
        let mut unchecked = configuration();
        unchecked.components.remove(&ComponentKind::GuestImage);
        assert!(matches!(
            ConfigurationInventory::new(unchecked, Vec::new()).err(),
            Some(InventoryRefusal::Configuration { .. })
        ));
    }

    #[test]
    fn inventories_are_read_strictly() {
        let json = serde_json::to_value(runtime_inventory()).unwrap();
        assert_eq!(
            serde_json::from_value::<ComponentInventory>(json.clone()).unwrap(),
            runtime_inventory()
        );
        let mut extra = json.clone();
        extra["trusted"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ComponentInventory>(extra).is_err());
        let mut missing = json;
        missing.as_object_mut().unwrap().remove("complete_for");
        assert!(serde_json::from_value::<ComponentInventory>(missing).is_err());
    }
}
