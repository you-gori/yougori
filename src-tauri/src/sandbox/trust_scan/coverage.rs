//! Coverage completeness: whether a scan saw every package the inventory lists for a
//! component it covered (M18: "checking that a scanner saw every inventoried package";
//! VM-W47, line 2670: "Gate by applicability ... and evidence"; line 2459: a green scan
//! is not "security proof").
//!
//! A component counts as covered when a target the report names is bound to it at its
//! pinned version ([`super::intake`]). That says a scan ran over the component, not that
//! it read every package in it. Where the format lists the packages it read, the list is
//! compared with the inventory, and inventoried packages the scan did not see are named:
//!
//! | Format | What it states | Completeness |
//! | --- | --- | --- |
//! | Trivy with `Packages` (`--list-all-pkgs`) | every package read | [`PackageCompleteness::Compared`] |
//! | Trivy without `Packages` | nothing | [`PackageCompleteness::CannotTell`] |
//! | OSV-Scanner, all-packages mode stated by the caller | every package read | [`PackageCompleteness::Compared`] |
//! | OSV-Scanner otherwise | packages with findings | [`PackageCompleteness::CannotTell`] |
//! | cargo audit with `lockfile` | how many packages the lockfile holds | [`PackageCompleteness::Counted`] |
//! | cargo audit without `lockfile` | nothing | [`PackageCompleteness::CannotTell`] |
//!
//! Nothing here assumes full coverage: a format that cannot tell says so. Packages are
//! the same when their ecosystem, compared name and exact version are.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::inventory::ConfigurationInventory;
use super::package::{Ecosystem, PackageRef, PackageVersion};
use super::report::PackagesRead;
use crate::sandbox::trust::ComponentKind;

/// What the caller states about a report's package lists, as part of what it ran. Input.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageListStatement {
    /// Nothing is stated. A format whose output does not show whether it names every
    /// package it read is taken as not telling.
    #[default]
    NotStated,
    /// OSV-Scanner ran in all-packages mode (`--all-packages`), so its output names every
    /// package it read. Only an OSV-Scanner run may state it.
    OsvAllPackages,
}

/// Why a format cannot tell which packages a scan read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotTellable {
    /// The report names only packages with findings (OSV-Scanner without the all-packages
    /// statement).
    NamesFindingsOnly,
    /// The report gives no package list for a target bound to the component (Trivy
    /// without `Packages`, cargo audit without `lockfile`).
    NoPackageList,
    /// The report only counts the packages of one of several targets bound to the
    /// component.
    CountOnly,
}

/// Whether one scan saw every package the inventory lists for one component it covered.
/// Serialize only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "completeness", rename_all = "snake_case")]
pub enum PackageCompleteness {
    /// The component has no inventory to compare with.
    NoInventory,
    /// Every target bound to the component lists every package the scan read in it.
    /// `not_seen` holds the inventoried packages none of them lists: the scan did not
    /// see them. Empty when it saw every one.
    Compared {
        inventoried: usize,
        not_seen: Vec<PackageRef>,
    },
    /// The report counts the packages it read without naming them. A count below the
    /// inventory's shows that the scan missed some; an equal or higher one cannot tell
    /// which were read (a lockfile also holds packages the build does not ship).
    Counted {
        inventoried: usize,
        counted: u64,
        fewer_than_inventoried: bool,
    },
    /// The format cannot tell which packages the scan read. `not_listed` holds the
    /// inventoried packages the report does not name; the scan may still have read them.
    CannotTell {
        why: NotTellable,
        inventoried: usize,
        not_listed: Vec<PackageRef>,
    },
}

impl PackageCompleteness {
    /// The inventoried packages this scan does not name: `not_seen`, `not_listed`, or for
    /// a count every inventoried package. `None` without an inventory.
    pub fn not_named<'a>(
        &'a self,
        inventoried: &'a BTreeSet<PackageRef>,
    ) -> Option<Vec<&'a PackageRef>> {
        match self {
            Self::NoInventory => None,
            Self::Compared { not_seen, .. } => Some(not_seen.iter().collect()),
            Self::CannotTell { not_listed, .. } => Some(not_listed.iter().collect()),
            Self::Counted { .. } => Some(inventoried.iter().collect()),
        }
    }

    /// Whether a package outside the scan's lists may still have been read by it.
    pub fn undetermined(&self) -> bool {
        matches!(self, Self::Counted { .. } | Self::CannotTell { .. })
    }
}

/// How a package is compared: ecosystem, compared name, exact version.
pub(super) type PackageKey = (Ecosystem, String, PackageVersion);

pub(super) fn package_key(package: &PackageRef) -> PackageKey {
    (
        package.ecosystem,
        package.name_key(),
        package.version.clone(),
    )
}

/// The completeness of one scan for `component`, from what the report says about each
/// target bound to the component at its pinned version (`reads`) and the caller's
/// statement.
pub(super) fn completeness(
    inventory: &ConfigurationInventory,
    component: ComponentKind,
    reads: &[&PackagesRead],
    statement: PackageListStatement,
) -> PackageCompleteness {
    let Some(inventoried) = inventory.packages(component) else {
        return PackageCompleteness::NoInventory;
    };
    let mut listed: BTreeSet<PackageKey> = BTreeSet::new();
    let mut counted: Option<u64> = None;
    let mut not_tellable: Option<NotTellable> = None;
    for read in reads {
        match read {
            PackagesRead::Listed { packages } => listed.extend(packages.iter().map(package_key)),
            PackagesRead::Named { packages } => {
                listed.extend(packages.iter().map(package_key));
                if statement != PackageListStatement::OsvAllPackages {
                    not_tellable.get_or_insert(NotTellable::NamesFindingsOnly);
                }
            }
            PackagesRead::Counted { count } => {
                counted = Some(counted.unwrap_or(0).saturating_add(*count));
            }
            PackagesRead::NotStated => {
                not_tellable.get_or_insert(NotTellable::NoPackageList);
            }
        }
    }
    let missing: Vec<PackageRef> = inventoried
        .iter()
        .filter(|package| !listed.contains(&package_key(package)))
        .cloned()
        .collect();
    let count = inventoried.len();
    match (counted, not_tellable) {
        (Some(counted), None) if listed.is_empty() => PackageCompleteness::Counted {
            inventoried: count,
            counted,
            fewer_than_inventoried: counted < u64::try_from(count).unwrap_or(u64::MAX),
        },
        (Some(_), None) => PackageCompleteness::CannotTell {
            why: NotTellable::CountOnly,
            inventoried: count,
            not_listed: missing,
        },
        (_, Some(why)) => PackageCompleteness::CannotTell {
            why,
            inventoried: count,
            not_listed: missing,
        },
        (None, None) if reads.is_empty() => PackageCompleteness::CannotTell {
            why: NotTellable::NoPackageList,
            inventoried: count,
            not_listed: missing,
        },
        (None, None) => PackageCompleteness::Compared {
            inventoried: count,
            not_seen: missing,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::trust_scan::inventory::tests::{configuration, package, runtime_inventory};

    fn inventory() -> ConfigurationInventory {
        ConfigurationInventory::new(configuration(), vec![runtime_inventory()]).unwrap()
    }

    fn crates(names: &[(&str, &str)]) -> BTreeSet<PackageRef> {
        names
            .iter()
            .map(|(name, version)| package(Ecosystem::CratesIo, name, version))
            .collect()
    }

    fn names(packages: &[PackageRef]) -> Vec<String> {
        packages.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn the_inventory_lists_its_packages() {
        let inventory = inventory();
        let listed = inventory.packages(ComponentKind::Runtime).unwrap();
        assert_eq!(listed.len(), runtime_inventory().packages.len());
        assert!(inventory.packages(ComponentKind::GuestKernel).is_none());
    }

    #[test]
    fn a_full_list_names_what_the_scan_did_not_see() {
        let inventory = inventory();
        // Names compare as the ecosystem compares them; versions exactly.
        let listed = PackagesRead::Listed {
            packages: crates(&[("Fixture_Codec", "2.1.0"), ("serde", "1.0.211")]),
        };
        let result = completeness(
            &inventory,
            ComponentKind::Runtime,
            &[&listed],
            PackageListStatement::NotStated,
        );
        let PackageCompleteness::Compared {
            inventoried,
            not_seen,
        } = &result
        else {
            panic!("not compared: {result:?}");
        };
        assert_eq!(*inventoried, 3);
        assert_eq!(
            names(not_seen),
            ["crates_io fixture_codec 1.0.0", "crates_io serde 1.0.210"]
        );
        assert!(!result.undetermined());
        // Two full lists of one component are joined.
        let rest = PackagesRead::Listed {
            packages: crates(&[("fixture_codec", "1.0.0"), ("serde", "1.0.210")]),
        };
        assert_eq!(
            completeness(
                &inventory,
                ComponentKind::Runtime,
                &[&listed, &rest],
                PackageListStatement::NotStated
            ),
            PackageCompleteness::Compared {
                inventoried: 3,
                not_seen: Vec::new()
            }
        );
    }

    #[test]
    fn osv_names_are_a_full_list_only_when_all_packages_mode_is_stated() {
        let inventory = inventory();
        let named = PackagesRead::Named {
            packages: crates(&[("fixture-codec", "2.1.0")]),
        };
        let unstated = completeness(
            &inventory,
            ComponentKind::Runtime,
            &[&named],
            PackageListStatement::NotStated,
        );
        assert!(matches!(
            &unstated,
            PackageCompleteness::CannotTell {
                why: NotTellable::NamesFindingsOnly,
                inventoried: 3,
                not_listed
            } if not_listed.len() == 2
        ));
        assert!(unstated.undetermined());
        assert!(matches!(
            completeness(
                &inventory,
                ComponentKind::Runtime,
                &[&named],
                PackageListStatement::OsvAllPackages
            ),
            PackageCompleteness::Compared { not_seen, .. } if not_seen.len() == 2
        ));
    }

    #[test]
    fn a_count_shows_only_a_shortfall() {
        let inventory = inventory();
        let count = |count| {
            completeness(
                &inventory,
                ComponentKind::Runtime,
                &[&PackagesRead::Counted { count }],
                PackageListStatement::NotStated,
            )
        };
        assert_eq!(
            count(2),
            PackageCompleteness::Counted {
                inventoried: 3,
                counted: 2,
                fewer_than_inventoried: true
            }
        );
        assert_eq!(
            count(40),
            PackageCompleteness::Counted {
                inventoried: 3,
                counted: 40,
                fewer_than_inventoried: false
            }
        );
        let listed = PackagesRead::Listed {
            packages: crates(&[("serde", "1.0.210")]),
        };
        assert!(matches!(
            completeness(
                &inventory,
                ComponentKind::Runtime,
                &[&listed, &PackagesRead::Counted { count: 9 }],
                PackageListStatement::NotStated
            ),
            PackageCompleteness::CannotTell {
                why: NotTellable::CountOnly,
                ..
            }
        ));
        let inventoried = inventory.packages(ComponentKind::Runtime).unwrap();
        assert_eq!(
            count(2).not_named(inventoried).map(|named| named.len()),
            Some(3)
        );
    }

    #[test]
    fn a_format_that_states_nothing_says_so() {
        let inventory = inventory();
        let listed = PackagesRead::Listed {
            packages: crates(&[("serde", "1.0.210")]),
        };
        let result = completeness(
            &inventory,
            ComponentKind::Runtime,
            &[&listed, &PackagesRead::NotStated],
            PackageListStatement::NotStated,
        );
        assert!(matches!(
            &result,
            PackageCompleteness::CannotTell {
                why: NotTellable::NoPackageList,
                not_listed,
                ..
            } if not_listed.len() == 2
        ));
        assert_eq!(
            completeness(
                &inventory,
                ComponentKind::GuestKernel,
                &[&listed],
                PackageListStatement::NotStated
            ),
            PackageCompleteness::NoInventory
        );
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["completeness"], "cannot_tell");
        assert_eq!(json["why"], "no_package_list");
        assert_eq!(
            serde_json::from_str::<PackageListStatement>("\"osv_all_packages\"").unwrap(),
            PackageListStatement::OsvAllPackages
        );
        assert!(serde_json::from_str::<PackageListStatement>("\"all\"").is_err());
    }
}
