//! VM-CP-02's golden file for the Firecracker backend (line 3152: "the hypervisor
//! configuration (Firecracker API calls or QEMU argv) matches the approved profile's
//! golden file: no network device, no console, no balloon, no PCI transport unless the
//! device profile declares it"; positive control: "the golden file is versioned with the
//! backend"; VM-P02 line 2777: no universal device-count target).
//!
//! A golden file holds the pinned Firecracker version and one entry per leaf of the
//! configuration: the call sequence, every Firecracker argument and every leaf of every
//! API body, keyed `<method> <path> <JSON pointer>`. Its canonical text is fixed, so its
//! digest changes with any entry or the version, and a parsed file must be in canonical
//! form. A comparison reports unexpected, missing and changed entries; a separate scan
//! names forbidden configuration in what was observed. Of the items VM-CP-02 names, only a
//! network interface can be declared by a Firecracker profile; a console, a balloon and the
//! PCI transport are never declarable here, and neither are a metadata service, a seccomp
//! override or a snapshot operation in a cold-boot launch (§6.6 line 2338; §7.2 line 2368).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::api::{ApiCall, ApiPlan};
use super::canonical::canonical_json;
use super::profile::FirecrackerProfile;
use super::LaunchPlan;
use crate::foundation::ids::{digest, Digest};
use crate::sandbox::trust::ComponentVersion;

/// The golden file format version.
pub const GOLDEN_SCHEMA: u32 = 1;
/// Digest domain of [`GoldenFile::digest`].
pub const GOLDEN_DOMAIN: &str = "yougori/sandbox/firecracker/golden/v1";
/// The longest golden file accepted, in bytes.
pub const MAX_GOLDEN_BYTES: usize = 256 * 1024;
/// The longest entry key accepted, in bytes.
pub const MAX_ENTRY_KEY_BYTES: usize = 256;
/// The entry holding the call sequence.
pub const SEQUENCE_KEY: &str = "sequence";
/// The prefix of the entries holding Firecracker's arguments.
pub const ARGS_KEY: &str = "firecracker.args";
/// The pseudo-key a version difference is reported under.
pub const VERSION_KEY: &str = "firecracker_version";

/// A golden file: the Firecracker version and the configuration's leaves.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GoldenFile {
    schema: u32,
    firecracker_version: ComponentVersion,
    entries: BTreeMap<String, Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GoldenText {
    schema: u32,
    firecracker_version: ComponentVersion,
    entries: BTreeMap<String, Value>,
}

/// Why a golden file was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum GoldenError {
    TooLarge {
        bytes: usize,
        max_bytes: usize,
    },
    Unreadable {
        detail: String,
    },
    UnsupportedSchema {
        schema: u32,
    },
    InvalidKey {
        key: String,
    },
    /// An entry's value is a non-empty object or array rather than a leaf.
    NotLeaf {
        key: String,
    },
    /// The text is not the canonical form of its own content.
    NotCanonical,
}

impl fmt::Display for GoldenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { bytes, max_bytes } => {
                write!(f, "the golden file is {bytes} bytes, more than {max_bytes}")
            }
            Self::Unreadable { detail } => write!(f, "the golden file cannot be read: {detail}"),
            Self::UnsupportedSchema { schema } => {
                write!(f, "golden file schema {schema} is not {GOLDEN_SCHEMA}")
            }
            Self::InvalidKey { key } => write!(f, "the entry key {key:?} is invalid"),
            Self::NotLeaf { key } => write!(f, "the entry {key:?} is not a leaf value"),
            Self::NotCanonical => f.write_str(
                "the golden file is not in canonical form; regenerate it rather than edit it",
            ),
        }
    }
}

impl std::error::Error for GoldenError {}

fn escape_pointer(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

fn is_leaf(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.is_empty(),
        Value::Array(items) => items.is_empty(),
        _ => true,
    }
}

fn flatten(value: &Value, prefix: &str, pointer: &str, entries: &mut BTreeMap<String, Value>) {
    match value {
        Value::Object(map) if !map.is_empty() => {
            for (key, item) in map {
                flatten(
                    item,
                    prefix,
                    &format!("{pointer}/{}", escape_pointer(key)),
                    entries,
                );
            }
        }
        Value::Array(items) if !items.is_empty() => {
            for (index, item) in items.iter().enumerate() {
                flatten(item, prefix, &format!("{pointer}/{index}"), entries);
            }
        }
        leaf => {
            let key = if pointer.is_empty() {
                prefix.to_owned()
            } else {
                format!("{prefix} {pointer}")
            };
            entries.insert(key, leaf.clone());
        }
    }
}

fn check_key(key: &str) -> Result<(), GoldenError> {
    let printable = key.bytes().all(|byte| (0x20..=0x7e).contains(&byte));
    if key.is_empty() || key.len() > MAX_ENTRY_KEY_BYTES || !printable {
        return Err(GoldenError::InvalidKey {
            key: key.chars().take(MAX_ENTRY_KEY_BYTES).collect(),
        });
    }
    Ok(())
}

impl GoldenFile {
    /// The golden file of an API plan and Firecracker's arguments under `version`.
    pub fn from_parts(
        version: &ComponentVersion,
        api: &ApiPlan,
        firecracker_args: &[String],
    ) -> Self {
        Self::from_calls(version, &api.calls(), firecracker_args)
    }

    /// The golden file of API calls as they were sent, in sending order, and Firecracker's
    /// arguments under `version`: the observed side of VM-CP-02.
    pub(super) fn from_calls(
        version: &ComponentVersion,
        calls: &[ApiCall],
        firecracker_args: &[String],
    ) -> Self {
        let mut entries = BTreeMap::new();
        entries.insert(
            SEQUENCE_KEY.to_owned(),
            Value::String(
                calls
                    .iter()
                    .map(|call| format!("{} {}", call.method, call.path))
                    .collect::<Vec<String>>()
                    .join(", "),
            ),
        );
        for (index, argument) in firecracker_args.iter().enumerate() {
            entries.insert(
                format!("{ARGS_KEY} /{index}"),
                Value::String(argument.clone()),
            );
        }
        for call in calls {
            flatten(
                &call.body,
                &format!("{} {}", call.method, call.path),
                "",
                &mut entries,
            );
        }
        Self {
            schema: GOLDEN_SCHEMA,
            firecracker_version: version.clone(),
            entries,
        }
    }

    /// The golden file of a launch plan: what the backend sends and passes to Firecracker.
    pub fn from_plan(plan: &LaunchPlan) -> Self {
        Self::from_parts(
            plan.firecracker_version(),
            plan.api(),
            &plan.jailer().firecracker_args(),
        )
    }

    /// A golden file from entries, checking each key and value.
    pub fn from_entries(
        version: ComponentVersion,
        entries: BTreeMap<String, Value>,
    ) -> Result<Self, GoldenError> {
        for (key, value) in &entries {
            check_key(key)?;
            if !is_leaf(value) {
                return Err(GoldenError::NotLeaf { key: key.clone() });
            }
        }
        Ok(Self {
            schema: GOLDEN_SCHEMA,
            firecracker_version: version,
            entries,
        })
    }

    /// Parses a golden file, which must be in canonical form.
    pub fn parse(text: &str) -> Result<Self, GoldenError> {
        if text.len() > MAX_GOLDEN_BYTES {
            return Err(GoldenError::TooLarge {
                bytes: text.len(),
                max_bytes: MAX_GOLDEN_BYTES,
            });
        }
        let parsed: GoldenText =
            serde_json::from_str(text).map_err(|error| GoldenError::Unreadable {
                detail: error.to_string(),
            })?;
        if parsed.schema != GOLDEN_SCHEMA {
            return Err(GoldenError::UnsupportedSchema {
                schema: parsed.schema,
            });
        }
        let golden = Self::from_entries(parsed.firecracker_version, parsed.entries)?;
        if golden.canonical_text() != text {
            return Err(GoldenError::NotCanonical);
        }
        Ok(golden)
    }

    /// The canonical text: one entry per line in key order, ending with a newline.
    pub fn canonical_text(&self) -> String {
        let string = |text: &str| Value::String(text.to_owned()).to_string();
        let mut text = format!(
            "{{\n  \"schema\": {},\n  \"firecracker_version\": {},\n  \"entries\": {{",
            self.schema,
            string(self.firecracker_version.as_str())
        );
        for (index, (key, value)) in self.entries.iter().enumerate() {
            text.push_str(if index == 0 { "\n    " } else { ",\n    " });
            text.push_str(&string(key));
            text.push_str(": ");
            text.push_str(&canonical_json(value));
        }
        text.push_str(if self.entries.is_empty() {
            "}\n}\n"
        } else {
            "\n  }\n}\n"
        });
        text
    }

    /// A digest of the canonical text.
    pub fn digest(&self) -> Digest {
        digest(GOLDEN_DOMAIN, &[self.canonical_text().as_bytes()])
    }

    pub fn firecracker_version(&self) -> &ComponentVersion {
        &self.firecracker_version
    }

    pub fn entries(&self) -> &BTreeMap<String, Value> {
        &self.entries
    }

    /// Firecracker's arguments as the file holds them, in argument order: the entries
    /// `firecracker.args /0`, `firecracker.args /1` and so on, each a string, with no index
    /// missing or written in another form. `None` when an entry under that prefix is
    /// anything else.
    pub fn firecracker_args(&self) -> Option<Vec<&str>> {
        let mut args = BTreeMap::new();
        for (key, value) in &self.entries {
            let Some(rest) = key.strip_prefix(ARGS_KEY) else {
                continue;
            };
            let digits = rest.strip_prefix(" /")?;
            let index: usize = digits.parse().ok()?;
            if index.to_string() != digits {
                return None;
            }
            args.insert(index, value.as_str()?);
        }
        args.keys()
            .copied()
            .eq(0..args.len())
            .then(|| args.into_values().collect())
    }
}

/// One entry of a golden file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GoldenEntry {
    pub key: String,
    pub value: Value,
}

/// An entry present on both sides with different values.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ChangedEntry {
    pub key: String,
    pub expected: Value,
    pub observed: Value,
}

/// The difference between a golden file and an observed configuration.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct GoldenDiff {
    /// Observed but not in the golden file.
    pub unexpected: Vec<GoldenEntry>,
    /// In the golden file but not observed.
    pub missing: Vec<GoldenEntry>,
    /// Observed with another value; a version difference is reported under
    /// [`VERSION_KEY`].
    pub changed: Vec<ChangedEntry>,
}

impl GoldenDiff {
    /// Whether the observed configuration matches the golden file exactly.
    pub fn is_match(&self) -> bool {
        self.unexpected.is_empty() && self.missing.is_empty() && self.changed.is_empty()
    }
}

/// Compares an observed configuration with the golden file.
pub fn compare(golden: &GoldenFile, observed: &GoldenFile) -> GoldenDiff {
    let mut diff = GoldenDiff::default();
    if golden.firecracker_version != observed.firecracker_version {
        diff.changed.push(ChangedEntry {
            key: VERSION_KEY.to_owned(),
            expected: Value::String(golden.firecracker_version.to_string()),
            observed: Value::String(observed.firecracker_version.to_string()),
        });
    }
    for (key, expected) in &golden.entries {
        match observed.entries.get(key) {
            None => diff.missing.push(GoldenEntry {
                key: key.clone(),
                value: expected.clone(),
            }),
            Some(found) if found != expected => diff.changed.push(ChangedEntry {
                key: key.clone(),
                expected: expected.clone(),
                observed: found.clone(),
            }),
            Some(_) => {}
        }
    }
    for (key, value) in &observed.entries {
        if !golden.entries.contains_key(key) {
            diff.unexpected.push(GoldenEntry {
                key: key.clone(),
                value: value.clone(),
            });
        }
    }
    diff
}

/// Configuration VM-CP-02 forbids unless declared, or that a cold-boot launch never has.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(tag = "item", rename_all = "snake_case")]
pub enum ForbiddenItem {
    /// A network interface the profile does not declare.
    UndeclaredNetworkInterface {
        iface_id: String,
    },
    /// A console in the boot arguments or a serial device.
    Console,
    Balloon,
    PciTransport,
    MetadataService,
    /// A seccomp override in Firecracker's arguments.
    SeccompOverride,
    /// A snapshot load or creation in a cold-boot launch.
    SnapshotOperation,
}

/// Names forbidden configuration in an observed golden file.
pub fn forbidden(observed: &GoldenFile, profile: &FirecrackerProfile) -> BTreeSet<ForbiddenItem> {
    let declared: BTreeSet<&str> = profile
        .network_interfaces
        .iter()
        .map(|interface| interface.iface_id.as_str())
        .collect();
    let mut found = BTreeSet::new();
    for (key, value) in &observed.entries {
        if key.starts_with(ARGS_KEY) {
            match value.as_str() {
                Some("--enable-pci") => {
                    found.insert(ForbiddenItem::PciTransport);
                }
                Some("--no-seccomp" | "--seccomp-filter") => {
                    found.insert(ForbiddenItem::SeccompOverride);
                }
                Some("--metadata") => {
                    found.insert(ForbiddenItem::MetadataService);
                }
                _ => {}
            }
            continue;
        }
        let mut parts = key.splitn(3, ' ');
        let (Some(_method), Some(path)) = (parts.next(), parts.next()) else {
            continue;
        };
        let pointer = parts.next().unwrap_or_default();
        if let Some(iface_id) = path.strip_prefix("/network-interfaces/") {
            if !declared.contains(iface_id) {
                found.insert(ForbiddenItem::UndeclaredNetworkInterface {
                    iface_id: iface_id.to_owned(),
                });
            }
        } else if path == "/balloon" || path.starts_with("/balloon/") {
            found.insert(ForbiddenItem::Balloon);
        } else if path == "/mmds" || path.starts_with("/mmds/") {
            found.insert(ForbiddenItem::MetadataService);
        } else if path == "/serial" {
            found.insert(ForbiddenItem::Console);
        } else if path.starts_with("/snapshot/") {
            found.insert(ForbiddenItem::SnapshotOperation);
        } else if path == "/boot-source" && pointer == "/boot_args" {
            let console = value.as_str().is_some_and(|args| {
                args.split_whitespace()
                    .any(|arg| arg.starts_with("console="))
            });
            if console {
                found.insert(ForbiddenItem::Console);
            }
        }
    }
    found
}

/// The VM-CP-02 result: the difference from the golden file and the forbidden items.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GoldenCheck {
    pub diff: GoldenDiff,
    pub forbidden: BTreeSet<ForbiddenItem>,
}

impl GoldenCheck {
    /// Compares `observed` with `golden` and scans it against `profile`.
    pub fn run(golden: &GoldenFile, observed: &GoldenFile, profile: &FirecrackerProfile) -> Self {
        Self {
            diff: compare(golden, observed),
            forbidden: forbidden(observed, profile),
        }
    }

    /// Whether the configuration matches and holds nothing forbidden.
    pub fn passed(&self) -> bool {
        self.diff.is_match() && self.forbidden.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::super::fixtures;
    use super::*;
    use serde_json::json;

    fn golden() -> GoldenFile {
        GoldenFile::from_plan(&fixtures::plan())
    }

    fn with(entries: &[(&str, Value)]) -> GoldenFile {
        let base = golden();
        let mut map = base.entries().clone();
        for (key, value) in entries {
            map.insert((*key).to_owned(), value.clone());
        }
        GoldenFile::from_entries(base.firecracker_version().clone(), map).unwrap()
    }

    #[test]
    fn the_golden_file_of_the_strict_profile_is_exact() {
        let text = golden().canonical_text();
        let expected = r#"{
  "schema": 1,
  "firecracker_version": "1.10.1",
  "entries": {
    "PUT /actions /action_type": "InstanceStart",
    "PUT /boot-source /boot_args": "reboot=k panic=1 pci=off 8250.nr_uarts=0",
    "PUT /boot-source /kernel_image_path": "/images/vmlinux",
    "PUT /drives/rootfs /drive_id": "rootfs",
    "PUT /drives/rootfs /is_read_only": true,
    "PUT /drives/rootfs /is_root_device": true,
    "PUT /drives/rootfs /path_on_host": "/images/rootfs.img",
    "PUT /entropy": {},
    "PUT /logger /level": "Warning",
    "PUT /logger /log_path": "/sinks/log.fifo",
    "PUT /logger /show_level": false,
    "PUT /logger /show_log_origin": false,
    "PUT /machine-config /mem_size_mib": 1024,
    "PUT /machine-config /smt": false,
    "PUT /machine-config /track_dirty_pages": false,
    "PUT /machine-config /vcpu_count": 2,
    "PUT /metrics /metrics_path": "/sinks/metrics.fifo",
    "PUT /vsock /guest_cid": 3,
    "PUT /vsock /uds_path": "/run/link.sock",
    "firecracker.args /0": "--api-sock",
    "firecracker.args /1": "/run/firecracker.socket",
    "sequence": "PUT /logger, PUT /metrics, PUT /machine-config, PUT /boot-source, PUT /drives/rootfs, PUT /vsock, PUT /entropy, PUT /actions"
  }
}
"#;
        assert_eq!(text, expected);
        assert_eq!(GoldenFile::parse(&text), Ok(golden()));
        assert_eq!(golden().digest(), golden().digest());
        assert!(GoldenCheck::run(&golden(), &golden(), &fixtures::profile()).passed());
    }

    #[test]
    fn firecrackers_arguments_read_back_in_order_from_exact_entries_only() {
        assert_eq!(
            golden().firecracker_args(),
            Some(vec!["--api-sock", "/run/firecracker.socket"])
        );
        // Twelve arguments: the keys sort as text, `/10` before `/2`, and still read back
        // in argument order.
        let version = ComponentVersion::new("1.10.1").unwrap();
        let args: Vec<String> = (0..12).map(|index| format!("--arg-{index}")).collect();
        let many = GoldenFile::from_parts(&version, fixtures::plan().api(), &args);
        assert_eq!(
            many.firecracker_args(),
            Some(args.iter().map(String::as_str).collect())
        );
        for (key, value) in [
            ("firecracker.args /3", json!("--after-a-gap")),
            ("firecracker.args /01", json!("--leading-zero")),
            ("firecracker.args /+1", json!("--signed")),
            ("firecracker.args /x", json!("--not-an-index")),
            ("firecracker.args", json!("--no-index")),
            ("firecracker.argsx", json!("--other-prefix")),
            ("firecracker.args /1", json!(1)),
        ] {
            assert_eq!(with(&[(key, value)]).firecracker_args(), None, "{key}");
        }
        let empty = GoldenFile::from_entries(version, BTreeMap::new()).unwrap();
        assert_eq!(empty.firecracker_args(), Some(Vec::new()));
    }

    #[test]
    fn the_digest_changes_with_every_entry_and_the_version() {
        let base = golden();
        let mut seen = BTreeSet::new();
        seen.insert(base.digest());
        for key in base.entries().keys() {
            let changed = with(&[(key.as_str(), json!("changed"))]);
            assert!(seen.insert(changed.digest()), "{key}");
            let mut fewer = base.entries().clone();
            fewer.remove(key);
            let removed =
                GoldenFile::from_entries(base.firecracker_version().clone(), fewer).unwrap();
            assert!(seen.insert(removed.digest()), "{key}");
        }
        let other_version = GoldenFile::from_entries(
            ComponentVersion::new("1.10.2").unwrap(),
            base.entries().clone(),
        )
        .unwrap();
        assert!(seen.insert(other_version.digest()));
    }

    #[test]
    fn a_declared_network_interface_is_required_for_one_to_appear() {
        let strict = golden();
        let network_plan = fixtures::network_plan();
        let observed = GoldenFile::from_plan(&network_plan);
        let check = GoldenCheck::run(&strict, &observed, &fixtures::profile());
        assert!(!check.passed());
        let unexpected: Vec<&str> = check
            .diff
            .unexpected
            .iter()
            .map(|entry| entry.key.as_str())
            .collect();
        assert_eq!(
            unexpected,
            [
                "PUT /network-interfaces/eth0 /guest_mac",
                "PUT /network-interfaces/eth0 /host_dev_name",
                "PUT /network-interfaces/eth0 /iface_id",
            ]
        );
        assert_eq!(check.diff.changed.len(), 1);
        assert_eq!(check.diff.changed[0].key, SEQUENCE_KEY);
        assert!(check.diff.missing.is_empty());
        assert_eq!(
            check.forbidden,
            [ForbiddenItem::UndeclaredNetworkInterface {
                iface_id: "eth0".to_owned()
            }]
            .into_iter()
            .collect()
        );

        let approved = GoldenFile::from_plan(&network_plan);
        let declared = GoldenCheck::run(&approved, &observed, &fixtures::network_profile());
        assert!(declared.passed());
    }

    #[test]
    fn missing_and_changed_entries_and_versions_are_reported() {
        let base = golden();
        let mut without_entropy = base.entries().clone();
        without_entropy.remove("PUT /entropy");
        let observed =
            GoldenFile::from_entries(base.firecracker_version().clone(), without_entropy).unwrap();
        let diff = compare(&base, &observed);
        assert_eq!(
            diff.missing,
            [GoldenEntry {
                key: "PUT /entropy".to_owned(),
                value: json!({})
            }]
        );
        assert!(diff.unexpected.is_empty() && diff.changed.is_empty());

        let resized = with(&[("PUT /machine-config /vcpu_count", json!(4))]);
        let diff = compare(&base, &resized);
        assert_eq!(
            diff.changed,
            [ChangedEntry {
                key: "PUT /machine-config /vcpu_count".to_owned(),
                expected: json!(2),
                observed: json!(4)
            }]
        );

        let other_version = GoldenFile::from_entries(
            ComponentVersion::new("1.11.0").unwrap(),
            base.entries().clone(),
        )
        .unwrap();
        let diff = compare(&base, &other_version);
        assert_eq!(diff.changed.len(), 1);
        assert_eq!(diff.changed[0].key, VERSION_KEY);
        assert!(!diff.is_match());
    }

    #[test]
    fn forbidden_configuration_is_named() {
        let profile = fixtures::profile();
        let cases = [
            (
                "PUT /boot-source /boot_args",
                json!("console=ttyS0 reboot=k panic=1 pci=off"),
                ForbiddenItem::Console,
            ),
            (
                "PUT /serial /serial_out_path",
                json!("/dev/pts/3"),
                ForbiddenItem::Console,
            ),
            (
                "PUT /balloon /amount_mib",
                json!(64),
                ForbiddenItem::Balloon,
            ),
            (
                "PUT /mmds/config /version",
                json!("V2"),
                ForbiddenItem::MetadataService,
            ),
            ("PUT /mmds", json!({}), ForbiddenItem::MetadataService),
            (
                "firecracker.args /2",
                json!("--enable-pci"),
                ForbiddenItem::PciTransport,
            ),
            (
                "firecracker.args /2",
                json!("--no-seccomp"),
                ForbiddenItem::SeccompOverride,
            ),
            (
                "firecracker.args /2",
                json!("--seccomp-filter"),
                ForbiddenItem::SeccompOverride,
            ),
            (
                "firecracker.args /2",
                json!("--metadata"),
                ForbiddenItem::MetadataService,
            ),
            (
                "PUT /snapshot/load /snapshot_path",
                json!("/snap"),
                ForbiddenItem::SnapshotOperation,
            ),
        ];
        for (key, value, item) in cases {
            let observed = with(&[(key, value)]);
            let check = GoldenCheck::run(&golden(), &observed, &profile);
            assert_eq!(
                check.forbidden,
                [item.clone()].into_iter().collect(),
                "{key}"
            );
            assert!(!check.passed());
        }
        assert!(forbidden(&golden(), &profile).is_empty());
    }

    #[test]
    fn parsing_is_strict() {
        let text = golden().canonical_text();
        let cases = [
            (text.replace("\"schema\": 1", "\"schema\": 2"), "schema"),
            (
                text.replacen("{\n", "{\n  \"signed\": true,\n", 1),
                "unknown",
            ),
            (text.replace("\n    ", "\n  "), "whitespace"),
            (text.trim_end().to_owned(), "newline"),
            (
                text.replace("\"sequence\":", "\"PUT /entropy\": {},\n    \"sequence\":"),
                "duplicate",
            ),
            (
                text.replace("\"PUT /entropy\": {}", "\"PUT /entropy\": {\"a\": 1}"),
                "leaf",
            ),
            (
                text.replace("\"PUT /entropy\"", "\"PUT\\t/entropy\""),
                "key",
            ),
            (text.replace("\"1.10.1\"", "\"1.10.1 beta\""), "version"),
            ("[]".to_owned(), "shape"),
        ];
        for (bad, what) in cases {
            assert!(GoldenFile::parse(&bad).is_err(), "{what}");
        }
        assert_eq!(
            GoldenFile::parse(&text.replace("\"schema\": 1", "\"schema\": 2")),
            Err(GoldenError::UnsupportedSchema { schema: 2 })
        );
        assert_eq!(
            GoldenFile::parse(&text.replace("\n    ", "\n  ")),
            Err(GoldenError::NotCanonical)
        );
        assert!(matches!(
            GoldenFile::parse(
                &text.replace("\"PUT /entropy\": {}", "\"PUT /entropy\": {\"a\": 1}")
            ),
            Err(GoldenError::NotLeaf { .. })
        ));
        assert!(matches!(
            GoldenFile::parse(&" ".repeat(MAX_GOLDEN_BYTES + 1)),
            Err(GoldenError::TooLarge { .. })
        ));
        assert!(matches!(
            GoldenFile::from_entries(
                ComponentVersion::new("1.10.1").unwrap(),
                [(String::new(), json!(1))].into_iter().collect()
            ),
            Err(GoldenError::InvalidKey { .. })
        ));
        let empty =
            GoldenFile::from_entries(ComponentVersion::new("1.10.1").unwrap(), BTreeMap::new())
                .unwrap();
        assert_eq!(GoldenFile::parse(&empty.canonical_text()), Ok(empty));
    }
}
