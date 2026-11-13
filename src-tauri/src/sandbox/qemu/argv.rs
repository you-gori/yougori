//! Argument vectors: the structured form a profile renders, its concrete and canonical
//! text, an observed vector as a process listing shows it, and the keyed comparison of
//! two vectors (VM-CP-02, line 3152). The vector goes to the process directly, never
//! through a shell; QEMU option values double every literal comma.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Serialize;

/// Most arguments an observed vector may have.
pub const MAX_OBSERVED_ARGUMENTS: usize = 512;
/// Longest observed argument, in bytes.
pub const MAX_OBSERVED_ARGUMENT_BYTES: usize = 8192;

/// A per-launch value of a profile. The canonical form writes `{role}` in its place, so
/// one golden file covers every launch of a profile while every fixed argument stays
/// exact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(tag = "role", rename_all = "snake_case")]
pub enum Role {
    Instance,
    VcpuCount,
    Memory,
    FirmwareDirectory,
    Kernel,
    Initrd,
    KernelArguments,
    RootImage,
    Volume { index: u16 },
    QmpSocket,
    LinkSocket,
    LinkSecret,
    EgressEndpoints,
    Workload,
    GuestCid,
    /// One of the network filter's four sockets (`NETWORK_SOCKET_NAMES`).
    NetworkSocket { index: u8 },
}

impl Role {
    /// The text written in place of the value in the canonical form.
    pub fn placeholder(self) -> String {
        match self {
            Self::Instance => "{instance}".into(),
            Self::VcpuCount => "{vcpu_count}".into(),
            Self::Memory => "{memory}".into(),
            Self::FirmwareDirectory => "{firmware_directory}".into(),
            Self::Kernel => "{kernel}".into(),
            Self::Initrd => "{initrd}".into(),
            Self::KernelArguments => "{kernel_arguments}".into(),
            Self::RootImage => "{root_image}".into(),
            Self::Volume { index } => format!("{{volume{index}}}"),
            Self::QmpSocket => "{qmp_socket}".into(),
            Self::LinkSocket => "{link_socket}".into(),
            Self::LinkSecret => "{link_secret}".into(),
            Self::EgressEndpoints => "{egress_endpoints}".into(),
            Self::Workload => "{workload}".into(),
            Self::GuestCid => "{guest_cid}".into(),
            Self::NetworkSocket { index } => format!("{{network_socket{index}}}"),
        }
    }
}

/// One value: fixed text, or a per-launch value with its role.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Part {
    Text(String),
    Bound(Role, String),
}

impl Part {
    pub(super) fn text(text: impl Into<String>) -> Self {
        Self::Text(text.into())
    }

    fn concrete(&self) -> &str {
        match self {
            Self::Text(text) | Self::Bound(_, text) => text,
        }
    }

    fn canonical(&self) -> String {
        match self {
            Self::Text(text) => text.clone(),
            Self::Bound(role, _) => role.placeholder(),
        }
    }
}

/// One `key=value` item of a QEMU option, or the option's implied first value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Item {
    pub(super) key: Option<&'static str>,
    pub(super) part: Part,
}

impl Item {
    pub(super) fn implied(text: impl Into<String>) -> Self {
        Self {
            key: None,
            part: Part::text(text),
        }
    }

    pub(super) fn pair(key: &'static str, text: impl Into<String>) -> Self {
        Self {
            key: Some(key),
            part: Part::text(text),
        }
    }

    pub(super) fn bound(key: &'static str, role: Role, text: impl Into<String>) -> Self {
        Self {
            key: Some(key),
            part: Part::Bound(role, text.into()),
        }
    }
}

/// An option's value: plain text QEMU takes whole, or a comma-separated item list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Value {
    Plain(Part),
    Items(Vec<Item>),
}

/// One option of a rendered vector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Arg {
    pub(super) option: &'static str,
    pub(super) value: Option<Value>,
}

impl Arg {
    pub(super) fn flag(option: &'static str) -> Self {
        Self {
            option,
            value: None,
        }
    }

    pub(super) fn plain(option: &'static str, part: Part) -> Self {
        Self {
            option,
            value: Some(Value::Plain(part)),
        }
    }

    pub(super) fn items(option: &'static str, items: Vec<Item>) -> Self {
        Self {
            option,
            value: Some(Value::Items(items)),
        }
    }

    fn render(&self, canonical: bool) -> Pair {
        let value = self.value.as_ref().map(|value| match value {
            Value::Plain(part) if canonical => part.canonical(),
            Value::Plain(part) => part.concrete().to_owned(),
            Value::Items(items) => items
                .iter()
                .map(|item| {
                    let text = if canonical {
                        escape(&item.part.canonical())
                    } else {
                        escape(item.part.concrete())
                    };
                    match item.key {
                        Some(key) => format!("{key}={text}"),
                        None => text,
                    }
                })
                .collect::<Vec<_>>()
                .join(","),
        });
        Pair {
            option: self.option.to_owned(),
            value,
        }
    }

    /// The per-launch values of this option, by where they appear.
    fn sites(&self) -> Vec<(Site, Role, String)> {
        match &self.value {
            Some(Value::Plain(Part::Bound(role, text))) => {
                vec![(Site::new(self.option, None), *role, text.clone())]
            }
            Some(Value::Items(items)) => items
                .iter()
                .filter_map(|item| match &item.part {
                    Part::Bound(role, text) => {
                        Some((Site::new(self.option, item.key), *role, text.clone()))
                    }
                    Part::Text(_) => None,
                })
                .collect(),
            _ => Vec::new(),
        }
    }
}

/// Doubles every comma, QEMU's escape inside an option value.
pub(super) fn escape(text: &str) -> String {
    text.replace(',', ",,")
}

/// Splits an option value into its items at single commas, undoing doubled commas.
/// Items without `=` have no key.
pub(super) fn split_items(value: &str) -> Vec<(Option<String>, String)> {
    let mut items = Vec::new();
    let mut current = String::new();
    let mut characters = value.chars().peekable();
    while let Some(character) = characters.next() {
        if character == ',' {
            if characters.peek() == Some(&',') {
                characters.next();
                current.push(',');
            } else {
                items.push(std::mem::take(&mut current));
            }
        } else {
            current.push(character);
        }
    }
    items.push(current);
    items
        .into_iter()
        .map(|item| match item.split_once('=') {
            Some((key, value)) => (Some(key.to_owned()), value.to_owned()),
            None => (None, item),
        })
        .collect()
}

/// Joins items back into an option value.
fn join_items(items: &[(Option<String>, String)]) -> String {
    items
        .iter()
        .map(|(key, value)| match key {
            Some(key) => format!("{key}={}", escape(value)),
            None => escape(value),
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Options whose value QEMU takes whole, without item parsing.
const PLAIN_OPTIONS: &[&str] = &["-L", "-kernel", "-initrd", "-append", "-m", "-name", "-cpu"];

/// Options that take a value. Anything else that starts with `-` is a flag or unknown.
pub(super) const VALUE_OPTIONS: &[&str] = &[
    "-accel",
    "-action",
    "-add-fd",
    "-append",
    "-audio",
    "-audiodev",
    "-bios",
    "-blockdev",
    "-boot",
    "-cdrom",
    "-chardev",
    "-chroot",
    "-compat",
    "-cpu",
    "-D",
    "-d",
    "-debugcon",
    "-device",
    "-display",
    "-drive",
    "-fda",
    "-fdb",
    "-fsdev",
    "-fw_cfg",
    "-gdb",
    "-global",
    "-hda",
    "-hdb",
    "-hdc",
    "-hdd",
    "-icount",
    "-incoming",
    "-initrd",
    "-iscsi",
    "-k",
    "-kernel",
    "-L",
    "-loadvm",
    "-M",
    "-m",
    "-machine",
    "-mem-path",
    "-mon",
    "-monitor",
    "-msg",
    "-mtdblock",
    "-name",
    "-net",
    "-netdev",
    "-nic",
    "-numa",
    "-object",
    "-option-rom",
    "-overcommit",
    "-parallel",
    "-pflash",
    "-pidfile",
    "-plugin",
    "-qmp",
    "-qmp-pretty",
    "-readconfig",
    "-rtc",
    "-run-with",
    "-runas",
    "-sandbox",
    "-sd",
    "-semihosting-config",
    "-serial",
    "-smbios",
    "-smp",
    "-spice",
    "-tpmdev",
    "-trace",
    "-usbdevice",
    "-uuid",
    "-vga",
    "-virtfs",
    "-vnc",
    "-watchdog-action",
    "-writeconfig",
];

/// Options that take no value.
pub(super) const FLAG_OPTIONS: &[&str] = &[
    "-daemonize",
    "-enable-kvm",
    "-full-screen",
    "-no-acpi",
    "-no-fd-bootchk",
    "-no-hpet",
    "-no-reboot",
    "-no-shutdown",
    "-no-user-config",
    "-nodefaults",
    "-nographic",
    "-only-migratable",
    "-preconfig",
    "-S",
    "-s",
    "-semihosting",
    "-snapshot",
    "-usb",
    "-win2k-hack",
];

/// Options that may appear several times, told apart by an identifying item.
const REPEATED_OPTIONS: &[&str] = &[
    "-device",
    "-blockdev",
    "-chardev",
    "-mon",
    "-fw_cfg",
    "-object",
    "-netdev",
    "-nic",
    "-net",
    "-drive",
    "-global",
    "-fsdev",
    "-virtfs",
    "-tpmdev",
    "-audiodev",
    "-add-fd",
];

/// An option and its value, as text.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct Pair {
    pub option: String,
    pub value: Option<String>,
}

impl Pair {
    /// The option and value as one line of text.
    pub fn text(&self) -> String {
        match &self.value {
            Some(value) => format!("{} {}", self.option, value),
            None => self.option.clone(),
        }
    }

    fn tokens(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.option.as_str()).chain(self.value.as_deref())
    }

    /// The name QEMU reads: `--x` is the same option as `-x`, and `-M` is `-machine`.
    pub(super) fn normalized_option(&self) -> String {
        normalize(&self.option)
    }
}

pub(super) fn normalize(option: &str) -> String {
    let single = match option.strip_prefix("--") {
        Some(rest) => format!("-{rest}"),
        None => option.to_owned(),
    };
    if single == "-M" {
        "-machine".to_owned()
    } else {
        single
    }
}

/// Renders options as concrete pairs.
pub(super) fn concrete(args: &[Arg]) -> Vec<Pair> {
    args.iter().map(|arg| arg.render(false)).collect()
}

/// Renders options as canonical pairs, per-launch values replaced by their roles.
pub(super) fn canonical(args: &[Arg]) -> Vec<Pair> {
    args.iter().map(|arg| arg.render(true)).collect()
}

/// Flattens pairs into an argument vector.
pub(super) fn flatten(pairs: &[Pair]) -> Vec<String> {
    pairs
        .iter()
        .flat_map(|pair| pair.tokens().map(str::to_owned).collect::<Vec<_>>())
        .collect()
}

/// Where a per-launch value appears: an option and, for an item list, the item's key.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Site {
    option: String,
    key: Option<String>,
}

impl Site {
    fn new(option: &str, key: Option<&str>) -> Self {
        Self {
            option: option.to_owned(),
            key: key.map(str::to_owned),
        }
    }
}

/// The per-launch values of a rendered vector, by site, for canonicalizing an observed
/// vector against the launch that was meant to produce it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Bindings(BTreeMap<Site, Vec<(Role, String)>>);

impl Bindings {
    pub(super) fn of(args: &[Arg]) -> Self {
        let mut sites: BTreeMap<Site, Vec<(Role, String)>> = BTreeMap::new();
        for (site, role, text) in args.iter().flat_map(Arg::sites) {
            sites.entry(site).or_default().push((role, text));
        }
        Self(sites)
    }

    fn role_at(&self, option: &str, key: Option<&str>, text: &str) -> Option<Role> {
        self.0
            .get(&Site::new(option, key))?
            .iter()
            .find(|(_, bound)| bound == text)
            .map(|(role, _)| *role)
    }

    /// The canonical form of an observed pair: a value equal to a per-launch value at the
    /// same site becomes that value's placeholder; everything else stays as written.
    pub(super) fn canonicalize(&self, pair: &Pair) -> Pair {
        let option = pair.option.as_str();
        let value = pair.value.as_ref().map(|value| {
            if PLAIN_OPTIONS.contains(&option) {
                match self.role_at(option, None, value) {
                    Some(role) => role.placeholder(),
                    None => value.clone(),
                }
            } else {
                let items: Vec<(Option<String>, String)> = split_items(value)
                    .into_iter()
                    .map(|(key, text)| {
                        match key
                            .as_deref()
                            .and_then(|key| self.role_at(option, Some(key), &text))
                        {
                            Some(role) => (key, role.placeholder()),
                            None => (key, text),
                        }
                    })
                    .collect();
                join_items(&items)
            }
        });
        Pair {
            option: pair.option.clone(),
            value,
        }
    }
}

/// Why an observed argument vector could not be read at all.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum ObservedArgvError {
    /// A process listing always names the executable first.
    NoExecutable,
    TooManyArguments {
        count: usize,
        max: usize,
    },
    ArgumentTooLong {
        index: usize,
        length_bytes: usize,
        max_bytes: usize,
    },
}

impl fmt::Display for ObservedArgvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoExecutable => f.write_str("the process listing names no executable"),
            Self::TooManyArguments { count, max } => {
                write!(f, "the process has {count} arguments, more than {max}")
            }
            Self::ArgumentTooLong {
                index,
                length_bytes,
                max_bytes,
            } => write!(
                f,
                "argument {index} is {length_bytes} bytes, more than {max_bytes}"
            ),
        }
    }
}

impl std::error::Error for ObservedArgvError {}

/// A hypervisor's argument vector as the host's process listing shows it: the executable
/// first, then the arguments (VM-CP-01, VM-CP-03: host-observed).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ObservedArgv {
    executable: String,
    arguments: Vec<String>,
}

impl ObservedArgv {
    /// Reads a process listing's vector: the executable, then the arguments.
    pub fn from_process_listing(argv: &[String]) -> Result<Self, ObservedArgvError> {
        let (executable, arguments) = argv.split_first().ok_or(ObservedArgvError::NoExecutable)?;
        Self::new(executable.clone(), arguments.to_vec())
    }

    /// Refuses a vector without an executable or beyond the size bounds.
    pub fn new(executable: String, arguments: Vec<String>) -> Result<Self, ObservedArgvError> {
        if executable.is_empty() || executable.starts_with('-') {
            return Err(ObservedArgvError::NoExecutable);
        }
        if arguments.len() > MAX_OBSERVED_ARGUMENTS {
            return Err(ObservedArgvError::TooManyArguments {
                count: arguments.len(),
                max: MAX_OBSERVED_ARGUMENTS,
            });
        }
        for (index, argument) in std::iter::once(&executable)
            .chain(arguments.iter())
            .enumerate()
        {
            if argument.len() > MAX_OBSERVED_ARGUMENT_BYTES {
                return Err(ObservedArgvError::ArgumentTooLong {
                    index,
                    length_bytes: argument.len(),
                    max_bytes: MAX_OBSERVED_ARGUMENT_BYTES,
                });
            }
        }
        Ok(Self {
            executable,
            arguments,
        })
    }

    pub fn executable(&self) -> &str {
        &self.executable
    }

    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }

    /// The arguments as options with their values, in order; see [`pairs_of`].
    pub(super) fn pairs(&self) -> Vec<Pair> {
        pairs_of(&self.arguments)
    }
}

/// Reads arguments as options with their values. A value is taken for every option QEMU
/// gives one; an unknown option takes the next argument if it does not start with `-`.
/// An argument where an option belongs is positional (QEMU reads it as a disk image) and
/// is kept in place as a pair without a value whose option does not start with `-`.
pub(super) fn pairs_of(arguments: &[String]) -> Vec<Pair> {
    let mut pairs = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        index += 1;
        if is_positional(argument) {
            pairs.push(Pair {
                option: argument.clone(),
                value: None,
            });
            continue;
        }
        let name = normalize(argument);
        let takes_value = if VALUE_OPTIONS.contains(&name.as_str()) {
            true
        } else if FLAG_OPTIONS.contains(&name.as_str()) {
            false
        } else {
            arguments
                .get(index)
                .is_some_and(|next| !next.starts_with('-'))
        };
        let value = if takes_value {
            let value = arguments.get(index).cloned();
            index += 1;
            value
        } else {
            None
        };
        pairs.push(Pair {
            option: argument.clone(),
            value,
        });
    }
    pairs
}

/// Whether an argument stands where an option belongs without being one.
pub(super) fn is_positional(argument: &str) -> bool {
    !argument.starts_with('-') || argument == "-"
}

/// How an observed vector differs from an expected one, option by option.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "difference", rename_all = "snake_case")]
pub enum ArgumentDifference {
    /// An argument the expected vector does not have.
    Unexpected { argument: String },
    /// An expected argument the observed vector lacks.
    Missing { argument: String },
    /// The same option, identified the same way, with another value.
    Changed { expected: String, observed: String },
}

impl fmt::Display for ArgumentDifference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unexpected { argument } => write!(f, "unexpected argument `{argument}`"),
            Self::Missing { argument } => write!(f, "missing argument `{argument}`"),
            Self::Changed { expected, observed } => {
                write!(f, "argument `{observed}` should be `{expected}`")
            }
        }
    }
}

/// The identity of an option within a vector: its normalized name, for a repeated
/// option its `id`, `node-name`, `name`, `chardev` or first item, and its occurrence
/// among options so identified.
fn keys(pairs: &[Pair]) -> Vec<String> {
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    pairs
        .iter()
        .map(|pair| {
            let option = pair.normalized_option();
            let base = if REPEATED_OPTIONS.contains(&option.as_str()) {
                let items = pair.value.as_deref().map(split_items).unwrap_or_default();
                let identifier = ["id", "node-name", "name", "chardev"]
                    .iter()
                    .find_map(|wanted| {
                        items
                            .iter()
                            .find(|(key, _)| key.as_deref() == Some(*wanted))
                            .map(|(key, value)| format!("{}={value}", key.as_deref().unwrap_or("")))
                    })
                    .or_else(|| items.first().map(|(_, value)| value.clone()))
                    .unwrap_or_default();
                format!("{option} {identifier}")
            } else {
                option
            };
            let count = seen.entry(base.clone()).or_insert(0);
            *count += 1;
            format!("{base}#{count}")
        })
        .collect()
}

/// Compares two vectors option by option. Returns the differences and whether the same
/// options appear in another order (QEMU applies some options in order, so order is part
/// of a profile).
pub(super) fn compare(expected: &[Pair], observed: &[Pair]) -> (Vec<ArgumentDifference>, bool) {
    let expected_keys = keys(expected);
    let observed_keys = keys(observed);
    let observed_by_key: BTreeMap<&String, &Pair> = observed_keys.iter().zip(observed).collect();
    let expected_set: BTreeSet<&String> = expected_keys.iter().collect();
    let mut differences = Vec::new();
    for (key, pair) in expected_keys.iter().zip(expected) {
        match observed_by_key.get(key) {
            None => differences.push(ArgumentDifference::Missing {
                argument: pair.text(),
            }),
            Some(seen) if seen.value != pair.value || seen.option != pair.option => differences
                .push(ArgumentDifference::Changed {
                    expected: pair.text(),
                    observed: seen.text(),
                }),
            Some(_) => {}
        }
    }
    for (key, pair) in observed_keys.iter().zip(observed) {
        if !expected_set.contains(key) {
            differences.push(ArgumentDifference::Unexpected {
                argument: pair.text(),
            });
        }
    }
    let reordered = differences.is_empty() && expected_keys != observed_keys;
    (differences, reordered)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(option: &str, value: Option<&str>) -> Pair {
        Pair {
            option: option.into(),
            value: value.map(Into::into),
        }
    }

    #[test]
    fn commas_are_doubled_and_undone() {
        assert_eq!(escape(r"C:\a,b"), r"C:\a,,b");
        assert_eq!(
            split_items(r"driver=file,filename=C:\a,,b,read-only=on"),
            vec![
                (Some("driver".into()), "file".into()),
                (Some("filename".into()), r"C:\a,b".into()),
                (Some("read-only".into()), "on".into()),
            ]
        );
        assert_eq!(
            split_items("microvm,acpi=on"),
            vec![(None, "microvm".into()), (Some("acpi".into()), "on".into())]
        );
        let items = split_items("socket,id=q,path=/a,,b=c,server=on");
        assert_eq!(items[2], (Some("path".into()), "/a,b=c".into()));
        assert_eq!(join_items(&items), "socket,id=q,path=/a,,b=c,server=on");
    }

    #[test]
    fn rendering_binds_values_to_roles() {
        let args = vec![
            Arg::plain("-m", Part::Bound(Role::Memory, "512M".into())),
            Arg::items(
                "-blockdev",
                vec![
                    Item::pair("driver", "file"),
                    Item::pair("node-name", "root-file"),
                    Item::bound("filename", Role::RootImage, "/x,y/root.img"),
                ],
            ),
            Arg::flag("-nodefaults"),
        ];
        let concrete = concrete(&args);
        assert_eq!(
            flatten(&concrete),
            vec![
                "-m",
                "512M",
                "-blockdev",
                "driver=file,node-name=root-file,filename=/x,,y/root.img",
                "-nodefaults"
            ]
        );
        let canonical_text = flatten(&canonical(&args));
        assert_eq!(canonical_text[1], "{memory}");
        assert_eq!(
            canonical_text[3],
            "driver=file,node-name=root-file,filename={root_image}"
        );
        let bindings = Bindings::of(&args);
        let recanonical: Vec<Pair> = concrete
            .iter()
            .map(|pair| bindings.canonicalize(pair))
            .collect();
        assert_eq!(recanonical, canonical(&args));
        // A value equal to a bound one at another site stays literal.
        assert_eq!(
            bindings
                .canonicalize(&pair("-blockdev", Some("driver=file,node-name=512M")))
                .value
                .unwrap(),
            "driver=file,node-name=512M"
        );
    }

    #[test]
    fn observed_vectors_need_an_executable_and_are_bounded() {
        assert_eq!(
            ObservedArgv::from_process_listing(&[]),
            Err(ObservedArgvError::NoExecutable)
        );
        assert_eq!(
            ObservedArgv::from_process_listing(&["-accel".into()]),
            Err(ObservedArgvError::NoExecutable)
        );
        let many = vec!["-S".to_owned(); MAX_OBSERVED_ARGUMENTS + 1];
        assert!(matches!(
            ObservedArgv::new("qemu".into(), many),
            Err(ObservedArgvError::TooManyArguments { .. })
        ));
        assert!(matches!(
            ObservedArgv::new(
                "qemu".into(),
                vec!["x".repeat(MAX_OBSERVED_ARGUMENT_BYTES + 1)]
            ),
            Err(ObservedArgvError::ArgumentTooLong { index: 1, .. })
        ));
    }

    #[test]
    fn observed_vectors_split_into_options_and_positionals() {
        let observed = ObservedArgv::from_process_listing(
            &[
                "qemu",
                "-nodefaults",
                "-m",
                "512M",
                "--accel",
                "kvm",
                "disk.img",
                "-unknown",
                "v",
                "-other",
                "-S",
            ]
            .map(String::from),
        )
        .unwrap();
        let pairs = observed.pairs();
        assert_eq!(
            pairs,
            vec![
                pair("-nodefaults", None),
                pair("-m", Some("512M")),
                pair("--accel", Some("kvm")),
                pair("disk.img", None),
                pair("-unknown", Some("v")),
                pair("-other", None),
                pair("-S", None),
            ]
        );
        assert_eq!(pairs[2].normalized_option(), "-accel");
        assert!(is_positional(&pairs[3].option));
        assert!(is_positional("-"));
        assert_eq!(normalize("-M"), "-machine");
    }

    #[test]
    fn comparison_reports_unexpected_missing_changed_and_order() {
        let expected = vec![
            pair("-nodefaults", None),
            pair("-device", Some("virtio-rng-device,id=rng")),
            pair("-device", Some("virtio-blk-device,id=root-disk,drive=root")),
            pair("-m", Some("512M")),
        ];
        assert_eq!(compare(&expected, &expected), (Vec::new(), false));
        let mut reordered = expected.clone();
        reordered.swap(1, 2);
        assert_eq!(compare(&expected, &reordered), (Vec::new(), true));
        let observed = vec![
            pair("-device", Some("virtio-rng-device,id=rng")),
            pair(
                "-device",
                Some("virtio-blk-device,id=root-disk,drive=other"),
            ),
            pair("-m", Some("1024M")),
            pair("-device", Some("virtio-balloon-device")),
            pair("-m", Some("512M")),
        ];
        let (differences, reordered) = compare(&expected, &observed);
        assert!(!reordered);
        assert_eq!(
            differences,
            vec![
                ArgumentDifference::Missing {
                    argument: "-nodefaults".into()
                },
                ArgumentDifference::Changed {
                    expected: "-device virtio-blk-device,id=root-disk,drive=root".into(),
                    observed: "-device virtio-blk-device,id=root-disk,drive=other".into(),
                },
                ArgumentDifference::Changed {
                    expected: "-m 512M".into(),
                    observed: "-m 1024M".into(),
                },
                ArgumentDifference::Unexpected {
                    argument: "-device virtio-balloon-device".into()
                },
                ArgumentDifference::Unexpected {
                    argument: "-m 512M".into()
                },
            ]
        );
        // A different spelling of the same option is a change, not a match.
        let spelled = vec![pair("--nodefaults", None)];
        assert_eq!(
            compare(&[pair("-nodefaults", None)], &spelled).0,
            vec![ArgumentDifference::Changed {
                expected: "-nodefaults".into(),
                observed: "--nodefaults".into()
            }]
        );
    }
}
