//! Tests of the host checks module: the strict parsers, both reader layouts, each guard
//! on recorded sysfs trees in temporary directories (a complete group, a group shared
//! with another device, no reset method, the boot display, missing ACS and facts that
//! cannot be read), the mapping onto VM-CP-31's observations and its positive control,
//! and the runner through the probes adapter into a real CORE-01 registry and through the
//! probes judge. Nothing here reads the host's own sysfs.

use std::collections::BTreeSet;
use std::sync::atomic::Ordering;

use super::address::{AddressError, IommuGroup, PciAddress, RootBus};
use super::assess::{assess, Hazard, Problem, Unassessable, Verdict};
use super::attributes::{
    parse_boot_vga, parse_class, parse_device_path, parse_driver_link, parse_group_link,
    parse_group_members, parse_reset_methods, ParseError, ResetMethod, MAX_UPSTREAM_PORTS,
};
use super::config::{
    parse_config, AcsRegisters, ConfigError, HeaderLayout, PortType, ACS_REQUEST_REDIRECT,
    ACS_REQUIRED,
};
use super::fixtures::*;
use super::node::{Attribute, NodeKind, SysfsNode};
use super::reader::{decode_component, encode_component, ReadError, SysfsReader};
use super::runner::{
    GpuAssignmentRunner, SettingsError, ACS_CHECKED, DISPLAY_OWNING, INCOMPLETE_GROUP, MAX_GPUS,
    QUALIFYING_ASSIGNS, RESET_CHECKED,
};
use crate::foundation::evidence::{
    Capability, GpuDeviceSubject, HostSubject, ObservationResult, OsKind, ProbeAdapter,
    Requirement, SourceClass, Subject, SupportDetail, UnknownReason, UnsupportedReason,
};
use crate::foundation::ids::{digest, GpuDeviceKey};
use crate::sandbox::backend::{
    GpuAssignmentOrder, GpuIsolation, GpuIsolationCheck, HostObserved, ObservedGpu,
    CHECKED_BEFORE_ASSIGNMENT,
};
use crate::sandbox::probes::{
    check, evaluate_observations, expectation, judge, CheckId, CheckStatus,
    DeviceAssignmentIsolatedProbe, ExpectationId, Failure, HostCheckRunner, HostKind,
    InconclusiveReason, Observations, Observed, Part, PartResult, ProbeOutcome, Role, RunResult,
    RunnerInconclusive,
};

// ---------------------------------------------------------------- helpers

fn cp31() -> CheckId {
    CheckId::new(31).unwrap()
}

fn id(name: &str) -> ExpectationId {
    ExpectationId::named(name).unwrap()
}

fn observed(result: RunResult) -> Observations {
    match result {
        RunResult::Observed { observations } => observations,
        other => panic!("expected observations, got {other:?}"),
    }
}

fn run(runner: &impl HostCheckRunner) -> RunResult {
    runner.run(cp31(), Part::Primary, &gpu_subject())
}

fn hazard(verdict: &Verdict) -> &Hazard {
    match verdict {
        Verdict::Hazard { hazard } => hazard,
        other => panic!("expected a hazard, got {other:?}"),
    }
}

fn undecided_at(verdict: &Verdict) -> (SysfsNode, Problem) {
    match verdict {
        Verdict::Undecided { problem } => (problem.node, problem.problem),
        other => panic!("expected an undecided verdict, got {other:?}"),
    }
}

fn missing() -> Problem {
    Problem::Read {
        error: ReadError::Missing,
    }
}

/// The result one refresh of the probes adapter stamps through a fresh registry.
fn refreshed(tree: &Tree, reference_gpu: Option<PciAddress>) -> ObservationResult {
    let (mut registry, _clock) = registry();
    registry
        .register(Box::new(DeviceAssignmentIsolatedProbe::new(runner(
            tree,
            reference_gpu,
        ))))
        .unwrap();
    registry
        .refresh(Capability::DeviceAssignmentIsolated, &gpu_subject())
        .unwrap()
        .result()
        .clone()
}

fn not_isolated() -> ObservationResult {
    ObservationResult::Unsupported {
        reason: UnsupportedReason::DeviceNotIsolated,
    }
}

fn unknown(reason: UnknownReason) -> ObservationResult {
    ObservationResult::Unknown { reason }
}

/// The trees of the four hazards, each with the expectation it must fail.
fn hazard_trees() -> Vec<(&'static str, Tree, &'static str)> {
    let shared = Tree::host();
    shared.device(&DeviceSpec {
        address: nic(),
        class: "0x020000\n",
        boot_vga: None,
        driver: Some("e1000e"),
        ..gpu_spec()
    });
    shared.group(1, &[gpu(), audio(), nic()]);

    let no_reset = Tree::host();
    no_reset.file(node(gpu(), Attribute::ResetMethod), b"");

    let boot_vga = Tree::host();
    boot_vga.file(node(gpu(), Attribute::BootVga), b"1\n");

    let missing_acs = Tree::host();
    missing_acs.port(
        port_a(),
        PortSpec {
            acs: None,
            ..PortSpec::root_port(0x01)
        },
    );

    vec![
        (
            "a group shared with another device",
            shared,
            INCOMPLETE_GROUP,
        ),
        ("no reset method", no_reset, RESET_CHECKED),
        ("the boot display", boot_vga, DISPLAY_OWNING),
        ("missing ACS", missing_acs, ACS_CHECKED),
    ]
}

// ---------------------------------------------------------------- addresses and parsers

#[test]
fn addresses_parse_only_in_the_kernels_spelling() {
    let address = PciAddress::parse("0000:01:00.1").unwrap();
    assert_eq!(
        (
            address.domain(),
            address.bus(),
            address.device(),
            address.function()
        ),
        (0, 1, 0, 1)
    );
    assert_eq!(address.to_string(), "0000:01:00.1");
    // A VMD domain above 0xffff keeps all its digits.
    assert_eq!(
        PciAddress::parse("10000:e1:1f.7").unwrap().to_string(),
        "10000:e1:1f.7"
    );
    for (text, error) in [
        ("0000:01:00", AddressError::Malformed),
        ("0000:01:00.0:1", AddressError::Malformed),
        ("000:01:00.0", AddressError::NotCanonical),
        ("00000:01:00.0", AddressError::NotCanonical),
        ("0000:1:00.0", AddressError::NotCanonical),
        ("0000:0A:00.0", AddressError::Malformed),
        ("0000:01:20.0", AddressError::DeviceOutOfRange),
        ("0000:01:00.8", AddressError::FunctionOutOfRange),
        ("0000:01:00.a", AddressError::Malformed),
        ("0000:01:00.10", AddressError::Malformed),
        ("+000:01:00.0", AddressError::Malformed),
        (" 0000:01:00.0", AddressError::Malformed),
        ("0000:01:00.0\n", AddressError::Malformed),
        ("", AddressError::Malformed),
    ] {
        assert_eq!(PciAddress::parse(text), Err(error), "{text:?}");
    }
    assert!(gpu().same_device(audio()));
    assert!(!gpu().same_device(reference()));
    assert!(!gpu().same_device(at("0000:01:01.0")));
    assert_eq!(
        PciAddress::new(0, 0, 0x20, 0),
        Err(AddressError::DeviceOutOfRange)
    );
}

#[test]
fn root_buses_and_groups_parse_only_in_the_kernels_spelling() {
    let root = RootBus::parse("pci0000:00").unwrap();
    assert_eq!((root.domain(), root.bus()), (0, 0));
    assert_eq!(RootBus::parse("pci10000:80").unwrap().domain(), 0x10000);
    for text in ["pci0000", "pci000:00", "PCI0000:00", "pci0000:0", "0000:00"] {
        assert!(RootBus::parse(text).is_err(), "{text}");
    }
    assert_eq!(IommuGroup::parse("0").unwrap().number(), 0);
    assert_eq!(IommuGroup::parse("117").unwrap().number(), 117);
    for text in ["", "07", "-1", "1a", "99999999999"] {
        assert!(IommuGroup::parse(text).is_err(), "{text}");
    }
}

#[test]
fn attribute_values_parse_strictly() {
    let class = parse_class(b"0x030000\n").unwrap();
    assert!(class.is_display() && class.is_vga());
    let three_d = parse_class(b"0x030200\n").unwrap();
    assert!(three_d.is_display() && !three_d.is_vga());
    assert!(!parse_class(b"0x040300\n").unwrap().is_display());
    for bytes in [
        &b"0x030000"[..],
        b"0x30000\n",
        b"0x0300000\n",
        b"0X030000\n",
        b"0x03000A\n",
        b"0x030000\n\n",
        b"0x030000\r\n",
        b" 0x030000\n",
    ] {
        assert_eq!(parse_class(bytes), Err(ParseError::Class), "{bytes:?}");
    }

    assert_eq!(parse_boot_vga(b"0\n"), Ok(false));
    assert_eq!(parse_boot_vga(b"1\n"), Ok(true));
    for bytes in [&b"1"[..], b"2\n", b"01\n", b"", b"yes\n"] {
        assert_eq!(parse_boot_vga(bytes), Err(ParseError::BootVga), "{bytes:?}");
    }

    assert_eq!(
        parse_reset_methods(b"device_specific acpi flr af_flr pm bus cxl_bus\n").unwrap(),
        ResetMethod::ALL.to_vec()
    );
    assert_eq!(parse_reset_methods(b""), Ok(Vec::new()));
    for (bytes, error) in [
        (&b"flr"[..], ParseError::ResetMethods),
        (b"flr  bus\n", ParseError::ResetMethods),
        (b" flr\n", ParseError::ResetMethods),
        (b"flr bus \n", ParseError::ResetMethods),
        (b"\n", ParseError::ResetMethods),
        (b"flr warm\n", ParseError::UnknownResetMethod),
        (b"FLR\n", ParseError::UnknownResetMethod),
        (b"flr flr\n", ParseError::RepeatedResetMethod),
    ] {
        assert_eq!(parse_reset_methods(bytes), Err(error), "{bytes:?}");
    }
}

#[test]
fn link_targets_parse_strictly() {
    assert_eq!(
        parse_group_link("../../../../kernel/iommu_groups/12").unwrap(),
        IommuGroup::new(12)
    );
    for target in [
        "kernel/iommu_groups/12",
        "/sys/kernel/iommu_groups/12",
        "../../../../kernel/iommu_groups/012",
        "../../../../kernel/iommu_groups/12/",
        "../../../../kernel/iommu_groups/../12",
        "../../../../kernel/groups/12",
        "../..//kernel/iommu_groups/12",
    ] {
        assert_eq!(
            parse_group_link(target),
            Err(ParseError::GroupLink),
            "{target}"
        );
    }

    assert_eq!(
        parse_driver_link("../../../../bus/pci/drivers/vfio-pci")
            .unwrap()
            .as_str(),
        "vfio-pci"
    );
    assert_eq!(
        parse_driver_link("../../bus/pci/drivers/snd_hda_intel")
            .unwrap()
            .as_str(),
        "snd_hda_intel"
    );
    let too_long = format!("../../bus/pci/drivers/{}", "a".repeat(65));
    for target in [
        "bus/pci/drivers/nvidia",
        "../../bus/usb/drivers/nvidia",
        "../../bus/pci/drivers/",
        "../../bus/pci/drivers/nvi dia",
        "../../bus/pci/drivers/..",
        too_long.as_str(),
    ] {
        assert_eq!(
            parse_driver_link(target),
            Err(ParseError::DriverLink),
            "{target}"
        );
    }

    let path = "../../../devices/pci0000:00/0000:00:01.0/0000:01:00.0";
    assert_eq!(parse_device_path(path, gpu()).unwrap(), vec![port_a()]);
    let switched =
        "../../../devices/pci0000:00/0000:00:01.0/0000:01:00.0/0000:02:01.0/0000:03:00.0";
    assert_eq!(
        parse_device_path(switched, at("0000:03:00.0")).unwrap(),
        vec![port_a(), at("0000:01:00.0"), at("0000:02:01.0")]
    );
    assert_eq!(
        parse_device_path(
            "../../../devices/pci0000:00/0000:00:02.0",
            at("0000:00:02.0")
        )
        .unwrap(),
        Vec::new()
    );
    for (target, error) in [
        (
            "../../devices/pci0000:00/0000:00:01.0/0000:01:00.0",
            ParseError::DevicePath,
        ),
        (
            "../../../devices/platform/0000:00:01.0/0000:01:00.0",
            ParseError::DevicePath,
        ),
        ("../../../devices/pci0000:00", ParseError::DevicePath),
        (
            "../../../devices/pci0000:00/0000:00:01.0/../0000:01:00.0",
            ParseError::DevicePath,
        ),
        (
            "../../../devices/pci0000:00/0000:00:01.0/0000:01:00.1",
            ParseError::DevicePathElsewhere,
        ),
        (
            "../../../devices/pci0001:00/0000:00:01.0/0000:01:00.0",
            ParseError::DevicePathDomain,
        ),
        (
            "../../../devices/pci0000:80/0000:00:01.0/0000:01:00.0",
            ParseError::DevicePathDomain,
        ),
    ] {
        assert_eq!(parse_device_path(target, gpu()), Err(error), "{target}");
    }
    let deep = format!(
        "../../../devices/pci0000:00/{}/0000:01:00.0",
        vec!["0000:00:01.0"; MAX_UPSTREAM_PORTS + 1].join("/")
    );
    assert_eq!(
        parse_device_path(&deep, gpu()),
        Err(ParseError::TooManyPorts)
    );
}

#[test]
fn group_members_parse_strictly() {
    let names = vec!["0000:01:00.1".to_owned(), "0000:01:00.0".to_owned()];
    assert_eq!(
        parse_group_members(&names).unwrap(),
        BTreeSet::from([gpu(), audio()])
    );
    assert_eq!(parse_group_members(&[]), Err(ParseError::EmptyGroup));
    assert_eq!(
        parse_group_members(&["0000:01:00.0".to_owned(), "type".to_owned()]),
        Err(ParseError::GroupMember)
    );
}

#[test]
fn configuration_spaces_parse_strictly() {
    let space = parse_config(&config_space(PortSpec::root_port(0x01))).unwrap();
    assert_eq!(space.layout, HeaderLayout::Bridge);
    assert_eq!(space.secondary_bus, Some(0x01));
    assert_eq!(space.express, Some(PortType::RootPort));
    assert_eq!(
        space.acs,
        Some(AcsRegisters {
            capability: FULL_ACS.0,
            control: FULL_ACS.1
        })
    );
    assert!(!space.multifunction);

    // A conventional bridge has no PCI Express capability and needs no extended space.
    let conventional = parse_config(&config_space(PortSpec {
        port_type: None,
        length: 256,
        ..PortSpec::root_port(0x01)
    }))
    .unwrap();
    assert_eq!((conventional.express, conventional.acs), (None, None));

    // The unprivileged 64-byte view, and a PCI Express port without its extended space.
    for (length, needed) in [(64, 256), (256, 4096), (63, 64), (0, 64)] {
        assert_eq!(
            parse_config(&config_space(PortSpec {
                length,
                ..PortSpec::root_port(0x01)
            })),
            Err(ConfigError::Truncated { length, needed }),
            "{length}"
        );
    }
    let mut long = config_space(PortSpec::root_port(0x01));
    long.push(0);
    assert_eq!(
        parse_config(&long),
        Err(ConfigError::TooLong { length: 4097 })
    );

    let mut absent = config_space(PortSpec::root_port(0x01));
    absent[0..2].copy_from_slice(&[0xff, 0xff]);
    assert_eq!(parse_config(&absent), Err(ConfigError::NoFunction));

    let mut layout = config_space(PortSpec::root_port(0x01));
    layout[0x0e] = 0x03;
    assert_eq!(parse_config(&layout), Err(ConfigError::UnknownLayout));

    let mut into_header = config_space(PortSpec::root_port(0x01));
    into_header[0x41] = 0x20;
    assert_eq!(
        parse_config(&into_header),
        Err(ConfigError::BadPointer { offset: 0x20 })
    );

    let mut standard_loop = config_space(PortSpec::root_port(0x01));
    standard_loop[0x41] = 0x40;
    assert_eq!(
        parse_config(&standard_loop),
        Err(ConfigError::CapabilityLoop)
    );

    let mut extended_loop = config_space(PortSpec {
        acs: None,
        ..PortSpec::root_port(0x01)
    });
    extended_loop[0x100..0x104].copy_from_slice(&(0x0001u32 | (0x100 << 20)).to_le_bytes());
    assert_eq!(
        parse_config(&extended_loop),
        Err(ConfigError::CapabilityLoop)
    );

    let mut backwards = config_space(PortSpec::root_port(0x01));
    backwards[0x100..0x104].copy_from_slice(&(0x0001u32 | (0x0c0 << 20)).to_le_bytes());
    assert_eq!(
        parse_config(&backwards),
        Err(ConfigError::BadPointer { offset: 0x0c0 })
    );

    // ACS at the very end of the space has no room for its registers.
    let mut cramped = config_space(PortSpec {
        acs: None,
        ..PortSpec::root_port(0x01)
    });
    cramped[0x100..0x104].copy_from_slice(&(0x0001u32 | (0xffc << 20)).to_le_bytes());
    cramped[0xffc..0x1000].copy_from_slice(&0x000du32.to_le_bytes());
    assert_eq!(
        parse_config(&cramped),
        Err(ConfigError::BadPointer { offset: 0xffc })
    );

    // A control the capability does not list is fixed on; one it lists must be on.
    let registers = |capability, control| AcsRegisters {
        capability,
        control,
    };
    assert_eq!(registers(0x001f, 0x001d).missing_controls(), 0);
    assert_eq!(registers(0x0000, 0x0000).missing_controls(), 0);
    assert_eq!(
        registers(0x001f, 0x0019).missing_controls(),
        ACS_REQUEST_REDIRECT
    );
    assert_eq!(registers(ACS_REQUIRED, 0).missing_controls(), ACS_REQUIRED);
}

// ---------------------------------------------------------------- the reader

#[test]
fn nodes_name_exactly_the_sysfs_paths_read() {
    let paths: Vec<String> = [
        SysfsNode::Device { address: gpu() },
        node(gpu(), Attribute::Class),
        node(gpu(), Attribute::BootVga),
        node(gpu(), Attribute::ResetMethod),
        node(gpu(), Attribute::Config),
        node(gpu(), Attribute::Driver),
        node(gpu(), Attribute::IommuGroup),
        SysfsNode::GroupDevices {
            group: IommuGroup::new(12),
        },
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    assert_eq!(
        paths,
        [
            "bus/pci/devices/0000:01:00.0",
            "bus/pci/devices/0000:01:00.0/class",
            "bus/pci/devices/0000:01:00.0/boot_vga",
            "bus/pci/devices/0000:01:00.0/reset_method",
            "bus/pci/devices/0000:01:00.0/config",
            "bus/pci/devices/0000:01:00.0/driver",
            "bus/pci/devices/0000:01:00.0/iommu_group",
            "kernel/iommu_groups/12/devices",
        ]
    );
    assert_eq!(SysfsNode::Device { address: gpu() }.kind(), NodeKind::Link);
    assert_eq!(
        SysfsNode::GroupDevices {
            group: IommuGroup::new(12)
        }
        .kind(),
        NodeKind::Directory
    );
}

#[test]
fn the_recorded_layout_reads_files_links_and_directories() {
    let tree = Tree::host();
    let reader = tree.reader();
    let class = node(gpu(), Attribute::Class);
    assert!(reader
        .location(&class)
        .ends_with("bus/pci/devices/0000%3A01%3A00.0/class"));
    assert!(reader
        .location(&SysfsNode::Device { address: gpu() })
        .ends_with("bus/pci/devices/0000%3A01%3A00.0.link"));
    assert_eq!(reader.read(&class, 4096).unwrap(), b"0x030000\n");
    assert_eq!(reader.read(&class, 8), Err(ReadError::TooLong { limit: 8 }));
    assert_eq!(
        reader.link(&node(gpu(), Attribute::IommuGroup)).unwrap(),
        "../../../../kernel/iommu_groups/1"
    );
    // A recorded link may omit the newline `readlink` prints.
    tree.file(
        node(gpu(), Attribute::Driver),
        b"../../../../bus/pci/drivers/vfio-pci",
    );
    assert_eq!(
        reader.link(&node(gpu(), Attribute::Driver)).unwrap(),
        "../../../../bus/pci/drivers/vfio-pci"
    );
    let listing = SysfsNode::GroupDevices {
        group: IommuGroup::new(1),
    };
    assert_eq!(
        reader.list(&listing).unwrap(),
        vec!["0000:01:00.0".to_owned(), "0000:01:00.1".to_owned()]
    );

    // Each node takes only the read of its kind.
    assert_eq!(class.kind(), NodeKind::File);
    assert_eq!(reader.link(&class), Err(ReadError::WrongKind));
    assert_eq!(reader.list(&class), Err(ReadError::WrongKind));
    assert_eq!(
        reader.read(&node(gpu(), Attribute::Driver), 4096),
        Err(ReadError::WrongKind)
    );
    assert_eq!(reader.read(&listing, 4096), Err(ReadError::WrongKind));

    // Absent entries, an entry of the wrong kind on disk, and undecodable names.
    assert_eq!(
        reader.read(&node(audio(), Attribute::BootVga), 4096),
        Err(ReadError::Missing)
    );
    assert_eq!(
        reader
            .link(&node(reference(), Attribute::IommuGroup))
            .unwrap(),
        "../../../../kernel/iommu_groups/2"
    );
    // A directory where an attribute file belongs is the wrong kind.
    std::fs::create_dir_all(reader.location(&node(gpu(), Attribute::Config))).unwrap();
    assert_eq!(
        reader.read(&node(gpu(), Attribute::Config), 4096),
        Err(ReadError::WrongKind)
    );
    let odd = Tree::host();
    let directory = odd.reader().location(&listing);
    std::fs::write(directory.join("0000%3B01%3A00.0.link"), b"x\n").unwrap();
    assert_eq!(odd.reader().list(&listing), Err(ReadError::Undecodable));
    let not_text = Tree::host();
    not_text.file(node(gpu(), Attribute::Driver), &[0xff, 0xfe, b'\n']);
    assert_eq!(
        not_text.reader().link(&node(gpu(), Attribute::Driver)),
        Err(ReadError::Undecodable)
    );
}

#[test]
fn a_directory_with_too_many_entries_is_refused() {
    let tree = Tree::empty();
    let members: Vec<PciAddress> = (0..=255u8)
        .flat_map(|bus| {
            [
                PciAddress::new(0, bus, 0, 0).unwrap(),
                PciAddress::new(0, bus, 1, 0).unwrap(),
            ]
        })
        .take(super::reader::MAX_ENTRIES + 1)
        .collect();
    tree.group(9, &members);
    assert_eq!(
        tree.reader().list(&SysfsNode::GroupDevices {
            group: IommuGroup::new(9)
        }),
        Err(ReadError::TooLong {
            limit: super::reader::MAX_ENTRIES
        })
    );
}

#[test]
fn the_recorded_encoding_round_trips_and_refuses_stray_escapes() {
    for name in ["0000:01:00.0", "pci0000:00", "50%:x", "plain", ""] {
        assert_eq!(
            decode_component(&encode_component(name)).as_deref(),
            Some(name)
        );
    }
    assert_eq!(encode_component("0000:01:00.0"), "0000%3A01%3A00.0");
    for stored in ["%", "%3", "%3a", "%41", "x%2"] {
        assert_eq!(decode_component(stored), None, "{stored}");
    }
}

#[cfg(unix)]
#[test]
fn the_native_layout_reads_the_kernels_names_and_symbolic_links() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let device = root.join("devices/pci0000:00/0000:00:01.0/0000:01:00.0");
    std::fs::create_dir_all(&device).unwrap();
    std::fs::write(device.join("class"), b"0x030000\n").unwrap();
    std::fs::create_dir_all(root.join("kernel/iommu_groups/1/devices")).unwrap();
    std::fs::create_dir_all(root.join("bus/pci/devices")).unwrap();
    symlink(
        "../../../devices/pci0000:00/0000:00:01.0/0000:01:00.0",
        root.join("bus/pci/devices/0000:01:00.0"),
    )
    .unwrap();
    symlink(
        "../../../../kernel/iommu_groups/1",
        device.join("iommu_group"),
    )
    .unwrap();
    symlink(
        "../../../../devices/pci0000:00/0000:00:01.0/0000:01:00.0",
        root.join("kernel/iommu_groups/1/devices/0000:01:00.0"),
    )
    .unwrap();

    let reader = super::reader::SysfsDir::native(root);
    assert_eq!(
        reader.read(&node(gpu(), Attribute::Class), 4096).unwrap(),
        b"0x030000\n"
    );
    assert_eq!(
        reader.link(&SysfsNode::Device { address: gpu() }).unwrap(),
        "../../../devices/pci0000:00/0000:00:01.0/0000:01:00.0"
    );
    assert_eq!(
        reader.link(&node(gpu(), Attribute::IommuGroup)).unwrap(),
        "../../../../kernel/iommu_groups/1"
    );
    assert_eq!(
        reader
            .list(&SysfsNode::GroupDevices {
                group: IommuGroup::new(1)
            })
            .unwrap(),
        vec!["0000:01:00.0".to_owned()]
    );
    // A regular file where a link belongs is the wrong kind; an absent link is missing.
    std::fs::write(device.join("driver"), b"vfio-pci\n").unwrap();
    assert_eq!(
        reader.link(&node(gpu(), Attribute::Driver)),
        Err(ReadError::WrongKind)
    );
    assert_eq!(
        reader.link(&node(audio(), Attribute::Driver)),
        Err(ReadError::Missing)
    );
}

// ---------------------------------------------------------------- the guards

#[test]
fn a_complete_group_qualifies() {
    let tree = Tree::host();
    let assessment = assess(&tree.reader(), gpu()).unwrap();
    assert_eq!(assessment.device, gpu());
    for verdict in [
        &assessment.group,
        &assessment.display,
        &assessment.reset,
        &assessment.acs,
    ] {
        assert_eq!(verdict, &Verdict::Clear);
    }
    assert!(assessment.qualifies());
    // The reference 3D controller has no boot_vga, as the kernel gives it none.
    assert!(assess(&tree.reader(), reference()).unwrap().qualifies());
    // An unbound function has no host user.
    tree.remove(node(audio(), Attribute::Driver));
    assert!(assess(&tree.reader(), gpu()).unwrap().qualifies());
}

#[test]
fn a_group_shared_with_another_device_is_a_hazard() {
    let (_, shared, _) = hazard_trees().remove(0);
    let assessment = assess(&shared.reader(), gpu()).unwrap();
    assert_eq!(
        hazard(&assessment.group),
        &Hazard::SharedGroup {
            group: IommuGroup::new(1),
            others: vec![nic()]
        }
    );
    assert!(!assessment.qualifies());
    // In the strict reading a bridge in the group is another device too.
    let with_bridge = Tree::host();
    with_bridge.group(1, &[port_a(), gpu(), audio()]);
    assert_eq!(
        hazard(&assess(&with_bridge.reader(), gpu()).unwrap().group),
        &Hazard::SharedGroup {
            group: IommuGroup::new(1),
            others: vec![port_a()]
        }
    );
    // An ARI function numbered above 7 has another device number.
    let ari = Tree::host();
    ari.group(1, &[gpu(), audio(), at("0000:01:01.0")]);
    assert!(matches!(
        hazard(&assess(&ari.reader(), gpu()).unwrap().group),
        Hazard::SharedGroup { .. }
    ));
}

#[test]
fn a_device_without_an_iommu_group_is_a_hazard() {
    let tree = Tree::host();
    tree.remove(node(gpu(), Attribute::IommuGroup));
    let assessment = assess(&tree.reader(), gpu()).unwrap();
    assert_eq!(hazard(&assessment.group), &Hazard::NoIommuGroup);
    // Its other functions are then unknown, so host use stays undecided.
    assert_eq!(
        undecided_at(&assessment.display),
        (node(gpu(), Attribute::IommuGroup), missing())
    );
}

#[test]
fn group_facts_that_cannot_be_read_leave_the_group_undecided() {
    let unlisted = Tree::host();
    unlisted.group(1, &[audio()]);
    let listing = SysfsNode::GroupDevices {
        group: IommuGroup::new(1),
    };
    assert_eq!(
        undecided_at(&assess(&unlisted.reader(), gpu()).unwrap().group),
        (listing, Problem::NotInItsGroup)
    );
    let dangling = Tree::host();
    dangling.link(
        node(gpu(), Attribute::IommuGroup),
        "../../../../kernel/iommu_groups/7",
    );
    let assessment = assess(&dangling.reader(), gpu()).unwrap();
    assert_eq!(
        undecided_at(&assessment.group),
        (
            SysfsNode::GroupDevices {
                group: IommuGroup::new(7)
            },
            missing()
        )
    );
    assert!(matches!(assessment.display, Verdict::Undecided { .. }));
    let garbled = Tree::host();
    garbled.link(node(gpu(), Attribute::IommuGroup), "../kernel/groups/1");
    assert_eq!(
        undecided_at(&assess(&garbled.reader(), gpu()).unwrap().group),
        (
            node(gpu(), Attribute::IommuGroup),
            Problem::Parse {
                error: ParseError::GroupLink
            }
        )
    );
}

#[test]
fn no_reset_method_is_a_hazard_and_a_missing_attribute_is_undecided() {
    let tree = Tree::host();
    tree.file(node(gpu(), Attribute::ResetMethod), b"");
    assert_eq!(
        hazard(&assess(&tree.reader(), gpu()).unwrap().reset),
        &Hazard::NoResetMethod
    );
    tree.file(node(gpu(), Attribute::ResetMethod), b"bus\n");
    assert_eq!(assess(&tree.reader(), gpu()).unwrap().reset, Verdict::Clear);
    tree.remove(node(gpu(), Attribute::ResetMethod));
    assert_eq!(
        undecided_at(&assess(&tree.reader(), gpu()).unwrap().reset),
        (node(gpu(), Attribute::ResetMethod), missing())
    );
    tree.file(node(gpu(), Attribute::ResetMethod), b"flr reboot\n");
    assert_eq!(
        undecided_at(&assess(&tree.reader(), gpu()).unwrap().reset).1,
        Problem::Parse {
            error: ParseError::UnknownResetMethod
        }
    );
}

#[test]
fn the_boot_display_is_a_hazard() {
    let tree = Tree::host();
    tree.file(node(gpu(), Attribute::BootVga), b"1\n");
    let assessment = assess(&tree.reader(), gpu()).unwrap();
    assert_eq!(hazard(&assessment.display), &Hazard::BootDisplay);
    assert_eq!(assessment.group, Verdict::Clear);
    // A VGA controller without boot_vga is a missing fact; a malformed one too.
    tree.remove(node(gpu(), Attribute::BootVga));
    assert_eq!(
        undecided_at(&assess(&tree.reader(), gpu()).unwrap().display),
        (node(gpu(), Attribute::BootVga), missing())
    );
    tree.file(node(gpu(), Attribute::BootVga), b"true\n");
    assert_eq!(
        undecided_at(&assess(&tree.reader(), gpu()).unwrap().display).1,
        Problem::Parse {
            error: ParseError::BootVga
        }
    );
    // A boot display shows the hazard even when the class cannot be read.
    tree.file(node(gpu(), Attribute::BootVga), b"1\n");
    tree.file(node(gpu(), Attribute::Class), b"VGA\n");
    assert_eq!(
        hazard(&assess(&tree.reader(), gpu()).unwrap().display),
        &Hazard::BootDisplay
    );
}

#[test]
fn a_host_driver_on_any_function_is_a_hazard() {
    let tree = Tree::host();
    tree.link(
        node(gpu(), Attribute::Driver),
        "../../../../bus/pci/drivers/nvidia",
    );
    let assessment = assess(&tree.reader(), gpu()).unwrap();
    match hazard(&assessment.display) {
        Hazard::HostDriver { function, driver } => {
            assert_eq!((*function, driver.as_str()), (gpu(), "nvidia"));
        }
        other => panic!("{other:?}"),
    }
    let audio_held = Tree::host();
    audio_held.link(
        node(audio(), Attribute::Driver),
        "../../../../bus/pci/drivers/snd_hda_intel",
    );
    match hazard(&assess(&audio_held.reader(), gpu()).unwrap().display) {
        Hazard::HostDriver { function, driver } => {
            assert_eq!((*function, driver.as_str()), (audio(), "snd_hda_intel"));
        }
        other => panic!("{other:?}"),
    }
    let garbled = Tree::host();
    garbled.link(node(audio(), Attribute::Driver), "../../drivers/vfio-pci");
    assert_eq!(
        undecided_at(&assess(&garbled.reader(), gpu()).unwrap().display),
        (
            node(audio(), Attribute::Driver),
            Problem::Parse {
                error: ParseError::DriverLink
            }
        )
    );
}

#[test]
fn missing_acs_is_a_hazard() {
    let (_, missing_acs, _) = hazard_trees().remove(3);
    assert_eq!(
        hazard(&assess(&missing_acs.reader(), gpu()).unwrap().acs),
        &Hazard::NoAcs { port: port_a() }
    );
    let off = Tree::host();
    off.port(
        port_a(),
        PortSpec {
            acs: Some((0x001f, 0x0019)),
            ..PortSpec::root_port(0x01)
        },
    );
    assert_eq!(
        hazard(&assess(&off.reader(), gpu()).unwrap().acs),
        &Hazard::AcsControlsOff {
            port: port_a(),
            missing: ACS_REQUEST_REDIRECT
        }
    );
    for (port_type, layout) in [
        (Some(PCIE_TO_PCI_BRIDGE), 1),
        (None, 1),
        (Some(ROOT_PORT), 2),
    ] {
        let bridge = Tree::host();
        bridge.port(
            port_a(),
            PortSpec {
                port_type,
                layout,
                acs: None,
                ..PortSpec::root_port(0x01)
            },
        );
        assert_eq!(
            hazard(&assess(&bridge.reader(), gpu()).unwrap().acs),
            &Hazard::BridgeWithoutAcs { port: port_a() },
            "{port_type:?} {layout}"
        );
    }
    // A GPU on its root bus has no port to isolate it.
    let integrated = Tree::host();
    let on_root = at("0000:00:03.0");
    integrated.device(&DeviceSpec {
        address: on_root,
        path: Vec::new(),
        group: Some(4),
        ..gpu_spec()
    });
    integrated.group(4, &[on_root]);
    let assessment = assess(&integrated.reader(), on_root).unwrap();
    assert_eq!(hazard(&assessment.acs), &Hazard::NoIsolatingPort);
    assert_eq!(assessment.group, Verdict::Clear);
}

#[test]
fn a_switch_needs_acs_on_its_downstream_ports_and_on_a_multifunction_upstream_port() {
    let switch_up = at("0000:01:00.0");
    let switch_down = at("0000:02:01.0");
    let behind = at("0000:03:00.0");
    let tree = Tree::empty();
    tree.port(port_a(), PortSpec::root_port(0x01));
    tree.port(
        switch_up,
        PortSpec {
            port_type: Some(UPSTREAM_PORT),
            acs: None,
            ..PortSpec::root_port(0x02)
        },
    );
    tree.port(
        switch_down,
        PortSpec {
            port_type: Some(DOWNSTREAM_PORT),
            ..PortSpec::root_port(0x03)
        },
    );
    tree.device(&DeviceSpec {
        address: behind,
        path: vec![port_a(), switch_up, switch_down],
        group: Some(5),
        ..gpu_spec()
    });
    tree.group(5, &[behind]);
    assert!(assess(&tree.reader(), behind).unwrap().qualifies());

    tree.port(
        switch_up,
        PortSpec {
            port_type: Some(UPSTREAM_PORT),
            multifunction: true,
            acs: None,
            ..PortSpec::root_port(0x02)
        },
    );
    assert_eq!(
        hazard(&assess(&tree.reader(), behind).unwrap().acs),
        &Hazard::NoAcs { port: switch_up }
    );
    tree.port(
        switch_up,
        PortSpec {
            port_type: Some(UPSTREAM_PORT),
            ..PortSpec::root_port(0x02)
        },
    );
    tree.port(
        switch_down,
        PortSpec {
            port_type: Some(DOWNSTREAM_PORT),
            acs: None,
            ..PortSpec::root_port(0x03)
        },
    );
    assert_eq!(
        hazard(&assess(&tree.reader(), behind).unwrap().acs),
        &Hazard::NoAcs { port: switch_down }
    );
}

#[test]
fn acs_facts_that_cannot_be_read_leave_acs_undecided() {
    let config = node(port_a(), Attribute::Config);
    // The 64 bytes an unprivileged reader gets.
    let unprivileged = Tree::host();
    unprivileged.port(
        port_a(),
        PortSpec {
            length: 64,
            ..PortSpec::root_port(0x01)
        },
    );
    assert_eq!(
        undecided_at(&assess(&unprivileged.reader(), gpu()).unwrap().acs),
        (
            config,
            Problem::Config {
                error: ConfigError::Truncated {
                    length: 64,
                    needed: 256
                }
            }
        )
    );
    let absent = Tree::host();
    absent.remove(config);
    assert_eq!(
        undecided_at(&assess(&absent.reader(), gpu()).unwrap().acs),
        (config, missing())
    );
    // A bridge whose secondary bus is not the next device's bus, and an endpoint on the
    // path, do not describe the path.
    let broken = Tree::host();
    broken.port(port_a(), PortSpec::root_port(0x05));
    assert_eq!(
        undecided_at(&assess(&broken.reader(), gpu()).unwrap().acs),
        (config, Problem::PathBroken)
    );
    for (port_type, layout) in [(Some(ROOT_PORT), 0), (Some(ENDPOINT), 1)] {
        let not_bridge = Tree::host();
        not_bridge.port(
            port_a(),
            PortSpec {
                port_type,
                layout,
                ..PortSpec::root_port(0x01)
            },
        );
        assert_eq!(
            undecided_at(&assess(&not_bridge.reader(), gpu()).unwrap().acs),
            (config, Problem::NotABridge)
        );
    }
    let no_link = Tree::host();
    no_link.remove(SysfsNode::Device { address: gpu() });
    assert_eq!(
        undecided_at(&assess(&no_link.reader(), gpu()).unwrap().acs),
        (SysfsNode::Device { address: gpu() }, missing())
    );
    let elsewhere = Tree::host();
    elsewhere.link(
        SysfsNode::Device { address: gpu() },
        "../../../devices/platform/vmbus/0000:01:00.0",
    );
    assert_eq!(
        undecided_at(&assess(&elsewhere.reader(), gpu()).unwrap().acs).1,
        Problem::Parse {
            error: ParseError::DevicePath
        }
    );
}

#[test]
fn a_shown_hazard_outweighs_a_fact_of_the_same_guard_that_could_not_be_read() {
    let switch_up = at("0000:01:00.0");
    let switch_down = at("0000:02:01.0");
    let behind = at("0000:03:00.0");
    let tree = Tree::empty();
    tree.port(
        port_a(),
        PortSpec {
            length: 64,
            ..PortSpec::root_port(0x01)
        },
    );
    tree.port(
        switch_up,
        PortSpec {
            port_type: Some(UPSTREAM_PORT),
            ..PortSpec::root_port(0x02)
        },
    );
    tree.port(
        switch_down,
        PortSpec {
            port_type: Some(DOWNSTREAM_PORT),
            acs: None,
            ..PortSpec::root_port(0x03)
        },
    );
    tree.device(&DeviceSpec {
        address: behind,
        path: vec![port_a(), switch_up, switch_down],
        group: Some(5),
        ..gpu_spec()
    });
    tree.group(5, &[behind]);
    assert_eq!(
        hazard(&assess(&tree.reader(), behind).unwrap().acs),
        &Hazard::NoAcs { port: switch_down }
    );
    // Host use: a host driver on the audio function stands although boot_vga is missing.
    let display = Tree::host();
    display.remove(node(gpu(), Attribute::BootVga));
    display.link(
        node(audio(), Attribute::Driver),
        "../../../../bus/pci/drivers/snd_hda_intel",
    );
    assert!(matches!(
        hazard(&assess(&display.reader(), gpu()).unwrap().display),
        Hazard::HostDriver { .. }
    ));
}

#[test]
fn devices_that_are_absent_or_not_gpus_are_not_assessed() {
    let tree = Tree::host();
    assert_eq!(
        assess(&tree.reader(), nic()),
        Err(Unassessable::Absent { device: nic() })
    );
    match assess(&tree.reader(), audio()) {
        Err(Unassessable::NotAGpu { device, class }) => {
            assert_eq!((device, class.code()), (audio(), 0x040300));
        }
        other => panic!("{other:?}"),
    }
    // A class that cannot be parsed is not a refusal of the device: the display guard,
    // which needs it, is undecided.
    tree.file(node(gpu(), Attribute::Class), b"0x30000\n");
    assert_eq!(
        undecided_at(&assess(&tree.reader(), gpu()).unwrap().display),
        (
            node(gpu(), Attribute::Class),
            Problem::Parse {
                error: ParseError::Class
            }
        )
    );
}

#[test]
fn an_assessment_serializes_with_its_nodes_and_hazards() {
    let (_, shared, _) = hazard_trees().remove(0);
    shared.remove(node(gpu(), Attribute::ResetMethod));
    let assessment = assess(&shared.reader(), gpu()).unwrap();
    let json = serde_json::to_value(&assessment).unwrap();
    assert_eq!(
        json,
        serde_json::json!({
            "device": "0000:01:00.0",
            "group": {
                "verdict": "hazard",
                "hazard": { "hazard": "shared_group", "group": 1, "others": ["0000:03:00.0"] }
            },
            "display": { "verdict": "clear" },
            "reset": {
                "verdict": "undecided",
                "problem": {
                    "node": "bus/pci/devices/0000:01:00.0/reset_method",
                    "problem": { "problem": "read", "error": { "read": "missing" } }
                }
            },
            "acs": { "verdict": "clear" }
        })
    );
    assert_eq!(
        hazard(&assessment.group).to_string(),
        "IOMMU group 1 also holds 0000:03:00.0"
    );
}

// ---------------------------------------------------------------- VM-CP-31's observations

#[test]
fn the_runner_reports_exactly_vm_cp_31s_observations() {
    let tree = Tree::host();
    let observations = observed(run(&runner(&tree, None)));
    let row = check(cp31());
    let expected: BTreeSet<ExpectationId> = row
        .expectations()
        .filter(|entry| entry.part == Part::Primary && entry.scope.applies(OsKind::Linux))
        .map(|entry| entry.id)
        .collect();
    let reported: BTreeSet<ExpectationId> = observations.keys().copied().collect();
    assert_eq!(reported, expected);
    assert_eq!(reported.len(), 5);
    for (id, seen) in &observations {
        let entry = expectation(*id).unwrap();
        assert_eq!(seen.kind(), entry.expect.judges(), "{id}");
        assert_eq!(entry.expect.holds(seen), Ok(true), "{id}");
    }
    assert_eq!(
        row.control().map(|control| control.id),
        Some(id(QUALIFYING_ASSIGNS))
    );
    assert_eq!(
        expectation(id(QUALIFYING_ASSIGNS)).unwrap().role,
        Role::PositiveControl
    );
    assert_eq!(
        evaluate_observations(row, Part::Primary, &observations, OsKind::Linux),
        PartResult::Holds
    );
    assert_eq!(
        observations.get(&id(INCOMPLETE_GROUP)),
        Some(&Observed::Attempt { refused: true })
    );
    assert_eq!(
        observations.get(&id(RESET_CHECKED)),
        Some(&Observed::Presence { present: true })
    );
    assert_eq!(
        observations.get(&id(QUALIFYING_ASSIGNS)),
        Some(&Observed::Attempt { refused: false })
    );
}

#[test]
fn each_hazard_fails_its_own_expectation_with_the_control_held() {
    let row = check(cp31());
    for (case, tree, failing) in hazard_trees() {
        let observations = observed(run(&runner(&tree, Some(reference()))));
        assert_eq!(observations.len(), 5, "{case}");
        assert_eq!(
            evaluate_observations(row, Part::Primary, &observations, OsKind::Linux),
            PartResult::Fails { id: id(failing) },
            "{case}"
        );
        for name in [INCOMPLETE_GROUP, DISPLAY_OWNING, RESET_CHECKED, ACS_CHECKED] {
            let holds = expectation(id(name))
                .unwrap()
                .expect
                .holds(&observations[&id(name)]);
            assert_eq!(holds, Ok(name != failing), "{case}: {name}");
        }
        assert_eq!(
            observations.get(&id(QUALIFYING_ASSIGNS)),
            Some(&Observed::Attempt { refused: false }),
            "{case}"
        );
    }
}

#[test]
fn the_positive_control_needs_a_qualifying_device_read_in_the_same_run() {
    let control = id(QUALIFYING_ASSIGNS);
    let (_, boot_vga, _) = hazard_trees().remove(2);
    // Without a reference, a GPU that does not qualify leaves the control unobserved.
    assert_eq!(observed(run(&runner(&boot_vga, None))).get(&control), None);
    // A reference that qualifies holds it.
    assert_eq!(
        observed(run(&runner(&boot_vga, Some(reference())))).get(&control),
        Some(&Observed::Attempt { refused: false })
    );
    // A reference that does not qualify, or that the host does not have, fails it.
    boot_vga.file(node(reference(), Attribute::ResetMethod), b"");
    assert_eq!(
        observed(run(&runner(&boot_vga, Some(reference())))).get(&control),
        Some(&Observed::Attempt { refused: true })
    );
    assert_eq!(
        observed(run(&runner(&boot_vga, Some(nic())))).get(&control),
        Some(&Observed::Attempt { refused: true })
    );
    // A qualifying subject is its own control and the reference is not read.
    let tree = Tree::host();
    let (reader, reads) = super::fixtures::CountingReader::new(tree.reader());
    let counted = GpuAssignmentRunner::new(reader, settings(None)).unwrap();
    observed(run(&counted));
    let without = reads.load(Ordering::SeqCst);
    let (reader, reads) = super::fixtures::CountingReader::new(tree.reader());
    let counted = GpuAssignmentRunner::new(reader, settings(Some(reference()))).unwrap();
    assert_eq!(
        observed(run(&counted)).get(&control),
        Some(&Observed::Attempt { refused: false })
    );
    assert_eq!(reads.load(Ordering::SeqCst), without);
}

#[test]
fn facts_that_cannot_be_read_leave_their_observation_out() {
    let row = check(cp31());
    let tree = Tree::host();
    tree.remove(node(gpu(), Attribute::ResetMethod));
    let observations = observed(run(&runner(&tree, Some(reference()))));
    assert!(!observations.contains_key(&id(RESET_CHECKED)));
    assert_eq!(observations.len(), 4);
    assert_eq!(
        evaluate_observations(row, Part::Primary, &observations, OsKind::Linux),
        PartResult::Inconclusive {
            reason: InconclusiveReason::MissingObservation {
                id: id(RESET_CHECKED)
            }
        }
    );
    // A conclusive hazard is still reported beside the missing fact.
    tree.file(node(gpu(), Attribute::BootVga), b"1\n");
    let observations = observed(run(&runner(&tree, Some(reference()))));
    assert_eq!(
        evaluate_observations(row, Part::Primary, &observations, OsKind::Linux),
        PartResult::Fails {
            id: id(DISPLAY_OWNING)
        }
    );
}

#[test]
fn a_host_that_is_not_linux_gets_no_observation_and_nothing_is_read() {
    let tree = Tree::host();
    for os in [OsKind::Windows, OsKind::MacOs, OsKind::Wsl2] {
        let (reader, reads) = super::fixtures::CountingReader::new(tree.reader());
        let runner = GpuAssignmentRunner::new(
            reader,
            super::runner::RunnerSettings {
                os,
                ..settings(Some(reference()))
            },
        )
        .unwrap();
        assert_eq!(runner.os(), os);
        assert_eq!(observed(run(&runner)), Observations::new(), "{os}");
        assert_eq!(runner.assess(gpu()), None);
        assert_eq!(reads.load(Ordering::SeqCst), 0, "{os}");
    }
}

#[test]
fn subjects_the_runner_cannot_place_are_unreachable() {
    let tree = Tree::host();
    tree.device(&DeviceSpec {
        address: nic(),
        class: "0x020000\n",
        boot_vga: None,
        group: Some(3),
        ..gpu_spec()
    });
    tree.group(3, &[nic()]);
    let unreachable = RunResult::Inconclusive {
        reason: RunnerInconclusive::Unreachable,
    };
    let other = |machine, device| Subject::GpuDevice(GpuDeviceSubject { machine, device });
    let mut gpus = settings(None).gpus;
    gpus.insert(device_digest("absent"), at("0000:09:00.0"));
    gpus.insert(device_digest("nic"), nic());
    let runner = GpuAssignmentRunner::new(
        tree.reader(),
        super::runner::RunnerSettings {
            gpus,
            ..settings(None)
        },
    )
    .unwrap();
    for subject in [
        other(
            digest("yougori/test/host-checks/machine/v1", &[b"another"]),
            device_digest("gpu-a"),
        ),
        other(machine(), device_digest("unmapped")),
        other(machine(), device_digest("absent")),
        other(machine(), device_digest("nic")),
        Subject::Host(HostSubject { machine: machine() }),
    ] {
        assert_eq!(
            runner.run(cp31(), Part::Primary, &subject),
            unreachable,
            "{subject:?}"
        );
    }
    assert_eq!(runner.address_of(&gpu_subject()), Some(gpu()));
}

#[test]
fn only_vm_cp_31s_own_part_is_answered() {
    let tree = Tree::host();
    let (reader, reads) = super::fixtures::CountingReader::new(tree.reader());
    let runner = GpuAssignmentRunner::new(reader, settings(None)).unwrap();
    for number in [1, 4, 30, 32] {
        let check_id = CheckId::new(number).unwrap();
        for part in check(check_id).parts() {
            assert_eq!(
                observed(runner.run(check_id, part, &gpu_subject())),
                Observations::new()
            );
        }
    }
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    assert_eq!(runner.configuration(), configuration());
    assert_eq!(runner.fresh_for(), FRESH);
}

#[test]
fn settings_are_checked() {
    let tree = Tree::host();
    let refused = |settings| GpuAssignmentRunner::new(tree.reader(), settings).err();
    assert_eq!(
        refused(super::runner::RunnerSettings {
            fresh_for: std::time::Duration::ZERO,
            ..settings(None)
        }),
        Some(SettingsError::ZeroFreshness)
    );
    let mut repeated = settings(None).gpus;
    repeated.insert(device_digest("again"), gpu());
    assert_eq!(
        refused(super::runner::RunnerSettings {
            gpus: repeated,
            ..settings(None)
        }),
        Some(SettingsError::RepeatedAddress { address: gpu() })
    );
    let many = (0..=MAX_GPUS)
        .map(|index| {
            let index = u8::try_from(index).unwrap();
            (
                device_digest(&format!("gpu-{index}")),
                PciAddress::new(0, index, 0, 0).unwrap(),
            )
        })
        .collect();
    assert_eq!(
        refused(super::runner::RunnerSettings {
            gpus: many,
            ..settings(None)
        }),
        Some(SettingsError::TooManyGpus)
    );
    assert!(GpuAssignmentRunner::new(tree.reader(), settings(Some(reference()))).is_ok());
}

// ---------------------------------------------------------------- through the probes adapter

#[test]
fn through_the_adapter_a_qualifying_gpu_satisfies_a_host_only_requirement() {
    let tree = Tree::host();
    let (mut registry, _clock) = registry();
    let adapter = DeviceAssignmentIsolatedProbe::new(runner(&tree, None));
    assert_eq!(adapter.source(), SourceClass::HostProbe);
    assert!(adapter.host_changes().is_empty());
    registry.register(Box::new(adapter)).unwrap();
    let envelope = registry
        .refresh(Capability::DeviceAssignmentIsolated, &gpu_subject())
        .unwrap();
    assert_eq!(envelope.source(), SourceClass::HostProbe);
    assert_eq!(
        envelope.result(),
        &ObservationResult::Supported {
            detail: SupportDetail::Plain
        }
    );
    let requirement = Requirement::host_only(
        Capability::DeviceAssignmentIsolated,
        gpu_subject(),
        MAX_AGE,
        configuration(),
    );
    let satisfied = registry.evaluate(&requirement).unwrap();
    assert_eq!(satisfied.source(), SourceClass::HostProbe);
}

#[test]
fn through_the_adapter_each_hazard_refuses_the_gpu() {
    for (case, tree, _) in hazard_trees() {
        assert_eq!(
            refreshed(&tree, Some(reference())),
            not_isolated(),
            "{case}"
        );
        // Without a qualifying device in the run, the refusal is not attributable.
        assert_eq!(
            refreshed(&tree, None),
            unknown(UnknownReason::Inconclusive),
            "{case}"
        );
        let (mut registry, _clock) = registry();
        registry
            .register(Box::new(DeviceAssignmentIsolatedProbe::new(runner(
                &tree,
                Some(reference()),
            ))))
            .unwrap();
        registry
            .refresh(Capability::DeviceAssignmentIsolated, &gpu_subject())
            .unwrap();
        let requirement = Requirement::host_only(
            Capability::DeviceAssignmentIsolated,
            gpu_subject(),
            MAX_AGE,
            configuration(),
        );
        assert!(registry.evaluate(&requirement).is_err(), "{case}");
    }
}

#[test]
fn through_the_adapter_facts_that_cannot_be_read_are_inconclusive() {
    let reset_missing = Tree::host();
    reset_missing.remove(node(gpu(), Attribute::ResetMethod));
    let unprivileged = Tree::host();
    unprivileged.port(
        port_a(),
        PortSpec {
            length: 64,
            ..PortSpec::root_port(0x01)
        },
    );
    let group_unlisted = Tree::host();
    group_unlisted.group(1, &[audio()]);
    let boot_vga_missing = Tree::host();
    boot_vga_missing.remove(node(gpu(), Attribute::BootVga));
    for (case, tree) in [
        ("reset_method missing", reset_missing),
        ("unprivileged config", unprivileged),
        ("group does not list the GPU", group_unlisted),
        ("boot_vga missing", boot_vga_missing),
    ] {
        for reference_gpu in [None, Some(reference())] {
            assert_eq!(
                refreshed(&tree, reference_gpu),
                unknown(UnknownReason::Inconclusive),
                "{case} {reference_gpu:?}"
            );
        }
    }
}

#[test]
fn through_the_adapter_a_host_that_is_not_linux_reads_not_tested() {
    let tree = Tree::host();
    for os in [OsKind::Windows, OsKind::MacOs, OsKind::Wsl2] {
        let (reader, reads) = super::fixtures::CountingReader::new(tree.reader());
        let runner = GpuAssignmentRunner::new(
            reader,
            super::runner::RunnerSettings {
                os,
                ..settings(Some(reference()))
            },
        )
        .unwrap();
        let (mut registry, _clock) = registry();
        registry
            .register(Box::new(DeviceAssignmentIsolatedProbe::new(runner)))
            .unwrap();
        let envelope = registry
            .refresh(Capability::DeviceAssignmentIsolated, &gpu_subject())
            .unwrap();
        // VM-CP-31 is scoped to Linux hosts: not tested, never supported, and nothing
        // is read.
        assert_eq!(
            envelope.result(),
            &unknown(UnknownReason::NotTested),
            "{os}"
        );
        assert_eq!(reads.load(Ordering::SeqCst), 0, "{os}");
        // The probes judge reads it not tested on such a host too, whatever is given.
        let context = crate::sandbox::probes::JudgeContext {
            now: registry.now(),
            configuration: configuration(),
            max_age: MAX_AGE,
            os,
        };
        let linux_outcome = ProbeOutcome::host(
            cp31(),
            Part::Primary,
            HostKind::Host,
            registry.now(),
            FRESH,
            configuration(),
            run(&super::fixtures::runner(&tree, Some(reference()))),
        )
        .unwrap();
        assert_eq!(
            judge(check(cp31()), &[linux_outcome], &context),
            CheckStatus::NotTested {
                reason: crate::sandbox::probes::NotTestedReason::NoObservationForHost { os }
            },
            "{os}"
        );
    }
}

#[test]
fn an_assessment_gives_the_checks_a_gpu_backend_stamps_before_assignment() {
    let qualifying = assess(&Tree::host().reader(), gpu()).unwrap();
    let before = qualifying.checks_before_assignment();
    assert_eq!(
        before.checks,
        CHECKED_BEFORE_ASSIGNMENT
            .into_iter()
            .collect::<BTreeSet<_>>()
    );
    assert!(before.unsafe_settings.is_empty());
    // Each hazard leaves exactly its own check out.
    for (case, tree, hazard) in hazard_trees() {
        let lacking = match hazard {
            INCOMPLETE_GROUP => GpuIsolationCheck::CompleteIsolationGroup,
            DISPLAY_OWNING => GpuIsolationCheck::NoHostDisplayOrOtherUsers,
            RESET_CHECKED => GpuIsolationCheck::SafeResetAndReassignment,
            _ => GpuIsolationCheck::NoUnsafeAcsOrIommuBypass,
        };
        let assessment = assess(&tree.reader(), gpu()).unwrap();
        let checks = assessment.checks_before_assignment().checks;
        assert!(!checks.contains(&lacking), "{case}");
        assert_eq!(checks.len(), CHECKED_BEFORE_ASSIGNMENT.len() - 1, "{case}");
    }
    // An undecided guard leaves its check out too.
    let unreadable = Tree::host();
    unreadable.remove(node(gpu(), Attribute::ResetMethod));
    let checks = assess(&unreadable.reader(), gpu())
        .unwrap()
        .checks_before_assignment()
        .checks;
    assert!(!checks.contains(&GpuIsolationCheck::SafeResetAndReassignment));

    // Stamped before the assignment, the qualifying device's checks are what admission
    // asks of the order (VM-CP-31): the four checks, made first.
    let (registry, clock) = registry();
    let device = GpuDeviceKey {
        machine: machine(),
        device: device_digest("gpu0"),
    };
    let checked = HostObserved::stamp(
        ObservedGpu {
            device,
            isolation: before,
        },
        registry.now(),
        FRESH,
        configuration(),
    );
    clock.advance(std::time::Duration::from_secs(1));
    let order = GpuAssignmentOrder {
        checked,
        assigned: HostObserved::stamp(device, registry.now(), FRESH, configuration()),
    };
    assert!(order.checked_before_assignment());
    assert!(order.missing_before_assignment().is_empty());
    assert!(!order.isolation().is_isolated());
    assert_ne!(order.isolation(), &GpuIsolation::complete());
}

#[test]
fn through_the_adapter_a_gpu_the_host_does_not_have_is_unreachable() {
    let tree = Tree::host();
    let (mut registry, _clock) = registry();
    let mut gpus = settings(None).gpus;
    gpus.insert(device_digest("absent"), at("0000:09:00.0"));
    registry
        .register(Box::new(DeviceAssignmentIsolatedProbe::new(
            GpuAssignmentRunner::new(
                tree.reader(),
                super::runner::RunnerSettings {
                    gpus,
                    ..settings(None)
                },
            )
            .unwrap(),
        )))
        .unwrap();
    for device in ["absent", "unmapped"] {
        let subject = Subject::GpuDevice(GpuDeviceSubject {
            machine: machine(),
            device: device_digest(device),
        });
        assert_eq!(
            registry
                .refresh(Capability::DeviceAssignmentIsolated, &subject)
                .unwrap()
                .result(),
            &unknown(UnknownReason::Unreachable),
            "{device}"
        );
    }
}

#[test]
fn each_refresh_reads_the_host_again() {
    let tree = Tree::host();
    let (mut registry, _clock) = registry();
    registry
        .register(Box::new(DeviceAssignmentIsolatedProbe::new(runner(
            &tree,
            Some(reference()),
        ))))
        .unwrap();
    let refresh = |registry: &mut crate::foundation::evidence::ProbeRegistry<_>| {
        registry
            .refresh(Capability::DeviceAssignmentIsolated, &gpu_subject())
            .unwrap()
            .result()
            .clone()
    };
    assert!(matches!(
        refresh(&mut registry),
        ObservationResult::Supported { .. }
    ));
    // The host driver takes the GPU back between two refreshes.
    tree.link(
        node(gpu(), Attribute::Driver),
        "../../../../bus/pci/drivers/nouveau",
    );
    assert_eq!(refresh(&mut registry), not_isolated());
    tree.link(
        node(gpu(), Attribute::Driver),
        "../../../../bus/pci/drivers/vfio-pci",
    );
    assert!(matches!(
        refresh(&mut registry),
        ObservationResult::Supported { .. }
    ));
}

// ---------------------------------------------------------------- through the probes judge

#[test]
fn the_probes_judge_names_the_expectation_a_hazard_fails() {
    let (registry, _clock) = registry();
    let context = crate::sandbox::probes::JudgeContext {
        now: registry.now(),
        configuration: configuration(),
        max_age: MAX_AGE,
        os: OsKind::Linux,
    };
    let judged = |tree: &Tree, reference_gpu| {
        let runner = runner(tree, reference_gpu);
        let outcome = ProbeOutcome::host(
            cp31(),
            Part::Primary,
            HostKind::Host,
            registry.now(),
            runner.fresh_for(),
            runner.configuration(),
            run(&runner),
        )
        .unwrap();
        judge(check(cp31()), &[outcome], &context)
    };
    assert_eq!(judged(&Tree::host(), None), CheckStatus::Passed);
    for (case, tree, failing) in hazard_trees() {
        assert_eq!(
            judged(&tree, Some(reference())),
            CheckStatus::Failed {
                failure: Failure::Expectation {
                    id: id(failing),
                    part: Part::Primary
                }
            },
            "{case}"
        );
        assert_eq!(
            judged(&tree, None),
            CheckStatus::Inconclusive {
                reason: InconclusiveReason::NoPositiveControl {
                    id: id(QUALIFYING_ASSIGNS)
                }
            },
            "{case}"
        );
    }
    let missing_reset = Tree::host();
    missing_reset.remove(node(gpu(), Attribute::ResetMethod));
    assert_eq!(
        judged(&missing_reset, Some(reference())),
        CheckStatus::Inconclusive {
            reason: InconclusiveReason::MissingObservation {
                id: id(RESET_CHECKED)
            }
        }
    );
}
