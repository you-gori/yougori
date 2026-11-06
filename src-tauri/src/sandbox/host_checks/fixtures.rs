//! Test fixtures: recorded sysfs trees written into temporary directories in the
//! recorded layout of [`SysfsDir`], PCI configuration spaces built byte by byte, runner
//! settings and a CORE-01 registry on a manual clock. Nothing here reads the host's own
//! sysfs.

use std::collections::BTreeMap;
use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::address::PciAddress;
use super::node::{Attribute, SysfsNode};
use super::reader::{ReadError, SysfsDir, SysfsReader};
use super::runner::{GpuAssignmentRunner, RunnerSettings};
use crate::foundation::evidence::{
    ConfigurationFingerprint, GpuDeviceSubject, OsKind, ProbeRegistry, Subject,
};
use crate::foundation::ids::{digest, Digest, ManualClock, MonotonicTime};

pub const FRESH: Duration = Duration::from_secs(600);
pub const MAX_AGE: Duration = Duration::from_secs(300);

/// PCI Express port types (PCI Express Capabilities register, bits 4–7).
pub const ROOT_PORT: u8 = 0x4;
pub const UPSTREAM_PORT: u8 = 0x5;
pub const DOWNSTREAM_PORT: u8 = 0x6;
pub const PCIE_TO_PCI_BRIDGE: u8 = 0x7;
pub const ENDPOINT: u8 = 0x0;

/// ACS registers: every control implemented (SV, TB, RR, CR, UF) and the required four
/// on.
pub const FULL_ACS: (u16, u16) = (0x001f, 0x001d);

pub fn at(text: &str) -> PciAddress {
    PciAddress::parse(text).unwrap_or_else(|error| panic!("{text}: {error}"))
}

/// The GPU under test, its audio function, the reference GPU, the root ports above them
/// and a network adapter that a shared group can pull in.
pub fn gpu() -> PciAddress {
    at("0000:01:00.0")
}

pub fn audio() -> PciAddress {
    at("0000:01:00.1")
}

pub fn reference() -> PciAddress {
    at("0000:02:00.0")
}

pub fn port_a() -> PciAddress {
    at("0000:00:01.0")
}

pub fn port_b() -> PciAddress {
    at("0000:00:02.0")
}

pub fn nic() -> PciAddress {
    at("0000:03:00.0")
}

pub fn node(address: PciAddress, attribute: Attribute) -> SysfsNode {
    SysfsNode::attribute(address, attribute)
}

/// One PCI device of a recorded tree.
#[derive(Clone, Debug)]
pub struct DeviceSpec {
    pub address: PciAddress,
    /// The bridges between it and the root bus `pci0000:00`, root first.
    pub path: Vec<PciAddress>,
    /// The `class` attribute's bytes.
    pub class: &'static str,
    pub boot_vga: Option<&'static str>,
    pub reset: Option<&'static str>,
    pub driver: Option<&'static str>,
    pub group: Option<u32>,
}

impl DeviceSpec {
    /// The device link's target, `../../../devices/pci0000:00/<path>/<address>`.
    pub fn device_path(&self) -> String {
        let mut target = String::from("../../../devices/pci0000:00");
        for port in &self.path {
            target.push('/');
            target.push_str(&port.to_string());
        }
        target.push('/');
        target.push_str(&self.address.to_string());
        target
    }

    /// The `..` steps from the device's directory up to the sysfs root.
    fn up(&self) -> String {
        "../".repeat(3 + self.path.len())
    }
}

/// A root port's configuration space.
#[derive(Clone, Copy, Debug)]
pub struct PortSpec {
    /// `None` for a conventional PCI bridge without a PCI Express capability.
    pub port_type: Option<u8>,
    /// The header type's layout (1 for a bridge).
    pub layout: u8,
    pub multifunction: bool,
    pub secondary_bus: u8,
    pub acs: Option<(u16, u16)>,
    /// How many bytes the `config` read returns.
    pub length: usize,
}

impl PortSpec {
    pub const fn root_port(secondary_bus: u8) -> Self {
        Self {
            port_type: Some(ROOT_PORT),
            layout: 1,
            multifunction: false,
            secondary_bus,
            acs: Some(FULL_ACS),
            length: 4096,
        }
    }
}

/// The bytes of a configuration space: a PCI power management capability at 0x40, then
/// the PCI Express capability at 0x50; in the extended space an AER capability at 0x100,
/// then ACS at 0x140 when the port has it.
pub fn config_space(spec: PortSpec) -> Vec<u8> {
    let mut bytes = vec![0u8; 4096];
    bytes[0..2].copy_from_slice(&0x8086u16.to_le_bytes());
    bytes[2..4].copy_from_slice(&0x1234u16.to_le_bytes());
    bytes[0x06] = 0x10;
    bytes[0x0e] = spec.layout | if spec.multifunction { 0x80 } else { 0 };
    bytes[0x19] = spec.secondary_bus;
    bytes[0x34] = 0x40;
    bytes[0x40] = 0x01;
    if let Some(port_type) = spec.port_type {
        bytes[0x41] = 0x50;
        bytes[0x50] = 0x10;
        bytes[0x51] = 0x00;
        bytes[0x52] = (port_type << 4) | 0x2;
    }
    let aer_next: u32 = if spec.acs.is_some() { 0x140 } else { 0 };
    let aer = 0x0001 | (1 << 16) | (aer_next << 20);
    bytes[0x100..0x104].copy_from_slice(&aer.to_le_bytes());
    if let Some((capability, control)) = spec.acs {
        let header: u32 = 0x000d | (1 << 16);
        bytes[0x140..0x144].copy_from_slice(&header.to_le_bytes());
        bytes[0x144..0x146].copy_from_slice(&capability.to_le_bytes());
        bytes[0x146..0x148].copy_from_slice(&control.to_le_bytes());
    }
    bytes.truncate(spec.length);
    bytes
}

/// A recorded sysfs tree in a temporary directory.
pub struct Tree {
    dir: tempfile::TempDir,
}

impl Tree {
    pub fn empty() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    /// The host of the passing case: root port 00:01.0 above the VGA GPU 01:00.0 and its
    /// audio function 01:00.1 (group 1, both on `vfio-pci`, the GPU with FLR and bus
    /// reset, not the boot display); root port 00:02.0 above the reference 3D controller
    /// 02:00.0 (group 2); every root port with full ACS.
    pub fn host() -> Self {
        let tree = Self::empty();
        tree.port(port_a(), PortSpec::root_port(0x01));
        tree.port(port_b(), PortSpec::root_port(0x02));
        tree.device(&gpu_spec());
        tree.device(&DeviceSpec {
            address: audio(),
            class: "0x040300\n",
            boot_vga: None,
            reset: Some("flr\n"),
            ..gpu_spec()
        });
        tree.device(&reference_spec());
        tree.group(1, &[gpu(), audio()]);
        tree.group(2, &[reference()]);
        tree
    }

    pub fn reader(&self) -> SysfsDir {
        SysfsDir::recorded(self.dir.path())
    }

    /// Writes the attribute file `node`.
    pub fn file(&self, node: SysfsNode, bytes: &[u8]) {
        let location = self.reader().location(&node);
        fs::create_dir_all(location.parent().unwrap()).unwrap();
        fs::write(location, bytes).unwrap();
    }

    /// Writes the link `node` with `target`, as `readlink` prints it.
    pub fn link(&self, node: SysfsNode, target: &str) {
        self.file(node, format!("{target}\n").as_bytes());
    }

    /// Removes the file or link `node`.
    pub fn remove(&self, node: SysfsNode) {
        fs::remove_file(self.reader().location(&node)).unwrap();
    }

    /// Writes every attribute `spec` has.
    pub fn device(&self, spec: &DeviceSpec) {
        let address = spec.address;
        self.link(SysfsNode::Device { address }, &spec.device_path());
        self.file(node(address, Attribute::Class), spec.class.as_bytes());
        if let Some(boot_vga) = spec.boot_vga {
            self.file(node(address, Attribute::BootVga), boot_vga.as_bytes());
        }
        if let Some(reset) = spec.reset {
            self.file(node(address, Attribute::ResetMethod), reset.as_bytes());
        }
        if let Some(driver) = spec.driver {
            self.link(
                node(address, Attribute::Driver),
                &format!("{}bus/pci/drivers/{driver}", spec.up()),
            );
        }
        if let Some(group) = spec.group {
            self.link(
                node(address, Attribute::IommuGroup),
                &format!("{}kernel/iommu_groups/{group}", spec.up()),
            );
        }
    }

    /// Writes a bridge's configuration space.
    pub fn port(&self, address: PciAddress, spec: PortSpec) {
        self.file(node(address, Attribute::Config), &config_space(spec));
    }

    /// Writes group `number`'s `devices` directory with exactly `members`.
    pub fn group(&self, number: u32, members: &[PciAddress]) {
        let listing = SysfsNode::GroupDevices {
            group: super::address::IommuGroup::new(number),
        };
        let directory = self.reader().location(&listing);
        if directory.exists() {
            fs::remove_dir_all(&directory).unwrap();
        }
        fs::create_dir_all(&directory).unwrap();
        for member in members {
            let name = super::reader::encode_component(&member.to_string());
            fs::write(
                directory.join(format!("{name}.link")),
                format!("../../../../devices/pci0000:00/{member}\n"),
            )
            .unwrap();
        }
    }
}

/// The GPU under test as the passing host records it.
pub fn gpu_spec() -> DeviceSpec {
    DeviceSpec {
        address: gpu(),
        path: vec![port_a()],
        class: "0x030000\n",
        boot_vga: Some("0\n"),
        reset: Some("flr bus\n"),
        driver: Some("vfio-pci"),
        group: Some(1),
    }
}

/// The reference GPU, a 3D controller without `boot_vga`.
pub fn reference_spec() -> DeviceSpec {
    DeviceSpec {
        address: reference(),
        path: vec![port_b()],
        class: "0x030200\n",
        boot_vga: None,
        reset: Some("flr\n"),
        driver: Some("vfio-pci"),
        group: Some(2),
    }
}

pub fn machine() -> Digest {
    digest("yougori/test/host-checks/machine/v1", &[b"machine"])
}

pub fn device_digest(name: &str) -> Digest {
    digest("yougori/test/host-checks/device/v1", &[name.as_bytes()])
}

pub fn configuration() -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_settings([("host", "gpu-host")]).unwrap()
}

/// The subject naming the GPU under test.
pub fn gpu_subject() -> Subject {
    Subject::GpuDevice(GpuDeviceSubject {
        machine: machine(),
        device: device_digest("gpu-a"),
    })
}

/// Settings for a Linux host with the GPU under test and the reference GPU mapped.
pub fn settings(reference_gpu: Option<PciAddress>) -> RunnerSettings {
    RunnerSettings {
        os: OsKind::Linux,
        machine: machine(),
        configuration: configuration(),
        fresh_for: FRESH,
        gpus: BTreeMap::from([
            (device_digest("gpu-a"), gpu()),
            (device_digest("gpu-ref"), reference()),
        ]),
        reference: reference_gpu,
    }
}

pub fn runner(tree: &Tree, reference_gpu: Option<PciAddress>) -> GpuAssignmentRunner<SysfsDir> {
    GpuAssignmentRunner::new(tree.reader(), settings(reference_gpu)).unwrap()
}

/// A CORE-01 registry on a manual clock.
pub fn registry() -> (ProbeRegistry<Arc<ManualClock>>, Arc<ManualClock>) {
    let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(1_000_000)));
    (ProbeRegistry::new(Arc::clone(&clock)), clock)
}

/// A reader that counts every read it is asked for.
pub struct CountingReader {
    pub inner: SysfsDir,
    pub reads: Arc<AtomicUsize>,
}

impl CountingReader {
    pub fn new(inner: SysfsDir) -> (Self, Arc<AtomicUsize>) {
        let reads = Arc::new(AtomicUsize::new(0));
        (
            Self {
                inner,
                reads: Arc::clone(&reads),
            },
            reads,
        )
    }

    fn count(&self) {
        self.reads.fetch_add(1, Ordering::SeqCst);
    }
}

impl SysfsReader for CountingReader {
    fn read(&self, node: &SysfsNode, limit: usize) -> Result<Vec<u8>, ReadError> {
        self.count();
        self.inner.read(node, limit)
    }

    fn link(&self, node: &SysfsNode) -> Result<String, ReadError> {
        self.count();
        self.inner.link(node)
    }

    fn list(&self, node: &SysfsNode) -> Result<Vec<String>, ReadError> {
        self.count();
        self.inner.list(node)
    }
}
