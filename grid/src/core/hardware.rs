//! What a computer can report about itself, with how it was learned and when.
//!
//! This is not a connector and it could not be one. `Connector::plan` takes a `Request`, a
//! `Request` carries a `Subject`, and a `Subject` is a person's email. A computer reporting on
//! itself is inbound, has no credential, no destination and no person, and `revoke` would mean
//! nothing. So it has a seam of its own, with two operations instead of nine.
//!
//! The rule the whole file is built on is the one `identity::Attestation` already follows, and it
//! is followed here rather than a second rule being invented: a fact that was not measured is
//! reported as not measured, never as "no". A `None` in a `Machine` means this build could not
//! read that on this computer. It does not mean the computer does not have it, and the difference
//! matters most for exactly the facts a security administrator cares about. A computer with no
//! TPM and a computer whose TPM this build cannot reach are not the same computer, and reporting
//! both as "no TPM" would make the second one look like the first.
//!
//! Every fact also carries how it was learned, in `Source`, because the facts are not equally
//! good. A number from a system call and a number parsed out of a vendor tool's printed output are
//! both useful and they are not the same kind of evidence, and the type says which is which rather
//! than a comment somewhere saying it usually.
//!
//! What stops a gap being silent is `could_not_measure`: a sentence naming the thing and why, so a
//! gap is something somebody reads rather than a missing field somebody has to notice.
//!
//! ## Why there is a `Probe` trait and not only a function
//!
//! Some of what a realm wants to know is already measured by the application this crate is a part
//! of, and it is measured there because that is where the code to do it lives: the GPU adapters
//! come from a probe program that ships beside the app, the disks come from a crate the app
//! depends on. `src-tauri` depends on this crate and not the other way round, so this file cannot
//! call any of it. Reading the same hardware twice, once here and once there, would be two answers
//! that can disagree.
//!
//! So `Probe` is the seam the host fills in. This crate supplies `Local`, which reads what it can
//! reach with what it already has, and says plainly what it cannot. A host that knows more
//! implements `Probe` and adds it. Nothing is invented at either end.
use super::identity::Attestation;
use super::work::{GpuIsolation, Resources};
use serde::{Deserialize, Serialize};

#[cfg(test)]
mod tests;

/// How a fact about a computer was learned.
///
/// Nothing in this list is proof against the operating system of the computer that reported it.
/// The strongest of them is still a number that computer's kernel handed over, which is why
/// `Trust` below caps where it does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Source {
    /// A system call on this computer.
    Syscall,
    /// A file the operating system publishes, read as it was written.
    SystemFile,
    /// A program that ships with this application, run here, with its output parsed.
    Helper,
    /// A tool the hardware vendor installed, found and run with a fixed argument list.
    VendorTool,
    /// Signed by a key the operating system holds and this process cannot read. Nothing in this
    /// repository produces one. The variant exists so that when something does, the difference is
    /// in the type rather than in a comment, and so `Trust` can refuse to rise without it.
    SignedByHardware,
}

impl Source {
    pub fn describe(self) -> &'static str {
        match self {
            Source::Syscall => "a system call on this computer",
            Source::SystemFile => "a file the operating system publishes",
            Source::Helper => "a program that ships with this application",
            Source::VendorTool => "a tool the hardware vendor installed",
            Source::SignedByHardware => "signed by a key this process cannot read",
        }
    }

    /// Whether a fact learned this way is anything more than this computer's own word.
    ///
    /// Four of the five are not, and saying so here is what keeps `trust` honest: an administrator
    /// on a computer can change what a system call returns to a process they started.
    pub fn is_more_than_self_report(self) -> bool {
        matches!(self, Source::SignedByHardware)
    }

    /// How much a fact learned this way is worth, from least to most.
    ///
    /// Deliberately not the order the variants are declared in, and deliberately not a derived
    /// ordering, because the two would not agree and a derived one would silently decide which
    /// evidence is better. Text printed by a tool somebody else wrote is the weakest, because a
    /// change to its output is a change to what this grid believes; text printed by a program that
    /// ships with this application is next, because at least both halves move together; a file the
    /// operating system publishes is above both; a system call is above that; and only the last of
    /// them is evidence against the computer that produced it.
    pub fn strength(self) -> u8 {
        match self {
            Source::VendorTool => 0,
            Source::Helper => 1,
            Source::SystemFile => 2,
            Source::Syscall => 3,
            Source::SignedByHardware => 4,
        }
    }
}

/// One fact, with how it was learned and when.
///
/// There is no constructor that leaves out the source, which is what stops a guess being recorded
/// as a measurement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Measured<T> {
    pub value: T,
    pub source: Source,
    pub at: i64,
}

impl<T> Measured<T> {
    pub fn new(value: T, source: Source, at: i64) -> Measured<T> {
        Measured { value, source, at }
    }
}

/// Which company made a card.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Vendor {
    Nvidia,
    Amd,
    Intel,
    Apple,
    #[default]
    Unknown,
}

impl Vendor {
    /// The company behind a PCI vendor identifier. Four are recognised; anything else is unknown,
    /// which is the honest answer rather than a guess from a card's printed name.
    pub fn of_pci(id: u32) -> Vendor {
        match id {
            0x10de => Vendor::Nvidia,
            0x1002 | 0x1022 => Vendor::Amd,
            0x8086 => Vendor::Intel,
            0x106b => Vendor::Apple,
            _ => Vendor::Unknown,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Vendor::Nvidia => "NVIDIA",
            Vendor::Amd => "AMD",
            Vendor::Intel => "Intel",
            Vendor::Apple => "Apple",
            Vendor::Unknown => "a vendor this build does not recognise",
        }
    }
}

/// Which compute stack is installed beside a card.
///
/// Finding one installed is not finding a working driver, and nothing here claims it is. CUDA
/// being on the disk says a package was installed; whether a kernel can be launched on this card
/// right now is a different question that this build does not ask.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "stack")]
pub enum Compute {
    /// NVIDIA CUDA, with the driver version the vendor tool printed.
    Cuda { driver: String },
    /// AMD ROCm, with the version the vendor tool printed.
    Rocm { version: String },
    /// Intel's oneAPI Level Zero.
    LevelZero,
    /// Apple Metal.
    Metal,
}

impl Compute {
    pub fn name(&self) -> &'static str {
        match self {
            Compute::Cuda { .. } => "NVIDIA CUDA",
            Compute::Rocm { .. } => "AMD ROCm",
            Compute::LevelZero => "Intel Level Zero",
            Compute::Metal => "Apple Metal",
        }
    }
}

/// What a TPM answered, which is not the same as whether one exists.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "tpm")]
pub enum Tpm {
    /// The operating system says there is a TPM and it is usable.
    Ready { version: String },
    /// There is one and it is not usable: not provisioned, or owned by something else.
    NotReady,
    /// There is none. Only ever reported when the computer said so, never inferred from a failure
    /// to find one.
    Absent,
}

impl Tpm {
    pub fn usable(&self) -> bool {
        matches!(self, Tpm::Ready { .. })
    }
}

/// One graphics card as this computer describes it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Card {
    pub vendor: Vendor,
    pub name: String,
    pub vram_gb: Option<Measured<f64>>,
    /// How it is isolated, when the computer could say. Never inferred: a card that is merely
    /// visible stays `None`, which `resources` turns into `GpuIsolation::Unknown`, which
    /// `work::GpuIsolation::shareable` already refuses to share.
    pub isolation: Option<Measured<GpuIsolation>>,
    /// Which compute stack is installed beside it, when one was found.
    pub compute: Option<Measured<Compute>>,
}

impl Card {
    pub fn new(vendor: Vendor, name: &str) -> Card {
        Card { vendor, name: name.chars().filter(|letter| !letter.is_control()).take(128).collect(), vram_gb: None, isolation: None, compute: None }
    }
}

/// One network interface as this computer describes it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Interface {
    pub name: String,
    /// Whether the operating system says the cable or the radio is up, when it says. A link state
    /// nobody could read is `None`, which is not "down".
    pub up: Option<Measured<bool>>,
    /// Megabits a second, when the interface reports a speed. Virtual interfaces mostly do not.
    pub speed_mbps: Option<Measured<u32>>,
    /// Whether this is a loopback or virtual interface rather than a real one, when the computer
    /// said which. Deliberately not guessed from the name: `eth0` inside a container is virtual
    /// and `vmbr0` on a hypervisor is where the real traffic goes.
    pub physical: Option<Measured<bool>>,
}

impl Interface {
    pub fn new(name: &str) -> Interface {
        Interface { name: name.chars().filter(|letter| letter.is_ascii_graphic()).take(64).collect(), up: None, speed_mbps: None, physical: None }
    }
}

/// Which fact a gap sentence is about, when whoever wrote the sentence could say.
///
/// This exists for one job. `Machine::filled_in_with` has to drop a gap because the fact it is
/// about has now been measured, and matching the words of the sentence does not tell it that: the
/// sentence about a graphics card names memory while explaining what would read one, so a word
/// match removed it the moment anything measured memory, and a card nobody enumerated quietly
/// stopped being reported. The tag says what the sentence is about rather than what it mentions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fact {
    Processors,
    Memory,
    FreeDisk,
    Graphics,
    Tpm,
    SecureBoot,
    DiskEncryption,
    Interfaces,
}

/// One thing this build could not measure, in words, with the fact it is about when the sentence
/// was written somewhere that could say which.
///
/// It is written and read back as the bare sentence, so what a realm records is exactly what it
/// recorded before and a sentence that came from another computer reads back with no tag at all.
/// An untagged gap is never dropped, which over-reports rather than hides, and over-reporting a
/// gap costs a line somebody reads while hiding one costs a realm a fact it thought it had.
#[derive(Clone, Debug)]
pub struct Gap {
    pub said: String,
    pub about: Option<Fact>,
}

impl Gap {
    fn new(sentence: &str, about: Option<Fact>) -> Gap {
        Gap { said: sentence.chars().filter(|letter| !letter.is_control()).take(240).collect(), about }
    }
}

/// Two gaps are the same gap when they say the same thing. The tag is about where the sentence
/// was written and not about what it says, so it is no part of whether a list already holds one.
impl PartialEq for Gap {
    fn eq(&self, other: &Gap) -> bool {
        self.said == other.said
    }
}

impl std::ops::Deref for Gap {
    type Target = str;
    fn deref(&self) -> &str {
        &self.said
    }
}

impl std::fmt::Display for Gap {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.said)
    }
}

impl Serialize for Gap {
    fn serialize<S: serde::Serializer>(&self, writer: S) -> Result<S::Ok, S::Error> {
        writer.serialize_str(&self.said)
    }
}

impl<'de> Deserialize<'de> for Gap {
    fn deserialize<D: serde::Deserializer<'de>>(reader: D) -> Result<Gap, D::Error> {
        Ok(Gap { said: String::deserialize(reader)?, about: None })
    }
}

/// What a probe found on one computer.
///
/// Every field is optional and a `None` means this build could not measure it here, in the same
/// way `identity::Attestation` already means it.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Machine {
    pub os: Option<Measured<String>>,
    pub cpus: Option<Measured<u32>>,
    pub cpu_model: Option<Measured<String>>,
    pub memory_gb: Option<Measured<f64>>,
    pub free_memory_gb: Option<Measured<f64>>,
    pub disk_gb: Option<Measured<f64>>,
    pub free_disk_gb: Option<Measured<f64>>,
    #[serde(default)]
    pub cards: Vec<Card>,
    #[serde(default)]
    pub interfaces: Vec<Interface>,
    pub secure_boot: Option<Measured<bool>>,
    pub tpm: Option<Measured<Tpm>>,
    /// Whether the disk this computer boots from is encrypted at rest: BitLocker, FileVault or
    /// LUKS, whichever this computer has. One field, because what a realm wants to know is the
    /// same question on all three, and the `encryption_named` sentence says which one answered.
    pub disk_encryption: Option<Measured<bool>>,
    /// Which product answered the disk encryption question, when one did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption_named: Option<String>,
    pub on_battery: Option<Measured<bool>>,
    pub battery_percent: Option<Measured<u8>>,
    /// What this build could not measure on this computer, in words, each one naming the thing and
    /// why. A gap is a sentence somebody reads rather than a missing field somebody has to notice.
    #[serde(default)]
    pub could_not_measure: Vec<Gap>,
}

impl Machine {
    /// Records that something was not measured, and why. Said once however many times it is noted,
    /// because the same gap reported eight times is eight lines nobody reads.
    ///
    /// For a sentence that is not about one of the facts `filled_in_with` can fill. A gap recorded
    /// this way is never dropped, which is right for a sentence about a whole platform or about
    /// why a measured answer looks the way it does.
    pub fn gap(&mut self, sentence: &str) {
        self.note_gap(Gap::new(sentence, None));
    }

    /// The same, for a sentence about one named fact, so that a computer which measured that fact
    /// closes this gap and nothing else does.
    pub fn gap_about(&mut self, fact: Fact, sentence: &str) {
        self.note_gap(Gap::new(sentence, Some(fact)));
    }

    fn note_gap(&mut self, gap: Gap) {
        if !self.could_not_measure.contains(&gap) {
            self.could_not_measure.push(gap);
        }
    }

    /// Whether every fact in here carries a source. Nothing can build a `Measured` without one, so
    /// this cannot fail by construction; it is here because a later field added as a bare value
    /// rather than a `Measured` would be a silent loss of the rule this file is about, and a test
    /// that walks the serialised form catches that.
    pub fn every_fact_says_how_it_was_learned(&self) -> bool {
        fn sourced(value: &serde_json::Value) -> bool {
            match value {
                serde_json::Value::Object(fields) if fields.contains_key("value") => fields.contains_key("source") && fields.contains_key("at"),
                serde_json::Value::Object(fields) => fields.values().all(sourced),
                serde_json::Value::Array(items) => items.iter().all(sourced),
                _ => true,
            }
        }
        serde_json::to_value(self).map(|value| sourced(&value)).unwrap_or(false)
    }

    /// The facts the other computer measured, added to the facts this one did.
    ///
    /// A host that knows something this crate cannot read fills it in here. What is already
    /// measured is kept: a `Probe` adding what it knows must not be able to overwrite a reading
    /// with a worse one, and the gaps it filled stop being gaps.
    pub fn filled_in_with(mut self, other: Machine) -> Machine {
        fn keep<T>(mine: Option<Measured<T>>, theirs: Option<Measured<T>>) -> Option<Measured<T>> {
            mine.or(theirs)
        }
        self.os = keep(self.os, other.os);
        self.cpus = keep(self.cpus, other.cpus);
        self.cpu_model = keep(self.cpu_model.take(), other.cpu_model);
        self.memory_gb = keep(self.memory_gb, other.memory_gb);
        self.free_memory_gb = keep(self.free_memory_gb, other.free_memory_gb);
        self.disk_gb = keep(self.disk_gb, other.disk_gb);
        self.free_disk_gb = keep(self.free_disk_gb, other.free_disk_gb);
        self.secure_boot = keep(self.secure_boot, other.secure_boot);
        self.tpm = self.tpm.take().or(other.tpm);
        self.disk_encryption = keep(self.disk_encryption, other.disk_encryption);
        self.encryption_named = self.encryption_named.take().or(other.encryption_named);
        self.on_battery = keep(self.on_battery, other.on_battery);
        self.battery_percent = keep(self.battery_percent, other.battery_percent);
        if self.cards.is_empty() {
            self.cards = other.cards;
        }
        if self.interfaces.is_empty() {
            self.interfaces = other.interfaces;
        }
        for gap in other.could_not_measure {
            self.note_gap(gap);
        }
        // A gap the other computer filled in is no longer a gap. What decides that is the fact the
        // sentence says it is about, not a word somewhere in the sentence: the one about a
        // graphics card explains that the application reports vendor, device and memory, and
        // matching words took it away the moment anything measured memory. A gap that says nothing
        // about which fact it is for is kept, because a gap reported twice is a line somebody
        // reads and a gap removed is a fact a realm thinks it has.
        let filled: Vec<Fact> = [
            self.cpus.is_some().then_some(Fact::Processors),
            self.memory_gb.is_some().then_some(Fact::Memory),
            self.free_disk_gb.is_some().then_some(Fact::FreeDisk),
            (!self.cards.is_empty()).then_some(Fact::Graphics),
            self.tpm.is_some().then_some(Fact::Tpm),
            self.secure_boot.is_some().then_some(Fact::SecureBoot),
            self.disk_encryption.is_some().then_some(Fact::DiskEncryption),
            (!self.interfaces.is_empty()).then_some(Fact::Interfaces),
        ]
        .into_iter()
        .flatten()
        .collect();
        self.could_not_measure.retain(|gap| !gap.about.is_some_and(|fact| filled.contains(&fact)));
        self
    }
}

/// What a computer can report about itself.
///
/// One operation and no credential. A host implements this when it can measure something this
/// crate cannot reach, and `Local` is what this crate can reach on its own.
pub trait Probe: Send + Sync {
    /// What this probe is, for the note that says where a fact came from.
    fn name(&self) -> &'static str;

    /// Reads this computer. May run system calls and short helper programs, so call it from a
    /// blocking thread. Nothing here reaches the network and nothing here writes anything.
    fn read(&self, now: i64) -> Machine;
}

/// What this crate can read on its own, with nothing added to the build for it.
///
/// Deliberately modest. What it will not do is run a vendor tool: there is no way to run a child
/// process with a timeout and a bounded output with what this crate depends on, and a hardware
/// probe that can hang on a `manage-bde` waiting for an elevation prompt is worse than one that
/// says it did not look. Those facts are gaps with sentences, and a host that has the machinery to
/// run tools safely fills them in through `Probe`.
pub struct Local;

impl Probe for Local {
    fn name(&self) -> &'static str {
        "this grid, reading what it can reach"
    }

    fn read(&self, now: i64) -> Machine {
        let mut machine = Machine { os: Some(Measured::new(std::env::consts::OS.to_owned(), Source::Syscall, now)), ..Machine::default() };
        if let Ok(cpus) = std::thread::available_parallelism() {
            machine.cpus = Some(Measured::new(cpus.get() as u32, Source::Syscall, now));
        } else {
            machine.gap_about(Fact::Processors, "How many processors this computer has could not be read, so nothing is assumed about its size.");
        }
        let power = crate::power::current();
        machine.on_battery = Some(Measured::new(power.on_battery, Source::Syscall, now));
        match power.percent {
            Some(percent) => machine.battery_percent = Some(Measured::new(percent, Source::Syscall, now)),
            None => machine.gap("This computer did not report a battery percentage, which is not the same as a battery that is low."),
        }
        platform::read(&mut machine, now);
        gaps(&mut machine);
        machine
    }
}

/// The sentences for everything nothing measured, after the platform has had its turn.
///
/// Every one of them names the fact and says what would read it, so somebody reading the list
/// knows what is missing and what would fill it rather than only that something is absent.
fn gaps(machine: &mut Machine) {
    if machine.memory_gb.is_none() {
        machine.gap_about(Fact::Memory, "How much memory this computer has could not be read on this platform.");
    }
    if machine.free_disk_gb.is_none() {
        machine.gap_about(Fact::FreeDisk, "Free disk was not read here. The application that holds this grid measures it and reports it through the probe seam, so it is read once rather than twice.");
    }
    if machine.cards.is_empty() {
        machine.gap_about(Fact::Graphics, "No graphics card was enumerated here. The application that holds this grid runs a probe program that reports vendor, device and memory, and supplies it through the probe seam.");
    }
    if machine.tpm.is_none() {
        machine.gap_about(Fact::Tpm, "This computer's TPM was not read. Reading it needs a call into the platform's own TPM service, which nothing in this grid makes, so whether there is one is unknown rather than no.");
    }
    if machine.secure_boot.is_none() {
        machine.gap_about(Fact::SecureBoot, "Whether this computer booted with Secure Boot was not read, so it is unknown rather than off.");
    }
    if machine.disk_encryption.is_none() {
        machine.gap_about(Fact::DiskEncryption, "Whether this computer's disk is encrypted at rest was not read. BitLocker and FileVault are reported by tools this grid does not run, so the answer is unknown rather than no.");
    }
    if machine.interfaces.is_empty() {
        machine.gap_about(Fact::Interfaces, "This computer's network interfaces were not enumerated on this platform.");
    }
    if !machine.cards.iter().any(|card| card.isolation.is_some()) && !machine.cards.is_empty() {
        machine.gap("How this computer's cards are isolated was not read from any driver, so no card here may be shared between two people's work.");
    }
}

/// What this computer offers a realm, from what was measured.
///
/// A fact that was not measured contributes nothing rather than a default. `cpu` is zero when the
/// processor count could not be read, and a realm that sees zero places nothing on this computer,
/// which is the right answer: a computer that cannot say how big it is should not be filled up.
pub fn resources(machine: &Machine) -> Resources {
    Resources {
        cpu: machine.cpus.map(|cpus| f64::from(cpus.value)).unwrap_or_default(),
        memory_gb: machine.memory_gb.map(|memory| memory.value).unwrap_or_default(),
        disk_gb: machine.free_disk_gb.or(machine.disk_gb).map(|disk| disk.value).unwrap_or_default(),
        // A card that is there is a card, whether or not its memory could be read.
        gpu: !machine.cards.is_empty(),
        vram_gb: machine.cards.iter().filter_map(|card| card.vram_gb.map(|vram| vram.value)).fold(0.0, f64::max),
    }
}

/// How a computer's cards are isolated, as one answer for the whole computer.
///
/// One disagreement makes the whole computer unknown, because the scheduler places work on a
/// computer and not on a card: a computer with one partitioned card and one card nobody measured
/// is a computer where work can land on the one nobody measured. A computer with no card at all is
/// unknown too, which is what `work::Host` already defaults to and what the scheduler already
/// refuses to share.
pub fn isolation(machine: &Machine) -> GpuIsolation {
    let mut answer: Option<GpuIsolation> = None;
    for card in &machine.cards {
        let Some(measured) = card.isolation else { return GpuIsolation::Unknown };
        match answer {
            None => answer = Some(measured.value),
            Some(agreed) if agreed == measured.value => {}
            Some(_) => return GpuIsolation::Unknown,
        }
    }
    answer.unwrap_or(GpuIsolation::Unknown)
}

/// The `Attestation` the realm records.
///
/// A field nothing could measure stays `None`, which `Attestation::describe` already reports as
/// "unverified: this computer cannot report its own state". A TPM that answered `NotReady` or
/// `Absent` is a measured no and is recorded as one; a TPM nothing read is not.
pub fn attestation(machine: &Machine, agent_version: &str) -> Attestation {
    // The weaker of the two, because a pair of answers is only as good as the worse of them.
    let source = [machine.secure_boot.map(|fact| fact.source), machine.tpm.as_ref().map(|fact| fact.source)].into_iter().flatten().min_by_key(|source| source.strength());
    let measured_at = [machine.secure_boot.map(|fact| fact.at), machine.tpm.as_ref().map(|fact| fact.at)].into_iter().flatten().max();
    Attestation {
        secure_boot: machine.secure_boot.map(|fact| fact.value),
        tpm: machine.tpm.as_ref().map(|fact| fact.value.usable()),
        os: machine.os.as_ref().map(|fact| fact.value.clone()),
        agent_version: (!agent_version.is_empty()).then(|| agent_version.chars().filter(|letter| !letter.is_control()).take(64).collect()),
        source,
        measured_at,
        could_not_measure: machine.could_not_measure.iter().map(|gap| gap.said.clone()).collect(),
    }
}

/// How much of what a computer says about itself has been shown rather than asserted.
///
/// The order is the order of evidence. The gap between the second and the third is the whole point
/// of this type: everything a computer measures about itself, however carefully, is still that
/// computer telling the realm about that computer, and an administrator on that computer can
/// change what it says.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Trust {
    /// Nothing was measured, or what was measured says this computer is not protected.
    #[default]
    Unverified,
    /// The computer measured Secure Boot and a usable TPM and reported them. Nothing signed the
    /// report, and nothing stops the report being written by hand.
    SelfReported,
    /// A key the operating system holds, which this process cannot read, signed a statement over a
    /// value this realm chose, so an old report cannot be replayed.
    DeviceSigned,
    /// A TPM quote over named platform registers, with a certificate chain to a manufacturer root
    /// this realm trusts.
    HardwareAttested,
}

impl Trust {
    pub fn word(self) -> &'static str {
        match self {
            Trust::Unverified => "unverified",
            Trust::SelfReported => "selfReported",
            Trust::DeviceSigned => "deviceSigned",
            Trust::HardwareAttested => "hardwareAttested",
        }
    }

    pub fn parse(word: &str) -> Option<Trust> {
        [Trust::Unverified, Trust::SelfReported, Trust::DeviceSigned, Trust::HardwareAttested].into_iter().find(|trust| trust.word() == word)
    }

    /// What this means, in words that never claim more than it is.
    pub fn describe(self) -> &'static str {
        match self {
            Trust::Unverified => "this computer has shown nothing about its own state",
            Trust::SelfReported => "this computer says it booted with Secure Boot and has a usable TPM, and nothing has checked that but the computer itself",
            Trust::DeviceSigned => "a key this computer's operating system holds signed a statement this grid asked for",
            Trust::HardwareAttested => "this computer's TPM quoted its own measurements, with a chain to a manufacturer this grid trusts",
        }
    }
}

/// The highest trust anything in this repository can produce.
///
/// Nothing here mints a key inside a TPM, asks for a quote over platform registers, or checks a
/// manufacturer's certificate chain. The constant exists so that a later change claiming more
/// without writing the code fails a test here rather than an audit at a customer.
pub const CEILING: Trust = Trust::SelfReported;

/// How long a computer's measurement of itself counts for. A laptop that proved its state a month
/// ago has proved nothing about today.
pub const STALE_AFTER: i64 = 24 * 60 * 60;

/// What this computer has shown, as of `now`. Never above `CEILING`, whatever it reported.
///
/// Three things have to be true for anything above unverified: the computer said Secure Boot is on
/// and its TPM is usable, it said so recently enough to be about today, and it said how it learned
/// it. A report with no source is a report from a build that did not record one, and counting it
/// would be counting a guess.
pub fn trust(attestation: &Attestation, now: i64) -> Trust {
    // The window is a day either way, and the two sides mean different things. A measurement more
    // than a day old is not about today. A measurement stamped more than a day in the future is
    // not about today either, because the clock that stamped it does not agree with this realm's.
    // Inside the day in either direction it counts, and that tolerance is bought on purpose: two
    // computers' clocks are never exactly the same, and refusing a computer whose clock is a few
    // minutes ahead would be refusing it for its clock rather than for its state.
    let fresh = attestation.measured_at.is_some_and(|at| (now - at).abs() < STALE_AFTER);
    let shown = match (attestation.secure_boot, attestation.tpm, attestation.source, fresh) {
        (Some(true), Some(true), Some(source), true) => {
            if source.is_more_than_self_report() {
                Trust::DeviceSigned
            } else {
                Trust::SelfReported
            }
        }
        _ => Trust::Unverified,
    };
    shown.min(CEILING)
}

/// Whether a realm that demands `wanted` may place work on a computer that has shown `shown`.
///
/// A realm that demands `HardwareAttested` takes no computer here at all, and that is the correct
/// answer rather than a bug to work around: nothing in this repository can produce that evidence,
/// so a realm asking for it should get nothing rather than something relabelled.
pub fn admits(wanted: Trust, shown: Trust) -> bool {
    shown >= wanted
}

/// Why this computer may not take work for a realm that demands `wanted`, in words, or nothing
/// when it may. Never an accusation: a computer that has shown nothing is usually a computer
/// nobody has set up to show anything.
pub fn why_refused(wanted: Trust, shown: Trust) -> Option<String> {
    if admits(wanted, shown) {
        return None;
    }
    Some(format!(
        "This computer has shown {}, and this grid takes only computers that have shown {}. {}.",
        shown.word(),
        wanted.word(),
        if wanted > CEILING { format!("Nothing in this version can show {}, so no computer will be taken until that changes", wanted.word()) } else { shown.describe().to_owned() }
    ))
}

// ---- What each platform can read, with nothing added to the build ----

#[cfg(target_os = "linux")]
mod platform {
    use super::*;

    pub fn read(machine: &mut Machine, now: i64) {
        if let Ok(text) = std::fs::read_to_string("/proc/meminfo") {
            if let Some(total) = super::parse::meminfo(&text, "MemTotal") {
                machine.memory_gb = Some(Measured::new(total, Source::SystemFile, now));
            }
            if let Some(free) = super::parse::meminfo(&text, "MemAvailable") {
                machine.free_memory_gb = Some(Measured::new(free, Source::SystemFile, now));
            }
        }
        if let Ok(text) = std::fs::read_to_string("/proc/cpuinfo") {
            if let Some(model) = super::parse::cpu_model(&text) {
                machine.cpu_model = Some(Measured::new(model, Source::SystemFile, now));
            }
        }
        if let Ok(bytes) = std::fs::read("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c") {
            if let Some(on) = super::parse::efi_secure_boot(&bytes) {
                machine.secure_boot = Some(Measured::new(on, Source::SystemFile, now));
            }
        } else if !std::path::Path::new("/sys/firmware/efi").exists() {
            machine.secure_boot = Some(Measured::new(false, Source::SystemFile, now));
            machine.gap("This computer did not boot through UEFI, so Secure Boot is not a question it can answer, and it is recorded as off rather than as unknown.");
        }
        if let Some(tpm) = read_tpm() {
            machine.tpm = Some(Measured::new(tpm, Source::SystemFile, now));
        }
        if let Some(encrypted) = read_luks() {
            machine.disk_encryption = Some(Measured::new(encrypted, Source::SystemFile, now));
            machine.encryption_named = Some("LUKS".into());
        }
        machine.cards = read_cards(now);
        machine.interfaces = read_interfaces(now);
    }

    /// `/sys/class/tpm` is the kernel's own list. An empty directory is a kernel that looked and
    /// found nothing, which is a measured absence; an unreadable one is not an answer at all.
    fn read_tpm() -> Option<Tpm> {
        let entries: Vec<_> = std::fs::read_dir("/sys/class/tpm").ok()?.flatten().collect();
        if entries.is_empty() {
            return Some(Tpm::Absent);
        }
        for entry in entries {
            if let Ok(version) = std::fs::read_to_string(entry.path().join("tpm_version_major")) {
                return Some(super::parse::tpm_version(version.trim()));
            }
        }
        None
    }

    fn read_luks() -> Option<bool> {
        let blocks = std::fs::read_dir("/sys/block").ok()?;
        for entry in blocks.flatten() {
            if let Ok(uuid) = std::fs::read_to_string(entry.path().join("dm/uuid")) {
                if uuid.trim_start().starts_with("CRYPT-LUKS") {
                    return Some(true);
                }
            }
        }
        // Looking at every block device and finding no encrypted one is a measured no.
        Some(false)
    }

    fn read_cards(now: i64) -> Vec<Card> {
        let Ok(entries) = std::fs::read_dir("/sys/class/drm") else { return Vec::new() };
        let mut cards = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with("card") || name.contains('-') {
                continue;
            }
            let device = entry.path().join("device");
            let Ok(vendor) = std::fs::read_to_string(device.join("vendor")) else { continue };
            let Some(id) = super::parse::pci_id(vendor.trim()) else { continue };
            let mut card = Card::new(Vendor::of_pci(id), &name);
            if let Some(vram) = std::fs::read_to_string(device.join("mem_info_vram_total")).ok().and_then(|text| text.trim().parse::<u64>().ok()) {
                card.vram_gb = Some(Measured::new(vram as f64 / 1_073_741_824.0, Source::SystemFile, now));
            }
            cards.push(card);
        }
        cards.sort_by(|left, right| left.name.cmp(&right.name));
        cards
    }

    fn read_interfaces(now: i64) -> Vec<Interface> {
        let Ok(entries) = std::fs::read_dir("/sys/class/net") else { return Vec::new() };
        let mut interfaces = Vec::new();
        for entry in entries.flatten() {
            let mut interface = Interface::new(&entry.file_name().to_string_lossy());
            if let Ok(state) = std::fs::read_to_string(entry.path().join("operstate")) {
                if let Some(up) = super::parse::operstate(state.trim()) {
                    interface.up = Some(Measured::new(up, Source::SystemFile, now));
                }
            }
            if let Some(speed) = std::fs::read_to_string(entry.path().join("speed")).ok().and_then(|text| text.trim().parse::<i64>().ok()).filter(|speed| *speed > 0) {
                interface.speed_mbps = Some(Measured::new(speed as u32, Source::SystemFile, now));
            }
            // The kernel says which interfaces have a real device behind them, so this is read
            // rather than guessed from the name.
            interface.physical = Some(Measured::new(entry.path().join("device").exists(), Source::SystemFile, now));
            interfaces.push(interface);
        }
        interfaces.sort_by(|left, right| left.name.cmp(&right.name));
        interfaces
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

    pub fn read(machine: &mut Machine, now: i64) {
        let mut status = MEMORYSTATUSEX {
            dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
            dwMemoryLoad: 0,
            ullTotalPhys: 0,
            ullAvailPhys: 0,
            ullTotalPageFile: 0,
            ullAvailPageFile: 0,
            ullTotalVirtual: 0,
            ullAvailVirtual: 0,
            ullAvailExtendedVirtual: 0,
        };
        // SAFETY: `status` is a correctly sized MEMORYSTATUSEX owned by this frame, with its
        // length set the way the call requires.
        if unsafe { GlobalMemoryStatusEx(&mut status) } != 0 && status.ullTotalPhys > 0 {
            machine.memory_gb = Some(Measured::new(status.ullTotalPhys as f64 / 1_073_741_824.0, Source::Syscall, now));
            machine.free_memory_gb = Some(Measured::new(status.ullAvailPhys as f64 / 1_073_741_824.0, Source::Syscall, now));
        }
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
mod platform {
    use super::*;

    pub fn read(machine: &mut Machine, _now: i64) {
        machine.gap(&format!(
            "This build reads almost nothing about a {} computer: there is no platform module for it here, so every fact below is unknown rather than absent.",
            std::env::consts::OS
        ));
    }
}

/// Reading what an operating system or a vendor tool printed.
///
/// Every one of these is a pure function over bytes, which is the point: the parsing is the part
/// that goes wrong, and it is the part that can be exercised on any computer with fixture bytes
/// rather than only on hardware somebody happens to have. Every one of them follows the same rule:
/// an input that does not match exactly answers `None`, never a default.
pub mod parse {
    use super::{Card, Compute, GpuIsolation, Measured, Source, Tpm, Vendor};

    /// One line of `/proc/meminfo`, in gigabytes. The file is in kilobytes and says so on each
    /// line; a line that does not say `kB` is a line this does not understand.
    pub fn meminfo(text: &str, name: &str) -> Option<f64> {
        let line = text.lines().find(|line| line.starts_with(name) && line[name.len()..].starts_with(':'))?;
        let rest = line.split_once(':')?.1.trim();
        let kilobytes: f64 = rest.strip_suffix(" kB")?.trim().parse().ok()?;
        Some(kilobytes / 1_048_576.0)
    }

    /// The processor's name out of `/proc/cpuinfo`.
    pub fn cpu_model(text: &str) -> Option<String> {
        let line = text.lines().find(|line| line.starts_with("model name"))?;
        let name = line.split_once(':')?.1.trim();
        (!name.is_empty()).then(|| name.chars().take(128).collect())
    }

    /// The UEFI `SecureBoot` variable: four bytes of attributes and then one byte, 1 or 0.
    /// Anything else is a variable this build does not understand, and it answers nothing.
    pub fn efi_secure_boot(bytes: &[u8]) -> Option<bool> {
        match bytes {
            [_, _, _, _, 1] => Some(true),
            [_, _, _, _, 0] => Some(false),
            _ => None,
        }
    }

    /// What `tpm_version_major` means. A 2 is a TPM 2.0 the kernel can talk to; a 1 is a TPM 1.2,
    /// which is a TPM that exists and which this grid will not call usable.
    pub fn tpm_version(text: &str) -> Tpm {
        match text.trim() {
            "2" => Tpm::Ready { version: "2.0".into() },
            "1" => Tpm::NotReady,
            _ => Tpm::NotReady,
        }
    }

    /// `0x10de` and the like, out of a sysfs file.
    pub fn pci_id(text: &str) -> Option<u32> {
        u32::from_str_radix(text.trim().strip_prefix("0x")?, 16).ok()
    }

    /// `operstate`: the kernel's own word for whether the link is up. `unknown` is what a virtual
    /// interface reports and it is not "down", so it answers nothing.
    pub fn operstate(text: &str) -> Option<bool> {
        match text.trim() {
            "up" => Some(true),
            "down" | "lowerlayerdown" => Some(false),
            _ => None,
        }
    }

    /// `manage-bde -status C:` on Windows. Only the two exact phrases Microsoft prints are
    /// accepted; a locale this build does not recognise answers nothing rather than guessing.
    pub fn bitlocker(text: &str) -> Option<bool> {
        if text.contains("Protection On") {
            Some(true)
        } else if text.contains("Protection Off") {
            Some(false)
        } else {
            None
        }
    }

    /// `fdesetup status` on macOS, in the same way.
    pub fn filevault(text: &str) -> Option<bool> {
        if text.contains("FileVault is On.") {
            Some(true)
        } else if text.contains("FileVault is Off.") {
            Some(false)
        } else {
            None
        }
    }

    /// `nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv,noheader,nounits`.
    ///
    /// One card a line, three fields. The units matter: `nounits` means the memory is in
    /// mebibytes, and a line with a unit on it is a line this build was not expecting and does not
    /// read, because a value in the wrong unit is worse than no value.
    pub fn nvidia_smi(text: &str, at: i64) -> Vec<Card> {
        let mut cards = Vec::new();
        for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
            let fields: Vec<&str> = line.split(',').map(str::trim).collect();
            let [name, driver, memory] = fields.as_slice() else { continue };
            let Ok(mebibytes) = memory.parse::<f64>() else { continue };
            let mut card = Card::new(Vendor::Nvidia, name);
            card.vram_gb = Some(Measured::new(mebibytes / 1024.0, Source::VendorTool, at));
            card.compute = Some(Measured::new(Compute::Cuda { driver: (*driver).to_owned() }, Source::VendorTool, at));
            cards.push(card);
        }
        cards
    }

    /// `nvidia-smi -L`, which lists cards and, under a card with MIG on, its instances.
    ///
    /// A MIG instance line is the only thing in this file that may set `Partitioned`, and even
    /// then only for a workload pinned to one of the instance identifiers. A card with MIG enabled
    /// whose work is not pinned is a card where two pieces of work land on the same hardware, so
    /// it stays unknown. Nothing here reads a partition's real isolation from the driver, and the
    /// registry row says so.
    pub fn mig_instances(text: &str) -> Vec<String> {
        text.lines()
            .map(str::trim)
            .filter(|line| line.starts_with("MIG "))
            .filter_map(|line| {
                let start = line.find("(UUID: ")? + "(UUID: ".len();
                let end = line[start..].find(')')? + start;
                Some(line[start..end].to_owned())
            })
            .collect()
    }

    /// How a card is isolated, from what `nvidia-smi -L` listed and what this piece of work was
    /// pinned to. Everything that is not "this work runs on exactly one listed MIG instance" is
    /// unknown, which `work::GpuIsolation::shareable` already refuses to share.
    pub fn mig_isolation(listed: &[String], pinned_to: Option<&str>, at: i64) -> Option<Measured<GpuIsolation>> {
        let pinned = pinned_to?;
        listed.iter().any(|uuid| uuid == pinned).then(|| Measured::new(GpuIsolation::Partitioned, Source::VendorTool, at))
    }

    /// `rocm-smi --showproductname --csv`, which prints a header line and then one card a line.
    pub fn rocm_smi(text: &str, version: &str, at: i64) -> Vec<Card> {
        let mut cards = Vec::new();
        for line in text.lines().map(str::trim).skip(1).filter(|line| line.starts_with("card")) {
            let fields: Vec<&str> = line.split(',').map(str::trim).collect();
            let Some(name) = fields.get(1).filter(|name| !name.is_empty()) else { continue };
            let mut card = Card::new(Vendor::Amd, name);
            card.compute = Some(Measured::new(Compute::Rocm { version: version.to_owned() }, Source::VendorTool, at));
            cards.push(card);
        }
        cards
    }
}
