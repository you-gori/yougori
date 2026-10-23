//! What this application already measures about this computer, handed to a realm through the one
//! seam Grid Core has for it.
//!
//! The reason this file exists rather than Grid Core reading the hardware itself is the dependency
//! direction. This crate depends on `yougori-grid` and not the other way round, so the core cannot
//! call the GPU probe program that ships beside this application, and it cannot call the crate
//! this application uses to enumerate disks. If it read the same hardware a second way, there
//! would be two answers to every question and nothing to say which one a realm should believe.
//!
//! So `core::hardware::Probe` is the seam, and this is the host filling it in. Nothing here
//! measures anything new: every fact below is something this application already had, turned into
//! the shape a realm records, with how it was learned attached. A fact this application does not
//! have stays unmeasured, and `Machine::filled_in_with` keeps whatever the core read for itself in
//! preference to anything here, so adding this can only ever close a gap and never overwrite a
//! reading.
//!
//! Nothing in this application drives a realm yet. The four products keep their own hubs while
//! Grid Core is built, so this has no caller outside its own tests, and that is why the items
//! below say so rather than being quietly warned about: it is waiting for the bridge, not unused
//! by accident. What it does hold to now is the shape and the rule, both of which are exercised.
#![allow(dead_code)]

use crate::models::HostMetrics;
use crate::runtime::gpu::GpuAdapter;
use yougori_grid::core::hardware::{Card, Fact, Machine, Measured, Probe, Source, Vendor};

/// What this application knows about this computer.
///
/// Built from the metrics the application samples anyway and from the graphics adapters its own
/// probe program enumerated. Both are optional: a realm that asks before either has been read gets
/// a machine that says it measured nothing, which is the truth at that moment.
pub struct HostProbe {
    metrics: Option<HostMetrics>,
    adapters: Vec<GpuAdapter>,
}

impl HostProbe {
    pub fn new(metrics: Option<HostMetrics>, adapters: Vec<GpuAdapter>) -> HostProbe {
        HostProbe { metrics, adapters }
    }

    /// One graphics adapter as a realm records it.
    ///
    /// The vendor comes from the PCI identifier the probe read, never from the card's printed
    /// name: a name is a marketing string and matching on one is how an Intel card ends up filed
    /// as an AMD one. Memory of zero is the probe saying it could not read it, so it is recorded
    /// as unmeasured rather than as a card with no memory.
    fn card(adapter: &GpuAdapter, at: i64) -> Card {
        let mut card = Card::new(Vendor::of_pci(adapter.vendor_id), &adapter.name);
        if adapter.memory_bytes > 0 {
            card.vram_gb = Some(Measured::new(adapter.memory_bytes as f64 / 1_073_741_824.0, Source::Helper, at));
        }
        // How the card is isolated is deliberately not set. Nothing in this application reads a
        // partition's real isolation from a driver, so it stays unmeasured, which the scheduler
        // already refuses to share.
        card
    }

    /// When this application last sampled these metrics, or nothing when it did not record a time
    /// this can read back.
    ///
    /// The reason this is not simply the time of asking is that these readings are last sampled
    /// whenever the screen last refreshed. Stamping them with the moment a realm asked would claim
    /// a freshness they do not have, against a type whose whole point is that a fact says when it
    /// was learned, and `core::hardware::trust` ages a measurement by exactly that stamp.
    fn sampled_at(metrics: &HostMetrics) -> Option<i64> {
        chrono::DateTime::parse_from_rfc3339(&metrics.updated_at).ok().map(|when| when.timestamp())
    }
}

impl Probe for HostProbe {
    fn name(&self) -> &'static str {
        "this application, from what it already measures"
    }

    fn read(&self, now: i64) -> Machine {
        let mut machine = Machine { cards: self.adapters.iter().map(|adapter| HostProbe::card(adapter, now)).collect(), ..Machine::default() };
        if machine.cards.is_empty() {
            machine.gap_about(Fact::Graphics, "No graphics card was enumerated. On Windows this application runs a probe program that lists them; on every other platform it does not, so whether there is a card is unknown rather than no.");
        }
        let Some(metrics) = &self.metrics else {
            machine.gap("This application has not sampled this computer yet, so nothing below was measured. It is unknown rather than absent.");
            return machine;
        };
        // The time the readings below were taken, not the time a realm asked for them. Without it
        // an hour-old sample would be recorded as measured this second.
        let at = match HostProbe::sampled_at(metrics) {
            Some(at) => at,
            None => {
                machine.gap("This application did not record when it last looked at this computer, so the readings beside it carry the time of asking and may be older than that.");
                now
            }
        };
        if !metrics.os.is_empty() {
            machine.os = Some(Measured::new(metrics.os.clone(), Source::Syscall, at));
        }
        if !metrics.cpu_model.is_empty() {
            machine.cpu_model = Some(Measured::new(metrics.cpu_model.clone(), Source::Syscall, at));
        }
        if metrics.total_cpu > 0 {
            machine.cpus = Some(Measured::new(metrics.total_cpu as u32, Source::Syscall, at));
        }
        if metrics.total_memory_gb > 0.0 {
            machine.memory_gb = Some(Measured::new(metrics.total_memory_gb, Source::Syscall, at));
            machine.free_memory_gb = Some(Measured::new((metrics.total_memory_gb - metrics.used_memory_gb).max(0.0), Source::Syscall, at));
        }
        // Storage of zero is what this application reports when it could not find the volume its
        // runtime data lives on, so it is recorded as unmeasured rather than as a full disk.
        if metrics.total_storage_gb > 0.0 {
            machine.disk_gb = Some(Measured::new(metrics.total_storage_gb, Source::Syscall, at));
            machine.free_disk_gb = Some(Measured::new((metrics.total_storage_gb - metrics.used_storage_gb).max(0.0), Source::Syscall, at));
        } else {
            machine.gap_about(Fact::FreeDisk, "The volume this application keeps its runtime data on could not be read, so how much free disk this computer has is unknown rather than none.");
        }
        // Three sentences rather than one. They are three separate facts, and a computer that
        // measures any one of them elsewhere closes that gap alone; one sentence naming all three
        // would be dropped whole the moment any of them was filled in.
        machine.gap_about(Fact::Tpm, "This application does not read this computer's TPM, so whether there is one is unknown rather than no.");
        machine.gap_about(Fact::SecureBoot, "This application does not read whether this computer booted with Secure Boot, so it is unknown rather than off.");
        machine.gap_about(Fact::DiskEncryption, "This application does not read whether this computer's disk is encrypted at rest, so it is unknown rather than off.");
        machine
    }
}

/// What a realm should be told about this computer: what the core could read for itself, with what
/// this application already knew filled in around it.
///
/// The order is the point. The core's own readings win, because they are the ones made at the
/// moment of asking; this application's are last sampled whenever the screen last refreshed, and
/// each of them carries the time of that sample rather than the time a realm asked. A gap either
/// of them had and the other filled stops being a gap, and a gap whose own fact nobody filled is
/// still reported.
pub fn machine(metrics: Option<HostMetrics>, adapters: Vec<GpuAdapter>, now: i64) -> Machine {
    use yougori_grid::core::hardware::Local;
    Local.read(now).filled_in_with(HostProbe::new(metrics, adapters).read(now))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::HostPressure;

    fn metrics() -> HostMetrics {
        HostMetrics {
            hostname: "hub-01".into(),
            os: "Windows 11".into(),
            cpu_model: "A Processor 9000".into(),
            total_cpu: 16,
            used_cpu_percent: 12.0,
            gpu_usage_percent: Some(3.0),
            total_memory_gb: 64.0,
            used_memory_gb: 20.0,
            total_storage_gb: 2000.0,
            used_storage_gb: 1570.0,
            storage_drive: Some("C:\\".into()),
            storage_drives: Vec::new(),
            storage_saved_gb: 0.0,
            pressure: HostPressure::Low,
            cpu_history: Vec::new(),
            gpu_history: Vec::new(),
            memory_history: Vec::new(),
            updated_at: String::new(),
        }
    }

    fn adapter(vendor_id: u32, memory_bytes: u64) -> GpuAdapter {
        GpuAdapter { id: "1".into(), name: "A Card".into(), luid: "0".into(), vendor_id, device_id: 1, sub_sys_id: 0, revision: 0, memory_bytes }
    }

    #[test]
    fn what_this_application_already_measured_is_handed_over_and_nothing_else_is() {
        let now = 1_700_000_000;
        let machine = HostProbe::new(Some(metrics()), vec![adapter(0x10de, 50 * 1_073_741_824)]).read(now);
        assert_eq!(machine.cpus.unwrap().value, 16);
        assert_eq!(machine.memory_gb.unwrap().value, 64.0);
        assert_eq!(machine.free_memory_gb.unwrap().value, 44.0);
        assert_eq!(machine.free_disk_gb.unwrap().value, 430.0, "what a realm can use is what is free, not what the disk holds");
        assert_eq!(machine.cards.len(), 1);
        assert_eq!(machine.cards[0].vendor, Vendor::Nvidia, "the vendor comes from the PCI identifier and never from the card's printed name");
        assert_eq!(machine.cards[0].vram_gb.unwrap().value, 50.0);
        assert!(machine.cards[0].isolation.is_none(), "nothing here reads a partition's real isolation, so no card may be shared");
        assert!(machine.every_fact_says_how_it_was_learned());

        // The three this application does not read stay unknown, in three sentences somebody
        // reads. Three and not one, because a computer that measures any of them elsewhere closes
        // that gap alone and leaves the other two standing.
        assert!(machine.tpm.is_none() && machine.secure_boot.is_none() && machine.disk_encryption.is_none());
        for named in ["TPM", "Secure Boot", "encrypted at rest"] {
            assert!(machine.could_not_measure.iter().any(|said| said.contains(named)), "{named} is not in {:?}", machine.could_not_measure);
        }
    }

    #[test]
    fn a_reading_carries_the_time_this_application_took_it_and_not_the_time_a_realm_asked() {
        let now = 1_700_000_000;
        // An hour before the realm asked. These metrics are sampled whenever the screen last
        // refreshed, so stamping them with the moment of asking would claim a freshness they do
        // not have, and `core::hardware::trust` ages a measurement by exactly that stamp.
        let sampled = 1_699_996_400;
        let mut older = metrics();
        older.updated_at = "2023-11-14T21:13:20+00:00".into();
        let machine = HostProbe::new(Some(older), Vec::new()).read(now);
        assert_eq!(machine.cpus.unwrap().at, sampled, "the processor count is stamped when it was sampled");
        assert_eq!(machine.memory_gb.unwrap().at, sampled);
        assert_eq!(machine.free_disk_gb.unwrap().at, sampled);
        assert!(!machine.could_not_measure.iter().any(|said| said.contains("time of asking")));

        // And when this application recorded no time at all, the readings carry the time of asking
        // and the list says so, rather than a stale reading quietly passing as a fresh one.
        let machine = HostProbe::new(Some(metrics()), Vec::new()).read(now);
        assert_eq!(machine.cpus.unwrap().at, now);
        assert!(machine.could_not_measure.iter().any(|said| said.contains("time of asking")), "{:?}", machine.could_not_measure);
    }

    #[test]
    fn a_reading_that_is_missing_is_never_reported_as_a_zero() {
        let now = 1_700_000_000;
        // Nothing sampled yet: everything is unknown, and the list says so rather than a realm
        // seeing a computer with no processors and no memory.
        let nothing = HostProbe::new(None, Vec::new()).read(now);
        assert!(nothing.cpus.is_none() && nothing.memory_gb.is_none() && nothing.cards.is_empty());
        assert!(nothing.could_not_measure.iter().any(|said| said.contains("has not sampled this computer yet")));

        // A volume this application could not find is unknown free disk, not a disk that is full.
        let mut blind = metrics();
        blind.total_storage_gb = 0.0;
        let machine = HostProbe::new(Some(blind), Vec::new()).read(now);
        assert!(machine.free_disk_gb.is_none() && machine.disk_gb.is_none());
        assert!(machine.could_not_measure.iter().any(|said| said.contains("unknown rather than none")));

        // A card whose memory the probe could not read is still a card, with unmeasured memory.
        let machine = HostProbe::new(Some(metrics()), vec![adapter(0x8086, 0)]).read(now);
        assert_eq!(machine.cards[0].vendor, Vendor::Intel);
        assert!(machine.cards[0].vram_gb.is_none());
    }

    #[test]
    fn the_core_keeps_its_own_readings_and_this_fills_the_gaps_around_them() {
        let now = 1_700_000_000;
        let together = machine(Some(metrics()), vec![adapter(0x10de, 1_073_741_824)], now);
        // Free disk is the one this application has and the core does not, so it is there.
        assert_eq!(together.free_disk_gb.unwrap().value, 430.0);
        assert_eq!(together.cards.len(), 1);
        // What a realm would record out of it never claims more than that the computer said so.
        let attestation = yougori_grid::core::hardware::attestation(&together, env!("CARGO_PKG_VERSION"));
        assert!(attestation.trust(now) <= yougori_grid::core::hardware::CEILING);
        assert!(!attestation.verified(), "nothing here reads a TPM or Secure Boot, so nothing is verified");
        assert!(together.every_fact_says_how_it_was_learned());
    }
}
