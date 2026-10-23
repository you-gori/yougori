//! What the probe seam must hold true, which is almost entirely about what it refuses to say.
//!
//! Two kinds of test here, and the difference matters. The parser tests are table-driven over
//! bytes written out in this file, so they run the same way on every computer and prove the thing
//! that actually goes wrong: reading a tool's or a kernel's output. The one test that calls
//! `Local::read` asserts only the rules, never a reading, because what this computer has is not
//! something a test can know.
use super::parse;
use super::*;
use crate::core::identity::Attestation;
use crate::core::work::GpuIsolation;

fn at() -> i64 {
    1_700_000_000
}

#[test]
fn a_fact_that_was_not_measured_is_never_reported_as_no() {
    // The rule, stated as a table over every parser, with an input each one does not recognise.
    // Not one of them may answer with a default.
    assert_eq!(parse::efi_secure_boot(&[6, 0, 0, 0, 1]), Some(true));
    assert_eq!(parse::efi_secure_boot(&[6, 0, 0, 0, 0]), Some(false));
    for refused in [&[][..], &[1][..], &[6, 0, 0, 0, 2][..], &[6, 0, 0, 0, 1, 0][..]] {
        assert_eq!(parse::efi_secure_boot(refused), None, "{refused:?} is not a SecureBoot variable this build reads");
    }

    assert_eq!(parse::operstate("up"), Some(true));
    assert_eq!(parse::operstate("down"), Some(false));
    assert_eq!(parse::operstate("unknown"), None, "a virtual interface reports unknown, and unknown is not down");
    assert_eq!(parse::operstate("testing"), None);

    assert_eq!(parse::bitlocker("Conversion Status: Fully Decrypted\n    Protection Status: Protection Off"), Some(false));
    assert_eq!(parse::bitlocker("    Protection Status:    Protection On"), Some(true));
    assert_eq!(parse::bitlocker("Statut de la protection : Protection activee"), None, "a locale this build does not recognise is not an answer");
    assert_eq!(parse::bitlocker(""), None);

    assert_eq!(parse::filevault("FileVault is On."), Some(true));
    assert_eq!(parse::filevault("FileVault is Off."), Some(false));
    assert_eq!(parse::filevault("FileVault is On, Deferred enablement appears to be active"), None, "a sentence that is nearly the one expected is not the one expected");

    assert_eq!(parse::meminfo("MemTotal:       32768000 kB\nMemAvailable:    8192000 kB\n", "MemTotal"), Some(31.25));
    assert_eq!(parse::meminfo("MemTotal:       32768000 kB\n", "MemAvailable"), None, "a line that is not there is nothing");
    assert_eq!(parse::meminfo("MemTotal:       32768000\n", "MemTotal"), None, "a value with no unit on it is a file this build does not understand");
    assert_eq!(parse::meminfo("MemTotalHuge:   1 kB\n", "MemTotal"), None, "a different field whose name starts the same way is a different field");

    assert_eq!(parse::cpu_model("processor\t: 0\nmodel name\t: A Processor 9000\n").as_deref(), Some("A Processor 9000"));
    assert_eq!(parse::cpu_model("processor\t: 0\n"), None);

    assert_eq!(parse::pci_id("0x10de"), Some(0x10de));
    assert_eq!(parse::pci_id("10de"), None, "a sysfs vendor file is written with the prefix, and one without it is not that file");
    assert_eq!(Vendor::of_pci(0x10de), Vendor::Nvidia);
    assert_eq!(Vendor::of_pci(0x1002), Vendor::Amd);
    assert_eq!(Vendor::of_pci(0x8086), Vendor::Intel);
    assert_eq!(Vendor::of_pci(0x1234), Vendor::Unknown, "a vendor this build does not recognise is unknown, not absent");
}

#[test]
fn a_tpm_that_was_not_read_is_not_a_computer_without_one() {
    // The three answers a computer can give, and they are three different things.
    assert_eq!(parse::tpm_version("2"), Tpm::Ready { version: "2.0".into() });
    assert!(parse::tpm_version("2").usable());
    assert_eq!(parse::tpm_version("1"), Tpm::NotReady, "a TPM 1.2 exists and this grid will not call it usable");
    assert!(!parse::tpm_version("").usable());

    // What the realm records: a measured absence is a no, and nothing measured is nothing.
    let measured_absent = Machine { tpm: Some(Measured::new(Tpm::Absent, Source::SystemFile, at())), ..Machine::default() };
    assert_eq!(attestation(&measured_absent, "1.0.21").tpm, Some(false), "a kernel that looked and found none is a measured no");
    let not_read = Machine::default();
    assert_eq!(attestation(&not_read, "1.0.21").tpm, None, "nothing looked, so nothing is known");
    assert_eq!(attestation(&not_read, "1.0.21").describe(), "unverified: this computer cannot report its own state");
    assert_eq!(attestation(&measured_absent, "1.0.21").describe(), "unverified: this computer reports no secure boot or TPM");
}

#[test]
fn a_computer_that_reports_on_itself_never_rises_above_self_reported() {
    let good = |source: Source, measured_at: i64| Attestation {
        secure_boot: Some(true),
        tpm: Some(true),
        os: Some("linux".into()),
        agent_version: Some("1.0.21".into()),
        source: Some(source),
        measured_at: Some(measured_at),
        could_not_measure: Vec::new(),
    };

    // Everything measured, measured now, and measured by the strongest thing this build has.
    assert_eq!(trust(&good(Source::Syscall, at()), at()), Trust::SelfReported);
    // Even a report claiming the one source that would be worth more is clamped, because nothing
    // in this repository produces one and a build that claimed to would be lying about itself.
    assert_eq!(trust(&good(Source::SignedByHardware, at()), at()), CEILING);
    assert_eq!(CEILING, Trust::SelfReported, "nothing here mints a key in a TPM, asks for a quote or checks a manufacturer chain");

    // Stale in either direction is not about today: more than a day old, or more than a day
    // ahead, which is a clock that does not agree with this realm's.
    assert_eq!(trust(&good(Source::Syscall, at() - STALE_AFTER - 1), at()), Trust::Unverified);
    assert_eq!(trust(&good(Source::Syscall, at() + STALE_AFTER + 1), at()), Trust::Unverified, "a measurement from the future is a clock that does not agree");
    // And what the window actually allows, said rather than assumed: a clock half a day ahead is
    // still counted, which is the tolerance the day in either direction buys.
    assert_eq!(trust(&good(Source::Syscall, at() + STALE_AFTER / 2), at()), Trust::SelfReported, "a clock half a day ahead is inside the window on purpose");
    assert_eq!(trust(&good(Source::Syscall, at() - STALE_AFTER / 2), at()), Trust::SelfReported);

    // A report from a build that did not record how or when is not evidence.
    let mut sourceless = good(Source::Syscall, at());
    sourceless.source = None;
    assert_eq!(trust(&sourceless, at()), Trust::Unverified);
    let mut timeless = good(Source::Syscall, at());
    timeless.measured_at = None;
    assert_eq!(trust(&timeless, at()), Trust::Unverified);

    // And a computer that said no about either half shows nothing.
    for (secure_boot, tpm) in [(Some(false), Some(true)), (Some(true), Some(false)), (None, Some(true)), (Some(true), None)] {
        let mut partial = good(Source::Syscall, at());
        partial.secure_boot = secure_boot;
        partial.tpm = tpm;
        assert_eq!(trust(&partial, at()), Trust::Unverified, "{secure_boot:?} {tpm:?}");
    }

    // A realm demanding more than this version can produce takes no computer at all, and the
    // sentence says that rather than leaving somebody to work out why nothing is running.
    assert!(admits(Trust::Unverified, Trust::Unverified) && admits(Trust::SelfReported, Trust::SelfReported));
    assert!(!admits(Trust::DeviceSigned, Trust::SelfReported) && !admits(Trust::HardwareAttested, Trust::SelfReported));
    assert_eq!(why_refused(Trust::Unverified, Trust::Unverified), None);
    let refused = why_refused(Trust::HardwareAttested, Trust::SelfReported).unwrap();
    assert!(refused.contains("Nothing in this version can show hardwareAttested"), "{refused}");
    let ordinary = why_refused(Trust::SelfReported, Trust::Unverified).unwrap();
    assert!(ordinary.contains("has shown nothing about its own state") && !ordinary.contains("Nothing in this version"), "{ordinary}");
    // The order of the ladder is the order of evidence, and nothing may reorder it quietly.
    assert!(Trust::Unverified < Trust::SelfReported && Trust::SelfReported < Trust::DeviceSigned && Trust::DeviceSigned < Trust::HardwareAttested);
    for trust in [Trust::Unverified, Trust::SelfReported, Trust::DeviceSigned, Trust::HardwareAttested] {
        assert_eq!(Trust::parse(trust.word()), Some(trust));
    }
    assert_eq!(Trust::parse("verified"), None, "there is no such thing as verified here");
}

#[test]
fn a_card_that_is_merely_visible_is_never_shared() {
    // nvidia-smi, with the fields and the units this build asks for.
    let listing = "NVIDIA RTX A6000, 550.90.07, 49140\nNVIDIA RTX A6000, 550.90.07, 49140\n";
    let cards = parse::nvidia_smi(listing, at());
    assert_eq!(cards.len(), 2);
    assert_eq!(cards[0].vendor, Vendor::Nvidia);
    assert_eq!(cards[0].compute.as_ref().unwrap().value, Compute::Cuda { driver: "550.90.07".into() });
    assert_eq!(cards[0].compute.as_ref().unwrap().source, Source::VendorTool, "a tool's printed output is not a system call and the type says so");
    assert!((cards[0].vram_gb.unwrap().value - 47.98).abs() < 0.01);
    assert!(cards[0].isolation.is_none(), "nothing nvidia-smi prints about memory says how a card is isolated");

    // A line with a unit on it is a line this build was not expecting, and a value in the wrong
    // unit is worse than no value.
    assert!(parse::nvidia_smi("NVIDIA RTX A6000, 550.90.07, 49140 MiB\n", at()).is_empty());
    assert!(parse::nvidia_smi("", at()).is_empty());

    // MIG: the only thing in this file that may say Partitioned, and only for a workload pinned
    // to one listed instance.
    let listed = "GPU 0: NVIDIA A100-SXM4-40GB (UUID: GPU-aaa)\n  MIG 1g.5gb Device 0: (UUID: MIG-bbb)\n  MIG 1g.5gb Device 1: (UUID: MIG-ccc)\n";
    let instances = parse::mig_instances(listed);
    assert_eq!(instances, vec!["MIG-bbb".to_owned(), "MIG-ccc".to_owned()]);
    assert_eq!(parse::mig_instances("GPU 0: NVIDIA A100-SXM4-40GB (UUID: GPU-aaa)\n"), Vec::<String>::new(), "a card with no MIG lines partitions nothing");
    assert_eq!(parse::mig_isolation(&instances, Some("MIG-bbb"), at()).unwrap().value, GpuIsolation::Partitioned);
    assert!(parse::mig_isolation(&instances, None, at()).is_none(), "a card with MIG on, whose work is not pinned, is a card two pieces of work land on");
    assert!(parse::mig_isolation(&instances, Some("MIG-not-listed"), at()).is_none());

    // And the whole-computer answer, which is what the scheduler sees.
    let mut machine = Machine::default();
    machine.cards = vec![Card::new(Vendor::Nvidia, "card0")];
    assert_eq!(isolation(&machine), GpuIsolation::Unknown);
    assert!(!isolation(&machine).shareable(), "which is what work::GpuIsolation already refuses to share");
    machine.cards[0].isolation = parse::mig_isolation(&instances, Some("MIG-bbb"), at());
    assert_eq!(isolation(&machine), GpuIsolation::Partitioned);
    // One card nobody measured makes the whole computer unknown, because work lands on a computer.
    machine.cards.push(Card::new(Vendor::Nvidia, "card1"));
    assert_eq!(isolation(&machine), GpuIsolation::Unknown);
    assert_eq!(isolation(&Machine::default()), GpuIsolation::Unknown, "a computer with no card at all shares nothing");
}

#[test]
fn amd_and_the_other_stacks_are_read_the_same_way_or_not_at_all() {
    let rocm = "device,Card series,Card model\ncard0,Radeon Pro W7900,0x7448\ncard1,Radeon Pro W7900,0x7448\n";
    let cards = parse::rocm_smi(rocm, "6.1.2", at());
    assert_eq!(cards.len(), 2);
    assert_eq!(cards[0].vendor, Vendor::Amd);
    assert_eq!(cards[0].compute.as_ref().unwrap().value, Compute::Rocm { version: "6.1.2".into() });
    assert!(cards[0].vram_gb.is_none(), "this listing does not print memory, so none is recorded");
    assert!(parse::rocm_smi("device,Card series\n", "6.1.2", at()).is_empty(), "a header with no cards under it is no cards");

    // The names, which are what a person reads, and which the registry rows have to match.
    assert_eq!(Compute::Cuda { driver: "x".into() }.name(), "NVIDIA CUDA");
    assert_eq!(Compute::Rocm { version: "x".into() }.name(), "AMD ROCm");
    assert_eq!(Compute::LevelZero.name(), "Intel Level Zero");
    assert_eq!(Compute::Metal.name(), "Apple Metal");
    assert_eq!(Vendor::Apple.name(), "Apple");
}

#[test]
fn what_a_computer_offers_is_built_only_from_what_it_measured() {
    // Nothing measured: a computer that cannot say how big it is offers nothing, and a realm that
    // sees nothing places nothing, which is the right answer rather than a bug.
    let nothing = resources(&Machine::default());
    assert_eq!((nothing.cpu, nothing.memory_gb, nothing.disk_gb, nothing.gpu, nothing.vram_gb), (0.0, 0.0, 0.0, false, 0.0));

    let mut machine = Machine {
        cpus: Some(Measured::new(16, Source::Syscall, at())),
        memory_gb: Some(Measured::new(64.0, Source::Syscall, at())),
        disk_gb: Some(Measured::new(2000.0, Source::Syscall, at())),
        free_disk_gb: Some(Measured::new(430.5, Source::Syscall, at())),
        ..Machine::default()
    };
    let offered = resources(&machine);
    assert_eq!((offered.cpu, offered.memory_gb, offered.disk_gb), (16.0, 64.0, 430.5), "what a realm can use is what is free, not what the disk holds");
    assert!(!offered.gpu && offered.vram_gb == 0.0);

    // A card that is there is a card, whether or not its memory could be read.
    machine.cards = vec![Card::new(Vendor::Intel, "card0")];
    assert!(resources(&machine).gpu && resources(&machine).vram_gb == 0.0, "a card with no measured memory offers no memory and is still a card");
    machine.cards.push({
        let mut card = Card::new(Vendor::Nvidia, "card1");
        card.vram_gb = Some(Measured::new(48.0, Source::VendorTool, at()));
        card
    });
    assert_eq!(resources(&machine).vram_gb, 48.0, "the largest card is what one piece of work could have");
}

#[test]
fn a_host_that_knows_more_fills_the_gaps_in_and_cannot_overwrite_a_reading() {
    // The sentences this module actually writes, rather than abridged ones written here. That is
    // the whole point of this test: the real sentence about a graphics card explains that the
    // application reports vendor, device and memory, so a gap matched on the words of its sentence
    // disappeared as soon as anything measured memory, and a card nobody enumerated stopped being
    // reported at all.
    let mut mine = Machine { cpus: Some(Measured::new(8, Source::Syscall, at())), ..Machine::default() };
    super::gaps(&mut mine);
    assert!(mine.could_not_measure.iter().any(|said| said.contains("graphics")));

    let theirs = Machine {
        // A worse reading of something already measured, which must not win.
        cpus: Some(Measured::new(2, Source::Helper, at())),
        memory_gb: Some(Measured::new(32.0, Source::Helper, at())),
        free_disk_gb: Some(Measured::new(120.0, Source::Helper, at())),
        ..Machine::default()
    };
    let together = mine.filled_in_with(theirs);
    assert_eq!(together.cpus.unwrap().value, 8, "a probe adding what it knows cannot replace a reading with a worse one");
    assert_eq!(together.free_disk_gb.unwrap().value, 120.0);
    assert_eq!(together.memory_gb.unwrap().value, 32.0);
    // A gap whose own fact was filled is no longer a gap.
    assert!(!together.could_not_measure.iter().any(|said| said.contains("Free disk")), "{:?}", together.could_not_measure);
    assert!(!together.could_not_measure.iter().any(|said| said.contains("How much memory")), "{:?}", together.could_not_measure);
    // And one whose fact was not filled is still said out loud, however many other facts its
    // sentence happens to name.
    assert!(together.cards.is_empty());
    assert!(together.could_not_measure.iter().any(|said| said.contains("No graphics card")), "nobody enumerated a card, and the list still says so: {:?}", together.could_not_measure);
    assert!(together.could_not_measure.iter().any(|said| said.contains("TPM")), "nobody read the TPM, and the list still says so");
    assert!(together.could_not_measure.iter().any(|said| said.contains("encrypted at rest")), "nobody read disk encryption either");

    // The other half of the same rule: a computer that does supply the card and the encryption
    // closes exactly those two and leaves the rest.
    let more = Machine {
        cards: vec![Card::new(Vendor::Nvidia, "GPU 0")],
        disk_encryption: Some(Measured::new(true, Source::Helper, at())),
        ..Machine::default()
    };
    let fuller = together.filled_in_with(more);
    assert_eq!(fuller.cards.len(), 1);
    assert!(!fuller.could_not_measure.iter().any(|said| said.contains("No graphics card")), "{:?}", fuller.could_not_measure);
    assert!(!fuller.could_not_measure.iter().any(|said| said.contains("encrypted at rest")), "{:?}", fuller.could_not_measure);
    assert!(fuller.could_not_measure.iter().any(|said| said.contains("TPM")));

    // A sentence that came from another computer carries no fact of its own, because what travels
    // between them is the words. It is kept rather than guessed at, which over-reports a gap
    // rather than hiding one.
    let mut word_of_mouth = Machine::default();
    word_of_mouth.gap("No graphics card was enumerated here. The application that holds this grid runs a probe program that reports vendor, device and memory, and supplies it through the probe seam.");
    let carried: Machine = serde_json::from_str(&serde_json::to_string(&word_of_mouth).unwrap()).unwrap();
    assert!(carried.could_not_measure[0].about.is_none(), "a sentence read back from a realm says nothing about which fact it is for");
    let with_cards = Machine { cards: vec![Card::new(Vendor::Nvidia, "GPU 0")], ..Machine::default() }.filled_in_with(carried);
    assert_eq!(with_cards.could_not_measure.len(), 1, "an untagged gap is kept, which over-reports rather than hides");

    // The same sentence twice is one line, because a gap reported eight times is eight lines
    // nobody reads.
    let mut noisy = Machine::default();
    noisy.gap("The same thing.");
    noisy.gap("The same thing.");
    assert_eq!(noisy.could_not_measure.len(), 1);
}

#[test]
fn every_fact_carries_how_it_was_learned_and_when() {
    let machine = Machine {
        os: Some(Measured::new("linux".into(), Source::Syscall, at())),
        cpus: Some(Measured::new(16, Source::Syscall, at())),
        secure_boot: Some(Measured::new(true, Source::SystemFile, at())),
        tpm: Some(Measured::new(Tpm::Ready { version: "2.0".into() }, Source::SystemFile, at())),
        disk_encryption: Some(Measured::new(true, Source::Helper, at())),
        encryption_named: Some("LUKS".into()),
        cards: vec![{
            let mut card = Card::new(Vendor::Nvidia, "card0");
            card.vram_gb = Some(Measured::new(48.0, Source::VendorTool, at()));
            card
        }],
        interfaces: vec![Interface { name: "eth0".into(), up: Some(Measured::new(true, Source::SystemFile, at())), speed_mbps: Some(Measured::new(10_000, Source::SystemFile, at())), physical: Some(Measured::new(true, Source::SystemFile, at())) }],
        ..Machine::default()
    };
    assert!(machine.every_fact_says_how_it_was_learned(), "a field added as a bare value rather than a Measured is a silent loss of the rule this file is about");

    // What the realm records out of it, and what each source is worth.
    let recorded = attestation(&machine, "1.0.21");
    assert_eq!((recorded.secure_boot, recorded.tpm), (Some(true), Some(true)));
    assert_eq!(recorded.source, Some(Source::SystemFile), "the weaker of the two answers is what the pair is worth");
    assert_eq!(recorded.measured_at, Some(at()));
    assert_eq!(recorded.trust(at()), Trust::SelfReported);
    assert!(!Source::Syscall.is_more_than_self_report() && !Source::VendorTool.is_more_than_self_report());
    assert!(Source::SignedByHardware.is_more_than_self_report(), "the one source that would be worth more, and nothing here produces one");
    // How good the evidence is, which is deliberately not the order the variants are declared in:
    // text somebody else's tool printed is the weakest thing here and a system call is not.
    assert!(Source::VendorTool.strength() < Source::Helper.strength());
    assert!(Source::Helper.strength() < Source::SystemFile.strength());
    assert!(Source::SystemFile.strength() < Source::Syscall.strength());
    assert!(Source::Syscall.strength() < Source::SignedByHardware.strength());
    // A pair where one half came from a tool is worth what the tool is worth, not what the other
    // half is worth.
    let mixed = Machine {
        secure_boot: Some(Measured::new(true, Source::Syscall, at())),
        tpm: Some(Measured::new(Tpm::Ready { version: "2.0".into() }, Source::VendorTool, at())),
        ..Machine::default()
    };
    assert_eq!(attestation(&mixed, "1.0.21").source, Some(Source::VendorTool));
    for source in [Source::Syscall, Source::SystemFile, Source::Helper, Source::VendorTool, Source::SignedByHardware] {
        assert!(!source.describe().is_empty());
    }

    // An attestation written by a build before any of this existed still loads, and shows nothing.
    let old: Attestation = serde_json::from_str(r#"{"secureBoot":true,"tpm":true}"#).unwrap();
    assert!(old.verified(), "what verified meant, it still means");
    assert_eq!(old.trust(at()), Trust::Unverified, "and what it was worth is now said separately, which is less than it looked");
}

#[test]
fn reading_this_computer_says_only_what_it_measured() {
    // This runs on whatever computer the tests are on, so it asserts the rules and not a reading.
    // Nothing here runs a vendor tool, opens a prompt or reaches anything.
    let machine = Local.read(at());
    assert!(machine.every_fact_says_how_it_was_learned());
    assert_eq!(machine.os.as_ref().unwrap().value, std::env::consts::OS);
    assert!(machine.on_battery.is_some(), "power is the one thing this grid has always measured, on every platform it builds for");
    for sentence in &machine.could_not_measure {
        assert!(sentence.ends_with('.') && sentence.len() > 30, "a gap is a sentence somebody reads: {sentence}");
        assert!(!sentence.contains("no ") || sentence.contains("unknown rather than"), "a gap must never read as a no: {sentence}");
    }
    // Whatever this computer is, nothing it said about itself is worth more than its own word.
    assert!(attestation(&machine, "1.0.21").trust(at()) <= CEILING);
    assert_eq!(isolation(&machine), GpuIsolation::Unknown, "no driver here reports a partition's real isolation, on any computer this builds for");
    assert_eq!(Local.name(), "this grid, reading what it can reach");
}
