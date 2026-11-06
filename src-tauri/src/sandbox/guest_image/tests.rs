//! Tests of the build record, the kernel facts, the feature manifest, the signature and
//! the selection.

use std::sync::Arc;

use chrono::{DateTime, Utc};

use super::fixtures::*;
use super::*;
use crate::foundation::catalog::{
    ArtifactClass, ContentDescriptor, ObjectBytes, Scope, VerifierRejection,
};
use crate::foundation::ids::{digest, ContentKey};
use crate::foundation::signing::{
    ComponentVerification, SharedTrustRoots, SignedArtifactVerifier, StatementBinding,
    StructureValidator, TrustCalendar,
};
use crate::sandbox::link::{Hello, PROTOCOL_VERSION};
use crate::sandbox::trust::{
    Architecture, BootMethod, ComponentKind, ComponentVersion, DeviceModel, PinRefusal, UnixSeconds,
};
use crate::sandbox_contract::confinement::{
    KernelBuildRecord, KernelOption, KernelSetting, OptionState, WorkloadProfile,
};

fn record() -> BuildRecord {
    BuildRecord::new(record_document()).unwrap()
}

fn record_with(edit: impl FnOnce(&mut RecordDocument)) -> Result<BuildRecord, RecordError> {
    let mut document = record_document();
    edit(&mut document);
    BuildRecord::new(document)
}

/// The fixture's tool or package named `name`.
fn tool_named<'a>(document: &'a mut RecordDocument, name: &str) -> &'a mut ToolInput {
    document
        .inputs
        .toolchain
        .iter_mut()
        .find(|tool| tool.name.as_str() == name)
        .unwrap()
}

fn package_named<'a>(document: &'a mut RecordDocument, name: &str) -> &'a mut PackageInput {
    document
        .inputs
        .packages
        .iter_mut()
        .find(|package| package.name.as_str() == name)
        .unwrap()
}

fn manifest_with(
    edit: impl FnOnce(&mut ManifestDocument),
) -> Result<FeatureManifest, ManifestError> {
    let mut document = manifest_document(&record());
    edit(&mut document);
    FeatureManifest::new(document)
}

/// The document `bytes` with `edit` applied, written canonically.
fn edited_json(bytes: &[u8], edit: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
    let mut value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    edit(&mut value);
    super::canonical::encode(&value).unwrap()
}

#[test]
fn input_names_and_command_text_follow_their_rules() {
    for good in [
        "libstdc++",
        "github.com/hanwen/go-fuse/v2",
        "1:2.3~rc1-r0",
        "mkfs.ext4",
        "a@b",
    ] {
        assert!(InputName::new(good).is_ok(), "{good}");
    }
    for (bad, error) in [
        ("", TextError::Empty),
        ("/usr/bin/go", TextError::InvalidStart),
        (".hidden", TextError::InvalidStart),
        ("a//b", TextError::InvalidComponent),
        ("a/../b", TextError::InvalidComponent),
        ("a/./b", TextError::InvalidComponent),
        ("a/", TextError::InvalidComponent),
        ("a b", TextError::InvalidCharacter { character: ' ' }),
        ("a\\b", TextError::InvalidCharacter { character: '\\' }),
    ] {
        assert_eq!(InputName::new(bad), Err(error), "{bad:?}");
    }
    assert_eq!(
        InputVersion::new("1".repeat(MAX_NAME_BYTES + 1)),
        Err(TextError::TooLong {
            max_bytes: MAX_NAME_BYTES
        })
    );
    assert!(ImageName::new("yougori/guest").is_err());
    assert!(BuildArgument::new("").is_ok());
    assert!(BuildArgument::new("-ldflags=-s -w -buildid=").is_ok());
    assert_eq!(BuildArgument::new("a\nb"), Err(TextError::ControlCharacter));
    assert_eq!(
        BuildArgument::new("x".repeat(MAX_ARGUMENT_BYTES + 1)),
        Err(TextError::TooLong {
            max_bytes: MAX_ARGUMENT_BYTES
        })
    );
    assert!(EnvironmentName::new("SOURCE_DATE_EPOCH").is_ok());
    assert!(EnvironmentName::new("_X1").is_ok());
    assert_eq!(
        EnvironmentName::new("path"),
        Err(TextError::InvalidCharacter { character: 'p' })
    );
    assert_eq!(EnvironmentName::new("1A"), Err(TextError::InvalidStart));
    assert_eq!(
        EnvironmentValue::new("a\0"),
        Err(TextError::ControlCharacter)
    );
    assert!(serde_json::from_str::<InputName>("\"a//b\"").is_err());
    assert_eq!(
        serde_json::from_str::<InputName>("\"go\"").unwrap(),
        InputName::new("go").unwrap()
    );
    assert_eq!(
        format!("{:?}", InputName::new("go").unwrap()),
        "InputName(\"go\")"
    );
    for error in [
        TextError::Empty,
        TextError::InvalidStart,
        TextError::InvalidComponent,
        TextError::ControlCharacter,
    ] {
        assert!(!error.to_string().is_empty());
    }
}

#[test]
fn a_record_is_sorted_canonical_and_read_back_exactly() {
    let record = record();
    let document = record.document();
    let names: Vec<&str> = document
        .inputs
        .toolchain
        .iter()
        .map(|tool| tool.name.as_str())
        .collect();
    assert_eq!(
        names,
        ["apk", "go", "mkfs.ext4", "mkinitfs", "musl-cc", "qemu-img"]
    );
    assert_eq!(
        document.inputs.sources[0].name.as_str(),
        "alpine-minirootfs-3.24.1-x86_64.tar.gz"
    );
    assert_eq!(
        document.inputs.packages[0].name.as_str(),
        "busybox-mdev-openrc"
    );
    // The steps keep their order.
    assert_eq!(document.steps[0].name.as_str(), "build-agent");

    let bytes = record.canonical_bytes();
    let text = std::str::from_utf8(bytes).unwrap();
    assert!(text.starts_with("{\"architecture\":\"x86_64\",\"artifacts\":{\"initrd\":"));
    assert!(!text.contains('\n') && !text.contains("\": "));
    assert_eq!(record.content_key(), ContentKey::of(bytes));
    let again = BuildRecord::from_canonical(bytes).unwrap();
    assert_eq!(again, record);
    assert_eq!(
        serde_json::to_vec(&record).unwrap(),
        serde_json::to_vec(record.document()).unwrap()
    );

    // Pretty-printed, reordered, unknown field, another format, too large.
    let pretty = serde_json::to_vec_pretty(record.document()).unwrap();
    assert_eq!(
        BuildRecord::from_canonical(&pretty),
        Err(RecordError::Document {
            error: DocumentError::NotCanonical
        })
    );
    let unsorted = edited_json(bytes, |value| {
        value["inputs"]["toolchain"]
            .as_array_mut()
            .unwrap()
            .reverse();
    });
    assert_eq!(
        BuildRecord::from_canonical(&unsorted),
        Err(RecordError::Document {
            error: DocumentError::NotCanonical
        })
    );
    let unknown = edited_json(bytes, |value| {
        value["reproducible"] = serde_json::json!(true)
    });
    assert!(matches!(
        BuildRecord::from_canonical(&unknown),
        Err(RecordError::Document {
            error: DocumentError::Malformed { .. }
        })
    ));
    let future = edited_json(bytes, |value| {
        value["format"] = serde_json::json!(2);
        value["layout"] = serde_json::json!("new");
    });
    assert_eq!(
        BuildRecord::from_canonical(&future),
        Err(RecordError::Document {
            error: DocumentError::UnsupportedFormat { found: 2 }
        })
    );
    assert_eq!(
        BuildRecord::from_canonical(&vec![b' '; MAX_RECORD_BYTES + 1]),
        Err(RecordError::Document {
            error: DocumentError::TooLarge {
                max_bytes: MAX_RECORD_BYTES
            }
        })
    );
    assert!(matches!(
        BuildRecord::from_canonical(b"\xff"),
        Err(RecordError::Document {
            error: DocumentError::Malformed { .. }
        })
    ));
    assert_eq!(
        record_with(|document| document.format = 2),
        Err(RecordError::Document {
            error: DocumentError::UnsupportedFormat { found: 2 }
        })
    );
}

#[test]
fn a_record_refuses_duplicates_unknown_programs_and_missing_artifacts() {
    let duplicate = record_with(|document| {
        let first = document.inputs.sources[0].clone();
        document.inputs.sources.push(first);
    });
    assert_eq!(
        duplicate,
        Err(RecordError::Duplicate {
            list: RecordList::Sources,
            name: name("yougori-oci-runtime-linux-amd64.tar.gz")
        })
    );
    let repeated_step = record_with(|document| {
        let first = document.steps[0].clone();
        document.steps.push(first);
    });
    assert_eq!(
        repeated_step,
        Err(RecordError::Duplicate {
            list: RecordList::Steps,
            name: name("build-agent")
        })
    );
    assert_eq!(
        record_with(|document| document.steps[1].program = name("gcc")),
        Err(RecordError::UnknownProgram {
            step: name("build-mount-helper"),
            program: name("gcc")
        })
    );
    assert_eq!(
        record_with(|document| document.steps.clear()),
        Err(RecordError::NoSteps)
    );
    assert_eq!(
        record_with(|document| {
            document.artifacts.remove(&ArtifactRole::Kernel);
        }),
        Err(RecordError::MissingArtifact {
            role: ArtifactRole::Kernel
        })
    );
    assert_eq!(
        record_with(|document| {
            document
                .artifacts
                .insert(ArtifactRole::Profile, produced("profile-1", b""));
        }),
        Err(RecordError::Empty { what: "artifact" })
    );
    assert_eq!(
        record_with(|document| document.inputs.kernel_configuration.length_bytes = 0),
        Err(RecordError::Empty {
            what: "kernel configuration"
        })
    );
    assert_eq!(
        record_with(|document| package_named(document, "openrc").length_bytes = 0),
        Err(RecordError::Empty { what: "input" })
    );
    assert_eq!(
        record_with(|document| {
            document.inputs.sources = (0..=MAX_SOURCES)
                .map(|index| SourceInput {
                    name: name(&format!("source-{index}")),
                    content_key: ContentKey::of(b"s"),
                    length_bytes: 1,
                })
                .collect();
        }),
        Err(RecordError::TooMany {
            list: RecordList::Sources,
            max: MAX_SOURCES
        })
    );
    assert_eq!(
        record_with(|document| {
            document.steps[0].arguments =
                vec![BuildArgument::new("x").unwrap(); MAX_STEP_ARGUMENTS + 1];
        }),
        Err(RecordError::StepTooLarge {
            step: name("build-agent")
        })
    );
    for error in [
        RecordError::NoSteps,
        RecordError::Empty { what: "input" },
        RecordError::MissingArtifact {
            role: ArtifactRole::RootImage,
        },
    ] {
        assert!(!error.to_string().is_empty());
    }
}

#[test]
fn build_inputs_cover_the_inputs_and_not_the_outputs() {
    let base = record();
    let inputs = base.build_inputs();
    assert_eq!(inputs.source, base.document().inputs.repository);
    assert_eq!(inputs, record().build_inputs());

    let other_output = record_with(|document| {
        document.artifacts.insert(
            ArtifactRole::RootImage,
            produced("appliance-2026.10.3", b"rebuilt"),
        );
    })
    .unwrap();
    assert_eq!(other_output.build_inputs(), inputs);
    assert_ne!(other_output.content_key(), base.content_key());

    let other_tool =
        record_with(|document| *tool_named(document, "apk") = tool("apk", "2.14.11-r0")).unwrap();
    assert_ne!(other_tool.toolchain_digest(), base.toolchain_digest());
    assert_eq!(
        other_tool.configuration_digest(),
        base.configuration_digest()
    );

    let other_package =
        record_with(|document| *package_named(document, "openrc") = package("openrc", "0.62.7-r0"))
            .unwrap();
    assert_ne!(
        other_package.configuration_digest(),
        base.configuration_digest()
    );
    assert_eq!(other_package.builder_digest(), base.builder_digest());

    let other_epoch =
        record_with(|document| document.inputs.source_date_epoch = UnixSeconds::new(1)).unwrap();
    assert_ne!(
        other_epoch.configuration_digest(),
        base.configuration_digest()
    );

    let other_argument = record_with(|document| {
        document.steps[0].arguments[1] = BuildArgument::new("-buildvcs=true").unwrap();
    })
    .unwrap();
    assert_ne!(other_argument.builder_digest(), base.builder_digest());
    assert_eq!(other_argument.toolchain_digest(), base.toolchain_digest());

    let other_environment = record_with(|document| {
        document.steps[0].environment.clear();
    })
    .unwrap();
    assert_ne!(other_environment.builder_digest(), base.builder_digest());
}

#[test]
fn a_rebuild_records_every_difference() {
    let original = record();
    let same = compare_rebuild(&original, &record());
    assert!(same.reproduced());
    assert!(same.same_inputs());
    assert_eq!(same.original, same.rebuilt);

    let drifted = record_with(|document| {
        document.artifacts.insert(
            ArtifactRole::RootImage,
            produced("appliance-2026.10.3", b"other ext4 uuid"),
        );
        document.artifacts.remove(&ArtifactRole::Initrd);
        document
            .artifacts
            .insert(ArtifactRole::Profile, produced("profile-1", b"profile"));
    })
    .unwrap();
    let report = compare_rebuild(&original, &drifted);
    assert!(report.same_inputs());
    assert!(!report.reproduced());
    assert_eq!(
        report.differences,
        vec![
            RebuildDifference::Artifact {
                role: ArtifactRole::RootImage,
                original: produced("appliance-2026.10.3", ROOT_IMAGE),
                rebuilt: produced("appliance-2026.10.3", b"other ext4 uuid"),
            },
            RebuildDifference::ArtifactMissing {
                role: ArtifactRole::Initrd
            },
            RebuildDifference::ArtifactAdded {
                role: ArtifactRole::Profile
            },
        ]
    );

    let other_inputs = record_with(|document| {
        *tool_named(document, "go") = tool("go", "go1.27.3");
        document.steps.pop();
        document.architecture = Architecture::Aarch64;
    })
    .unwrap();
    let report = compare_rebuild(&original, &other_inputs);
    assert!(!report.same_inputs());
    assert_eq!(
        report.differences,
        vec![
            RebuildDifference::Input {
                part: InputPart::Architecture
            },
            RebuildDifference::Input {
                part: InputPart::Toolchain
            },
            RebuildDifference::Input {
                part: InputPart::Steps
            },
        ]
    );
    assert_eq!(
        serde_json::to_value(&report.differences[0]).unwrap(),
        serde_json::json!({"difference": "input", "part": "architecture"})
    );
}

#[test]
fn a_kernel_configuration_is_read_strictly() {
    let image = *ContentKey::of(KERNEL).digest();
    let record = parse_kernel_config(image, KERNEL_CONFIG.as_bytes()).unwrap();
    assert_eq!(record.kernel_image(), image);
    assert_eq!(
        record.state(KernelOption::IoUring),
        Some(OptionState::NotSet)
    );
    assert_eq!(
        record.state(KernelOption::BpfSyscall),
        Some(OptionState::NotSet)
    );
    assert_eq!(
        record.state(KernelOption::Modules),
        Some(OptionState::BuiltIn)
    );
    assert_eq!(
        record.state(KernelOption::Vsockets),
        Some(OptionState::BuiltIn)
    );
    assert_eq!(
        record.state(KernelOption::LockDownForceIntegrity),
        Some(OptionState::NotSet)
    );
    // Not in the file: unknown, never absent.
    assert_eq!(record.state(KernelOption::ModuleSigForce), None);

    let parse = |text: &str| parse_kernel_config(image, text.as_bytes());
    assert_eq!(
        parse("CONFIG_IO_URING=m\nCONFIG_PERF_EVENTS=n\n")
            .unwrap()
            .state(KernelOption::IoUring),
        Some(OptionState::Module)
    );
    assert_eq!(
        parse("CONFIG_PERF_EVENTS=n")
            .unwrap()
            .state(KernelOption::PerfEvents),
        Some(OptionState::NotSet)
    );
    assert_eq!(
        parse("# CONFIG_IO_URING is not set\r\n"),
        Err(KernelConfigError::CarriageReturn { line: 1 })
    );
    assert_eq!(
        parse("CONFIG_X=y\n CONFIG_IO_URING=y\n"),
        Err(KernelConfigError::Malformed { line: 2 })
    );
    assert_eq!(
        parse("IO_URING=y"),
        Err(KernelConfigError::Malformed { line: 1 })
    );
    assert_eq!(
        parse("CONFIG_=y"),
        Err(KernelConfigError::Malformed { line: 1 })
    );
    assert_eq!(
        parse("CONFIG_IO_URING=\"y\""),
        Err(KernelConfigError::NotTristate {
            line: 1,
            option: KernelOption::IoUring
        })
    );
    assert_eq!(
        parse("# CONFIG_IO_URING is not set\nCONFIG_IO_URING=y\n"),
        Err(KernelConfigError::Repeated {
            line: 2,
            option: KernelOption::IoUring
        })
    );
    // Untracked options, values and comments are ignored, even repeated.
    assert!(parse("CONFIG_HZ=250\nCONFIG_HZ=1000\n# comment\n#\n").is_ok());
    assert_eq!(
        parse_kernel_config(image, b"CONFIG_IO_URING=\xff"),
        Err(KernelConfigError::NotText)
    );
    assert_eq!(
        parse_kernel_config(image, &vec![b'\n'; MAX_KERNEL_CONFIG_BYTES + 1]),
        Err(KernelConfigError::TooLarge {
            max_bytes: MAX_KERNEL_CONFIG_BYTES
        })
    );
    assert!(!KernelConfigError::NotText.to_string().is_empty());
}

#[test]
fn the_kernel_record_digest_binds_the_image_and_every_option() {
    let image = *ContentKey::of(KERNEL).digest();
    let record = |options: &[(KernelOption, OptionState)]| {
        KernelBuildRecord::new(image, options.iter().copied()).unwrap()
    };
    let base = record(&[(KernelOption::IoUring, OptionState::NotSet)]);
    assert_eq!(
        kernel_record_digest(&base),
        kernel_record_digest(&base.clone())
    );
    assert_ne!(
        kernel_record_digest(&base),
        kernel_record_digest(&record(&[(KernelOption::IoUring, OptionState::BuiltIn)]))
    );
    assert_ne!(
        kernel_record_digest(&base),
        kernel_record_digest(&record(&[]))
    );
    let other_image = KernelBuildRecord::new(
        *ContentKey::of(b"other kernel").digest(),
        [(KernelOption::IoUring, OptionState::NotSet)],
    )
    .unwrap();
    assert_ne!(
        kernel_record_digest(&base),
        kernel_record_digest(&other_image)
    );
}

#[test]
fn kernel_requirements_follow_the_profile() {
    let image = *ContentKey::of(KERNEL).digest();
    let strict = KernelRequirements::of_profile(&strict());
    assert_eq!(
        strict.absent().iter().copied().collect::<Vec<_>>(),
        [KernelOption::IoUring]
    );
    assert!(strict.settings().is_empty());
    assert!(KernelRequirements::of_profile(&developer())
        .absent()
        .is_empty());

    let fixture = parse_kernel_config(image, KERNEL_CONFIG.as_bytes()).unwrap();
    assert_eq!(strict.check(&fixture), Ok(()));
    let io_uring =
        KernelBuildRecord::new(image, [(KernelOption::IoUring, OptionState::BuiltIn)]).unwrap();
    assert_eq!(
        strict.check(&io_uring),
        Err(KernelRequirementFailure::OptionNotAbsent {
            option: KernelOption::IoUring,
            state: Some(OptionState::BuiltIn)
        })
    );
    let unlisted = KernelBuildRecord::new(image, NO_OPTIONS).unwrap();
    assert_eq!(
        strict.check(&unlisted),
        Err(KernelRequirementFailure::OptionNotAbsent {
            option: KernelOption::IoUring,
            state: None
        })
    );

    let lockdown = KernelRequirements::new(NO_ABSENT, [KernelSetting::LockdownIntegrity]);
    assert_eq!(
        lockdown.check(&fixture),
        Err(KernelRequirementFailure::SettingNotForced {
            setting: KernelSetting::LockdownIntegrity
        })
    );
    let forced = KernelBuildRecord::new(
        image,
        [(
            KernelOption::LockDownForceConfidentiality,
            OptionState::BuiltIn,
        )],
    )
    .unwrap();
    assert_eq!(lockdown.check(&forced), Ok(()));
    let securebits = KernelRequirements::new(NO_ABSENT, [KernelSetting::SecurebitsLocked]);
    assert!(securebits.check(&forced).is_err());
    for failure in [
        strict.check(&io_uring).unwrap_err(),
        strict.check(&unlisted).unwrap_err(),
        lockdown.check(&fixture).unwrap_err(),
    ] {
        assert!(
            failure.to_string().contains("CONFIG_") || failure.to_string().contains("lockdown")
        );
    }
}

#[test]
fn the_io_uring_control_happens_only_for_an_io_uring_image() {
    let image = *ContentKey::of(b"io_uring test kernel").digest();
    let io_uring =
        KernelBuildRecord::new(image, [(KernelOption::IoUring, OptionState::Module)]).unwrap();
    let strict = KernelRequirements::of_profile(&strict());
    assert!(KernelControl::run(&strict, &io_uring).happened());
    let fixture =
        parse_kernel_config(*ContentKey::of(KERNEL).digest(), KERNEL_CONFIG.as_bytes()).unwrap();
    assert!(!KernelControl::run(&strict, &fixture).happened());
    let developer = KernelRequirements::of_profile(&developer());
    assert!(!KernelControl::run(&developer, &io_uring).happened());
    // A record that does not list io_uring is refused, but is no io_uring test image.
    let unlisted = KernelBuildRecord::new(image, NO_OPTIONS).unwrap();
    assert!(!KernelControl::run(&strict, &unlisted).happened());
}

#[test]
fn a_manifest_is_checked_and_canonical() {
    let manifest = manifest_with(|_| {}).unwrap();
    assert_eq!(
        manifest
            .document()
            .workloads
            .iter()
            .map(|feature| feature.workload)
            .collect::<Vec<_>>(),
        [WorkloadProfile::StrictTool, WorkloadProfile::Developer]
    );
    assert_eq!(manifest.root_image(), *ContentKey::of(ROOT_IMAGE).digest());
    assert_eq!(manifest.expectation().root_image, manifest.root_image());
    assert_eq!(&manifest.expectation().kernel, manifest.kernel());
    assert_eq!(manifest.release(), ReleaseNumber::new(3).unwrap());
    assert!(manifest.workload(WorkloadProfile::Service).is_none());
    assert_eq!(manifest.devices().len(), 3);
    assert_eq!(manifest.artifacts().len(), 3);
    assert_eq!(
        FeatureManifest::from_canonical(manifest.canonical_bytes()).unwrap(),
        manifest
    );
    assert_eq!(
        manifest.content_key(),
        ContentKey::of(manifest.canonical_bytes())
    );

    assert_eq!(
        manifest_with(|document| document.expires_at = document.issued_at),
        Err(ManifestError::ExpiryNotAfterIssue)
    );
    assert_eq!(
        manifest_with(|document| {
            document.artifacts.remove(&ArtifactRole::RootImage);
        }),
        Err(ManifestError::MissingArtifact {
            role: ArtifactRole::RootImage
        })
    );
    assert_eq!(
        manifest_with(|document| {
            document
                .artifacts
                .get_mut(&ArtifactRole::Initrd)
                .unwrap()
                .length_bytes = 0;
        }),
        Err(ManifestError::EmptyArtifact {
            role: ArtifactRole::Initrd
        })
    );
    assert_eq!(
        manifest_with(|document| {
            document
                .artifacts
                .insert(ArtifactRole::Firmware, produced("ovmf-2025.08", b"ovmf"));
        }),
        Err(ManifestError::FirmwareWithoutFirmwareBoot)
    );
    assert_eq!(
        manifest_with(|document| document.boot = BootMethod::Firmware),
        Err(ManifestError::FirmwareBootWithoutFirmware)
    );
    let other_kernel = *ContentKey::of(b"other kernel").digest();
    assert_eq!(
        manifest_with(|document| {
            document.kernel = KernelBuildRecord::new(other_kernel, NO_OPTIONS).unwrap();
        }),
        Err(ManifestError::KernelRecordNotBound {
            kernel: *ContentKey::of(KERNEL).digest(),
            record: other_kernel
        })
    );
    assert_eq!(
        manifest_with(|document| document.workloads.clear()),
        Err(ManifestError::NoWorkloads)
    );
    assert_eq!(
        manifest_with(|document| document.workloads.push(workload(&strict()))),
        Err(ManifestError::DuplicateWorkload {
            workload: WorkloadProfile::StrictTool
        })
    );
    let zero = edited_json(manifest.canonical_bytes(), |value| {
        value["release"] = serde_json::json!(0);
    });
    assert!(matches!(
        FeatureManifest::from_canonical(&zero),
        Err(ManifestError::Document {
            error: DocumentError::Malformed { .. }
        })
    ));
    let duplicated_device = {
        let text = String::from_utf8(manifest.canonical_bytes().to_vec()).unwrap();
        text.replace("\"devices\":[", "\"devices\":[\"virtio_blk\",")
    };
    assert_eq!(
        FeatureManifest::from_canonical(duplicated_device.as_bytes()),
        Err(ManifestError::Document {
            error: DocumentError::NotCanonical
        })
    );
    assert_eq!(ReleaseNumber::new(0), None);
    assert_eq!(ReleaseNumber::FIRST.get(), 1);
    assert_eq!(serde_json::to_value(&manifest).unwrap()["release"], 3);
    for error in [
        ManifestError::NoWorkloads,
        ManifestError::ExpiryNotAfterIssue,
        ManifestError::FirmwareBootWithoutFirmware,
    ] {
        assert!(!error.to_string().is_empty());
    }
}

#[test]
fn a_manifest_binds_exactly_its_build_record() {
    let record = record();
    let manifest = FeatureManifest::new(manifest_document(&record)).unwrap();
    assert_eq!(manifest.bind(&record), Ok(()));

    let other = record_with(|document| {
        document.steps.pop();
    })
    .unwrap();
    assert_eq!(
        manifest.bind(&other),
        Err(BindingError::RecordNotBound {
            manifest: record.content_key(),
            record: other.content_key()
        })
    );
    let bound = |edit: fn(&mut ManifestDocument)| {
        let mut document = manifest_document(&record);
        edit(&mut document);
        FeatureManifest::new(document).unwrap().bind(&record)
    };
    assert_eq!(
        bound(|document| document.image = ImageName::new("yougori-guest-service").unwrap()),
        Err(BindingError::ImageDiffers {
            manifest: ImageName::new("yougori-guest-service").unwrap(),
            record: image_name()
        })
    );
    assert_eq!(
        bound(|document| document.architecture = Architecture::Aarch64),
        Err(BindingError::ArchitectureDiffers {
            manifest: Architecture::Aarch64,
            record: Architecture::X86_64
        })
    );
    assert_eq!(
        bound(|document| {
            document
                .artifacts
                .insert(ArtifactRole::Profile, produced("profile-1", b"profile"));
        }),
        Err(BindingError::ArtifactNotBuilt {
            role: ArtifactRole::Profile
        })
    );
    assert_eq!(
        bound(|document| {
            document.artifacts.remove(&ArtifactRole::Initrd);
        }),
        Err(BindingError::ArtifactNotListed {
            role: ArtifactRole::Initrd
        })
    );
    assert_eq!(
        bound(|document| {
            document
                .artifacts
                .get_mut(&ArtifactRole::Initrd)
                .unwrap()
                .version = ComponentVersion::new("6.12.48-0-virt").unwrap();
        }),
        Err(BindingError::ArtifactDiffers {
            role: ArtifactRole::Initrd
        })
    );
    assert!(BindingError::ArtifactDiffers {
        role: ArtifactRole::Kernel
    }
    .to_string()
    .contains("kernel"));
}

#[test]
fn a_hello_must_agree_with_the_manifest() {
    let manifest = manifest_with(|_| {}).unwrap();
    let agent = manifest.agent();
    let hello = |guest_version, agent_build| Hello {
        guest_version,
        agent_build,
        claimed_vm: None,
        claimed_boot: None,
    };
    let build = *ContentKey::of(AGENT).digest();
    assert_eq!(agent.check_hello(&hello(PROTOCOL_VERSION, build)), Ok(()));
    assert_eq!(
        agent.check_hello(&hello(PROTOCOL_VERSION + 1, build)),
        Err(HelloMismatch::ProtocolVersion {
            manifest: PROTOCOL_VERSION,
            guest: PROTOCOL_VERSION + 1
        })
    );
    let other = digest("yougori/test/agent/v1", &[b"other"]);
    assert_eq!(
        agent.check_hello(&hello(PROTOCOL_VERSION, other)),
        Err(HelloMismatch::AgentBuild {
            manifest: build,
            guest: other
        })
    );
    assert!(!HelloMismatch::AgentBuild {
        manifest: build,
        guest: other
    }
    .to_string()
    .is_empty());
}

struct FixedCalendar;

impl TrustCalendar for FixedCalendar {
    fn now(&self) -> DateTime<Utc> {
        DateTime::from_timestamp(i64::try_from(NOW).unwrap(), 0).unwrap()
    }
}

struct AnyStructure;

impl StructureValidator for AnyStructure {
    fn validate(
        &self,
        _content: &ContentDescriptor,
        _bytes: &mut ObjectBytes,
    ) -> Result<(), VerifierRejection> {
        Ok(())
    }
}

#[test]
fn a_release_verifies_under_the_trust_roots_and_the_catalogs_statement() {
    let release = release();
    let verified = release.verified();
    assert_eq!(verified.key().as_str(), "guest-release-2026");
    assert!(verified.component().is_verified());
    assert_eq!(verified.component().class(), ArtifactClass::GuestImage);
    assert_eq!(verified.manifest(), &release.manifest);
    assert_eq!(verified.record(), &release.record);
    assert_eq!(
        verified.component().statement(),
        &signing_statement(
            &release.signature.publisher,
            release.manifest.canonical_bytes()
        )
    );

    // The catalog's verifier for guest images authenticates the stored manifest with the
    // same signature (S02, S08).
    let descriptor = ContentDescriptor {
        scope: Scope::Host,
        class: ArtifactClass::GuestImage,
        content_key: release.manifest.content_key(),
        length_bytes: release.manifest.canonical_bytes().len() as u64,
        manifest_digest: digest("yougori/test/declaration/v1", &[b"declaration"]),
    };
    assert_eq!(
        StatementBinding::Content.statement(
            &release.signature.publisher,
            MANIFEST_CLASS,
            &descriptor
        ),
        *verified.component().statement()
    );
    let catalog = SignedArtifactVerifier::new(
        ArtifactClass::GuestImage,
        StatementBinding::Content,
        SharedTrustRoots::new(roots()),
        Arc::new(FixedCalendar),
        Box::new(AnyStructure),
    );
    assert_eq!(
        catalog
            .check(
                &descriptor,
                &release.signature.publisher,
                release.signature.signature.as_bytes()
            )
            .unwrap()
            .as_str(),
        "guest-release-2026"
    );
    let signature: ManifestSignature =
        serde_json::from_value(serde_json::to_value(&release.signature).unwrap()).unwrap();
    assert_eq!(signature, release.signature);
    assert!(
        serde_json::from_value::<ManifestSignature>(serde_json::json!({
            "publisher": release.signature.publisher,
            "signature": "00",
            "key": "x"
        }))
        .is_err()
    );
}

fn refusal_of(
    release: &Release,
    roots: &crate::foundation::signing::TrustRoots,
) -> ComponentVerification {
    match release.verify(roots, NOW) {
        Err(VerifyRefusal::Signature { component }) => component.verification().clone(),
        other => panic!("expected a signature refusal, got {other:?}"),
    }
}

#[test]
fn signature_refusals_are_typed() {
    let mut unsigned = release();
    unsigned.signature.signature = crate::sandbox::trust::HexBytes::new(Vec::new());
    assert_eq!(unsigned.verify(&roots(), NOW), Err(VerifyRefusal::Unsigned));

    let mut stranger = release();
    stranger.signature = sign(9, stranger.manifest.canonical_bytes());
    assert_eq!(
        refusal_of(&stranger, &roots()),
        ComponentVerification::UnknownPublisher {}
    );

    let mut forged = release();
    forged.signature.signature = sign(9, forged.manifest.canonical_bytes()).signature;
    assert!(matches!(
        refusal_of(&forged, &roots()),
        ComponentVerification::BadSignature { .. }
    ));

    let signed = release();
    let revoked = roots_of(&[
        key_json(
            "guest-release-2026",
            RELEASE,
            &["guest_image"],
            "2027-01-01T00:00:00Z",
            true,
        ),
        key_json(
            "guest-release-next",
            8,
            &["guest_image"],
            "2027-01-01T00:00:00Z",
            false,
        ),
    ]);
    assert!(matches!(
        refusal_of(&signed, &revoked),
        ComponentVerification::Revoked { .. }
    ));
    let expired = roots_of(&[key_json(
        "guest-release-2026",
        RELEASE,
        &["guest_image"],
        "2026-06-01T00:00:00Z",
        false,
    )]);
    assert!(matches!(
        refusal_of(&signed, &expired),
        ComponentVerification::Expired { .. }
    ));
    let other_class = roots_of(&[
        key_json(
            "runtime-release",
            RELEASE,
            &["runtime_update"],
            "2027-01-01T00:00:00Z",
            false,
        ),
        key_json(
            "guest-release-other",
            8,
            &["guest_image"],
            "2027-01-01T00:00:00Z",
            false,
        ),
    ]);
    assert!(matches!(
        refusal_of(&signed, &other_class),
        ComponentVerification::ClassNotAllowed { .. }
    ));
    let no_guest_keys = roots_of(&[key_json(
        "runtime-release",
        RELEASE,
        &["runtime_update"],
        "2027-01-01T00:00:00Z",
        false,
    )]);
    assert_eq!(
        refusal_of(&signed, &no_guest_keys),
        ComponentVerification::NoKeysForClass {}
    );
    assert_eq!(
        signed.verify(&roots(), u64::MAX),
        Err(VerifyRefusal::TimeOutOfRange {
            now: UnixSeconds::new(u64::MAX)
        })
    );
    assert!(!VerifyRefusal::Unsigned.to_string().is_empty());
    let text = signed.verify(&revoked, NOW).unwrap_err().to_string();
    assert!(
        text.contains("guest-release-2026 is revoked (key-compromise)"),
        "{text}"
    );
    for (roots, words) in [
        (expired, "expired at 2026-06-01"),
        (other_class, "may not sign guest_image"),
        (no_guest_keys, "no key that may sign guest_image"),
    ] {
        let text = signed.verify(&roots, NOW).unwrap_err().to_string();
        assert!(text.contains(words), "{text}");
    }
    let text = stranger.verify(&roots(), NOW).unwrap_err().to_string();
    assert!(text.contains("publisher"), "{text}");
    let text = forged.verify(&roots(), NOW).unwrap_err().to_string();
    assert!(text.contains("does not verify"), "{text}");
}

#[test]
fn only_authenticated_bytes_are_read() {
    let release = release();
    // A manifest changed after signing fails its signature before it is read.
    let changed = edited_json(release.manifest.canonical_bytes(), |value| {
        value["release"] = serde_json::json!(4);
    });
    assert!(matches!(
        verify_release(
            &changed,
            release.record.canonical_bytes(),
            &release.signature,
            &roots(),
            UnixSeconds::new(NOW)
        ),
        Err(VerifyRefusal::Signature { .. })
    ));
    // A signed manifest that is not canonical is refused after its signature.
    let pretty = serde_json::to_vec_pretty(release.manifest.document()).unwrap();
    assert_eq!(
        verify_release(
            &pretty,
            release.record.canonical_bytes(),
            &sign(RELEASE, &pretty),
            &roots(),
            UnixSeconds::new(NOW)
        ),
        Err(VerifyRefusal::Manifest {
            error: ManifestError::Document {
                error: DocumentError::NotCanonical
            }
        })
    );
    // Record bytes other than the bound ones are refused before they are read.
    let mut record = release.record.canonical_bytes().to_vec();
    record.push(b' ');
    assert_eq!(
        verify_release(
            release.manifest.canonical_bytes(),
            &record,
            &release.signature,
            &roots(),
            UnixSeconds::new(NOW)
        ),
        Err(VerifyRefusal::Binding {
            error: BindingError::RecordNotBound {
                manifest: release.record.content_key(),
                record: ContentKey::of(&record)
            }
        })
    );
    // A bound record that is not canonical is refused when read.
    let mut document = manifest_document(&release.record);
    document.build_record = ContentKey::of(&record);
    let bound_to_bad = release_of(release.record.clone(), document);
    assert_eq!(
        verify_release(
            bound_to_bad.manifest.canonical_bytes(),
            &record,
            &bound_to_bad.signature,
            &roots(),
            UnixSeconds::new(NOW)
        ),
        Err(VerifyRefusal::Record {
            error: RecordError::Document {
                error: DocumentError::NotCanonical
            }
        })
    );
    // The binding is checked after both are read.
    let unbuilt = release_with(|document| {
        document
            .artifacts
            .insert(ArtifactRole::Profile, produced("profile-1", b"profile"));
    });
    assert_eq!(
        unbuilt.verify(&roots(), NOW),
        Err(VerifyRefusal::Binding {
            error: BindingError::ArtifactNotBuilt {
                role: ArtifactRole::Profile
            }
        })
    );
    let large = vec![b' '; MAX_MANIFEST_BYTES + 1];
    assert_eq!(
        verify_release(
            &large,
            b"",
            &release.signature,
            &roots(),
            UnixSeconds::new(NOW)
        ),
        Err(VerifyRefusal::Manifest {
            error: ManifestError::Document {
                error: DocumentError::TooLarge {
                    max_bytes: MAX_MANIFEST_BYTES
                }
            }
        })
    );
    let large_record = vec![b' '; MAX_RECORD_BYTES + 1];
    assert_eq!(
        verify_release(
            release.manifest.canonical_bytes(),
            &large_record,
            &release.signature,
            &roots(),
            UnixSeconds::new(NOW)
        ),
        Err(VerifyRefusal::Record {
            error: RecordError::Document {
                error: DocumentError::TooLarge {
                    max_bytes: MAX_RECORD_BYTES
                }
            }
        })
    );
}

fn selection_of(
    release: &Release,
    row: &crate::sandbox::trust::PinnedConfiguration,
    profile: &crate::sandbox_contract::confinement::ConfinementProfile,
    floor: Option<&ReleaseFloor>,
    now: u64,
) -> Result<SelectedImage, SelectionRefusal> {
    select(
        release.verified(),
        Selection {
            row,
            profile,
            floor,
            now: UnixSeconds::new(now),
        },
    )
}

#[test]
fn a_selection_names_one_image_row_and_profile() {
    let release = release();
    let row = row(&release.record);
    let selected = selection_of(&release, &row, &strict(), None, NOW).unwrap();
    assert_eq!(selected.image(), &image_name());
    assert_eq!(selected.release(), ReleaseNumber::new(3).unwrap());
    assert_eq!(selected.manifest(), release.manifest.content_key());
    assert_eq!(selected.record(), &release.record);
    assert_eq!(selected.root_image(), *ContentKey::of(ROOT_IMAGE).digest());
    assert_eq!(selected.configuration(), firecracker_key());
    assert_eq!(selected.fingerprint(), row.fingerprint().unwrap());
    assert_eq!(selected.workload(), WorkloadProfile::StrictTool);
    assert_eq!(selected.key().as_str(), "guest-release-2026");
    assert_eq!(selected.expectation(), release.manifest.expectation());
    assert_eq!(selected.verified().manifest(), &release.manifest);
    let floor = selected.floor();
    assert_eq!(
        floor,
        ReleaseFloor {
            image: image_name(),
            release: ReleaseNumber::new(3).unwrap(),
            manifest: release.manifest.content_key(),
        }
    );
    assert_eq!(
        serde_json::from_value::<ReleaseFloor>(serde_json::to_value(&floor).unwrap()).unwrap(),
        floor
    );
    let record = serde_json::to_value(&selected).unwrap();
    assert_eq!(record["workload"], "strict_tool");
    assert!(record.get("verified").is_none());
    // The same release again under its own floor.
    assert!(selection_of(&release, &row, &strict(), Some(&floor), NOW).is_ok());
    // The developer profile is installed too.
    assert!(selection_of(&release, &row, &developer(), None, NOW).is_ok());
}

#[test]
fn expiry_and_rollback_are_refused() {
    let release = release();
    let row = row(&release.record);
    assert!(selection_of(&release, &row, &strict(), None, EXPIRES_AT - 1).is_ok());
    assert_eq!(
        selection_of(&release, &row, &strict(), None, EXPIRES_AT),
        Err(SelectionRefusal::Expired {
            expires_at: UnixSeconds::new(EXPIRES_AT),
            now: UnixSeconds::new(EXPIRES_AT)
        })
    );
    let floor = |release: u64, manifest: ContentKey| ReleaseFloor {
        image: image_name(),
        release: ReleaseNumber::new(release).unwrap(),
        manifest,
    };
    let newer = floor(4, ContentKey::of(b"release 4"));
    assert_eq!(
        selection_of(&release, &row, &strict(), Some(&newer), NOW),
        Err(SelectionRefusal::RolledBack {
            release: ReleaseNumber::new(3).unwrap(),
            floor: ReleaseNumber::new(4).unwrap()
        })
    );
    let reused = floor(3, ContentKey::of(b"another release 3"));
    assert_eq!(
        selection_of(&release, &row, &strict(), Some(&reused), NOW),
        Err(SelectionRefusal::ReleaseReused {
            release: ReleaseNumber::new(3).unwrap(),
            admitted: ContentKey::of(b"another release 3"),
            presented: release.manifest.content_key()
        })
    );
    assert!(selection_of(
        &release,
        &row,
        &strict(),
        Some(&floor(2, ContentKey::of(b"2"))),
        NOW
    )
    .is_ok());
    let other_line = ReleaseFloor {
        image: ImageName::new("yougori-guest-service").unwrap(),
        ..floor(1, ContentKey::of(b"1"))
    };
    assert_eq!(
        selection_of(&release, &row, &strict(), Some(&other_line), NOW),
        Err(SelectionRefusal::FloorOfOtherImage {
            floor: ImageName::new("yougori-guest-service").unwrap(),
            image: image_name()
        })
    );
}

#[test]
fn the_pinned_row_must_pin_this_release_exactly() {
    let release = release();
    let good = row(&release.record);
    let refused = |edit: &dyn Fn(&mut crate::sandbox::trust::PinnedConfiguration)| {
        let mut row = good.clone();
        edit(&mut row);
        selection_of(&release, &row, &strict(), None, NOW).map(|_| ())
    };
    assert_eq!(
        refused(&|row| {
            row.components.remove(&ComponentKind::GuestKernel);
        }),
        Err(SelectionRefusal::Row {
            refusal: PinRefusal::MissingComponent {
                key: firecracker_key(),
                component: ComponentKind::GuestKernel
            }
        })
    );
    assert_eq!(
        refused(&|row| row.key.architecture = Architecture::Aarch64),
        Err(SelectionRefusal::ArchitectureDiffers {
            row: Architecture::Aarch64,
            manifest: Architecture::X86_64
        })
    );
    assert_eq!(
        refused(&|row| {
            row.boot = BootMethod::Firmware;
            row.components.insert(
                ComponentKind::Firmware,
                pin(
                    ComponentKind::Firmware,
                    &produced("ovmf-2025.08", b"ovmf"),
                    &release.record,
                ),
            );
        }),
        Err(SelectionRefusal::BootMethodDiffers {
            row: BootMethod::Firmware,
            manifest: BootMethod::DirectKernel
        })
    );
    let image = |edit: &dyn Fn(&mut crate::sandbox::trust::ComponentPin)| {
        refused(&|row| edit(row.components.get_mut(&ComponentKind::GuestImage).unwrap()))
    };
    let mismatch = |field| {
        Err(SelectionRefusal::PinMismatch {
            component: ComponentKind::GuestImage,
            field,
        })
    };
    assert_eq!(
        image(&|pin| pin.version = ComponentVersion::new("appliance-2026.10.2").unwrap()),
        mismatch(PinField::Version)
    );
    assert_eq!(
        image(&|pin| pin.content_key = ContentKey::of(b"release 2 root image")),
        mismatch(PinField::ContentKey)
    );
    assert_eq!(
        image(&|pin| pin.length_bytes += 1),
        mismatch(PinField::Length)
    );
    assert_eq!(
        image(&|pin| pin.build.toolchain = digest("yougori/test/toolchain/v1", &[b"other"])),
        mismatch(PinField::BuildInputs)
    );
    assert_eq!(
        refused(&|row| {
            row.devices.remove(&DeviceModel::VirtioRng);
        }),
        Err(SelectionRefusal::DeviceAbsent {
            device: DeviceModel::VirtioRng
        })
    );
    for refusal in [
        SelectionRefusal::NotPinned {
            component: ComponentKind::Firmware,
        },
        SelectionRefusal::PinnedNotInRelease {
            component: ComponentKind::Firmware,
        },
        SelectionRefusal::PinMismatch {
            component: ComponentKind::GuestKernel,
            field: PinField::BuildInputs,
        },
    ] {
        assert!(!refusal.to_string().is_empty());
    }
}

#[test]
fn a_firmware_release_is_selected_on_a_firmware_row() {
    let firmware = produced("ovmf-2025.08", b"ovmf firmware");
    let record = BuildRecord::new({
        let mut document = record_document();
        document
            .artifacts
            .insert(ArtifactRole::Firmware, firmware.clone());
        document
    })
    .unwrap();
    let mut manifest = manifest_document(&record);
    manifest.boot = BootMethod::Firmware;
    let release = release_of(record, manifest);
    let mut row = row(&release.record);
    row.key.backend = crate::sandbox::trust::SandboxBackend::QemuSecure;
    row.boot = BootMethod::Firmware;
    row.components.insert(
        ComponentKind::Firmware,
        pin(ComponentKind::Firmware, &firmware, &release.record),
    );
    assert!(selection_of(&release, &row, &strict(), None, NOW).is_ok());
    row.components
        .get_mut(&ComponentKind::Firmware)
        .unwrap()
        .content_key = ContentKey::of(b"other firmware");
    assert_eq!(
        selection_of(&release, &row, &strict(), None, NOW).map(|_| ()),
        Err(SelectionRefusal::PinMismatch {
            component: ComponentKind::Firmware,
            field: PinField::ContentKey
        })
    );
}

/// The fixture release with `edit` applied to the build record; the manifest lists the
/// record's artifacts.
fn release_of_record(edit: impl FnOnce(&mut RecordDocument)) -> Release {
    let record = record_with(edit).unwrap();
    let manifest = manifest_document(&record);
    release_of(record, manifest)
}

/// `release` selected on `row` with `edit` applied to the row's pin of `kind`.
fn with_pin_edited(
    release: &Release,
    row: &crate::sandbox::trust::PinnedConfiguration,
    kind: ComponentKind,
    edit: &dyn Fn(&mut crate::sandbox::trust::ComponentPin),
) -> Result<(), SelectionRefusal> {
    let mut row = row.clone();
    edit(row.components.get_mut(&kind).unwrap());
    selection_of(release, &row, &strict(), None, NOW).map(|_| ())
}

#[test]
fn a_row_without_the_initrd_refuses_a_release_that_ships_one() {
    let release = release();
    assert!(release.manifest.artifact(ArtifactRole::Initrd).is_some());
    let row = row(&release.record);
    assert!(selection_of(&release, &row, &strict(), None, NOW).is_ok());

    let mut without = row.clone();
    without.components.remove(&ComponentKind::GuestInitrd);
    // A valid row: the initrd is not required of every configuration.
    assert_eq!(without.check(), Ok(()));
    let refusal = selection_of(&release, &without, &strict(), None, NOW).map(|_| ());
    assert_eq!(
        refusal,
        Err(SelectionRefusal::NotPinned {
            component: ComponentKind::GuestInitrd
        })
    );
    assert_eq!(
        refusal.unwrap_err().to_string(),
        "the configuration pins no guest_initrd for the release"
    );

    let mismatch = |field| {
        Err(SelectionRefusal::PinMismatch {
            component: ComponentKind::GuestInitrd,
            field,
        })
    };
    let initrd = |edit: &dyn Fn(&mut crate::sandbox::trust::ComponentPin)| {
        with_pin_edited(&release, &row, ComponentKind::GuestInitrd, edit)
    };
    assert_eq!(
        initrd(&|pin| pin.content_key = ContentKey::of(b"initramfs of release 2")),
        mismatch(PinField::ContentKey)
    );
    assert_eq!(
        initrd(&|pin| pin.version = ComponentVersion::new("6.12.46-0-virt").unwrap()),
        mismatch(PinField::Version)
    );

    // A row that pins an initrd is refused for a release without one.
    let no_initrd = release_of_record(|document| {
        document.artifacts.remove(&ArtifactRole::Initrd);
    });
    assert_eq!(
        selection_of(&no_initrd, &row, &strict(), None, NOW).map(|_| ()),
        Err(SelectionRefusal::PinnedNotInRelease {
            component: ComponentKind::GuestInitrd
        })
    );
    assert!(selection_of(&no_initrd, &without, &strict(), None, NOW).is_ok());
}

#[test]
fn a_mismatched_profile_is_refused() {
    let profiled = release_of_record(|document| {
        document.artifacts.insert(
            ArtifactRole::Profile,
            produced("profile-1", b"sealed guest policies"),
        );
    });
    let row = row(&profiled.record);
    assert!(row.component(ComponentKind::GuestProfile).is_some());
    assert!(selection_of(&profiled, &row, &strict(), None, NOW).is_ok());

    let mismatch = |field| {
        Err(SelectionRefusal::PinMismatch {
            component: ComponentKind::GuestProfile,
            field,
        })
    };
    let profile = |edit: &dyn Fn(&mut crate::sandbox::trust::ComponentPin)| {
        with_pin_edited(&profiled, &row, ComponentKind::GuestProfile, edit)
    };
    assert_eq!(
        profile(&|pin| pin.content_key = ContentKey::of(b"other guest policies")),
        mismatch(PinField::ContentKey)
    );
    assert_eq!(
        profile(&|pin| pin.version = ComponentVersion::new("profile-2").unwrap()),
        mismatch(PinField::Version)
    );
    assert_eq!(
        profile(&|pin| pin.length_bytes += 1),
        mismatch(PinField::Length)
    );
    assert_eq!(
        profile(&|pin| pin.build.builder = digest("yougori/test/builder/v1", &[b"other"])),
        mismatch(PinField::BuildInputs)
    );

    let mut without = row.clone();
    without.components.remove(&ComponentKind::GuestProfile);
    assert_eq!(
        selection_of(&profiled, &without, &strict(), None, NOW).map(|_| ()),
        Err(SelectionRefusal::NotPinned {
            component: ComponentKind::GuestProfile
        })
    );
    // The row of the profiled release pins a profile the fixture release does not have.
    assert_eq!(
        selection_of(&release(), &row, &strict(), None, NOW).map(|_| ()),
        Err(SelectionRefusal::PinnedNotInRelease {
            component: ComponentKind::GuestProfile
        })
    );
}

#[test]
fn an_older_row_without_the_initrd_and_profile_kinds_still_reads() {
    let release = release();
    let json = serde_json::to_value(row_without_initrd_or_profile(&release.record)).unwrap();
    let kinds: std::collections::BTreeSet<&str> = json["components"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        kinds,
        ["guest_image", "guest_kernel", "jailer", "runtime"].into()
    );
    let older: crate::sandbox::trust::PinnedConfiguration = serde_json::from_value(json).unwrap();
    assert_eq!(older.check(), Ok(()));
    // It refuses a release that ships an initrd ...
    assert_eq!(
        selection_of(&release, &older, &strict(), None, NOW).map(|_| ()),
        Err(SelectionRefusal::NotPinned {
            component: ComponentKind::GuestInitrd
        })
    );
    // ... and selects one that ships neither an initrd nor a profile, under the same
    // fingerprint as before.
    let bare = release_of_record(|document| {
        document.artifacts.remove(&ArtifactRole::Initrd);
    });
    assert_eq!(row(&bare.record), older);
    let selected = selection_of(&bare, &older, &strict(), None, NOW).unwrap();
    assert_eq!(selected.fingerprint(), older.fingerprint().unwrap());
    assert_eq!(
        selected
            .admit_boot(
                &BootSet::new()
                    .with(ArtifactRole::RootImage, HostArtifact::of_bytes(ROOT_IMAGE))
                    .with(ArtifactRole::Kernel, HostArtifact::of_bytes(KERNEL))
            )
            .map(|_| ()),
        Ok(())
    );
}

#[test]
fn every_role_is_pinned_under_its_own_component() {
    let kinds: Vec<ComponentKind> = ArtifactRole::ALL
        .iter()
        .map(|role| role.pinned_kind())
        .collect();
    assert_eq!(
        kinds,
        [
            ComponentKind::GuestImage,
            ComponentKind::GuestKernel,
            ComponentKind::GuestInitrd,
            ComponentKind::Firmware,
            ComponentKind::GuestProfile,
        ]
    );
    for role in ArtifactRole::ALL {
        assert_eq!(role.component(), Some(role.pinned_kind()));
    }
}

#[test]
fn the_link_protocol_and_the_profile_must_be_this_hosts() {
    let other_protocol =
        release_with(|document| document.agent.link_protocol = PROTOCOL_VERSION + 1);
    let row = row(&other_protocol.record);
    assert_eq!(
        selection_of(&other_protocol, &row, &strict(), None, NOW).map(|_| ()),
        Err(SelectionRefusal::LinkProtocol {
            image: PROTOCOL_VERSION + 1,
            host: PROTOCOL_VERSION
        })
    );
    let developer_only = release_with(|document| document.workloads = vec![workload(&developer())]);
    assert_eq!(
        selection_of(&developer_only, &row, &strict(), None, NOW).map(|_| ()),
        Err(SelectionRefusal::ProfileNotInstalled {
            workload: WorkloadProfile::StrictTool,
            profile: strict().digest()
        })
    );
    let other_strict = release_with(|document| {
        document.workloads[1].confinement_profile =
            digest("yougori/test/profile/v1", &[b"old strict"]);
    });
    assert!(matches!(
        selection_of(&other_strict, &row, &strict(), None, NOW),
        Err(SelectionRefusal::ProfileNotInstalled { .. })
    ));
    let io_uring = release_with(|document| {
        let kernel = document.kernel.kernel_image();
        document.kernel =
            KernelBuildRecord::new(kernel, [(KernelOption::IoUring, OptionState::BuiltIn)])
                .unwrap();
    });
    assert_eq!(
        selection_of(&io_uring, &row, &strict(), None, NOW).map(|_| ()),
        Err(SelectionRefusal::KernelRequirement {
            failure: KernelRequirementFailure::OptionNotAbsent {
                option: KernelOption::IoUring,
                state: Some(OptionState::BuiltIn)
            }
        })
    );
    // The developer profile does not rely on the kernel for io_uring.
    assert!(selection_of(&io_uring, &row, &developer(), None, NOW).is_ok());
}

#[test]
fn every_refusal_reads_as_text_and_json() {
    let refusals = [
        SelectionRefusal::Expired {
            expires_at: UnixSeconds::new(1),
            now: UnixSeconds::new(2),
        },
        SelectionRefusal::LinkProtocol { image: 2, host: 1 },
        SelectionRefusal::DeviceAbsent {
            device: DeviceModel::VirtioRng,
        },
        SelectionRefusal::Fingerprint {
            detail: "x".to_owned(),
        },
    ];
    for refusal in &refusals {
        assert!(!refusal.to_string().is_empty());
        assert!(serde_json::to_value(refusal).unwrap()["kind"].is_string());
    }
}

/// The JSON pointer of every string of the document `bytes` that names a variant of an
/// enum `T` reads, with the index serde gives the variant: `T` refuses a string no enum
/// names in its place as an unknown variant and lists the names in order.
fn variant_indices<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Vec<(String, u64)> {
    use serde_json::Value;
    const PROBE: &str = "vst2_no_such_variant";
    fn strings(value: &Value, pointer: String, found: &mut Vec<(String, String)>) {
        match value {
            Value::String(text) => found.push((pointer, text.clone())),
            Value::Object(fields) => {
                for (key, field) in fields {
                    let key = key.replace('~', "~0").replace('/', "~1");
                    strings(field, format!("{pointer}/{key}"), found);
                }
            }
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    strings(item, format!("{pointer}/{index}"), found);
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }
    let value: Value = serde_json::from_slice(bytes).unwrap();
    let mut found = Vec::new();
    strings(&value, String::new(), &mut found);
    found
        .into_iter()
        .filter_map(|(pointer, name)| {
            let mut probe = value.clone();
            *probe.pointer_mut(&pointer)? = Value::from(PROBE);
            let message = serde_json::from_value::<T>(probe).err()?.to_string();
            let (_, listed) =
                message.split_once(&format!("unknown variant `{PROBE}`, expected "))?;
            let index = listed
                .split('`')
                .skip(1)
                .step_by(2)
                .position(|candidate| candidate == name)?;
            Some((pointer, u64::try_from(index).unwrap()))
        })
        .collect()
}

/// `foundation::strict_serde` (the S06 item "Strict tags of read-back tagged enums" of
/// docs/combined-plan-leftover-tasks.md): a manifest and a build record hold no internally
/// or adjacently tagged enum, the one form serde reads a number for once it has buffered a
/// record, so each is read straight from its bytes. Signed by the release key, a manifest
/// with a variant name swapped for the variant's index, with an artifact role's index as a
/// key, or with a key written twice, is still refused when it is read; so is such a build
/// record.
#[test]
fn a_signed_manifest_with_a_number_for_a_variant_or_a_repeated_key_is_refused() {
    let release = release();
    let manifest = release.manifest.canonical_bytes();
    let record = release.record.canonical_bytes();
    let verify = |bytes: &[u8]| {
        verify_release(
            bytes,
            record,
            &sign(RELEASE, bytes),
            &roots(),
            UnixSeconds::new(NOW),
        )
    };
    let manifest_refused = |bytes: &[u8]| {
        matches!(
            verify(bytes),
            Err(VerifyRefusal::Manifest {
                error: ManifestError::Document { .. }
            })
        )
    };
    let record_refused = |bytes: &[u8]| {
        matches!(
            BuildRecord::from_canonical(bytes),
            Err(RecordError::Document { .. })
        )
    };
    assert!(verify(manifest).is_ok());
    assert!(BuildRecord::from_canonical(record).is_ok());

    // Every variant name by its index.
    let named = variant_indices::<ManifestDocument>(manifest);
    for (pointer, index) in &named {
        let bytes = edited_json(manifest, |value| {
            *value.pointer_mut(pointer).unwrap() = serde_json::json!(index);
        });
        assert!(manifest_refused(&bytes), "manifest {pointer}");
    }
    for pointer in [
        "/architecture",
        "/boot",
        "/devices/0",
        "/workloads/0/workload",
    ] {
        assert!(
            named.iter().any(|(found, _)| found == pointer),
            "{pointer}: {named:?}"
        );
    }
    let named = variant_indices::<RecordDocument>(record);
    assert!(
        named.iter().any(|(found, _)| found == "/architecture"),
        "{named:?}"
    );
    for (pointer, index) in &named {
        let bytes = edited_json(record, |value| {
            *value.pointer_mut(pointer).unwrap() = serde_json::json!(index);
        });
        assert!(record_refused(&bytes), "record {pointer}");
    }
    // The kernel's artifact role by its index, as the key of the artifacts.
    let by_index = |bytes: &[u8]| {
        edited_json(bytes, |value| {
            let artifacts = value["artifacts"].as_object_mut().unwrap();
            let kernel = artifacts.remove("kernel").unwrap();
            artifacts.insert("1".to_owned(), kernel);
        })
    };
    assert!(manifest_refused(&by_index(manifest)));
    assert!(record_refused(&by_index(record)));

    // A field, a workload's field and an artifact written twice.
    let text = std::str::from_utf8(manifest).unwrap();
    let value: serde_json::Value = serde_json::from_slice(manifest).unwrap();
    let kernel =
        String::from_utf8(super::canonical::encode(&value["artifacts"]["kernel"]).unwrap())
            .unwrap();
    let workload = value["workloads"][0]["workload"].as_str().unwrap();
    for field in [
        format!(r#""release":{}"#, value["release"]),
        format!(r#""workload":"{workload}""#),
        format!(r#""kernel":{kernel}"#),
    ] {
        assert!(text.contains(&field), "{field}");
        let twice = text.replacen(&field, &format!("{field},{field}"), 1);
        assert!(manifest_refused(twice.as_bytes()), "{field} twice");
    }
    let text = std::str::from_utf8(record).unwrap();
    let field = r#""format":1"#;
    assert!(text.contains(field));
    let twice = text.replacen(field, &format!("{field},{field}"), 1);
    assert!(record_refused(twice.as_bytes()), "{field} twice");
}
