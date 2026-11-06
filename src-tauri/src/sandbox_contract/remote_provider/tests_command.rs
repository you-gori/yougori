//! The typed values, the exact runpodctl argv, the limits and the strict parsing, on
//! fixtures. Nothing here runs runpodctl.

use std::time::Duration;

use super::command::{CommandKind, RunPodCommand, RunPodSettings, RunpodctlLimits};
use super::fakes::{catalog, offering_name, region, spec, GPU, OFFERING};
use super::parse::{
    account_keys, created_pod, error_object, failure_messages, pod_detail, pod_listing, recognise,
    recognise_any, ParseProblem, Recognised, SshAddress,
};
use super::values::{
    CatalogRefusal, ContainerImage, GpuTypeId, PodId, PodName, PodStatus, RunPodCatalog,
    ValueProblem, POD_NAME_KEY_BYTES, POD_NAME_PREFIX, UNLISTED_OFFERING_PREFIX,
};
use crate::sandbox_contract::destinations::{
    AddressClass, DestinationHost, HostAddressGeneration, HostAddressState,
};
use crate::sandbox_contract::remote::fakes::attempt;
use crate::sandbox_contract::remote::ProviderError;
use crate::sandbox_contract::remote_ssh::{
    SshLimit, SshLimitsRefusal, SshOutput, SshTermination, MAX_DEADLINE, MAX_OUTPUT_BYTES,
};

fn words(list: &[&str]) -> Vec<String> {
    list.iter().map(|word| (*word).to_owned()).collect()
}

#[test]
fn commands_render_exact_argv_from_typed_values_ending_in_json_output() {
    let name = PodName::for_attempt(&attempt(1));
    let create = RunPodCommand::CreatePod {
        name: name.clone(),
        spec: spec(GPU, 2),
        region: region("EU-RO-1"),
    };
    assert_eq!(create.kind(), CommandKind::CreatePod);
    assert_eq!(
        create.arguments(),
        words(&[
            "pod",
            "create",
            "--name",
            name.as_str(),
            "--image",
            "runpod/pytorch:2.4.0-py3.11-cuda12.4.1",
            "--compute-type",
            "GPU",
            "--gpu-id",
            "NVIDIA A40",
            "--gpu-count",
            "2",
            "--cloud-type",
            "SECURE",
            "--data-center-ids",
            "EU-RO-1",
            "--container-disk-in-gb",
            "40",
            "--ports",
            "22/tcp",
            "--output",
            "json",
        ])
    );
    let pod = PodId::new("abc123xyz").unwrap();
    let cases = [
        (
            RunPodCommand::ListPods,
            CommandKind::ListPods,
            words(&["pod", "list", "--all", "--output", "json"]),
        ),
        (
            RunPodCommand::GetPod { pod: pod.clone() },
            CommandKind::GetPod,
            words(&["pod", "get", "abc123xyz", "--output", "json"]),
        ),
        (
            RunPodCommand::DeletePod { pod },
            CommandKind::DeletePod,
            words(&["pod", "delete", "abc123xyz", "--output", "json"]),
        ),
        (
            RunPodCommand::ListSshKeys,
            CommandKind::ListSshKeys,
            words(&["ssh", "list-keys", "--output", "json"]),
        ),
    ];
    for (command, kind, argv) in cases {
        assert_eq!(command.kind(), kind);
        assert_eq!(command.arguments(), argv);
    }
    // No value can be read as a flag: every typed value starts with a letter or digit.
    for argument in create.arguments().iter().skip(2).step_by(2) {
        assert!(argument.starts_with("--"), "{argument}");
    }
    for value in create.arguments().iter().skip(3).step_by(2) {
        assert!(!value.starts_with('-'), "{value}");
    }
}

#[test]
fn typed_values_refuse_anything_runpodctl_could_misread() {
    assert!(GpuTypeId::new("NVIDIA GeForce RTX 4090").is_ok());
    assert!(GpuTypeId::new("AMD Instinct MI300X OAM").is_ok());
    for (bad, problem) in [
        ("", ValueProblem::Empty),
        ("--gpu-id", ValueProblem::InvalidEdge),
        ("NVIDIA A40 ", ValueProblem::InvalidEdge),
        ("NVIDIA;A40", ValueProblem::InvalidCharacter),
        ("NVIDIA\nA40", ValueProblem::InvalidCharacter),
    ] {
        assert_eq!(GpuTypeId::new(bad), Err(problem), "{bad:?}");
    }
    assert!(matches!(
        GpuTypeId::new("A".repeat(129)),
        Err(ValueProblem::TooLong { max_bytes: 128 })
    ));
    assert!(ContainerImage::new("ghcr.io/org/image@sha256:abc").is_ok());
    for bad in ["-image", "image name", "image$(id)", "/root"] {
        assert!(ContainerImage::new(bad).is_err(), "{bad:?}");
    }
    assert!(PodId::new("abc123").is_ok());
    for bad in ["", "-abc", "abc-123", "abc 123", "abc/123"] {
        assert!(PodId::new(bad).is_err(), "{bad:?}");
    }
    // Values read back go through the same checks.
    assert!(serde_json::from_str::<PodId>("\"--all\"").is_err());
    assert_eq!(
        serde_json::from_str::<GpuTypeId>("\"NVIDIA A40\"").unwrap(),
        GpuTypeId::new(GPU).unwrap()
    );
    let mut value = serde_json::to_value(spec(GPU, 1)).unwrap();
    value["env"] = serde_json::json!({"SECRET": "x"});
    assert!(serde_json::from_value::<super::values::PodSpec>(value).is_err());
}

#[test]
fn the_pod_name_carries_the_attempts_key_and_is_matched_as_runpod_may_store_it() {
    let name = PodName::for_attempt(&attempt(7));
    let hex = attempt(7).digest().to_hex();
    assert_eq!(
        name.as_str(),
        format!("{POD_NAME_PREFIX}{}", &hex[..POD_NAME_KEY_BYTES * 2])
    );
    assert_eq!(name.as_str().len(), 40);
    assert_ne!(name, PodName::for_attempt(&attempt(8)));
    assert!(name.carried_by(name.as_str()));
    assert!(name.carried_by(&format!("  {}  ", name.as_str().to_ascii_uppercase())));
    assert!(!name.carried_by(&format!("{}-copy", name.as_str())));
    assert!(!name.carried_by(&name.as_str()[..39]));
}

#[test]
fn the_catalog_refuses_bad_entries_and_maps_a_delivered_gpu_back_to_an_offering() {
    assert_eq!(RunPodCatalog::new([]), Err(CatalogRefusal::Empty));
    assert_eq!(
        RunPodCatalog::new([
            (offering_name("a"), spec(GPU, 1)),
            (offering_name("a"), spec(GPU, 2))
        ]),
        Err(CatalogRefusal::Duplicate {
            offering: offering_name("a")
        })
    );
    assert!(matches!(
        RunPodCatalog::new([(offering_name("unlisted-x"), spec(GPU, 1))]),
        Err(CatalogRefusal::ReservedName { .. })
    ));
    assert!(matches!(
        RunPodCatalog::new([(offering_name("a"), spec(GPU, 9))]),
        Err(CatalogRefusal::GpuCount { count: 9, .. })
    ));
    let mut small = spec(GPU, 1);
    small.container_disk_gb = 4;
    assert!(matches!(
        RunPodCatalog::new([(offering_name("a"), small)]),
        Err(CatalogRefusal::ContainerDisk { gb: 4, .. })
    ));
    let catalog = catalog();
    let requested = offering_name(OFFERING);
    let a40 = GpuTypeId::new(GPU).unwrap();
    let h100 = GpuTypeId::new("NVIDIA H100 80GB HBM3").unwrap();
    assert_eq!(
        catalog.delivered_offering(&requested, &a40, 1),
        Some(requested.clone())
    );
    assert_eq!(
        catalog.delivered_offering(&requested, &h100, 1),
        Some(offering_name("pod-h100"))
    );
    let unlisted = catalog.delivered_offering(&requested, &a40, 2).unwrap();
    assert!(unlisted.as_str().starts_with(UNLISTED_OFFERING_PREFIX));
    assert_ne!(
        Some(unlisted),
        catalog.delivered_offering(&requested, &GpuTypeId::new("NVIDIA L4").unwrap(), 1)
    );
}

#[test]
fn statuses_outside_runpods_set_are_unknown_and_only_terminated_is_gone() {
    for status in [
        PodStatus::Created,
        PodStatus::Running,
        PodStatus::Restarting,
        PodStatus::Exited,
        PodStatus::Paused,
        PodStatus::Dead,
    ] {
        assert_eq!(PodStatus::parse(status.word()), Some(status));
        assert!(status.exists());
    }
    assert_eq!(PodStatus::parse("terminated"), Some(PodStatus::Terminated));
    assert!(!PodStatus::Terminated.exists());
    for unknown in ["", "MIGRATING", "RUNNING ", "STOPPED"] {
        assert_eq!(PodStatus::parse(unknown), None, "{unknown:?}");
    }
}

#[test]
fn limits_are_checked_with_the_ssh_limits_ranges() {
    assert_eq!(
        RunpodctlLimits::new(Duration::from_secs(40), 4 << 20, 256 << 10),
        Ok(RunpodctlLimits::QUERY)
    );
    assert_eq!(
        RunpodctlLimits::new(Duration::from_millis(999), 1, 1),
        Err(SshLimitsRefusal::OutOfRange {
            limit: SshLimit::Deadline,
            min: 1,
            max: MAX_DEADLINE.as_secs()
        })
    );
    assert_eq!(
        RunpodctlLimits::new(Duration::from_secs(1), 0, 1),
        Err(SshLimitsRefusal::OutOfRange {
            limit: SshLimit::MaxStdout,
            min: 1,
            max: MAX_OUTPUT_BYTES
        })
    );
    assert_eq!(
        RunpodctlLimits::new(Duration::from_secs(1), 1, MAX_OUTPUT_BYTES + 1),
        Err(SshLimitsRefusal::OutOfRange {
            limit: SshLimit::MaxStderr,
            min: 1,
            max: MAX_OUTPUT_BYTES
        })
    );
    let settings = RunPodSettings::STANDARD;
    assert_eq!(
        settings.limits(CommandKind::CreatePod),
        RunpodctlLimits::CREATE
    );
    assert_eq!(settings.limits(CommandKind::GetPod), RunpodctlLimits::QUERY);
    assert_eq!(
        settings.limits(CommandKind::DeletePod),
        RunpodctlLimits::CHANGE
    );
    assert_eq!(settings.listing_settle, Duration::from_secs(120));
}

#[test]
fn created_pod_answers_are_read_strictly() {
    let pod = PodId::new("abc123").unwrap();
    assert_eq!(
        created_pod(br#"{"id":"abc123","extra":1}"#),
        Ok(pod.clone())
    );
    assert_eq!(created_pod(br#"{"pod":{"id":"abc123"}}"#), Ok(pod));
    for (answer, problem) in [
        (&b"Pod abc123 created"[..], ParseProblem::NotJson),
        (b"[]", ParseProblem::NotAnObject),
        (b"{}", ParseProblem::Missing { field: "id" }),
        (br#"{"id":7}"#, ParseProblem::WrongType { field: "id" }),
        (br#"{"id":"--all"}"#, ParseProblem::BadPodId),
        (
            br#"{"pod":"abc123"}"#,
            ParseProblem::WrongType { field: "pod" },
        ),
        (b"{\"id\":\"abc\xff\"}", ParseProblem::NotJson),
    ] {
        assert_eq!(created_pod(answer), Err(problem), "{answer:?}");
    }
}

#[test]
fn listings_are_complete_or_refused_whole() {
    let pods = pod_listing(
        br#"[{"id":"a1","name":"x","desiredStatus":"RUNNING","costPerHr":0.4},
             {"id":"b2","name":null,"desiredStatus":"MIGRATING"},
             {"id":"c3","desiredStatus":"TERMINATED"}]"#,
    )
    .unwrap();
    assert_eq!(pods.len(), 3);
    assert_eq!(pods[0].status, Some(PodStatus::Running));
    assert_eq!(pods[1].name, None);
    assert_eq!(pods[1].status, None);
    assert_eq!(pods[2].status, Some(PodStatus::Terminated));
    assert_eq!(pod_listing(b"[]"), Ok(Vec::new()));
    for (listing, problem) in [
        (&b""[..], ParseProblem::NotJson),
        (b"No pods found", ParseProblem::NotJson),
        (br#"{"pods":[]}"#, ParseProblem::NotAList),
        (br#"[1]"#, ParseProblem::NotAnObject),
        (
            br#"[{"name":"x","desiredStatus":"RUNNING"}]"#,
            ParseProblem::Missing { field: "id" },
        ),
        (
            br#"[{"id":"a1","name":"x"}]"#,
            ParseProblem::Missing {
                field: "desiredStatus",
            },
        ),
        (
            br#"[{"id":"a1","name":5,"desiredStatus":"RUNNING"}]"#,
            ParseProblem::WrongType { field: "name" },
        ),
        (
            concat!(
                r#"[{"id":"a1","name":"x","desiredStatus":"RUNNING"},"#,
                r#"{"id":"a1","name":"y","desiredStatus":"EXITED"}]"#
            )
            .as_bytes(),
            ParseProblem::DuplicatePod,
        ),
    ] {
        assert_eq!(pod_listing(listing), Err(problem), "{listing:?}");
    }
}

fn public_host() -> HostAddressState {
    HostAddressState::new(HostAddressGeneration::FIRST, [])
}

#[test]
fn pod_details_give_what_was_delivered_and_a_public_ssh_address_only() {
    let pod = PodId::new("a1").unwrap();
    let detail = pod_detail(
        br#"{"id":"a1","name":"n","desiredStatus":"RUNNING","gpuTypeId":"NVIDIA A40",
             "gpuCount":1,"machine":{"dataCenterId":"EU-RO-1"},
             "ssh":{"ip":"194.68.245.20","port":22101}}"#,
        &pod,
    )
    .unwrap();
    let delivered = detail.delivered().unwrap();
    assert_eq!(delivered.region, region("EU-RO-1"));
    assert_eq!(delivered.gpu, GpuTypeId::new(GPU).unwrap());
    assert_eq!(delivered.gpu_count, 1);
    let SshAddress::Public(authority) = detail.ssh(&public_host()).unwrap() else {
        panic!("not public");
    };
    assert_eq!(
        authority.host,
        DestinationHost::Address("194.68.245.20".parse().unwrap())
    );
    assert_eq!(authority.port.get(), 22_101);

    assert_eq!(
        pod_detail(br#"{"id":"b2","desiredStatus":"RUNNING"}"#, &pod),
        Err(ParseProblem::OtherPod)
    );
    assert_eq!(
        pod_detail(br#"{"id":"a1","desiredStatus":"SLEEPING"}"#, &pod),
        Err(ParseProblem::UnknownStatus)
    );
    let base = |extra: &str| {
        format!(
            r#"{{"id":"a1","desiredStatus":"RUNNING","gpuTypeId":"{GPU}","gpuCount":1{extra}}}"#
        )
    };
    for (extra, problem) in [
        ("", ParseProblem::Missing { field: "machine" }),
        (
            r#","machine":null"#,
            ParseProblem::WrongType { field: "machine" },
        ),
        (
            r#","machine":{}"#,
            ParseProblem::Missing {
                field: "dataCenterId",
            },
        ),
        (
            r#","machine":{"dataCenterId":"EU RO 1"}"#,
            ParseProblem::BadRegion,
        ),
    ] {
        let detail = pod_detail(base(extra).as_bytes(), &pod).unwrap();
        assert_eq!(detail.delivered(), Err(problem), "{extra}");
    }
    let detail = pod_detail(
        br#"{"id":"a1","desiredStatus":"RUNNING","gpuTypeId":"NVIDIA A40","gpuCount":-1,
             "machine":{"dataCenterId":"EU-RO-1"}}"#,
        &pod,
    )
    .unwrap();
    assert_eq!(detail.delivered(), Err(ParseProblem::BadGpuCount));

    let ssh = |ssh: &str| {
        pod_detail(
            format!(r#"{{"id":"a1","desiredStatus":"RUNNING","ssh":{ssh}}}"#).as_bytes(),
            &pod,
        )
        .unwrap()
        .ssh(&public_host())
    };
    assert_eq!(ssh("null"), Ok(SshAddress::None));
    assert_eq!(ssh(r#"{"ip":"","port":22}"#), Ok(SshAddress::None));
    assert_eq!(
        ssh(r#"{"ip":"010.1.1.1","port":22}"#),
        Err(ParseProblem::BadAddress)
    );
    assert_eq!(
        ssh(r#"{"ip":"194.68.245.20","port":0}"#),
        Err(ParseProblem::BadAddress)
    );
    assert_eq!(
        ssh(r#"{"ip":"194.68.245.20"}"#),
        Err(ParseProblem::Missing { field: "ssh.port" })
    );
    for (ip, class) in [
        ("127.0.0.1", AddressClass::Loopback),
        ("169.254.169.254", AddressClass::Metadata),
        ("203.0.113.7", AddressClass::Documentation),
        ("10.0.0.5", AddressClass::Private),
    ] {
        let Ok(SshAddress::Refused(refusal)) = ssh(&format!(r#"{{"ip":"{ip}","port":22}}"#)) else {
            panic!("{ip} was not refused");
        };
        assert_eq!(refusal.verdict.class, class, "{ip}");
    }
}

#[test]
fn account_keys_are_read_strictly() {
    assert_eq!(
        account_keys(
            br#"{"keys":[{"key":"ssh-ed25519 AAAA one","name":"a"},{"key":"ssh-rsa BBBB"}]}"#
        ),
        Ok(vec!["AAAA".to_owned(), "BBBB".to_owned()])
    );
    assert_eq!(
        account_keys(br#"{}"#),
        Err(ParseProblem::Missing { field: "keys" })
    );
    assert_eq!(
        account_keys(br#"{"keys":[{"name":"a"}]}"#),
        Err(ParseProblem::Missing { field: "key" })
    );
}

fn output(code: i32, stdout: &str, stderr: &str) -> SshOutput {
    SshOutput {
        termination: SshTermination::Exited { code },
        stdout: stdout.as_bytes().to_vec(),
        stderr: stderr.as_bytes().to_vec(),
    }
}

#[test]
fn failure_messages_are_recognised_whole_never_by_substring() {
    let capacity = "There are no longer any instances available with the requested \
                    specifications. Please refresh and try again.";
    let messages = failure_messages(&output(1, &format!(r#"{{"error":"{capacity}"}}"#), ""));
    assert_eq!(
        recognise_any(&messages),
        Some(Recognised::Provider(ProviderError::CapacityUnavailable))
    );
    assert_eq!(
        recognise_any(&failure_messages(&output(1, "", "Error: Unauthorized\n"))),
        Some(Recognised::Provider(ProviderError::Unauthorized))
    );
    // Cobra prints its own refusal first and its usage after it.
    assert_eq!(
        recognise_any(&failure_messages(&output(
            1,
            "",
            "Error: unknown flag: --output\nUsage:\n  runpodctl pod create [flags]\n\n"
        ))),
        Some(Recognised::LocalRefusal)
    );
    for unrecognised in [
        "Error: something went wrong",
        "the request was unauthorized by policy",
        "There are no longer any instances available with the requested specifications, \
         but one was made",
        "pod created; unknown flag: --x ignored",
    ] {
        assert_eq!(
            recognise_any(&failure_messages(&output(1, "", unrecognised))),
            None,
            "{unrecognised}"
        );
    }
    assert_eq!(
        recognise("UNAUTHORIZED"),
        None,
        "messages are normalised first"
    );
    assert_eq!(
        error_object(br#"{"error":"  Error: Unauthorized. "}"#),
        Some("unauthorized".to_owned())
    );
    assert_eq!(error_object(br#"{"error":""}"#), None);
    assert_eq!(error_object(br#"{"id":"a"}"#), None);
    assert!(failure_messages(&output(1, "", "\u{fffd}")).len() == 1);
    assert!(failure_messages(&SshOutput {
        termination: SshTermination::Exited { code: 1 },
        stdout: Vec::new(),
        stderr: vec![0xff, 0xfe],
    })
    .is_empty());
}
