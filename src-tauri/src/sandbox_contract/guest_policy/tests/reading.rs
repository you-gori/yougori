//! Strict reading: round trips, tampering, re-sealed edits and widenings, the invariants
//! that need no profile, unknown fields at every level, closed sets, the size bound, the
//! OCI field names, the seccomp section's shape and the digest bytes (M07A items 6 and 7).

use std::num::NonZeroU32;

use sha2::Digest as _;

use super::*;
use crate::foundation::ids::digest;
use crate::sandbox_contract::confinement::Errno;

fn strict_policy() -> GuestPolicy {
    compiled(&builtin(WorkloadProfile::StrictTool))
}

/// The policy's JSON after `edit`, without re-sealing.
fn edited(policy: &GuestPolicy, edit: impl FnOnce(&mut serde_json::Value)) -> String {
    let mut value = json(policy);
    edit(&mut value);
    serde_json::to_string(&value).unwrap()
}

fn object(value: &mut serde_json::Value) -> &mut serde_json::Map<String, serde_json::Value> {
    value.as_object_mut().unwrap()
}

fn malformed(text: &str) -> bool {
    matches!(
        GuestPolicy::from_json(text),
        Err(PolicyReadRefusal::Malformed { .. })
    )
}

/// What reading `body`, edited by `edit` and re-sealed, refuses for.
fn reseal_refusal(
    policy: &GuestPolicy,
    edit: impl FnOnce(&mut GuestPolicyBody),
) -> Result<GuestPolicy, PolicyReadRefusal> {
    let mut body = policy.body().clone();
    edit(&mut body);
    GuestPolicy::from_json(&resealed(body))
}

fn invariant(
    policy: &GuestPolicy,
    edit: impl FnOnce(&mut GuestPolicyBody),
) -> Option<PolicyInvariant> {
    match reseal_refusal(policy, edit) {
        Err(PolicyReadRefusal::Invariant(invariant)) => Some(invariant),
        _ => None,
    }
}

fn position(policy: &GuestPolicy, interface: Interface) -> usize {
    policy
        .body()
        .seccomp
        .refusals
        .iter()
        .position(|refusal| refusal.interface == interface)
        .unwrap()
}

#[test]
fn every_policy_round_trips_through_strict_json_and_matches_its_compilation() {
    for profile in profiles() {
        let policy = compiled(&profile);
        let text = policy.to_json().unwrap();
        let again = GuestPolicy::from_json(&text).unwrap();
        assert_eq!(again, policy);
        assert_eq!(again.digest(), policy.digest());
        assert_eq!(again.check_against(&profile, &layout()), Ok(()));
        let embedded: GuestPolicy = serde_json::from_str(&text).unwrap();
        assert_eq!(embedded, policy);
    }
    let device = compile(&device_with_lsm_path(), &device_layout()).unwrap();
    let again = GuestPolicy::from_json(&device.to_json().unwrap()).unwrap();
    assert_eq!(
        again.check_against(&device_with_lsm_path(), &device_layout()),
        Ok(())
    );
}

/// One edit of a policy's JSON.
type JsonEdit = Box<dyn Fn(&mut serde_json::Value)>;

#[test]
fn an_edit_without_resealing_is_refused_by_the_digest() {
    let policy = strict_policy();
    let edits: Vec<JsonEdit> = vec![
        Box::new(|value| {
            value["body"]["oci"]["process"]["capabilities"]["bounding"] =
                serde_json::json!(["CAP_NET_RAW"]);
        }),
        Box::new(|value| {
            value["body"]["seccomp"]["refusals"][0]["errno"] = serde_json::json!(38);
        }),
        Box::new(|value| {
            value["body"]["seccomp"]["refusals"]
                .as_array_mut()
                .unwrap()
                .remove(0);
        }),
        Box::new(|value| {
            value["body"]["oci"]["linux"]["readonlyPaths"] = serde_json::json!([]);
        }),
        Box::new(|value| {
            value["body"]["exceptions"] = serde_json::json!([]);
            value["body"]["verification"]
                .as_array_mut()
                .unwrap()
                .remove(0);
        }),
    ];
    for edit in edits {
        let text = edited(&policy, |value| edit(value));
        assert!(
            matches!(
                GuestPolicy::from_json(&text),
                Err(PolicyReadRefusal::DigestMismatch { stored, .. }) if stored == policy.digest()
            ),
            "{text}"
        );
    }
}

#[test]
fn the_reviewers_widened_policy_is_refused_on_read() {
    let policy = strict_policy();
    let text = edited(&policy, |value| {
        let body = &mut value["body"];
        body["oci"]["process"]["user"]["uid"] = 0.into();
        body["oci"]["process"]["user"]["gid"] = 0.into();
        for set in [
            "bounding",
            "effective",
            "inheritable",
            "permitted",
            "ambient",
        ] {
            body["oci"]["process"]["capabilities"][set] = serde_json::json!(["CAP_SYS_ADMIN"]);
        }
        body["oci"]["process"]["noNewPrivileges"] = false.into();
        body["seccomp"]["refusals"] = serde_json::json!([]);
        body["seccomp"]["architectures"] = serde_json::json!([]);
    });
    assert!(malformed(&text));
    // Each part on its own, re-sealed wherever it can be typed at all.
    for (pointer, value) in [
        ("/body/oci/process/user/uid", serde_json::json!(0)),
        ("/body/oci/process/user/gid", serde_json::json!(0)),
        (
            "/body/oci/process/capabilities/bounding",
            serde_json::json!(["CAP_SYS_ADMIN"]),
        ),
    ] {
        let text = edited(&policy, |json| *json.pointer_mut(pointer).unwrap() = value);
        assert!(malformed(&text), "{pointer}");
    }
    assert_eq!(
        invariant(&policy, |body| body.oci.process.no_new_privileges = false),
        Some(PolicyInvariant::NoNewPrivilegesRequired)
    );
    assert_eq!(
        invariant(&policy, |body| body.seccomp.architectures.clear()),
        Some(PolicyInvariant::SeccompArchitectures)
    );
    assert_eq!(
        invariant(&policy, |body| body
            .seccomp
            .architectures
            .retain(|abi| *abi == SeccompArchitecture::X86_64)),
        Some(PolicyInvariant::SeccompArchitectures)
    );
    assert_eq!(
        invariant(&policy, |body| body.seccomp.refusals.clear()),
        Some(PolicyInvariant::SeccompRefusalMissing {
            interface: Interface::IoUring
        })
    );
    let raw = OciCapability::new(LinuxCapability::NetRaw);
    assert_eq!(
        invariant(&policy, |body| {
            body.oci.process.capabilities =
                OciCapabilities::exactly(&[LinuxCapability::NetRaw].into_iter().collect());
        }),
        Some(PolicyInvariant::CapabilityWithoutException {
            capability: LinuxCapability::NetRaw
        })
    );
    assert_eq!(
        invariant(&policy, |body| body.oci.process.capabilities.bounding =
            vec![raw]),
        Some(PolicyInvariant::CapabilitySetsDiffer)
    );
    assert_eq!(
        invariant(&policy, |body| body.oci.process.user = None),
        Some(PolicyInvariant::UserDisagreesWithUidPolicy)
    );
    assert_eq!(
        invariant(&policy, |body| {
            body.oci.process.user = Some(OciUser {
                uid: NonZeroU32::new(1001).unwrap(),
                gid: NonZeroU32::new(1000).unwrap(),
            });
        }),
        Some(PolicyInvariant::UserDisagreesWithUidPolicy)
    );
    let service = compiled(&builtin(WorkloadProfile::Service));
    assert_eq!(
        invariant(&service, |body| {
            body.oci.process.user = Some(OciUser {
                uid: NonZeroU32::new(1000).unwrap(),
                gid: NonZeroU32::new(1000).unwrap(),
            });
        }),
        Some(PolicyInvariant::UserDisagreesWithUidPolicy)
    );
    let raw_developer = compiled(&developer_with_net_raw());
    assert_eq!(
        invariant(&raw_developer, |body| body.exceptions.clear()),
        Some(PolicyInvariant::CapabilityWithoutException {
            capability: LinuxCapability::NetRaw
        })
    );
}

#[test]
fn a_resealed_seccomp_forgery_breaks_an_invariant() {
    let policy = strict_policy();
    let vsock = position(&policy, Interface::VsockSocket);
    assert_eq!(
        invariant(&policy, |body| {
            body.seccomp.refusals.remove(vsock);
        }),
        Some(PolicyInvariant::SeccompRefusalMissing {
            interface: Interface::VsockSocket
        })
    );
    // Dropping the plan's step too still leaves AF_VSOCK, which every profile refuses by
    // seccomp alone.
    assert_eq!(
        invariant(&policy, |body| {
            body.seccomp.refusals.remove(vsock);
            body.verification
                .retain(|step| step.interface != Interface::VsockSocket);
        }),
        Some(PolicyInvariant::SeccompRefusalMissing {
            interface: Interface::VsockSocket
        })
    );
    // AF_INET instead of AF_VSOCK: a rule no interface compiles to.
    assert_eq!(
        invariant(&policy, |body| {
            if let Some(argument) = body.seccomp.refusals[vsock].rules[0].argument.as_mut() {
                argument.value = 2;
            }
        }),
        Some(PolicyInvariant::SeccompRefusalNotCompiled {
            interface: Interface::VsockSocket
        })
    );
    assert_eq!(
        invariant(&policy, |body| {
            if let Some(argument) = body.seccomp.refusals[vsock].rules[0].argument.as_mut() {
                argument.mask = 0xff;
            }
        }),
        Some(PolicyInvariant::SeccompRefusalNotCompiled {
            interface: Interface::VsockSocket
        })
    );
    assert_eq!(
        invariant(&policy, |body| body.seccomp.refusals[0].errno =
            Errno::ENOSYS),
        Some(PolicyInvariant::SeccompRefusalNotCompiled {
            interface: Interface::IoUring
        })
    );
    let ptrace = position(&policy, Interface::Ptrace);
    assert_eq!(
        invariant(&policy, |body| {
            body.seccomp.refusals[ptrace].rules[0].syscalls = vec![Syscall::Ptrace];
        }),
        Some(PolicyInvariant::SeccompRefusalNotCompiled {
            interface: Interface::Ptrace
        })
    );
    assert_eq!(
        invariant(&policy, |body| body.seccomp.refusals.reverse()),
        Some(PolicyInvariant::SeccompRefusalNotCompiled {
            interface: Interface::Ptrace
        })
    );
    let developer = compiled(&builtin(WorkloadProfile::Developer));
    assert_eq!(
        invariant(&developer, |body| {
            let at = body
                .seccomp
                .refusals
                .iter()
                .position(|refusal| refusal.interface > Interface::Ptrace)
                .unwrap();
            let refusal = SeccompRefusal::compiled(Interface::Ptrace).unwrap();
            body.seccomp.refusals.insert(at, refusal);
        }),
        Some(PolicyInvariant::SeccompRefusalUndeclared {
            interface: Interface::Ptrace
        })
    );
    let landlock = compiled(&device_with_lsm_path());
    assert_eq!(
        invariant(&landlock, |body| {
            if let Some(ruleset) = body.lsm.landlock.as_mut() {
                ruleset.restriction = LandlockRestriction::CapSysAdminBeforeCapabilityDrop;
            }
        }),
        Some(PolicyInvariant::LandlockRestrictionDisagrees)
    );
    let no_nnp = compiled(&device_with_lsm_path_without_no_new_privs());
    assert_eq!(
        invariant(&no_nnp, |body| {
            if let Some(ruleset) = body.lsm.landlock.as_mut() {
                ruleset.restriction = LandlockRestriction::NoNewPrivileges;
            }
        }),
        Some(PolicyInvariant::LandlockRestrictionDisagrees)
    );
}

#[test]
fn a_resealed_edit_within_the_invariants_is_caught_by_recompiling() {
    let profile = builtin(WorkloadProfile::StrictTool);
    let policy = compiled(&profile);
    let read = reseal_refusal(&policy, |body| {
        body.oci.linux.readonly_paths.pop();
    })
    .unwrap();
    assert_eq!(
        read.check_against(&profile, &layout()),
        Err(PolicyReadRefusal::DiffersFromCompilation)
    );
    assert_eq!(
        policy.check_against(&profile, &layout_with(&["/tmp"])),
        Err(PolicyReadRefusal::DiffersFromCompilation)
    );
    let developer = builtin(WorkloadProfile::Developer);
    assert_eq!(
        policy.check_against(&developer, &layout()),
        Err(PolicyReadRefusal::OtherProfile {
            policy: profile.digest(),
            profile: developer.digest(),
        })
    );
}

#[test]
fn unknown_fields_are_refused_at_every_level() {
    let strict = strict_policy();
    let landlock = compiled(&device_with_lsm_path());
    let perf = compiled(&strict_with_perf());
    let vsock = position(&strict, Interface::VsockSocket);
    let argument = format!("/body/seccomp/refusals/{vsock}/rules/0/argument");
    let pointers = [
        "",
        "/body",
        "/body/layout",
        "/body/oci",
        "/body/oci/process",
        "/body/oci/process/user",
        "/body/oci/process/capabilities",
        "/body/oci/linux",
        "/body/seccomp",
        "/body/seccomp/refusals/0",
        "/body/seccomp/refusals/0/rules/0",
        argument.as_str(),
        "/body/protected_paths",
        "/body/protected_paths/paths/0",
        "/body/lsm",
        "/body/lsm/yama",
        "/body/kernel",
        "/body/verification/0",
        "/body/verification/0/mechanisms/0",
        // A unit variant: serde alone would ignore a field beside its tag.
        "/body/verification/0/verified_by/0",
    ];
    for pointer in pointers {
        let text = edited(&strict, |value| {
            object(value.pointer_mut(pointer).unwrap()).insert("extra".into(), 1.into());
        });
        assert!(malformed(&text), "{pointer}");
    }
    for pointer in ["/body/lsm/landlock", "/body/lsm/landlock/rules/0"] {
        let text = edited(&landlock, |value| {
            object(value.pointer_mut(pointer).unwrap()).insert("extra".into(), 1.into());
        });
        assert!(malformed(&text), "{pointer}");
    }
    for pointer in [
        "/body/exceptions/0",
        "/body/exceptions/0/exception",
        "/body/exceptions/0/effect",
        "/body/exceptions/0/effect/rules/0",
    ] {
        let text = edited(&perf, |value| {
            object(value.pointer_mut(pointer).unwrap()).insert("extra".into(), 1.into());
        });
        assert!(malformed(&text), "{pointer}");
    }
}

#[test]
fn another_version_and_values_outside_the_closed_sets_are_refused() {
    let strict = strict_policy();
    let landlock = compiled(&device_with_lsm_path());
    let cases: Vec<(&GuestPolicy, &str, serde_json::Value)> = vec![
        (&strict, "/body/version", 1.into()),
        (&strict, "/body/version", 3.into()),
        (&strict, "/body/meaning", "boundary".into()),
        (&strict, "/body/seccomp/base_filter", "none".into()),
        (&strict, "/body/seccomp/architectures/0", "x86".into()),
        (
            &strict,
            "/body/seccomp/architectures/0",
            "SCMP_ARCH_X86_64".into(),
        ),
        (
            &strict,
            "/body/seccomp/refusals/0/interface",
            "everything".into(),
        ),
        (
            &strict,
            "/body/seccomp/refusals/0/rules/0/syscalls/0",
            "openat".into(),
        ),
        (&strict, "/body/seccomp/refusals/0/errno", 0.into()),
        (
            &strict,
            "/body/oci/linux/readonlyPaths/0",
            "relative/path".into(),
        ),
        (
            &strict,
            "/body/oci/linux/readonlyPaths/0",
            "/home/agent/../root".into(),
        ),
        (
            &strict,
            "/body/oci/process/capabilities/bounding",
            serde_json::json!(["CAP_EVERYTHING"]),
        ),
        (
            &strict,
            "/body/oci/process/capabilities/bounding",
            serde_json::json!(["sys_admin"]),
        ),
        (
            &strict,
            "/body/oci/process/capabilities/ambient",
            serde_json::json!(["CAP_SYS_MODULE"]),
        ),
        (&strict, "/body/oci/process/user/uid", (-1).into()),
        (&strict, "/body/lsm/yama/ptrace_scope", 0.into()),
        (&strict, "/body/lsm/yama/ptrace_scope", 3.into()),
        (
            &strict,
            "/body/verification/0/verified_by/0/by",
            "host_says_so".into(),
        ),
        (&strict, "/body/uid/policy", "root".into()),
        (&landlock, "/body/lsm/landlock/abi", 2.into()),
        (&landlock, "/body/lsm/landlock/restriction", "none".into()),
        (
            &landlock,
            "/body/lsm/landlock/rules/0/grant",
            "anything".into(),
        ),
        (
            &landlock,
            "/body/lsm/landlock/handled_access_fs/0",
            "LANDLOCK_ACCESS_FS_EXECUTE".into(),
        ),
    ];
    for (policy, pointer, replacement) in cases {
        let text = edited(policy, |value| {
            *value.pointer_mut(pointer).unwrap() = replacement.clone();
        });
        assert!(malformed(&text), "{pointer} = {replacement}");
    }
    let removed = edited(&strict, |value| {
        object(value.pointer_mut("/body/seccomp").unwrap()).remove("base_filter");
    });
    assert!(malformed(&removed));
    assert!(malformed("not json"));
    let oversized = " ".repeat(MAX_GUEST_POLICY_BYTES + 1);
    assert_eq!(
        GuestPolicy::from_json(&oversized),
        Err(PolicyReadRefusal::TooLarge {
            bytes: MAX_GUEST_POLICY_BYTES + 1,
            max: MAX_GUEST_POLICY_BYTES,
        })
    );
}

#[test]
fn the_oci_section_alone_is_never_a_seccomp_profile() {
    for profile in profiles() {
        let value = json(&compiled(&profile));
        let oci = &value["body"]["oci"];
        let mut found = Vec::new();
        keys(oci, &mut found);
        for forbidden in ["seccomp", "defaultAction", "syscalls", "architectures"] {
            assert!(!found.iter().any(|key| key == forbidden), "{forbidden}");
        }
        let text = serde_json::to_string(oci).unwrap();
        assert!(!text.contains("SCMP_"), "{text}");
        // Read as the fragment it is, it refuses a seccomp member outright.
        let mut with_seccomp = oci.clone();
        object(&mut with_seccomp["linux"]).insert(
            "seccomp".into(),
            serde_json::json!({ "defaultAction": "SCMP_ACT_ALLOW", "syscalls": [] }),
        );
        assert!(serde_json::from_value::<OciFragment>(with_seccomp).is_err());
        assert!(serde_json::from_value::<OciFragment>(oci.clone()).is_ok());
        // The seccomp section has no default action and carries its requirement.
        let seccomp = &value["body"]["seccomp"];
        assert_eq!(seccomp["base_filter"], "runtime_deny_by_default");
        let mut section = Vec::new();
        keys(seccomp, &mut section);
        for absent in ["defaultAction", "default_action", "action", "names"] {
            assert!(!section.iter().any(|key| key == absent), "{absent}");
        }
    }
    let strict = strict_policy();
    let smuggled = edited(&strict, |value| {
        object(value.pointer_mut("/body/oci/linux").unwrap()).insert(
            "seccomp".into(),
            serde_json::json!({ "defaultAction": "SCMP_ACT_ALLOW" }),
        );
    });
    assert!(malformed(&smuggled));
    let defaulted = edited(&strict, |value| {
        object(value.pointer_mut("/body/seccomp").unwrap())
            .insert("defaultAction".into(), "SCMP_ACT_ALLOW".into());
    });
    assert!(malformed(&defaulted));
}

#[test]
fn the_oci_fragment_uses_the_runtime_specs_field_names_and_values() {
    let allowed = [
        "process",
        "linux",
        "user",
        "uid",
        "gid",
        "capabilities",
        "bounding",
        "effective",
        "inheritable",
        "permitted",
        "ambient",
        "noNewPrivileges",
        "readonlyPaths",
    ];
    for profile in profiles() {
        let value = json(&compiled(&profile));
        let mut found = Vec::new();
        keys(&value["body"]["oci"], &mut found);
        for key in &found {
            assert!(allowed.contains(&key.as_str()), "{key}");
        }
    }
    let value = json(&strict_policy());
    let oci = &value["body"]["oci"];
    assert_eq!(oci["process"]["noNewPrivileges"], true);
    assert_eq!(oci["process"]["user"]["uid"], 1000);
    assert_eq!(
        oci["linux"]["readonlyPaths"],
        serde_json::json!([
            "/home/agent/.bashrc",
            "/home/agent/.config/git",
            "/home/agent/.gitconfig",
            "/workspace/.git",
            "/workspace/.git/hooks"
        ])
    );
    let seccomp = &value["body"]["seccomp"];
    assert_eq!(
        seccomp["architectures"],
        serde_json::json!(["x86_64", "aarch64"])
    );
    let refusals = seccomp["refusals"].as_array().unwrap();
    assert_eq!(refusals[0]["interface"], "io_uring");
    assert_eq!(refusals[0]["errno"], 1);
    assert_eq!(
        refusals[0]["rules"],
        serde_json::json!([{
            "syscalls": ["io_uring_enter", "io_uring_register", "io_uring_setup"]
        }])
    );
    let vsock = refusals
        .iter()
        .find(|refusal| refusal["interface"] == "vsock_socket")
        .unwrap();
    assert_eq!(
        vsock["rules"],
        serde_json::json!([{
            "syscalls": ["socket"],
            "argument": { "index": 0, "mask": 4294967295u64, "value": 40 }
        }])
    );
    let userfaultfd = refusals
        .iter()
        .find(|refusal| refusal["interface"] == "userfaultfd")
        .unwrap();
    assert_eq!(
        userfaultfd["rules"][1],
        serde_json::json!({
            "syscalls": ["ioctl"],
            "argument": { "index": 1, "mask": 4294967295u64, "value": 43520 }
        })
    );
    let service = json(&compiled(&builtin(WorkloadProfile::Service)));
    assert_eq!(
        service["body"]["oci"]["process"]["capabilities"]["bounding"],
        serde_json::json!(["CAP_NET_BIND_SERVICE"])
    );
    assert!(service["body"]["oci"]["process"].get("user").is_none());
    let mut found = Vec::new();
    keys(&value, &mut found);
    for absent in [
        "rlimits",
        "maskedPaths",
        "root",
        "readonly",
        "errnoRet",
        "valueTwo",
    ] {
        assert!(!found.iter().any(|key| key == absent), "{absent}");
    }
}

#[test]
fn the_digest_covers_exactly_the_compact_body_bytes_the_go_side_hashes() {
    for profile in profiles() {
        let policy = compiled(&profile);
        let compact_body = serde_json::to_vec(policy.body()).unwrap();
        assert_eq!(
            digest(GUEST_POLICY_DOMAIN, &[&compact_body]),
            policy.digest()
        );
        // The stored file's raw `body` member with whitespace removed, as json.Compact
        // leaves it, is the same bytes.
        let text = policy.to_json().unwrap();
        let start = text.find("\"body\": ").unwrap() + "\"body\": ".len();
        let end = text.rfind('}').unwrap();
        let raw = text[start..end].trim_end();
        assert_eq!(compact(raw).as_bytes(), compact_body.as_slice());
        // The framing, spelled out: lengths as big-endian u64 before the domain and B.
        let domain = GUEST_POLICY_DOMAIN.as_bytes();
        let mut hasher = sha2::Sha256::new();
        hasher.update(u64::try_from(domain.len()).unwrap().to_be_bytes());
        hasher.update(domain);
        hasher.update(u64::try_from(compact_body.len()).unwrap().to_be_bytes());
        hasher.update(&compact_body);
        assert_eq!(hex::encode(hasher.finalize()), policy.digest().to_hex());
        assert!(text.contains(&format!("\"digest\": \"{}\"", policy.digest().to_hex())));
    }
}

#[test]
fn every_policy_states_that_its_controls_are_defense_in_depth() {
    for profile in profiles() {
        let policy = compiled(&profile);
        assert_eq!(
            policy.body().meaning,
            PolicyMeaning::InnerControlsDefenseInDepth
        );
        assert_eq!(
            policy.body().seccomp.base_filter,
            BaseFilterRequirement::RuntimeDenyByDefault
        );
        let value = json(&policy);
        assert_eq!(value["body"]["meaning"], "inner_controls_defense_in_depth");
        assert_eq!(
            value["body"]["seccomp"]["base_filter"],
            "runtime_deny_by_default"
        );
        assert_eq!(value["body"]["version"], GUEST_POLICY_VERSION);
    }
}
