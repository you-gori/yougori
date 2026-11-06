//! Tests for the identity file's protection (M16D; VM part §4.5): the owner-only rules as
//! decisions over what was read back, on Windows the DACL applied and read back and the
//! refusal of another trustee, a null DACL, an inheriting DACL, a missing path and a
//! directory, and [`ManagementChannel`] refusing calls while its identity file is not
//! owner-only.

use std::sync::Arc;

use super::fakes::{exited, mgmt_key, FakeSshPort, Scratch, World};
use super::invocation::{IdentityFile, SshLimits};
use super::known_hosts::KnownHostsFile;
use super::management::{ManagementCallRefusal, ManagementChannel};
use super::protection::{
    check_identity_file, judge_dacl, judge_mode, protect_identity_file, AclEntry, Dacl,
    IdentityFileRefusal, SecurityReadBack, ACCESS_ALLOWED_ACE_TYPE, INHERITED_ACE_FLAG,
    LOCAL_SYSTEM_SID,
};
use crate::sandbox_contract::remote::fakes::{
    attempt, config, dedicated_offering, parent, vm_request, HostWorld, HOUR,
};
use crate::sandbox_contract::remote::RemoteVmAdapter;

#[cfg(windows)]
use super::protection::{apply_dacl, read_security, set_null_dacl, OwnedSid};
#[cfg(windows)]
use windows_sys::Win32::Security::{
    WinBuiltinAdministratorsSid, WinBuiltinUsersSid, WinLocalSystemSid, WinWorldSid, INHERITED_ACE,
};

const USER: &str = "S-1-5-21-1111111111-2222222222-3333333333-1001";
const EVERYONE: &str = "S-1-1-0";
const ADMINISTRATORS: &str = "S-1-5-32-544";

fn entry(trustee: &str) -> AclEntry {
    AclEntry {
        ace_type: ACCESS_ALLOWED_ACE_TYPE,
        flags: 0,
        trustee: Some(trustee.to_owned()),
    }
}

fn read_back(owner: Option<&str>, protected: bool, entries: Vec<AclEntry>) -> SecurityReadBack {
    SecurityReadBack {
        owner: owner.map(str::to_owned),
        dacl: Some(Dacl { protected, entries }),
    }
}

fn with_owner(mut read: SecurityReadBack, owner: Option<&str>) -> SecurityReadBack {
    read.owner = owner.map(str::to_owned);
    read
}

fn owner_only(user: &str) -> SecurityReadBack {
    read_back(Some(user), true, vec![entry(user), entry(LOCAL_SYSTEM_SID)])
}

#[test]
fn the_windows_rule_accepts_only_a_protected_dacl_for_the_owner_and_system() {
    assert_eq!(judge_dacl(&owner_only(USER), USER), Ok(()));
    // Order does not matter, and SYSTEM is not required.
    let reordered = read_back(Some(USER), true, vec![entry(LOCAL_SYSTEM_SID), entry(USER)]);
    assert_eq!(judge_dacl(&reordered, USER), Ok(()));
    assert_eq!(
        judge_dacl(&read_back(Some(USER), true, vec![entry(USER)]), USER),
        Ok(())
    );

    let refused = |read: SecurityReadBack, refusal: IdentityFileRefusal| {
        assert_eq!(judge_dacl(&read, USER), Err(refusal));
    };
    refused(
        with_owner(owner_only(USER), Some(ADMINISTRATORS)),
        IdentityFileRefusal::OwnerNotCurrentUser {
            owner: Some(ADMINISTRATORS.to_owned()),
        },
    );
    refused(
        with_owner(owner_only(USER), None),
        IdentityFileRefusal::OwnerNotCurrentUser { owner: None },
    );
    refused(
        SecurityReadBack {
            owner: Some(USER.to_owned()),
            dacl: None,
        },
        IdentityFileRefusal::NoDacl,
    );
    refused(
        read_back(Some(USER), false, vec![entry(USER)]),
        IdentityFileRefusal::DaclNotProtected,
    );
    let mut inherited = entry(USER);
    inherited.flags = INHERITED_ACE_FLAG;
    refused(
        read_back(Some(USER), true, vec![entry(USER), inherited]),
        IdentityFileRefusal::InheritedEntry {
            trustee: Some(USER.to_owned()),
        },
    );
    let mut denied = entry(EVERYONE);
    denied.ace_type = 1;
    refused(
        read_back(Some(USER), true, vec![entry(USER), denied]),
        IdentityFileRefusal::UnexpectedEntry {
            ace_type: 1,
            flags: 0,
        },
    );
    let mut object_inherit = entry(USER);
    object_inherit.flags = 0x01;
    refused(
        read_back(Some(USER), true, vec![object_inherit]),
        IdentityFileRefusal::UnexpectedEntry {
            ace_type: 0,
            flags: 0x01,
        },
    );
    let mut anonymous = entry(USER);
    anonymous.trustee = None;
    refused(
        read_back(Some(USER), true, vec![entry(USER), anonymous]),
        IdentityFileRefusal::UnexpectedEntry {
            ace_type: 0,
            flags: 0,
        },
    );
    for other in [
        EVERYONE,
        ADMINISTRATORS,
        "S-1-5-32-545",
        "S-1-5-11",
        "S-1-3-0",
    ] {
        let mut read = owner_only(USER);
        if let Some(dacl) = read.dacl.as_mut() {
            dacl.entries.push(entry(other));
        }
        refused(
            read,
            IdentityFileRefusal::OtherTrustee {
                trustee: other.to_owned(),
            },
        );
    }
    refused(
        read_back(Some(USER), true, vec![entry(LOCAL_SYSTEM_SID)]),
        IdentityFileRefusal::NoEntryForCurrentUser,
    );
    refused(
        read_back(Some(USER), true, Vec::new()),
        IdentityFileRefusal::NoEntryForCurrentUser,
    );
}

#[test]
fn the_unix_rule_accepts_only_mode_0600_for_the_current_uid() {
    assert_eq!(judge_mode(1_000, 0o100_600, 1_000), Ok(()));
    for (mode, bits) in [
        (0o100_644, 0o644),
        (0o100_640, 0o640),
        (0o100_400, 0o400),
        (0o100_700, 0o700),
        (0o104_600, 0o4_600),
        (0o100_000, 0),
    ] {
        assert_eq!(
            judge_mode(1_000, mode, 1_000),
            Err(IdentityFileRefusal::ModeNotOwnerOnly { mode: bits }),
            "{mode:o}"
        );
    }
    assert_eq!(
        judge_mode(0, 0o100_600, 1_000),
        Err(IdentityFileRefusal::OwnerNotCurrentUser {
            owner: Some("0".to_owned())
        })
    );
}

#[cfg(windows)]
#[test]
fn the_dacl_is_applied_and_read_back_as_the_owner_and_system_only() {
    let scratch = Scratch::new();
    let path = scratch.path("id_ed25519");
    std::fs::write(path.as_path(), b"key").unwrap();
    // As written, the file takes its directory's permissions.
    assert_eq!(
        check_identity_file(&path),
        Err(IdentityFileRefusal::DaclNotProtected)
    );

    protect_identity_file(&path).unwrap();
    let user = OwnedSid::current_user().unwrap().text().unwrap();
    assert!(user.starts_with("S-1-5-"), "{user}");
    assert_eq!(read_security(path.as_path()).unwrap(), owner_only(&user));
    assert_eq!(check_identity_file(&path), Ok(()));
    // Protecting again changes nothing, and the owner can still use the file.
    protect_identity_file(&path).unwrap();
    assert_eq!(read_security(path.as_path()).unwrap(), owner_only(&user));
    assert_eq!(std::fs::read(path.as_path()).unwrap(), b"key");

    // The constants of the decision are the platform's.
    assert_eq!(
        OwnedSid::well_known(WinLocalSystemSid)
            .unwrap()
            .text()
            .unwrap(),
        LOCAL_SYSTEM_SID
    );
    assert_eq!(u32::from(INHERITED_ACE_FLAG), INHERITED_ACE);
}

#[cfg(windows)]
#[test]
fn a_file_granting_another_trustee_or_everyone_is_refused() {
    let scratch = Scratch::new();
    let path = scratch.path("id_ed25519");
    std::fs::write(path.as_path(), b"key").unwrap();
    protect_identity_file(&path).unwrap();
    let user = OwnedSid::current_user().unwrap();
    let system = OwnedSid::well_known(WinLocalSystemSid).unwrap();
    for (kind, text) in [
        (WinWorldSid, EVERYONE),
        (WinBuiltinAdministratorsSid, ADMINISTRATORS),
        (WinBuiltinUsersSid, "S-1-5-32-545"),
    ] {
        let extra = OwnedSid::well_known(kind).unwrap();
        apply_dacl(path.as_path(), None, &[&user, &system, &extra]).unwrap();
        assert_eq!(
            check_identity_file(&path),
            Err(IdentityFileRefusal::OtherTrustee {
                trustee: text.to_owned()
            })
        );
    }
    // SYSTEM alone: the owner keeps the right to read and change the DACL, not the key.
    apply_dacl(path.as_path(), None, &[&system]).unwrap();
    assert_eq!(
        check_identity_file(&path),
        Err(IdentityFileRefusal::NoEntryForCurrentUser)
    );
    // No DACL at all grants everyone everything.
    set_null_dacl(path.as_path()).unwrap();
    assert_eq!(read_security(path.as_path()).unwrap().dacl, None);
    assert_eq!(check_identity_file(&path), Err(IdentityFileRefusal::NoDacl));
    // Protection repairs each of them.
    protect_identity_file(&path).unwrap();
    assert_eq!(check_identity_file(&path), Ok(()));
}

#[cfg(windows)]
#[test]
fn a_missing_path_or_a_directory_is_refused_and_left_alone() {
    let scratch = Scratch::new();
    let missing = scratch.path("missing");
    assert_eq!(
        check_identity_file(&missing),
        Err(IdentityFileRefusal::Missing)
    );
    assert_eq!(
        protect_identity_file(&missing),
        Err(IdentityFileRefusal::Missing)
    );
    assert!(!missing.as_path().exists());

    let directory = scratch.path("keys");
    std::fs::create_dir(directory.as_path()).unwrap();
    let before = read_security(directory.as_path()).unwrap();
    assert_eq!(
        protect_identity_file(&directory),
        Err(IdentityFileRefusal::NotAFile)
    );
    assert_eq!(
        check_identity_file(&directory),
        Err(IdentityFileRefusal::NotAFile)
    );
    assert_eq!(read_security(directory.as_path()).unwrap(), before);
}

#[test]
fn a_management_channel_refuses_every_call_while_its_identity_file_is_not_owner_only() {
    let world = World::standard();
    let scratch = Scratch::new();
    let known_hosts =
        KnownHostsFile::write(world.key.clone(), scratch.path("known_hosts")).unwrap();
    let path = scratch.path("id_ed25519");
    let mut channel = ManagementChannel::new(
        FakeSshPort::new(Vec::new(), exited(0, "")),
        known_hosts,
        IdentityFile::new(mgmt_key(), path.clone()),
        SshLimits::STANDARD,
    );
    // A run that has not been provisioned: a call that passes the identity file check
    // meets the enrollment check next.
    let host_world = HostWorld::new(4 * HOUR);
    let mut authority = host_world.delegation();
    let mut adapter = RemoteVmAdapter::plan(
        Arc::clone(&host_world.clock),
        attempt(1),
        parent(),
        &vm_request(),
        &[dedicated_offering()],
        config(),
    )
    .unwrap();
    let invocation = world.launch();
    let mut call = |channel: &mut ManagementChannel<FakeSshPort>| {
        channel
            .call(
                &mut adapter,
                &mut authority,
                &world.known,
                &world.identity,
                &invocation,
            )
            .unwrap_err()
    };
    let identity_file = |refusal| ManagementCallRefusal::IdentityFile { refusal };

    assert_eq!(
        call(&mut channel),
        identity_file(IdentityFileRefusal::Missing)
    );
    std::fs::write(path.as_path(), b"key").unwrap();
    // As written, the file has its directory's permissions (or the umask's).
    assert!(matches!(
        call(&mut channel),
        ManagementCallRefusal::IdentityFile { .. }
    ));
    protect_identity_file(&path).unwrap();
    assert_eq!(call(&mut channel), ManagementCallRefusal::NotEnrolled);

    // Widened again after it was protected: refused again, on the next call.
    #[cfg(windows)]
    {
        let user = OwnedSid::current_user().unwrap();
        let system = OwnedSid::well_known(WinLocalSystemSid).unwrap();
        let everyone = OwnedSid::well_known(WinWorldSid).unwrap();
        apply_dacl(path.as_path(), None, &[&user, &system, &everyone]).unwrap();
        assert_eq!(
            call(&mut channel),
            identity_file(IdentityFileRefusal::OtherTrustee {
                trustee: EVERYONE.to_owned()
            })
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path.as_path(), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            call(&mut channel),
            identity_file(IdentityFileRefusal::ModeNotOwnerOnly { mode: 0o644 })
        );
    }
    protect_identity_file(&path).unwrap();
    assert_eq!(call(&mut channel), ManagementCallRefusal::NotEnrolled);
    // Nothing reached the port.
    assert!(channel.port().stdin_seen.is_empty());
    let json = serde_json::to_value(identity_file(IdentityFileRefusal::NoDacl)).unwrap();
    assert_eq!(json["kind"], "identity_file");
    assert_eq!(json["refusal"]["problem"], "no_dacl");
}
