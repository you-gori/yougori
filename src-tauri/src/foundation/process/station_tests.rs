//! Tests of the sandbox desktop (M02, M04). They create a real desktop of this logon
//! session on its own window station and close it again; the interactive desktop, the
//! user's windows and every host setting are untouched.

use super::*;
use crate::foundation::process::{LoweredIntegrity, SandboxDesktop};
use windows_sys::Win32::Security::{WinBuiltinUsersSid, WinRestrictedCodeSid};

/// A desktop name of this test process and line, so parallel tests never collide.
fn name(line: u32) -> String {
    format!("ygt{}-{line}", std::process::id())
}

fn sids() -> (Sid, Sid) {
    (
        Sid::well_known(WinBuiltinUsersSid).unwrap(),
        Sid::well_known(WinRestrictedCodeSid).unwrap(),
    )
}

#[test]
fn a_desktop_is_created_and_destroyed_with_its_last_handle() {
    let (user, restricted) = sids();
    let name = name(line!());
    let desktop =
        SandboxDesktop::create(&name, &user, &[&restricted], LoweredIntegrity::Low).unwrap();
    assert_eq!(desktop.name(), name);
    drop(desktop);
    // The same name is free again, which it would not be if the first still existed with
    // another security descriptor: creating it a second time proves the first was gone.
    let again = SandboxDesktop::create(&name, &user, &[&restricted], LoweredIntegrity::Low);
    assert!(again.is_ok(), "{:?}", again.err());
}

#[test]
fn a_name_that_is_not_letters_digits_or_hyphens_is_refused() {
    let (user, restricted) = sids();
    for bad in [
        "",
        "has space",
        "has\\backslash",
        "has/slash",
        "a.b",
        &"x".repeat(65),
    ] {
        let refused = SandboxDesktop::create(bad, &user, &[&restricted], LoweredIntegrity::Low);
        assert!(
            matches!(refused, Err(ProcessError::Spawn { .. })),
            "{bad:?} was not refused"
        );
    }
}

#[test]
fn the_sandbox_rights_exclude_input_hooks_enumeration_and_switching() {
    // DESKTOP_JOURNALRECORD 0x0010, DESKTOP_JOURNALPLAYBACK 0x0020, DESKTOP_ENUMERATE
    // 0x0040, DESKTOP_HOOKCONTROL 0x0008, DESKTOP_SWITCHDESKTOP 0x0100 (winuser.h).
    for forbidden in [0x0010, 0x0020, 0x0040, 0x0008, 0x0100] {
        assert_eq!(
            DESKTOP_FOR_SANDBOX & forbidden,
            0,
            "{forbidden:#x} is granted"
        );
    }
    assert_eq!(DESKTOP_FOR_SANDBOX, 0x0087);
}
