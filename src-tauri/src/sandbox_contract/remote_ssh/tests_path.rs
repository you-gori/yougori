//! Tests for where an `SshFilePath` may point on each platform: on Windows only a
//! drive-qualified path, so the engine and a client running in another working directory
//! open the same file.

use super::path::{SshFilePath, SshPathRefusal};

#[cfg(windows)]
#[test]
fn on_windows_only_a_drive_qualified_path_names_a_file() {
    use SshPathRefusal::{DriveRequired, InvalidCharacter, InvalidComponent, NotAbsolute};
    for (path, refusal) in [
        // Rooted without a drive: the current drive of whoever opens it.
        ("/run/kh", DriveRequired),
        ("/Users/me/known_hosts", DriveRequired),
        ("\\run\\kh", NotAbsolute),
        // Drive-relative: the drive's current directory.
        ("C:kh", NotAbsolute),
        ("C:run/kh", NotAbsolute),
        // UNC, verbatim and device forms, with either separator.
        ("\\\\server\\share\\kh", NotAbsolute),
        ("//server/share/kh", InvalidComponent),
        ("\\\\?\\C:\\run\\kh", NotAbsolute),
        ("//?/C:/run/kh", InvalidCharacter { character: '?' }),
        ("\\\\?\\UNC\\server\\share\\kh", NotAbsolute),
        (
            "//?/UNC/server/share/kh",
            InvalidCharacter { character: '?' },
        ),
        ("\\\\.\\C:\\run\\kh", NotAbsolute),
        ("//./C:/run/kh", InvalidCharacter { character: ':' }),
        ("//./pipe/kh", InvalidComponent),
        // Reserved device names, in any case and with any extension.
        ("C:/run/NUL", InvalidComponent),
        ("C:/run/nul", InvalidComponent),
        ("C:/run/con.txt", InvalidComponent),
        ("C:/run/Com1", InvalidComponent),
        ("C:/run/COM0", InvalidComponent),
        ("C:/LPT9.log/kh", InvalidComponent),
        ("C:/aux/kh", InvalidComponent),
        ("C:/run/prn.known_hosts", InvalidComponent),
    ] {
        assert_eq!(SshFilePath::new(path), Err(refusal), "{path:?}");
    }
    for good in [
        "C:/run/kh",
        "d:/x",
        "C:/run/console",
        "C:/run/com10",
        "C:/run/nul-x",
        "C:/run/NULL",
        "C:/run/lpt",
    ] {
        assert_eq!(SshFilePath::new(good).unwrap().as_str(), good);
    }
}

#[cfg(not(windows))]
#[test]
fn elsewhere_only_a_slash_rooted_path_names_a_file() {
    // `C:/...` is a relative path here.
    for path in ["C:/run/kh", "d:/x"] {
        assert_eq!(
            SshFilePath::new(path),
            Err(SshPathRefusal::NotAbsolute),
            "{path:?}"
        );
    }
    // Device names mean nothing here.
    for good in ["/run/kh", "/run/NUL", "/con/kh"] {
        assert_eq!(SshFilePath::new(good).unwrap().as_str(), good);
    }
}
