//! Transfer the shared appliance credential through firmware, never /proc/cmdline.
use std::{fs::File, io::Write, path::{Path, PathBuf}};

pub(super) struct BootTokenFile { path: PathBuf }
impl BootTokenFile {
    pub fn create(directory: &Path, token: &str) -> Result<Self, String> {
        if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("Invalid appliance credential".into());
        }
        let path = directory.join(format!("boot-token-{}", uuid::Uuid::new_v4().simple()));
        let mut file = create_private(&path).map_err(|_| "Cannot create private appliance credential file")?;
        let owner = Self { path };
        file.write_all(token.as_bytes()).and_then(|_| file.sync_all())
            .map_err(|_| "Cannot prepare private appliance credential file")?;
        Ok(owner)
    }
    pub fn argument(&self) -> String {
        // QEMU's key/value option syntax escapes literal commas by doubling.
        format!("name=opt/yougori/control-token,file={}", self.path.to_string_lossy().replace(',', ",,"))
    }
}
impl Drop for BootTokenFile {
    fn drop(&mut self) { let _ = std::fs::remove_file(&self.path); }
}

#[cfg(unix)]
pub(super) fn create_private(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)
}

#[cfg(windows)]
pub(super) fn create_private(path: &Path) -> std::io::Result<File> {
    use std::os::windows::{ffi::OsStrExt, io::FromRawHandle};
    use windows_sys::Win32::{
        Foundation::{LocalFree, INVALID_HANDLE_VALUE, GENERIC_WRITE},
        Security::{Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW, SECURITY_ATTRIBUTES},
        Storage::FileSystem::{CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_DELETE},
    };
    let sid = yougori_cli::wire::user_sid()?;
    let sddl = format!("D:P(A;;GA;;;{sid})\0").encode_utf16().collect::<Vec<_>>();
    let path = path.as_os_str().encode_wide().chain(Some(0)).collect::<Vec<_>>();
    unsafe {
        let mut descriptor = std::ptr::null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), 1, &mut descriptor, std::ptr::null_mut()) == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor, bInheritHandle: 0,
        };
        // Protect the file at creation, before any secret is written or an
        // inherited broad directory ACL could give another user a read handle.
        let handle = CreateFileW(path.as_ptr(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE,
            &attributes, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, std::ptr::null_mut());
        let error = std::io::Error::last_os_error();
        LocalFree(descriptor);
        if handle == INVALID_HANDLE_VALUE { return Err(error); }
        Ok(File::from_raw_handle(handle.cast()))
    }
}

/// A directory only the current user can open, whose new files inherit that
/// protection, including files created by helper processes that pass no ACL.
#[cfg(unix)]
pub(super) fn create_private_directory(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().mode(0o700).create(path)
}

#[cfg(windows)]
pub(super) fn create_private_directory(path: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW, SECURITY_ATTRIBUTES},
        Storage::FileSystem::CreateDirectoryW,
    };
    let sid = yougori_cli::wire::user_sid()?;
    let sddl = format!("D:P(A;OICI;FA;;;{sid})\0").encode_utf16().collect::<Vec<_>>();
    let path = path.as_os_str().encode_wide().chain(Some(0)).collect::<Vec<_>>();
    unsafe {
        let mut descriptor = std::ptr::null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), 1, &mut descriptor, std::ptr::null_mut()) == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor, bInheritHandle: 0,
        };
        let created = CreateDirectoryW(path.as_ptr(), &attributes);
        let error = std::io::Error::last_os_error();
        LocalFree(descriptor);
        if created == 0 { return Err(error); }
        Ok(())
    }
}

/// Replaces an existing directory's DACL with the private one above. Windows
/// recomputes the inherited entries of everything inside it.
#[cfg(windows)]
pub(super) fn protect_private_directory(path: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SE_FILE_OBJECT},
            GetSecurityDescriptorDacl, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        },
    };
    let sid = yougori_cli::wire::user_sid()?;
    let sddl = format!("D:P(A;OICI;FA;;;{sid})\0").encode_utf16().collect::<Vec<_>>();
    let path = path.as_os_str().encode_wide().chain(Some(0)).collect::<Vec<_>>();
    unsafe {
        let mut descriptor = std::ptr::null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), 1, &mut descriptor, std::ptr::null_mut()) == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let (mut present, mut defaulted, mut dacl) = (0, 0, std::ptr::null_mut());
        let result = if GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) == 0 || present == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            match SetNamedSecurityInfoW(path.as_ptr(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(), std::ptr::null_mut(), dacl, std::ptr::null_mut()) {
                0 => Ok(()),
                error => Err(std::io::Error::from_raw_os_error(error as i32)),
            }
        };
        LocalFree(descriptor);
        result
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn private_directories_protect_files_created_inside_them() {
        let parent = tempfile::tempdir().unwrap();
        let directory = parent.path().join("security-test");
        super::create_private_directory(&directory).unwrap();
        std::fs::write(directory.join("tpm.nv"), b"state").unwrap();
        assert!(super::create_private_directory(&directory).is_err(), "an existing directory is never adopted");
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777, 0o700);
        }
        #[cfg(windows)] {
            let output = std::process::Command::new("icacls").arg(directory.join("tpm.nv")).output().unwrap();
            let acl = String::from_utf8_lossy(&output.stdout).to_lowercase();
            assert!(output.status.success());
            for broad in ["users:", "everyone:", "authenticated users:", "administrators:"] {
                assert!(!acl.contains(broad), "inherited a broad grant: {acl}");
            }
        }
    }

    use super::*;
    #[test]
    fn firmware_credential_is_private_and_never_in_its_argument() {
        let directory = tempfile::Builder::new().prefix("firmware é, ").tempdir().unwrap();
        let token = "ab".repeat(32);
        let file = BootTokenFile::create(directory.path(), &token).unwrap();
        assert_eq!(std::fs::read_to_string(&file.path).unwrap(), token);
        assert!(!file.argument().contains(&token));
        assert!(file.argument().contains("é,, "));
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&file.path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let path = file.path.clone();
        drop(file);
        assert!(!path.exists());
        assert!(BootTokenFile::create(directory.path(), "invalid").is_err());
    }
}
