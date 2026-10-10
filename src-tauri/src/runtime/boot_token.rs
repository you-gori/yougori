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

#[cfg(test)]
mod tests {
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
