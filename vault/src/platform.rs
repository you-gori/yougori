use std::{
    ffi::c_void,
    io::Seek,
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    path::{Path, PathBuf},
    ptr::null_mut,
};
use windows_sys::Win32::Storage::FileSystem::{
    FileIdInfo, GetFileInformationByHandleEx, GetFinalPathNameByHandleW, FILE_GENERIC_EXECUTE,
    FILE_GENERIC_READ, FILE_ID_INFO, FILE_NAME_NORMALIZED, FILE_SHARE_READ, VOLUME_NAME_DOS,
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    System::{Pipes::*, Threading::*},
    UI::{Shell::*, WindowsAndMessaging::*},
};

pub(crate) fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}
fn last() -> String {
    std::io::Error::last_os_error().to_string()
}
pub(crate) struct Handle(pub HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

fn known(id: &windows_sys::core::GUID) -> Result<PathBuf, String> {
    unsafe {
        let mut ptr = null_mut();
        if SHGetKnownFolderPath(id, 0, null_mut(), &mut ptr) < 0 {
            return Err("Cannot locate Windows protected folders".into());
        }
        let mut len = 0;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        let result = PathBuf::from(String::from_utf16_lossy(std::slice::from_raw_parts(
            ptr, len,
        )));
        windows_sys::Win32::System::Com::CoTaskMemFree(ptr.cast());
        Ok(result)
    }
}
pub fn installed_binary() -> Result<PathBuf, String> {
    Ok(known(&FOLDERID_ProgramFiles)?
        .join("Yougori Vault")
        .join("yougori-vault.exe"))
}
pub(crate) fn data_directory() -> Result<PathBuf, String> {
    Ok(known(&FOLDERID_ProgramData)?
        .join("YougoriVault")
        .join(user_sid()?))
}

fn token(process: HANDLE) -> Result<Handle, String> {
    unsafe {
        let mut h = null_mut();
        if OpenProcessToken(process, TOKEN_QUERY, &mut h) == 0 {
            return Err(last());
        }
        Ok(Handle(h))
    }
}
fn sid_of_token(token: HANDLE) -> Result<String, String> {
    unsafe {
        let mut size = 0;
        GetTokenInformation(token, TokenUser, null_mut(), 0, &mut size);
        // usize storage keeps TOKEN_USER (which holds a pointer) aligned.
        let mut buf = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
        if GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), size, &mut size) == 0 {
            return Err(last());
        }
        let sid = (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid;
        sid_text(sid)
    }
}
pub(crate) unsafe fn sid_text(sid: PSID) -> Result<String, String> {
    let mut value = null_mut();
    if ConvertSidToStringSidW(sid, &mut value) == 0 {
        return Err(last());
    }
    let mut len = 0;
    while *value.add(len) != 0 {
        len += 1;
    }
    let text = String::from_utf16_lossy(std::slice::from_raw_parts(value, len));
    LocalFree(value.cast());
    Ok(text)
}
pub fn user_sid() -> Result<String, String> {
    sid_of_token(token(unsafe { GetCurrentProcess() })?.0)
}
fn elevated(process: HANDLE) -> Result<bool, String> {
    unsafe {
        let token = token(process)?;
        let mut elevation = TOKEN_ELEVATION::default();
        let mut size = 0;
        if GetTokenInformation(
            token.0,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        ) == 0
        {
            return Err(last());
        }
        Ok(elevation.TokenIsElevated != 0)
    }
}
fn path_of_process(process: HANDLE) -> Result<PathBuf, String> {
    unsafe {
        let mut path = vec![0u16; 32768];
        let mut len = path.len() as u32;
        if QueryFullProcessImageNameW(process, 0, path.as_mut_ptr(), &mut len) == 0 {
            return Err(last());
        }
        Ok(PathBuf::from(String::from_utf16_lossy(
            &path[..len as usize],
        )))
    }
}
pub fn endpoint() -> Result<String, String> {
    Ok(format!(r"\\.\pipe\Yougori.ProtectedVault.{}", user_sid()?))
}

/// An executable held open for reading only. While the handle is held, Windows
/// refuses writes, renames and deletion of the file (and renames of its folders),
/// so a verified file cannot be swapped before Windows starts it.
pub(crate) struct PinnedFile {
    file: std::fs::File,
    path: PathBuf,
}
impl PinnedFile {
    pub(crate) fn open(path: &Path) -> Result<Self, String> {
        no_reparse(path)?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(path)
            .map_err(|_| "Cannot open the Personal Vault component for verification")?;
        let path = final_path(&file)?;
        Ok(Self { file, path })
    }
    pub(crate) fn sha256(&self) -> Result<String, String> {
        sha256_of(&self.file)
    }
}
fn sha256_of(mut file: &std::fs::File) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    file.rewind()
        .map_err(|_| "Cannot read the Personal Vault component")?;
    let mut hash = Sha256::new();
    std::io::copy(&mut file, &mut hash).map_err(|_| "Cannot read the Personal Vault component")?;
    Ok(hex::encode(hash.finalize()))
}
/// The resolved path of an open file, without junctions or the `\\?\` prefix
/// (the shell cannot launch extended-length paths reliably).
fn final_path(file: &std::fs::File) -> Result<PathBuf, String> {
    let mut buffer = vec![0u16; 32768];
    let length = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
        )
    } as usize;
    if length == 0 || length >= buffer.len() {
        return Err("Cannot resolve the Personal Vault component path".into());
    }
    Ok(PathBuf::from(plain_path(&String::from_utf16_lossy(&buffer[..length]))))
}
fn plain_path(path: &str) -> String {
    if let Some(unc) = path.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{unc}")
    } else {
        path.strip_prefix(r"\\?\").unwrap_or(path).to_owned()
    }
}
/// Case-insensitive comparison key for local executable paths.
pub(crate) fn path_key(path: &str) -> String {
    plain_path(path).replace('/', "\\").to_lowercase()
}

/// The DER-encoded subject of a file's valid, trusted Authenticode signer.
/// `None` means the file carries no signature; a present signature that is
/// tampered, expired without a timestamp or untrusted is an error.
fn signer(file: &std::fs::File, path: &Path) -> Result<Option<Vec<u8>>, String> {
    use windows_sys::Win32::Security::WinTrust::*;
    let identity = file_identity(file);
    if let Some(key) = &identity {
        if let Some(cached) = SIGNERS.lock().unwrap().get(key) {
            return Ok(cached.clone());
        }
    }
    let wide_path = wide(&path.to_string_lossy());
    let mut info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: wide_path.as_ptr(),
        hFile: file.as_raw_handle(),
        pgKnownSubject: null_mut(),
    };
    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 { pFile: &mut info },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
        ..Default::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let result = unsafe {
        let status = WinVerifyTrust(
            INVALID_HANDLE_VALUE,
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast(),
        );
        let result = if status == 0 {
            let provider = WTHelperProvDataFromStateData(data.hWVTStateData);
            let signer = if provider.is_null() {
                null_mut()
            } else {
                WTHelperGetProvSignerFromChain(provider, 0, 0, 0)
            };
            let certificate = if signer.is_null() {
                null_mut()
            } else {
                WTHelperGetProvCertFromChain(signer, 0)
            };
            if certificate.is_null()
                || (*certificate).pCert.is_null()
                || (*(*certificate).pCert).pCertInfo.is_null()
            {
                Err("Cannot read the executable's signer".to_string())
            } else {
                let subject = &(*(*(*certificate).pCert).pCertInfo).Subject;
                Ok(Some(
                    std::slice::from_raw_parts(subject.pbData, subject.cbData as usize).to_vec(),
                ))
            }
        } else if status == TRUST_E_NOSIGNATURE {
            Ok(None)
        } else {
            Err(format!(
                "{} has an invalid or untrusted signature",
                path.file_name().unwrap_or_default().to_string_lossy()
            ))
        };
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(
            INVALID_HANDLE_VALUE,
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast(),
        );
        result
    };
    if let (Some(key), Ok(value)) = (identity, &result) {
        let mut cache = SIGNERS.lock().unwrap();
        if cache.len() >= 64 {
            cache.clear();
        }
        cache.insert(key, value.clone());
    }
    result
}
/// Verification is cached per unchanged file: volume, file ID, size and write time.
type FileKey = (u64, u128, u64, Option<std::time::SystemTime>);
static SIGNERS: std::sync::Mutex<std::collections::BTreeMap<FileKey, Option<Vec<u8>>>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());
fn file_identity(file: &std::fs::File) -> Option<FileKey> {
    let mut info = FILE_ID_INFO::default();
    let okay = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            (&mut info as *mut FILE_ID_INFO).cast(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    };
    if okay == 0 {
        return None;
    }
    let metadata = file.metadata().ok()?;
    Some((
        info.VolumeSerialNumber,
        u128::from_le_bytes(info.FileId.Identifier),
        metadata.len(),
        metadata.modified().ok(),
    ))
}
/// The signer of this running executable. An invalid signature on our own image
/// is treated as unsigned: it cannot pin a publisher.
fn own_signer() -> Option<&'static [u8]> {
    static OWN: std::sync::OnceLock<Option<Vec<u8>>> = std::sync::OnceLock::new();
    OWN.get_or_init(|| {
        let path = std::env::current_exe().ok()?;
        let file = std::fs::File::open(&path).ok()?;
        signer(&file, &path).ok().flatten()
    })
    .as_deref()
}
/// A Desktop may elevate only a broker from its own publisher. Unsigned
/// development Desktops have no publisher to pin and accept the pinned file.
fn authorize_bundle(bundle: &PinnedFile) -> Result<(), String> {
    let Some(publisher) = own_signer() else {
        return Ok(());
    };
    match signer(&bundle.file, &bundle.path) {
        Ok(Some(subject)) if subject == publisher => Ok(()),
        _ => Err("The bundled Personal Vault component is not signed by this Yougori's publisher. Nothing was installed; reinstall Yougori.".into()),
    }
}
/// Whether a verified local client is this account's Yougori Desktop. A signed
/// broker requires the same Authenticode publisher; an unsigned development
/// broker requires a Desktop path registered by an elevated install. A signed
/// broker also accepts an explicitly registered (administrator-approved) path, so
/// an unsigned source build can use a vault installed by a signed release.
fn desktop_client(executable: &Path, file: &std::fs::File) -> bool {
    if !executable
        .file_name()
        .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case("yougori.exe"))
    {
        return false;
    }
    match own_signer() {
        Some(publisher) => signer(file, executable).is_ok_and(|subject| subject.as_deref() == Some(publisher))
            || registered_desktops().is_some_and(|paths| paths.contains(&path_key(&executable.to_string_lossy()))),
        None => registered_desktops().map_or(true, |paths| {
            paths.contains(&path_key(&executable.to_string_lossy()))
        }),
    }
}
const DESKTOPS: &str = "desktops.json";
/// Registered Desktop paths, or `None` for a broker installed before
/// registration existed (accepted by name until its next update).
fn registered_desktops() -> Option<Vec<String>> {
    registered_desktops_at(&data_directory().ok()?.join(DESKTOPS))
}
fn registered_desktops_at(path: &Path) -> Option<Vec<String>> {
    // Only a list certainly absent means a broker from before registration. One that could
    // not be checked or read recognises no Desktop, never every Desktop by name.
    match crate::storage::present(path) {
        Ok(false) => return None,
        Ok(true) => {}
        Err(_) => return Some(Vec::new()),
    }
    let Ok(bytes) = crate::storage::bounded_read(path, 64 * 1024) else { return Some(Vec::new()) };
    Some(serde_json::from_slice::<Vec<String>>(&bytes).unwrap_or_default())
}
fn record_desktop(desktop: &str) -> Result<(), String> {
    if !Path::new(desktop).is_absolute()
        || !Path::new(desktop)
            .file_name()
            .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case("yougori.exe"))
        || !crate::policy::safe_text(desktop, 2048)
    {
        return Err("Register an installed Yougori Desktop executable".into());
    }
    let key = path_key(desktop);
    let mut paths = registered_desktops().unwrap_or_default();
    paths.retain(|path| *path != key);
    paths.push(key);
    // A few development and installed copies; the oldest registration expires.
    let keep = paths.len().saturating_sub(8);
    paths.drain(..keep);
    // The list names trusted Desktops and holds no vault data, so one that could not be read or
    // checked is replaced rather than refused: refusing it would leave no way back but deleting
    // it by hand.
    let path = data_directory()?.join(DESKTOPS);
    crate::storage::atomic_replace(&path, &serde_json::to_vec(&paths).map_err(|e| e.to_string())?).map_err(|error| {
        format!("Personal Vault could not record this Yougori in {} ({error}). Delete that file as an administrator; it holds no vault data. Then choose Update vault again.", path.display())
    })
}

pub(crate) fn no_reparse(path: &Path) -> Result<(), String> {
    use std::os::windows::fs::MetadataExt;
    if std::fs::symlink_metadata(path)
        .map_err(|e| e.to_string())?
        .file_attributes()
        & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
        != 0
    {
        return Err("Vault paths cannot be junctions or symbolic links".into());
    }
    Ok(())
}
// Owner must be Administrators, not the filtered interactive user: an owner can
// rewrite a DACL even if ordinary file writes are denied.
pub(crate) fn secure(path: &Path, public_read: bool) -> Result<(), String> {
    no_reparse(path)?;
    let sddl = if public_read {
        "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)"
    } else {
        "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
    };
    unsafe {
        let mut descriptor = null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide(sddl).as_ptr(),
            1,
            &mut descriptor,
            null_mut(),
        ) == 0
        {
            return Err(last());
        }
        let result = SetFileSecurityW(
            wide(&path.to_string_lossy()).as_ptr(),
            OWNER_SECURITY_INFORMATION
                | GROUP_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor,
        );
        LocalFree(descriptor);
        if result == 0 {
            return Err(last());
        }
    }
    verify_protected(path, public_read)
}
pub(crate) fn verify_protected(path: &Path, public_read: bool) -> Result<(), String> {
    no_reparse(path)?;
    unsafe {
        let mut owner = null_mut();
        let mut dacl = null_mut();
        let mut descriptor = null_mut();
        let result = GetNamedSecurityInfoW(
            wide(&path.to_string_lossy()).as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        );
        if result != 0 {
            return Err("Cannot verify vault file protections".into());
        }
        let guard = HandleLocal(descriptor);
        let owner = sid_text(owner)?;
        if !matches!(owner.as_str(), "S-1-5-32-544" | "S-1-5-18") || dacl.is_null() {
            return Err("Vault requires administrator-owned files with a restrictive ACL".into());
        }
        for index in 0..(*dacl).AceCount {
            let mut ace: *mut c_void = null_mut();
            if GetAce(dacl, index as u32, &mut ace) == 0 {
                return Err(last());
            }
            let header = &*(ace as *const ACE_HEADER);
            if header.AceType != 0 {
                return Err("Unexpected vault file access rule".into());
            } // ACCESS_ALLOWED_ACE_TYPE
            let allowed = &*(ace as *const ACCESS_ALLOWED_ACE);
            let sid = sid_text((&allowed.SidStart as *const u32).cast_mut().cast())?;
            if matches!(sid.as_str(), "S-1-5-32-544" | "S-1-5-18") {
                continue;
            }
            let read_only =
                FILE_GENERIC_READ | FILE_GENERIC_EXECUTE | GENERIC_READ | GENERIC_EXECUTE;
            if !public_read || sid != "S-1-5-32-545" || allowed.Mask & !read_only != 0 {
                return Err("Vault path is writable outside its trusted broker".into());
            }
        }
        drop(guard);
        Ok(())
    }
}
struct HandleLocal(*mut c_void);
impl Drop for HandleLocal {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

pub(crate) fn require_broker() -> Result<(), String> {
    unsafe {
        windows_sys::Win32::System::LibraryLoader::SetDefaultDllDirectories(
            windows_sys::Win32::System::LibraryLoader::LOAD_LIBRARY_SEARCH_SYSTEM32
                | windows_sys::Win32::System::LibraryLoader::LOAD_LIBRARY_SEARCH_APPLICATION_DIR,
        );
    }
    if !elevated(unsafe { GetCurrentProcess() })? {
        return Err(
            "The vault broker needs Windows administrator protection. Open it from Personal Vault."
                .into(),
        );
    }
    let expected = installed_binary()?;
    if std::env::current_exe().map_err(|e| e.to_string())? != expected {
        return Err("The vault can only run from its protected installation".into());
    }
    verify_protected(expected.parent().unwrap(), true)?;
    verify_protected(&expected, true)?;
    Ok(())
}
pub fn launch(bundled: &Path, allow_elevation: bool) -> Result<(), String> {
    let installed = installed_binary()?;
    // Deliberately `exists()`: a broker that cannot be checked is installed again, with the
    // person's consent, and is never run unchecked. Keep that direction.
    if installed.exists() && !update_required(bundled)? {
        verify_protected(installed.parent().unwrap(), true)?;
        verify_protected(&installed, true)?;
        match crate::task::run(&installed, &user_sid()?) {
            Ok(()) => Ok(()),
            Err(error) if allow_elevation => {
                // A failed task must be repaired, not bypassed for this one
                // launch; otherwise the next Desktop start prompts again.
                elevate(&PinnedFile::open(&installed)?, &install_arguments(None)?)
                    .map_err(|e| format!("Protected vault startup task failed: {error}. {e}"))
            }
            Err(error) => Err(format!("Protected vault startup task failed: {error}. Open Personal Vault MCP and choose Repair startup to fix it.")),
        }
    } else {
        if !bundled.is_file() {
            return Err("The protected vault component is missing. Reinstall Yougori.".into());
        }
        if !allow_elevation {
            return Err("Personal Vault needs an update. Open Personal Vault MCP and choose Update vault.".into());
        }
        // The bundled copy lives in a user-writable folder. Verify it, then elevate
        // a copy from a folder nothing can write to, kept pinned until its installer
        // exits; the installer also checks its protected copy has this digest.
        let bundle = PinnedFile::open(bundled)?;
        authorize_bundle(&bundle)?;
        let digest = bundle.sha256()?;
        let staged = Staged::create(&bundle, &digest)?;
        let result = elevate(&staged.executable, &install_arguments(Some(&digest))?);
        staged.remove();
        result
    }
}
/// A verified broker copy alone in a fresh folder whose ACL lets this account
/// only read, run and later delete it. An elevated process searches its own
/// folder for DLLs first; nothing can be planted beside this executable.
struct Staged {
    executable: PinnedFile,
    folder: std::fs::File,
    path: PathBuf,
}
const STAGING_PREFIX: &str = "yougori-vault-update-";
impl Staged {
    fn create(bundle: &PinnedFile, digest: &str) -> Result<Self, String> {
        let temporary = std::env::temp_dir();
        Self::clean(&temporary);
        let path = temporary.join(format!("{STAGING_PREFIX}{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir(&path).map_err(|_| "Cannot prepare the Personal Vault update")?;
        let executable = path.join("yougori-vault.exe");
        let copied = (|| {
            let mut source = &bundle.file;
            source.rewind().ok()?;
            let mut target = std::fs::File::create_new(&executable).ok()?;
            std::io::copy(&mut source, &mut target).ok()?;
            target.sync_all().ok()
        })();
        let user = user_sid()?;
        // OW (owner rights) removes this account's implicit right to change the ACL.
        let file_acl = format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;{user})(A;;0x1300a9;;;OW)");
        let folder_acl = format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;{user})(A;;0x1300a9;;;OW)");
        if copied.is_none() || set_dacl(&executable, &file_acl).is_err() || set_dacl(&path, &folder_acl).is_err() {
            let _ = std::fs::remove_file(&executable);
            let _ = std::fs::remove_dir(&path);
            return Err("Cannot prepare the Personal Vault update".into());
        }
        // Read-only sharing fails if any writer opened the folder or file before
        // it was locked, so its contents are final once both pins succeed.
        let folder = std::fs::OpenOptions::new()
            .access_mode(windows_sys::Win32::Storage::FileSystem::FILE_LIST_DIRECTORY)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS)
            .open(&path)
            .map_err(|_| "Another program is using the Personal Vault update folder")?;
        let staged = Self { executable: PinnedFile::open(&executable)?, folder, path };
        let entries: Vec<_> = std::fs::read_dir(&staged.path)
            .map_err(|_| "Cannot verify the Personal Vault update")?
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .collect();
        if entries.len() != 1 || entries[0] != "yougori-vault.exe" || staged.executable.sha256()? != digest {
            staged.remove();
            return Err("The Personal Vault update folder was modified. Nothing was installed.".into());
        }
        Ok(staged)
    }
    fn remove(self) {
        let Self { executable, folder, path } = self;
        drop((executable, folder));
        let _ = std::fs::remove_file(path.join("yougori-vault.exe"));
        let _ = std::fs::remove_dir(&path);
    }
    /// Earlier staging folders whose installer did not finish.
    fn clean(temporary: &Path) {
        for entry in std::fs::read_dir(temporary).into_iter().flatten().filter_map(Result::ok) {
            if entry.file_name().to_string_lossy().starts_with(STAGING_PREFIX) {
                let _ = std::fs::remove_file(entry.path().join("yougori-vault.exe"));
                let _ = std::fs::remove_dir(entry.path());
            }
        }
    }
}
fn set_dacl(path: &Path, sddl: &str) -> Result<(), String> {
    unsafe {
        let mut descriptor = null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(wide(sddl).as_ptr(), 1, &mut descriptor, null_mut()) == 0 {
            return Err(last());
        }
        let result = SetFileSecurityW(
            wide(&path.to_string_lossy()).as_ptr(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor,
        );
        LocalFree(descriptor);
        if result == 0 {
            return Err(last());
        }
    }
    Ok(())
}
/// Registers this Desktop with an unsigned development broker. Signed brokers
/// recognize Desktop by its publisher and need no registration.
pub fn register_desktop() -> Result<(), String> {
    let installed = installed_binary()?;
    verify_protected(installed.parent().unwrap(), true)?;
    verify_protected(&installed, true)?;
    elevate(
        &PinnedFile::open(&installed)?,
        &format!("--register --owner {} --desktop {}", user_sid()?, quoted_desktop()?),
    )
}
fn quoted_desktop() -> Result<String, String> {
    let path = std::env::current_exe().map_err(|e| e.to_string())?;
    let path = plain_path(&path.to_string_lossy());
    if path.contains('"') || path.ends_with('\\') {
        return Err("Yougori Desktop has an unsupported installation path".into());
    }
    Ok(format!("\"{path}\""))
}
fn install_arguments(digest: Option<&str>) -> Result<String, String> {
    let mut arguments = format!("--install --owner {} --desktop {}", user_sid()?, quoted_desktop()?);
    if let Some(digest) = digest {
        arguments.push_str(" --sha256 ");
        arguments.push_str(digest);
    }
    Ok(arguments)
}
pub fn update_required(bundled: &Path) -> Result<bool, String> {
    use sha2::{Digest, Sha256};
    let installed = installed_binary()?;
    // Deliberately `exists()`: with no broker to compare, there is nothing to update here, and
    // `launch` installs one instead (with consent). Nothing is written on this answer.
    if !installed.exists() || !bundled.is_file() {
        return Ok(false);
    }
    verify_protected(installed.parent().unwrap(), true)?;
    verify_protected(&installed, true)?;
    let digest = |path: &Path| -> Result<_, String> {
        let mut file = std::fs::File::open(path).map_err(|e| e.to_string())?;
        let mut hash = Sha256::new();
        std::io::copy(&mut file, &mut hash).map_err(|e| e.to_string())?;
        Ok(hash.finalize())
    };
    Ok(digest(bundled)? != digest(&installed)?)
}
/// Starts the pinned executable elevated and waits for it to finish while the
/// file stays pinned.
fn elevate(executable: &PinnedFile, arguments: &str) -> Result<(), String> {
    let directory = executable.path.parent().ok_or("Invalid broker path")?;
    let (verb, file, parameters, folder) = (
        wide("runas"),
        wide(&executable.path.to_string_lossy()),
        wide(arguments),
        wide(&directory.to_string_lossy()),
    );
    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI,
        lpVerb: verb.as_ptr(),
        lpFile: file.as_ptr(),
        lpParameters: parameters.as_ptr(),
        lpDirectory: folder.as_ptr(),
        nShow: SW_HIDE,
        ..Default::default()
    };
    unsafe {
        if ShellExecuteExW(&mut info) == 0 || info.hProcess.is_null() {
            return Err(
                "Windows did not start the protected vault. No vault data was opened.".into(),
            );
        }
        let process = Handle(info.hProcess);
        match WaitForSingleObject(process.0, 120_000) {
            WAIT_OBJECT_0 => {
                let mut code = 0;
                if GetExitCodeProcess(process.0, &mut code) != 0 && code != 0 {
                    return Err("The protected vault installer stopped before finishing. Existing vault data was not changed.".into());
                }
            }
            WAIT_TIMEOUT => {
                return Err("The protected vault installer did not finish. Retry from Personal Vault MCP.".into())
            }
            // Without wait rights the caller polls the broker as before; the
            // installer's own digest check still protects the protected copy.
            _ => (),
        }
    }
    Ok(())
}
fn same_file(left: &Path, right: &Path) -> bool {
    match (std::fs::canonicalize(left), std::fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => {
            path_key(&left.to_string_lossy()) == path_key(&right.to_string_lossy())
        }
        _ => false,
    }
}
pub fn install(desktop: Option<&str>, digest: Option<&str>) -> Result<(), String> {
    if !elevated(unsafe { GetCurrentProcess() })? {
        return Err("Windows approval is required to install Personal Vault".into());
    }
    let destination = installed_binary()?;
    let directory = destination.parent().unwrap();
    std::fs::create_dir_all(directory).map_err(|e| e.to_string())?;
    secure(directory, true)?;
    let source = std::env::current_exe().map_err(|e| e.to_string())?;
    // Repairing from the protected copy keeps its executable; Windows cannot
    // replace a running image and there is nothing newer to copy.
    if !same_file(&source, &destination) {
        // Stage and sync the whole new executable before stopping the old process.
        // An interrupted copy must not damage the existing protected installation.
        let staged = tempfile::NamedTempFile::new_in(directory).map_err(|e| e.to_string())?;
        std::fs::copy(&source, staged.path()).map_err(|e| e.to_string())?;
        secure(staged.path(), true)?;
        staged.as_file().sync_all().map_err(|e| e.to_string())?;
        if let Some(expected) = digest {
            // Desktop verified this digest on the file it pinned. A source swapped
            // after this process started must not become the protected broker.
            if !sha256_of(staged.as_file())?.eq_ignore_ascii_case(expected) {
                return Err("The vault component changed after verification. Nothing was installed.".into());
            }
        }
        if crate::storage::present(&destination)? {
            verify_protected(&destination, true)?;
            stop_installed_broker(&destination)?;
        }
        staged.persist(&destination).map_err(|e| e.to_string())?;
    }
    verify_protected(&destination, true)?;
    let data = data_directory()?;
    std::fs::create_dir_all(data.parent().unwrap()).map_err(|e| e.to_string())?;
    secure(data.parent().unwrap(), false)?;
    std::fs::create_dir_all(&data).map_err(|e| e.to_string())?;
    secure(&data, false)?;
    if let Some(desktop) = desktop {
        record_desktop(desktop)?;
    }
    crate::task::install(&destination, &user_sid()?)?;
    use std::os::windows::process::CommandExt;
    std::process::Command::new(&destination)
        .arg("--serve")
        .arg("--owner")
        .arg(user_sid()?)
        .current_dir(directory)
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|e| e.to_string())?;
    Ok(())
}
/// Elevated registration of an unsigned development Desktop path.
pub fn register(desktop: &str) -> Result<(), String> {
    if !elevated(unsafe { GetCurrentProcess() })? {
        return Err("Windows approval is required to register Yougori Desktop".into());
    }
    let installed = installed_binary()?;
    if !same_file(&std::env::current_exe().map_err(|e| e.to_string())?, &installed) {
        return Err("Register Desktop from the protected vault installation".into());
    }
    verify_protected(&installed, true)?;
    let data = data_directory()?;
    verify_protected(data.parent().unwrap(), false)?;
    verify_protected(&data, false)?;
    record_desktop(desktop)
}
// Only the UAC-elevated installer can replace the protected broker. Stop only
// this account's verified installed executable; never stop desktop/workloads.
fn stop_installed_broker(destination: &Path) -> Result<(), String> {
    use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
    unsafe {
        let snapshot = Handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if snapshot.0 == INVALID_HANDLE_VALUE {
            return Err(last());
        }
        let owner = user_sid()?;
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut found = Process32FirstW(snapshot.0, &mut entry);
        while found != 0 {
            let end = entry
                .szExeFile
                .iter()
                .position(|v| *v == 0)
                .unwrap_or(entry.szExeFile.len());
            if entry.th32ProcessID != GetCurrentProcessId()
                && String::from_utf16_lossy(&entry.szExeFile[..end])
                    .eq_ignore_ascii_case("yougori-vault.exe")
            {
                let process = Handle(OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | PROCESS_SYNCHRONIZE,
                    0,
                    entry.th32ProcessID,
                ));
                if !process.0.is_null()
                    && path_of_process(process.0).is_ok_and(|path| path == destination)
                    && sid_of_token(token(process.0)?.0)? == owner
                    && elevated(process.0)?
                {
                    if TerminateProcess(process.0, 0) == 0
                        || WaitForSingleObject(process.0, 5000) != WAIT_OBJECT_0
                    {
                        return Err(
                            "Close the Personal Vault broker before installing its update.".into(),
                        );
                    }
                }
            }
            found = Process32NextW(snapshot.0, &mut entry);
        }
    }
    Ok(())
}

pub(crate) fn verify_server(handle: HANDLE) -> Result<(), String> {
    unsafe {
        let mut pid = 0;
        if GetNamedPipeServerProcessId(handle, &mut pid) == 0 {
            return Err(last());
        }
        let process = Handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid));
        if process.0.is_null() {
            return Err(last());
        }
        let expected = installed_binary()?;
        if path_of_process(process.0)? != expected
            || !elevated(process.0)?
            || sid_of_token(token(process.0)?.0)? != user_sid()?
        {
            return Err("Cannot authenticate the protected vault broker".into());
        }
        verify_protected(expected.parent().unwrap(), true)?;
        verify_protected(&expected, true)
    }
}
/// The verified client identity and whether it is this account's Desktop.
pub(crate) fn peer(handle: HANDLE) -> Result<(crate::policy::Identity, bool), String> {
    use sha2::{Digest, Sha256};
    unsafe {
        let mut pid = 0;
        if GetNamedPipeClientProcessId(handle, &mut pid) == 0 {
            return Err(last());
        }
        let process = Handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid));
        if process.0.is_null() {
            return Err(last());
        }
        let sid = sid_of_token(token(process.0)?.0)?;
        if sid != user_sid()? {
            return Err("A different Windows user cannot access this vault".into());
        }
        let path = path_of_process(process.0)?;
        if !crate::policy::safe_text(&path.to_string_lossy(), 2048) {
            return Err("Client executable path cannot be displayed safely".into());
        }
        // Read-only sharing: the image cannot be rewritten while its fingerprint
        // and publisher are checked.
        let file = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(&path)
            .map_err(|_| "Cannot authenticate client executable")?;
        let mut digest = Sha256::new();
        std::io::copy(&mut &file, &mut digest)
            .map_err(|_| "Cannot fingerprint client executable")?;
        let desktop = desktop_client(&path, &file);
        let mut name = vec![0u16; 256];
        let mut len = name.len() as u32;
        if windows_sys::Win32::System::WindowsProgramming::GetComputerNameW(
            name.as_mut_ptr(),
            &mut len,
        ) == 0
        {
            return Err(last());
        }
        let mut identity = crate::policy::Identity::local(
            path.to_string_lossy().into(),
            hex::encode(digest.finalize()),
            String::from_utf16_lossy(&name[..len as usize]),
            sid.clone(),
            pid,
        );
        if let Some((launcher, hash)) = launcher(pid, process.0, &sid) {
            identity.environment =
                format!("Host computer; verified launcher: {launcher}\nLauncher SHA-256: {hash}");
            identity.id = hex::encode(Sha256::digest(format!(
                "{}\0{launcher}\0{hash}",
                identity.id
            )));
        }
        Ok((identity, desktop))
    }
}

/// `desktop` is the connection's verified Desktop status from `peer`.
pub(crate) fn desktop_foreground(identity: &crate::policy::Identity, desktop: bool) -> bool {
    use windows_sys::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowThreadProcessId};
    if !desktop { return false; }
    unsafe {
        let window = GetForegroundWindow();
        if window.is_null() { return false; }
        let mut process = 0;
        GetWindowThreadProcessId(window, &mut process);
        process == identity.process
    }
}
unsafe fn launcher(pid: u32, child: HANDLE, sid: &str) -> Option<(String, String)> {
    use sha2::{Digest, Sha256};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
    let snapshot = Handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if snapshot.0 == INVALID_HANDLE_VALUE {
        return None;
    }
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut found = Process32FirstW(snapshot.0, &mut entry);
    while found != 0 {
        if entry.th32ProcessID == pid {
            let parent = Handle(OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                0,
                entry.th32ParentProcessID,
            ));
            if parent.0.is_null() {
                return None;
            }
            if sid_of_token(token(parent.0).ok()?.0).ok()? != sid {
                return None;
            }
            let creation = |process| {
                let (mut start, mut end, mut kernel, mut user) = (
                    FILETIME::default(),
                    FILETIME::default(),
                    FILETIME::default(),
                    FILETIME::default(),
                );
                if GetProcessTimes(process, &mut start, &mut end, &mut kernel, &mut user) == 0 {
                    None
                } else {
                    Some(((start.dwHighDateTime as u64) << 32) | start.dwLowDateTime as u64)
                }
            };
            if creation(parent.0)? > creation(child)? {
                return None;
            }
            let path = path_of_process(parent.0).ok()?;
            let name = path.to_string_lossy().into_owned();
            if !crate::policy::safe_text(&name, 2048) {
                return None;
            }
            let mut file = std::fs::File::open(path).ok()?;
            let mut hash = Sha256::new();
            std::io::copy(&mut file, &mut hash).ok()?;
            return Some((name, hex::encode(hash.finalize())));
        }
        found = Process32NextW(snapshot.0, &mut entry);
    }
    None
}
pub(crate) fn bind(
    first: bool,
) -> Result<tokio::net::windows::named_pipe::NamedPipeServer, String> {
    unsafe {
        let sddl = wide(&format!(
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;{})S:(ML;;NW;;;ME)",
            user_sid()?
        ));
        let mut descriptor = null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            null_mut(),
        ) == 0
        {
            return Err(last());
        }
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let result = tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .max_instances(32)
            .create_with_security_attributes_raw(
                endpoint()?,
                (&mut attributes as *mut SECURITY_ATTRIBUTES).cast(),
            );
        LocalFree(descriptor);
        result.map_err(|_| {
            "Cannot open the protected vault endpoint. Another broker may already be running."
                .into()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn updates_elevate_a_copy_that_this_account_cannot_change() {
        let source = tempfile::tempdir().unwrap();
        let bundled = source.path().join("yougori-vault.exe");
        std::fs::write(&bundled, b"fixture broker").unwrap();
        let bundle = PinnedFile::open(&bundled).unwrap();
        // The pinned bundle cannot be replaced while it is being verified.
        assert!(std::fs::OpenOptions::new().write(true).open(&bundled).is_err());
        let digest = bundle.sha256().unwrap();
        let staged = Staged::create(&bundle, &digest).unwrap();
        let folder = staged.path.clone();
        assert_eq!(std::fs::read(folder.join("yougori-vault.exe")).unwrap(), b"fixture broker");
        assert_eq!(path_key(&staged.executable.path.to_string_lossy()), path_key(&std::fs::canonicalize(folder.join("yougori-vault.exe")).unwrap().to_string_lossy()));
        if !elevated(unsafe { GetCurrentProcess() }).unwrap() {
            // No DLL can be planted beside it and the owner cannot reopen the ACL.
            assert!(std::fs::File::create_new(folder.join("version.dll")).is_err());
            assert!(std::fs::OpenOptions::new().write(true).open(folder.join("yougori-vault.exe")).is_err());
            assert!(set_dacl(&folder, "D:P(A;;FA;;;WD)").is_err());
        }
        assert!(Staged::create(&bundle, &"0".repeat(64)).is_err());
        staged.remove();
        assert!(!folder.exists());
        drop(bundle);
        assert!(std::fs::OpenOptions::new().write(true).open(&bundled).is_ok());
    }
    #[test]
    fn executable_paths_compare_without_extended_prefixes_or_case() {
        assert_eq!(plain_path(r"\\?\C:\Apps\Yougori\yougori.exe"), r"C:\Apps\Yougori\yougori.exe");
        assert_eq!(plain_path(r"\\?\UNC\server\share\yougori.exe"), r"\\server\share\yougori.exe");
        assert_eq!(path_key(r"C:/Apps/YOUGORI/Yougori.exe"), path_key(r"\\?\c:\apps\yougori\yougori.exe"));
    }
}
