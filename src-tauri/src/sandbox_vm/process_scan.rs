//! The host's process list for the doctor's process-list observations (VM-CP-01's
//! `cp01.no-tcg-hypervisor`, VM-CP-33's `cp33.fallback-start`; the facts are built and
//! judged in `sandbox::probes::process_scan`): every process with its parent, image name and
//! creation time, and the command line of each hypervisor process when this process may read
//! it. Nothing here keeps a command line beyond the scan that classifies it. On Windows from
//! a Toolhelp snapshot; on Linux from `/proc` (creation times in clock ticks after boot).

#[cfg(windows)]
mod sys {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

    use windows_sys::Win32::Foundation::{FILETIME, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    use crate::sandbox::probes::{is_hypervisor_image, ListedProcess};

    /// The host's process list now.
    pub fn list_processes() -> Result<Vec<ListedProcess>, String> {
        // SAFETY: a process snapshot of the whole system takes no pointer.
        let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if raw == INVALID_HANDLE_VALUE || raw.is_null() {
            return Err(format!(
                "the process list could not be read: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: a valid snapshot handle CreateToolhelp32Snapshot has just returned is owned
        // here.
        let snapshot = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut entry = PROCESSENTRY32W {
            dwSize: u32::try_from(std::mem::size_of::<PROCESSENTRY32W>()).unwrap_or(u32::MAX),
            ..PROCESSENTRY32W::default()
        };
        let mut list = Vec::new();
        // SAFETY: the snapshot handle is open and `entry` is live with its size set.
        let mut more = unsafe { Process32FirstW(snapshot.as_raw_handle(), &mut entry) } != 0;
        while more {
            let name = &entry.szExeFile;
            let length = name.iter().position(|unit| *unit == 0).unwrap_or(name.len());
            let image = String::from_utf16_lossy(&name[..length]);
            let pid = entry.th32ProcessID;
            let (created, command_line) = inspect(pid, is_hypervisor_image(&image));
            list.push(ListedProcess {
                pid,
                parent: entry.th32ParentProcessID,
                image,
                created,
                command_line,
            });
            // SAFETY: as for Process32FirstW.
            more = unsafe { Process32NextW(snapshot.as_raw_handle(), &mut entry) } != 0;
        }
        Ok(list)
    }

    /// The creation time of `pid` and, for a hypervisor, its command line, when this process
    /// may open it for limited query; nothing of a process it may not open.
    fn inspect(pid: u32, hypervisor: bool) -> (Option<u64>, Option<Vec<String>>) {
        if pid == 0 {
            return (None, None);
        }
        // SAFETY: OpenProcess takes no pointer; a null result is checked.
        let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if raw.is_null() {
            return (None, None);
        }
        // SAFETY: a valid process handle OpenProcess has just returned is owned here.
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        let zero = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let (mut creation, mut exit, mut kernel, mut user) = (zero, zero, zero, zero);
        // SAFETY: the handle is open and the four FILETIMEs are live.
        let read = unsafe {
            GetProcessTimes(
                handle.as_raw_handle(),
                &mut creation,
                &mut exit,
                &mut kernel,
                &mut user,
            )
        } != 0;
        let created = read.then(|| {
            (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime)
        });
        let command_line = if hypervisor {
            crate::foundation::process::read_command_line(handle.as_raw_handle()).ok()
        } else {
            None
        };
        (created, command_line)
    }
}

#[cfg(target_os = "linux")]
mod sys {
    use crate::sandbox::probes::{is_hypervisor_image, ListedProcess};

    /// One process's stat fields after the command name: its state at index 0, its parent
    /// at 1 and its start time (clock ticks after boot) at 19.
    fn stat_fields(pid: u32) -> Option<Vec<String>> {
        let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let (_, rest) = text.rsplit_once(')')?;
        Some(rest.split_whitespace().map(str::to_owned).collect())
    }

    /// The image name: the executable's file name where this process may read the link
    /// (`/proc/<pid>/exe`), else the kernel's 15-byte command name.
    fn image_of(pid: u32) -> String {
        std::fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .and_then(|path| path.file_name().map(|name| name.to_string_lossy().into_owned()))
            .or_else(|| {
                std::fs::read_to_string(format!("/proc/{pid}/comm"))
                    .ok()
                    .map(|name| name.trim().to_owned())
            })
            .unwrap_or_default()
    }

    /// The host's process list now (`/proc`).
    pub fn list_processes() -> Result<Vec<ListedProcess>, String> {
        let entries = std::fs::read_dir("/proc")
            .map_err(|error| format!("the process list could not be read: {error}"))?;
        let mut list = Vec::new();
        for entry in entries.filter_map(Result::ok) {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            let Some(fields) = stat_fields(pid) else {
                continue;
            };
            let image = image_of(pid);
            let command_line = is_hypervisor_image(&image)
                .then(|| std::fs::read(format!("/proc/{pid}/cmdline")).ok())
                .flatten()
                .map(|raw| {
                    raw.split(|byte| *byte == 0)
                        .filter(|part| !part.is_empty())
                        .map(|part| String::from_utf8_lossy(part).into_owned())
                        .collect()
                });
            list.push(ListedProcess {
                pid,
                parent: fields.get(1).and_then(|value| value.parse().ok()).unwrap_or(0),
                image,
                created: fields.get(19).and_then(|value| value.parse().ok()),
                command_line,
            });
        }
        Ok(list)
    }
}

pub use sys::list_processes;

#[cfg(test)]
mod tests {
    use super::*;

    /// PROVES the scan lists this test process with its creation time, and that a QEMU
    /// image's command line is read when the process may be opened.
    #[test]
    fn the_process_list_holds_this_process() {
        let list = list_processes().unwrap();
        let me = std::process::id();
        let mine = list.iter().find(|process| process.pid == me).unwrap();
        assert!(mine.created.is_some());
        assert!(mine.command_line.is_none(), "only hypervisors' command lines are read");
        assert!(list.len() > 1, "{} processes", list.len());
    }
}
