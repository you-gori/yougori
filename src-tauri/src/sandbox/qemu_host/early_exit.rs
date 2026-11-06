//! QEMU's own report when it ends before its QMP socket accepts a connection, read the
//! same way on every host (M02, M04; docs/combined-gpu-memory-and-vm-sandbox-plan.md:
//! VM-W22 row, line 2621): the tail of its standard error ([`log_tail`]) and what it means
//! ([`classify_report`]). A line whose message names the host's hardware hypervisor is
//! [`StartFailure::HardwareVirtualization`] with QEMU's text: the launch is refused and
//! nothing retries into emulation. Anything else is a process failure with the text and
//! the exit code. Each host names its own hypervisor's words (WHPX on Windows, KVM on
//! Linux) and writes its own exit codes.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::foundation::process::ProcessError;
use crate::sandbox::qemu::StartFailure;

/// The most bytes of QEMU's standard error the host reads back, from its end.
pub const MAX_STDERR_TAIL_BYTES: usize = 4096;
/// The most bytes of QEMU's text a start failure carries.
pub const MAX_FAILURE_TEXT_BYTES: usize = 1024;

/// The last [`MAX_STDERR_TAIL_BYTES`] of QEMU's log, or why it could not be read.
pub fn log_tail(path: &Path) -> String {
    let read = || -> std::io::Result<String> {
        let mut file = File::open(path)?;
        let length = file.metadata()?.len();
        let tail = u64::try_from(MAX_STDERR_TAIL_BYTES).unwrap_or(u64::MAX);
        file.seek(SeekFrom::Start(length.saturating_sub(tail)))?;
        let mut bytes = Vec::new();
        file.take(tail).read_to_end(&mut bytes)?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    };
    read().unwrap_or_else(|error| format!("(QEMU's log could not be read: {error})"))
}

/// What QEMU's report of an end before QMP answered means (module notes):
/// `hardware_words` the host's hypervisor words, `exit` the exit code as the host writes
/// it, `stderr` the tail of QEMU's standard error.
pub fn classify_report(hardware_words: &[&str], exit: &str, stderr: &str) -> StartFailure {
    let lines: Vec<&str> = stderr
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    let hardware: Vec<&str> = lines
        .iter()
        .copied()
        .filter(|line| reports_hardware(hardware_words, line))
        .collect();
    if !hardware.is_empty() {
        return StartFailure::HardwareVirtualization {
            detail: bounded(&hardware.join("; ")),
        };
    }
    let report = if lines.is_empty() {
        "it wrote nothing to standard error".to_owned()
    } else {
        format!("its standard error: {}", bounded(&lines.join("; ")))
    };
    StartFailure::Process {
        error: ProcessError::Spawn {
            detail: format!(
                "QEMU exited with code {exit} before its QMP socket accepted a connection; {report}"
            ),
        },
    }
}

/// Whether a line of QEMU's standard error reports the hardware hypervisor: its message,
/// after QEMU's program name and an option location such as `-accel whpx,...:`, names it.
fn reports_hardware(hardware_words: &[&str], line: &str) -> bool {
    let message = message_of(line).to_ascii_lowercase();
    hardware_words.iter().any(|word| message.contains(word))
}

/// The message of a QEMU error line `<program>: [<option>: ]<message>`.
fn message_of(line: &str) -> &str {
    let mut rest = line;
    if let Some((program, after)) = rest.split_once(": ") {
        if program.to_ascii_lowercase().contains("qemu") {
            rest = after;
        }
    }
    if rest.starts_with('-') {
        if let Some((_, after)) = rest.split_once(": ") {
            rest = after;
        }
    }
    rest
}

/// `text` with control characters as spaces, cut to [`MAX_FAILURE_TEXT_BYTES`] at a
/// character boundary.
fn bounded(text: &str) -> String {
    let clean: String = text
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect();
    if clean.len() <= MAX_FAILURE_TEXT_BYTES {
        return clean;
    }
    let mut end = MAX_FAILURE_TEXT_BYTES;
    while !clean.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &clean[..end])
}
