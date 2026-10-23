//! Whether the person at this computer is using it: time since their last keyboard or
//! mouse input. Remote (SSH) sessions do not count as someone at the computer.
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Activity {
    /// Time since the signed-in person last used the keyboard or mouse.
    Idle(Duration),
    /// Nobody is signed in at this computer's screen or console.
    Nobody,
    /// This computer cannot report user activity.
    Unknown(String),
}

/// Reads the operating system; on Linux and macOS this runs a short system command,
/// so call it from a blocking thread.
pub fn current() -> Activity {
    imp::current()
}

#[cfg(windows)]
mod imp {
    use super::*;
    use windows_sys::Win32::{
        System::SystemInformation::GetTickCount,
        UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO},
    };
    pub fn current() -> Activity {
        let mut info = LASTINPUTINFO { cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32, dwTime: 0 };
        // SAFETY: `info` is a correctly sized LASTINPUTINFO owned by this frame.
        if unsafe { GetLastInputInfo(&mut info) } == 0 {
            return Activity::Unknown("Windows did not report the last keyboard or mouse input".into());
        }
        // Both counters wrap after 49.7 days; wrapping subtraction keeps the difference right.
        let now = unsafe { GetTickCount() };
        Activity::Idle(Duration::from_millis(u64::from(now.wrapping_sub(info.dwTime))))
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::*;
    pub fn current() -> Activity {
        let output = std::process::Command::new("/usr/sbin/ioreg").args(["-c", "IOHIDSystem", "-d", "4", "-r", "-k", "HIDIdleTime"]).output();
        match output {
            Ok(output) if output.status.success() => parse_ioreg(&String::from_utf8_lossy(&output.stdout))
                .map_or_else(|| Activity::Unknown("macOS did not report keyboard and mouse activity".into()), Activity::Idle),
            _ => Activity::Unknown("macOS did not report keyboard and mouse activity".into()),
        }
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
mod imp {
    use super::*;
    use std::process::Command;
    pub fn current() -> Activity {
        let unknown = || Activity::Unknown("systemd-logind did not report user sessions on this computer".into());
        let Ok(list) = Command::new("loginctl").args(["list-sessions", "--no-legend"]).output() else { return unknown() };
        if !list.status.success() {
            return unknown();
        }
        let mut sessions = Vec::new();
        for id in String::from_utf8_lossy(&list.stdout).lines().filter_map(|line| line.split_whitespace().next()).take(64) {
            let properties = ["Class", "Remote", "Active", "IdleHint", "IdleSinceHint"].iter().flat_map(|name| ["-p", *name]);
            // A session whose details cannot be read is not evidence that nobody is there.
            match Command::new("loginctl").arg("show-session").arg(id).args(properties).output() {
                Ok(output) if output.status.success() => sessions.push(String::from_utf8_lossy(&output.stdout).into_owned()),
                _ => return Activity::Unknown(format!("systemd-logind did not describe session {id} on this computer")),
            }
        }
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        from_logind(&sessions, now.as_micros() as u64)
    }
}

/// `ioreg` reports nanoseconds since the last input as `"HIDIdleTime" = N`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn parse_ioreg(text: &str) -> Option<Duration> {
    text.lines()
        .find_map(|line| line.split_once("\"HIDIdleTime\" = ").and_then(|(_, value)| value.trim().parse::<u64>().ok()))
        .map(Duration::from_nanos)
}

/// The least idle active local session. logind sets an idle hint once the desktop or console
/// has been idle for its own timeout; until then the person counts as present.
#[cfg_attr(any(windows, target_os = "macos"), allow(dead_code))]
fn from_logind(sessions: &[String], now_micros: u64) -> Activity {
    let mut least: Option<Duration> = None;
    for text in sessions {
        let property = |name: &str| text.lines().find_map(|line| line.strip_prefix(name)?.strip_prefix('='));
        if property("Class") != Some("user") || property("Remote") == Some("yes") || property("Active") != Some("yes") {
            continue;
        }
        let idle = if property("IdleHint") == Some("yes") {
            property("IdleSinceHint")
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|since| *since > 0)
                .map_or(Duration::ZERO, |since| Duration::from_micros(now_micros.saturating_sub(since)))
        } else {
            Duration::ZERO
        };
        least = Some(least.map_or(idle, |least| least.min(idle)));
    }
    least.map_or(Activity::Nobody, Activity::Idle)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn macos_idle_time_is_read_from_ioreg() {
        let text = "  |   \"HIDIdleTime\" = 125000000000\n  |   \"Other\" = 1\n";
        assert_eq!(parse_ioreg(text), Some(Duration::from_secs(125)));
        assert_eq!(parse_ioreg("nothing here"), None);
    }
    #[test]
    fn logind_counts_only_active_local_people() {
        let now = 1_000_000_000_000;
        let idle = |seconds: u64| format!("Class=user\nRemote=no\nActive=yes\nIdleHint=yes\nIdleSinceHint={}\n", now - seconds * 1_000_000);
        assert_eq!(from_logind(&[idle(600)], now), Activity::Idle(Duration::from_secs(600)));
        let present = "Class=user\nRemote=no\nActive=yes\nIdleHint=no\nIdleSinceHint=0\n".to_owned();
        assert_eq!(from_logind(&[idle(600), present], now), Activity::Idle(Duration::ZERO));
        let remote = "Class=user\nRemote=yes\nActive=yes\nIdleHint=no\n".to_owned();
        let greeter = "Class=greeter\nRemote=no\nActive=yes\nIdleHint=no\n".to_owned();
        let background = "Class=user\nRemote=no\nActive=no\nIdleHint=no\n".to_owned();
        assert_eq!(from_logind(&[remote, greeter, background], now), Activity::Nobody);
        assert_eq!(from_logind(&[], now), Activity::Nobody);
    }
    #[test]
    fn this_computer_reports_something() {
        // Any answer is valid; the call must not panic or hang.
        let _ = current();
    }
}
