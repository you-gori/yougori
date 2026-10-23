//! Whether this computer runs on its battery, and how much is left. A computer on battery hosts
//! no new desk, and one whose battery is running down hands the desks it holds to another
//! computer while it still has the time to copy them.
use std::time::Duration;

/// How a computer is powered right now.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Power {
    pub on_battery: bool,
    /// What is left, 0–100, when the computer reports it.
    pub percent: Option<u8>,
}

impl Power {
    /// On battery and low enough that a desk should move before the computer sleeps.
    pub fn draining(self, below: u8) -> bool {
        self.on_battery && self.percent.is_some_and(|percent| percent <= below)
    }
}

/// Reads the operating system; on Linux and macOS this runs a short system command or reads
/// `/sys`, so call it from a blocking thread.
pub fn current() -> Power {
    imp::current()
}

#[cfg(windows)]
mod imp {
    use super::*;
    use windows_sys::Win32::System::Power::{GetSystemPowerStatus, SYSTEM_POWER_STATUS};
    pub fn current() -> Power {
        let mut status = SYSTEM_POWER_STATUS { ACLineStatus: 255, BatteryFlag: 255, BatteryLifePercent: 255, SystemStatusFlag: 0, BatteryLifeTime: u32::MAX, BatteryFullLifeTime: u32::MAX };
        // SAFETY: `status` is a correctly sized SYSTEM_POWER_STATUS owned by this frame.
        if unsafe { GetSystemPowerStatus(&mut status) } == 0 {
            return Power::default();
        }
        // 128 in BatteryFlag means no battery at all: a desktop is never "on battery".
        Power {
            on_battery: status.ACLineStatus == 0 && status.BatteryFlag != 128,
            percent: (status.BatteryLifePercent <= 100).then_some(status.BatteryLifePercent),
        }
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::*;
    pub fn current() -> Power {
        let Ok(output) = std::process::Command::new("/usr/bin/pmset").args(["-g", "batt"]).output() else { return Power::default() };
        if !output.status.success() {
            return Power::default();
        }
        read_pmset(&String::from_utf8_lossy(&output.stdout))
    }
}

/// `pmset -g batt` says which source is drawing and, with a battery, its percentage.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn read_pmset(text: &str) -> Power {
    let on_battery = text.contains("'Battery Power'");
    let percent = text
        .split_once(";")
        .and_then(|(head, _)| head.rsplit_once('\t'))
        .and_then(|(_, tail)| tail.trim().strip_suffix('%'))
        .and_then(|value| value.parse().ok());
    Power { on_battery, percent: percent.filter(|percent| *percent <= 100) }
}

#[cfg(all(unix, not(target_os = "macos")))]
mod imp {
    use super::*;
    use std::path::Path;
    pub fn current() -> Power {
        let supply = Path::new("/sys/class/power_supply");
        let Ok(entries) = std::fs::read_dir(supply) else { return Power::default() };
        let mut power = Power::default();
        let mut mains_online = None;
        for entry in entries.flatten() {
            let path = entry.path();
            let kind = std::fs::read_to_string(path.join("type")).unwrap_or_default();
            match kind.trim() {
                "Mains" => {
                    let online = std::fs::read_to_string(path.join("online")).unwrap_or_default();
                    mains_online = Some(mains_online.unwrap_or(false) || online.trim() == "1");
                }
                "Battery" => {
                    if let Some(percent) = std::fs::read_to_string(path.join("capacity")).ok().and_then(|value| value.trim().parse::<u8>().ok()) {
                        power.percent = Some(power.percent.map_or(percent, |have: u8| have.min(percent)));
                    }
                }
                _ => {}
            }
        }
        // Only a computer with a battery can be on battery; no mains supply at all means a desktop.
        power.on_battery = power.percent.is_some() && mains_online == Some(false);
        power
    }
}

/// Lower bound for how long a battery lasts, so a computer with little left hands its desks on
/// before it sleeps. Used only to explain the decision; the percentage is what decides.
pub const MOVE_BELOW_PERCENT: u8 = 30;
/// A computer with less free disk than this cannot take another desk's data.
pub const KEEP_FREE_DISK_GB: f64 = 10.0;
/// Below this much free disk, a computer hands its desks on before it runs out.
pub const LOW_DISK_GB: f64 = 5.0;
/// How long a desk's data may take to copy; a computer going away waits this long for it.
pub const MOVE_WAIT: Duration = Duration::from_secs(15 * 60);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_draining_battery_is_told_apart_from_a_full_one_and_from_mains() {
        assert!(Power { on_battery: true, percent: Some(12) }.draining(MOVE_BELOW_PERCENT));
        assert!(!Power { on_battery: true, percent: Some(88) }.draining(MOVE_BELOW_PERCENT));
        assert!(!Power { on_battery: false, percent: Some(4) }.draining(MOVE_BELOW_PERCENT), "plugged in is never draining");
        assert!(!Power { on_battery: true, percent: None }.draining(MOVE_BELOW_PERCENT), "an unknown battery is not assumed to be low");
        // A real computer is read without panicking, whatever it runs on.
        let _ = current();
    }

    #[test]
    fn macos_battery_output_is_read() {
        let battery = "Now drawing from 'Battery Power'\n -InternalBattery-0 (id=1234)\t27%; discharging; 1:12 remaining present: true\n";
        assert_eq!(read_pmset(battery), Power { on_battery: true, percent: Some(27) });
        let mains = "Now drawing from 'AC Power'\n -InternalBattery-0 (id=1234)\t100%; charged; 0:00 remaining present: true\n";
        assert_eq!(read_pmset(mains), Power { on_battery: false, percent: Some(100) });
        assert_eq!(read_pmset("nothing useful"), Power::default());
    }
}
