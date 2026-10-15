//! Weekly windows in a computer's local time when it may serve the grid,
//! e.g. `Mon-Fri 18:00-08:00; Sat,Sun`.
use std::{fmt, str::FromStr};

const DAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const NAMES: [&str; 7] = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"];
const WHOLE_DAY: (u16, u16) = (0, 1440);

#[derive(Clone, Debug, PartialEq, Eq)]
struct Window {
    /// Monday first.
    days: [bool; 7],
    /// Minutes after midnight. A window that ends before it starts runs past midnight
    /// into the next day, so `Fri 18:00-08:00` lasts until Saturday morning.
    start: u16,
    end: u16,
}

/// One or more windows separated by `;`. Each names its days (`Mon`, `Mon-Fri`, `Sat,Sun`,
/// `daily`, `weekdays`, `weekends`) and optionally a time range; without times the days
/// count whole. A time range alone applies every day.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Schedule {
    windows: Vec<Window>,
}

fn day(text: &str) -> Result<usize, String> {
    let lower = text.trim().to_ascii_lowercase();
    NAMES
        .iter()
        .position(|name| lower.len() >= 3 && name.starts_with(&lower))
        .ok_or_else(|| format!("Unknown day '{}': use Mon, Tue, Wed, Thu, Fri, Sat or Sun", text.trim()))
}

fn days(text: &str) -> Result<[bool; 7], String> {
    let mut set = [false; 7];
    for item in text.split(',').map(str::trim) {
        match item.to_ascii_lowercase().as_str() {
            "daily" => set = [true; 7],
            "weekdays" => set[..5].fill(true),
            "weekends" => set[5..].fill(true),
            _ => {
                let (first, last) = item.split_once('-').unwrap_or((item, item));
                let (first, last) = (day(first)?, day(last)?);
                // Ranges may wrap around the week: Sat-Mon.
                let mut current = first;
                loop {
                    set[current] = true;
                    if current == last {
                        break;
                    }
                    current = (current + 1) % 7;
                }
            }
        }
    }
    Ok(set)
}

fn minute(text: &str, end: bool) -> Result<u16, String> {
    let invalid = || format!("Invalid time '{text}': write 24-hour times such as 08:00 or 18:30");
    let (hours, minutes) = text.split_once(':').ok_or_else(invalid)?;
    if hours.is_empty() || hours.len() > 2 || minutes.len() != 2 {
        return Err(invalid());
    }
    let (hours, minutes): (u16, u16) = (hours.parse().map_err(|_| invalid())?, minutes.parse().map_err(|_| invalid())?);
    if end && hours == 24 && minutes == 0 {
        return Ok(1440);
    }
    if hours > 23 || minutes > 59 {
        return Err(invalid());
    }
    Ok(hours * 60 + minutes)
}

fn clock(minute: u16) -> String {
    format!("{:02}:{:02}", minute / 60, minute % 60)
}

fn describe(days: &[bool; 7]) -> String {
    if days.iter().all(|day| *day) {
        return "daily".into();
    }
    let mut parts = Vec::new();
    let mut index = 0;
    while index < 7 {
        if !days[index] {
            index += 1;
            continue;
        }
        let start = index;
        while index + 1 < 7 && days[index + 1] {
            index += 1;
        }
        parts.push(if start == index { DAYS[start].to_owned() } else { format!("{}-{}", DAYS[start], DAYS[index]) });
        index += 1;
    }
    parts.join(",")
}

impl FromStr for Schedule {
    type Err = String;
    fn from_str(text: &str) -> Result<Self, String> {
        if text.len() > 512 {
            return Err("A schedule must be at most 512 characters".into());
        }
        let mut windows = Vec::new();
        for part in text.split(';').map(str::trim).filter(|part| !part.is_empty()) {
            let (names, range) = match part.rsplit_once(char::is_whitespace) {
                Some((names, range)) if range.contains(':') => (names.trim(), Some(range)),
                None if part.contains(':') => ("daily", Some(part)),
                _ => (part, None),
            };
            let (start, end) = match range {
                None => WHOLE_DAY,
                Some(range) => {
                    let (start, end) = range.split_once('-').ok_or_else(|| format!("Invalid time range '{range}': write it as 18:00-08:00"))?;
                    (minute(start, false)?, minute(end, true)?)
                }
            };
            if start == end {
                return Err(format!("'{part}' starts and ends at the same time; leave out the times to use whole days"));
            }
            windows.push(Window { days: days(names)?, start, end });
        }
        if windows.is_empty() {
            return Err("The schedule is empty; for example: Mon-Fri 18:00-08:00; Sat,Sun".into());
        }
        if windows.len() > 32 {
            return Err("A schedule can have at most 32 windows".into());
        }
        Ok(Self { windows })
    }
}

impl fmt::Display for Schedule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let parts = self.windows.iter().map(|window| {
            if (window.start, window.end) == WHOLE_DAY {
                describe(&window.days)
            } else {
                format!("{} {}-{}", describe(&window.days), clock(window.start), clock(window.end))
            }
        });
        write!(f, "{}", parts.collect::<Vec<_>>().join("; "))
    }
}

impl Schedule {
    /// `weekday` counts from Monday = 0; `minute` from midnight.
    pub fn contains(&self, weekday: usize, minute: u16) -> bool {
        let previous = (weekday + 6) % 7;
        self.windows.iter().any(|window| {
            if window.start < window.end {
                window.days[weekday] && (window.start..window.end).contains(&minute)
            } else {
                window.days[weekday] && minute >= window.start || window.days[previous] && minute < window.end
            }
        })
    }

    pub fn contains_local(&self, now: &chrono::DateTime<chrono::Local>) -> bool {
        use chrono::{Datelike, Timelike};
        self.contains(now.weekday().num_days_from_monday() as usize, (now.hour() * 60 + now.minute()) as u16)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const MON: usize = 0;
    const FRI: usize = 4;
    const SAT: usize = 5;
    const SUN: usize = 6;
    fn at(hours: u16, minutes: u16) -> u16 {
        hours * 60 + minutes
    }
    #[test]
    fn overnight_windows_run_into_the_next_morning() {
        let schedule: Schedule = "Mon-Fri 18:00-08:00; Sat,Sun".parse().unwrap();
        assert!(!schedule.contains(MON, at(12, 0)));
        assert!(schedule.contains(MON, at(18, 0)));
        assert!(schedule.contains(MON, at(23, 59)));
        assert!(!schedule.contains(MON, at(7, 59)), "Sunday's whole day does not reach into Monday morning");
        assert!(schedule.contains(FRI + 1, at(7, 59)), "Friday night runs into Saturday");
        assert!(schedule.contains(SAT, at(12, 0)) && schedule.contains(SUN, at(23, 0)));
        assert!(!schedule.contains(FRI, at(17, 59)));
    }
    #[test]
    fn sunday_night_wraps_into_monday() {
        let schedule: Schedule = "Sun 22:00-06:00".parse().unwrap();
        assert!(schedule.contains(MON, at(5, 59)));
        assert!(!schedule.contains(MON, at(6, 0)));
        assert!(schedule.contains(SUN, at(22, 0)));
        assert!(!schedule.contains(SAT, at(23, 0)));
    }
    #[test]
    fn aliases_ranges_and_times_alone() {
        let schedule: Schedule = "weekdays 09:00-17:00".parse().unwrap();
        assert!(schedule.contains(FRI, at(9, 0)) && !schedule.contains(SAT, at(10, 0)) && !schedule.contains(MON, at(17, 0)));
        let nightly: Schedule = "20:00-24:00".parse().unwrap();
        assert!((0..7).all(|day| nightly.contains(day, at(23, 59)) && !nightly.contains(day, at(19, 59))));
        let wrapped: Schedule = "Sat-Mon".parse().unwrap();
        assert!(wrapped.contains(SAT, 0) && wrapped.contains(SUN, 0) && wrapped.contains(MON, 0) && !wrapped.contains(FRI, 0));
        let spaced: Schedule = "Mon, Wed 09:00-12:00; saturday".parse().unwrap();
        assert!(spaced.contains(2, at(10, 0)) && !spaced.contains(1, at(10, 0)) && spaced.contains(SAT, 0));
    }
    #[test]
    fn canonical_text_round_trips() {
        for (input, canonical) in [
            ("mon-fri 18:00-08:00; sat,sun", "Mon-Fri 18:00-08:00; Sat-Sun"),
            ("weekends", "Sat-Sun"),
            ("20:00-24:00", "daily 20:00-24:00"),
            ("Mon, Wed 9:00-12:00", "Mon,Wed 09:00-12:00"),
        ] {
            let schedule: Schedule = input.parse().unwrap();
            assert_eq!(schedule.to_string(), canonical);
            assert_eq!(canonical.parse::<Schedule>().unwrap(), schedule);
        }
    }
    #[test]
    fn invalid_schedules_explain_themselves() {
        for (input, needle) in [
            ("", "empty"),
            ("Funday", "Unknown day"),
            ("Mon 25:00-08:00", "Invalid time"),
            ("Mon 08:00", "Invalid time range"),
            ("Mon 08:00-08:00", "same time"),
            ("Mon 8-17", "Unknown day"),
            ("Mon 24:00-08:00", "Invalid time"),
            ("Mon 08:5-09:00", "Invalid time"),
        ] {
            let error = input.parse::<Schedule>().unwrap_err();
            assert!(error.contains(needle), "{input}: {error}");
        }
        assert!(["Mon"; 33].join(";").parse::<Schedule>().is_err());
    }
}
