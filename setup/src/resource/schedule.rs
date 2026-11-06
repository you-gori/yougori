//! When a scheduled backup runs: the times a template writes (`daily 02:00`, `Mon-Fri 01:30;
//! Sun 04:00`), the time zone they are read in, and the arithmetic that turns both into moments
//! in UTC. Everything here is pure: the engine keeps its schedules in UTC and asks this module
//! for the next moment, so every client and the engine agree on the same words and times.
//!
//! The day words are the grid's (`grid/src/schedule.rs`): `daily`, `weekdays`, `weekends`, a day
//! (`Mon`) or a range (`Mon-Fri`, `Sat-Mon`) and lists of them (`Mon,Thu`). A grid schedule names
//! windows; this one names moments, so each entry gives one or more times of day instead of a
//! range.
//!
//! Daylight saving follows RFC 5545 (iCalendar, section 3.3.5): a time that does not exist on the
//! day the clocks go forward is read with the offset in force before the change, so 02:30 runs
//! at 03:30; a time that happens twice when the clocks go back runs once, the first time.
//!
//! Time zones: `local` (this computer's own clock, with the daylight-saving rules its operating
//! system keeps), `UTC`, a fixed offset (`UTC+02:00`, which never changes for daylight saving),
//! or one of the named zones below, with the daylight-saving rules they follow today. No time
//! zone database is compiled in: a country that changes its rules needs a newer Yougori, and a
//! zone not in the list can be written as `local` on a computer set to it.
use std::{fmt, str::FromStr};

/// The longest schedule text.
pub const SCHEDULE_CHARS: usize = 200;
/// Entries separated by `;`.
pub const ENTRIES: usize = 8;
/// Times in one entry.
pub const TIMES: usize = 24;

const DAY: i64 = 86_400;
const DAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const DAY_NAMES: [&str; 7] = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
const LOWER: [&str; 7] = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"];

#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    /// Monday first.
    days: [bool; 7],
    /// Minutes after midnight, sorted, each once.
    minutes: Vec<u16>,
}

/// The moments of a schedule, in the wall-clock time of its zone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Times {
    entries: Vec<Entry>,
}

fn day(text: &str) -> Result<usize, String> {
    let lower = text.trim().to_ascii_lowercase();
    LOWER
        .iter()
        .position(|name| lower.len() >= 3 && name.starts_with(&lower))
        .ok_or_else(|| format!("{} is not a day: use Mon, Tue, Wed, Thu, Fri, Sat or Sun", crate::text::shown(text.trim())))
}

fn days(text: &str) -> Result<[bool; 7], String> {
    let mut set = [false; 7];
    for item in text.split(',').map(str::trim) {
        match item.to_ascii_lowercase().as_str() {
            "daily" => set = [true; 7],
            "weekdays" => set[..5].fill(true),
            "weekends" => set[5..].fill(true),
            "" => return Err("a list of days has an empty item".into()),
            _ => {
                let (first, last) = item.split_once('-').unwrap_or((item, item));
                let (first, last) = (day(first)?, day(last)?);
                // A range may wrap around the week: Sat-Mon.
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

fn minute(text: &str) -> Result<u16, String> {
    let invalid = || format!("{} is not a time: write 24-hour times such as 02:00 or 18:30", crate::text::shown(text));
    let (hours, minutes) = text.split_once(':').ok_or_else(invalid)?;
    if hours.is_empty() || hours.len() > 2 || minutes.len() != 2 || !hours.bytes().chain(minutes.bytes()).all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }
    let (hours, minutes): (u16, u16) = (hours.parse().map_err(|_| invalid())?, minutes.parse().map_err(|_| invalid())?);
    if hours > 23 || minutes > 59 {
        return Err(invalid());
    }
    Ok(hours * 60 + minutes)
}

fn clock(minute: u16) -> String {
    format!("{:02}:{:02}", minute / 60, minute % 60)
}

/// The days as the schedule writes them: `daily`, `weekdays`, `Mon-Fri,Sun`.
fn short_days(days: &[bool; 7]) -> String {
    match days {
        [true, true, true, true, true, true, true] => return "daily".into(),
        [true, true, true, true, true, false, false] => return "weekdays".into(),
        [false, false, false, false, false, true, true] => return "weekends".into(),
        _ => {}
    }
    runs(days).into_iter().map(|(start, end)| if start == end { DAYS[start].to_owned() } else { format!("{}-{}", DAYS[start], DAYS[end]) }).collect::<Vec<_>>().join(",")
}

/// The days in words: `every day`, `Monday to Friday`, `Monday and Thursday`.
fn day_words(days: &[bool; 7]) -> String {
    match days {
        [true, true, true, true, true, true, true] => return "every day".into(),
        [true, true, true, true, true, false, false] => return "on weekdays".into(),
        [false, false, false, false, false, true, true] => return "at weekends".into(),
        _ => {}
    }
    // Three days or more in a row read as a range; one or two as names.
    let parts = runs(days)
        .into_iter()
        .flat_map(|(start, end)| {
            if end - start >= 2 {
                vec![format!("{} to {}", DAY_NAMES[start], DAY_NAMES[end])]
            } else {
                (start..=end).map(|day| DAY_NAMES[day].to_owned()).collect()
            }
        })
        .collect::<Vec<_>>();
    format!("on {}", list(&parts))
}

/// Consecutive days, Monday first.
fn runs(days: &[bool; 7]) -> Vec<(usize, usize)> {
    let mut found = Vec::new();
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
        found.push((start, index));
        index += 1;
    }
    found
}

fn list(parts: &[String]) -> String {
    match parts {
        [] => String::new(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

impl FromStr for Times {
    type Err = String;
    fn from_str(text: &str) -> Result<Times, String> {
        if text.chars().count() > SCHEDULE_CHARS {
            return Err(format!("a schedule is at most {SCHEDULE_CHARS} characters"));
        }
        if text.chars().any(char::is_control) {
            return Err("a schedule is one line of text".into());
        }
        let mut entries = Vec::new();
        for part in text.split(';').map(str::trim) {
            if part.is_empty() {
                continue;
            }
            // `DAYS TIME[,TIME…]`, or the times alone for every day.
            let (names, times) = match part.rsplit_once(char::is_whitespace) {
                Some((names, times)) => (names.trim(), times),
                None if part.contains(':') => ("daily", part),
                None => return Err(format!("{} names no time: write the days and a time, such as daily 02:00", crate::text::shown(part))),
            };
            if !times.contains(':') {
                return Err(format!("{} names no time: write the days and a time, such as daily 02:00", crate::text::shown(part)));
            }
            let mut minutes = times.split(',').map(|time| minute(time.trim())).collect::<Result<Vec<_>, _>>()?;
            if minutes.len() > TIMES {
                return Err(format!("an entry has at most {TIMES} times"));
            }
            let count = minutes.len();
            minutes.sort_unstable();
            minutes.dedup();
            if minutes.len() != count {
                return Err(format!("{} names the same time twice", crate::text::shown(part)));
            }
            entries.push(Entry { days: days(names)?, minutes });
        }
        if entries.is_empty() {
            return Err("the schedule is empty: write the days and a time, such as daily 02:00 or Mon-Fri 01:30".into());
        }
        if entries.len() > ENTRIES {
            return Err(format!("a schedule has at most {ENTRIES} entries"));
        }
        Ok(Times { entries })
    }
}

impl fmt::Display for Times {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let parts = self
            .entries
            .iter()
            .map(|entry| format!("{} {}", short_days(&entry.days), entry.minutes.iter().map(|m| clock(*m)).collect::<Vec<_>>().join(",")));
        formatter.write_str(&parts.collect::<Vec<_>>().join("; "))
    }
}

impl Times {
    /// The schedule in a sentence: `every day at 02:00; on Sunday at 04:00 and 16:00`.
    pub fn describe(&self) -> String {
        self.entries
            .iter()
            .map(|entry| format!("{} at {}", day_words(&entry.days), list(&entry.minutes.iter().map(|m| clock(*m)).collect::<Vec<_>>())))
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// The shortest gap between two runs in a week, in minutes (a schedule that runs every
    /// minute is allowed, but the review says so).
    pub fn shortest_gap_minutes(&self) -> u32 {
        let mut moments = self
            .entries
            .iter()
            .flat_map(|entry| (0..7).filter(|d| entry.days[*d]).flat_map(move |d| entry.minutes.iter().map(move |m| d as u32 * 1440 + u32::from(*m))))
            .collect::<Vec<_>>();
        moments.sort_unstable();
        moments.dedup();
        let week = 7 * 1440;
        match moments.as_slice() {
            [] => week,
            [_] => week,
            many => many.windows(2).map(|pair| pair[1] - pair[0]).chain([many[0] + week - many[many.len() - 1]]).min().unwrap_or(week),
        }
    }
}

// ---- Time zones ----

/// When the clocks change: the `week`th `weekday` (0 = Sunday) of `month`, 5 meaning the last,
/// at `at` seconds after midnight in the time in force just before the change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Change {
    month: u32,
    week: u32,
    weekday: u32,
    at: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Summer {
    /// How far summer time is ahead of standard time, in seconds.
    save: i64,
    start: Change,
    end: Change,
}

/// A named zone: its standard offset east of UTC and today's daylight-saving rule, if any.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Named {
    pub name: &'static str,
    standard: i64,
    summer: Option<Summer>,
}

const fn hours(hours: i64, minutes: i64) -> i64 {
    hours * 3600 + if hours < 0 { -minutes * 60 } else { minutes * 60 }
}

const fn change(month: u32, week: u32, at_hours: i64) -> Change {
    Change { month, week, weekday: 0, at: at_hours * 3600 }
}

/// The European Union's rule, which the UK and most of Europe also follow: the last Sunday of
/// March to the last Sunday of October, both at 01:00 UTC.
const fn europe(standard: i64) -> Option<Summer> {
    let utc_one = 3600;
    Some(Summer {
        save: 3600,
        start: Change { month: 3, week: 5, weekday: 0, at: utc_one + standard },
        end: Change { month: 10, week: 5, weekday: 0, at: utc_one + standard + 3600 },
    })
}

/// The United States' and Canada's rule: the second Sunday of March to the first Sunday of
/// November, both at 02:00 local time.
const NORTH_AMERICA: Option<Summer> = Some(Summer { save: 3600, start: change(3, 2, 2), end: change(11, 1, 2) });
/// South-eastern Australia: the first Sunday of October to the first Sunday of April.
const AUSTRALIA: Option<Summer> = Some(Summer { save: 3600, start: change(10, 1, 2), end: change(4, 1, 3) });
/// New Zealand: the last Sunday of September to the first Sunday of April.
const NEW_ZEALAND: Option<Summer> = Some(Summer { save: 3600, start: change(9, 5, 2), end: change(4, 1, 3) });

const fn zone(name: &'static str, standard: i64, summer: Option<Summer>) -> Named {
    Named { name, standard, summer }
}

/// The named zones Yougori knows, with the rules they follow today.
pub const ZONES: &[Named] = &[
    zone("Africa/Johannesburg", hours(2, 0), None),
    zone("Africa/Lagos", hours(1, 0), None),
    zone("Africa/Nairobi", hours(3, 0), None),
    zone("America/Anchorage", hours(-9, 0), NORTH_AMERICA),
    zone("America/Argentina/Buenos_Aires", hours(-3, 0), None),
    zone("America/Bogota", hours(-5, 0), None),
    zone("America/Chicago", hours(-6, 0), NORTH_AMERICA),
    zone("America/Denver", hours(-7, 0), NORTH_AMERICA),
    zone("America/Edmonton", hours(-7, 0), NORTH_AMERICA),
    zone("America/Halifax", hours(-4, 0), NORTH_AMERICA),
    zone("America/Lima", hours(-5, 0), None),
    zone("America/Los_Angeles", hours(-8, 0), NORTH_AMERICA),
    zone("America/Mexico_City", hours(-6, 0), None),
    zone("America/New_York", hours(-5, 0), NORTH_AMERICA),
    zone("America/Phoenix", hours(-7, 0), None),
    zone("America/Sao_Paulo", hours(-3, 0), None),
    zone("America/St_Johns", hours(-3, 30), NORTH_AMERICA),
    zone("America/Toronto", hours(-5, 0), NORTH_AMERICA),
    zone("America/Vancouver", hours(-8, 0), NORTH_AMERICA),
    zone("America/Winnipeg", hours(-6, 0), NORTH_AMERICA),
    zone("Asia/Bangkok", hours(7, 0), None),
    zone("Asia/Dhaka", hours(6, 0), None),
    zone("Asia/Dubai", hours(4, 0), None),
    zone("Asia/Ho_Chi_Minh", hours(7, 0), None),
    zone("Asia/Hong_Kong", hours(8, 0), None),
    zone("Asia/Jakarta", hours(7, 0), None),
    zone("Asia/Karachi", hours(5, 0), None),
    zone("Asia/Kathmandu", hours(5, 45), None),
    zone("Asia/Kolkata", hours(5, 30), None),
    zone("Asia/Manila", hours(8, 0), None),
    zone("Asia/Riyadh", hours(3, 0), None),
    zone("Asia/Seoul", hours(9, 0), None),
    zone("Asia/Shanghai", hours(8, 0), None),
    zone("Asia/Singapore", hours(8, 0), None),
    zone("Asia/Taipei", hours(8, 0), None),
    zone("Asia/Tokyo", hours(9, 0), None),
    zone("Australia/Adelaide", hours(9, 30), AUSTRALIA),
    zone("Australia/Brisbane", hours(10, 0), None),
    zone("Australia/Darwin", hours(9, 30), None),
    zone("Australia/Hobart", hours(10, 0), AUSTRALIA),
    zone("Australia/Melbourne", hours(10, 0), AUSTRALIA),
    zone("Australia/Perth", hours(8, 0), None),
    zone("Australia/Sydney", hours(10, 0), AUSTRALIA),
    zone("Europe/Amsterdam", hours(1, 0), europe(hours(1, 0))),
    zone("Europe/Athens", hours(2, 0), europe(hours(2, 0))),
    zone("Europe/Berlin", hours(1, 0), europe(hours(1, 0))),
    zone("Europe/Brussels", hours(1, 0), europe(hours(1, 0))),
    zone("Europe/Bucharest", hours(2, 0), europe(hours(2, 0))),
    zone("Europe/Budapest", hours(1, 0), europe(hours(1, 0))),
    zone("Europe/Copenhagen", hours(1, 0), europe(hours(1, 0))),
    zone("Europe/Dublin", hours(0, 0), europe(0)),
    zone("Europe/Helsinki", hours(2, 0), europe(hours(2, 0))),
    zone("Europe/Istanbul", hours(3, 0), None),
    zone("Europe/Kyiv", hours(2, 0), europe(hours(2, 0))),
    zone("Europe/Lisbon", hours(0, 0), europe(0)),
    zone("Europe/London", hours(0, 0), europe(0)),
    zone("Europe/Madrid", hours(1, 0), europe(hours(1, 0))),
    zone("Europe/Moscow", hours(3, 0), None),
    zone("Europe/Oslo", hours(1, 0), europe(hours(1, 0))),
    zone("Europe/Paris", hours(1, 0), europe(hours(1, 0))),
    zone("Europe/Prague", hours(1, 0), europe(hours(1, 0))),
    zone("Europe/Rome", hours(1, 0), europe(hours(1, 0))),
    zone("Europe/Sofia", hours(2, 0), europe(hours(2, 0))),
    zone("Europe/Stockholm", hours(1, 0), europe(hours(1, 0))),
    zone("Europe/Vienna", hours(1, 0), europe(hours(1, 0))),
    zone("Europe/Warsaw", hours(1, 0), europe(hours(1, 0))),
    zone("Europe/Zurich", hours(1, 0), europe(hours(1, 0))),
    zone("Pacific/Auckland", hours(12, 0), NEW_ZEALAND),
    zone("Pacific/Honolulu", hours(-10, 0), None),
];

/// The time zone a schedule is read in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Zone {
    /// This computer's own clock, with the daylight-saving rules its operating system keeps.
    Local,
    Utc,
    /// Seconds east of UTC, all year round.
    Fixed(i64),
    Named(&'static Named),
}

impl FromStr for Zone {
    type Err = String;
    fn from_str(text: &str) -> Result<Zone, String> {
        let trimmed = text.trim();
        let refused = || {
            format!(
                "{} is not a time zone Yougori knows: use local (this computer's clock), UTC, an offset such as UTC+02:00, or a zone such as Europe/London or America/New_York",
                crate::text::shown(trimmed)
            )
        };
        if trimmed.eq_ignore_ascii_case("local") {
            return Ok(Zone::Local);
        }
        if trimmed.eq_ignore_ascii_case("utc") {
            return Ok(Zone::Utc);
        }
        if let Some(rest) = trimmed.strip_prefix("UTC").or_else(|| trimmed.strip_prefix("utc")) {
            let (sign, rest) = match rest.as_bytes().first() {
                Some(b'+') => (1, &rest[1..]),
                Some(b'-') => (-1, &rest[1..]),
                _ => return Err(refused()),
            };
            let (h, m) = rest.split_once(':').unwrap_or((rest, "00"));
            if h.is_empty() || h.len() > 2 || m.len() != 2 || !h.bytes().chain(m.bytes()).all(|b| b.is_ascii_digit()) {
                return Err(refused());
            }
            let (h, m): (i64, i64) = (h.parse().map_err(|_| refused())?, m.parse().map_err(|_| refused())?);
            let seconds = sign * (h * 3600 + m * 60);
            if !matches!(m, 0 | 15 | 30 | 45) || !(-12 * 3600..=14 * 3600).contains(&seconds) {
                return Err(format!("{}: an offset runs from UTC-12:00 to UTC+14:00 in steps of 15 minutes", crate::text::shown(trimmed)));
            }
            return Ok(if seconds == 0 { Zone::Utc } else { Zone::Fixed(seconds) });
        }
        ZONES.iter().find(|zone| zone.name.eq_ignore_ascii_case(trimmed)).map(Zone::Named).ok_or_else(refused)
    }
}

impl fmt::Display for Zone {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Zone::Local => formatter.write_str("local"),
            Zone::Utc => formatter.write_str("UTC"),
            Zone::Fixed(seconds) => {
                let sign = if *seconds < 0 { '-' } else { '+' };
                let magnitude = seconds.abs();
                write!(formatter, "UTC{sign}{:02}:{:02}", magnitude / 3600, magnitude % 3600 / 60)
            }
            Zone::Named(zone) => formatter.write_str(zone.name),
        }
    }
}

impl Zone {
    /// The zone in words for a review.
    pub fn describe(&self) -> String {
        match self {
            Zone::Local => "this computer's time zone".into(),
            Zone::Utc => "UTC".into(),
            Zone::Fixed(_) => format!("{self}, all year round"),
            Zone::Named(zone) if zone.summer.is_some() => format!("{} time, with its summer time", zone.name),
            Zone::Named(zone) => format!("{} time", zone.name),
        }
    }

    /// Seconds east of UTC at the moment `utc`. `local` answers for this computer's own clock.
    pub fn offset(&self, utc: i64, local: &dyn Fn(i64) -> i64) -> i64 {
        match self {
            Zone::Local => local(utc),
            Zone::Utc => 0,
            Zone::Fixed(seconds) => *seconds,
            Zone::Named(zone) => zone.offset(utc),
        }
    }

    /// The moment in UTC of a wall-clock time (seconds since 1970 as if the wall clock were UTC),
    /// by RFC 5545: the first of two, and a time in a gap read with the offset before the gap.
    pub fn resolve(&self, wall: i64, local: &dyn Fn(i64) -> i64) -> i64 {
        // Real zones change at most twice a year, so 36 hours either side reach past any one
        // change: the offsets before and after the nearest.
        let before = self.offset(wall - 36 * 3600, local);
        let after = self.offset(wall + 36 * 3600, local);
        let mut found = [before, after]
            .into_iter()
            .map(|offset| wall - offset)
            .filter(|utc| self.offset(*utc, local) == wall - utc)
            .collect::<Vec<_>>();
        found.sort_unstable();
        found.first().copied().unwrap_or(wall - before)
    }
}

impl Named {
    fn offset(&self, utc: i64) -> i64 {
        let Some(summer) = self.summer else { return self.standard };
        let (year, _, _) = civil(floor_div(utc + self.standard, DAY));
        let start = summer.start.instant(year, self.standard);
        let end = summer.end.instant(year, self.standard + summer.save);
        let in_summer = if start < end { (start..end).contains(&utc) } else { utc >= start || utc < end };
        if in_summer { self.standard + summer.save } else { self.standard }
    }
}

impl Change {
    /// The moment in UTC this change happens in `year`, for a clock `offset` seconds east of UTC
    /// just before it.
    fn instant(&self, year: i64, offset: i64) -> i64 {
        let first = days_from_civil(year, self.month, 1);
        let next = if self.month == 12 { days_from_civil(year + 1, 1, 1) } else { days_from_civil(year, self.month + 1, 1) };
        let sunday_first = |days: i64| (days + 4).rem_euclid(7);
        let mut day = first + (i64::from(self.weekday) - sunday_first(first)).rem_euclid(7) + 7 * (i64::from(self.week) - 1);
        while day >= next {
            day -= 7;
        }
        day * DAY + self.at - offset
    }
}

fn floor_div(value: i64, by: i64) -> i64 {
    value.div_euclid(by)
}

/// Days since 1970-01-01 of a date (proleptic Gregorian).
pub fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_from_march = (i64::from(month) + 9) % 12;
    let day_of_year = (153 * month_from_march + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The date of a day number from 1970-01-01.
pub fn civil(days: i64) -> (i64, u32, u32) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_from_march = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_from_march + 2) / 5 + 1) as u32;
    let month = if month_from_march < 10 { month_from_march + 3 } else { month_from_march - 9 } as u32;
    (era * 400 + year_of_era + i64::from(month <= 2), month, day)
}

/// The first moment strictly after `after` (Unix seconds, UTC) that `times` names in `zone`.
/// Two wall-clock times that land on the same moment (one of them in a gap) run once.
pub fn next_after(times: &Times, zone: &Zone, after: i64, local: &dyn Fn(i64) -> i64) -> i64 {
    let today = floor_div(after + zone.offset(after, local), DAY);
    let mut best: Option<i64> = None;
    // Every entry names at least one day, so the next run is within the coming week; a day
    // either side covers the offset moving across midnight.
    for day in today - 1..=today + 8 {
        let weekday = (day + 3).rem_euclid(7) as usize;
        for entry in times.entries.iter().filter(|entry| entry.days[weekday]) {
            for minute in &entry.minutes {
                let moment = zone.resolve(day * DAY + i64::from(*minute) * 60, local);
                if moment > after && best.is_none_or(|best| moment < best) {
                    best = Some(moment);
                }
            }
        }
    }
    best.unwrap_or(after + 7 * DAY)
}

/// How many moments `times` names in `(from, to]`, counting at most `cap`.
pub fn count_between(times: &Times, zone: &Zone, from: i64, to: i64, local: &dyn Fn(i64) -> i64, cap: usize) -> usize {
    let mut count = 0;
    let mut at = from;
    while count < cap {
        at = next_after(times, zone, at, local);
        if at > to {
            break;
        }
        count += 1;
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utc(year: i64, month: u32, day: u32, hour: i64, minute: i64) -> i64 {
        days_from_civil(year, month, day) * DAY + hour * 3600 + minute * 60
    }
    fn no_local(_: i64) -> i64 {
        panic!("only the local zone reads this computer's clock")
    }
    fn zone(name: &str) -> Zone {
        name.parse().unwrap()
    }
    fn times(text: &str) -> Times {
        text.parse().unwrap()
    }

    #[test]
    fn dates_round_trip_and_know_their_weekday() {
        for days in [-800_000, -1, 0, 1, 365, 20_000, 20_752, 2_932_896] {
            let (y, m, d) = civil(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
        assert_eq!(civil(0), (1970, 1, 1));
        assert_eq!(days_from_civil(2026, 10, 26), 20_752);
        // 26 October 2026 is a Monday: Monday is 0.
        assert_eq!((20_752 + 3_i64).rem_euclid(7), 0);
        assert_eq!(days_from_civil(2024, 2, 29) + 1, days_from_civil(2024, 3, 1));
    }

    #[test]
    fn schedules_parse_print_and_read_as_sentences() {
        let both = times("Mon-Fri 01:30; sun 04:00,16:00");
        assert_eq!(both.to_string(), "weekdays 01:30; Sun 04:00,16:00");
        assert_eq!(both.describe(), "on weekdays at 01:30; on Sunday at 04:00 and 16:00");
        assert_eq!(times("02:00").to_string(), "daily 02:00");
        assert_eq!(times("Sat-Mon 03:00").describe(), "on Monday, Saturday and Sunday at 03:00");
        assert_eq!(times("Mon,Thu 02:00").describe(), "on Monday and Thursday at 02:00");
        assert_eq!(times("Tue-Thu 02:00").describe(), "on Tuesday to Thursday at 02:00");
        assert_eq!(times("daily 00:00,12:00").shortest_gap_minutes(), 720);
        assert_eq!(times("Sun 23:00; Mon 01:00").shortest_gap_minutes(), 120);
        for (bad, says) in [
            ("", "empty"),
            ("nightly", "names no time"),
            ("daily 2am", "names no time"),
            ("daily 2:00am", "not a time"),
            ("daily 24:00", "not a time"),
            ("daily 02:60", "not a time"),
            ("Funday 02:00", "not a day"),
            ("daily 02:00,02:00", "same time twice"),
            ("Mon 02:00 Tue", "names no time"),
            ("Mon,,Tue 02:00", "empty item"),
            ("Mon, 02:00", "empty item"),
            ("daily 02:00\n", "one line"),
        ] {
            let error = bad.parse::<Times>().unwrap_err();
            assert!(error.contains(says), "{bad:?}: {error}");
        }
        assert!(["daily 01:00"; 9].join("; ").parse::<Times>().unwrap_err().contains("at most 8 entries"));
        let many = (0..25).map(|h| format!("{:02}:{:02}", h % 24, h / 24)).collect::<Vec<_>>().join(",");
        assert!(format!("daily {many}").parse::<Times>().unwrap_err().contains("at most 24 times"));
        assert!("x".repeat(201).parse::<Times>().unwrap_err().contains("at most 200"));
    }

    #[test]
    fn zones_parse_and_print() {
        assert_eq!(zone("local"), Zone::Local);
        assert_eq!(zone("UTC"), Zone::Utc);
        assert_eq!(zone("UTC+00:00"), Zone::Utc);
        assert_eq!(zone("UTC+2").to_string(), "UTC+02:00");
        assert_eq!(zone("UTC-05:30").to_string(), "UTC-05:30");
        assert_eq!(zone("europe/london").to_string(), "Europe/London");
        assert_eq!(zone("UTC+05:45"), Zone::Fixed(5 * 3600 + 45 * 60));
        for bad in ["Mars/Olympus", "UTC+15:00", "UTC+02:10", "UTC+", "GMT+1", "UTC2", ""] {
            assert!(bad.parse::<Zone>().is_err(), "{bad}");
        }
        let mut names = ZONES.iter().map(|z| z.name).collect::<Vec<_>>();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count, "each zone once");
        assert_eq!(names, ZONES.iter().map(|z| z.name).collect::<Vec<_>>(), "the table stays in name order");
    }

    #[test]
    fn named_zones_change_their_clocks_on_the_right_days() {
        let london = zone("Europe/London");
        assert_eq!(london.offset(utc(2026, 3, 29, 0, 59), &no_local), 0);
        assert_eq!(london.offset(utc(2026, 3, 29, 1, 0), &no_local), 3600);
        assert_eq!(london.offset(utc(2026, 10, 25, 0, 59), &no_local), 3600);
        assert_eq!(london.offset(utc(2026, 10, 25, 1, 0), &no_local), 0);
        let berlin = zone("Europe/Berlin");
        assert_eq!(berlin.offset(utc(2026, 3, 29, 1, 0), &no_local), 7200, "the EU changes everywhere at 01:00 UTC");
        let new_york = zone("America/New_York");
        assert_eq!(new_york.offset(utc(2026, 3, 8, 6, 59), &no_local), -5 * 3600);
        assert_eq!(new_york.offset(utc(2026, 3, 8, 7, 0), &no_local), -4 * 3600);
        assert_eq!(new_york.offset(utc(2026, 11, 1, 5, 59), &no_local), -4 * 3600);
        assert_eq!(new_york.offset(utc(2026, 11, 1, 6, 0), &no_local), -5 * 3600);
        let sydney = zone("Australia/Sydney");
        assert_eq!(sydney.offset(utc(2026, 1, 15, 0, 0), &no_local), 11 * 3600, "summer in January");
        assert_eq!(sydney.offset(utc(2026, 4, 4, 15, 59), &no_local), 11 * 3600);
        assert_eq!(sydney.offset(utc(2026, 4, 4, 16, 0), &no_local), 10 * 3600);
        assert_eq!(sydney.offset(utc(2026, 10, 3, 15, 59), &no_local), 10 * 3600);
        assert_eq!(sydney.offset(utc(2026, 10, 3, 16, 0), &no_local), 11 * 3600);
        assert_eq!(sydney.offset(utc(2026, 12, 31, 23, 0), &no_local), 11 * 3600);
        assert_eq!(zone("Asia/Kolkata").offset(utc(2026, 6, 1, 0, 0), &no_local), 5 * 3600 + 1800);
        assert_eq!(zone("UTC+02:00").offset(utc(2026, 7, 1, 0, 0), &no_local), 7200, "a fixed offset ignores summer time");
    }

    #[test]
    fn a_time_skipped_by_the_clocks_runs_later_by_the_gap() {
        let london = zone("Europe/London");
        let daily = times("daily 01:30");
        // The night before: 01:30 GMT.
        assert_eq!(next_after(&daily, &london, utc(2026, 3, 28, 0, 0), &no_local), utc(2026, 3, 28, 1, 30));
        // 01:30 doesn't exist on 29 March: read with the offset before the gap, it is 01:30 UTC,
        // which the clocks show as 02:30.
        assert_eq!(next_after(&daily, &london, utc(2026, 3, 28, 1, 30), &no_local), utc(2026, 3, 29, 1, 30));
        // The night after, 01:30 summer time.
        assert_eq!(next_after(&daily, &london, utc(2026, 3, 29, 1, 30), &no_local), utc(2026, 3, 30, 0, 30));
        let new_york = zone("America/New_York");
        let late = times("daily 02:30");
        assert_eq!(next_after(&late, &new_york, utc(2026, 3, 7, 12, 0), &no_local), utc(2026, 3, 8, 7, 30));
        assert_eq!(next_after(&late, &new_york, utc(2026, 3, 8, 7, 30), &no_local), utc(2026, 3, 9, 6, 30));
        // Two times that land on the same moment run once.
        let both = times("daily 01:30,02:30");
        assert_eq!(next_after(&both, &london, utc(2026, 3, 29, 0, 0), &no_local), utc(2026, 3, 29, 1, 30));
        assert_eq!(next_after(&both, &london, utc(2026, 3, 29, 1, 30), &no_local), utc(2026, 3, 30, 0, 30));
        let sydney = zone("Australia/Sydney");
        assert_eq!(next_after(&late, &sydney, utc(2026, 10, 3, 12, 0), &no_local), utc(2026, 10, 3, 16, 30), "02:30 on 4 October read as standard time");
    }

    #[test]
    fn a_time_the_clocks_repeat_runs_once() {
        let london = zone("Europe/London");
        let daily = times("daily 01:30");
        let first = next_after(&daily, &london, utc(2026, 10, 24, 12, 0), &no_local);
        assert_eq!(first, utc(2026, 10, 25, 0, 30), "the first 01:30, in summer time");
        assert_eq!(next_after(&daily, &london, first, &no_local), utc(2026, 10, 26, 1, 30), "not again an hour later");
        let new_york = zone("America/New_York");
        let night = times("daily 01:30");
        let first = next_after(&night, &new_york, utc(2026, 10, 31, 12, 0), &no_local);
        assert_eq!(first, utc(2026, 11, 1, 5, 30));
        assert_eq!(next_after(&night, &new_york, first, &no_local), utc(2026, 11, 2, 6, 30));
    }

    #[test]
    fn days_of_the_week_and_the_local_clock() {
        let weekdays = times("Mon-Fri 09:00");
        // Friday 30 October 2026, 10:00 UTC: next is Monday 2 November.
        assert_eq!(next_after(&weekdays, &Zone::Utc, utc(2026, 10, 30, 10, 0), &no_local), utc(2026, 11, 2, 9, 0));
        assert_eq!(next_after(&weekdays, &Zone::Utc, utc(2026, 10, 30, 8, 59), &no_local), utc(2026, 10, 30, 9, 0));
        let tokyo = zone("Asia/Tokyo");
        // 09:00 in Tokyo is 00:00 UTC the same day.
        assert_eq!(next_after(&weekdays, &tokyo, utc(2026, 10, 29, 23, 0), &no_local), utc(2026, 10, 30, 0, 0));
        // The local zone asks the engine's clock: here, one that is UTC-03:00.
        let minus_three = |_: i64| -3 * 3600;
        assert_eq!(next_after(&times("daily 02:00"), &Zone::Local, utc(2026, 10, 26, 0, 0), &minus_three), utc(2026, 10, 26, 5, 0));
        assert_eq!(count_between(&times("daily 02:00"), &Zone::Utc, utc(2026, 10, 20, 3, 0), utc(2026, 10, 26, 3, 0), &no_local, 100), 6);
        assert_eq!(count_between(&times("daily 02:00"), &Zone::Utc, utc(2026, 1, 1, 0, 0), utc(2027, 1, 1, 0, 0), &no_local, 10), 10, "counting stops at the cap");
    }
}
