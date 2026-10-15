//! When a member computer may serve the grid: inside its schedule, and only after its
//! person has been away from the keyboard and mouse for a while.
use crate::{activity::Activity, schedule::Schedule};
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub const DEFAULT_IDLE_MINUTES: u32 = 10;
pub const MAX_IDLE_MINUTES: u32 = 1440;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdlePolicy {
    /// Minutes without keyboard or mouse input before serving; 0 ignores activity.
    pub idle_after_minutes: u32,
    /// Weekly windows in local time (canonical text); none serves at any time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<String>,
}

impl Default for IdlePolicy {
    fn default() -> Self {
        Self { idle_after_minutes: DEFAULT_IDLE_MINUTES, schedule: None }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    Serve,
    OutsideSchedule,
    PersonActive { idle: Duration, needed: Duration },
    ActivityUnknown(String),
}

impl Decision {
    pub fn serves(&self) -> bool {
        *self == Decision::Serve
    }
    /// A stable code reported to the hub and shown in status.
    pub fn state(&self) -> &'static str {
        match self {
            Decision::Serve => "available",
            Decision::OutsideSchedule => "outside_schedule",
            Decision::PersonActive { .. } => "person_active",
            Decision::ActivityUnknown(_) => "activity_unknown",
        }
    }
    pub fn reason(&self) -> String {
        match self {
            Decision::Serve => "Idle; serving the grid".into(),
            Decision::OutsideSchedule => "Outside this computer's grid schedule".into(),
            Decision::PersonActive { idle, needed } => format!(
                "Someone is using this computer (last input {} ago); it serves after {} without input",
                span(*idle),
                span(*needed)
            ),
            Decision::ActivityUnknown(reason) => format!("{reason}. Contribute with --idle-after 0 to rely on the schedule alone"),
        }
    }
}

fn span(duration: Duration) -> String {
    let seconds = duration.as_secs();
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3600 {
        format!("{} min", seconds / 60)
    } else {
        format!("{}h {}m", seconds / 3600, seconds % 3600 / 60)
    }
}

impl IdlePolicy {
    /// Validates a person's choices and stores the schedule in canonical form.
    pub fn new(idle_after_minutes: Option<u32>, schedule: Option<&str>) -> Result<Self, String> {
        let idle_after_minutes = idle_after_minutes.unwrap_or(DEFAULT_IDLE_MINUTES);
        if idle_after_minutes > MAX_IDLE_MINUTES {
            return Err(format!("--idle-after must be 0–{MAX_IDLE_MINUTES} minutes"));
        }
        let schedule = schedule
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(|text| text.parse::<Schedule>().map(|schedule| schedule.to_string()))
            .transpose()?;
        Ok(Self { idle_after_minutes, schedule })
    }

    pub fn parsed_schedule(&self) -> Result<Option<Schedule>, String> {
        self.schedule.as_deref().map(str::parse).transpose()
    }

    /// `weekday` counts from Monday = 0; `minute` from local midnight.
    pub fn decide(&self, schedule: Option<&Schedule>, weekday: usize, minute: u16, activity: &Activity) -> Decision {
        if schedule.is_some_and(|schedule| !schedule.contains(weekday, minute)) {
            return Decision::OutsideSchedule;
        }
        if self.idle_after_minutes == 0 {
            return Decision::Serve;
        }
        let needed = Duration::from_secs(u64::from(self.idle_after_minutes) * 60);
        match activity {
            Activity::Nobody => Decision::Serve,
            Activity::Idle(idle) if *idle >= needed => Decision::Serve,
            Activity::Idle(idle) => Decision::PersonActive { idle: *idle, needed },
            Activity::Unknown(reason) => Decision::ActivityUnknown(reason.clone()),
        }
    }

    pub fn decide_at(&self, now: &chrono::DateTime<chrono::Local>, activity: &Activity) -> Decision {
        use chrono::{Datelike, Timelike};
        let schedule = match self.parsed_schedule() {
            Ok(schedule) => schedule,
            // A stored schedule was validated when saved; never serve on one that no longer parses.
            Err(_) => return Decision::OutsideSchedule,
        };
        self.decide(schedule.as_ref(), now.weekday().num_days_from_monday() as usize, (now.hour() * 60 + now.minute()) as u16, activity)
    }

    pub fn describe(&self) -> String {
        let away = match self.idle_after_minutes {
            0 => "whether or not someone is using it".to_owned(),
            minutes => format!("after {minutes} min without keyboard or mouse input"),
        };
        match &self.schedule {
            Some(schedule) => format!("{schedule}, {away}"),
            None => format!("Any time, {away}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn serves_inside_the_schedule_once_the_person_is_away() {
        let policy = IdlePolicy::new(Some(10), Some("mon-fri 18:00-08:00")).unwrap();
        assert_eq!(policy.schedule.as_deref(), Some("Mon-Fri 18:00-08:00"));
        let schedule = policy.parsed_schedule().unwrap();
        let away = Activity::Idle(Duration::from_secs(11 * 60));
        let working = Activity::Idle(Duration::from_secs(30));
        assert_eq!(policy.decide(schedule.as_ref(), 0, 19 * 60, &away), Decision::Serve);
        assert_eq!(policy.decide(schedule.as_ref(), 0, 12 * 60, &away), Decision::OutsideSchedule);
        let active = policy.decide(schedule.as_ref(), 0, 19 * 60, &working);
        assert_eq!(active.state(), "person_active");
        assert!(active.reason().contains("30s") && active.reason().contains("10 min"));
        assert_eq!(policy.decide(schedule.as_ref(), 0, 19 * 60, &Activity::Nobody), Decision::Serve);
    }
    #[test]
    fn zero_minutes_ignores_activity_and_unknown_activity_never_serves() {
        let schedule_only = IdlePolicy::new(Some(0), None).unwrap();
        assert!(schedule_only.decide(None, 3, 600, &Activity::Idle(Duration::ZERO)).serves());
        assert!(schedule_only.decide(None, 3, 600, &Activity::Unknown("no".into())).serves());
        let default = IdlePolicy::new(None, Some("  ")).unwrap();
        assert_eq!(default, IdlePolicy::default());
        let unknown = default.decide(None, 3, 600, &Activity::Unknown("No sessions".into()));
        assert_eq!(unknown.state(), "activity_unknown");
        assert!(unknown.reason().contains("--idle-after 0"));
    }
    #[test]
    fn invalid_choices_are_refused() {
        assert!(IdlePolicy::new(Some(MAX_IDLE_MINUTES + 1), None).is_err());
        assert!(IdlePolicy::new(None, Some("Mon 25:00-26:00")).is_err());
        assert_eq!(IdlePolicy::default().describe(), "Any time, after 10 min without keyboard or mouse input");
        assert_eq!(IdlePolicy::new(Some(0), Some("sat,sun")).unwrap().describe(), "Sat-Sun, whether or not someone is using it");
    }
}
