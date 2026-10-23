//! Compiled distribution policy shared by the CLI, grid and desktop engine.
//! Public source exports replace distribution.txt with `public`; this is not a runtime setting.
pub const LIVE_TARGETS: bool = matches!(include_str!("distribution.txt").as_bytes(), b"private\n" | b"private\r\n");
pub const LIVE_TARGETS_DISABLED: &str = "Live URL targets are not available in the public edition. Import source code and test its isolated sandbox instead.";

pub fn check_live_target(external: bool) -> Result<(), String> {
    if external && !LIVE_TARGETS { Err(LIVE_TARGETS_DISABLED.into()) } else { Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn distribution_is_explicit_and_cannot_be_changed_by_runtime_settings() {
        let profile = include_str!("distribution.txt").trim();
        assert!(matches!(profile, "public" | "private"), "unknown distribution profile");
        assert_eq!(LIVE_TARGETS, profile == "private");
        assert!(check_live_target(false).is_ok());
        assert_eq!(check_live_target(true).is_ok(), LIVE_TARGETS);
    }
}
