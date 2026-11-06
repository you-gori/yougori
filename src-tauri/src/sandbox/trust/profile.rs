//! The assurance profile and how it may be chosen (line 2282: "Developer unsigned
//! builds must be outside the production assurance profile and cannot be enabled by an
//! inherited guest-controlled environment variable. Never allow unsigned developer mode
//! to activate production credential grants accidentally"; VM-W45, line 2493:
//! "development mode clearly separate").
//!
//! A [`ResolvedProfile`] is the only way to tell the update client which profile it runs
//! under, and it is constructed only by [`ResolvedProfile::resolve`] from a request that
//! names where the request came from. The developer profile is granted from host
//! configuration or an operator command, never from an inherited environment variable
//! or any guest-controlled input; the production profile is granted from anywhere, since
//! asking for strictness needs no authority.

use std::fmt;

use serde::{Deserialize, Serialize};

/// The two assurance profiles.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssuranceProfile {
    /// Signed releases under production-grade schemes only.
    Production,
    /// Developer builds: unsigned artifacts and test schemes are admitted, and nothing
    /// verified here is a production release.
    Developer,
}

impl fmt::Display for AssuranceProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Production => "production",
            Self::Developer => "developer",
        })
    }
}

/// Where a profile request came from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RequestOrigin {
    /// A setting in the host's own configuration, written by the host operator.
    HostConfiguration { setting: String },
    /// An explicit operator command on the host.
    OperatorCommand,
    /// An environment variable the process inherited; a guest, a parent process or a
    /// shell profile could have set it.
    InheritedEnvironment { variable: String },
    /// Anything a guest sent: a report, a request field, a template, a file in the guest.
    GuestInput { channel: String },
}

/// A request for a profile, with its origin.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileRequest {
    pub profile: AssuranceProfile,
    pub origin: RequestOrigin,
}

/// Why the developer profile was not granted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum ProfileRefusal {
    /// An inherited environment variable asked for developer mode (line 2282).
    DeveloperFromInheritedEnvironment { variable: String },
    /// A guest-controlled input asked for developer mode (line 2282).
    DeveloperFromGuestInput { channel: String },
}

impl fmt::Display for ProfileRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeveloperFromInheritedEnvironment { variable } => write!(
                f,
                "the developer profile cannot be enabled by the inherited environment variable {variable:?}"
            ),
            Self::DeveloperFromGuestInput { channel } => write!(
                f,
                "the developer profile cannot be enabled by guest input ({channel})"
            ),
        }
    }
}

impl std::error::Error for ProfileRefusal {}

/// A profile that was granted from an allowed origin. It has no public constructor
/// besides [`ResolvedProfile::resolve`] and [`ResolvedProfile::PRODUCTION`], so a
/// developer profile in hand proves the host chose it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ResolvedProfile {
    profile: AssuranceProfile,
}

impl ResolvedProfile {
    /// The production profile, which needs no origin.
    pub const PRODUCTION: Self = Self {
        profile: AssuranceProfile::Production,
    };

    /// Grants the requested profile if its origin may ask for it.
    pub fn resolve(request: &ProfileRequest) -> Result<Self, ProfileRefusal> {
        match (request.profile, &request.origin) {
            (AssuranceProfile::Production, _) => Ok(Self::PRODUCTION),
            (
                AssuranceProfile::Developer,
                RequestOrigin::HostConfiguration { .. } | RequestOrigin::OperatorCommand,
            ) => Ok(Self {
                profile: AssuranceProfile::Developer,
            }),
            (AssuranceProfile::Developer, RequestOrigin::InheritedEnvironment { variable }) => {
                Err(ProfileRefusal::DeveloperFromInheritedEnvironment {
                    variable: variable.clone(),
                })
            }
            (AssuranceProfile::Developer, RequestOrigin::GuestInput { channel }) => {
                Err(ProfileRefusal::DeveloperFromGuestInput {
                    channel: channel.clone(),
                })
            }
        }
    }

    pub const fn profile(self) -> AssuranceProfile {
        self.profile
    }

    pub const fn is_production(self) -> bool {
        matches!(self.profile, AssuranceProfile::Production)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn developer_mode_comes_only_from_the_host() {
        let host = ProfileRequest {
            profile: AssuranceProfile::Developer,
            origin: RequestOrigin::HostConfiguration {
                setting: "sandbox.assurance_profile".to_owned(),
            },
        };
        assert_eq!(
            ResolvedProfile::resolve(&host).unwrap().profile(),
            AssuranceProfile::Developer
        );
        let operator = ProfileRequest {
            profile: AssuranceProfile::Developer,
            origin: RequestOrigin::OperatorCommand,
        };
        assert!(!ResolvedProfile::resolve(&operator).unwrap().is_production());

        let environment = ProfileRequest {
            profile: AssuranceProfile::Developer,
            origin: RequestOrigin::InheritedEnvironment {
                variable: "YOUGORI_ALLOW_UNSIGNED".to_owned(),
            },
        };
        assert_eq!(
            ResolvedProfile::resolve(&environment),
            Err(ProfileRefusal::DeveloperFromInheritedEnvironment {
                variable: "YOUGORI_ALLOW_UNSIGNED".to_owned()
            })
        );
        let guest = ProfileRequest {
            profile: AssuranceProfile::Developer,
            origin: RequestOrigin::GuestInput {
                channel: "agent-report".to_owned(),
            },
        };
        assert_eq!(
            ResolvedProfile::resolve(&guest),
            Err(ProfileRefusal::DeveloperFromGuestInput {
                channel: "agent-report".to_owned()
            })
        );
    }

    #[test]
    fn production_may_be_asked_for_from_anywhere() {
        for origin in [
            RequestOrigin::InheritedEnvironment {
                variable: "X".to_owned(),
            },
            RequestOrigin::GuestInput {
                channel: "c".to_owned(),
            },
            RequestOrigin::OperatorCommand,
        ] {
            let request = ProfileRequest {
                profile: AssuranceProfile::Production,
                origin,
            };
            assert_eq!(
                ResolvedProfile::resolve(&request),
                Ok(ResolvedProfile::PRODUCTION)
            );
        }
        assert!(ResolvedProfile::PRODUCTION.is_production());
    }

    #[test]
    fn requests_refuse_unknown_fields() {
        let json = serde_json::json!({
            "profile": "developer",
            "origin": {"inherited_environment": {"variable": "V", "value": "1"}}
        });
        assert!(serde_json::from_value::<ProfileRequest>(json).is_err());
        let json = serde_json::json!({"profile": "developer", "origin": "operator_command"});
        assert_eq!(
            serde_json::from_value::<ProfileRequest>(json).unwrap(),
            ProfileRequest {
                profile: AssuranceProfile::Developer,
                origin: RequestOrigin::OperatorCommand
            }
        );
    }
}
