//! The trust client's scheme registry for the production profile (§8.3, plan line 2457:
//! "Developer unsigned builds must be outside the production assurance profile"; the
//! trust client's line 2282 reading: test-signed builds are outside it too).
//!
//! [`production_registry`] holds the Ed25519 adapter and nothing else, so a key of the
//! HMAC test scheme meets [`SignatureRejection::SchemeUnavailable`] there, an explicit
//! refusal. [`check_production_registry`] refuses a registry built elsewhere that holds a
//! verifier for a scheme that is not production grade, before it serves a production
//! client.
//!
//! [`SignatureRejection::SchemeUnavailable`]: crate::sandbox::trust::SignatureRejection::SchemeUnavailable

use std::fmt;

use serde::Serialize;

use super::scheme::Ed25519Scheme;
use crate::sandbox::trust::{DuplicateScheme, SchemeKind, SchemeRegistry};

/// The registry for the production profile: Ed25519 only. The HMAC test scheme has no
/// verifier here, so its keys are refused.
pub fn production_registry() -> SchemeRegistry {
    let mut registry = SchemeRegistry::new();
    match registry.register(Box::new(Ed25519Scheme)) {
        // A fresh registry holds no verifier, so there is no earlier one to clash with;
        // either way it now holds exactly one Ed25519 verifier and nothing else.
        Ok(()) | Err(DuplicateScheme { .. }) => registry,
    }
}

/// A registry offered for the production profile holds a verifier for a scheme that is
/// not production grade.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct TestSchemeRegistered {
    pub scheme: SchemeKind,
}

impl fmt::Display for TestSchemeRegistered {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the registry holds a verifier for the {} scheme, which the production profile does not accept",
            self.scheme
        )
    }
}

impl std::error::Error for TestSchemeRegistered {}

/// Refuses `schemes` for the production profile if it holds a verifier for any scheme
/// that is not production grade.
pub fn check_production_registry(schemes: &SchemeRegistry) -> Result<(), TestSchemeRegistered> {
    match SchemeKind::ALL
        .into_iter()
        .filter(|scheme| !scheme.production_grade())
        .find(|scheme| schemes.is_registered(*scheme))
    {
        Some(scheme) => Err(TestSchemeRegistered { scheme }),
        None => Ok(()),
    }
}
