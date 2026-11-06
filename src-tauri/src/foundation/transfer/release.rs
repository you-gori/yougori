//! The general release budget of a sandbox (VM-D12), kept apart from transfer budgets
//! (S3.7: a large model request does not increase the general release budget).
//!
//! Nothing in the transfer module takes or returns a [`GeneralReleaseBudget`]: model
//! downloads and private-weight uploads carry their own explicit byte budgets in their
//! envelopes, and those are reserved through the byte-budget port, never from here.

use std::fmt;

/// VM-D12's starting value for the general release budget: 8 MiB.
pub const VM_D12_GENERAL_RELEASE_BUDGET_BYTES: u64 = 8 * 1024 * 1024;

/// What a sandbox may release outside the typed transfer paths (VM-D12).
///
/// The limit is set when the budget is made: VM-D12's 8 MiB, or a value release policy
/// adopts from measurement (VM-D12: adjusted per VM part §12.4). No method raises it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneralReleaseBudget {
    limit_bytes: u64,
    released_bytes: u64,
}

impl GeneralReleaseBudget {
    /// VM-D12's starting value.
    pub const fn vm_d12_default() -> Self {
        Self::with_limit(VM_D12_GENERAL_RELEASE_BUDGET_BYTES)
    }

    /// A limit release policy set from measurement; transfers never call this.
    pub const fn with_limit(limit_bytes: u64) -> Self {
        Self {
            limit_bytes,
            released_bytes: 0,
        }
    }

    pub const fn limit_bytes(&self) -> u64 {
        self.limit_bytes
    }

    pub const fn released_bytes(&self) -> u64 {
        self.released_bytes
    }

    pub const fn remaining_bytes(&self) -> u64 {
        self.limit_bytes.saturating_sub(self.released_bytes)
    }

    /// Charges `bytes` released through the general path, or refuses without charging.
    pub fn charge(&mut self, bytes: u64) -> Result<(), ReleaseBudgetExceeded> {
        match self.released_bytes.checked_add(bytes) {
            Some(released) if released <= self.limit_bytes => {
                self.released_bytes = released;
                Ok(())
            }
            _ => Err(ReleaseBudgetExceeded {
                limit_bytes: self.limit_bytes,
                released_bytes: self.released_bytes,
                requested_bytes: bytes,
            }),
        }
    }
}

/// A general release would exceed the budget (VM-D12).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReleaseBudgetExceeded {
    pub limit_bytes: u64,
    pub released_bytes: u64,
    pub requested_bytes: u64,
}

impl fmt::Display for ReleaseBudgetExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "releasing {} more bytes would exceed the general release budget: {} of {} are \
             used; bulk model data moves only through a transfer grant with its own budget",
            self.requested_bytes, self.released_bytes, self.limit_bytes
        )
    }
}

impl std::error::Error for ReleaseBudgetExceeded {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_vm_d12_default_is_8_mib() {
        let budget = GeneralReleaseBudget::vm_d12_default();
        assert_eq!(budget.limit_bytes(), 8_388_608);
        assert_eq!(budget.remaining_bytes(), 8_388_608);
        assert_eq!(budget.released_bytes(), 0);
    }

    #[test]
    fn charges_stop_at_the_limit() {
        let mut budget = GeneralReleaseBudget::vm_d12_default();
        budget.charge(8 * 1024 * 1024 - 1).unwrap();
        budget.charge(1).unwrap();
        assert_eq!(budget.remaining_bytes(), 0);
        assert_eq!(
            budget.charge(1),
            Err(ReleaseBudgetExceeded {
                limit_bytes: 8_388_608,
                released_bytes: 8_388_608,
                requested_bytes: 1
            })
        );
        assert_eq!(budget.released_bytes(), 8_388_608);
        let mut overflow = GeneralReleaseBudget::with_limit(u64::MAX);
        overflow.charge(u64::MAX).unwrap();
        assert!(overflow.charge(1).is_err());
    }
}
