use super::*;
use crate::foundation::evidence::ProviderKind;
use crate::foundation::ids::MonotonicTime;
use crate::sandbox_contract::destinations::{Authority, DestinationPort};
use crate::sandbox_contract::remote::{
    EnrollmentEvidence, EnrollmentPolicy, HostEnrollment, KnownHostsState, OfferingKind,
    OfferingName, ProviderInstance, RegionName,
};
use crate::sandbox_contract::remote_ssh::{parse_owner_public_key, SshTarget};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedHost {
    version: u32,
    known: KnownHostsState,
    review_required: bool,
    #[serde(default)]
    retired: Vec<HostEnrollment>,
}

pub(super) struct Host {
    pub known: KnownHosts,
    path: PathBuf,
    serial: Mutex<Option<SavedHost>>,
    review: AtomicBool,
    failed: AtomicBool,
    retired: Vec<HostEnrollment>,
}
impl Host {
    pub fn persist(&self) -> Result<(), String> {
        let mut saved = self
            .serial
            .lock()
            .map_err(|_| "SSH trust lock unavailable")?;
        let state = SavedHost {
            version: 1,
            known: self.known.snapshot(),
            review_required: self.review.load(Ordering::Acquire),
            retired: self.retired.clone(),
        };
        if saved.as_ref() == Some(&state) {
            return Ok(());
        }
        let result = serde_json::to_vec(&state)
            .map_err(|e| e.to_string())
            .and_then(|bytes| {
                if bytes.len() as u64 > MAX_JOURNAL {
                    return Err("SSH trust history exceeds its journal bound; the previous record was retained.".into());
                }
                write_atomic(&self.path, &bytes).map_err(|e| e.to_string())
            });
        if result.is_err() {
            self.failed.store(true, Ordering::Release)
        } else {
            *saved = Some(state)
        }
        result
    }
    pub fn require_review(&self) -> Result<(), String> {
        self.review.store(true, Ordering::Release);
        self.persist()
    }
    pub fn check_new(&self) -> Result<(), String> {
        if self.failed.load(Ordering::Acquire) {
            return Err("SSH trust persistence failed; new authority is blocked.".into());
        }
        if self.review.load(Ordering::Acquire) {
            return Err("This host has an interrupted remote run. Reconcile it, then explicitly confirm its host key before starting new work.".into());
        }
        Ok(())
    }
}

/// Profiles that differ only in username or display name share one host authority.
pub(super) fn target(profile: &SshProfile) -> Result<(ProviderInstance, SshTarget), String> {
    let port = DestinationPort::new(profile.port).map_err(|e| e.to_string())?;
    let name = if profile.host.contains(':') && !profile.host.starts_with('[') {
        format!("[{}]", profile.host)
    } else {
        profile.host.clone()
    };
    let authority = Authority::parse(&name, port).map_err(|e| e.to_string())?;
    if authority.port != port {
        return Err("SSH host field must not override the selected port.".into());
    }
    let instance = ProviderInstance {
        provider: ProviderKind::ExistingSsh,
        region: RegionName::new("owner-connected").map_err(|e| e.to_string())?,
        offering: OfferingName::new("per-sandbox-qemu").map_err(|e| e.to_string())?,
        kind: OfferingKind::PerSandboxVmHost,
        instance: digest(
            "yougori/remote-home/ssh-host/v1",
            &[authority.to_string().as_bytes()],
        ),
    };
    let target = SshTarget::new(instance.host(), authority);
    Ok((instance, target))
}

impl Manager {
    pub(super) fn host(
        &self,
        profile: &SshProfile,
        accepted: Option<&str>,
        now: MonotonicTime,
        recovery: bool,
    ) -> Result<Arc<Host>, String> {
        let (instance, _) = target(profile)?;
        let id = instance.host();
        let public = parse_owner_public_key(profile.host_key.as_bytes())?;
        if let Some(accepted) = accepted {
            if accepted != public.openssh_fingerprint {
                return Err(
                    "Accepted fingerprint differs from the saved connection's host key.".into(),
                );
            }
        }
        let mut hosts = self.hosts.lock().map_err(|_| "SSH host map unavailable")?;
        let host = if let Some(host) = hosts.get(&id) {
            Arc::clone(host)
        } else {
            let path = self
                .root
                .join("hosts")
                .join(format!("{}.json", instance.instance.to_hex()));
            let (known, review, retired) = if path.exists() {
                let saved: SavedHost = read_json(&path)?;
                if saved.version != 1 {
                    return Err("Unsupported SSH trust record.".into());
                }
                if saved.retired.len() > 256 || saved.retired.iter().any(|e| e.host != id) {
                    return Err(
                        "SSH retirement history is inconsistent or exceeds its bound.".into(),
                    );
                }
                (
                    KnownHosts::restore(saved.known).map_err(|e| e.to_string())?,
                    saved.review_required,
                    saved.retired,
                )
            } else {
                if recovery || accepted.is_none() {
                    return Err(format!(
                        "Explicitly confirm the SSH host fingerprint {} before first use.",
                        public.openssh_fingerprint
                    ));
                }
                let mut known = KnownHosts::new();
                known
                    .enroll(
                        id,
                        &public.key,
                        EnrollmentEvidence::OwnerPinned {
                            expected: public.key.fingerprint(),
                        },
                        EnrollmentPolicy::default(),
                        now,
                    )
                    .map_err(|e| e.to_string())?;
                (known, false, Vec::new())
            };
            let host = Arc::new(Host {
                known,
                path,
                serial: Mutex::new(None),
                review: AtomicBool::new(review),
                failed: AtomicBool::new(false),
                retired,
            });
            host.persist()?;
            hosts.insert(id, host.clone());
            host
        };
        // Loading history for recovery/status must remain possible after a key
        // rejection. Session::prepare verifies it again before any SSH operation.
        if !recovery {
            host.known
                .verify(&id, &public.key)
                .map_err(|e| e.to_string())?;
        }
        // Explicit review only after every former run is confirmed closed. The
        // caller owns the runs lock at launch, so check via the durable journals.
        if !recovery && accepted.is_some() && host.review.load(Ordering::Acquire) {
            for path in journal_paths(&self.root.join("runs"))? {
                let run: Run = read_json(&path)?;
                if run.host == id && !run.phase.terminal() {
                    return Err(
                        "Reconcile this host's previous runs before confirming it for new work."
                            .into(),
                    );
                }
            }
            host.review.store(false, Ordering::Release);
            host.persist()?;
        }
        Ok(host)
    }

    /// Only explicit owner confirmation can replace an enrollment. No holder of
    /// the old live authority may survive the replacement; old runs get cleanup
    /// credentials only, keeping their launch identity and exact VM observation.
    pub(super) fn confirm_host(
        self: &Arc<Self>,
        p: Arc<Production>,
        profile: &SshProfile,
        accepted: &str,
    ) -> Result<Value, String> {
        if p.shutdown.is_cancelled() || self.failed.load(Ordering::Acquire) {
            return Err("The engine or remote journal is unavailable for trust changes.".into());
        }
        let (instance, _) = target(profile)?;
        let id = instance.host();
        let public = parse_owner_public_key(profile.host_key.as_bytes())?;
        if accepted != public.openssh_fingerprint {
            return Err(
                "Accepted fingerprint differs from the saved connection's host key.".into(),
            );
        }
        let runs = self.runs.lock().map_err(|_| "Remote lock unavailable")?;
        let affected = runs
            .values()
            .filter(|entry| entry.snapshot().host == id)
            .cloned()
            .collect::<Vec<_>>();
        if affected
            .iter()
            .any(|entry| !entry.finished.load(Ordering::Acquire))
        {
            return Err("Stop and finish this host's workers before changing its trust. Unconfirmed runs may then be reconciled under the explicitly confirmed key.".into());
        }
        // Load an existing book without forgiving its rejection. A first-use
        // enrollment needs the same explicit owner pin as the launch flow.
        let existing = self
            .root
            .join("hosts")
            .join(format!("{}.json", instance.instance.to_hex()))
            .exists()
            || self
                .hosts
                .lock()
                .map_err(|_| "SSH host map unavailable")?
                .contains_key(&id);
        let old = self.host(
            profile,
            if existing { None } else { Some(accepted) },
            p.clock.now(),
            existing,
        )?;
        let mut known = KnownHosts::restore(old.known.snapshot()).map_err(|e| e.to_string())?;
        let mut retired = old.retired.clone();
        if known.verify(&id, &public.key).is_err() {
            if retired.len() >= 256 {
                return Err("SSH retirement history is full; its evidence was retained.".into());
            }
            if let Some(previous) = known.retire(&id) {
                retired.push(previous);
            }
        }
        let enrollment = known
            .enroll(
                id,
                &public.key,
                EnrollmentEvidence::OwnerPinned {
                    expected: public.key.fingerprint(),
                },
                EnrollmentPolicy::default(),
                p.clock.now(),
            )
            .map_err(|e| e.to_string())?;
        let pending = affected
            .into_iter()
            .filter(|entry| !entry.snapshot().phase.terminal())
            .collect::<Vec<_>>();
        let new = Arc::new(Host {
            known,
            path: old.path.clone(),
            serial: Mutex::new(None),
            review: AtomicBool::new(!pending.is_empty()),
            failed: AtomicBool::new(false),
            retired,
        });
        // Persist trust first. Any partial failure leaves work blocked, with old
        // cleanup intents recoverable. Retrying this explicit action is idempotent.
        if let Err(error) = new.persist() {
            self.failed.store(true, Ordering::Release);
            return Err(error);
        }
        self.hosts
            .lock()
            .map_err(|_| "SSH host map unavailable")?
            .insert(id, new);
        for entry in &pending {
            self.update(entry, |run| run.cleanup_profile = Some(profile.clone()))?;
        }
        drop(runs);
        for entry in &pending {
            self.spawn(p.clone(), entry.clone(), true)?;
        }
        Ok(
            json!({"host":profile.host,"port":profile.port,"fingerprint":public.openssh_fingerprint,
            "enrollment":enrollment,"cleanup_pending":pending.len(),"new_authority":false,
            "detail":"Only cleanup uses the confirmed key for earlier runs. Their workload authority is not resumed."}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn growing_trust_history_cannot_overwrite_a_readable_record_with_an_unreadable_one() {
        use crate::sandbox_contract::remote::fakes::{host_id, host_key};
        use crate::sandbox_contract::remote::{RejectionEvidence, RejectionObserver};
        let directory = tempfile::tempdir().unwrap();
        let id = host_id(1);
        let key = host_key(1);
        let mut known = KnownHosts::new();
        let evidence = EnrollmentEvidence::OwnerPinned {
            expected: key.fingerprint(),
        };
        known
            .enroll(
                id,
                &key,
                evidence,
                EnrollmentPolicy::default(),
                MonotonicTime::ZERO,
            )
            .unwrap();
        let mut host = Host {
            known,
            path: directory.path().join("host.json"),
            serial: Mutex::new(None),
            review: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            retired: Vec::new(),
        };
        host.persist().unwrap();
        let previous = fs::read(&host.path).unwrap();
        for _ in 0..256 {
            let enrollment = host.known.enrollment(&id).unwrap().clone();
            host.known
                .record_rejection(
                    &id,
                    enrollment.generation,
                    RejectionObserver::ManagementSsh,
                    RejectionEvidence::SshKeyChanged { printed: None },
                    MonotonicTime::ZERO,
                )
                .unwrap();
            host.retired.push(host.known.retire(&id).unwrap());
            host.known
                .enroll(
                    id,
                    &key,
                    evidence,
                    EnrollmentPolicy::default(),
                    MonotonicTime::ZERO,
                )
                .unwrap();
        }
        // Both histories are individually within their count limits and the
        // authority history is structurally valid; their combined bytes matter.
        assert!(KnownHosts::restore(host.known.snapshot()).is_ok());
        assert!(host.persist().is_err());
        assert_eq!(fs::read(&host.path).unwrap(), previous);
        assert!(read_json::<SavedHost>(&host.path).is_ok());
        assert!(host.check_new().is_err());
    }
    #[test]
    fn profiles_cannot_bypass_host_rejection_with_another_name_or_login() {
        let mut a = SshProfile {
            name: "one".into(),
            vendor: "manual".into(),
            host: "Example.COM".into(),
            port: 2222,
            username: "one".into(),
            identity_file: "ignored".into(),
            host_key: "ignored".into(),
        };
        let first = target(&a).unwrap().0;
        a.host = "example.com".into();
        a.name = "another".into();
        a.username = "two".into();
        assert_eq!(first, target(&a).unwrap().0);
        a.port = 2223;
        assert_ne!(first.host(), target(&a).unwrap().0.host());
        a.host = "example.com:22".into();
        assert!(target(&a).is_err());
    }
}
