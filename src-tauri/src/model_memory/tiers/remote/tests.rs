use super::*;
use crate::model_memory::residency::eviction::Content;
use crate::model_memory::tiers::fakes::{consumer, path, scope, source_id, weights, GB, KIB};

/// Appendix A.2 line 1495 moves weights in 8 MiB parts; the tests scale a part to 8 KiB.
const PART: u64 = 8 * KIB;

/// `count` parts of `PART` bytes, part `index` filled with `index`, and their specs.
fn artifact(count: u8) -> (Vec<Vec<u8>>, Vec<RangeSpec>) {
    let parts: Vec<Vec<u8>> = (0..count).map(|index| vec![index; PART as usize]).collect();
    let specs = parts
        .iter()
        .enumerate()
        .map(|(index, bytes)| {
            let offset = index as u64 * PART;
            RangeSpec {
                offset,
                length_bytes: PART,
                digest: range_digest(offset, bytes),
            }
        })
        .collect();
    (parts, specs)
}

/// A remote that serves alice's scope with an egress budget.
fn remote(egress_budget_bytes: u64) -> RemoteSource {
    RemoteSource::new(RemotePolicy {
        access: BTreeSet::from([scope("alice")]),
        egress_budget_bytes,
    })
}

/// A remote listing alice's three-part llama, and the parts.
fn listed(egress_budget_bytes: u64) -> (RemoteSource, ObjectRef, Vec<Vec<u8>>) {
    let mut source = remote(egress_budget_bytes);
    let llama = weights("alice", "llama-8b");
    let (parts, specs) = artifact(3);
    source
        .list(llama.class, llama.content, RemoteContent::Original, specs)
        .unwrap();
    (source, llama, parts)
}

#[test]
fn ranges_tile_an_artifact_exactly() {
    let mut source = remote(u64::MAX);
    let llama = weights("alice", "llama-8b");
    let (_, specs) = artifact(3);
    let list = |source: &mut RemoteSource, name: &str, ranges: Vec<RangeSpec>| {
        let object = weights("alice", name);
        source.list(
            object.class,
            object.content,
            RemoteContent::PublisherPrepared,
            ranges,
        )
    };
    assert_eq!(
        source.list(
            llama.class,
            llama.content,
            RemoteContent::Original,
            specs.clone()
        ),
        Ok(3 * PART)
    );
    assert_eq!(
        source.content_of(llama.class, llama.content),
        Some(RemoteContent::Original)
    );
    assert_eq!(
        source.list(
            llama.class,
            llama.content,
            RemoteContent::Original,
            specs.clone()
        ),
        Err(RemoteRefusal::AlreadyListed {
            class: llama.class,
            content: llama.content,
        })
    );
    assert_eq!(
        list(&mut source, "empty", Vec::new()),
        Err(RemoteRefusal::NoRanges)
    );
    let mut empty_range = specs.clone();
    empty_range[1].length_bytes = 0;
    assert_eq!(
        list(&mut source, "empty range", empty_range),
        Err(RemoteRefusal::ZeroLengthRange { index: 1 })
    );
    let mut gap = specs.clone();
    gap[1].offset += 1;
    assert_eq!(
        list(&mut source, "gap", gap),
        Err(RemoteRefusal::RangeGap {
            index: 1,
            expected_offset: PART,
            offset: PART + 1,
        })
    );
    let mut overlap = specs.clone();
    overlap[2].offset -= 1;
    assert_eq!(
        list(&mut source, "overlap", overlap),
        Err(RemoteRefusal::RangeGap {
            index: 2,
            expected_offset: 2 * PART,
            offset: 2 * PART - 1,
        })
    );
    let mut late_start = specs;
    late_start[0].offset = 5;
    assert_eq!(
        list(&mut source, "late start", late_start),
        Err(RemoteRefusal::RangeGap {
            index: 0,
            expected_offset: 0,
            offset: 5,
        })
    );
    let digest = range_digest(0, b"");
    let overflowing = vec![
        RangeSpec {
            offset: 0,
            length_bytes: u64::MAX,
            digest,
        },
        RangeSpec {
            offset: u64::MAX,
            length_bytes: 1,
            digest,
        },
    ];
    assert_eq!(
        list(&mut source, "overflow", overflowing),
        Err(RemoteRefusal::Overflow)
    );
    assert_eq!(
        source.content_of(llama.class, weights("alice", "gap").content),
        None
    );
}

#[test]
fn an_interrupted_download_resumes_with_its_unverified_ranges() {
    let (mut source, llama, parts) = listed(u64::MAX);
    let alice = consumer("alice", "exe-alice-1");
    let mut download = source.begin(&llama, &alice).unwrap();
    assert_eq!(download.object(), &llama);
    assert_eq!(download.pending(), [0, 1, 2]);
    assert_eq!(
        (download.pending_bytes(), download.verified_bytes()),
        (3 * PART, 0)
    );
    source.fetch(&mut download, 0, &parts[0]).unwrap();
    // A corrupted or truncated range fails its integrity check and stays pending; it is
    // never counted as received.
    let mut corrupted = parts[1].clone();
    corrupted[17] ^= 1;
    assert_eq!(
        source.fetch(&mut download, 1, &corrupted),
        Err(RemoteRefusal::IntegrityMismatch { index: 1 })
    );
    assert_eq!(
        source.fetch(&mut download, 1, &parts[1][..100]),
        Err(RemoteRefusal::IntegrityMismatch { index: 1 })
    );
    // The connection drops here. Resuming fetches only what is not verified, and a
    // verified range is never fetched again.
    assert_eq!(download.pending(), [1, 2]);
    assert_eq!(download.verified_bytes(), PART);
    assert!(!download.is_complete());
    assert_eq!(
        source.fetch(&mut download, 0, &parts[0]),
        Err(RemoteRefusal::AlreadyVerified { index: 0 })
    );
    assert_eq!(
        source.fetch(&mut download, 3, &parts[0]),
        Err(RemoteRefusal::UnknownRange { index: 3 })
    );
    source.fetch(&mut download, 1, &parts[1]).unwrap();
    source.fetch(&mut download, 2, &parts[2]).unwrap();
    assert!(download.is_complete());
    assert_eq!(
        (download.pending_bytes(), download.verified_bytes()),
        (0, 3 * PART)
    );
    // Every byte that crossed the link counted, the failed ones included.
    assert_eq!(source.egress_used_bytes(), 5 * PART);
}

#[test]
fn every_fetched_range_counts_against_the_egress_budget() {
    // Two and a half parts may leave the remote in total.
    let (mut source, llama, parts) = listed(2 * PART + PART / 2);
    let alice = consumer("alice", "exe-alice-1");
    let mut download = source.begin(&llama, &alice).unwrap();
    source.fetch(&mut download, 0, &parts[0]).unwrap();
    let mut corrupted = parts[1].clone();
    corrupted[0] ^= 1;
    assert_eq!(
        source.fetch(&mut download, 1, &corrupted),
        Err(RemoteRefusal::IntegrityMismatch { index: 1 })
    );
    // The failed range was charged too (S3.7), so the good copy no longer fits.
    assert_eq!(source.egress_used_bytes(), 2 * PART);
    assert_eq!(
        source.fetch(&mut download, 1, &parts[1]),
        Err(RemoteRefusal::EgressBudgetExhausted {
            egress_budget_bytes: 2 * PART + PART / 2,
            egress_used_bytes: 2 * PART,
            requested_bytes: PART,
        })
    );
    assert_eq!(download.pending(), [1, 2]);
    // Nothing raises the budget implicitly; an offer covers only what remains.
    assert_eq!(source.policy().egress_budget_bytes, 2 * PART + PART / 2);
    let route = || path(0.1 * GB, 0.2, &[]);
    let offer = source
        .offer(source_id("hub"), &llama, &alice, route())
        .unwrap();
    assert_eq!(
        (offer.tier(), offer.covers_bytes()),
        (Tier::Remote, PART / 2)
    );
    // With nothing left the remote offers nothing.
    let (mut spent, llama, parts) = listed(PART);
    let mut download = spent.begin(&llama, &alice).unwrap();
    spent.fetch(&mut download, 0, &parts[0]).unwrap();
    assert_eq!(spent.egress_remaining_bytes(), 0);
    assert_eq!(
        spent
            .offer(source_id("hub"), &llama, &alice, route())
            .unwrap_err()
            .reason,
        TierRefusal::Remote(RemoteRefusal::EgressBudgetExhausted {
            egress_budget_bytes: PART,
            egress_used_bytes: PART,
            requested_bytes: 3 * PART,
        })
    );
}

#[test]
fn downloads_go_only_into_the_requesters_own_scope_under_the_access_policy() {
    let (source, llama, _) = listed(u64::MAX);
    let alice = consumer("alice", "exe-alice-1");
    let bob = consumer("bob", "exe-bob-1");
    // The same content in Bob's scope is another object, which this remote does not serve:
    // content hashing establishes equality, not permission (line 546).
    let bobs = ObjectRef {
        scope: scope("bob"),
        ..llama.clone()
    };
    assert_eq!(
        source.begin(&bobs, &bob),
        Err(RemoteRefusal::AccessDenied {
            scope: scope("bob")
        })
    );
    // A download goes only into the requester's own scope.
    assert_eq!(
        source.begin(&llama, &bob),
        Err(RemoteRefusal::NotRequestersScope {
            object: llama.clone()
        })
    );
    let unlisted = weights("alice", "mistral-7b");
    assert_eq!(
        source.begin(&unlisted, &alice),
        Err(RemoteRefusal::NotListed {
            class: unlisted.class,
            content: unlisted.content,
        })
    );
    let route = || path(0.1 * GB, 0.2, &[]);
    assert_eq!(
        source
            .offer(source_id("hub"), &bobs, &bob, route())
            .unwrap_err()
            .reason,
        TierRefusal::Remote(RemoteRefusal::AccessDenied {
            scope: scope("bob")
        })
    );
    // Like a download, an offer is only for the requester's own scope.
    assert_eq!(
        source
            .offer(source_id("hub"), &llama, &bob, route())
            .unwrap_err()
            .reason,
        TierRefusal::Remote(RemoteRefusal::NotRequestersScope {
            object: llama.clone()
        })
    );
    let offer = source
        .offer(source_id("hub"), &llama, &alice, route())
        .unwrap();
    assert_eq!(offer.covers_bytes(), 3 * PART);
    assert_eq!(offer.requester(), &alice);
}

#[test]
fn a_range_digest_binds_offset_length_and_bytes() {
    let bytes = vec![3u8; 16];
    assert_eq!(
        range_digest(0, &bytes),
        DigestBuilder::new(RANGE_DOMAIN)
            .u64(0)
            .bytes(&bytes)
            .finish()
    );
    assert_eq!(RANGE_DOMAIN, "yougori/model-memory/tiers/range/v1");
    // Equal bytes at another offset, or fewer of them, are another range.
    assert_ne!(range_digest(0, &bytes), range_digest(16, &bytes));
    assert_ne!(range_digest(0, &bytes), range_digest(0, &bytes[..15]));
    // So the digest of one range never verifies the bytes of another place.
    let (mut source, _, _) = listed(u64::MAX);
    let same = vec![9u8; PART as usize];
    let specs: Vec<RangeSpec> = (0..2)
        .map(|index| RangeSpec {
            offset: index * PART,
            length_bytes: PART,
            digest: range_digest(0, &same),
        })
        .collect();
    let repeated = weights("alice", "repeated parts");
    source
        .list(
            repeated.class,
            repeated.content,
            RemoteContent::Original,
            specs,
        )
        .unwrap();
    let mut download = source
        .begin(&repeated, &consumer("alice", "exe-alice-1"))
        .unwrap();
    source.fetch(&mut download, 0, &same).unwrap();
    assert_eq!(
        source.fetch(&mut download, 1, &same),
        Err(RemoteRefusal::IntegrityMismatch { index: 1 })
    );
}

#[test]
fn a_remote_copy_never_rebuilds_a_dropped_gpu_copy() {
    let (source, llama, _) = listed(u64::MAX);
    // Nothing here verified it, and access can end (T08).
    let copy = source.copy_of(&llama).unwrap();
    assert_eq!((&copy.object, copy.holder.as_ref()), (&llama, None));
    assert_eq!(copy.copy.tier, CopyTier::RemoteSource);
    assert_eq!(copy.copy.verification, Verification::Unverified);
    assert!(!copy.copy.reconstructs(&Content::Immutable(llama.content)));
    let bobs = ObjectRef {
        scope: scope("bob"),
        ..llama
    };
    assert_eq!(source.copy_of(&bobs), None);
    assert_eq!(source.copy_of(&weights("alice", "mistral-7b")), None);
}
