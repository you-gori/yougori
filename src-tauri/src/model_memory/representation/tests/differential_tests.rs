//! §4.2 exact differential materialization: R minus A, stable identities, compatibility,
//! verification, the full-loader cutoff and measured sharing.

use super::super::differential::*;
use super::*;
use crate::foundation::ids::digest;
use crate::model_memory::manifest::{Distribution, ExtentDecoder, ExtentError, RankRefusal};

const VALUES: usize = 512; // 1024 bytes per tensor: four extents of G

fn tensors(seed: u64, names: &[&'static str]) -> Vec<(&'static str, Vec<u8>)> {
    names
        .iter()
        .enumerate()
        .map(|(index, name)| (*name, bf16_weights(seed * 100 + index as u64, VALUES, 0.02)))
        .collect()
}

fn decoders(decoder: &ZstdDecoder) -> [&dyn ExtentDecoder; 1] {
    [decoder as &dyn ExtentDecoder]
}

fn checkpoint_pair() -> (Model, Model) {
    let base_tensors = tensors(1, &["a", "b", "c", "d"]);
    let mut target_tensors = base_tensors.clone();
    target_tensors[2].1 = fine_tune(&base_tensors[2].1, 9, 0.01);
    (
        build_model(&ModelSpec::single(base_tensors)),
        build_model(&ModelSpec::single(target_tensors)),
    )
}

#[test]
fn only_r_minus_a_is_loaded_and_the_result_is_bit_exact() {
    let (base, target) = checkpoint_pair();
    let (residents, resident_bytes) = resident_model(&base);
    let required = RequiredSet::for_all_tensors(&target.manifest).unwrap();
    assert_eq!(required.len(), 16);
    let plan = plan(&required, &residents, &consumer(), &clock());
    // Tensor c changed: its four extents are missing, the other twelve are reused.
    assert_eq!(plan.missing().len(), 4);
    assert_eq!(plan.reused().len(), 12);
    assert_eq!(plan.missing_stored_bytes().unwrap(), 4 * G);
    assert_eq!(plan.reused_stored_bytes().unwrap(), 12 * G);
    assert_eq!(plan.required_stored_bytes().unwrap(), 16 * G);
    assert!(plan.rejections().is_empty());
    let c_extents = RequiredSet::for_tensors(&target.manifest, &["c"]).unwrap();
    assert!(plan
        .missing()
        .iter()
        .all(|extent| c_extents.contains(&extent.key)));

    let decoder = ZstdDecoder;
    let differential = materialize(
        &target.manifest,
        &plan,
        &target,
        &resident_bytes,
        &decoders(&decoder),
        &clock(),
    )
    .unwrap();
    assert_eq!(differential.transferred_stored_bytes, 4 * G);
    assert_eq!(differential.reused_decoded_bytes, 12 * G);
    assert_eq!(differential.verified_decoded_bytes, 16 * G);
    let full = full_load(&target.manifest, &required, &target, &decoders(&decoder)).unwrap();
    assert_eq!(full.transferred_stored_bytes, 16 * G);
    for name in ["a", "b", "c", "d"] {
        let bytes = differential.tensor_bytes(&target.manifest, name).unwrap();
        assert_eq!(bytes, full.tensor_bytes(&target.manifest, name).unwrap());
        assert_eq!(bytes, target.tensor_source_bytes(name));
    }
}

#[test]
fn aliases_and_tied_copies_keep_one_identity() {
    let base = tensors(2, &["embed.weight", "layer.0"]);
    let embed = base[0].1.clone();
    let mut spec = ModelSpec::single(vec![
        ("embed.weight", embed.clone()),
        ("layer.0", base[1].1.clone()),
        ("tied.copy", embed),
    ]);
    spec.aliases = vec![("lm_head.weight", "embed.weight")];
    let model = build_model(&spec);
    let embed_only = RequiredSet::for_tensors(&model.manifest, &["embed.weight"]).unwrap();
    let with_alias =
        RequiredSet::for_tensors(&model.manifest, &["embed.weight", "lm_head.weight"]).unwrap();
    let with_copy =
        RequiredSet::for_tensors(&model.manifest, &["embed.weight", "tied.copy"]).unwrap();
    assert_eq!(with_alias, embed_only);
    // The stored copy has the same decoded keys, so it adds no element to R.
    assert_eq!(with_copy.len(), embed_only.len());
    assert_eq!(with_copy.decoded_bytes().unwrap(), 4 * G);
    assert_eq!(
        RequiredSet::for_tensors(&model.manifest, &["missing"]),
        Err(DifferentialError::UnknownTensor {
            name: "missing".into()
        })
    );
    // An alias identity is its target's identity.
    let entry = model.manifest.tensor("lm_head.weight").unwrap();
    assert_eq!(entry.name.as_str(), "embed.weight");
}

fn adapter_pair() -> (Model, Model) {
    let base_tensors = tensors(3, &["layer.0", "layer.1"]);
    let adapter = WeightFile::aligned(
        "adapter.safetensors",
        vec![
            ("lora.a", bf16_weights(31, 256, 0.01)),
            ("lora.b", bf16_weights(32, 256, 0.01)),
        ],
    );
    let base = build_model(&ModelSpec::single(base_tensors.clone()));
    let mut spec = ModelSpec::single(base_tensors);
    spec.files.push(adapter);
    spec.adapters = vec![digest("yougori/test/adapter/v1", &[b"lora"])];
    (base, build_model(&spec))
}

#[test]
fn an_unchanged_adapter_base_keeps_its_identity() {
    let (base, target) = adapter_pair();
    // The artifacts differ, so their identities differ...
    assert_ne!(base.manifest.digest(), target.manifest.digest());
    // ...but every base extent keeps its decoded content key.
    let base_keys: Vec<_> = RequiredSet::for_all_tensors(&base.manifest)
        .unwrap()
        .extents()
        .map(|extent| extent.key)
        .collect();
    let target_required = RequiredSet::for_all_tensors(&target.manifest).unwrap();
    assert!(base_keys.iter().all(|key| target_required.contains(key)));
    let (residents, resident_bytes) = resident_model(&base);
    let plan = plan(&target_required, &residents, &consumer(), &clock());
    let adapter = RequiredSet::for_tensors(&target.manifest, &["lora.a", "lora.b"]).unwrap();
    assert_eq!(plan.missing().len(), adapter.len());
    assert!(plan
        .missing()
        .iter()
        .all(|extent| adapter.contains(&extent.key)));
    let decoder = ZstdDecoder;
    let loaded = materialize(
        &target.manifest,
        &plan,
        &target,
        &resident_bytes,
        &decoders(&decoder),
        &clock(),
    )
    .unwrap();
    assert_eq!(
        loaded.transferred_stored_bytes,
        adapter.stored_bytes().unwrap()
    );
    let sharing = measure_sharing(&base.manifest, &base, &target.manifest, &target).unwrap();
    assert_eq!(sharing.relation(), FamilyRelation::AdapterFamily);
}

#[test]
fn reuse_does_not_depend_on_the_encoding() {
    let weights = tensors(4, &["a", "b"]);
    let raw = build_model(&ModelSpec::single(weights.clone()));
    let encoded = build_model(&ModelSpec {
        storage: ZSTD,
        ..ModelSpec::single(weights)
    });
    assert_ne!(raw.manifest.digest(), encoded.manifest.digest());
    let decoder = ZstdDecoder;
    for (resident, target) in [(&raw, &encoded), (&encoded, &raw)] {
        let (residents, bytes) = resident_model(resident);
        let required = RequiredSet::for_all_tensors(&target.manifest).unwrap();
        let plan = plan(&required, &residents, &consumer(), &clock());
        assert!(plan.missing().is_empty());
        let loaded = materialize(
            &target.manifest,
            &plan,
            target,
            &bytes,
            &decoders(&decoder),
            &clock(),
        )
        .unwrap();
        assert_eq!(loaded.transferred_stored_bytes, 0);
        assert_eq!(
            loaded.tensor_bytes(&target.manifest, "b").unwrap(),
            target.tensor_source_bytes("b")
        );
    }
}

#[test]
fn incompatible_resident_copies_are_not_in_a() {
    let (base, target) = checkpoint_pair();
    let (residents, _) = resident_model(&base);
    let required = RequiredSet::for_tensors(&target.manifest, &["a"]).unwrap();
    let key = required.extents().next().unwrap().key;
    let original = *residents
        .iter()
        .find(|resident| resident.key == key)
        .unwrap();
    let variants = [
        (
            ResidentExtent {
                expires_at: crate::foundation::ids::MonotonicTime::from_nanos(1_000),
                ..original
            },
            ResidentRejection::Expired,
        ),
        (
            ResidentExtent {
                scope: tenant_scope("tenant-b"),
                ..original
            },
            ResidentRejection::OtherTrustScope,
        ),
        (
            ResidentExtent {
                scope: crate::foundation::ids::TrustScope::named(
                    crate::foundation::ids::ExecutionCategory::VmSandbox,
                    "tenant-a",
                ),
                ..original
            },
            ResidentRejection::OtherTrustScope,
        ),
        (
            ResidentExtent {
                device: device("gpu-1"),
                ..original
            },
            ResidentRejection::OtherDevice,
        ),
        (
            ResidentExtent {
                true_length_bytes: original.true_length_bytes + 1,
                ..original
            },
            ResidentRejection::LengthMismatch,
        ),
    ];
    for (resident, reason) in variants {
        let plan = plan(&required, &[resident], &consumer(), &clock());
        assert!(plan.reused().iter().all(|reused| reused.extent.key != key));
        assert!(plan.rejections().contains(&(key, reason)), "{reason:?}");
    }
    // A compatible copy beside an incompatible one is enough, and nothing is rejected.
    let both = [variants[1].0, original];
    let plan = plan(&required, &both, &consumer(), &clock());
    assert!(plan.reused().iter().any(|reused| reused.extent.key == key));
    assert!(plan
        .rejections()
        .iter()
        .all(|(rejected, _)| *rejected != key));
}

#[test]
fn bytes_that_fail_verification_are_refused_not_used() {
    let (base, target) = checkpoint_pair();
    let (residents, mut bytes) = resident_model(&base);
    let required = RequiredSet::for_all_tensors(&target.manifest).unwrap();
    let plan = plan(&required, &residents, &consumer(), &clock());
    let decoder = ZstdDecoder;
    let reused = plan.reused()[0].extent.key;
    bytes.consumer_copy(&reused).unwrap()[0] ^= 1;
    assert_eq!(
        materialize(
            &target.manifest,
            &plan,
            &target,
            &bytes,
            &decoders(&decoder),
            &clock()
        ),
        Err(DifferentialError::ResidentMismatch { key: reused })
    );
    bytes.remove_consumer_copy(&reused);
    assert_eq!(
        materialize(
            &target.manifest,
            &plan,
            &target,
            &bytes,
            &decoders(&decoder),
            &clock()
        ),
        Err(DifferentialError::ResidentUnavailable { key: reused })
    );
    // Stored bytes that do not match the target manifest.
    struct Corrupt<'a>(&'a Model);
    impl StoredExtents for Corrupt<'_> {
        fn stored(&self, extent_index: usize) -> Option<Vec<u8>> {
            let mut bytes = self.0.stored(extent_index)?;
            bytes[0] ^= 1;
            Some(bytes)
        }
        fn dictionary(&self, _: &crate::model_memory::manifest::DictionaryId) -> Option<Vec<u8>> {
            None
        }
    }
    let (_, fresh) = resident_model(&base);
    let missing = plan.missing()[0].extent_index;
    assert_eq!(
        materialize(
            &target.manifest,
            &plan,
            &Corrupt(&target),
            &fresh,
            &decoders(&decoder),
            &clock()
        ),
        Err(DifferentialError::Verification {
            extent_index: missing,
            error: ExtentError::ContentKeyMismatch
        })
    );
    // A plan made for another manifest is refused.
    assert_eq!(
        materialize(
            &base.manifest,
            &plan,
            &base,
            &fresh,
            &decoders(&decoder),
            &clock()
        ),
        Err(DifferentialError::PlanForAnotherManifest)
    );
    assert_eq!(
        full_load(&base.manifest, &required, &base, &decoders(&decoder)),
        Err(DifferentialError::PlanForAnotherManifest)
    );
}

#[test]
fn the_full_loader_is_kept_unless_the_saved_transfer_strictly_exceeds_index_and_hash_cost() {
    let (base, target) = checkpoint_pair();
    let (residents, _) = resident_model(&base);
    let required = RequiredSet::for_all_tensors(&target.manifest).unwrap();
    let plan = plan(&required, &residents, &consumer(), &clock());
    // 3,072 reused and 1,024 missing stored bytes over a 1,024 B/s link: 3 s saved of 4 s.
    let link = 1024.0;
    let cost = |index_seconds| IndexHashCost {
        index_seconds,
        hashed_bytes: 2048,
        hash_bytes_per_second: 1024.0,
    };
    // 0.5 s indexing + 2 s hashing = 2.5 s < 3 s: differential, 3.5 s instead of 4 s.
    let cheap = choose_loader(&plan, link, &cost(0.5)).unwrap();
    assert_eq!(cheap.choice, LoaderChoice::Differential);
    assert_eq!(cheap.saved_transfer_seconds, 3.0);
    assert_eq!(cheap.index_hash_seconds, 2.5);
    assert_eq!(cheap.differential_seconds, 3.5);
    assert_eq!(cheap.full_loader_seconds, 4.0);
    // 1 s + 2 s = 3 s: equal to the saving, so the full loader is kept.
    assert_eq!(
        choose_loader(&plan, link, &cost(1.0)).unwrap().choice,
        LoaderChoice::FullLoader
    );
    // 1.5 s + 2 s exceeds the saving.
    assert_eq!(
        choose_loader(&plan, link, &cost(1.5)).unwrap().choice,
        LoaderChoice::FullLoader
    );
    // Nothing reused: even a free index cannot amortize.
    let nothing = plan_with_no_residents(&target);
    let free = IndexHashCost {
        index_seconds: 0.0,
        hashed_bytes: 0,
        hash_bytes_per_second: 1.0,
    };
    assert_eq!(
        choose_loader(&nothing, link, &free).unwrap().choice,
        LoaderChoice::FullLoader
    );
    // Invalid rates are refused, never clamped.
    assert!(choose_loader(&plan, 0.0, &cost(0.5)).is_err());
    assert!(choose_loader(&plan, link, &cost(f64::NAN)).is_err());
    assert!(choose_loader(
        &plan,
        link,
        &IndexHashCost {
            hash_bytes_per_second: 0.0,
            ..cost(0.5)
        }
    )
    .is_err());
}

fn plan_with_no_residents(target: &Model) -> DifferentialPlan {
    let required = RequiredSet::for_all_tensors(&target.manifest).unwrap();
    plan(&required, &[], &consumer(), &clock())
}

#[test]
fn families_are_judged_by_measured_sharing_never_assumed() {
    // Adapter family.
    let (base, adapter) = adapter_pair();
    let sharing = measure_sharing(&base.manifest, &base, &adapter.manifest, &adapter).unwrap();
    assert_eq!(sharing.relation(), FamilyRelation::AdapterFamily);
    assert_eq!(sharing.shared_tensor_bytes, 2 * 4 * G);
    // Checkpoint family with actually unchanged tensors, aligned to extents: tensor and
    // extent sharing agree.
    let (base, checkpoint) = checkpoint_pair();
    let sharing =
        measure_sharing(&base.manifest, &base, &checkpoint.manifest, &checkpoint).unwrap();
    assert_eq!(sharing.relation(), FamilyRelation::CheckpointFamily);
    assert_eq!(sharing.shared_tensors, 3);
    assert_eq!(sharing.shared_tensor_bytes, 12 * G);
    assert_eq!(sharing.shared_extent_bytes, 12 * G);
    assert_eq!(sharing.target_extent_bytes, 16 * G);
    assert_eq!(sharing.hashed_bytes, 32 * G);
    // An unrelated dense fine-tune with the same names: every tensor changed, nothing
    // is shared at either granularity, and the differential path saves nothing.
    let names = ["a", "b", "c", "d"];
    let base_tensors = tensors(1, &names);
    let tuned: Vec<_> = base_tensors
        .iter()
        .enumerate()
        .map(|(index, (name, bytes))| (*name, fine_tune(bytes, 50 + index as u64, 0.002)))
        .collect();
    let changed_bytes = base_tensors
        .iter()
        .zip(&tuned)
        .flat_map(|((_, a), (_, b))| a.iter().zip(b).map(|(x, y)| x != y))
        .filter(|changed| *changed)
        .count();
    // Virtually every byte pair changed: at least half of all bytes differ.
    assert!(changed_bytes * 2 > 4 * VALUES * 2, "{changed_bytes}");
    let tuned_model = build_model(&ModelSpec::single(tuned));
    let sharing =
        measure_sharing(&base.manifest, &base, &tuned_model.manifest, &tuned_model).unwrap();
    assert_eq!(sharing.relation(), FamilyRelation::Unrelated);
    assert_eq!(sharing.shared_tensor_bytes, 0);
    assert_eq!(sharing.shared_extent_bytes, 0);
    let (residents, _) = resident_model(&base);
    let required = RequiredSet::for_all_tensors(&tuned_model.manifest).unwrap();
    let dense = plan(&required, &residents, &consumer(), &clock());
    assert!(dense.reused().is_empty());
    // The same tensors one byte further into the file: every tensor is shared, yet no
    // file-aligned extent is, so only tensor-granularity reuse could help.
    let mut shifted = ModelSpec::single(base_tensors.clone());
    shifted.files[0].header_length_bytes = ALIGNED_HEADER + 1;
    let shifted = build_model(&shifted);
    let sharing = measure_sharing(&base.manifest, &base, &shifted.manifest, &shifted).unwrap();
    assert_eq!(sharing.relation(), FamilyRelation::Identical);
    assert_eq!(sharing.shared_tensor_bytes, 16 * G);
    assert_eq!(sharing.shared_extent_bytes, 0);
}

#[test]
fn a_rank_plan_for_another_layout_or_rank_is_refused() {
    let (_, target) = checkpoint_pair();
    let single = RequiredSet::for_rank(&target.manifest, &Distribution::SINGLE, 0).unwrap();
    assert_eq!(
        single,
        RequiredSet::for_all_tensors(&target.manifest).unwrap()
    );
    let other = Distribution {
        tensor_parallel_size: 2,
        ..Distribution::SINGLE
    };
    assert!(matches!(
        RequiredSet::for_rank(&target.manifest, &other, 0),
        Err(DifferentialError::Rank(RankRefusal::LayoutMismatch { .. }))
    ));
    assert!(matches!(
        RequiredSet::for_rank(&target.manifest, &Distribution::SINGLE, 1),
        Err(DifferentialError::Rank(RankRefusal::RankOutOfRange { .. }))
    ));
}

#[test]
fn tensor_identity_binds_interpretation_and_bytes_but_not_names() {
    let (base, target) = checkpoint_pair();
    let a_base = base.manifest.tensor("a").unwrap();
    let a_target = target.manifest.tensor("a").unwrap();
    let bytes = base.tensor_source_bytes("a");
    assert_eq!(
        TensorIdentity::of(a_base, &bytes),
        TensorIdentity::of(a_target, &target.tensor_source_bytes("a"))
    );
    let mut reshaped = a_base.clone();
    reshaped.shape = vec![2, VALUES as u64 / 2];
    assert_ne!(
        TensorIdentity::of(a_base, &bytes),
        TensorIdentity::of(&reshaped, &bytes)
    );
    let mut renamed = a_base.clone();
    renamed.name = tensor_name("renamed");
    assert_eq!(
        TensorIdentity::of(a_base, &bytes),
        TensorIdentity::of(&renamed, &bytes)
    );
}

/// A stored-extent port that counts reads.
struct Counting<'a> {
    model: &'a Model,
    reads: std::cell::Cell<usize>,
}

impl StoredExtents for Counting<'_> {
    fn stored(&self, extent_index: usize) -> Option<Vec<u8>> {
        self.reads.set(self.reads.get() + 1);
        self.model.stored(extent_index)
    }

    fn dictionary(&self, _: &crate::model_memory::manifest::DictionaryId) -> Option<Vec<u8>> {
        None
    }
}

/// A resident port that serves a key from whichever copy it holds, ignoring the binding.
struct Elsewhere {
    copies: BTreeMap<ContentKey, Vec<u8>>,
    scope: TrustScope,
    device: GpuDeviceKey,
}

impl ResidentBytes for Elsewhere {
    fn resident(&self, resident: &ResidentExtent) -> Option<ResidentRead> {
        self.copies.get(&resident.key).map(|bytes| ResidentRead {
            scope: self.scope,
            device: self.device,
            bytes: bytes.clone(),
        })
    }
}

#[test]
fn a_reuse_reads_only_the_copy_the_plan_bound() {
    let (base, target) = checkpoint_pair();
    let (residents, bytes) = resident_model(&base);
    let required = RequiredSet::for_all_tensors(&target.manifest).unwrap();
    let switch = plan(&required, &residents, &consumer(), &clock());
    let decoder = ZstdDecoder;
    // Every reuse records the copy the plan accepted.
    assert!(switch.reused().iter().all(|reused| {
        reused.resident.key == reused.extent.key
            && reused.resident.scope == consumer().scope
            && reused.resident.device == consumer().device
    }));
    let first = switch.reused()[0].extent.key;
    let elsewhere = [
        (tenant_scope("tenant-b"), consumer().device),
        (consumer().scope, device("gpu-1")),
    ];
    // The same bytes served from another scope or device are refused, though they hash
    // to the right key.
    for (scope, device) in elsewhere {
        let port = Elsewhere {
            copies: base.decoded_extents(),
            scope,
            device,
        };
        assert_eq!(
            materialize(
                &target.manifest,
                &switch,
                &target,
                &port,
                &decoders(&decoder),
                &clock()
            ),
            Err(DifferentialError::ResidentOutsideBinding { key: first })
        );
    }
    // A correct port that holds the key only in another scope or on another device has
    // no copy to serve.
    for (scope, device) in elsewhere {
        let moved = Residents(
            bytes
                .0
                .iter()
                .map(|((key, _, _), data)| ((*key, scope, device), data.clone()))
                .collect(),
        );
        assert_eq!(
            materialize(
                &target.manifest,
                &switch,
                &target,
                &moved,
                &decoders(&decoder),
                &clock()
            ),
            Err(DifferentialError::ResidentUnavailable { key: first })
        );
    }
    assert!(materialize(
        &target.manifest,
        &switch,
        &target,
        &bytes,
        &decoders(&decoder),
        &clock()
    )
    .is_ok());
}

#[test]
fn a_copy_that_expires_between_plan_and_materialize_is_refused_before_any_read() {
    let (base, target) = checkpoint_pair();
    let (residents, bytes) = resident_model(&base);
    let required = RequiredSet::for_all_tensors(&target.manifest).unwrap();
    let decoder = ZstdDecoder;
    let switch_clock = clock();
    let switch = plan(&required, &residents, &consumer(), &switch_clock);
    assert_eq!(switch.reused().len(), 12);
    switch_clock.advance_to(EXPIRES);
    let stored = Counting {
        model: &target,
        reads: std::cell::Cell::new(0),
    };
    assert!(matches!(
        materialize(
            &target.manifest,
            &switch,
            &stored,
            &bytes,
            &decoders(&decoder),
            &switch_clock
        ),
        Err(DifferentialError::ResidentExpired { expired_at, .. }) if expired_at == EXPIRES
    ));
    assert_eq!(stored.reads.get(), 0);
    // Of two compatible copies the plan binds the one that lives longer.
    let short_lived: Vec<ResidentExtent> = residents
        .iter()
        .map(|resident| ResidentExtent {
            expires_at: MonotonicTime::from_nanos(2_000),
            ..*resident
        })
        .collect();
    let mut both = short_lived.clone();
    both.extend(residents.iter().copied());
    let later = clock();
    let robust = plan(&required, &both, &consumer(), &later);
    assert!(robust
        .reused()
        .iter()
        .all(|reused| reused.resident.expires_at == EXPIRES));
    later.advance_to(MonotonicTime::from_nanos(5_000));
    assert!(materialize(
        &target.manifest,
        &robust,
        &target,
        &bytes,
        &decoders(&decoder),
        &later
    )
    .is_ok());
    let fragile = plan(&required, &short_lived, &consumer(), &clock());
    assert!(matches!(
        materialize(
            &target.manifest,
            &fragile,
            &target,
            &bytes,
            &decoders(&decoder),
            &later
        ),
        Err(DifferentialError::ResidentExpired { .. })
    ));
}
