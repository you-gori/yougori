//! §1.1, line 308: an immutable base with unmerged adapters, or a merged variant with its
//! own identity; floating-point subtraction is not a bit-exact undo.

use super::super::*;
use super::support::*;

fn session_for(execution: ExecutionIdentity, adapter: Option<AdapterIdentity>) -> SessionIdentity {
    SessionSpec {
        execution,
        adapter,
        ..session_spec()
    }
    .identity()
}

fn execution_of(logical: &LogicalModelSpec) -> ExecutionIdentity {
    ExecutionSpec {
        logical: logical.identity(),
        ..execution_spec()
    }
    .identity()
    .unwrap()
}

#[test]
fn a_merged_lora_variant_has_its_own_identity() {
    let base = logical_spec();
    let variant = base.with_merged(merged("org/a", 1.0));

    // The base is untouched and keeps its identity.
    assert_eq!(base, logical_spec());
    assert_eq!(base.identity(), logical());
    assert_eq!(base.adapters, AdapterRecipe::None);
    assert_ne!(variant.identity(), base.identity());
    assert_ne!(execution_of(&variant), execution_of(&base));

    // Base with the adapter unmerged and the merged variant are different sessions:
    // the same weights in two representations, never treated as equal.
    let unmerged = session_for(execution_of(&base), Some(adapter("org/a")));
    let merged_session = session_for(execution_of(&variant), None);
    let plain = session_for(execution_of(&base), None);
    assert_all_distinct(&[
        ("base with unmerged adapter", unmerged),
        ("merged variant", merged_session),
        ("base alone", plain),
    ]);
}

#[test]
fn merge_order_scale_and_procedure_are_part_of_the_variant() {
    let base = logical_spec();
    let a_then_b = base
        .with_merged(merged("org/a", 1.0))
        .with_merged(merged("org/b", 1.0));
    let b_then_a = base
        .with_merged(merged("org/b", 1.0))
        .with_merged(merged("org/a", 1.0));
    let half = base.with_merged(merged("org/a", 0.5));
    let other_procedure = base.with_merged(MergedAdapter {
        procedure: versioned("peft-merge-bf16", "0.13"),
        ..merged("org/a", 1.0)
    });
    assert_all_distinct(&[
        ("a then b", a_then_b.identity()),
        ("b then a", b_then_a.identity()),
        ("a at half scale", half.identity()),
        ("a by another procedure", other_procedure.identity()),
        ("a", base.with_merged(merged("org/a", 1.0)).identity()),
        ("base", base.identity()),
    ]);
    assert_eq!(
        MergedAdapters::new(vec![merged("org/a", 1.0), merged("org/b", 1.0)])
            .map(AdapterRecipe::Merged),
        Ok(a_then_b.adapters)
    );
}

#[test]
fn subtracting_a_merged_adapter_is_refused() {
    let base = AdaptedModel::base(logical_spec());
    let merged_a = base
        .apply(&AdapterChange::Merge(merged("org/a", 1.0)))
        .unwrap();
    assert_ne!(merged_a.logical.identity(), logical());

    // Merge-then-subtract is not an exact undo: reload the immutable base instead.
    assert_eq!(
        merged_a.apply(&AdapterChange::SubtractMerged(adapter("org/a"))),
        Err(LoraRefusal::SubtractionIsNotExactUndo {
            load_instead: logical(),
        })
    );

    // With two merged, the refusal names the variant without that adapter.
    let merged_ab = merged_a
        .apply(&AdapterChange::Merge(merged("org/b", 1.0)))
        .unwrap();
    assert_eq!(
        merged_ab.apply(&AdapterChange::SubtractMerged(adapter("org/a"))),
        Err(LoraRefusal::SubtractionIsNotExactUndo {
            load_instead: logical_spec().with_merged(merged("org/b", 1.0)).identity(),
        })
    );
    assert_eq!(
        merged_ab.apply(&AdapterChange::SubtractMerged(adapter("org/b"))),
        Err(LoraRefusal::SubtractionIsNotExactUndo {
            load_instead: merged_a.logical.identity(),
        })
    );

    // Nothing to subtract.
    assert_eq!(
        base.apply(&AdapterChange::SubtractMerged(adapter("org/a"))),
        Err(LoraRefusal::NotMerged {
            adapter: adapter("org/a")
        })
    );
    assert_eq!(
        merged_a.apply(&AdapterChange::SubtractMerged(adapter("org/c"))),
        Err(LoraRefusal::NotMerged {
            adapter: adapter("org/c")
        })
    );
}

#[test]
fn unmerged_adapters_leave_the_immutable_base_exactly_as_it_was() {
    let base = AdaptedModel::base(logical_spec());
    let attached = base
        .apply(&AdapterChange::AttachUnmerged(adapter("org/a")))
        .unwrap();
    assert_eq!(
        attached.logical.identity(),
        logical(),
        "the base is immutable"
    );
    assert_eq!(attached.unmerged, Some(adapter("org/a")));

    let detached = attached.apply(&AdapterChange::DetachUnmerged).unwrap();
    assert_eq!(
        detached, base,
        "detaching an unmerged adapter is an exact undo"
    );

    assert_eq!(
        attached.apply(&AdapterChange::AttachUnmerged(adapter("org/b"))),
        Err(LoraRefusal::AlreadyAttached {
            attached: adapter("org/a")
        })
    );
    assert_eq!(
        base.apply(&AdapterChange::DetachUnmerged),
        Err(LoraRefusal::NothingAttached)
    );

    // Merging while an unmerged adapter is attached keeps the attachment separate.
    let merged_with_attached = attached
        .apply(&AdapterChange::Merge(merged("org/b", 1.0)))
        .unwrap();
    assert_eq!(merged_with_attached.unmerged, Some(adapter("org/a")));
    assert_eq!(
        merged_with_attached.logical.identity(),
        logical_spec().with_merged(merged("org/b", 1.0)).identity()
    );
}

#[test]
fn merge_inputs_are_checked() {
    for scale in [0.0, -0.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert_eq!(
            MergeScale::new(scale),
            Err(IdentityError::InvalidMergeScale),
            "{scale}"
        );
    }
    assert_eq!(MergeScale::new(-0.25).map(MergeScale::get), Ok(-0.25));
    assert_eq!(
        MergedAdapters::new(Vec::new()),
        Err(IdentityError::NoMergedAdapters)
    );
}
