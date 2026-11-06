//! CORE-06 progress as shown, converted from a real hub's progress state and handed to the
//! setup crate's OperationEvent.

use super::*;
use crate::foundation::events::Phase;
use crate::foundation::product::ProgressShown;
use crate::product_views::from_setup::operation_event;

#[test]
fn a_hub_progress_state_converts_with_core06s_own_description() {
    let event = recorded(Phase::Queued, queued_for_memory());
    let shown = ProgressShown::of(&event).unwrap();
    assert_eq!(shown.phase(), Phase::Queued);
    assert!(!shown.ended());
    assert_eq!(
        shown.description().as_str(),
        "waiting for 4 GB of GPU memory"
    );
    assert_eq!(shown.operation().as_str(), "op-load-1");
    assert_eq!(round_trip(&shown), shown);

    let event = operation_event(&shown, 7, 1_700_000_000);
    assert_eq!(event.cursor, 7);
    assert_eq!(event.step, "queued");
    assert_eq!(event.message, "waiting for 4 GB of GPU memory");
    assert_eq!(event.resource, Some(weights().identity().to_hex()));
}
