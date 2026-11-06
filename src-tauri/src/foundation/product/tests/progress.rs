//! CORE-06 progress as shown: revalidated with CORE-06's own check when read. The setup
//! crate's OperationEvent is tested in `product_views`.

use serde_json::json;

use super::*;
use crate::foundation::events::Phase;
use crate::foundation::product::ProgressShown;

#[test]
fn reading_progress_back_runs_core06s_check_and_recomputes_the_description() {
    let shown = ProgressShown::of(&recorded(Phase::Queued, queued_for_memory())).unwrap();
    let json = serde_json::to_value(&shown).unwrap();

    let mut completed = json.clone();
    completed["phase"] = json!("completed");
    completed["ended"] = json!(true);
    let error = refused::<ProgressShown>(completed);
    assert!(error.contains("completed resource"), "{error}");

    let mut not_ended = json.clone();
    not_ended["update"]["queue_reason"] = serde_json::Value::Null;
    not_ended["phase"] = json!("loading");
    not_ended["description"] = json!("loading weights");
    assert!(serde_json::from_value::<ProgressShown>(not_ended.clone()).is_ok());
    not_ended["ended"] = json!(true);
    assert!(refused::<ProgressShown>(not_ended).contains("terminal"));

    let mut reworded = json.clone();
    reworded["description"] = json!("ready");
    assert!(refused::<ProgressShown>(reworded).contains("CORE-06's description"));

    let mut extra = json;
    extra["percent"] = json!(50);
    assert!(refused::<ProgressShown>(extra).contains("unknown field"));
}
