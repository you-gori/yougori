//! Refusals: safe, bounded text and a remedy's own words. Codes, conversions from domain
//! refusals and the setup crate's Diagnostic are tested in `product_views`.

use serde_json::json;

use super::*;
use crate::foundation::product::{
    MigrationCode, Refusal, RefusalCode, Remedy, ShownText, MAX_SHOWN_CHARS,
};

#[test]
fn refusal_text_is_bounded_and_never_carries_a_hazardous_character() {
    let refusal = Refusal::new(
        RefusalCode::Migration {
            code: MigrationCode::UnknownLegacyChoice,
        },
        "the type \u{1b}[31mred\u{202e} is unknown",
        Remedy::UpdateYougori,
    );
    let reason = refusal.reason.as_str();
    assert!(!reason.contains('\u{1b}') && !reason.contains('\u{202e}'));
    assert!(reason.contains("\\u{1b}"), "{reason}");
    assert_eq!(round_trip(&refusal), refusal);

    let long = ShownText::new(&"x".repeat(MAX_SHOWN_CHARS * 2));
    assert_eq!(long.as_str().chars().count(), MAX_SHOWN_CHARS);
    assert!(long.as_str().ends_with("..."));
    assert_eq!(ShownText::new("").as_str(), "-");

    let mut json = serde_json::to_value(&refusal).unwrap();
    json["reason"] = json!("line one\nline two");
    assert!(refused::<Refusal>(json.clone()).contains("hazardous"));
    json["reason"] = json!("");
    assert!(refused::<Refusal>(json.clone()).contains("empty"));
    json["reason"] = json!("fine");
    assert_eq!(
        serde_json::from_value::<Refusal>(json.clone())
            .unwrap()
            .remedy_text()
            .as_str(),
        Remedy::UpdateYougori.to_string()
    );
    json["remedy_text"] = json!("nothing to do");
    assert!(refused::<Refusal>(json.clone()).contains("remedy's own words"));
    json["remedy_text"] = json!(Remedy::UpdateYougori.to_string());
    json["severity"] = json!("info");
    assert!(refused::<Refusal>(json).contains("unknown field"));
    let unit_remedy = refused::<Remedy>(json!({"remedy": "free_memory", "now": true}));
    assert!(unit_remedy.contains("unknown field"), "{unit_remedy}");
}
