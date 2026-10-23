//! Which grids are on this computer, and which one a command is about.
//!
//! Nothing here starts anything. Each of the four products is asked for the status it already
//! answers, and what comes back is read into one shape so that `yougori grids list` can name all
//! four in one place for the first time.

use crate::automation::dispatch;
use serde_json::Value;
use crate::AppHandle;
use yougori_cli::grids::answer::Named;
use yougori_cli::grids::fault::{Code, Fault};
use yougori_cli::grids::{Capability, Product};

/// The short word `--grid` takes, made from the company's name.
fn handle(name: &str, fallback: &str) -> String {
    let slug: String = name
        .chars()
        .map(|character| if character.is_ascii_alphanumeric() { character.to_ascii_lowercase() } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|piece| !piece.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    if slug.is_empty() {
        fallback.to_owned()
    } else {
        slug
    }
}

pub(crate) fn named(product: Product, status: &Value) -> Option<Named> {
    // Three of the four products wrap the hub they run under `hub`. The Closed Bounty calls the
    // same thing `host`, so its own word is read rather than a shape guessed at. A product that
    // answers `"hub": null` falls through to the membership, which is why the second key is
    // reached for before either is weighed.
    let hub = status.get("hub").or_else(|| status.get("host")).filter(|hub| !hub.is_null());
    let member = status.get("member").filter(|member| !member.is_null());
    let (record, role) = match (hub, member) {
        (Some(record), _) => (record, "hub"),
        (None, Some(record)) => (record, "member"),
        (None, None) => return None,
    };
    let name = record
        .get("name")
        .or_else(|| record.get("company"))
        .or_else(|| record.get("grid"))
        .and_then(Value::as_str)
        .unwrap_or(product.product_name())
        .to_owned();
    let id = record
        .get("id")
        .or_else(|| record.get("gridId"))
        .and_then(Value::as_str)
        .unwrap_or(product.handle())
        .to_owned();
    let closing = record.get("closing").is_some_and(|closing| !closing.is_null() && closing != false);
    Some(Named {
        id,
        handle: handle(&name, product.handle()),
        name,
        kind: product.kind().to_owned(),
        does: vec![product.capability().word().to_owned()],
        lifecycle: if closing { "closing".to_owned() } else { "open".to_owned() },
        // Every grid is still served by its own product hub. This says which door answered, and
        // it will say `core` for a product on the day that product moves, not before.
        served_by: "product".to_owned(),
        role: role.to_owned(),
    })
}

/// A grid that does not exist yet, named by the words that are about to start it.
///
/// Nothing is written here and nothing is looked up: this is what `--serve` says the grid will
/// be, so that starting the first grid on a computer does not have to find a grid first.
pub(crate) fn fresh(product: Product, name: Option<&str>) -> Named {
    let name = name.map(str::trim).filter(|name| !name.is_empty()).unwrap_or(product.product_name()).to_owned();
    Named {
        id: product.handle().to_owned(),
        handle: handle(&name, product.handle()),
        name,
        kind: product.kind().to_owned(),
        does: vec![product.capability().word().to_owned()],
        lifecycle: "open".to_owned(),
        served_by: "product".to_owned(),
        role: "hub".to_owned(),
    }
}

/// Which product a grid belongs to, read back from what it does.
pub fn product_of(grid: &Named) -> Product {
    Product::all()
        .iter()
        .copied()
        .find(|product| grid.does.contains(&product.capability().word().to_owned()))
        .unwrap_or(Product::Neo)
}

fn status_method(product: Product) -> &'static str {
    match product {
        Product::Neo => "grid_status",
        Product::Desks => "desks_status",
        Product::Access => "access_status",
        Product::Bounty => "bounty_status",
    }
}

/// Every grid this computer runs or belongs to.
///
/// A product that cannot answer at all is left out rather than reported as a grid that is
/// broken: nothing here is a reason to stop the other three being listed.
pub async fn grids(app: &AppHandle) -> Vec<Named> {
    let mut found = Vec::new();
    for product in Product::all() {
        let status = dispatch::dispatch(app, status_method(*product), &serde_json::json!({})).await;
        if let Some(grid) = status.ok().as_ref().and_then(|status| named(*product, status)) {
            found.push(grid);
        }
    }
    // Two grids whose company names slug the same get their product's word to tell them apart.
    for index in 0..found.len() {
        let clash = found.iter().enumerate().any(|(other, grid)| other != index && grid.handle == found[index].handle);
        if clash {
            let product = product_of(&found[index]);
            found[index].handle = format!("{}-{}", found[index].handle, product.handle());
        }
    }
    found
}

/// Which grid a command is about.
///
/// Naming one is optional when exactly one grid on this computer can answer the question. When
/// more than one could, the refusal names them, because guessing would change the wrong grid.
pub async fn find(app: &AppHandle, wanted: Option<&str>, needs: &[Capability]) -> Result<Named, Fault> {
    let all = grids(app).await;
    if let Some(wanted) = wanted {
        let lowered = wanted.to_ascii_lowercase();
        return all
            .into_iter()
            .find(|grid| grid.handle == lowered || grid.name.to_ascii_lowercase() == lowered || grid.id == wanted)
            .ok_or_else(|| Fault::new(Code::NoSuchGrid, format!("There is no grid called {wanted} on this computer. Run yougori grids list to see the ones there are.")));
    }
    let able: Vec<Named> = all
        .into_iter()
        .filter(|grid| needs.is_empty() || needs.iter().any(|needed| grid.does.contains(&needed.word().to_owned())))
        .collect();
    match able.len() {
        1 => Ok(able.into_iter().next().expect("one grid")),
        0 if needs.is_empty() => Err(Fault::new(Code::NoSuchGrid, "This computer is not in a grid yet. Run yougori grids new to start one, or yougori grids join to join one.")),
        0 => {
            let doing: Vec<&str> = needs.iter().map(|capability| capability.doing()).collect();
            Err(Fault::new(
                Code::NoSuchGrid,
                format!("No grid on this computer can {}.", yougori_cli::grids::join_words(&doing)),
            ))
        }
        _ => {
            let names: Vec<&str> = able.iter().map(|grid| grid.name.as_str()).collect();
            Err(Fault::new(
                Code::GridNotNamed,
                format!("More than one grid could answer: {}. Say which with --grid.", yougori_cli::grids::join_words(&names)),
            ))
        }
    }
}
