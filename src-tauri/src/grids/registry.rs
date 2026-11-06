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
///
/// Nothing when what it does is not one of the four. That is not a grid this build knows how to
/// talk to, and sending it to a product chosen for it would act on the wrong grid: the caller
/// refuses instead (`product_or_refuse`).
pub fn product_of(grid: &Named) -> Option<Product> {
    Product::all().iter().copied().find(|product| grid.does.contains(&product.capability().word().to_owned()))
}

/// `product_of`, with the refusal a command gets when a grid says it does something this build
/// has never heard of, which is what a grid from a newer Yougori looks like from here.
pub fn product_or_refuse(grid: &Named) -> Result<Product, Fault> {
    product_of(grid).ok_or_else(|| {
        Fault::new(
            Code::GridRefused,
            format!(
                "{} is a kind of grid this version of Yougori does not know ({}). Update Yougori to use it; nothing was changed.",
                grid.name,
                yougori_cli::grids::join_words(&grid.does.iter().map(String::as_str).collect::<Vec<_>>())
            ),
        )
        .about(&grid.name)
    })
}

fn status_method(product: Product) -> &'static str {
    match product {
        Product::Neo => "grid_status",
        Product::Desks => "desks_status",
        Product::Access => "access_status",
        Product::Bounty => "bounty_status",
    }
}

/// One product's status read into one entry per grid it holds.
///
/// Three of the products can hold several grids on one computer and say so by listing each
/// instance; each has an expander in the CLI crate, and all three read alike. Swarm Mining keeps
/// one private project per computer until M11, so its status is one grid as it always was. An
/// answer from a build before any of this is one grid too, which is what the expanders return
/// when a status lists no instances.
fn each_grid(product: Product, status: &Value) -> Vec<Value> {
    use yougori_cli::grids::alias;
    match product {
        Product::Neo => alias::each_neo_grid(status),
        Product::Desks => alias::each_desks_grid(status),
        Product::Access => alias::each_access_grid(status),
        Product::Bounty => vec![status.clone()],
    }
}

/// Every grid this computer runs or belongs to, each one named apart: a computer may run several
/// hubs of a kind and belong to several grids of a kind.
///
/// A product that cannot answer at all is left out rather than reported as a grid that is
/// broken: nothing here is a reason to stop the others being listed.
pub async fn grids(app: &AppHandle) -> Vec<Named> {
    let mut answers = Vec::new();
    for product in Product::all() {
        if let Ok(status) = dispatch::dispatch(app, status_method(*product), &serde_json::json!({})).await {
            answers.push((*product, status));
        }
    }
    read_all(&answers)
}

/// The statuses the four products answered, read into one list. Apart from asking them, this is
/// the whole of `grids`, so it is what the tests drive.
pub(crate) fn read_all(answers: &[(Product, Value)]) -> Vec<Named> {
    let mut found: Vec<Named> = answers
        .iter()
        .flat_map(|(product, status)| each_grid(*product, status).into_iter().filter_map(|grid| named(*product, &grid)))
        .collect();
    tell_apart(&mut found);
    found
}

/// Gives every grid a handle of its own, so `--grid NAME` can name one.
///
/// Two grids slug the same whenever two companies are called the same thing, which two grids of
/// one product now can be. The product's word separates grids of different kinds; past that, the
/// grid's own id does, because it is the one thing no two grids share.
fn tell_apart(found: &mut [Named]) {
    let slugs: Vec<String> = found.iter().map(|grid| grid.handle.clone()).collect();
    for index in 0..found.len() {
        if !slugs.iter().enumerate().any(|(other, slug)| other != index && *slug == slugs[index]) {
            continue;
        }
        let product = product_of(&found[index]).map(Product::handle).unwrap_or("grid");
        found[index].handle = format!("{}-{product}", slugs[index]);
    }
    // Same company name, same product: the ids tell them apart, and every grid has one.
    let paired: Vec<String> = found.iter().map(|grid| grid.handle.clone()).collect();
    for index in 0..found.len() {
        if paired.iter().enumerate().any(|(other, handle)| other != index && *handle == paired[index]) {
            found[index].handle = handle(&found[index].id, &paired[index]);
        }
    }
}

/// Which grid a command is about.
///
/// Naming one is optional when exactly one grid on this computer can answer the question. When
/// more than one could, the refusal names them, because guessing would change the wrong grid.
pub async fn find(app: &AppHandle, wanted: Option<&str>, needs: &[Capability]) -> Result<Named, Fault> {
    choose(grids(app).await, wanted, needs)
}

/// `find`, over grids already read. Apart from reading them, this is the whole of it.
pub(crate) fn choose(all: Vec<Named>, wanted: Option<&str>, needs: &[Capability]) -> Result<Named, Fault> {
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
