//! Several Sandbox Grids on one computer.
//!
//! A computer can host one grid, belong to another and have its person signed in to a third. Each
//! of those lives in an instance. The one that existed before there could be several is `default`:
//! its files stay exactly where they always were (`grid/desks-hub.json`, `grid/desks-member.json`,
//! `grid/desk-login.json`, …), its vault entries keep their names (`yougori-desks-hub-key`, …) and
//! its hub keeps ports 7463 and 7464, so an installation from before reads and writes nothing new.
//! Every later instance is `i-` and eight hex digits: its files sit in `grid/desks/<instance>/`
//! under the same names, its vault entries end in `-<instance>`, and its ports are allocated when
//! its hub is made and kept in its hub record.
//!
//! Nothing here touches the engine: the paths, names and choices are worked out from plain data,
//! so they can be tested on a temporary folder without a running app or the OS vault.
use std::path::{Path, PathBuf};

/// The instance that predates several (`default`), whether `text` is an instance key (`default`,
/// or `i-` and eight lowercase hex digits), and an instance's vault name (the old name for
/// `default`, `<name>-<instance>` otherwise): the same rules for every grid product.
pub(crate) use crate::grid::instances::{is_key, vault_name, DEFAULT};

/// A key no instance in `taken` has.
pub(crate) fn new_key(taken: &[String]) -> String {
    loop {
        let key = crate::grid::instances::new_key();
        if !taken.contains(&key) {
            return key;
        }
    }
}

/// Where an instance's files live: the grid folder itself for `default`, `grid/desks/<instance>`
/// for every other one. `grid` is the engine's `grid` data folder.
pub(crate) fn folder(grid: &Path, instance: &str) -> PathBuf {
    if instance == DEFAULT {
        grid.to_owned()
    } else {
        grid.join("desks").join(instance)
    }
}

/// How an instance's files are named inside its folder. The same names for every instance.
pub(crate) const HUB: &str = "desks-hub.json";
pub(crate) const MEMBER: &str = "desks-member.json";
pub(crate) const TUNNEL: &str = "desks-tunnel.json";
pub(crate) const DELETED: &str = "desks-hub.deleted";
pub(crate) const HOSTED: &str = "desks.json";
pub(crate) const LOGIN: &str = "desk-login.json";
pub(crate) const PARCELS: &str = "desk-parcels.json";
pub(crate) const CLOUD: &str = "cloud-computers.json";

/// Every instance with something on disk: `default` always, first, then each `grid/desks/i-…`
/// folder in key order. A folder whose name is not a key is not an instance and is left alone.
pub(crate) fn on_disk(grid: &Path) -> Vec<String> {
    let mut found = vec![DEFAULT.to_owned()];
    let mut others: Vec<String> = std::fs::read_dir(grid.join("desks"))
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| entry.path().is_dir())
        .filter_map(|entry| entry.file_name().to_str().map(str::to_owned))
        .filter(|name| name != DEFAULT && is_key(name))
        .collect();
    others.sort();
    found.extend(others);
    found
}

/// Removes an instance's folder once nothing of it is left. Only empty folders go: anything a
/// person might still need (a move's leftovers, an image) keeps the folder where it is.
pub(crate) fn tidy(grid: &Path, instance: &str) {
    if instance == DEFAULT {
        return;
    }
    let folder = folder(grid, instance);
    for empty in ["moving", "incoming"] {
        let _ = std::fs::remove_dir(folder.join(empty));
    }
    let _ = std::fs::remove_dir(&folder);
}

/// What one role of an instance is part of: the grid's id and name, and its hub's fingerprint
/// when it is known (a hub here, or a membership).
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Grid {
    pub id: String,
    pub name: String,
    pub fingerprint: Option<String>,
}

/// What an instance holds: the hub it runs, the grid it is a member of, and the grid its person
/// is signed in to. Usually all one grid; the `default` instance may hold three different ones,
/// as it always could.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Seen {
    pub instance: String,
    pub hub: Option<Grid>,
    pub member: Option<Grid>,
    pub login: Option<Grid>,
}

impl Seen {
    fn holds(&self, role: Role) -> Option<&Grid> {
        match role {
            Role::Hub => self.hub.as_ref(),
            Role::Member => self.member.as_ref(),
            Role::Login => self.login.as_ref(),
        }
    }

    fn roles(&self) -> impl Iterator<Item = &Grid> {
        [&self.hub, &self.member, &self.login].into_iter().flatten()
    }
}

/// What a command needs the instance it acts on to have.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Role {
    Hub,
    Member,
    Login,
}

pub(crate) const ANY: &[Role] = &[Role::Hub, Role::Member, Role::Login];

/// How a grid is named in a refusal: its name and the id to give as gridId.
fn label(seen: &Seen, roles: &[Role]) -> String {
    let grid = roles.iter().find_map(|role| seen.holds(*role)).or_else(|| seen.roles().next());
    match grid {
        Some(grid) if grid.name.is_empty() => grid.id.clone(),
        Some(grid) => format!("{} ({})", grid.name, grid.id),
        None => seen.instance.clone(),
    }
}

/// Which instance a command acts on.
///
/// `wanted` is the gridId the command was given: a grid's id as status reports it, an instance
/// key, or a grid's name. Without one, the only instance that can answer is chosen, and with none
/// that can, `default`, so the command answers exactly as it did before there could be several.
/// With several that could, nothing is guessed: guessing would change the wrong grid.
pub(crate) fn choose(seen: &[Seen], wanted: Option<&str>, roles: &[Role]) -> Result<String, String> {
    let holders: Vec<&Seen> = seen.iter().filter(|seen| roles.iter().any(|role| seen.holds(*role).is_some())).collect();
    let Some(wanted) = wanted.map(str::trim).filter(|wanted| !wanted.is_empty()) else {
        return match holders.as_slice() {
            [] => Ok(DEFAULT.to_owned()),
            [only] => Ok(only.instance.clone()),
            several => Err(format!(
                "There are {} Sandbox Grids on this computer: {}. Say which with gridId.",
                several.len(),
                several.iter().map(|seen| label(seen, roles)).collect::<Vec<_>>().join(", ")
            )),
        };
    };
    if is_key(wanted) {
        return seen.iter().find(|seen| seen.instance == wanted).map(|seen| seen.instance.clone()).ok_or_else(|| missing(wanted));
    }
    // By id first, then by name. An instance holding the grid in a role this command needs is
    // the one meant; another holding the same grid in another role is only a fallback.
    let by_id = |grid: &Grid| grid.id == wanted;
    let by_name = |grid: &Grid| grid.name.eq_ignore_ascii_case(wanted);
    let tests: [&dyn Fn(&Grid) -> bool; 2] = [&by_id, &by_name];
    for matches in tests {
        let fitting: Vec<&Seen> = seen.iter().filter(|seen| roles.iter().any(|role| seen.holds(*role).is_some_and(|grid| matches(grid)))).collect();
        let fitting = if fitting.is_empty() { seen.iter().filter(|seen| seen.roles().any(|grid| matches(grid))).collect() } else { fitting };
        match fitting.as_slice() {
            [] => continue,
            [only] => return Ok(only.instance.clone()),
            several => {
                return Err(format!(
                    "{} Sandbox Grids on this computer answer to {wanted} ({}). Say which with gridId set to one of these.",
                    several.len(),
                    several.iter().map(|seen| seen.instance.as_str()).collect::<Vec<_>>().join(", ")
                ))
            }
        }
    }
    Err(missing(wanted))
}

fn missing(wanted: &str) -> String {
    format!("No Sandbox Grid on this computer has the id {wanted}. `yougori desks status` lists each one with its gridId.")
}

/// Where a new hub goes: `default` while it is free (no hub, no hub settings and no membership
/// there, as before), otherwise a new instance.
pub(crate) fn for_new_hub(default_free: bool) -> Option<String> {
    default_free.then(|| DEFAULT.to_owned())
}

/// What joining a grid by its invite does on this computer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Joining {
    /// This computer is already in that grid: the same hub, reached another way. The membership
    /// moves to the new address; there is never a second membership in one grid.
    Readdress(String),
    /// Join into this instance.
    Join(String),
    /// Join into a new instance.
    New,
}

/// Where joining the grid whose hub shows `fingerprint` goes. A membership of the same grid is
/// readdressed; a hub of that grid here (whose own computer left it) takes it back; `default`
/// takes it while it has no membership, as it always did; anything else is a new instance.
pub(crate) fn for_join(seen: &[Seen], fingerprint: &str) -> Joining {
    if let Some(seen) = seen.iter().find(|seen| seen.member.as_ref().is_some_and(|grid| grid.fingerprint.as_deref() == Some(fingerprint))) {
        return Joining::Readdress(seen.instance.clone());
    }
    if let Some(seen) = seen.iter().find(|seen| seen.member.is_none() && seen.hub.as_ref().is_some_and(|grid| grid.fingerprint.as_deref() == Some(fingerprint))) {
        return Joining::Join(seen.instance.clone());
    }
    if seen.iter().find(|seen| seen.instance == DEFAULT).is_none_or(|default| default.member.is_none()) {
        return Joining::Join(DEFAULT.to_owned());
    }
    Joining::New
}

/// Where a membership the hub made ahead of time goes. One for a grid this computer is already
/// in is refused, as it always was.
pub(crate) fn for_adopt(seen: &[Seen], fingerprint: &str, grid_id: Option<&str>) -> Result<Option<String>, String> {
    let same = |grid: &Grid| grid.fingerprint.as_deref() == Some(fingerprint) || grid_id.is_some_and(|id| grid.id == id);
    if let Some(grid) = seen.iter().filter_map(|seen| seen.member.as_ref()).find(|grid| same(grid)) {
        return Err(format!("This computer is already in {}'s sandbox grid", grid.name));
    }
    let default_free = seen.iter().find(|seen| seen.instance == DEFAULT).is_none_or(|default| default.member.is_none());
    Ok(default_free.then(|| DEFAULT.to_owned()))
}

/// Where a person's sign-in to `grid_id` goes: over their earlier sign-in to the same grid (a
/// changed account or a fresh session, as before); beside this computer's hub or membership of
/// that grid; into `default` while it has no sign-in; otherwise a new instance.
pub(crate) fn for_login(seen: &[Seen], grid_id: &str) -> Option<String> {
    if let Some(seen) = seen.iter().find(|seen| seen.login.as_ref().is_some_and(|grid| grid.id == grid_id)) {
        return Some(seen.instance.clone());
    }
    let same_grid = |grid: &Option<Grid>| grid.as_ref().is_some_and(|grid| grid.id == grid_id);
    if let Some(seen) = seen.iter().find(|seen| seen.login.is_none() && (same_grid(&seen.member) || same_grid(&seen.hub))) {
        return Some(seen.instance.clone());
    }
    let default_free = seen.iter().find(|seen| seen.instance == DEFAULT).is_none_or(|default| default.login.is_none());
    default_free.then(|| DEFAULT.to_owned())
}

/// How a sandbox that is a grid's desk is described. `grid` is the grid's id for every instance
/// but `default`, whose desks keep the description they have always had: a sandbox described the
/// old way belongs to `default`.
pub(crate) fn desk_tag(desk: &str, person: &str, grid: Option<&str>) -> String {
    let head = match grid {
        Some(grid) => format!("Grid desk {desk} [{grid}]"),
        None => format!("Grid desk {desk}"),
    };
    if person.is_empty() { head } else { format!("{head} · {person}") }
}

/// The desk a sandbox's description names, and the grid it names if any (`None` for a desk
/// described the old way, which is `default`'s).
pub(crate) fn desk_of(description: &str) -> Option<(&str, Option<&str>)> {
    let head = description.strip_prefix("Grid desk ")?.split(" · ").next()?.trim();
    let (desk, grid) = match head.strip_suffix(']').and_then(|rest| rest.rsplit_once(" [")) {
        Some((desk, grid)) if !grid.is_empty() && !grid.contains(' ') => (desk.trim(), Some(grid)),
        _ => (head, None),
    };
    // A desk's id is one word and never carries a bracket: without that last check, a description
    // whose desk id is empty (`Grid desk  [grid-b]`) read the grid's own tag back as the desk, and
    // the grid would then hold a desk that does not exist.
    let named = !desk.is_empty() && !desk.contains([' ', '[', ']']);
    named.then_some((desk, grid))
}

/// Whether a sandbox described as `description` is a desk of the grid whose tag is `grid`
/// (`None` for `default`).
pub(crate) fn tagged_for(description: &str, grid: Option<&str>) -> Option<String> {
    let (desk, tagged) = desk_of(description)?;
    (tagged == grid).then(|| desk.to_owned())
}

/// How a sandbox kept after leaving a grid is described: it was a desk and is now its owner's.
pub(crate) const RELEASED_DESK: &str = "Kept from grid desk ";

/// What a sandbox described as `description` is called once the grid tagged `grid` lets it go,
/// or `None` when it is not one of that grid's desks and is left exactly as it is.
pub(crate) fn released(description: &str, grid: Option<&str>) -> Option<String> {
    tagged_for(description, grid)?;
    description.strip_prefix("Grid desk ").map(|rest| format!("{RELEASED_DESK}{rest}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grid(id: &str, name: &str, fingerprint: &str) -> Option<Grid> {
        Some(Grid { id: id.into(), name: name.into(), fingerprint: Some(fingerprint.into()) })
    }

    #[test]
    fn instance_keys_are_default_or_eight_hex_digits() {
        assert!(is_key("default"));
        assert!(is_key("i-0a1b2c3d"));
        for bad in ["", "i-", "i-0A1B2C3D", "i-0a1b2c3", "i-0a1b2c3d4", "x-0a1b2c3d", "i-0a1b2c3g", "../i-0a1b"] {
            assert!(!is_key(bad), "{bad}");
        }
        let key = new_key(&[]);
        assert!(is_key(&key) && key != DEFAULT, "{key}");
        assert_ne!(new_key(&[key.clone()]), key);
    }

    #[test]
    fn the_default_instance_keeps_every_old_file_and_vault_name() {
        let grid = Path::new("data").join("grid");
        assert_eq!(folder(&grid, DEFAULT), grid);
        for (file, old) in [(HUB, "desks-hub.json"), (MEMBER, "desks-member.json"), (TUNNEL, "desks-tunnel.json"), (DELETED, "desks-hub.deleted"), (HOSTED, "desks.json"), (LOGIN, "desk-login.json"), (PARCELS, "desk-parcels.json"), (CLOUD, "cloud-computers.json")] {
            assert_eq!(folder(&grid, DEFAULT).join(file), grid.join(old));
        }
        for name in ["yougori-desks-hub-key", "yougori-desks-hub-password", "yougori-desks-member-token", "yougori-desks-parking", "yougori-desks-connection-connection-0123456789abcdef", "yougori-desks-person-session", "yougori-grid-desk-invite"] {
            assert_eq!(vault_name(name, DEFAULT), name);
        }
    }

    #[test]
    fn a_new_instance_has_a_folder_and_vault_names_of_its_own() {
        let grid = Path::new("data").join("grid");
        let (one, two) = ("i-0000000a", "i-0000000b");
        assert_eq!(folder(&grid, one), grid.join("desks").join(one));
        assert_ne!(folder(&grid, one).join(HUB), folder(&grid, two).join(HUB));
        assert_ne!(folder(&grid, one).join(HUB), folder(&grid, DEFAULT).join(HUB));
        assert_eq!(vault_name("yougori-desks-hub-key", one), "yougori-desks-hub-key-i-0000000a");
        assert_ne!(vault_name("yougori-desks-hub-key", one), vault_name("yougori-desks-hub-key", two));
        // The longest name still fits the vault's 80 characters.
        let longest = vault_name("yougori-desks-connection-connection-0123456789abcdef", one);
        assert!(yougori_cli::workload::identifier(&longest), "{longest}");
    }

    #[test]
    fn every_instance_on_disk_is_found_and_default_is_always_there() {
        let root = tempfile::tempdir().unwrap();
        let grid = root.path().join("grid");
        assert_eq!(on_disk(&grid), vec![DEFAULT.to_owned()], "nothing on disk yet: the old layout still answers");
        for name in ["i-0000000b", "i-0000000a", "not-an-instance", "default"] {
            std::fs::create_dir_all(grid.join("desks").join(name)).unwrap();
        }
        std::fs::write(grid.join("desks").join("i-0000000c"), b"a file, not a folder").unwrap();
        assert_eq!(on_disk(&grid), vec![DEFAULT.to_owned(), "i-0000000a".into(), "i-0000000b".into()]);
        // Tidying removes only an empty folder.
        std::fs::write(folder(&grid, "i-0000000b").join(LOGIN), b"{}").unwrap();
        tidy(&grid, "i-0000000a");
        tidy(&grid, "i-0000000b");
        tidy(&grid, DEFAULT);
        assert_eq!(on_disk(&grid), vec![DEFAULT.to_owned(), "i-0000000b".into()]);
        assert!(grid.is_dir());
    }

    fn census() -> Vec<Seen> {
        vec![
            Seen { instance: DEFAULT.into(), hub: grid("grid-aaa", "Acme", "AA"), member: grid("grid-aaa", "Acme", "AA"), login: None },
            Seen { instance: "i-0000000b".into(), hub: None, member: grid("grid-bbb", "Beta", "BB"), login: grid("grid-bbb", "Beta", "BB") },
        ]
    }

    #[test]
    fn a_command_without_a_grid_id_acts_on_the_only_grid_and_refuses_when_there_are_several() {
        // Nothing anywhere: default, so the command answers as it always did.
        assert_eq!(choose(&[Seen { instance: DEFAULT.into(), ..Default::default() }], None, &[Role::Hub]).unwrap(), DEFAULT);
        assert_eq!(choose(&[], None, ANY).unwrap(), DEFAULT);
        let seen = census();
        // One hub, one sign-in: each defaults to the only one that can answer.
        assert_eq!(choose(&seen, None, &[Role::Hub]).unwrap(), DEFAULT);
        assert_eq!(choose(&seen, None, &[Role::Login]).unwrap(), "i-0000000b");
        // Two memberships: refused in words that name both and say how to choose.
        let refused = choose(&seen, None, &[Role::Member]).unwrap_err();
        assert_eq!(refused, "There are 2 Sandbox Grids on this computer: Acme (grid-aaa), Beta (grid-bbb). Say which with gridId.");
        assert!(choose(&seen, Some("  "), &[Role::Member]).is_err(), "a blank gridId is no choice at all");
    }

    #[test]
    fn a_grid_id_an_instance_key_or_a_name_picks_one_grid() {
        let seen = census();
        assert_eq!(choose(&seen, Some("grid-bbb"), &[Role::Member]).unwrap(), "i-0000000b");
        assert_eq!(choose(&seen, Some("grid-aaa"), &[Role::Member]).unwrap(), DEFAULT);
        assert_eq!(choose(&seen, Some("i-0000000b"), &[Role::Hub]).unwrap(), "i-0000000b", "the key is taken at its word; the command then says what that grid lacks");
        assert_eq!(choose(&seen, Some("default"), &[Role::Member]).unwrap(), DEFAULT);
        assert_eq!(choose(&seen, Some("beta"), &[Role::Login]).unwrap(), "i-0000000b");
        assert!(choose(&seen, Some("grid-zzz"), ANY).unwrap_err().contains("No Sandbox Grid on this computer has the id grid-zzz"));
        assert!(choose(&seen, Some("i-0000000f"), ANY).is_err());
        // The same grid in two instances in different roles: the one with the needed role wins.
        let split = vec![
            Seen { instance: DEFAULT.into(), login: grid("grid-ccc", "Cobalt", "CC"), ..Default::default() },
            Seen { instance: "i-0000000c".into(), member: grid("grid-ccc", "Cobalt", "CC"), ..Default::default() },
        ];
        assert_eq!(choose(&split, Some("grid-ccc"), &[Role::Login]).unwrap(), DEFAULT);
        assert_eq!(choose(&split, Some("grid-ccc"), &[Role::Member]).unwrap(), "i-0000000c");
        assert_eq!(choose(&split, Some("grid-ccc"), &[Role::Hub]).unwrap_err(), "2 Sandbox Grids on this computer answer to grid-ccc (default, i-0000000c). Say which with gridId set to one of these.");
    }

    #[test]
    fn a_second_hub_membership_or_sign_in_makes_a_new_instance_and_the_first_stays_put() {
        assert_eq!(for_new_hub(true).as_deref(), Some(DEFAULT));
        assert_eq!(for_new_hub(false), None);
        let empty = vec![Seen { instance: DEFAULT.into(), ..Default::default() }];
        assert_eq!(for_join(&empty, "AA"), Joining::Join(DEFAULT.into()), "the first membership goes where it always did");
        let seen = census();
        assert_eq!(for_join(&seen, "AA"), Joining::Readdress(DEFAULT.into()), "the same grid again is the same membership, never a second one");
        assert_eq!(for_join(&seen, "BB"), Joining::Readdress("i-0000000b".into()));
        assert_eq!(for_join(&seen, "CC"), Joining::New);
        // The hub's own computer left its grid, and joins it again: back beside its hub.
        let left = vec![Seen { instance: DEFAULT.into(), member: grid("grid-aaa", "Acme", "AA"), ..Default::default() }, Seen { instance: "i-0000000d".into(), hub: grid("grid-ddd", "Delta", "DD"), ..Default::default() }];
        assert_eq!(for_join(&left, "DD"), Joining::Join("i-0000000d".into()));

        assert_eq!(for_adopt(&empty, "AA", None).unwrap().as_deref(), Some(DEFAULT));
        assert!(for_adopt(&seen, "AA", None).unwrap_err().contains("already in Acme's sandbox grid"));
        assert!(for_adopt(&seen, "XX", Some("grid-bbb")).is_err());
        assert_eq!(for_adopt(&seen, "CC", Some("grid-ccc")).unwrap(), None);

        assert_eq!(for_login(&empty, "grid-aaa").as_deref(), Some(DEFAULT));
        assert_eq!(for_login(&seen, "grid-bbb").as_deref(), Some("i-0000000b"), "signing in to the same grid again replaces that sign-in");
        assert_eq!(for_login(&seen, "grid-aaa").as_deref(), Some(DEFAULT), "beside this computer's own hub of that grid");
        let signed_in = vec![Seen { instance: DEFAULT.into(), login: grid("grid-aaa", "Acme", "AA"), ..Default::default() }];
        assert_eq!(for_login(&signed_in, "grid-eee"), None, "a second grid's sign-in no longer replaces the first");
    }

    #[test]
    fn a_desk_is_tagged_with_its_grid_and_the_old_tag_is_defaults() {
        assert_eq!(desk_tag("desk-1", "Ada", None), "Grid desk desk-1 · Ada", "default's desks are described exactly as before");
        assert_eq!(desk_tag("desk-1", "", None), "Grid desk desk-1");
        assert_eq!(desk_tag("desk-1", "Ada", Some("grid-bbb")), "Grid desk desk-1 [grid-bbb] · Ada");
        assert_eq!(desk_of("Grid desk desk-1 · Ada"), Some(("desk-1", None)));
        assert_eq!(desk_of("Grid desk desk-2"), Some(("desk-2", None)));
        assert_eq!(desk_of("Grid desk desk-1 [grid-bbb] · Ada [the second]"), Some(("desk-1", Some("grid-bbb"))));
        assert_eq!(desk_of("Grid desk desk-1 [grid-bbb]"), Some(("desk-1", Some("grid-bbb"))));
        assert_eq!(desk_of(&format!("{RELEASED_DESK}desk-1 · Ada")), None);
        assert_eq!(desk_of("Grid desk  · Ada"), None);
        assert_eq!(desk_of("Grid desk  [grid-bbb]"), None);
    }

    #[test]
    fn leaving_one_grid_never_relabels_another_grids_desks() {
        let sandboxes = ["Grid desk desk-1 · Ada", "Grid desk desk-2 [grid-bbb] · Bo", "Grid desk desk-3 [grid-ccc]", "My own sandbox", "Kept from grid desk desk-0 · Old"];
        // Default's grid lets its desks go: only the one described the old way changes.
        let default: Vec<Option<String>> = sandboxes.iter().map(|description| released(description, None)).collect();
        assert_eq!(default, vec![Some("Kept from grid desk desk-1 · Ada".into()), None, None, None, None]);
        // The grid tagged grid-bbb lets its desks go: only its own.
        let second: Vec<Option<String>> = sandboxes.iter().map(|description| released(description, Some("grid-bbb"))).collect();
        assert_eq!(second, vec![None, Some("Kept from grid desk desk-2 [grid-bbb] · Bo".into()), None, None, None]);
        // And each grid reads back only its own desks.
        assert_eq!(sandboxes.iter().filter_map(|description| tagged_for(description, Some("grid-ccc"))).collect::<Vec<_>>(), vec!["desk-3".to_owned()]);
        assert_eq!(sandboxes.iter().filter_map(|description| tagged_for(description, None)).collect::<Vec<_>>(), vec!["desk-1".to_owned()]);
    }
}
