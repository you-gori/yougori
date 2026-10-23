//! Protected bindings contain references in project/runtime metadata, never values.
use serde_json::{json, Value};
use std::collections::BTreeMap;
const SERVICE: &str = "Yougori.DeploymentSecrets.v1";
fn entry(name: &str) -> Result<keyring::Entry, String> {
    if !yougori_cli::workload::identifier(name) { return Err("Use a secret reference with 1–80 letters, digits, dots, dashes or underscores".into()); }
    keyring::Entry::new(SERVICE, name).map_err(|_| "Cannot open the OS credential vault".into())
}
pub(crate) fn store(name: &str, value: &str) -> Result<(), String> {
    // Env-file records are one line. JSON/PEM credentials belong in protected guest files instead.
    validate_value(value)?;
    entry(name)?.set_password(value).map_err(|_| "Cannot save the deployment secret in the OS credential vault".into())
}
fn validate_value(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 65536 || value.contains(['\0', '\r', '\n']) {
        return Err("A deployment environment secret must be a nonempty single line up to 64 KiB".into());
    }
    Ok(())
}
/// The byte door of the same store, for Grid Core's credential broker.
///
/// This is one credential vault with two doors on it, and on Windows they do not agree: the text
/// door above stores the UTF-16 of a value, so bytes read back from something written that way
/// are not the value's UTF-8. Whatever goes in through here comes back out through here
/// unchanged, on every platform, which is what lets the broker fingerprint what it read and know
/// it has the value the grid recorded. The two doors are never mixed on one entry; Grid Core's
/// entries are the ones named `grid-core.`, and `crate::core_vault` is the only caller.
///
/// Windows keeps a credential blob to 2560 bytes, so a long value belongs in a protected guest
/// file rather than here, the same as a multi-line one does.
pub(crate) fn store_bytes(name: &str, bytes: &[u8]) -> Result<(), String> {
    entry(name)?.set_secret(bytes).map_err(|_| "Cannot save that value in the OS credential vault".into())
}

/// Reads the bytes of one entry back, exactly as they were written, or nothing at all when there
/// is no such entry. What the bytes mean is the caller's to decide; nothing here looks at them.
///
/// An entry that is not there is told apart from a vault that would not answer, because the two
/// mean different things to whoever is waiting: one is something to go and store, the other is
/// something wrong with this computer.
pub(crate) fn resolve_bytes(name: &str) -> Result<Option<Vec<u8>>, String> {
    match entry(name)?.get_secret() {
        Ok(bytes) => Ok(Some(bytes)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(_) => Err(format!("The OS credential vault would not give this computer the entry '{name}'")),
    }
}

/// Takes one entry out. An entry that is already gone is not an error: the point is that it is
/// not there afterwards.
pub(crate) fn forget(name: &str) -> Result<(), String> {
    match entry(name)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(_) => Err("Cannot remove that value from the OS credential vault".into()),
    }
}

/// What the vault said about one entry, through the text door.
///
/// [`resolve`] below flattens all three into one error, which is right for a deployment secret
/// somebody has to go and store, and wrong everywhere the answer decides something destructive.
/// The grids' hub keys and memberships are the cases: "it is not there" means delete the grid or
/// join again, and the vault is routinely not ready at all while a computer is still starting, so
/// reading one as the other tells somebody to destroy what is merely not readable yet.
pub(crate) enum Secret {
    Found(String),
    /// The vault answered, and says it has no such entry.
    Absent,
    /// The vault could not be asked, would not answer, or gave back something unusable. Nothing
    /// is decided: ask again.
    Unavailable,
}

/// One entry, telling absence apart from a vault that would not answer. A stored value that is
/// no longer usable counts as `Unavailable` rather than `Absent`: it will not heal, but it is not
/// evidence that the entry was never there, and every caller of this treats absence as licence to
/// destroy something.
pub(crate) fn look_up(name: &str) -> Secret {
    let Ok(entry) = entry(name) else { return Secret::Unavailable };
    match entry.get_password() {
        Ok(value) if validate_value(&value).is_ok() => Secret::Found(value),
        Ok(_) => Secret::Unavailable,
        Err(keyring::Error::NoEntry) => Secret::Absent,
        Err(_) => Secret::Unavailable,
    }
}

/// What a grid can do about the two keys its hub needs.
pub(crate) enum Keys {
    Ready(String, String),
    /// Both doors answered and the keys are not there. Re-creating the grid is the way out.
    Gone,
    /// The vault could not be asked. Say so, change nothing, and look again.
    NotYet,
}

/// The rule all three hubs share. An unreadable answer outranks a missing one: if either key
/// could not be read, the pair is not known to be gone, and saying it is gone tells somebody to
/// delete a grid whose keys are sitting there intact.
pub(crate) fn hub_keys(key: Secret, password: Secret) -> Keys {
    match (key, password) {
        (Secret::Unavailable, _) | (_, Secret::Unavailable) => Keys::NotYet,
        (Secret::Absent, _) | (_, Secret::Absent) => Keys::Gone,
        (Secret::Found(key), Secret::Found(password)) => Keys::Ready(key, password),
    }
}

/// What reading a computer's grid membership told us: the record on disk and the token in the
/// vault can fail independently, and only one of the outcomes is final enough to act on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum MemberLoad {
    /// No membership record: this computer is genuinely not in a grid.
    Absent,
    /// Read, parsed, and opened.
    Loaded,
    /// The record is there and cannot be understood.
    Damaged,
    /// The record parsed, but no membership could be built from what it held.
    Incomplete,
    /// This computer could not look. Ordinary while it is still starting.
    NotYet,
}

impl MemberLoad {
    /// Whether this outcome is final. Anything else is read again on the next call, instead of
    /// being latched for the rest of the run.
    pub(crate) fn settled(self) -> bool {
        !matches!(self, MemberLoad::NotYet)
    }

    /// What to tell somebody, in the grid's own words. `NotYet` never says "join again": joining
    /// again starts a new membership whose orders do not name what this computer already hosts,
    /// and everything it hosts is then deleted with its data. The two that do say it are the two
    /// where it is genuinely the way out.
    pub(crate) fn message(self, subject: &str, password: &str) -> Option<String> {
        match self {
            MemberLoad::Absent | MemberLoad::Loaded => None,
            MemberLoad::Damaged => Some(format!("This computer's {subject} is damaged; join again with the {password}")),
            MemberLoad::Incomplete => Some(format!("This computer's {subject} is incomplete; join again with the {password}")),
            MemberLoad::NotYet => Some(format!(
                "This computer's {subject} could not be read yet, so nothing about it is decided. Yougori keeps trying, and what this computer hosts is left exactly as it is."
            )),
        }
    }
}

pub(crate) fn resolve(name: &str) -> Result<String, String> {
    let value=entry(name)?.get_password().map_err(|_| format!("YOUGORI_SECRET_UNAVAILABLE: deployment secret '{name}' is unavailable in the OS credential vault; store it before applying or starting this deployment"))?;
    validate_value(&value).map_err(|_|format!("YOUGORI_SECRET_INVALID: deployment secret '{name}' must be a nonempty single line up to 64 KiB; its value was withheld"))?;
    Ok(value)
}
pub(crate) fn inject(value: &mut Value, bindings: &BTreeMap<String,String>) -> Result<(), String> { inject_with(value, bindings, resolve) }
fn inject_with(value: &mut Value, bindings: &BTreeMap<String,String>, get: impl Fn(&str)->Result<String,String>) -> Result<(), String> {
    let mut protected = BTreeMap::new();
    for (variable, reference) in bindings { protected.insert(variable, get(reference)?); }
    // Guest receives these separately and uses a 0600 env file, never --env KEY=value argv.
    value["protectedEnvironment"] = json!(protected);
    value.as_object_mut().ok_or("Invalid workload options")?.remove("secretEnvironment");
    Ok(())
}
pub(crate) fn variable(options: &yougori_cli::workload::Options, name: &str) -> Result<String,String> {
    if let Some(reference) = options.secret_environment.get(name) { return resolve(reference) }
    options.environment.get(name).cloned().ok_or("This workload has no such secret binding".into())
}

#[tauri::command]
pub fn set_deployment_secret(name: String, value: String,window:crate::WebviewWindow) -> Result<Value,String> {
    if window.label()!="main"{return Err("Configure deployment secrets from the main Yougori window or its same-user CLI".into())}
    set_secret(&name,&value)
}
pub(crate) fn set_secret(name:&str,value:&str)->Result<Value,String>{
    store(&name, &value)?;
    Ok(json!({"reference":name,"stored":true,"storage":"OS credential vault","valueReturned":false}))
}
#[tauri::command]
pub fn delete_deployment_secret(name: String,window:crate::WebviewWindow) -> Result<Value,String> {
    if window.label()!="main"{return Err("Configure deployment secrets from the main Yougori window or its same-user CLI".into())}
    delete_secret(&name)
}
pub(crate) fn delete_secret(name:&str)->Result<Value,String>{
    match entry(&name)?.delete_credential() { Ok(()) | Err(keyring::Error::NoEntry) => {}, Err(_) => return Err("Cannot remove the deployment secret from the OS credential vault".into()) }
    Ok(json!({"reference":name,"deleted":true}))
}

#[cfg(test)] mod destructive_advice_tests {
    use super::*;

    #[test]
    fn a_vault_that_would_not_answer_never_says_the_grid_can_be_deleted() {
        // The vault is routinely not ready while a computer is still starting. Reading that as
        // "the keys are missing" put "delete the grid and create it again" on screen in all
        // three grids, over keys that were sitting there intact.
        assert!(matches!(hub_keys(Secret::Unavailable, Secret::Unavailable), Keys::NotYet));
        // One readable key is not enough to call the pair gone, in either order.
        assert!(matches!(hub_keys(Secret::Found("k".into()), Secret::Unavailable), Keys::NotYet));
        assert!(matches!(hub_keys(Secret::Unavailable, Secret::Found("p".into())), Keys::NotYet));
        // Unreadable outranks absent: one door saying "not there" while the other could not be
        // asked at all decides nothing.
        assert!(matches!(hub_keys(Secret::Absent, Secret::Unavailable), Keys::NotYet));
        assert!(matches!(hub_keys(Secret::Unavailable, Secret::Absent), Keys::NotYet));

        // Both doors answered and the keys are gone: re-creating really is the way out.
        assert!(matches!(hub_keys(Secret::Absent, Secret::Absent), Keys::Gone));
        assert!(matches!(hub_keys(Secret::Found("k".into()), Secret::Absent), Keys::Gone));
        assert!(matches!(hub_keys(Secret::Absent, Secret::Found("p".into())), Keys::Gone));

        match hub_keys(Secret::Found("k".into()), Secret::Found("p".into())) {
            Keys::Ready(key, password) => assert_eq!((key.as_str(), password.as_str()), ("k", "p")),
            _ => panic!("two readable keys start the hub"),
        }
    }

    #[test]
    fn a_membership_that_could_not_be_read_is_read_again_and_never_says_join_again() {
        assert!(!MemberLoad::NotYet.settled(), "a read that failed must be tried again");
        for outcome in [MemberLoad::Absent, MemberLoad::Loaded, MemberLoad::Damaged, MemberLoad::Incomplete] {
            assert!(outcome.settled(), "{outcome:?} cannot read differently on a retry");
        }

        // Both grids' wordings, since the rule is shared and the sentences are not.
        for (subject, password) in [("sandbox grid membership", "password"), ("grid membership", "company password")] {
            let waiting = MemberLoad::NotYet.message(subject, password).expect("it has to say something");
            assert!(!waiting.contains("join again"), "never send somebody to re-join over a read that failed: {waiting}");
            assert!(waiting.contains("left exactly as it is"), "say what is hosted is untouched: {waiting}");
            // Re-joining really is the way out of these two, so they are allowed to say it.
            for broken in [MemberLoad::Damaged, MemberLoad::Incomplete] {
                let said = broken.message(subject, password).expect("it has to say something");
                assert!(said.contains("join again with the") && said.contains(password), "{broken:?}: {said}");
            }
            assert!(MemberLoad::Absent.message(subject, password).is_none());
            assert!(MemberLoad::Loaded.message(subject, password).is_none());
        }
    }
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn invalid_protected_values_cannot_inject_environment_records_or_http_headers() {
        for value in ["".to_owned(), "private\r\nAuthorization: injected".into(), "private\nOTHER=injected".into(), "private\0suffix".into(), "x".repeat(65537)] {
            let error=validate_value(&value).unwrap_err();
            assert!(!error.contains("private"));
        }
        assert!(validate_value("literal '$VALUE' = credential").is_ok());
    }
    #[test] fn bindings_do_not_persist_values_or_return_them_in_metadata() {
        let options: yougori_cli::workload::Options = serde_json::from_value(json!({"secretEnvironment":{"API_KEY":"company-api"}})).unwrap();
        assert!(!serde_json::to_string(&options).unwrap().contains("top-secret"));
        let mut wire=serde_json::to_value(&options).unwrap();
        inject_with(&mut wire, &options.secret_environment, |_| Ok("top-secret".into())).unwrap();
        assert!(wire.get("secretEnvironment").is_none());
        assert_eq!(wire["protectedEnvironment"]["API_KEY"], "top-secret");
        assert!(wire["environment"].get("API_KEY").is_none());
    }
}
