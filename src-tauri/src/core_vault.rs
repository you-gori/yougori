//! The operating system's own credential vault, as Grid Core's broker asks for it.
//!
//! This is the one keeper this build can actually open, and it is deliberately thin: the layer it
//! sits on is `projects::secrets`, which this app already uses for deployment secrets and which
//! the Access Grid already uses for its hub key, its sealing key and its device tokens. That is
//! Windows Credential Manager, the macOS Keychain and the Linux Secret Service, through the
//! `keyring` crate. There is no second layer here and no second service name; Grid Core's entries
//! are the ones `core::vault::Entry::account` names, which all begin `grid-core.`, and they go
//! through the byte door while the deployment secrets beside them go through the text door.
//!
//! Three things are worth reading before the code.
//!
//! The encoding is written down rather than assumed. A credential vault is a byte store with a
//! text door beside it, and on Windows those doors disagree: the text door writes the UTF-16 of
//! the value, so a byte read of an entry written that way hands back bytes that are not the
//! value's UTF-8. They still have a length and they still look like a value, and they fingerprint
//! to something else entirely, which would refuse every send on Windows and nowhere else. So both
//! ends go through the byte door, and `core::vault::framed` writes a line in front of the value
//! saying which encoding this grid wrote. An entry written any other way is refused as damaged
//! rather than mistaken for a value.
//!
//! Nothing in the test suite opens the real vault of whoever runs it, because doing that would
//! write into a person's own Credential Manager or Keychain. That rule has not moved. What has
//! changed is that the store this sits on is a seam: `Store` is the three calls this file makes,
//! `TheOperatingSystem` is the one a shipped build uses, and the tests at the bottom put a fake
//! behind it that behaves the way each platform's store behaves, including Windows handing back
//! UTF-16 for an entry somebody wrote through the text door. So the framing and the encoding are
//! proved on both sides, through this file's own code, with nobody's real vault touched. What is
//! still not proved here is that `keyring` gives back the bytes it was given; that is what
//! `keyring` is for.
//!
//! Grid Core is not called by any shipped feature yet (see docs/grid-core/plan.md), so this is
//! here to be the real implementation behind the seam when it is.
#![allow(dead_code)]
use yougori_grid::core::vault::{framed, unframed, Entry, Held, Keeper, Trouble, Vault};

/// The byte door of a credential store, which is all of one this file uses.
///
/// It exists so the framing either side of it can be tested without writing into the real vault of
/// whoever runs the tests. There is exactly one of these in a shipped build.
pub trait Store: Send + Sync {
    /// The bytes of one entry, exactly as they were written, or nothing when there is no such
    /// entry. The two are told apart because they mean different things to whoever is waiting:
    /// one is something to go and store, the other is something wrong with this computer.
    fn read(&self, account: &str) -> Result<Option<Vec<u8>>, String>;
    fn write(&self, account: &str, bytes: &[u8]) -> Result<(), String>;
    fn forget(&self, account: &str) -> Result<(), String>;
}

/// This computer's own credential vault, through the layer the rest of the app already uses.
pub struct TheOperatingSystem;

impl Store for TheOperatingSystem {
    fn read(&self, account: &str) -> Result<Option<Vec<u8>>, String> {
        crate::projects::secrets::resolve_bytes(account)
    }
    fn write(&self, account: &str, bytes: &[u8]) -> Result<(), String> {
        crate::projects::secrets::store_bytes(account, bytes)
    }
    fn forget(&self, account: &str) -> Result<(), String> {
        crate::projects::secrets::forget(account)
    }
}

/// The operating system's credential vault, as a `Vault`.
pub struct OsVault<S = TheOperatingSystem> {
    store: S,
}

impl OsVault<TheOperatingSystem> {
    pub fn new() -> OsVault<TheOperatingSystem> {
        OsVault { store: TheOperatingSystem }
    }
}

impl Default for OsVault<TheOperatingSystem> {
    fn default() -> OsVault<TheOperatingSystem> {
        OsVault::new()
    }
}

impl<S: Store> Vault for OsVault<S> {
    fn keeper(&self) -> Keeper {
        Keeper::OperatingSystem
    }

    fn read(&self, entry: &Entry) -> Result<Held, Trouble> {
        match self.store.read(&entry.account()) {
            Ok(Some(blob)) => unframed(blob),
            Ok(None) => Err(Trouble::Missing),
            Err(_) => Err(Trouble::Refused),
        }
    }

    /// Windows keeps a credential blob to 2560 bytes, so a value longer than that cannot be put
    /// here at all and is refused rather than half written.
    fn write(&self, entry: &Entry, value: &Held) -> Result<(), Trouble> {
        let blob = framed(value);
        self.store.write(&entry.account(), blob.expose()).map_err(|_| Trouble::Refused)
    }

    fn remove(&self, entry: &Entry) -> Result<(), Trouble> {
        self.store.forget(&entry.account()).map_err(|_| Trouble::Refused)
    }

    /// Whether the store answers at all, for a status line. Asking for an entry that is not there
    /// is enough: the store either says there is no such entry, which is an answer, or it does
    /// not answer. Nothing is written to find out.
    fn reachable(&self) -> Result<(), Trouble> {
        let probe = Entry { realm_id: String::new(), vault_id: "reachable".into(), version: 1 };
        match self.read(&probe) {
            Ok(_) | Err(Trouble::Missing) | Err(Trouble::Damaged) => Ok(()),
            Err(trouble) => Err(trouble),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::HashMap,
        sync::{Mutex, MutexGuard},
    };
    use yougori_grid::core::credential::fingerprint_of;

    const SECRET: &str = "sk-live-7a\"b/c+d=0123456789abcdef";

    /// Which store is being pretended to be. The three differ in one thing that matters here:
    /// what a byte read gives back for an entry somebody wrote through the text door.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Platform {
        /// Windows Credential Manager. The text door writes the UTF-16 of the value, and a blob
        /// is at most 2560 bytes.
        Windows,
        /// The macOS Keychain. A generic password's data is bytes either way.
        Mac,
        /// The Linux Secret Service. A secret's value is bytes either way.
        Linux,
    }

    impl Platform {
        /// The bytes a byte read gives back for an entry written through the text door.
        fn as_text_door_writes(self, text: &str) -> Vec<u8> {
            match self {
                Platform::Windows => text.encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect(),
                Platform::Mac | Platform::Linux => text.as_bytes().to_vec(),
            }
        }

        /// The largest blob the store will take, or none where there is no such limit.
        fn most_bytes(self) -> Option<usize> {
            match self {
                Platform::Windows => Some(2560),
                Platform::Mac | Platform::Linux => None,
            }
        }
    }

    /// A credential store that behaves the way the operating system's does, without being one.
    ///
    /// It is here so the framing can be proved on both sides. Nothing in the test suite opens the
    /// real vault of whoever runs it, and this is what stands in for it.
    struct Fake {
        platform: Platform,
        entries: Mutex<HashMap<String, Vec<u8>>>,
        /// What a locked keychain or a store that will not answer looks like from here.
        answers: Mutex<bool>,
        reads: Mutex<usize>,
    }

    impl Fake {
        fn on(platform: Platform) -> Fake {
            Fake { platform, entries: Mutex::new(HashMap::new()), answers: Mutex::new(true), reads: Mutex::new(0) }
        }

        fn held(&self) -> MutexGuard<'_, HashMap<String, Vec<u8>>> {
            self.entries.lock().unwrap()
        }

        /// What another writer would leave behind by going through the text door of the same
        /// store, which on Windows is UTF-16 and elsewhere is UTF-8.
        fn written_through_the_text_door(&self, account: &str, text: &str) {
            self.held().insert(account.to_owned(), self.platform.as_text_door_writes(text));
        }

        fn stops_answering(&self) {
            *self.answers.lock().unwrap() = false;
        }

        fn reads(&self) -> usize {
            *self.reads.lock().unwrap()
        }
    }

    impl Store for Fake {
        fn read(&self, account: &str) -> Result<Option<Vec<u8>>, String> {
            *self.reads.lock().unwrap() += 1;
            if !*self.answers.lock().unwrap() {
                return Err("the vault would not answer".into());
            }
            Ok(self.held().get(account).cloned())
        }

        fn write(&self, account: &str, bytes: &[u8]) -> Result<(), String> {
            if !*self.answers.lock().unwrap() {
                return Err("the vault would not answer".into());
            }
            if self.platform.most_bytes().is_some_and(|most| bytes.len() > most) {
                return Err("the credential blob is too large for this store".into());
            }
            self.held().insert(account.to_owned(), bytes.to_vec());
            Ok(())
        }

        fn forget(&self, account: &str) -> Result<(), String> {
            if !*self.answers.lock().unwrap() {
                return Err("the vault would not answer".into());
            }
            self.held().remove(account);
            Ok(())
        }
    }

    fn entry(version: u32) -> Entry {
        Entry { realm_id: "realm-1".into(), vault_id: "billing-key".into(), version }
    }

    /// PROVES that a value written through this file comes back out of it unchanged on every
    /// platform, that the entry is named the one way `Entry::account` names one, and that a
    /// rotation is a different entry rather than the same one rewritten.
    ///
    /// DOES NOT PROVE that `keyring` hands back the bytes it was given. That is what `keyring` is
    /// for, and no test here opens anybody's real vault to check it.
    #[test]
    fn a_value_comes_back_out_of_each_platforms_store_exactly_as_it_went_in() {
        for platform in [Platform::Windows, Platform::Mac, Platform::Linux] {
            let vault = OsVault { store: Fake::on(platform) };
            assert_eq!(vault.keeper(), Keeper::OperatingSystem);
            assert_eq!(vault.read(&entry(1)).unwrap_err(), Trouble::Missing, "{platform:?}");

            vault.write(&entry(1), &Held::from(SECRET.as_bytes().to_vec())).unwrap();
            let back = vault.read(&entry(1)).unwrap();
            assert_eq!(back.as_text().unwrap(), SECRET, "{platform:?}");
            assert_eq!(back.fingerprint().unwrap(), fingerprint_of(SECRET), "{platform:?}");

            // What is actually in the store is the framed form, under the name the entry gives.
            let held = vault.store.held();
            let blob = held.get("grid-core.billing-key.v1").expect("the entry is named the one way an entry is named");
            assert!(blob.starts_with(b"grid-core/1\n"), "{platform:?}: {blob:?}");
            assert_eq!(&blob[12..], SECRET.as_bytes(), "{platform:?}");
            drop(held);

            // A rotation writes the next version, and the one before it is still there until it
            // is taken out on purpose.
            vault.write(&entry(2), &Held::from("sk-live-rotated".as_bytes().to_vec())).unwrap();
            assert_eq!(vault.read(&entry(1)).unwrap().as_text().unwrap(), SECRET, "{platform:?}");
            assert_eq!(vault.read(&entry(2)).unwrap().as_text().unwrap(), "sk-live-rotated", "{platform:?}");
            vault.remove(&entry(1)).unwrap();
            assert_eq!(vault.read(&entry(1)).unwrap_err(), Trouble::Missing, "{platform:?}");
            vault.remove(&entry(1)).unwrap();
        }
    }

    /// PROVES the thing the framing exists for: an entry somebody else wrote, in whatever
    /// encoding that store's text door uses, is refused as damaged rather than taken for the
    /// value. On Windows that encoding is UTF-16, which is where this would otherwise go wrong on
    /// one platform and nowhere else.
    #[test]
    fn an_entry_written_through_the_text_door_is_refused_rather_than_mistaken_for_the_value() {
        let windows = OsVault { store: Fake::on(Platform::Windows) };
        windows.store.written_through_the_text_door("grid-core.billing-key.v1", SECRET);
        {
            let held = windows.store.held();
            let blob = held.get("grid-core.billing-key.v1").unwrap();
            assert_eq!(blob.len(), SECRET.len() * 2, "Windows's text door wrote the UTF-16 of it");
            assert_ne!(blob.as_slice(), SECRET.as_bytes(), "which is not the value's UTF-8");
        }
        assert_eq!(windows.read(&entry(1)).unwrap_err(), Trouble::Damaged, "and it is refused rather than fingerprinted to something else");

        // On the other two the text door writes the same bytes, and it is still refused: the line
        // in front of the value is what says this grid wrote it, and nothing else wrote that.
        for platform in [Platform::Mac, Platform::Linux] {
            let vault = OsVault { store: Fake::on(platform) };
            vault.store.written_through_the_text_door("grid-core.billing-key.v1", SECRET);
            assert_eq!(vault.read(&entry(1)).unwrap_err(), Trouble::Damaged, "{platform:?}");
        }

        // The same value written through this file, on the same Windows store, reads back whole.
        windows.write(&entry(1), &Held::from(SECRET.as_bytes().to_vec())).unwrap();
        assert_eq!(windows.read(&entry(1)).unwrap().fingerprint().unwrap(), fingerprint_of(SECRET));
    }

    /// PROVES that every other shape an entry could hold is refused with the trouble that says
    /// what it is, and that nothing in a refusal needs the value to be guessed at.
    #[test]
    fn a_damaged_entry_an_empty_one_and_a_store_that_will_not_answer_are_each_told_apart() {
        let vault = OsVault { store: Fake::on(Platform::Windows) };
        let put = |bytes: Vec<u8>| vault.store.held().insert("grid-core.billing-key.v1".to_owned(), bytes);

        put(SECRET.as_bytes().to_vec());
        assert_eq!(vault.read(&entry(1)).unwrap_err(), Trouble::Damaged, "a bare value was not written by this grid");
        put(Vec::new());
        assert_eq!(vault.read(&entry(1)).unwrap_err(), Trouble::Damaged);
        put(b"grid-core/1\n".to_vec());
        assert_eq!(vault.read(&entry(1)).unwrap_err(), Trouble::Damaged, "and there has to be something after the line");
        put([b"grid-core/1\n".as_slice(), &[0xff, 0xfe]].concat());
        assert_eq!(vault.read(&entry(1)).unwrap_err(), Trouble::Damaged, "what follows the line still has to be text");
        put([b"grid-core/1\n".as_slice(), b"sk\0live"].concat());
        assert_eq!(vault.read(&entry(1)).unwrap_err(), Trouble::Damaged, "a NUL is not text a value is made of");

        // A value with several lines is held, because a GitHub App's private key is one and it
        // never travels as itself. Whether a line break is allowed is asked where the value goes
        // onto a request, by `core::mint::value_in`, and not here.
        let key = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----";
        vault.write(&entry(1), &Held::from(key.as_bytes().to_vec())).unwrap();
        assert_eq!(vault.read(&entry(1)).unwrap().as_text().unwrap(), key);
        assert!(vault.read(&entry(1)).unwrap().one_line().is_err(), "and it is refused where it would go into a header");

        // A store that will not answer is a different thing from an entry that is not there, and
        // the sentence each one puts in front of a person says which.
        let silent = OsVault { store: Fake::on(Platform::Mac) };
        silent.store.stops_answering();
        assert_eq!(silent.read(&entry(1)).unwrap_err(), Trouble::Refused);
        assert_eq!(silent.write(&entry(1), &Held::from(SECRET.as_bytes().to_vec())).unwrap_err(), Trouble::Refused);
        assert_eq!(silent.remove(&entry(1)).unwrap_err(), Trouble::Refused);
        assert_eq!(silent.reachable().unwrap_err(), Trouble::Refused);
        assert_eq!(
            Trouble::Damaged.describe(&entry(1), "the operating system's credential vault"),
            "What the operating system's credential vault holds in grid-core.billing-key.v1 is not a value this grid can send"
        );
    }

    /// PROVES that a value too long for Windows's credential blob is refused rather than half
    /// written, that nothing is left behind when it is, and that the same value is accepted on a
    /// store with no such limit.
    #[test]
    fn a_value_too_long_for_windows_is_refused_rather_than_half_written() {
        let long = "x".repeat(2560);
        let windows = OsVault { store: Fake::on(Platform::Windows) };
        assert_eq!(windows.write(&entry(1), &Held::from(long.as_bytes().to_vec())).unwrap_err(), Trouble::Refused);
        assert!(windows.store.held().is_empty(), "nothing was written");
        // One short enough for the line in front of it to fit as well does go in.
        let fits = "x".repeat(2560 - "grid-core/1\n".len());
        windows.write(&entry(1), &Held::from(fits.as_bytes().to_vec())).unwrap();
        assert_eq!(windows.read(&entry(1)).unwrap().len(), fits.len());

        let mac = OsVault { store: Fake::on(Platform::Mac) };
        mac.write(&entry(1), &Held::from(long.as_bytes().to_vec())).unwrap();
        assert_eq!(mac.read(&entry(1)).unwrap().len(), long.len());
    }

    /// PROVES that asking whether the store answers writes nothing and reads one entry that is
    /// not meant to be there, and that an entry somebody else happens to have written under that
    /// name does not make the store look unreachable.
    #[test]
    fn asking_whether_the_vault_answers_writes_nothing() {
        let vault = OsVault { store: Fake::on(Platform::Linux) };
        vault.reachable().unwrap();
        assert_eq!((vault.store.reads(), vault.store.held().len()), (1, 0), "one read and nothing written");

        vault.store.written_through_the_text_door("grid-core.reachable.v1", "somebody else's");
        vault.reachable().unwrap();
        assert_eq!(vault.store.held().len(), 1, "an entry that is damaged is still an answer");
    }
}
