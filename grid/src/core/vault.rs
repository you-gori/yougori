//! Where a secret actually is, and the one way the broker reads it.
//!
//! Nothing in Grid Core takes a secret as an argument. A value enters this process in exactly one
//! place, `Vault::read`, lives in a `Held` for as long as one request takes, and is overwritten
//! when that `Held` is dropped.
//!
//! Which keeper a grid uses is a property of this computer, not of the realm's record. It is
//! whichever `Vault` the caller hands the broker, so a backup carries no name of a vault this
//! computer may not even have, and a restored realm cannot end up recording a keeper it cannot
//! open. `Keeper` is here to say plainly which ones this build can open, and the registry in
//! `core::connector::registry` carries the same answer into the adapter matrix.
use super::credential::{fingerprint_of, Credential};

/// One entry in a vault: the entry a credential names, and which version of it. The version is
/// part of what is asked for, so a rotation cannot be half applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub realm_id: String,
    pub vault_id: String,
    pub version: u32,
}

impl Entry {
    /// The entry holding the value this credential is on now.
    pub fn of(credential: &Credential) -> Entry {
        Entry { realm_id: credential.realm_id.clone(), vault_id: credential.vault.id.clone(), version: credential.vault.version }
    }

    /// The entry a rotation has to write before the rotation is recorded.
    pub fn next(credential: &Credential) -> Entry {
        Entry { realm_id: credential.realm_id.clone(), vault_id: credential.vault.id.clone(), version: credential.vault.version.saturating_add(1) }
    }

    /// What the vault is asked for: the grid's own prefix, the entry's name and its version, so a
    /// rotation is a different entry and a version check is physical rather than advisory.
    ///
    /// The prefix keeps these apart from everything else this computer's vault holds. Two realms
    /// on one computer that name the same entry are naming one value, which is what asking for
    /// the same entry means; realms are kept apart by their database and their key, while the
    /// operating system's vault is one store for the whole computer.
    pub fn account(&self) -> String {
        format!("grid-core.{}.v{}", self.vault_id, self.version)
    }
}

/// Why a vault could not answer. None of this text comes from a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trouble {
    /// The vault itself cannot be reached, or it is locked.
    Unavailable,
    /// There is no such entry.
    Missing,
    /// The operating system refused this process.
    Refused,
    /// The entry is there, and what is in it is not a value this build can send.
    Damaged,
}

impl Trouble {
    /// What to tell the person who asked. The entry's name is a name, so it is safe to print;
    /// nothing here comes from the value.
    pub fn describe(self, entry: &Entry, vault: &str) -> String {
        match self {
            Trouble::Unavailable => format!("{vault} could not be reached, so {} was not read", entry.account()),
            Trouble::Missing => format!("{vault} holds no entry called {}", entry.account()),
            Trouble::Refused => format!("{vault} refused this computer the entry {}", entry.account()),
            Trouble::Damaged => format!("What {vault} holds in {} is not a value this grid can send", entry.account()),
        }
    }
}

/// A value in memory for as long as one request takes, overwritten when it is dropped.
///
/// There is no `Clone`, no `Display`, no `Serialize` and no `Deref`, and the `Debug` prints
/// nothing of it, so the ordinary ways a value escapes into a log are not available at all.
pub struct Held(Vec<u8>);

impl Held {
    pub fn from(bytes: Vec<u8>) -> Held {
        Held(bytes)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The value, for the one caller that has to put it on a request.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// The same as text, borrowed, so reading it makes no copy. A value that is not UTF-8 is not
    /// something this build can put in a header or a query, and says so rather than guessing.
    pub fn as_text(&self) -> Result<&str, Trouble> {
        std::str::from_utf8(&self.0).map_err(|_| Trouble::Damaged)
    }

    /// The same as text, and on one line.
    ///
    /// A value that travels as itself goes into a header, a parameter or a username, and a line
    /// break in one of those could end the header early, so one is refused here rather than
    /// discovered with the request half built.
    ///
    /// The rule is here and not in `unframed` because not every value travels as itself. A GitHub
    /// App's private key is a PEM block, which has several lines on purpose, and it never goes on
    /// a request at all: it signs a short assertion and the assertion travels. A vault that
    /// refused line breaks at the door would refuse that key and there would be nowhere to put
    /// it. So the vault takes any text that is not empty and holds no NUL, and this is the gate
    /// every kind that puts the value itself on the wire goes through.
    pub fn one_line(&self) -> Result<&str, Trouble> {
        let text = self.as_text()?;
        if text.is_empty() || text.contains(['\0', '\r', '\n']) {
            return Err(Trouble::Damaged);
        }
        Ok(text)
    }

    /// What it fingerprints to, for comparing with what the realm recorded.
    pub fn fingerprint(&self) -> Result<String, Trouble> {
        Ok(fingerprint_of(self.as_text()?))
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

impl std::fmt::Debug for Held {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Held(hidden)")
    }
}

/// The line this grid writes in front of a value in the operating system's vault.
///
/// The operating system's vault is a byte store with a text door beside it, and on Windows the two
/// doors do not agree: the text door writes the UTF-16 of the value, so a byte read of an entry
/// written through it hands back something that is not the value's UTF-8 at all. It still looks
/// like bytes, it still has a length, and it fingerprints to something else entirely, which is a
/// refusal on every send with nothing to point at.
///
/// So the encoding is written down rather than assumed. This grid uses the byte door at both ends
/// and puts this line in front of the value, and a read that does not find it refuses as damaged
/// instead of guessing. Anything else that wrote that entry, in any encoding, is told apart from a
/// value this grid wrote.
pub const WRITTEN_AS: &[u8] = b"grid-core/1\n";

/// The bytes to put in a vault entry for this value. The copy is a `Held`, so the framed form is
/// overwritten when it is dropped just as the value is.
pub fn framed(value: &Held) -> Held {
    let mut bytes = Vec::with_capacity(WRITTEN_AS.len() + value.len());
    bytes.extend_from_slice(WRITTEN_AS);
    bytes.extend_from_slice(value.expose());
    Held(bytes)
}

/// The value in the bytes a vault entry gave back, or `Damaged` if those bytes were not written by
/// this grid. The bytes handed in are overwritten here, whichever way it goes.
pub fn unframed(blob: Vec<u8>) -> Result<Held, Trouble> {
    let blob = Held(blob);
    let bytes = blob.expose();
    if bytes.len() < WRITTEN_AS.len() || &bytes[..WRITTEN_AS.len()] != WRITTEN_AS {
        return Err(Trouble::Damaged);
    }
    let value = Held(bytes[WRITTEN_AS.len()..].to_vec());
    // It has to be text with something in it. Whether it has to be one line depends on what the
    // credential does with it, and that is asked at the moment it goes on a request, by
    // `Held::one_line`: a GitHub App's private key is a PEM block of several lines and it never
    // travels as itself, so a vault that refused a line break here would refuse the one value
    // this grid holds that needs them.
    let text = value.as_text()?;
    if text.is_empty() || text.contains('\0') {
        return Err(Trouble::Damaged);
    }
    Ok(value)
}

/// Overwrites a buffer in place, without the compiler being allowed to decide the writes are
/// pointless because nobody reads them afterwards.
pub(crate) fn wipe(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        // Safety: a volatile write of one byte through a valid, uniquely borrowed pointer.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// Where a realm's secrets are kept.
///
/// Every method is synchronous, because every vault behind it is: the operating system's vault
/// blocks on a local call that may put a prompt in front of the person using the computer. The
/// broker never calls one of these from a thread that is also running other work; see
/// `broker::send`.
pub trait Vault: Send + Sync {
    /// Which keeper this is.
    fn keeper(&self) -> Keeper;
    /// What to call it when something goes wrong.
    fn name(&self) -> String {
        self.keeper().name().to_owned()
    }
    /// Reads one entry. Called by the broker, and by nothing else.
    fn read(&self, entry: &Entry) -> Result<Held, Trouble>;
    /// Writes one entry. Called by a rotation, and by nothing else.
    fn write(&self, entry: &Entry, value: &Held) -> Result<(), Trouble>;
    /// Removes an entry a rotation has replaced.
    fn remove(&self, entry: &Entry) -> Result<(), Trouble>;
    /// Whether it can be reached at all, for a status line.
    fn reachable(&self) -> Result<(), Trouble>;
}

/// Which keeper holds a realm's values.
///
/// Only the operating system's own vault can be opened by this build. The rest name the seam and
/// nothing more: `connected` says so, `unconnected` says so in words, and every one of them has a
/// row in `core::connector::registry` in that same state, so the adapter matrix cannot say
/// anything kinder than this enum does.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Keeper {
    #[default]
    OperatingSystem,
    HashiCorpVault,
    AzureKeyVault,
    AwsSecretsManager,
    GoogleSecretManager,
    CyberArk,
    BeyondTrust,
    HardwareSecurityModule,
    TrustedPlatformModule,
}

impl Keeper {
    /// Every keeper this seam names, in the order the adapter matrix lists them.
    pub fn all() -> &'static [Keeper] {
        &[
            Keeper::OperatingSystem,
            Keeper::HashiCorpVault,
            Keeper::AzureKeyVault,
            Keeper::AwsSecretsManager,
            Keeper::GoogleSecretManager,
            Keeper::CyberArk,
            Keeper::BeyondTrust,
            Keeper::HardwareSecurityModule,
            Keeper::TrustedPlatformModule,
        ]
    }

    pub fn name(self) -> &'static str {
        match self {
            Keeper::OperatingSystem => "the operating system's credential vault",
            Keeper::HashiCorpVault => "HashiCorp Vault",
            Keeper::AzureKeyVault => "Azure Key Vault",
            Keeper::AwsSecretsManager => "AWS Secrets Manager",
            Keeper::GoogleSecretManager => "Google Secret Manager",
            Keeper::CyberArk => "CyberArk",
            Keeper::BeyondTrust => "BeyondTrust",
            Keeper::HardwareSecurityModule => "A hardware security module (PKCS#11)",
            Keeper::TrustedPlatformModule => "TPM-backed key storage",
        }
    }

    /// Whether this build can open it. Only the operating system's vault, and the one in memory
    /// the tests use, which is not a keeper anybody ships.
    pub fn connected(self) -> bool {
        self == Keeper::OperatingSystem
    }

    /// What to tell a person who chose one that is not wired in.
    pub fn unconnected(self) -> String {
        format!("{} is not connected in this build; this grid keeps its values in the operating system's vault", self.name())
    }
}

/// A vault that answers nothing. This is what a realm has until one is wired in, and it is also
/// what every keeper this build cannot open is: every read fails, so a realm without a vault
/// refuses requests rather than sending them without a credential.
pub struct Unconnected(pub Keeper);

impl Vault for Unconnected {
    fn keeper(&self) -> Keeper {
        self.0
    }
    fn read(&self, _entry: &Entry) -> Result<Held, Trouble> {
        Err(Trouble::Unavailable)
    }
    fn write(&self, _entry: &Entry, _value: &Held) -> Result<(), Trouble> {
        Err(Trouble::Unavailable)
    }
    fn remove(&self, _entry: &Entry) -> Result<(), Trouble> {
        Err(Trouble::Unavailable)
    }
    fn reachable(&self) -> Result<(), Trouble> {
        Err(Trouble::Unavailable)
    }
}

/// A vault in memory, for the tests. It counts reads, so a test can prove a refusal happened
/// before any value was read, and it can be given something to do while a read is in flight, so a
/// test can change the realm at the one moment that matters.
#[cfg(test)]
pub struct MemoryVault {
    entries: std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
    pub reads: std::sync::atomic::AtomicUsize,
    /// Run at the start of every read, on the blocking thread the read is on.
    pub meanwhile: std::sync::Mutex<Option<Box<dyn FnMut() + Send>>>,
}

#[cfg(test)]
impl Default for MemoryVault {
    fn default() -> MemoryVault {
        MemoryVault::new()
    }
}

#[cfg(test)]
impl MemoryVault {
    pub fn new() -> MemoryVault {
        MemoryVault { entries: std::sync::Mutex::new(std::collections::HashMap::new()), reads: std::sync::atomic::AtomicUsize::new(0), meanwhile: std::sync::Mutex::new(None) }
    }

    /// Puts a value in, the way an administrator's tool would.
    pub fn put(&self, entry: &Entry, value: &str) {
        self.entries.lock().unwrap().insert(entry.account(), value.as_bytes().to_vec());
    }

    pub fn read_count(&self) -> usize {
        self.reads.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(test)]
impl Vault for MemoryVault {
    fn keeper(&self) -> Keeper {
        Keeper::OperatingSystem
    }
    fn name(&self) -> String {
        "a vault in memory".to_owned()
    }
    fn read(&self, entry: &Entry) -> Result<Held, Trouble> {
        if let Some(act) = self.meanwhile.lock().unwrap().as_mut() {
            act();
        }
        self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.entries.lock().unwrap().get(&entry.account()).map(|value| Held::from(value.clone())).ok_or(Trouble::Missing)
    }
    fn write(&self, entry: &Entry, value: &Held) -> Result<(), Trouble> {
        self.entries.lock().unwrap().insert(entry.account(), value.expose().to_vec());
        Ok(())
    }
    fn remove(&self, entry: &Entry) -> Result<(), Trouble> {
        self.entries.lock().unwrap().remove(&entry.account());
        Ok(())
    }
    fn reachable(&self) -> Result<(), Trouble> {
        Ok(())
    }
}
