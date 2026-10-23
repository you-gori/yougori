//! The on-disk shapes the four shipped products write, frozen as they are.
//!
//! Everything else in this phase rests on this one thing. A rehearsal is worth running only if
//! the record it rehearsed is the record the product will still be writing on the day of the
//! move; a backup is worth taking only if what comes back is what went in; a bridge can be
//! trusted only against a shape that is not moving under it. So the shapes are written down here,
//! in code, with a fixture per shape, and a test fails if any of them changes.
//!
//! What "frozen" means here is exact and narrow. It means: for every record named below there is
//! one file of bytes in `frozen/`, those bytes read back into this build's type, and writing that
//! value out again gives the same bytes. A field added, renamed, removed, newly defaulted or
//! given a different serialised name changes the bytes and fails the test.
//!
//! It does not mean the freeze is complete, and that limit has to be said rather than discovered.
//! A type nobody wrote a fixture for is not frozen, and nothing in Rust can notice a struct that
//! was never named here. The fixtures also start the day this landed: they are written from the
//! working tree, so they say what this build writes and say nothing at all about what 1.0.20 and
//! earlier wrote. Two things narrow that gap and neither closes it: every record this product has
//! ever shipped is at version 1, and the exhaustive destructuring tests in `crate::hub` and
//! `crate::bounty` fail to compile when a field is added to any type either record is made of,
//! which catches the one case bytes cannot, a new optional field that is skipped when it is
//! empty. Those two tests name every type under `hub::Record`, including the desks, the people
//! and the enterprise settings, and every type under `bounty::Record`. The single exception is
//! `bounty::Record::coordination`, which is named and not opened: it carries `skip_serializing`,
//! so no byte of it is in the record, and its fields are private to the module that owns it.
//!
//! `docs/grid-core/frozen-contracts.md` is rendered from `matrix()`, the way `adapters.md` is
//! rendered from the connector registry, and a test fails when the two stop agreeing.
// Only `fixture_folder` and the rewriter need a path here, and both are behind `cfg(test)`.
#[cfg(test)]
use std::path::{Path, PathBuf};

/// Which product writes a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Product {
    NeoGrid,
    SandboxGrid,
    SwarmMining,
    AccessGrid,
    /// Grid Core's own portable shape, which is what a backup and an export carry.
    Core,
}

impl Product {
    pub fn name(self) -> &'static str {
        match self {
            Product::NeoGrid => "Closed Neo Grid",
            Product::SandboxGrid => "Sandbox Grid",
            Product::SwarmMining => "Swarm Mining",
            Product::AccessGrid => "Access Grid",
            Product::Core => "Grid Core",
        }
    }

    /// The short word a command takes, and the word the rollout's own files are named by.
    pub fn word(self) -> &'static str {
        match self {
            Product::NeoGrid => "neo",
            Product::SandboxGrid => "sandbox",
            Product::SwarmMining => "swarm",
            Product::AccessGrid => "access",
            Product::Core => "core",
        }
    }

    pub fn from_word(word: &str) -> Option<Product> {
        Product::all().iter().copied().find(|product| product.word() == word)
    }

    /// The four shipped products and the core's own shape, in the order the rollout moves them.
    pub fn all() -> &'static [Product] {
        &[Product::NeoGrid, Product::SandboxGrid, Product::SwarmMining, Product::AccessGrid, Product::Core]
    }
}

/// What takes this record onto the core, or why nothing does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bridge {
    /// `compat::neo`: rehearse, import, roll back and compare.
    Neo,
    /// `compat::desks`: rehearse, import, roll back and compare.
    Desks,
    /// `compat::bounty`: rehearse, import, roll back and compare, into a research realm of its own.
    Bounty,
    /// `compat::access`: rehearse, import, roll back and compare, with no value carried.
    Access,
    /// Nothing imports this record, and this is why.
    None(&'static str),
}

impl Bridge {
    pub fn says(self) -> &'static str {
        match self {
            Bridge::Neo => "compat::neo, with rehearse, import, roll back and compare",
            Bridge::Desks => "compat::desks, with rehearse, import, roll back and compare",
            Bridge::Bounty => "compat::bounty, with rehearse, import, roll back and compare, into a research realm of its own",
            Bridge::Access => "compat::access, with rehearse, import, roll back and compare; no credential value is carried",
            Bridge::None(why) => why,
        }
    }

    pub fn imports(self) -> bool {
        !matches!(self, Bridge::None(_))
    }
}

/// What an older build does with a record a newer build wrote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Forward {
    /// The version is read and anything above this build's is refused, with words.
    Gated,
    /// Fields this build does not know are ignored on read and lost on the next save. Quiet, and
    /// worse than a refusal for exactly that reason.
    Dropped,
    /// One unknown field refuses the whole file, because something inside it carries
    /// `deny_unknown_fields`.
    Refused,
}

impl Forward {
    pub fn name(self) -> &'static str {
        match self {
            Forward::Gated => "Gated",
            Forward::Dropped => "Dropped",
            Forward::Refused => "Refused",
        }
    }

    pub fn means(self) -> &'static str {
        match self {
            Forward::Gated => "the loader reads the version first and refuses anything above this build's, saying so",
            Forward::Dropped => "an older build reads it, ignores what it does not know, and loses those fields the next time it saves",
            Forward::Refused => "an older build refuses the whole file, because a type inside it refuses an unknown field",
        }
    }
}

/// One record a shipped product writes, frozen as it is.
#[derive(Clone, Copy, Debug)]
pub struct Contract {
    pub name: &'static str,
    /// Under the application's own data folder. Never an absolute path, because an absolute path
    /// here would be one computer's, and this register is about every computer.
    pub path: &'static str,
    pub rust_type: &'static str,
    pub product: Product,
    /// The `version` the shipped builds write into it.
    pub version: u32,
    pub forward: Forward,
    /// The vault entries this record cannot be used without, by name. Never a value: these are
    /// the names of entries in the operating system's own vault, and this crate cannot read one.
    pub vault: &'static [&'static str],
    /// The file under `grid/src/core/compat/frozen/` that pins the shape.
    pub fixture: &'static str,
    /// SHA-256 of that file's bytes, so editing a fixture without saying so here fails.
    pub fixture_sha256: &'static str,
    pub bridge: Bridge,
}

/// The vault entry that holds a realm's key, which is the one thing a restore cannot do without.
/// Rendered from `store::KeyReference::for_realm` rather than typed out, with the realm's own
/// identifier left as a placeholder because it differs on every computer.
pub fn realm_key_entry() -> String {
    super::super::store::KeyReference::for_realm("<realm-id>").id
}

/// Every frozen record. Adding a row means adding a fixture; a row without one fails the tests.
pub fn contracts() -> &'static [Contract] {
    &[
        Contract {
            name: "The Closed Neo Grid hub's record",
            path: "grid/hub.json",
            rust_type: "crate::hub::Record",
            product: Product::NeoGrid,
            version: 1,
            forward: Forward::Gated,
            vault: &["yougori-grid-hub-key", "yougori-grid-hub-password", "yougori-grid-member-token"],
            fixture: "neo-hub-v1.json",
            fixture_sha256: "7e140c48f0c1b2b407de572b458c414931a2a18c5b397df394b910ac932e36b1",
            bridge: Bridge::Neo,
        },
        Contract {
            name: "The Sandbox Grid hub's record",
            path: "grid/desks-hub.json",
            rust_type: "crate::hub::Record",
            product: Product::SandboxGrid,
            version: 1,
            forward: Forward::Gated,
            vault: &[
                "yougori-desks-hub-key",
                "yougori-desks-hub-password",
                "yougori-desks-member-token",
                "yougori-desks-parking",
                "yougori-desks-connection-<connection-id>",
                "yougori-desks-person-session",
                "yougori-grid-desk-invite",
            ],
            fixture: "sandbox-hub-v1.json",
            fixture_sha256: "97877f7c2426662587a7b5b6977ee73caf15a5794e6ecfa47fbd4b368fd56f99",
            bridge: Bridge::Desks,
        },
        Contract {
            name: "The closed bounty host's record",
            path: "bounty/host.json",
            rust_type: "crate::bounty::Record",
            product: Product::SwarmMining,
            version: 1,
            forward: Forward::Gated,
            vault: &["yougori-bounty-hub-key", "yougori-bounty-hub-password"],
            fixture: "bounty-host-v1.json",
            fixture_sha256: "112d54e920682fd8d4848db9ad3e50bf038b422f942833f5e3310e892658d78d",
            bridge: Bridge::Bounty,
        },
        Contract {
            name: "The Access Grid hub's record",
            path: "grid/access-hub.json",
            rust_type: "crate::access::hub::Record",
            product: Product::AccessGrid,
            version: 1,
            forward: Forward::Dropped,
            vault: &["yougori-access-hub-key", "yougori-access-hub-seal", "yougori-access-device"],
            fixture: "access-hub-v1.json",
            fixture_sha256: "cfc45b783a3a738cb13c1fb0a87e0b4c360fc5571f82832c665b1bd021396f39",
            bridge: Bridge::Access,
        },
    ]
}

/// How many fixtures there must be. The folder holding more or fewer is a failure, so a fixture
/// cannot be deleted and the freeze cannot quietly narrow.
pub const FIXTURES: usize = 4;

/// Records the four products write that are deliberately **not** frozen here, and why not.
///
/// This list is as much a part of the freeze as the register is. Leaving it out would let the
/// document read as though every file on a customer's disk were pinned, and it is not.
pub fn not_frozen() -> &'static [(&'static str, &'static str)] {
    &[
        ("grid/member.json, grid/desks-member.json, grid/access-member.json", "written by the application, not by this crate: their types are in src-tauri and a fixture here could not read one"),
        ("grid/desks.json, grid/desk-login.json", "the same: a person's desk session on their own computer, kept by the application"),
        ("grid/tunnel.json, grid/desks-tunnel.json, grid/access-tunnel.json", "the same, and they hold a tunnel this crate never reads back"),
        ("swarm/workers.json, swarm/events/, swarm/receipts/<worker-id>/", "a worker's own files, written by the application. The product deletes receipts with the worker on purpose, so freezing them would promise something the product does not do"),
        ("bounty/imports/*.json", "a published bounty's source, which src-tauri/src/bounty.rs deletes after a day on purpose, for the same reason"),
        ("grid/core/<realm-id>.json", "Grid Core's own portable shape, which no shipped product writes. It already reads its own version and refuses a record from a newer build (`store::legacy::read`), and it is what a backup carries rather than what a customer's product keeps"),
    ]
}

/// The body of `docs/grid-core/frozen-contracts.md`, rendered from the register above.
pub fn matrix() -> String {
    let mut out = String::from("## What a forward-compatibility state means\n\n| State | Means |\n| --- | --- |\n");
    for state in [Forward::Gated, Forward::Dropped, Forward::Refused] {
        out.push_str(&format!("| **{}** | {} |\n", state.name(), state.means()));
    }
    out.push_str("\n## The frozen records\n\n| Record | Where | Type | Version | Forward | Bridge |\n| --- | --- | --- | --- | --- | --- |\n");
    for contract in contracts() {
        out.push_str(&format!(
            "| {} | `{}` | `{}` | {} | {} | {} |\n",
            contract.name,
            contract.path,
            contract.rust_type,
            contract.version,
            contract.forward.name(),
            contract.bridge.says()
        ));
    }
    out.push_str("\n## The fixture that pins each one\n\n| Record | Fixture | SHA-256 |\n| --- | --- | --- |\n");
    for contract in contracts() {
        out.push_str(&format!("| {} | `grid/src/core/compat/frozen/{}` | `{}` |\n", contract.name, contract.fixture, contract.fixture_sha256));
    }
    out.push_str("\n## The vault entries each record cannot be used without\n\nNames only. No value of any of these is in this repository, in a fixture, in a backup manifest or in a survey.\n\n| Record | Entries |\n| --- | --- |\n");
    for contract in contracts() {
        let entries: Vec<String> = contract.vault.iter().map(|entry| format!("`{entry}`")).collect();
        out.push_str(&format!("| {} | {} |\n", contract.name, entries.join(", ")));
    }
    out.push_str("\n## What is deliberately not frozen\n\n| Files | Why not |\n| --- | --- |\n");
    for (files, why) in not_frozen() {
        out.push_str(&format!("| `{files}` | {why} |\n"));
    }
    out
}

/// Where the fixtures are, in this repository. Only the tests and the rewriter use this: nothing
/// a customer runs ever reads a fixture.
///
/// Behind `cfg(test)` so that sentence is true of the binary as well as of the call sites.
/// `env!("CARGO_MANIFEST_DIR")` is the absolute path of whichever computer compiled this, and the
/// rest of this module is shipped, so left ungated it would put that path into a release build of
/// a crate that never reads a fixture.
#[cfg(test)]
pub fn fixture_folder() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/core/compat/frozen")
}

/// The SHA-256 of some bytes, as the register writes it.
pub fn digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// What shape a file's bytes are.
///
/// A shape is not always a product. The Closed Neo Grid and the Sandbox Grid keep one type,
/// `hub::Record`, in two files, and nothing in the bytes tells the two apart: a Sandbox Grid with
/// no desks yet and a Neo Grid serialise the same keys. The file it was found in is what says
/// which product it belongs to, and a reader should believe the path over this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    /// `hub::Record`: the Closed Neo Grid's record, and the Sandbox Grid's.
    Hub,
    BountyHost,
    AccessHub,
    CoreRecord,
}

impl Shape {
    pub fn name(self) -> &'static str {
        match self {
            Shape::Hub => "a grid hub's record",
            Shape::BountyHost => "a closed bounty host's record",
            Shape::AccessHub => "an Access Grid hub's record",
            Shape::CoreRecord => "a realm in the portable shape",
        }
    }

    /// Which products write this shape.
    pub fn products(self) -> &'static [Product] {
        match self {
            Shape::Hub => &[Product::NeoGrid, Product::SandboxGrid],
            Shape::BountyHost => &[Product::SwarmMining],
            Shape::AccessHub => &[Product::AccessGrid],
            Shape::CoreRecord => &[Product::Core],
        }
    }
}

/// What a file's bytes are, read from the bytes rather than from the file's name.
///
/// This is what makes a record found on a disk years from now readable: it is asked what it is.
/// Nothing is written and nothing is opened; the bytes are already in hand.
pub fn recognise(bytes: &[u8]) -> Option<Shape> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let has = |key: &str| value.get(key).is_some();
    if has("bounty") && has("certificate") {
        return Some(Shape::BountyHost);
    }
    if has("company") && has("credentials") {
        return Some(Shape::AccessHub);
    }
    if has("realm") && has("principals") {
        return Some(Shape::CoreRecord);
    }
    if has("plans") && has("members") && has("certificate") {
        return Some(Shape::Hub);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    /// The maximal value each fixture is written from.
    ///
    /// Maximal means: every optional field present, every list with at least two entries, every
    /// field that is skipped when it is empty in its serialising state, and every enum variant
    /// that can appear in that record appearing somewhere. That is what makes an *addition*
    /// visible: a field added to one of these types serialises into the output and is not in the
    /// fixture, so the round-trip below fails.
    ///
    /// Every value here was made up in this repository. None of it is, or has ever been, any
    /// deployment's bytes: the certificates say so in their own text, the salts and hashes are
    /// counting patterns, the addresses are private ones and every name is under `.invalid`,
    /// which is reserved and resolves nowhere.
    fn maximal() -> Vec<(&'static str, Value)> {
        vec![
            ("neo-hub-v1.json", hub_record("grid-0123456789abcdef", "Example Models")),
            ("sandbox-hub-v1.json", hub_record("grid-fedcba9876543210", "Example Desks")),
            ("bounty-host-v1.json", bounty_record()),
            ("access-hub-v1.json", access_record()),
        ]
    }

    fn share() -> Value {
        json!({"cpu": 4.0, "memoryGb": 8.0, "diskGb": 100.0, "gpu": true, "idleOnly": true})
    }

    fn spec(kind: &str, image: &str) -> Value {
        json!({"kind": kind, "cpu": 2.0, "memoryGb": 4.0, "diskGb": 40.0, "gpu": false, "image": image})
    }

    fn hub_record(id: &str, name: &str) -> Value {
        json!({
            "version": 1,
            "id": id,
            "name": name,
            "address": "10.0.0.5",
            "port": 7460,
            "hostname": "grid.example.invalid",
            "tunnelPort": 7461,
            "certificate": "FIXTURE CERTIFICATE, NOT A REAL ONE",
            "salt": "00112233445566778899aabbccddeeff",
            "createdAt": 1_700_000_000,
            "plans": [
                {"id": "plan-0000000000000001", "model": "example/one", "quant": "q4_k_m", "percent": 50,
                 "policy": {"idleAfterMinutes": 10, "schedule": "Mon-Fri 18:00-08:00"}, "createdAt": 1_700_000_100,
                 "target": {"kind": "all"}},
                {"id": "plan-0000000000000002", "model": "example/two", "quant": null, "percent": 25,
                 "policy": {"idleAfterMinutes": 0, "schedule": null}, "createdAt": 1_700_000_200,
                 "target": {"kind": "computers", "members": ["member-0000000000000001"]}},
                {"id": "plan-0000000000000003", "model": "example/three", "quant": null, "percent": 10,
                 "policy": {"idleAfterMinutes": 5, "schedule": null}, "createdAt": 1_700_000_300,
                 "target": {"kind": "remaining"}}
            ],
            "members": [
                {"id": "member-0000000000000001", "name": "Computer one", "platform": "linux",
                 "tokenHash": "1111111111111111111111111111111111111111111111111111111111111111",
                 "joinedAt": 1_700_000_400, "capable": true, "plan": "plan-0000000000000001",
                 "assignedAt": 1_700_000_500, "jobs": 12, "excluded": false, "share": share()},
                {"id": "member-0000000000000002", "name": "Computer two", "platform": "windows",
                 "tokenHash": "2222222222222222222222222222222222222222222222222222222222222222",
                 "joinedAt": 1_700_000_600, "capable": false, "plan": null,
                 "assignedAt": null, "jobs": 0, "excluded": true, "share": share()}
            ],
            "keys": [
                {"id": "key-0000000000000001", "name": "Example app", "prefix": "ygrid_aaaa",
                 "hash": "3333333333333333333333333333333333333333333333333333333333333333",
                 "createdAt": 1_700_000_700, "lastUsedAt": 1_700_000_800, "requests": 30, "failures": 1,
                 "tokensIn": 1000, "tokensOut": 2000},
                {"id": "key-0000000000000002", "name": "Second app", "prefix": "ygrid_bbbb",
                 "hash": "4444444444444444444444444444444444444444444444444444444444444444",
                 "createdAt": 1_700_000_900, "lastUsedAt": null, "requests": 0, "failures": 0,
                 "tokensIn": 0, "tokensOut": 0}
            ],
            "harnesses": [
                {"id": "harness-0000000000000001", "name": "research", "strategy": "plan", "lead": "example/one",
                 "workers": ["example/two", "example/three"], "computers": 2, "tasks": 3, "rounds": 2,
                 "createdAt": 1_700_001_000},
                {"id": "harness-0000000000000002", "name": "review", "strategy": "mixture", "lead": "example/two",
                 "workers": ["example/one", "example/three"], "computers": 1, "tasks": 2, "rounds": 1,
                 "createdAt": 1_700_001_100}
            ],
            "desks": [
                {"id": "desk-0000000000000001", "name": "Desk one", "spec": spec("container", "example/image:1"),
                 "access": "standard", "roleId": "role-0000000000000001",
                 "imageSha256": "5555555555555555555555555555555555555555555555555555555555555555",
                 "generation": 2, "movingFrom": "member-0000000000000002",
                 "parcel": {"store": "s3", "key": "desks/desk-0000000000000001", "bytes": 1048576,
                            "sha256": "6666666666666666666666666666666666666666666666666666666666666666",
                            "at": 1_700_001_200},
                 "person": "person-0000000000000001", "state": "moving", "host": "member-0000000000000001",
                 "environmentId": "env-0000000000000001", "note": "Its new computer is taking its data",
                 "trail": ["member-0000000000000001", "member-0000000000000002"], "attempts": 1,
                 "createdAt": 1_700_001_300, "updatedAt": 1_700_001_400},
                {"id": "desk-0000000000000002", "name": "Desk two", "spec": spec("microVm", "builtin:ubuntu"),
                 "access": "restricted", "roleId": null, "imageSha256": null, "generation": 0,
                 "person": null, "state": "planned", "note": "", "trail": [], "attempts": 0,
                 "createdAt": 1_700_001_500, "updatedAt": 1_700_001_600}
            ],
            "people": [
                {"id": "person-0000000000000001", "username": "one", "adminRole": "administrator",
                 "roleId": "role-0000000000000001", "name": "Person One",
                 "salt": "7777777777777777777777777777777777777777777777777777777777777777",
                 "keyHash": "8888888888888888888888888888888888888888888888888888888888888888",
                 "createdAt": 1_700_001_700, "lastLoginAt": 1_700_001_800, "totp": "FIXTURETOTPAAAAAAAA",
                 "totpPending": "FIXTUREPENDINGAAAAA", "email": "one@example.invalid"},
                {"id": "person-0000000000000002", "username": "two", "adminRole": "auditor",
                 "roleId": null, "name": "Person Two",
                 "salt": "9999999999999999999999999999999999999999999999999999999999999999",
                 "keyHash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                 "createdAt": 1_700_001_900}
            ],
            "enterprise": {
                "images": [
                    {"id": "image-0000000000000001", "name": "Prepared one", "version": "1",
                     "description": "A prepared image", "applications": ["editor", "browser"],
                     "spec": spec("microVm", "prepared-one.qcow2"),
                     "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                     "createdAt": 1_700_002_000},
                    {"id": "image-0000000000000002", "name": "Prepared two", "version": "2",
                     "description": "Another prepared image", "applications": [],
                     "spec": spec("container", "example/image:2"), "sha256": null,
                     "createdAt": 1_700_002_100}
                ],
                "roles": [
                    {"id": "role-0000000000000001", "name": "Engineering", "description": "Engineers",
                     "imageId": "image-0000000000000001", "access": "restricted", "createdAt": 1_700_002_200},
                    {"id": "role-0000000000000002", "name": "Support", "description": "Support",
                     "imageId": "image-0000000000000002", "access": "standard", "createdAt": 1_700_002_300}
                ],
                "connections": [
                    {"id": "connection-0000000000000001", "name": "Example desktops", "provider": "citrix",
                     "url": "https://desktops.example.invalid/launch", "roleIds": ["role-0000000000000001"],
                     "target": {"customerId": "example", "clientId": "example-client", "deliveryGroup": "Engineering"},
                     "credentialSet": true, "credentialAt": 1_700_002_400},
                    {"id": "connection-0000000000000002", "name": "Second desktops", "provider": "windows365",
                     "url": "https://windows365.example.invalid/launch", "roleIds": []}
                ],
                "audit": [
                    {"at": 1_700_002_500, "actor": "person-0000000000000001", "action": "desk.created", "subject": "desk-0000000000000001"},
                    {"at": 1_700_002_600, "actor": "person-0000000000000001", "action": "desk.assigned", "subject": "desk-0000000000000002"}
                ],
                "computerLimit": 64,
                "parking": {"provider": "awsS3", "location": "s3://example-bucket/desks", "setAt": 1_700_002_700},
                "cloudFallback": {"enabled": true, "provider": "aws", "account": "example", "region": "eu-west-1",
                                  "image": "ami-0000000000000001", "imageProject": "example-project",
                                  "machineType": "m6i.large", "subnet": "subnet-0000000000000001",
                                  "securityGroup": "sg-0000000000000001", "keyPair": "example",
                                  "resourceGroup": "example-group", "sshPublicKey": "ssh-ed25519 FIXTUREKEY example",
                                  "username": "ubuntu", "identityFile": "example.pem", "maxComputers": 4,
                                  "setAt": 1_700_002_800},
                "sso": {"issuer": "https://login.example.invalid/v2.0", "clientId": "example-client",
                        "usernameClaim": "email", "passwordless": true, "setAt": 1_700_002_900},
                "provisioning": [
                    {"id": "provisioning-0000000000000001", "connectionId": "connection-0000000000000001",
                     "want": "assign", "personId": "person-0000000000000001", "personName": "Person One",
                     "email": "one@example.invalid", "state": "done", "note": "", "at": 1_700_003_000,
                     "finishedAt": 1_700_003_100, "attempts": 1},
                    {"id": "provisioning-0000000000000002", "connectionId": "connection-0000000000000002",
                     "want": "test", "personName": "", "email": "", "state": "failed",
                     "note": "the provider refused", "at": 1_700_003_200, "attempts": 3}
                ]
            },
            "closing": {"requestedAt": 1_700_003_300, "until": 1_700_300_000, "told": ["member-0000000000000002"]}
        })
    }

    fn bounty_record() -> Value {
        json!({
            "version": 1,
            "id": "bounty-0123456789abcdef",
            "name": "Example Bounty",
            "address": "10.0.0.6",
            "port": 7470,
            "hostname": "bounty.example.invalid",
            "tunnelPort": 7471,
            "certificate": "FIXTURE CERTIFICATE, NOT A REAL ONE",
            "salt": "00112233445566778899aabbccddeeff",
            "createdAt": 1_700_000_000,
            "bounty": {
                "title": "Review the example service",
                "instructions": "Look for logic flaws in the checkout path",
                "authorization": "You may test only the source in this bounty",
                "files": [
                    {"path": "src/main.rs", "data": "Zm4gbWFpbigpIHt9"},
                    {"path": "src/lib.rs", "data": "cHViIGZuIG9uZSgpIHt9"}
                ],
                "target": {"kind": "web", "setupCommand": "npm ci", "startCommand": "npm start",
                           "testCommand": "npm test", "port": 3000, "healthPath": "/", "installNetwork": true}
            },
            "members": [
                {"id": "member-0000000000000001", "name": "Computer one", "platform": "linux",
                 "tokenHash": "1111111111111111111111111111111111111111111111111111111111111111",
                 "joinedAt": 1_700_000_400, "model": "example/one", "findings": 2},
                {"id": "member-0000000000000002", "name": "Computer two", "platform": "macos",
                 "tokenHash": "2222222222222222222222222222222222222222222222222222222222222222",
                 "joinedAt": 1_700_000_500, "model": null, "findings": 0}
            ],
            "findings": [
                {"id": "finding-0000000000000001", "memberId": "member-0000000000000001", "memberName": "Computer one",
                 "model": "example/one", "title": "An example finding", "detail": "What it found",
                 "severity": "medium", "createdAt": 1_700_000_600},
                {"id": "finding-0000000000000002", "memberId": "member-0000000000000001", "memberName": "Computer one",
                 "model": "example/one", "title": "A second example finding", "detail": "What else it found",
                 "severity": "", "createdAt": 1_700_000_700}
            ]
        })
    }

    fn access_record() -> Value {
        json!({
            "version": 1,
            "id": "access-0123456789abcdef",
            "company": "Example Company",
            "address": "10.0.0.7",
            "port": 7465,
            "tunnelPort": 7466,
            "certificate": "FIXTURE CERTIFICATE, NOT A REAL ONE",
            "createdAt": 1_700_000_000,
            "owner": "person-0000000000000001",
            "people": [
                {"id": "person-0000000000000001", "username": "one", "name": "Person One", "permission": "admin",
                 "teams": ["engineering", "support"],
                 "salt": "7777777777777777777777777777777777777777777777777777777777777777",
                 "keyHash": "8888888888888888888888888888888888888888888888888888888888888888",
                 "createdAt": 1_700_000_100, "lastSeenAt": 1_700_000_200, "email": "one@example.invalid",
                 "twoStep": "FIXTURESEALEDTWOSTEP", "generation": 3,
                 "devices": [
                    {"id": "device-0000000000000001", "hash": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                     "computer": "Computer one", "createdAt": 1_700_000_300, "lastUsedAt": 1_700_000_400,
                     "strong": true, "generation": 3},
                    {"id": "device-0000000000000002", "hash": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                     "computer": "Computer two", "createdAt": 1_700_000_500, "lastUsedAt": 1_700_000_600,
                     "strong": false, "generation": 2}
                 ]},
                {"id": "person-0000000000000002", "username": "two", "name": "Person Two", "permission": "approver",
                 "teams": [],
                 "salt": "9999999999999999999999999999999999999999999999999999999999999999",
                 "keyHash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                 "createdAt": 1_700_000_700, "generation": 0}
            ],
            "credentials": [
                {"id": "credential-0000000000000001", "name": "Example API", "kind": "bearer", "field": "",
                 "destinations": ["https://api.example.invalid", "https://second.example.invalid"],
                 "note": "The example service", "hint": "abcd", "sealed": "FIXTURE-SEALED-NOT-A-REAL-VALUE",
                 "createdAt": 1_700_000_800, "createdBy": "person-0000000000000001", "updatedAt": 1_700_000_900,
                 "config": {"tokenUrl": "https://token.example.invalid", "clientId": "example-client"}},
                {"id": "credential-0000000000000002", "name": "Second API", "kind": "github-app", "field": "X-Api-Key",
                 "destinations": ["https://third.example.invalid"], "note": "", "hint": "",
                 "sealed": "FIXTURE-SEALED-NOT-A-REAL-VALUE-TWO", "createdAt": 1_700_001_000,
                 "createdBy": "person-0000000000000001", "updatedAt": 1_700_001_100}
            ],
            "rules": [
                {"id": "rule-0000000000000001", "credential": "credential-0000000000000001", "who": "everyone",
                 "methods": ["GET", "POST"], "path": "/repos/example", "decision": "ask", "reveal": true,
                 "expiresAt": 1_700_900_000, "limit": 20, "note": "Ask an approver past twenty an hour",
                 "createdAt": 1_700_001_200, "createdBy": "person-0000000000000001"},
                {"id": "rule-0000000000000002", "credential": "credential-0000000000000002",
                 "who": "person:person-0000000000000002", "methods": [], "path": "", "decision": "never",
                 "reveal": false, "note": "", "createdAt": 1_700_001_300, "createdBy": "person-0000000000000001"}
            ],
            "settings": {"requireTwoStep": true},
            "sso": {"issuer": "https://login.example.invalid/v2.0", "clientId": "example-client",
                    "claim": "email", "passwordless": true, "redirectPort": 53_682},
            "closing": {"requestedAt": 1_700_001_400, "until": 1_700_300_000, "gone": false}
        })
    }

    /// Reads a fixture's bytes and writes them back through the type that owns it, so a
    /// difference is a difference in the shape and never in how the file was indented.
    fn round_trip(fixture: &str, bytes: &[u8]) -> Result<Vec<u8>, String> {
        let out = match fixture {
            "neo-hub-v1.json" | "sandbox-hub-v1.json" => serde_json::to_vec_pretty(&crate::hub::read(bytes)?),
            "bounty-host-v1.json" => serde_json::to_vec_pretty(&crate::bounty::read(bytes)?),
            "access-hub-v1.json" => {
                let record: crate::access::hub::Record = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
                serde_json::to_vec_pretty(&record)
            }
            other => return Err(format!("no reader for {other}")),
        };
        out.map_err(|error| error.to_string())
    }

    fn fixture_bytes(name: &str) -> Vec<u8> {
        let path = fixture_folder().join(name);
        let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{} is part of this repository: {error}", path.display()));
        text.replace("\r\n", "\n").into_bytes()
    }

    /// Writes the fixtures from the maximal values above. Ignored because it writes to the
    /// repository: run it on purpose, once, with
    /// `cargo test rewrite_the_frozen_fixtures -- --ignored`, and then update the SHA-256 values
    /// in `contracts()` from what `every_fixture_is_the_one_the_register_names` prints.
    ///
    /// A fixture is written once and never edited afterwards. Re-running this after a type has
    /// changed is the thing the freeze exists to make deliberate: the six steps a change takes
    /// are in docs/grid-core/frozen-contracts.md, and the first of them is not this test.
    #[test]
    #[ignore]
    fn rewrite_the_frozen_fixtures() {
        let folder = fixture_folder();
        std::fs::create_dir_all(&folder).unwrap();
        for (name, value) in maximal() {
            let bytes = serde_json::to_vec(&value).unwrap();
            let written = round_trip(name, &bytes).unwrap_or_else(|error| panic!("{name} could not be read by the type that owns it: {error}"));
            std::fs::write(folder.join(name), &written).unwrap();
        }
    }

    /// PROVES that every frozen record reads back into this build's types and writes out as
    /// exactly the bytes it was, so a field added, removed, renamed, newly defaulted or given a
    /// different serialised name fails the build.
    ///
    /// DOES NOT PROVE that a type nobody wrote a fixture for is frozen, and does not prove
    /// anything about what releases before this one wrote: the fixtures are made from the
    /// working tree, so the freeze begins here. It also cannot see a new optional field that is
    /// skipped when it is empty, because such a field round-trips unchanged; that is what the
    /// exhaustive destructuring tests in `crate::hub` and `crate::bounty` are for.
    #[test]
    fn a_frozen_record_reads_and_writes_back_exactly_as_it_was() {
        for contract in contracts() {
            let bytes = fixture_bytes(contract.fixture);
            let again = round_trip(contract.fixture, &bytes).unwrap_or_else(|error| panic!("{} no longer reads: {error}", contract.fixture));
            assert_eq!(
                String::from_utf8_lossy(&again),
                String::from_utf8_lossy(&bytes),
                "{} is no longer what {} writes. A frozen contract changed; docs/grid-core/frozen-contracts.md says what a change has to do.",
                contract.fixture,
                contract.rust_type
            );
        }
    }

    /// PROVES that the folder holds exactly the fixtures the register names, with the bytes it
    /// names, so a fixture cannot be deleted, added or edited without the register and the
    /// rendered document moving with it.
    ///
    /// DOES NOT PROVE that the fixtures still represent what the products write. Only the
    /// round-trip above says that.
    #[test]
    fn every_fixture_is_the_one_the_register_names() {
        let folder = fixture_folder();
        let mut found: Vec<String> = std::fs::read_dir(&folder)
            .unwrap_or_else(|error| panic!("{} is part of this repository: {error}", folder.display()))
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .collect();
        found.sort();
        assert_eq!(found.len(), FIXTURES, "the fixture folder holds {found:?} and the register says there are {FIXTURES}");
        for contract in contracts() {
            assert!(found.contains(&contract.fixture.to_owned()), "{} is named by the register and is not in the folder", contract.fixture);
            let bytes = fixture_bytes(contract.fixture);
            assert_eq!(
                digest(&bytes),
                contract.fixture_sha256,
                "{} is not the file the register names. If the change was deliberate, put {} in contracts().",
                contract.fixture,
                digest(&bytes)
            );
        }
    }

    /// PROVES that every frozen record still reads with the loader the product that wrote it
    /// uses, which is the promise that the read-only import tools stay available.
    ///
    /// DOES NOT PROVE that a record damaged on a real disk reads. It proves the shapes are still
    /// understood, not that any particular file is intact.
    #[test]
    fn every_frozen_record_still_reads_with_the_loader_that_wrote_it() {
        for contract in contracts() {
            let path = fixture_folder().join(contract.fixture);
            let reading = super::super::rollout::read_record(&path).unwrap_or_else(|error| panic!("{} no longer reads: {error}", contract.fixture));
            assert_eq!(reading.version, Some(contract.version), "{} is not at the version the register says", contract.fixture);
            assert!(reading.grid_id.is_some(), "{} should name the grid it belongs to", contract.fixture);
            assert!(!reading.counts.is_empty(), "{} should be countable", contract.fixture);
        }
    }

    /// PROVES that what a file's bytes say they are is what the register says they are, so a
    /// record found on a disk years from now is recognised without being told what it is.
    ///
    /// DOES NOT PROVE that the two grids can be told apart. They keep one type in two files and
    /// nothing in the bytes distinguishes them, which `Shape` says in its own words.
    #[test]
    fn a_record_says_what_shape_it_is_without_being_told() {
        assert_eq!(recognise(&fixture_bytes("neo-hub-v1.json")), Some(Shape::Hub));
        assert_eq!(recognise(&fixture_bytes("sandbox-hub-v1.json")), Some(Shape::Hub));
        assert_eq!(recognise(&fixture_bytes("bounty-host-v1.json")), Some(Shape::BountyHost));
        assert_eq!(recognise(&fixture_bytes("access-hub-v1.json")), Some(Shape::AccessHub));
        assert_eq!(recognise(b"{}"), None);
        assert_eq!(recognise(b"not json at all"), None);
        assert_eq!(Shape::Hub.products().len(), 2, "one type, two products, and the file it came from is what tells them apart");
    }

    /// PROVES the two forward-compatibility behaviours the register claims: three of the Sandbox
    /// Grid's enterprise types refuse the whole record when they meet a field they do not know,
    /// because they carry `deny_unknown_fields`, and everything else ignores it and loses it on
    /// the next save. The document cannot drift from this, because this is what it is rendered
    /// beside.
    ///
    /// DOES NOT PROVE that either behaviour is the right one. It pins what is true today so a
    /// change to it is a decision somebody makes rather than one that happens.
    #[test]
    fn three_enterprise_types_refuse_an_unknown_field_and_the_rest_drop_it() {
        let add = |where_to: &dyn Fn(&mut Value)| {
            let mut value = hub_record("grid-0123456789abcdef", "Example Models");
            where_to(&mut value);
            crate::hub::read(&serde_json::to_vec(&value).unwrap())
        };
        for (what, put) in [
            ("an image", Box::new(|value: &mut Value| value["enterprise"]["images"][0]["invented"] = json!(1)) as Box<dyn Fn(&mut Value)>),
            ("a workspace role", Box::new(|value: &mut Value| value["enterprise"]["roles"][0]["invented"] = json!(1))),
            ("a connector", Box::new(|value: &mut Value| value["enterprise"]["connections"][0]["invented"] = json!(1))),
        ] {
            assert!(add(&put).is_err(), "a field added to {what} makes the whole record unreadable by every older build");
        }
        for (what, put) in [
            ("the record itself", Box::new(|value: &mut Value| value["invented"] = json!(1)) as Box<dyn Fn(&mut Value)>),
            ("a computer", Box::new(|value: &mut Value| value["members"][0]["invented"] = json!(1))),
            ("a desk", Box::new(|value: &mut Value| value["desks"][0]["invented"] = json!(1))),
            ("a person", Box::new(|value: &mut Value| value["people"][0]["invented"] = json!(1))),
            ("a plan", Box::new(|value: &mut Value| value["plans"][0]["invented"] = json!(1))),
        ] {
            let record = add(&put).unwrap_or_else(|error| panic!("a field added to {what} should be ignored, and was refused: {error}"));
            let written = serde_json::to_string(&record).unwrap();
            assert!(!written.contains("invented"), "a field added to {what} is lost the next time the record is saved, which is quieter than a refusal and worse");
        }
    }

    /// PROVES that no fixture carries anything that could have come from a deployment: every
    /// name in one is under `.invalid`, every address is a private one, and every certificate,
    /// sealed value and secret-shaped string says in its own text that it is a fixture.
    ///
    /// DOES NOT PROVE that a future fixture is safe. It checks the strings these fixtures hold,
    /// so a new fixture carrying something new has to be added to this check.
    #[test]
    fn a_fixture_carries_nothing_a_deployment_ever_held() {
        for contract in contracts() {
            let text = String::from_utf8(fixture_bytes(contract.fixture)).unwrap();
            for line in text.lines() {
                let lower = line.to_ascii_lowercase();
                if lower.contains("certificate") || lower.contains("\"sealed\"") || lower.contains("totp") || lower.contains("sshpublickey") {
                    assert!(line.contains("FIXTURE"), "{}: {} should say in its own text that it is made up", contract.fixture, line.trim());
                }
                if lower.contains("https://") || lower.contains("@") {
                    assert!(
                        line.contains("example.invalid") || line.contains("FIXTURE"),
                        "{}: {} names something outside the reserved .invalid domain",
                        contract.fixture,
                        line.trim()
                    );
                }
            }
            assert!(!text.contains("192.168.") && !text.contains("172.1"), "{} should use one private range, 10.0.0.x, so the fixtures read as one set", contract.fixture);
        }
    }

    /// PROVES that nothing this crate ships compiles in the path of the computer that built it.
    /// `env!("CARGO_MANIFEST_DIR")` expands to an absolute path on the build machine, which in
    /// this repository is somebody's home folder, and it has to stay behind `cfg(test)`. The
    /// fixture folder is the easy place to lose that, because the helper that names it sits in a
    /// module the rest of which is shipped.
    ///
    /// DOES NOT PROVE anything about the compiled artefact, or about any other crate: it reads
    /// this crate's source. A `#[cfg(test)]` written above something it does not actually cover
    /// would pass here. It guards the mistake that happened, which is the attribute being absent.
    #[test]
    fn nothing_this_crate_ships_compiles_in_the_path_of_the_machine_that_built_it() {
        let mut folders = vec![Path::new(env!("CARGO_MANIFEST_DIR")).join("src")];
        let mut unguarded: Vec<String> = Vec::new();
        while let Some(folder) = folders.pop() {
            for entry in std::fs::read_dir(&folder).expect("this crate's own source").flatten() {
                let path = entry.path();
                if path.is_dir() {
                    folders.push(path);
                    continue;
                }
                if path.extension().is_none_or(|extension| extension != "rs") {
                    continue;
                }
                // A file named `tests.rs` is only ever declared behind `#[cfg(test)] mod tests;`.
                if path.file_name().is_some_and(|name| name == "tests.rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&path).expect("a source file of this crate");
                let lines: Vec<&str> = text.lines().collect();
                let mut in_the_test_module = false;
                for (at, line) in lines.iter().enumerate() {
                    if line.trim_start().starts_with("mod tests") && at > 0 && lines[at - 1].trim() == "#[cfg(test)]" {
                        in_the_test_module = true;
                    }
                    if !line.contains("CARGO_MANIFEST_DIR") || line.trim_start().starts_with("//") {
                        continue;
                    }
                    let guarded = in_the_test_module || lines[at.saturating_sub(8)..at].iter().any(|above| above.trim() == "#[cfg(test)]");
                    if !guarded {
                        unguarded.push(format!("{}:{}", path.display(), at + 1));
                    }
                }
            }
        }
        assert!(unguarded.is_empty(), "these reach for the build machine's own path outside the tests: {unguarded:?}");
    }

    const DOCUMENT: &str = "../docs/grid-core/frozen-contracts.md";
    const RENDERED_FROM: &str = "## What a forward-compatibility state means";
    const RENDERED_TO: &str = "\n## What a change to a frozen contract has to do";

    fn document() -> (PathBuf, String) {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(DOCUMENT);
        let text = std::fs::read_to_string(&path).expect("docs/grid-core/frozen-contracts.md is part of this repository").replace("\r\n", "\n");
        (path, text)
    }

    /// Puts what the register renders back into the document, leaving the prose around it alone.
    /// Ignored because it writes to the repository: run it on purpose, with
    /// `cargo test rewrite_the_frozen_contracts -- --ignored`, after changing the register.
    #[test]
    #[ignore]
    fn rewrite_the_frozen_contracts() {
        let (path, text) = document();
        let from = text.find(RENDERED_FROM).expect("the document still has the heading the register renders first");
        let to = text.find(RENDERED_TO).expect("the document still has the heading that follows the last table");
        std::fs::write(&path, format!("{}{}{}", &text[..from], matrix(), &text[to..])).unwrap();
    }

    /// PROVES that docs/grid-core/frozen-contracts.md holds exactly what the register renders,
    /// so the document cannot say a record is frozen that the code does not freeze.
    ///
    /// DOES NOT PROVE that the register's claims are true of any customer's disk. It proves the
    /// document matches the code.
    #[test]
    fn the_frozen_contracts_in_the_documentation_are_the_ones_in_the_code() {
        let (_, text) = document();
        assert!(
            text.contains(&matrix()),
            "docs/grid-core/frozen-contracts.md is no longer what core::compat::frozen renders. Run `cargo test rewrite_the_frozen_contracts -- --ignored` to put it back."
        );
        for state in [Forward::Gated, Forward::Dropped, Forward::Refused] {
            assert_eq!(
                text.matches(state.name()).count(),
                matrix().matches(state.name()).count(),
                "the document says {} in a place the register did not put it",
                state.name()
            );
        }
        for sentence in ["not frozen", "never a value", "begins here"] {
            assert!(text.contains(sentence), "the document has to say plainly what is {sentence}");
        }
    }

    /// PROVES that the register names a vault entry for every record and never a value, and that
    /// the realm's own entry is rendered from the code that mints it rather than typed out.
    ///
    /// DOES NOT PROVE that any of those entries is present on this computer. Reading a vault is
    /// the application's half; the runbook's step is to prove them before a migration.
    #[test]
    fn the_register_names_vault_entries_and_never_values() {
        for contract in contracts() {
            assert!(!contract.vault.is_empty(), "{} must say what it cannot be used without", contract.name);
            for entry in contract.vault {
                assert!(entry.starts_with("yougori-"), "{entry} is not the name of one of this product's vault entries");
            }
        }
        assert_eq!(realm_key_entry(), "yougori-core-<realm-id>", "the realm's own entry is rendered from KeyReference::for_realm");
        let rendered = matrix();
        for secret in ["FIXTURE CERTIFICATE", "FIXTURE-SEALED", "aaaaaaaa"] {
            assert!(!rendered.contains(secret), "the rendered register must carry no value of anything");
        }
    }

    /// PROVES that every shipped product names the bridge that brings it across, and that a
    /// product added later without one would have to say so in words rather than by omission.
    ///
    /// DOES NOT PROVE that any of the four bridges has run beside a product that is serving.
    #[test]
    fn every_product_names_the_bridge_that_brings_it_across() {
        let bridged: Vec<&str> = contracts().iter().filter(|contract| contract.bridge.imports()).map(|contract| contract.product.word()).collect();
        assert_eq!(bridged, vec!["neo", "sandbox", "swarm", "access"], "all four shipped products have a bridge");
        for contract in contracts() {
            assert!(contract.bridge.says().contains("rehearse, import, roll back and compare"), "{} has to say what brings it across", contract.name);
        }
        // And the machinery for a product that has none is still here and still says so in words.
        assert!(!Bridge::None("nothing: it was added without one").imports());
        assert!(Bridge::None("nothing: it was added without one").says().starts_with("nothing:"));
    }
}
