//! The shape of a realm's database, and how it moves between versions.
//!
//! One database per realm. Realms never share a file, so the trust boundary is also a physical
//! one: a research realm's database holds nothing of the company's, and no query can cross
//! between them because there is nothing to cross.
//!
//! The realm's key is never here. What is stored is the name of the vault entry that holds it,
//! which version it is, and a check value that says whether a key offered later is the right one.

/// The version this build writes. Every change of shape raises it and adds a step below.
pub const VERSION: u32 = 13;

/// Everything version 1 holds.
pub const V1: &str = r#"
CREATE TABLE realms (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    kind            TEXT NOT NULL CHECK (kind IN ('primary','research')),
    capabilities    TEXT NOT NULL,
    network         TEXT NOT NULL,
    lifecycle       TEXT NOT NULL,
    key_id          TEXT NOT NULL,
    key_version     INTEGER NOT NULL,
    key_check       TEXT NOT NULL,
    generation      INTEGER NOT NULL DEFAULT 1,
    policy_version  INTEGER NOT NULL DEFAULT 1,
    created_at      INTEGER NOT NULL
);

CREATE TABLE principals (
    id           TEXT PRIMARY KEY,
    realm_id     TEXT NOT NULL REFERENCES realms(id),
    kind         TEXT NOT NULL,
    name         TEXT NOT NULL,
    email        TEXT,
    created_at   INTEGER NOT NULL,
    suspended_at INTEGER,
    generation   INTEGER NOT NULL DEFAULT 1
);

-- What someone may do, one row per permission. A permission that comes with another is stored
-- in its own right, with the one it came from named, so administering and approving are never
-- the same row.
CREATE TABLE permissions (
    id           TEXT PRIMARY KEY,
    realm_id     TEXT NOT NULL REFERENCES realms(id),
    principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    permission   TEXT NOT NULL,
    derived_from TEXT,
    granted_by   TEXT NOT NULL,
    granted_at   INTEGER NOT NULL,
    UNIQUE (principal_id, permission)
);

CREATE TABLE devices (
    id           TEXT PRIMARY KEY,
    realm_id     TEXT NOT NULL REFERENCES realms(id),
    principal_id TEXT NOT NULL REFERENCES principals(id),
    name         TEXT NOT NULL,
    platform     TEXT NOT NULL,
    token_hash   TEXT NOT NULL,
    attestation  TEXT NOT NULL,
    enrolled_at  INTEGER NOT NULL,
    last_seen_at INTEGER,
    revoked_at   INTEGER,
    generation   INTEGER NOT NULL DEFAULT 1
);

-- Every withdrawal of trust, and the generation it moved the subject to. A permission issued
-- under an older generation is refused when it is used.
CREATE TABLE revocations (
    id         TEXT PRIMARY KEY,
    realm_id   TEXT NOT NULL REFERENCES realms(id),
    subject    TEXT NOT NULL CHECK (subject IN ('realm','principal','device')),
    subject_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    revoked_by TEXT NOT NULL,
    revoked_at INTEGER NOT NULL,
    reason     TEXT NOT NULL DEFAULT ''
);

CREATE TABLE hosts (
    id            TEXT PRIMARY KEY,
    realm_id      TEXT NOT NULL REFERENCES realms(id),
    device_id     TEXT NOT NULL REFERENCES devices(id),
    name          TEXT NOT NULL,
    capacity      TEXT NOT NULL,
    offered       TEXT NOT NULL,
    gpu_isolation TEXT NOT NULL,
    commitment    TEXT NOT NULL,
    draining      INTEGER NOT NULL DEFAULT 0,
    joined_at     INTEGER NOT NULL
);

CREATE TABLE workloads (
    id             TEXT PRIMARY KEY,
    realm_id       TEXT NOT NULL REFERENCES realms(id),
    capability     TEXT NOT NULL,
    kind           TEXT NOT NULL,
    principal_id   TEXT NOT NULL,
    device_id      TEXT NOT NULL,
    stage          TEXT NOT NULL,
    needs          TEXT NOT NULL,
    policy_version INTEGER NOT NULL,
    lease_id       TEXT,
    note           TEXT,
    created_at     INTEGER NOT NULL,
    updated_at     INTEGER NOT NULL,
    expires_at     INTEGER
);

CREATE TABLE leases (
    id          TEXT PRIMARY KEY,
    realm_id    TEXT NOT NULL REFERENCES realms(id),
    host_id     TEXT NOT NULL REFERENCES hosts(id),
    workload_id TEXT NOT NULL REFERENCES workloads(id),
    resources   TEXT NOT NULL,
    generation  INTEGER NOT NULL,
    granted_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    released_at INTEGER
);

CREATE TABLE requests (
    id           TEXT PRIMARY KEY,
    realm_id     TEXT NOT NULL REFERENCES realms(id),
    action       TEXT NOT NULL,
    resource_id  TEXT NOT NULL,
    method       TEXT,
    path         TEXT,
    requested_by TEXT NOT NULL REFERENCES principals(id),
    requested_at INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    every_time   INTEGER NOT NULL DEFAULT 0,
    state        TEXT NOT NULL CHECK (state IN ('waiting','granted','refused','expired'))
);

-- Written once and never changed: there is no path in the code that updates or deletes a row
-- here, and one request can hold only one decision.
CREATE TABLE decisions (
    id           TEXT PRIMARY KEY,
    request_id   TEXT NOT NULL UNIQUE REFERENCES requests(id),
    realm_id     TEXT NOT NULL REFERENCES realms(id),
    verdict      TEXT NOT NULL CHECK (verdict IN ('approve_once','approve_until','deny')),
    until        INTEGER,
    decided_by   TEXT NOT NULL REFERENCES principals(id),
    decided_at   INTEGER NOT NULL,
    self_issued  INTEGER NOT NULL DEFAULT 0,
    reason       TEXT NOT NULL DEFAULT '',
    allowance_id TEXT
);

CREATE TABLE standing_allowances (
    id           TEXT PRIMARY KEY,
    realm_id     TEXT NOT NULL REFERENCES realms(id),
    principal_id TEXT NOT NULL REFERENCES principals(id),
    resource_id  TEXT NOT NULL,
    method       TEXT,
    path         TEXT,
    approver_id  TEXT NOT NULL REFERENCES principals(id),
    request_id   TEXT NOT NULL REFERENCES requests(id),
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL
);

-- Each permission handed to a piece of work, with the generations it was issued under, so its
-- use can be checked against what is true now.
CREATE TABLE capabilities (
    id            TEXT PRIMARY KEY,
    realm_id      TEXT NOT NULL REFERENCES realms(id),
    capability    TEXT NOT NULL,
    principal_id  TEXT NOT NULL,
    device_id     TEXT NOT NULL,
    workload_id   TEXT NOT NULL,
    resource_id   TEXT NOT NULL,
    realm_gen     INTEGER NOT NULL,
    principal_gen INTEGER NOT NULL,
    device_gen    INTEGER NOT NULL,
    policy_version INTEGER NOT NULL DEFAULT 1,
    single_use    INTEGER NOT NULL DEFAULT 1,
    issued_at     INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    spent_at      INTEGER
);

-- The chain's own details, apart from the realm's ordinary records: which key seals it, which
-- version of that key, and where the chain has got to.
CREATE TABLE audit_chain (
    realm_id      TEXT PRIMARY KEY REFERENCES realms(id),
    key_id        TEXT NOT NULL,
    key_version   INTEGER NOT NULL,
    head_seal     TEXT NOT NULL,
    head_sequence INTEGER NOT NULL,
    exported_to   INTEGER NOT NULL DEFAULT 0,
    started_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
);

CREATE TABLE audit_events (
    sequence       INTEGER PRIMARY KEY,
    id             TEXT NOT NULL UNIQUE,
    realm_id       TEXT NOT NULL REFERENCES realms(id),
    at             INTEGER NOT NULL,
    capability     TEXT,
    principal_id   TEXT NOT NULL,
    device_id      TEXT,
    workload_id    TEXT,
    action         TEXT NOT NULL,
    resource_id    TEXT,
    policy_version INTEGER NOT NULL,
    decision       TEXT NOT NULL,
    reason         TEXT NOT NULL DEFAULT '',
    previous_seal  TEXT NOT NULL,
    seal           TEXT NOT NULL
);

-- A decision stands as it was made. Nothing in this build updates or deletes one, and these say
-- so to anything that opens the file with another tool.
CREATE TRIGGER decisions_never_change BEFORE UPDATE ON decisions
BEGIN SELECT RAISE(ABORT, 'a decision cannot be changed once it is made'); END;

CREATE TRIGGER decisions_never_vanish BEFORE DELETE ON decisions
BEGIN SELECT RAISE(ABORT, 'a decision cannot be withdrawn once it is made'); END;

CREATE TRIGGER audit_events_never_change BEFORE UPDATE ON audit_events
BEGIN SELECT RAISE(ABORT, 'an event cannot be changed once it is recorded'); END;

-- Old events are dropped only once they have been exported somewhere the hub cannot reach.
CREATE TRIGGER audit_events_keep_until_exported BEFORE DELETE ON audit_events
WHEN OLD.sequence > COALESCE((SELECT exported_to FROM audit_chain WHERE realm_id = OLD.realm_id), 0)
BEGIN SELECT RAISE(ABORT, 'this event has not been exported yet'); END;

CREATE INDEX permissions_by_principal ON permissions (principal_id);
CREATE INDEX devices_by_principal ON devices (principal_id);
CREATE INDEX revocations_by_subject ON revocations (subject, subject_id);
CREATE INDEX leases_by_host ON leases (host_id, released_at);
CREATE INDEX workloads_by_stage ON workloads (stage);
CREATE INDEX requests_by_state ON requests (state, expires_at);
CREATE INDEX allowances_by_holder ON standing_allowances (principal_id, resource_id, expires_at);
CREATE INDEX capabilities_by_expiry ON capabilities (expires_at);
"#;

/// What version 2 adds: credentials the realm holds on someone's behalf, and who may use them.
///
/// There is no column here for a value, and there never will be. What is kept is the name of the
/// vault entry holding the secret, which version of it, a fingerprint for telling one from
/// another, and the single destination it may be sent to.
pub const V2: &str = r#"
ALTER TABLE capabilities ADD COLUMN approval_id TEXT;

CREATE TABLE credentials (
    id            TEXT PRIMARY KEY,
    realm_id      TEXT NOT NULL REFERENCES realms(id),
    name          TEXT NOT NULL,
    kind          TEXT NOT NULL,
    vault_id      TEXT NOT NULL,
    vault_version INTEGER NOT NULL DEFAULT 1,
    fingerprint   TEXT NOT NULL,
    destination   TEXT NOT NULL,
    methods       TEXT NOT NULL DEFAULT '[]',
    paths         TEXT NOT NULL DEFAULT '[]',
    maximum_bytes INTEGER,
    owner_id      TEXT NOT NULL REFERENCES principals(id),
    every_time    INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL,
    rotated_at    INTEGER,
    rotate_by     INTEGER,
    retired_at    INTEGER,
    generation    INTEGER NOT NULL DEFAULT 1,
    UNIQUE (realm_id, name)
);

CREATE TABLE credential_grants (
    id            TEXT PRIMARY KEY,
    realm_id      TEXT NOT NULL REFERENCES realms(id),
    credential_id TEXT NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    principal_id  TEXT NOT NULL REFERENCES principals(id),
    methods       TEXT NOT NULL DEFAULT '[]',
    paths         TEXT NOT NULL DEFAULT '[]',
    granted_by    TEXT NOT NULL,
    granted_at    INTEGER NOT NULL,
    expires_at    INTEGER,
    UNIQUE (credential_id, principal_id)
);

CREATE INDEX credential_grants_by_holder ON credential_grants (principal_id, credential_id);
CREATE INDEX capabilities_by_approval ON capabilities (approval_id);
"#;

/// What version 3 adds: the model serving profile. Plans and assignments are kept in the same
/// realm database as identity and leases, while model inputs and outputs remain outside it.
pub const V3: &str = r#"
CREATE TABLE model_plans (
    id          TEXT PRIMARY KEY,
    realm_id    TEXT NOT NULL REFERENCES realms(id),
    model       TEXT NOT NULL,
    quant       TEXT,
    percent     INTEGER NOT NULL CHECK (percent BETWEEN 1 AND 100),
    policy      TEXT NOT NULL,
    target      TEXT NOT NULL,
    created_at  INTEGER NOT NULL
);

CREATE TABLE model_assignments (
    plan_id     TEXT NOT NULL REFERENCES model_plans(id) ON DELETE CASCADE,
    host_id     TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    assigned_at INTEGER NOT NULL,
    PRIMARY KEY (plan_id, host_id),
    UNIQUE (host_id)
);

CREATE INDEX model_assignments_by_host ON model_assignments (host_id);
"#;

/// What version 4 adds: workspaces, the desks a company's people sign in to. Metadata,
/// ownership, quotas and lifecycle only.
///
/// There is no column here for a person's files, and there never will be. What is kept is where
/// the data is and what it hashes to, never what it says. A workspace that is running keeps its
/// disk on the computer that holds its placement, named here by whatever that computer calls the
/// sandbox; a workspace that is moving keeps its disk in one packed file with the hub or in the
/// company's own bucket, named here by a key and a checksum. Neither is ever a folder on
/// anybody's machine, and the checks below refuse one.
pub const V4: &str = r#"
-- The pair of numbers a permission was issued under, beside the account, computer and policy
-- generations the row already carries. A workspace permission is refused at the moment of use
-- once its workspace has moved on, in the same mechanism that refuses a suspended account,
-- rather than in a check beside it that one caller might forget.
ALTER TABLE capabilities ADD COLUMN resource_gen INTEGER;

-- An image is known by what it is, not only by what it is called. A name and a version are a
-- label for people; the digest is the identity. The digest may be unknown at first, because the
-- product's own default image is an OCI tag and refusing that would mean no container workspace
-- could be recorded at all. It is written down the first time a computer fetches the bytes and
-- hashes them, and from then on two labels cannot name the same bytes.
CREATE TABLE workspace_images (
    id            TEXT PRIMARY KEY,
    realm_id      TEXT NOT NULL REFERENCES realms(id),
    name          TEXT NOT NULL,
    version       TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    kind          TEXT NOT NULL CHECK (kind IN ('container','microVm','vm')),
    digest        TEXT CHECK (digest IS NULL OR (length(digest) = 71 AND substr(digest, 1, 7) = 'sha256:')),
    -- Which sort of place the bytes come from, and the rest of it as it was written. The real
    -- check is in Rust, in ImageSource::checked, because what makes an address acceptable is not
    -- something a prefix test can decide; this says which of the five it is.
    source_kind   TEXT NOT NULL CHECK (source_kind IN ('oci','hub','https','media','builtin')),
    source        TEXT NOT NULL CHECK (length(source) <= 4096),
    bytes         INTEGER CHECK (bytes IS NULL OR bytes > 0),
    shape         TEXT NOT NULL,
    applications  TEXT NOT NULL DEFAULT '[]',
    published_by  TEXT NOT NULL REFERENCES principals(id),
    published_at  INTEGER NOT NULL,
    -- When the hub last saw these bytes hash to the digest above.
    verified_at   INTEGER,
    retired_at    INTEGER,
    UNIQUE (realm_id, name, version),
    UNIQUE (realm_id, digest)
);

-- One workspace: who it belongs to, what it is built from, how large it may grow, and where it
-- is in its life. A workspace with nobody owning it still exists and still holds its data; what
-- it cannot do is let anyone in.
CREATE TABLE workspaces (
    id            TEXT PRIMARY KEY,
    realm_id      TEXT NOT NULL REFERENCES realms(id),
    name          TEXT NOT NULL,
    owner_id      TEXT REFERENCES principals(id),
    image_id      TEXT NOT NULL REFERENCES workspace_images(id),
    -- The digest it was last built from, when anybody knows it, so a retired image still names
    -- what is running.
    image_digest  TEXT CHECK (image_digest IS NULL OR length(image_digest) = 71),
    shape         TEXT NOT NULL,
    access        TEXT NOT NULL CHECK (access IN ('standard','restricted')),
    quota         TEXT NOT NULL,
    state         TEXT NOT NULL CHECK (state IN
                      ('requested','provisioning','ready','assigned','running','draining','archived','failed')),
    note          TEXT NOT NULL DEFAULT '',
    -- Raised whenever ownership or entitlement changes. Only ever rises; see the trigger below.
    generation    INTEGER NOT NULL DEFAULT 1 CHECK (generation > 0),
    attempts      INTEGER NOT NULL DEFAULT 0,
    reset_count   INTEGER NOT NULL DEFAULT 0,
    ordered_by    TEXT NOT NULL REFERENCES principals(id),
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL,
    archived_at   INTEGER,
    UNIQUE (realm_id, name),
    -- A workspace nobody owns can never be in a state that lets somebody open it.
    CHECK (owner_id IS NOT NULL OR state NOT IN ('assigned','running'))
);

-- Where a workspace has been placed, one row per attempt. The piece of work that put it there
-- carries the ordinary Stage lifecycle; this row carries the placement's own number.
--
-- The rows stay for as long as the workspace does, so the trail leads back to the computers that
-- have held its data. Forgetting a workspace takes them with it, and says so.
CREATE TABLE workspace_assignments (
    id             TEXT PRIMARY KEY,
    realm_id       TEXT NOT NULL REFERENCES realms(id),
    workspace_id   TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    -- No action on the computer: a computer that offers again under another identity has these
    -- rows moved onto it by put_host, because a trail that vanished when somebody re-offered
    -- their laptop would not be a trail.
    host_id        TEXT NOT NULL REFERENCES hosts(id),
    generation     INTEGER NOT NULL CHECK (generation > 0),
    -- The workspace generation this placement was made under.
    workspace_gen  INTEGER NOT NULL CHECK (workspace_gen > 0),
    workload_id    TEXT NOT NULL REFERENCES workloads(id),
    -- What the computer calls the sandbox it built. Opaque to the realm, and never a path.
    placement_ref  TEXT CHECK (placement_ref IS NULL OR
                      (length(placement_ref) <= 64 AND placement_ref NOT GLOB '*[/\:]*')),
    placed_at      INTEGER NOT NULL,
    ready_at       INTEGER,
    released_at    INTEGER,
    release_reason TEXT NOT NULL DEFAULT '',
    UNIQUE (workspace_id, generation)
);

-- One live placement at a time, refused by the database rather than by a convention in the code.
CREATE UNIQUE INDEX workspace_one_live_placement
    ON workspace_assignments (workspace_id) WHERE released_at IS NULL;

-- A workspace's packed-up data while it moves or waits: a reference and a checksum. There is no
-- column that could hold the data itself, and the key cannot be a place on a computer.
CREATE TABLE workspace_artifacts (
    id             TEXT PRIMARY KEY,
    realm_id       TEXT NOT NULL REFERENCES realms(id),
    workspace_id   TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    workspace_gen  INTEGER NOT NULL CHECK (workspace_gen > 0),
    store          TEXT NOT NULL CHECK (store IN ('hub','bucket')),
    -- Which bucket, so the computer taking the workspace over can find it. The keys that open it
    -- are in the hub computer's vault and are not in this database.
    destination    TEXT NOT NULL DEFAULT '' CHECK (length(destination) <= 2048 AND destination NOT LIKE '%@%'),
    object_key     TEXT NOT NULL CHECK (
                       length(object_key) BETWEEN 1 AND 1024
                       AND object_key NOT GLOB '/*'
                       AND object_key NOT GLOB '[A-Za-z]:*'
                       AND object_key NOT GLOB '*..*'
                       AND object_key NOT GLOB '*\*'),
    bytes          INTEGER NOT NULL CHECK (bytes > 0),
    sha256         TEXT NOT NULL CHECK (length(sha256) = 64),
    packed_by      TEXT NOT NULL REFERENCES hosts(id),
    packed_at      INTEGER NOT NULL,
    taken_at       INTEGER,
    removed_at     INTEGER
);

-- A permission minted to open a workspace, with the pair of numbers it was minted under.
--
-- capability_id names a row in capabilities and deliberately does not reference it: expired
-- permissions are tidied away by forget_expired_capabilities, and a foreign key here would take
-- the record of who was in which workspace with them during routine housekeeping.
CREATE TABLE workspace_sessions (
    capability_id  TEXT PRIMARY KEY,
    realm_id       TEXT NOT NULL REFERENCES realms(id),
    workspace_id   TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    principal_id   TEXT NOT NULL REFERENCES principals(id),
    device_id      TEXT NOT NULL REFERENCES devices(id),
    host_id        TEXT NOT NULL REFERENCES hosts(id),
    workspace_gen  INTEGER NOT NULL,
    assignment_gen INTEGER NOT NULL,
    opened_at      INTEGER NOT NULL,
    expires_at     INTEGER NOT NULL,
    ended_at       INTEGER,
    ended_reason   TEXT NOT NULL DEFAULT ''
);

-- How a computer was committed to the realm, in its own right and insert-only, so dedicating one
-- and taking that back are two records rather than one field overwritten.
--
-- What the realm may run on a computer is here. What it may read of its person's own files is
-- nowhere, because no such permission exists in this grid: there is no column in this version
-- naming a folder on a computer, and no capability whose resource is anything but a workspace
-- this realm itself created.
CREATE TABLE host_commitments (
    id            TEXT PRIMARY KEY,
    realm_id      TEXT NOT NULL REFERENCES realms(id),
    host_id       TEXT NOT NULL REFERENCES hosts(id),
    commitment    TEXT NOT NULL CHECK (commitment IN ('share','dedicated','none')),
    offered       TEXT NOT NULL,
    idle_only     INTEGER NOT NULL DEFAULT 0,
    -- The exact words the person agreed to, kept so the agreement can be read back later.
    wording       TEXT NOT NULL,
    committed_by  TEXT NOT NULL REFERENCES principals(id),
    committed_at  INTEGER NOT NULL,
    withdrawn_by  TEXT REFERENCES principals(id),
    withdrawn_at  INTEGER
);

-- What a computer last said about itself. These decide, on their own, whether a workspace may be
-- placed there, so they are the person's protection rather than an optimisation. Unlike the
-- trail, this is only ever the latest answer, so it goes when the computer's row goes.
CREATE TABLE host_conditions (
    host_id       TEXT PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    realm_id      TEXT NOT NULL REFERENCES realms(id),
    on_battery    INTEGER NOT NULL DEFAULT 0,
    free_disk_gb  REAL NOT NULL DEFAULT 0,
    in_use        INTEGER NOT NULL DEFAULT 0,
    going_away    INTEGER NOT NULL DEFAULT 0,
    reported_at   INTEGER NOT NULL
);

-- A workspace generation only rises, so a number that has been left behind can never come back.
-- It fires on lowering alone, because SQLite fires BEFORE UPDATE OF whenever the column is named
-- in the SET at all, and every ordinary save here writes every column.
CREATE TRIGGER workspace_generation_only_rises BEFORE UPDATE OF generation ON workspaces
WHEN NEW.generation < OLD.generation
BEGIN SELECT RAISE(ABORT, 'a workspace generation only rises'); END;

-- A placement number is never handed out twice for the same workspace, so a computer that has
-- been left behind cannot be given a number it already has.
CREATE TRIGGER workspace_placement_number_never_repeats BEFORE INSERT ON workspace_assignments
WHEN NEW.generation <= COALESCE((SELECT MAX(generation) FROM workspace_assignments WHERE workspace_id = NEW.workspace_id), 0)
BEGIN SELECT RAISE(ABORT, 'a placement cannot take a number this workspace has already used'); END;

-- A placement that was given back stays given back.
CREATE TRIGGER workspace_placement_release_is_final BEFORE UPDATE OF released_at ON workspace_assignments
WHEN OLD.released_at IS NOT NULL AND NEW.released_at IS NOT OLD.released_at
BEGIN SELECT RAISE(ABORT, 'a placement that was given back cannot be taken up again'); END;

-- Forgetting a workspace is always two steps: it is archived first, so a delete is never the
-- first thing that happens to somebody's desk.
CREATE TRIGGER workspaces_are_archived_before_they_are_forgotten BEFORE DELETE ON workspaces
WHEN OLD.state <> 'archived'
BEGIN SELECT RAISE(ABORT, 'archive this workspace before forgetting it'); END;

-- A commitment is recorded as it was made; withdrawing it writes the withdrawal into the same
-- row and changes nothing else.
CREATE TRIGGER host_commitments_never_change
BEFORE UPDATE OF commitment, offered, idle_only, wording, committed_by, committed_at ON host_commitments
BEGIN SELECT RAISE(ABORT, 'a commitment is recorded as it was made; withdraw it and make another'); END;

CREATE INDEX workspaces_by_owner ON workspaces (owner_id, state);
CREATE INDEX workspaces_by_state ON workspaces (state, updated_at);
CREATE INDEX workspace_assignments_by_host ON workspace_assignments (host_id, released_at);
CREATE INDEX workspace_assignments_by_workspace ON workspace_assignments (workspace_id, generation DESC);
CREATE INDEX workspace_artifacts_by_workspace ON workspace_artifacts (workspace_id, removed_at);
CREATE INDEX workspace_sessions_by_workspace ON workspace_sessions (workspace_id, ended_at);
CREATE INDEX workspace_sessions_by_principal ON workspace_sessions (principal_id, ended_at);
CREATE INDEX host_commitments_by_host ON host_commitments (host_id, withdrawn_at);
"#;

/// What version 5 adds: the credential broker.
///
/// The broker is the only thing in a realm that reads a value, and it reads it from the vault at
/// the moment it sends. What is added here is how a credential travels on a request, which places
/// it may be sent to, and one row per brokered request, written before the value is read and
/// closed once with how it ended. There is no column here for a value, and there never will be.
///
/// Which keeper holds the values is deliberately not here. It is a property of the computer the
/// hub runs on, not of the realm's portable record, so a backup cannot carry the name of a vault
/// the computer it is restored onto has never heard of.
pub const V5: &str = r#"
-- How the value travels on a request, and which header, parameter or username carries it. Both
-- are names. The four words are the four ways a value goes as itself; the kinds that mint a
-- short-lived credential of their own are not brokered by this version and are refused above.
ALTER TABLE credentials ADD COLUMN presentation TEXT NOT NULL DEFAULT 'bearer';
ALTER TABLE credentials ADD COLUMN field TEXT NOT NULL DEFAULT '';

-- Every place one credential may be sent, as rows, so there is a single list to check against.
-- What a destination may look like is decided in Rust by forward::destination, because telling a
-- private address from a public one is not something a CHECK can do. These two are here because
-- they are what would make a row dangerous rather than merely wrong: a query is where a query
-- credential's value travels, and a user:password in an address is a value in a destination.
CREATE TABLE credential_destinations (
    credential_id TEXT NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    destination   TEXT NOT NULL CHECK (
                      (substr(destination, 1, 8) = 'https://' OR substr(destination, 1, 7) = 'http://')
                      AND instr(destination, '?') = 0
                      AND instr(destination, ' ') = 0
                      AND instr(destination, '@') = 0
                  ),
    added_by      TEXT NOT NULL,
    added_at      INTEGER NOT NULL,
    PRIMARY KEY (credential_id, destination)
);

-- The one destination each credential already had becomes its first row. OR IGNORE, because the
-- rows were written by a build whose only rule was that a destination starts with https://: one
-- that this version would refuse is left out rather than aborting the step and stranding the
-- realm at version 4 for ever. A credential with no row is refused by the broker until an
-- administrator gives it a destination, which is the safe way round.
INSERT OR IGNORE INTO credential_destinations (credential_id, destination, added_by, added_at)
SELECT id, destination, owner_id, created_at FROM credentials;

-- One row per brokered request. It is written before the value is read, which is also what stops
-- two hubs from being inside the same permission at once: capability_id is unique here. That
-- uniqueness is what forecloses a credential permission that could be used more than once, and
-- every credential permission is single use today (capability::Claims::new), so the schema is not
-- deciding anything the policy has not already decided.
--
-- capability_id is deliberately not a foreign key, because permissions that have expired are
-- tidied away and this record outlives them.
--
-- There is no fingerprint column. The vault entry and its version say which value was read, and
-- a fingerprint is an unsalted digest of the value; one copy of it, in the credential itself, is
-- enough to notice a rotation and is one copy more than belongs in a per-request ledger.
CREATE TABLE credential_uses (
    id             TEXT PRIMARY KEY,
    realm_id       TEXT NOT NULL REFERENCES realms(id),
    credential_id  TEXT NOT NULL REFERENCES credentials(id),
    capability_id  TEXT NOT NULL UNIQUE,
    approval_id    TEXT,
    principal_id   TEXT NOT NULL REFERENCES principals(id),
    device_id      TEXT NOT NULL,
    workload_id    TEXT NOT NULL,
    -- Scheme, host and port only. The query is never kept, because a query credential's value
    -- travels in it.
    destination    TEXT NOT NULL CHECK (instr(destination, '?') = 0),
    method         TEXT NOT NULL,
    path           TEXT NOT NULL CHECK (instr(path, '?') = 0),
    request_bytes  INTEGER NOT NULL CHECK (request_bytes >= 0),
    answer_bytes   INTEGER CHECK (answer_bytes IS NULL OR answer_bytes >= 0),
    status         INTEGER CHECK (status IS NULL OR (status BETWEEN 100 AND 599)),
    -- Which vault entry was read, and which version of it. Not the value.
    vault_id       TEXT NOT NULL,
    vault_version  INTEGER NOT NULL CHECK (vault_version >= 1),
    outcome        TEXT NOT NULL CHECK (outcome IN ('opening','sent','refused','failed','unknown')),
    -- One word from a fixed list, never the words a service or a TLS library chose. What a person
    -- reads is in the audit event, which passes the realm's redaction gate.
    reason         TEXT NOT NULL DEFAULT '' CHECK (length(reason) <= 32),
    policy_version INTEGER NOT NULL,
    started_at     INTEGER NOT NULL,
    finished_at    INTEGER
);

-- A brokered request is recorded as it was made, and closed exactly once. Everything that says
-- what was attempted is fixed at the opening; only how it ended may be filled in, and only from
-- the one statement that closes it.
CREATE TRIGGER credential_uses_close_once BEFORE UPDATE ON credential_uses
WHEN OLD.finished_at IS NOT NULL
  OR OLD.outcome <> 'opening'
  OR NEW.outcome = 'opening'
  OR NEW.finished_at IS NULL
  OR NEW.id <> OLD.id
  OR NEW.realm_id <> OLD.realm_id
  OR NEW.credential_id <> OLD.credential_id
  OR NEW.capability_id <> OLD.capability_id
  OR NEW.approval_id IS NOT OLD.approval_id
  OR NEW.principal_id <> OLD.principal_id
  OR NEW.device_id <> OLD.device_id
  OR NEW.workload_id <> OLD.workload_id
  OR NEW.destination <> OLD.destination
  OR NEW.method <> OLD.method
  OR NEW.path <> OLD.path
  OR NEW.request_bytes <> OLD.request_bytes
  OR NEW.vault_id <> OLD.vault_id
  OR NEW.vault_version <> OLD.vault_version
  OR NEW.policy_version <> OLD.policy_version
  OR NEW.started_at <> OLD.started_at
BEGIN SELECT RAISE(ABORT, 'a brokered request is recorded as it was made and closed once'); END;

CREATE TRIGGER credential_uses_never_vanish BEFORE DELETE ON credential_uses
BEGIN SELECT RAISE(ABORT, 'a brokered request cannot be withdrawn once it is made'); END;

-- A credential travels one of four ways, each of which puts a name beside a value. The value is
-- never one of them, and these say so to anything that opens the file with another tool.
CREATE TRIGGER credentials_presentation_on_insert BEFORE INSERT ON credentials
WHEN NEW.presentation NOT IN ('bearer','header','basic','query')
BEGIN SELECT RAISE(ABORT, 'a credential travels as bearer, header, basic or query'); END;

CREATE TRIGGER credentials_presentation_on_update BEFORE UPDATE ON credentials
WHEN NEW.presentation NOT IN ('bearer','header','basic','query')
BEGIN SELECT RAISE(ABORT, 'a credential travels as bearer, header, basic or query'); END;

CREATE INDEX credential_uses_by_credential ON credential_uses (credential_id, started_at);
CREATE INDEX credential_uses_by_person ON credential_uses (principal_id, started_at);
CREATE INDEX credential_uses_open ON credential_uses (started_at) WHERE finished_at IS NULL;
"#;

/// Taking version 5 back out again, for the rollback the plan asks every record-moving phase to
/// ship with.
///
/// It drops what version 5 added and nothing else: the ledger of brokered requests goes, because
/// a version 4 build has no table to keep it in, and the audit chain still holds every one of
/// those requests as an event. The destinations go back to the one each credential already
/// carries in its own row, which version 4 reads, so no credential loses the place it may be
/// sent. Anything an administrator added after the upgrade, a second destination or a way of
/// travelling other than bearer, is lost, and the runbook has to say so.
pub const DOWN5: &str = r#"
DROP TRIGGER credentials_presentation_on_update;
DROP TRIGGER credentials_presentation_on_insert;
DROP TRIGGER credential_uses_never_vanish;
DROP TRIGGER credential_uses_close_once;
DROP INDEX credential_uses_open;
DROP INDEX credential_uses_by_person;
DROP INDEX credential_uses_by_credential;
DROP TABLE credential_uses;
DROP TABLE credential_destinations;
ALTER TABLE credentials DROP COLUMN field;
ALTER TABLE credentials DROP COLUMN presentation;
"#;

/// What version 6 adds: the research profile.
///
/// A research realm is a realm of its own, so every table here only ever holds rows in one, and
/// the database itself says so rather than leaving it to the code that normally writes it. What is
/// kept is where material came from, what it hashes to, what was explicitly let in, what a run
/// produced, who looked at it and the one document that was sealed to be carried out. No source
/// byte and no artifact byte is here, and there is no column that could hold one.
///
/// Two things are said out loud because they are the containment boundary rather than bookkeeping.
/// A credential belongs to a company grid: the three triggers below refuse one in a research grid
/// whichever way the row is written, so the research realm cannot reach the broker even through a
/// hand-written INSERT. And a research result is accepted only by a company grid, because the
/// crossing is a document the company realm decides about, not an instruction it obeys.
pub const V6: &str = r#"
-- What may be researched, under what limits, in the material owner's own words, with a digest of
-- exactly those words. A scope is edited only while it is a draft. Freezing it fixes its digest,
-- and that takes a second person's granted decision over the digest; a change afterwards is a new
-- version naming the one it replaced, and acceptance starts again.
--
-- `generation` is this profile's revocation. It rises whenever what the scope allows narrows, and
-- a permission minted under an older one is refused at its next use by the one mechanism in
-- check_capability that already refuses a suspended account, rather than by a check beside it.
CREATE TABLE research_scopes (
    id                        TEXT PRIMARY KEY,
    realm_id                  TEXT NOT NULL REFERENCES realms(id),
    name                      TEXT NOT NULL,
    purpose                   TEXT NOT NULL,
    authorisation             TEXT NOT NULL,
    authorisation_digest      TEXT NOT NULL CHECK (length(authorisation_digest) = 64),
    -- The granted request a second approver decided over that digest. Null only while a draft.
    authorisation_approval_id TEXT UNIQUE REFERENCES requests(id),
    -- How sensitive the material is, named before any work starts and carried into every plan.
    classification            TEXT NOT NULL CHECK (classification IN ('public','internal','confidential','restricted')),
    limits                    TEXT NOT NULL,
    version                   INTEGER NOT NULL CHECK (version >= 1),
    supersedes                TEXT REFERENCES research_scopes(id),
    digest                    TEXT CHECK (digest IS NULL OR length(digest) = 64),
    generation                INTEGER NOT NULL DEFAULT 1 CHECK (generation > 0),
    created_by                TEXT NOT NULL REFERENCES principals(id),
    created_at                INTEGER NOT NULL,
    frozen_at                 INTEGER,
    closed_at                 INTEGER,
    closed_reason             TEXT NOT NULL DEFAULT '',
    UNIQUE (realm_id, name, version)
);

-- Everything explicitly let in: a source origin, a destination, a repository, a tool, a person.
-- Each row names the one agreement it came from, and the agreement is unique here, so one
-- decision admits one thing and nobody admits anything on their own say-so.
--
-- The column is called `subject` rather than `value` on purpose: nothing in a research grid holds
-- a value, and the guard test over these tables refuses that column name outright.
CREATE TABLE research_admissions (
    id               TEXT PRIMARY KEY,
    realm_id         TEXT NOT NULL REFERENCES realms(id),
    scope_id         TEXT NOT NULL REFERENCES research_scopes(id),
    kind             TEXT NOT NULL CHECK (kind IN ('source','destination','repository','tool','participant')),
    subject          TEXT NOT NULL,
    -- For a destination: the one method and the one path prefix it was admitted for, when it was
    -- narrowed to them. A URL path, never a place on anybody's disk.
    method           TEXT,
    path             TEXT,
    approval_id      TEXT NOT NULL UNIQUE REFERENCES requests(id),
    admitted_by      TEXT NOT NULL REFERENCES principals(id),
    admitted_at      INTEGER NOT NULL,
    expires_at       INTEGER,
    withdrawn_at     INTEGER,
    withdrawn_reason TEXT NOT NULL DEFAULT ''
);

-- Source acquired for a scope, under the admission that let it in. The reference is an address or
-- a name, never a credential. A source whose manifest no longer matches is quarantined, never
-- deleted, so what was worked on is still readable afterwards.
CREATE TABLE research_sources (
    id             TEXT PRIMARY KEY,
    realm_id       TEXT NOT NULL REFERENCES realms(id),
    scope_id       TEXT NOT NULL REFERENCES research_scopes(id),
    admission_id   TEXT NOT NULL REFERENCES research_admissions(id),
    origin         TEXT NOT NULL CHECK (origin IN ('upload','repository','archive')),
    reference      TEXT NOT NULL,
    revision       TEXT NOT NULL DEFAULT '',
    digest         TEXT NOT NULL CHECK (length(digest) = 64),
    bytes          INTEGER NOT NULL CHECK (bytes >= 0),
    file_count     INTEGER NOT NULL CHECK (file_count >= 0),
    retain_until   INTEGER,
    acquired_by    TEXT NOT NULL REFERENCES principals(id),
    acquired_at    INTEGER NOT NULL,
    verified_at    INTEGER,
    quarantined_at INTEGER,
    disposed_at    INTEGER,
    reason         TEXT NOT NULL DEFAULT '',
    UNIQUE (scope_id, digest)
);

-- The manifest of a source, one row per file, as it was when it was acquired. Hashing the folder
-- again and comparing it with these rows is how a change afterwards is noticed. The digests are
-- what the component that hashed the files reported; nothing here read a byte.
CREATE TABLE research_source_files (
    source_id TEXT NOT NULL REFERENCES research_sources(id),
    path      TEXT NOT NULL,
    sha256    TEXT NOT NULL CHECK (length(sha256) = 64),
    bytes     INTEGER NOT NULL CHECK (bytes >= 0),
    PRIMARY KEY (source_id, path)
);

-- What the source says it depends on, and what actually arrived. A dependency that does not match
-- what the lock file promised stops the work rather than being a note to carry on past.
CREATE TABLE research_dependencies (
    id         TEXT PRIMARY KEY,
    source_id  TEXT NOT NULL REFERENCES research_sources(id),
    ecosystem  TEXT NOT NULL,
    name       TEXT NOT NULL,
    version    TEXT NOT NULL,
    expected   TEXT NOT NULL CHECK (length(expected) = 64),
    seen       TEXT CHECK (seen IS NULL OR length(seen) = 64),
    state      TEXT NOT NULL CHECK (state IN ('declared','verified','mismatched','missing')),
    checked_at INTEGER,
    UNIQUE (source_id, ecosystem, name, version)
);

-- What a run produced: what it is called, what it hashes to and how large it is. The bytes are on
-- the computer that ran the enclosure, under a name the engine owns; this is the record of them.
CREATE TABLE research_artifacts (
    id           TEXT PRIMARY KEY,
    realm_id     TEXT NOT NULL REFERENCES realms(id),
    scope_id     TEXT NOT NULL REFERENCES research_scopes(id),
    source_id    TEXT REFERENCES research_sources(id),
    workload_id  TEXT NOT NULL REFERENCES workloads(id),
    name         TEXT NOT NULL,
    media_type   TEXT NOT NULL DEFAULT 'application/octet-stream',
    sha256       TEXT NOT NULL CHECK (length(sha256) = 64),
    bytes        INTEGER NOT NULL CHECK (bytes >= 0),
    -- When this may be let go of, from the scope's stated retention. Disposal is recorded, never
    -- silent, and the row stays with the reason on it.
    retain_until INTEGER,
    produced_at  INTEGER NOT NULL,
    disposed_at  INTEGER,
    disposed_reason TEXT NOT NULL DEFAULT '',
    UNIQUE (scope_id, name, sha256)
);

-- Who looked at an artifact and what they said. Insert-only, like a decision, because a later
-- change of mind must not erase who said what the first time. The current state of an artifact is
-- the row with the highest `sequence`.
--
-- This grid does not scan anything. There is no scanner in this repository, and this table is the
-- record of somebody's verdict, never evidence that the grid detected anything itself.
CREATE TABLE research_artifact_scans (
    id          TEXT PRIMARY KEY,
    realm_id    TEXT NOT NULL REFERENCES realms(id),
    artifact_id TEXT NOT NULL REFERENCES research_artifacts(id),
    verdict     TEXT NOT NULL CHECK (verdict IN ('pending','clean','flagged','quarantined')),
    -- The person in this grid who recorded it, and the tool they are reporting, when there is one.
    looked_by   TEXT NOT NULL REFERENCES principals(id),
    tool        TEXT NOT NULL DEFAULT '',
    reason      TEXT NOT NULL DEFAULT '',
    sequence    INTEGER NOT NULL CHECK (sequence > 0),
    looked_at   INTEGER NOT NULL,
    UNIQUE (artifact_id, sequence)
);

-- A finding, as the research realm records it, naming the exact source it was found against.
CREATE TABLE research_findings (
    id          TEXT PRIMARY KEY,
    realm_id    TEXT NOT NULL REFERENCES realms(id),
    scope_id    TEXT NOT NULL REFERENCES research_scopes(id),
    source_id   TEXT NOT NULL REFERENCES research_sources(id),
    workload_id TEXT NOT NULL REFERENCES workloads(id),
    title       TEXT NOT NULL,
    component   TEXT NOT NULL DEFAULT '',
    summary     TEXT NOT NULL DEFAULT '',
    severity    TEXT NOT NULL CHECK (severity IN ('unknown','low','medium','high')),
    state       TEXT NOT NULL CHECK (state IN ('draft','submitted','accepted','rejected','sealed')),
    reported_by TEXT NOT NULL REFERENCES principals(id),
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);

CREATE TABLE research_finding_artifacts (
    finding_id  TEXT NOT NULL REFERENCES research_findings(id),
    artifact_id TEXT NOT NULL REFERENCES research_artifacts(id),
    PRIMARY KEY (finding_id, artifact_id)
);

-- Reviewing a finding is an ordinary request for someone else's agreement, so this table is a
-- link and nothing more. The verdict, who gave it, when, whether they were the requester and
-- whether anyone else could have decided all live in `requests` and `decisions`, which already
-- refuse a second decision and refuse a change to one. No second approval mechanism is built.
CREATE TABLE research_reviews (
    finding_id TEXT NOT NULL REFERENCES research_findings(id),
    request_id TEXT NOT NULL UNIQUE REFERENCES requests(id),
    realm_id   TEXT NOT NULL REFERENCES realms(id),
    asked_at   INTEGER NOT NULL,
    PRIMARY KEY (finding_id, request_id)
);

-- The one document sealed to be carried out of this realm: a finding, its artifacts' digests and
-- the reviews it passed. The counts are taken from the rows at the moment it is written, not from
-- whoever asked. A sealed crossing is never edited; the single thing that may be filled in later
-- is that it is no longer good, because the source or the scope behind it changed.
CREATE TABLE research_crossings (
    id               TEXT PRIMARY KEY,
    realm_id         TEXT NOT NULL REFERENCES realms(id),
    finding_id       TEXT NOT NULL UNIQUE REFERENCES research_findings(id),
    digest           TEXT NOT NULL UNIQUE CHECK (length(digest) = 64),
    seal             TEXT NOT NULL,
    bundle_version   INTEGER NOT NULL DEFAULT 1,
    reviews          INTEGER NOT NULL CHECK (reviews >= 1),
    artifacts        INTEGER NOT NULL CHECK (artifacts >= 1),
    scope_digest     TEXT NOT NULL,
    source_digest    TEXT NOT NULL,
    sealed_by        TEXT NOT NULL REFERENCES principals(id),
    sealed_at        INTEGER NOT NULL,
    withdrawn_at     INTEGER,
    withdrawn_reason TEXT NOT NULL DEFAULT ''
);

-- What a company grid accepted from a research grid. The research grid's key means nothing here.
-- What makes this row is a person in this grid deciding, with someone else agreeing, and that
-- decision is this grid's own. The same document is never accepted twice.
CREATE TABLE research_imports (
    id                   TEXT PRIMARY KEY,
    realm_id             TEXT NOT NULL REFERENCES realms(id),
    crossing_digest      TEXT NOT NULL UNIQUE CHECK (length(crossing_digest) = 64),
    from_realm_id        TEXT NOT NULL,
    from_realm_name      TEXT NOT NULL,
    from_key_fingerprint TEXT NOT NULL,
    scope_digest         TEXT NOT NULL,
    source_digest        TEXT NOT NULL,
    title                TEXT NOT NULL,
    severity             TEXT NOT NULL CHECK (severity IN ('unknown','low','medium','high')),
    artifacts            INTEGER NOT NULL CHECK (artifacts >= 0),
    reviews              INTEGER NOT NULL CHECK (reviews >= 0),
    approval_id          TEXT NOT NULL UNIQUE REFERENCES requests(id),
    accepted_by          TEXT NOT NULL REFERENCES principals(id),
    accepted_at          INTEGER NOT NULL,
    note                 TEXT NOT NULL DEFAULT '',
    -- Set when somebody carries word that the source or the scope behind it changed. The
    -- acceptance stands as it was made; this says it is no longer good.
    withdrawn_at         INTEGER,
    withdrawn_reason     TEXT NOT NULL DEFAULT ''
);

-- Research belongs in a research grid of its own, and these say so to anything that opens the
-- file with another tool, not only to the code that normally writes it.
CREATE TRIGGER research_scopes_research_only BEFORE INSERT ON research_scopes
WHEN (SELECT kind FROM realms WHERE id = NEW.realm_id) <> 'research'
BEGIN SELECT RAISE(ABORT, 'research belongs in a research grid of its own'); END;

CREATE TRIGGER research_admissions_research_only BEFORE INSERT ON research_admissions
WHEN (SELECT kind FROM realms WHERE id = NEW.realm_id) <> 'research'
BEGIN SELECT RAISE(ABORT, 'research belongs in a research grid of its own'); END;

CREATE TRIGGER research_sources_research_only BEFORE INSERT ON research_sources
WHEN (SELECT kind FROM realms WHERE id = NEW.realm_id) <> 'research'
BEGIN SELECT RAISE(ABORT, 'research belongs in a research grid of its own'); END;

CREATE TRIGGER research_artifacts_research_only BEFORE INSERT ON research_artifacts
WHEN (SELECT kind FROM realms WHERE id = NEW.realm_id) <> 'research'
BEGIN SELECT RAISE(ABORT, 'research belongs in a research grid of its own'); END;

CREATE TRIGGER research_artifact_scans_research_only BEFORE INSERT ON research_artifact_scans
WHEN (SELECT kind FROM realms WHERE id = NEW.realm_id) <> 'research'
BEGIN SELECT RAISE(ABORT, 'research belongs in a research grid of its own'); END;

CREATE TRIGGER research_findings_research_only BEFORE INSERT ON research_findings
WHEN (SELECT kind FROM realms WHERE id = NEW.realm_id) <> 'research'
BEGIN SELECT RAISE(ABORT, 'research belongs in a research grid of its own'); END;

CREATE TRIGGER research_reviews_research_only BEFORE INSERT ON research_reviews
WHEN (SELECT kind FROM realms WHERE id = NEW.realm_id) <> 'research'
BEGIN SELECT RAISE(ABORT, 'research belongs in a research grid of its own'); END;

CREATE TRIGGER research_crossings_research_only BEFORE INSERT ON research_crossings
WHEN (SELECT kind FROM realms WHERE id = NEW.realm_id) <> 'research'
BEGIN SELECT RAISE(ABORT, 'research belongs in a research grid of its own'); END;

-- And a credential belongs in a company grid. A research grid cannot hold one, whichever way the
-- row is written: the capability refuses it, the Core method refuses it, and so do these.
CREATE TRIGGER credentials_company_only BEFORE INSERT ON credentials
WHEN (SELECT kind FROM realms WHERE id = NEW.realm_id) <> 'primary'
BEGIN SELECT RAISE(ABORT, 'a research grid cannot hold a company credential'); END;

CREATE TRIGGER credential_grants_company_only BEFORE INSERT ON credential_grants
WHEN (SELECT kind FROM realms WHERE id = NEW.realm_id) <> 'primary'
BEGIN SELECT RAISE(ABORT, 'a research grid cannot hold a company credential'); END;

CREATE TRIGGER credential_uses_company_only BEFORE INSERT ON credential_uses
WHEN (SELECT kind FROM realms WHERE id = NEW.realm_id) <> 'primary'
BEGIN SELECT RAISE(ABORT, 'a research grid cannot broker a company credential'); END;

-- A research result is accepted by a company grid, and only there.
CREATE TRIGGER research_imports_company_only BEFORE INSERT ON research_imports
WHEN (SELECT kind FROM realms WHERE id = NEW.realm_id) <> 'primary'
BEGIN SELECT RAISE(ABORT, 'only a company grid accepts a research result'); END;

-- A scope generation only rises, so a number that has been left behind can never come back.
CREATE TRIGGER research_scope_generation_only_rises BEFORE UPDATE OF generation ON research_scopes
WHEN NEW.generation < OLD.generation
BEGIN SELECT RAISE(ABORT, 'a research scope generation only rises'); END;

-- A frozen scope is what was agreed to. Changing one makes a new version instead. The name is
-- guarded with the rest because the digest is taken over it.
CREATE TRIGGER research_scopes_freeze_once BEFORE UPDATE ON research_scopes
WHEN OLD.frozen_at IS NOT NULL
 AND (NEW.name <> OLD.name OR NEW.purpose <> OLD.purpose OR NEW.authorisation <> OLD.authorisation
      OR NEW.authorisation_digest <> OLD.authorisation_digest OR NEW.classification <> OLD.classification
      OR NEW.limits <> OLD.limits OR NEW.version <> OLD.version OR NEW.digest IS NOT OLD.digest
      OR NEW.supersedes IS NOT OLD.supersedes OR NEW.created_by <> OLD.created_by
      OR NEW.authorisation_approval_id IS NOT OLD.authorisation_approval_id)
BEGIN SELECT RAISE(ABORT, 'a frozen scope is replaced by a new version, never edited'); END;

-- A verdict about an artifact stands as it was written. Changing your mind writes another row.
CREATE TRIGGER research_artifact_scans_never_change BEFORE UPDATE ON research_artifact_scans
BEGIN SELECT RAISE(ABORT, 'a verdict about an artifact cannot be changed once it is written'); END;

CREATE TRIGGER research_artifact_scans_never_vanish BEFORE DELETE ON research_artifact_scans
BEGIN SELECT RAISE(ABORT, 'a verdict about an artifact cannot be withdrawn once it is written'); END;

-- A sealed crossing and an accepted result stand as they were written. The one thing either may
-- gain afterwards is that it is no longer good.
CREATE TRIGGER research_crossings_never_change BEFORE UPDATE ON research_crossings
WHEN OLD.withdrawn_at IS NOT NULL
  OR NEW.id <> OLD.id OR NEW.realm_id <> OLD.realm_id OR NEW.finding_id <> OLD.finding_id
  OR NEW.digest <> OLD.digest OR NEW.seal <> OLD.seal OR NEW.bundle_version <> OLD.bundle_version
  OR NEW.reviews <> OLD.reviews OR NEW.artifacts <> OLD.artifacts
  OR NEW.scope_digest <> OLD.scope_digest OR NEW.source_digest <> OLD.source_digest
  OR NEW.sealed_by <> OLD.sealed_by OR NEW.sealed_at <> OLD.sealed_at
BEGIN SELECT RAISE(ABORT, 'a sealed crossing is recorded as it was sealed; it can only be marked no longer good'); END;

CREATE TRIGGER research_imports_never_change BEFORE UPDATE ON research_imports
WHEN OLD.withdrawn_at IS NOT NULL
  OR NEW.id <> OLD.id OR NEW.realm_id <> OLD.realm_id OR NEW.crossing_digest <> OLD.crossing_digest
  OR NEW.from_realm_id <> OLD.from_realm_id OR NEW.from_key_fingerprint <> OLD.from_key_fingerprint
  OR NEW.scope_digest <> OLD.scope_digest OR NEW.source_digest <> OLD.source_digest
  OR NEW.title <> OLD.title OR NEW.severity <> OLD.severity
  OR NEW.artifacts <> OLD.artifacts OR NEW.reviews <> OLD.reviews
  OR NEW.approval_id <> OLD.approval_id OR NEW.accepted_by <> OLD.accepted_by
  OR NEW.accepted_at <> OLD.accepted_at
BEGIN SELECT RAISE(ABORT, 'an accepted research result is recorded as it was accepted; it can only be marked no longer good'); END;

-- A sealed finding is finished with. Nothing takes it back to a draft.
CREATE TRIGGER research_findings_sealed_is_final BEFORE UPDATE ON research_findings
WHEN OLD.state = 'sealed' AND NEW.state <> 'sealed'
BEGIN SELECT RAISE(ABORT, 'a sealed finding cannot be moved back'); END;

-- These are the record. Quarantining, closing and disposing all leave the row where it is, and
-- these refuse the delete that would make the record disagree with what happened.
CREATE TRIGGER research_scopes_never_vanish BEFORE DELETE ON research_scopes
BEGIN SELECT RAISE(ABORT, 'a research scope is closed, never deleted'); END;

CREATE TRIGGER research_admissions_never_vanish BEFORE DELETE ON research_admissions
BEGIN SELECT RAISE(ABORT, 'an admission is withdrawn, never deleted'); END;

CREATE TRIGGER research_sources_never_vanish BEFORE DELETE ON research_sources
BEGIN SELECT RAISE(ABORT, 'a source is quarantined or disposed of, never deleted'); END;

CREATE TRIGGER research_artifacts_never_vanish BEFORE DELETE ON research_artifacts
BEGIN SELECT RAISE(ABORT, 'an artifact is disposed of with a reason, never deleted'); END;

CREATE TRIGGER research_findings_never_vanish BEFORE DELETE ON research_findings
BEGIN SELECT RAISE(ABORT, 'a finding stays in the record'); END;

CREATE TRIGGER research_reviews_never_vanish BEFORE DELETE ON research_reviews
BEGIN SELECT RAISE(ABORT, 'a review stays in the record'); END;

-- Nothing crosses that rests on no evidence, and nothing crosses that somebody has not looked at
-- and found clean. The second trigger reads the latest verdict for each linked artifact, because
-- the verdicts are insert-only and the newest one is the state.
CREATE TRIGGER research_crossings_need_evidence BEFORE INSERT ON research_crossings
WHEN NOT EXISTS (SELECT 1 FROM research_finding_artifacts WHERE finding_id = NEW.finding_id)
BEGIN SELECT RAISE(ABORT, 'a finding crosses with the artifacts it rests on, never on its own'); END;

CREATE TRIGGER research_crossings_need_clean_artifacts BEFORE INSERT ON research_crossings
WHEN EXISTS (
    SELECT 1 FROM research_finding_artifacts fa
    WHERE fa.finding_id = NEW.finding_id
      AND COALESCE((SELECT s.verdict FROM research_artifact_scans s
                     WHERE s.artifact_id = fa.artifact_id ORDER BY s.sequence DESC LIMIT 1), 'pending') <> 'clean')
BEGIN SELECT RAISE(ABORT, 'somebody looks at every artifact and finds it clean before anything crosses'); END;

CREATE INDEX research_scopes_by_realm ON research_scopes (realm_id, name, version);
CREATE UNIQUE INDEX research_admissions_live ON research_admissions (scope_id, kind, subject) WHERE withdrawn_at IS NULL;
CREATE INDEX research_admissions_by_scope ON research_admissions (scope_id, kind, expires_at);
CREATE INDEX research_sources_by_scope ON research_sources (scope_id, acquired_at);
CREATE INDEX research_dependencies_by_state ON research_dependencies (state);
CREATE INDEX research_artifacts_by_work ON research_artifacts (workload_id);
CREATE INDEX research_artifacts_by_scope ON research_artifacts (scope_id, produced_at);
CREATE INDEX research_artifact_scans_by_artifact ON research_artifact_scans (artifact_id, sequence DESC);
CREATE INDEX research_findings_by_scope ON research_findings (scope_id, state);
CREATE INDEX research_reviews_by_finding ON research_reviews (finding_id);
"#;

/// Taking version 6 back out again, for the rollback every record-moving phase ships with.
///
/// It drops what version 6 added and nothing else. A grid that has done research loses the record
/// of it, which is why the runbook has to say that a backup is taken first: the sealed history
/// still names every scope, admission, finding and crossing by id, and nothing else does.
pub const DOWN6: &str = r#"
DROP TRIGGER research_crossings_need_clean_artifacts;
DROP TRIGGER research_crossings_need_evidence;
DROP TRIGGER research_reviews_never_vanish;
DROP TRIGGER research_findings_never_vanish;
DROP TRIGGER research_artifacts_never_vanish;
DROP TRIGGER research_sources_never_vanish;
DROP TRIGGER research_admissions_never_vanish;
DROP TRIGGER research_scopes_never_vanish;
DROP TRIGGER research_findings_sealed_is_final;
DROP TRIGGER research_imports_never_change;
DROP TRIGGER research_crossings_never_change;
DROP TRIGGER research_artifact_scans_never_vanish;
DROP TRIGGER research_artifact_scans_never_change;
DROP TRIGGER research_scopes_freeze_once;
DROP TRIGGER research_scope_generation_only_rises;
DROP TRIGGER research_imports_company_only;
DROP TRIGGER credential_uses_company_only;
DROP TRIGGER credential_grants_company_only;
DROP TRIGGER credentials_company_only;
DROP TRIGGER research_crossings_research_only;
DROP TRIGGER research_reviews_research_only;
DROP TRIGGER research_findings_research_only;
DROP TRIGGER research_artifact_scans_research_only;
DROP TRIGGER research_artifacts_research_only;
DROP TRIGGER research_sources_research_only;
DROP TRIGGER research_admissions_research_only;
DROP TRIGGER research_scopes_research_only;
DROP TABLE research_imports;
DROP TABLE research_crossings;
DROP TABLE research_reviews;
DROP TABLE research_finding_artifacts;
DROP TABLE research_findings;
DROP TABLE research_artifact_scans;
DROP TABLE research_artifacts;
DROP TABLE research_dependencies;
DROP TABLE research_source_files;
DROP TABLE research_sources;
DROP TABLE research_admissions;
DROP TABLE research_scopes;
"#;

/// Version 7: which typed command caused an event.
///
/// One nullable column and one index. Every row already written stays as it is, with no command
/// against it, which is exactly true of it: it was written before commands were correlated. The
/// seal is taken over the command only when there is one, so nothing already sealed changes.
pub const V7: &str = r#"
ALTER TABLE audit_events ADD COLUMN command TEXT;
CREATE INDEX audit_events_by_command ON audit_events(command) WHERE command IS NOT NULL;
"#;

/// Taking version 7 back out again. SQLite has dropped a column since 3.35 and the index goes
/// with it; nothing else version 7 added needs undoing.
pub const DOWN7: &str = r#"
DROP INDEX audit_events_by_command;
ALTER TABLE audit_events DROP COLUMN command;
"#;

/// Version 8: what a connector was asked to do, and what a realm demands a computer shows.
///
/// The table is written before a connector is asked, so a hub that dies between a provider moving
/// and the realm recording it still knows to look. The triggers are the point of it: what was
/// asked is never editable, a settled task stays settled, attempts only rise, and nothing is
/// forgotten while a provider may still be out of step with it. Those are rules a second process,
/// or a person with sqlite3, hits as well, which a rule written in Rust would not be.
///
/// The partial unique index covers the whole of what was asked, not only the person. One
/// credential routinely reaches several targets: an application group, a delivery group, a pool.
/// Giving one person two pools under one credential is a legitimate pair of tasks, and an index on
/// the credential and the email alone would have the database refuse the second one with a message
/// about pressing a button twice. What it does refuse is the same person, the same credential, the
/// same target and the same direction, open twice, which is the real double-press.
pub const V8: &str = r#"
-- What a realm demands a computer shows before work is placed on it. Defaulting to unverified
-- means turning any of this on changes nothing for a realm that already exists.
ALTER TABLE realms ADD COLUMN demands_trust TEXT NOT NULL DEFAULT 'unverified'
    CHECK (demands_trust IN ('unverified','selfReported','deviceSigned','hardwareAttested'));

CREATE TABLE connector_intents (
    id             TEXT PRIMARY KEY,
    realm_id       TEXT NOT NULL REFERENCES realms(id),
    connector      TEXT NOT NULL CHECK (length(connector) BETWEEN 1 AND 128),
    credential_id  TEXT NOT NULL REFERENCES credentials(id),
    destination    TEXT NOT NULL CHECK (length(destination) BETWEEN 1 AND 512),
    change         TEXT NOT NULL CHECK (change IN ('give','takeBack')),
    subject_email  TEXT NOT NULL CHECK (length(subject_email) BETWEEN 3 AND 254 AND subject_email LIKE '%@%'),
    subject_name   TEXT NOT NULL CHECK (length(subject_name) BETWEEN 1 AND 128),
    target         TEXT NOT NULL CHECK (length(target) BETWEEN 1 AND 512),
    fingerprint    TEXT NOT NULL CHECK (length(fingerprint) BETWEEN 16 AND 128),
    principal_id   TEXT NOT NULL REFERENCES principals(id),
    device_id      TEXT NOT NULL REFERENCES devices(id),
    workload_id    TEXT NOT NULL REFERENCES workloads(id),
    state          TEXT NOT NULL CHECK (state IN
                      ('opened','done','alreadyTrue','refused','orphaned','reconciled','rolledBack','stuck')),
    attempts       INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0 AND attempts <= 16),
    policy_version INTEGER NOT NULL,
    opened_at      INTEGER NOT NULL,
    settled_at     INTEGER,
    note           TEXT NOT NULL DEFAULT '' CHECK (length(note) <= 500)
);

-- What was asked is what was asked. Only how it ended may be written later.
CREATE TRIGGER connector_intents_never_change_what_was_asked
BEFORE UPDATE OF realm_id, connector, credential_id, destination, change, subject_email,
                 subject_name, target, fingerprint, principal_id, device_id, workload_id,
                 policy_version, opened_at
ON connector_intents
BEGIN SELECT RAISE(ABORT, 'what a connector was asked to do is recorded as it was asked'); END;

-- A settled task is settled. Reopening one would let the sweeper act twice on one change.
CREATE TRIGGER connector_intents_settle_once BEFORE UPDATE OF state ON connector_intents
WHEN OLD.state IN ('refused','alreadyTrue','reconciled','rolledBack')
BEGIN SELECT RAISE(ABORT, 'this connector task has already been settled'); END;

-- Attempts only rise, so a row cannot be made to look fresh.
CREATE TRIGGER connector_intents_attempts_only_rise BEFORE UPDATE OF attempts ON connector_intents
WHEN NEW.attempts < OLD.attempts
BEGIN SELECT RAISE(ABORT, 'a connector task cannot forget how many times it has been tried'); END;

-- Nothing is forgotten while it may still be out of step with a provider.
CREATE TRIGGER connector_intents_are_settled_before_they_are_forgotten
BEFORE DELETE ON connector_intents
WHEN OLD.state IN ('opened','done','orphaned','stuck')
BEGIN SELECT RAISE(ABORT, 'settle this connector task before forgetting it'); END;

-- One open task per person per credential per target per direction, refused by the database
-- rather than by a convention: an administrator pressing the button twice must not make two
-- changes at a provider that counts them.
CREATE UNIQUE INDEX connector_intents_one_open_per_change
    ON connector_intents (credential_id, subject_email, target, change) WHERE state = 'opened';

CREATE INDEX connector_intents_unsettled ON connector_intents (state, opened_at);
"#;

/// Taking version 8 back out again. The column goes with SQLite's own DROP COLUMN, which it has
/// had since 3.35, and the triggers and indexes go with the table.
pub const DOWN8: &str = r#"
DROP INDEX connector_intents_unsettled;
DROP INDEX connector_intents_one_open_per_change;
DROP TRIGGER connector_intents_are_settled_before_they_are_forgotten;
DROP TRIGGER connector_intents_attempts_only_rise;
DROP TRIGGER connector_intents_settle_once;
DROP TRIGGER connector_intents_never_change_what_was_asked;
DROP TABLE connector_intents;
ALTER TABLE realms DROP COLUMN demands_trust;
"#;

/// Version 9: the rules withdrawal rests on, said by the database rather than only by the code.
///
/// Every one of these is already true of what this build writes. They are here because the Rust
/// that upholds them is not the only thing that can open a realm's file: a second process, a
/// person with sqlite3, or a future call site that forgets. Withdrawal works by comparing a
/// generation for equality, so a generation that could be lowered would revive every permission
/// issued under it, and `workspaces` has been the only table saying so since version 4.
///
/// The identifier bound is the second line behind `Core::accept` checking a signature before it
/// records anything. An identifier in the history is an identifier; real ones are far under these
/// lengths, so importing a chain written by an earlier build is untouched.
pub const V9: &str = r#"
CREATE TRIGGER realm_generation_only_rises BEFORE UPDATE OF generation ON realms
WHEN NEW.generation < OLD.generation
BEGIN SELECT RAISE(ABORT, 'a grid generation only rises'); END;

CREATE TRIGGER realm_policy_version_only_rises BEFORE UPDATE OF policy_version ON realms
WHEN NEW.policy_version < OLD.policy_version
BEGIN SELECT RAISE(ABORT, 'a policy version only rises'); END;

CREATE TRIGGER principal_generation_only_rises BEFORE UPDATE OF generation ON principals
WHEN NEW.generation < OLD.generation
BEGIN SELECT RAISE(ABORT, 'an account generation only rises'); END;

CREATE TRIGGER device_generation_only_rises BEFORE UPDATE OF generation ON devices
WHEN NEW.generation < OLD.generation
BEGIN SELECT RAISE(ABORT, 'a computer generation only rises'); END;

-- A permission that was used stays used.
CREATE TRIGGER capability_spending_is_final BEFORE UPDATE OF spent_at ON capabilities
WHEN OLD.spent_at IS NOT NULL AND NEW.spent_at IS NOT OLD.spent_at
BEGIN SELECT RAISE(ABORT, 'a permission that was used cannot be unused'); END;

-- A withdrawal is recorded as it happened, and cannot be unrecorded.
CREATE TRIGGER revocations_never_change BEFORE UPDATE ON revocations
BEGIN SELECT RAISE(ABORT, 'a withdrawal is recorded as it happened'); END;

CREATE TRIGGER revocations_never_vanish BEFORE DELETE ON revocations
BEGIN SELECT RAISE(ABORT, 'a withdrawal cannot be unrecorded'); END;

-- A packed copy's key and the place it is kept are printable, as Rust has always required. The
-- CHECK written at version 4 bounds the length and refuses a path; it says nothing about a tab or
-- a newline, so the two lines disagreed and the looser of them was the database. A trigger rather
-- than a CHECK because SQLite cannot add one to a table that already exists.
-- A nought byte is looked for as a blob rather than with GLOB, because SQLite reads a nought as
-- the end of a text value and every pattern match would stop there.
CREATE TRIGGER workspace_artifact_keys_are_printable BEFORE INSERT ON workspace_artifacts
WHEN NEW.object_key GLOB '*[' || char(1) || '-' || char(31) || ']*'
  OR NEW.object_key GLOB '*' || char(127) || '*'
  OR instr(CAST(NEW.object_key AS BLOB), x'00') > 0
  OR NEW.destination GLOB '*[' || char(1) || '-' || char(31) || ']*'
  OR NEW.destination GLOB '*' || char(127) || '*'
  OR instr(CAST(NEW.destination AS BLOB), x'00') > 0
BEGIN SELECT RAISE(ABORT, 'a packed copy is named by printable characters'); END;

-- An identifier in the history is an identifier, not a sentence somebody sent us.
CREATE TRIGGER audit_events_identifiers_are_identifiers BEFORE INSERT ON audit_events
WHEN length(NEW.principal_id) > 128
  OR (NEW.device_id IS NOT NULL AND length(NEW.device_id) > 128)
  OR (NEW.workload_id IS NOT NULL AND length(NEW.workload_id) > 128)
  OR (NEW.resource_id IS NOT NULL AND length(NEW.resource_id) > 256)
BEGIN SELECT RAISE(ABORT, 'an identifier in the history is an identifier'); END;
"#;

/// Taking version 9 back out again. Nothing but triggers was added, so dropping them is the whole
/// of it, and a realm taken back to version 8 is exactly the realm it was.
pub const DOWN9: &str = r#"
DROP TRIGGER audit_events_identifiers_are_identifiers;
DROP TRIGGER workspace_artifact_keys_are_printable;
DROP TRIGGER revocations_never_vanish;
DROP TRIGGER revocations_never_change;
DROP TRIGGER capability_spending_is_final;
DROP TRIGGER device_generation_only_rises;
DROP TRIGGER principal_generation_only_rises;
DROP TRIGGER realm_policy_version_only_rises;
DROP TRIGGER realm_generation_only_rises;
"#;

/// Version 10: the indexes the questions in this file are actually asked with.
///
/// Nothing here changes what a realm holds and nothing here is a new rule. Every statement is an
/// index, so a realm at version 10 answers the same questions as a realm at version 9 and answers
/// them without reading a whole table to find one row.
///
/// `hosts_by_device` is deliberately not unique, although one computer does offer one host row.
/// `put_host` keeps that true by writing the row that is staying first and deleting the others
/// after, so the reservations, placements, packed copies, sign-ins and commitments pointing at the
/// row that is going always have somewhere to move to. A unique index would refuse that first
/// write, and re-ordering it would mean either moving those rows onto a row that does not exist
/// yet or deleting an agreement a computer's owner made inside a performance change. The rule
/// stays where it is enforceable; this is the index that makes the question cheap.
pub const V10: &str = r#"
-- One host row per computer, which is the question offer_host, report_condition and withdrawing a
-- computer all ask. put_host is what keeps there being one.
CREATE INDEX hosts_by_device ON hosts (device_id);

-- What one piece of work has been tried on, and giving its reservations back.
CREATE INDEX leases_by_workload ON leases (workload_id);

-- The sweep: reservations that have run out, once a second, for ever.
CREATE INDEX leases_live_by_expiry ON leases (expires_at) WHERE released_at IS NULL;

-- What is reserved on one computer now.
CREATE INDEX leases_live_by_host ON leases (host_id, expires_at) WHERE released_at IS NULL;

-- Work on one computer, and the deadlines the sweep walks.
CREATE INDEX workloads_by_device ON workloads (device_id, stage);
CREATE INDEX workloads_by_principal ON workloads (principal_id, stage);
CREATE INDEX workloads_by_deadline ON workloads (expires_at) WHERE expires_at IS NOT NULL;

-- Whether anybody else in this grid could have agreed to this.
CREATE INDEX permissions_by_role ON permissions (permission, principal_id);

-- A request waiting for somebody to agree, found by what it is about.
CREATE INDEX requests_by_resource ON requests (resource_id, requested_by, state);

-- Allowances and sign-ins that have run out.
CREATE INDEX allowances_by_expiry ON standing_allowances (expires_at);
CREATE INDEX sessions_live_by_expiry ON workspace_sessions (expires_at) WHERE ended_at IS NULL;

-- The two columns put_host re-points that nothing indexed.
CREATE INDEX workspace_artifacts_by_packer ON workspace_artifacts (packed_by);
CREATE INDEX workspace_sessions_by_host ON workspace_sessions (host_id);

-- Packed copies nobody has been able to take.
CREATE INDEX workspace_artifacts_waiting ON workspace_artifacts (packed_at)
    WHERE taken_at IS NULL AND removed_at IS NULL;

-- Withdrawals newest first, and decisions by when they were made.
CREATE INDEX revocations_by_time ON revocations (revoked_at DESC);
CREATE INDEX decisions_by_time ON decisions (decided_at);

-- The history by time, for the window a reading reports over.
CREATE INDEX audit_events_by_time ON audit_events (at);
"#;

/// Taking version 10 back out again. Every statement in version 10 was an index, so dropping them
/// is the whole of it. A realm taken back to version 9 holds exactly the rows version 10 found and
/// answers exactly the same questions; it reads whole tables to find one row again. One host row
/// per computer is unaffected either way, because `put_host` is what keeps that true and
/// `put_host` does not change with the version.
pub const DOWN10: &str = r#"
DROP INDEX audit_events_by_time;
DROP INDEX decisions_by_time;
DROP INDEX revocations_by_time;
DROP INDEX workspace_artifacts_waiting;
DROP INDEX workspace_sessions_by_host;
DROP INDEX workspace_artifacts_by_packer;
DROP INDEX sessions_live_by_expiry;
DROP INDEX allowances_by_expiry;
DROP INDEX requests_by_resource;
DROP INDEX permissions_by_role;
DROP INDEX workloads_by_deadline;
DROP INDEX workloads_by_principal;
DROP INDEX workloads_by_device;
DROP INDEX leases_live_by_host;
DROP INDEX leases_live_by_expiry;
DROP INDEX leases_by_workload;
DROP INDEX hosts_by_device;
"#;

/// Version 11: what a bridge's import created, kept in the realm it created it in.
///
/// Until this, the only thing that could undo an import was a value in memory. A rollback was
/// therefore impossible after a restart, a crash or a reboot, which meant stage 4 of the rollout
/// had no undo on any day but the day it ran. Keeping it here rather than in a loose file beside
/// the realm gives three things a file cannot: it travels with `Core::backup`, it is covered by
/// the realm's own history, and it cannot be separated from the realm it describes.
///
/// The row holds identifiers and counts and nothing else: the accounts, computers, commitments,
/// images, workspaces and plans the import wrote, under the names the realm gave them. Nothing a
/// person typed and no value of anything is in it, which the column names and the trigger below
/// are both there to keep true.
///
/// A row is deleted when its import is undone. The evidence that it happened is the history,
/// which records both the import and the undoing of it and is never rewritten; keeping the row as
/// well would mean a realm that came back clean still differed from the realm before the import,
/// and the comparison that proves a rollback is exact would have to start making exceptions.
pub const V11: &str = r#"
CREATE TABLE bridge_imports (
    id        TEXT PRIMARY KEY,
    realm_id  TEXT NOT NULL REFERENCES realms(id),
    bridge    TEXT NOT NULL CHECK (bridge IN ('neo','desks')),
    grid_id   TEXT NOT NULL,
    at        INTEGER NOT NULL,
    undo      TEXT NOT NULL
);

CREATE INDEX bridge_imports_by_time ON bridge_imports (at);

-- What an import created is written once. Editing it would mean an undo that takes out something
-- the import never put in, which is the one mistake a rollback must not be able to make.
CREATE TRIGGER bridge_imports_never_change
BEFORE UPDATE ON bridge_imports
BEGIN SELECT RAISE(ABORT, 'what an import created is never rewritten'); END;
"#;

/// Taking version 11 back out again. The table goes, and with it the record of what any import
/// created; a realm taken back to version 10 can no longer undo an import it has not undone yet,
/// which is exactly the state version 11 exists to end.
pub const DOWN11: &str = r#"
DROP TRIGGER bridge_imports_never_change;
DROP INDEX bridge_imports_by_time;
DROP TABLE bridge_imports;
"#;

/// What version 12 adds: the other two bridges.
///
/// Version 11 wrote down what an import created and named the two bridges that existed then.
/// There are four now, and the column that says which one ran is checked against a list, so the
/// list is widened. SQLite cannot widen a CHECK in place, so the table is rebuilt and every row
/// it already held is carried over unchanged.
pub const V12: &str = r#"
DROP TRIGGER bridge_imports_never_change;
DROP INDEX bridge_imports_by_time;
ALTER TABLE bridge_imports RENAME TO bridge_imports_before_12;

CREATE TABLE bridge_imports (
    id        TEXT PRIMARY KEY,
    realm_id  TEXT NOT NULL REFERENCES realms(id),
    bridge    TEXT NOT NULL CHECK (bridge IN ('neo','desks','access','research')),
    grid_id   TEXT NOT NULL,
    at        INTEGER NOT NULL,
    undo      TEXT NOT NULL
);

INSERT INTO bridge_imports (id, realm_id, bridge, grid_id, at, undo)
SELECT id, realm_id, bridge, grid_id, at, undo FROM bridge_imports_before_12;

DROP TABLE bridge_imports_before_12;

CREATE INDEX bridge_imports_by_time ON bridge_imports (at);

CREATE TRIGGER bridge_imports_never_change
BEFORE UPDATE ON bridge_imports
BEGIN SELECT RAISE(ABORT, 'what an import created is never rewritten'); END;
"#;

/// Taking version 12 back out again, which narrows the list of bridges to the two that existed at
/// version 11.
///
/// A realm holding an Access Grid or a bounty import cannot go back: the copy below is refused by
/// the narrower check, the whole step is inside one transaction, and the realm stays at version 12
/// with its undo intact. That is the honest behaviour, because the alternative is a step that
/// quietly drops the one row a rollback needs.
pub const DOWN12: &str = r#"
DROP TRIGGER bridge_imports_never_change;
DROP INDEX bridge_imports_by_time;
ALTER TABLE bridge_imports RENAME TO bridge_imports_after_12;

CREATE TABLE bridge_imports (
    id        TEXT PRIMARY KEY,
    realm_id  TEXT NOT NULL REFERENCES realms(id),
    bridge    TEXT NOT NULL CHECK (bridge IN ('neo','desks')),
    grid_id   TEXT NOT NULL,
    at        INTEGER NOT NULL,
    undo      TEXT NOT NULL
);

INSERT INTO bridge_imports (id, realm_id, bridge, grid_id, at, undo)
SELECT id, realm_id, bridge, grid_id, at, undo FROM bridge_imports_after_12;

DROP TABLE bridge_imports_after_12;

CREATE INDEX bridge_imports_by_time ON bridge_imports (at);

CREATE TRIGGER bridge_imports_never_change
BEFORE UPDATE ON bridge_imports
BEGIN SELECT RAISE(ABORT, 'what an import created is never rewritten'); END;
"#;

/// What version 13 adds: the three ways of travelling that make a short-lived credential, the
/// settings each of them needs, and an administrator's say-so before a value may travel in a URL.
///
/// There is still no column here for a value, and there never will be. A minted token is a secret
/// with an expiry and it is held in memory by `core::mint::Cache`, which is handed to the broker
/// by whoever starts it; nothing writes one down, no backup carries one, and this file has nowhere
/// to put one.
///
/// What the settings are is decided in Rust by `credential::checked_settings`, because whether an
/// address is a token endpoint is not something a CHECK can answer. The two checks here are the
/// ones that would make a row dangerous rather than merely wrong: a settings map that holds
/// something that reads as a secret, and a value travelling in a URL with nobody's name against
/// the decision.
pub const V13: &str = r#"
-- What a minting credential needs besides its value: a token endpoint, a client identifier, a
-- region, a role. Names and addresses, and what each kind takes is decided in Rust by
-- credential::checked_settings, because whether an address is a token endpoint is not something a
-- CHECK can answer. The check here is narrow on purpose: it names a PEM block and the four keys a
-- value would be filed under, and nothing broader, because a rule that refused the word secret
-- anywhere would also refuse a token endpoint whose path happens to contain it.
ALTER TABLE credentials ADD COLUMN settings TEXT NOT NULL DEFAULT '{}' CHECK (
    substr(settings, 1, 1) = '{'
    AND instr(lower(settings), '-----begin') = 0
    AND instr(lower(settings), '"clientsecret"') = 0
    AND instr(lower(settings), '"secretaccesskey"') = 0
    AND instr(lower(settings), '"privatekey"') = 0
    AND instr(lower(settings), '"password"') = 0
);

-- Who said this credential's value may travel in the URL, and when. A query credential with
-- nothing here is recorded and refused by the broker, which is the safe way round: an Access Grid
-- brought across carries query credentials and has no such decision to carry with them.
ALTER TABLE credentials ADD COLUMN query_allowed_by TEXT;
ALTER TABLE credentials ADD COLUMN query_allowed_at INTEGER;

-- A credential that said it was a client certificate is retired and recorded as a token.
--
-- A client certificate is not a value that goes in a header, a parameter or a username: it is a
-- key the outgoing TLS handshake proves possession of, and the forwarder this grid sends through
-- builds its TLS with no client authentication. The word promised something the broker cannot do,
-- so it is gone from the type. Such a row is retired here, at a moment already on the row, so
-- that whatever it is called afterwards it is never sent; what to do with it is the
-- administrator's decision and `describe` says so. Nothing shipped ever wrote one.
UPDATE credentials SET kind = 'token', retired_at = COALESCE(retired_at, created_at) WHERE kind = 'certificate';

-- The seven words a credential may travel as, replacing the four of version 5. The three new ones
-- are the ones this grid makes a short-lived credential from; the value of each of those still
-- never leaves the computer the hub runs on.
DROP TRIGGER credentials_presentation_on_insert;
DROP TRIGGER credentials_presentation_on_update;

CREATE TRIGGER credentials_presentation_on_insert BEFORE INSERT ON credentials
WHEN NEW.presentation NOT IN ('bearer','header','basic','query','oauth','github-app','aws')
BEGIN SELECT RAISE(ABORT, 'a credential travels as bearer, header, basic, query, oauth, github-app or aws'); END;

CREATE TRIGGER credentials_presentation_on_update BEFORE UPDATE ON credentials
WHEN NEW.presentation NOT IN ('bearer','header','basic','query','oauth','github-app','aws')
BEGIN SELECT RAISE(ABORT, 'a credential travels as bearer, header, basic, query, oauth, github-app or aws'); END;

-- A credential is an API key, a password, a token or a service account. The fifth word is gone,
-- and these two are why the relabelling above comes before them rather than after.
CREATE TRIGGER credentials_kind_on_insert BEFORE INSERT ON credentials
WHEN NEW.kind NOT IN ('apiKey','password','token','serviceAccount')
BEGIN SELECT RAISE(ABORT, 'a credential is an API key, a password, a token or a service account; a client certificate needs mutual TLS, which this grid does not do'); END;

CREATE TRIGGER credentials_kind_on_update BEFORE UPDATE ON credentials
WHEN NEW.kind NOT IN ('apiKey','password','token','serviceAccount')
BEGIN SELECT RAISE(ABORT, 'a credential is an API key, a password, a token or a service account; a client certificate needs mutual TLS, which this grid does not do'); END;

-- Allowing a value to travel in the URL records who allowed it and when. One without the other
-- says nothing, and a flag with nobody's name on it is not a decision anybody made.
CREATE TRIGGER credentials_in_the_url_on_insert BEFORE INSERT ON credentials
WHEN (NEW.query_allowed_by IS NULL) <> (NEW.query_allowed_at IS NULL) OR TRIM(COALESCE(NEW.query_allowed_by, 'x')) = ''
BEGIN SELECT RAISE(ABORT, 'letting a credential travel in the URL records who allowed it and when'); END;

CREATE TRIGGER credentials_in_the_url_on_update BEFORE UPDATE ON credentials
WHEN (NEW.query_allowed_by IS NULL) <> (NEW.query_allowed_at IS NULL) OR TRIM(COALESCE(NEW.query_allowed_by, 'x')) = ''
BEGIN SELECT RAISE(ABORT, 'letting a credential travel in the URL records who allowed it and when'); END;
"#;

/// Taking version 13 back out again.
///
/// It drops what version 13 added and puts version 5's two triggers back, so a version 12 build
/// reads a version 12 shape. Three things do not come back, and the runbook has to say so: a
/// credential that travels as oauth, github-app or aws is left recorded with a word a version 12
/// build's trigger refuses to write, so it can be read and retired but not changed; the settings
/// those credentials carried are gone, so going forward again means entering them once more; and a
/// credential that said it was a client certificate stays retired and stays called a token.
pub const DOWN13: &str = r#"
DROP TRIGGER credentials_in_the_url_on_update;
DROP TRIGGER credentials_in_the_url_on_insert;
DROP TRIGGER credentials_kind_on_update;
DROP TRIGGER credentials_kind_on_insert;
DROP TRIGGER credentials_presentation_on_update;
DROP TRIGGER credentials_presentation_on_insert;

CREATE TRIGGER credentials_presentation_on_insert BEFORE INSERT ON credentials
WHEN NEW.presentation NOT IN ('bearer','header','basic','query')
BEGIN SELECT RAISE(ABORT, 'a credential travels as bearer, header, basic or query'); END;

CREATE TRIGGER credentials_presentation_on_update BEFORE UPDATE ON credentials
WHEN NEW.presentation NOT IN ('bearer','header','basic','query')
BEGIN SELECT RAISE(ABORT, 'a credential travels as bearer, header, basic or query'); END;

ALTER TABLE credentials DROP COLUMN query_allowed_at;
ALTER TABLE credentials DROP COLUMN query_allowed_by;
ALTER TABLE credentials DROP COLUMN settings;
"#;

/// The step from one version to the next. Version 1 builds everything; later versions each add
/// their own statements here, and run inside the same transaction as the record of having run.
pub fn step(version: u32) -> Option<&'static str> {
    match version {
        1 => Some(V1),
        2 => Some(V2),
        3 => Some(V3),
        4 => Some(V4),
        5 => Some(V5),
        6 => Some(V6),
        7 => Some(V7),
        8 => Some(V8),
        9 => Some(V9),
        10 => Some(V10),
        11 => Some(V11),
        12 => Some(V12),
        13 => Some(V13),
        _ => None,
    }
}

/// How to take one version back out, where that is possible at all. Version 1 built the whole
/// database and there is nothing to take it back to, and versions 2 to 4 have not been written
/// with a way back; what is here is what has one.
pub fn rollback(version: u32) -> Option<&'static str> {
    match version {
        5 => Some(DOWN5),
        6 => Some(DOWN6),
        7 => Some(DOWN7),
        8 => Some(DOWN8),
        9 => Some(DOWN9),
        10 => Some(DOWN10),
        11 => Some(DOWN11),
        12 => Some(DOWN12),
        13 => Some(DOWN13),
        _ => None,
    }
}

/// What each version did, for the record of migrations.
pub fn describe(version: u32) -> &'static str {
    match version {
        1 => "realms, people, computers, work, approvals, capabilities and the audit chain",
        2 => "credentials, who may use them, and which agreement each permission came from",
        3 => "model serving plans and sticky host assignments",
        4 => "workspaces, their placements, their images and how computers were committed",
        5 => "the credential broker: how a credential travels, where it may be sent, and one record per brokered request",
        6 => "the research profile: scopes, what was let in, acquired source, artifacts, findings and the one document that crosses",
        7 => "which typed command caused each event, so one command and everything it did read as one thing",
        8 => "what a connector was asked to do, written before it is asked, and what a realm demands a computer shows about itself",
        9 => "the rules withdrawal rests on, said by the database: generations only rise, a used permission stays used, a withdrawal is never unrecorded, and an identifier in the history is an identifier",
        10 => "the indexes the realm's questions are actually asked with; no row changed, and one host row per computer stays put_host's job",
        11 => "what a bridge's import created, so an import can still be undone after a restart and the undo travels with a backup",
        12 => "the other two bridges: an import may now say that an Access Grid or a bounty host is what it brought across",
        13 => "the three ways of travelling that make a short-lived credential and the settings each needs, an administrator's say-so before a value travels in a URL, and the retirement of any credential that called itself a client certificate",
        _ => "unknown",
    }
}
