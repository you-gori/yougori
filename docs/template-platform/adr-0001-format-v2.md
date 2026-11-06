# ADR 0001: Template format 2

Status: accepted, implemented in `setup/` (crate `yougori-setup`), 26 October 2026.

This is the reference for the format 2 template and project files, the conditions, the
placeholders, the typed resource kinds, the limits, the plan the crate computes, the review a
publisher uploads, and what every older client does with a format 2 package. The code is the
source of truth; this document states the contract it implements so the CLI, the desktop, the
engine and the website can be checked against the same words.

## 1. Decision

Keep `yougori-template.yaml` as the package entry point and `yougori.yaml` as the project. A file
that says `format_version: 2` is format 2. A file without one is format 1 (v1), read by the
clients' existing code. Every v1 field keeps its name and its meaning in format 2; nothing is
reinterpreted. Format 2 adds capabilities, bindings, typed resources, richer conditions, retention
defaults, views, aliases and a subtitle.

The shared crate `yougori-setup` owns the formats, the checks, the conditions, the resource
graph, the deterministic planner, the dependency lock and the published review. It reads no
file system, talks to no network and changes nothing; the same package and answers always give
the same plan and the same digest. The CLI, the desktop and the engine are renderers of its
results. Format 1 packages are planned by the same planner through the `v1` adapter, so they get
the same review, the same lock and the same determinism and are asked nothing new.

## 2. Version handling

| `format_version` | Meaning |
| --- | --- |
| absent, or `1` | Format 1. The clients' v1 parser reads it. `format::template` refuses it with `v1_format` so nothing in this crate pretends to read v1 YAML. |
| `2` | Format 2, read in full. |
| anything else | Refused with `needs_newer_yougori`: "This template needs a newer Yougori. It is written in format N, and this Yougori reads formats 1 and 2." Nothing is created. |

Both files of a format 2 package must say `format_version: 2`. A format 2 template must declare
`requires.yougori: 1.2.0` or newer: 1.2.0 is the first release that reads format 2, so an older
Yougori refuses the package at its requirement check, before creating anything.

What an older client does with a format 2 package: a 1.1.x CLI refuses `yougori-template.yaml`
at parse time (`format_version` is an unknown field in its strict v1 parser) and creates nothing.
The website stores a format 2 review beside the v1 keys (section 10), so a v1 client that only
reads a package's page still sees every grant.

## 3. `yougori-template.yaml`

Every v1 field is unchanged: `kind`, `name`, `title`, `summary`, `version`, `license`, `topics`,
`project`, `changelog`, `requires` (`yougori`, `gpu`, `platforms`), `inputs`, `tools`,
`tool_options`, `public`, `steps`, `outputs`. Format 2 adds:

| Field | Meaning |
| --- | --- |
| `format_version: 2` | Required. |
| `subtitle` | One line under the title, at most 120 characters. |
| `aliases` | Other names people search for. At most 16, each one line of at most 64 characters, no duplicates. |
| `profile` | `neo_grid`, `sandbox_grid`, `access_grid` or `swarm_mining_grid` when the template is one of the four grids. A grid resource's `spec.profile` must match it. Ordinary templates leave it out. |
| `capabilities` | A list of `{id, selection, locked, when}`. `id` is a registry id from `setup/src/capability.rs` (`grid.create`, `people.sso`, …); an unknown id is refused. `selection` is `required` (always on), `optional` (off unless the person turns it on) or `default` (on unless the person turns it off); it defaults to `required`. `locked: true` means the person cannot change the selection. `when` is a condition (section 5); a capability whose condition does not hold is not part of the setup. At most 64. |
| `bindings` | A list of `{id, type, resource, profile, question, hint, required, when}`. Installation-time choices the person makes on their own computer when the setup is applied: `type` is `folder`, `drive`, `file` or `resource`. For `resource`, `resource:` names the kind to choose from (`grid`, `environment`, `model_service`, …) and `profile:` may restrict a grid to one profile. Bindings share one id namespace with inputs. They are private to the installation: never in a public lock or review. Conditions cannot read them. |
| `inputs[].group` | Required on every input: one of `grid_workers`, `ai_models`, `website_api`, `people_access`, `files_data`, `automation_recovery`. The question is shown under that card. |
| `inputs[].editable` | Default `true`. `false` fixes the answer to the input's default (a default is then required; a secret cannot be fixed). An answer that differs from the default is refused with `fixed_value`. Requirements and permissions stay visible either way. |
| `inputs[].when` | A condition in any form of section 5 (v1's map form still works). |
| `outputs[].key` | A stable id for scripts, `[a-z][a-z0-9_]{0,31}`, unique. |
| `outputs[].private` | Shown once to the owner and never kept in public projections: an invitation, a key shown once. |
| `outputs[].when` | A condition; the output is shown only when it holds. |
| `retention` | `{on_stop: keep|ask, on_remove: keep|ask}`, both default `keep`. Deleting data is never a default; it is a separate operation that names what it deletes. |
| `views` | The standard views the setup page shows beside its overview, activity and settings: `computers`, `workers`, `models`, `workspaces`, `people`, `credentials`, `policies`, `approvals`, `audit`, `findings`, `reports`, `attempts`, `jobs`, `queues`, `files`, `storage`, `api`, `keys`, `usage`, `costs`, `budget`, `publications`, `teams`, `images`, `quotas`, `logs`, `diagram`. At most 16. Nothing else is rendered from template text. |
| `imports` | A map of namespace to `{item, version, digest, inputs, capabilities}`: a pinned component from another Hub template (section 8). At most 16. |

There is no `modes` key: a setup mode is an ordinary choice input (usually the first, with id
`mode`) that conditions refer to. There is no `actions` key: the setup page offers the actions the
selected capabilities support (the registry's `actions`), never actions a template declares.

Inputs keep the v1 question types `choice`, `multichoice`, `text`, `number`, `secret`, `domain`
and `yesno`, with the v1 rules for `choices`, `default`, `required`, `pattern` (the v1 pattern
engine, quantifiers up to 1000), `hint`, `min`, `max` and `min_length`. Ids of inputs, bindings
and output keys are `[a-z][a-z0-9_]{0,31}`.

`tools:` and `tool_options:` install into v1-style environments and into resources of kind
`environment` alike. `public:` entries name either kind too.

## 4. `yougori.yaml`

```yaml
format_version: 2
project: NAME
environments:        # optional, v1-style: the v1 fields with their v1 meaning
  web: {image: python:3.12-slim, ports: [8080]}
connections:         # optional, v1-style
  - web -> db
resources:           # format 2
  company:
    kind: grid
    capability: grid.create       # optional: left out of the plan when that capability is off
    depends_on: [other]           # readiness only, never connectivity
    when: {mode: create}          # a condition
    borrow: {setup: ID, resource: ID}   # or {binding: ID}: an existing resource, never destroyed here
    retention: {on_stop: keep, on_remove: ask}   # overrides the template default for this resource
    spec: {...}                   # typed per kind
```

Resource ids and import namespaces are `[a-z][a-z0-9_-]{0,62}`, the same pattern the website
stores. A v1-style environment, a `public:` entry and a connection become resources too: ids
`web`, `public_web` and `connection_web_db`. `publish:` is refused in a template, as in v1.

### 4.1 Kinds and their specs

Every spec refuses unknown fields. Defaults are in parentheses. Every kind except
`service_publication`, `volume`, `connection` and `artifact_store` also takes
`secrets: {NAME: "{{secrets.ID}}"}`, a map of named secret bindings the handler needs. Any list
entry of any spec may carry `when:` (section 5): the entry stays when the condition holds and
the key is removed before typing.

| Kind | Fields | Outputs |
| --- | --- | --- |
| `environment` | The v1 environment fields exactly: `type` (container, gpu, microvm, vm), `image`, `source`, `cpu`, `memory`, `gpu`, `command`, `entrypoint`, `environment`, `secrets`, `files`, `automatic_start`, `health`, `setup`, `working_dir`, `user`, `volumes`, `storage`, `storage_drive`, `ports`, `internet`, `pc_access`, `permissions`, `depends_on`, `restart`, `cloud`, `shared`; plus `tools` (filled by the planner). The v1 template rules apply: no `storage_drive`, no `health.bearer_secret`, paths inside the package only. | `name`, `address` |
| `grid` | `profile` (required: neo_grid, sandbox_grid, access_grid, swarm_mining_grid), `mode` create/join/attach (create; attach needs `borrow:`), `name`, `coordinator` this_computer/remote (this_computer), `address` (the coordinator's private network address), `access` lan/quick/domain (lan), `domain` (needed with domain), `member` computer/person (join only), `sign_in` password/sso, `username`. Join needs `secrets.invitation`; a person with password sign-in needs `secrets.password`. | `realm_id`, `join_address`, `name`, `page`, `invitation` |
| `compute_pool` | `grid` (reference), `source` this_computer/selected_computers/cloud/any (this_computer), `computers` (names, needed for selected_computers, at most 64), `gpu` none/optional/required, `limits {cpu, memory_gb, disk_gb, gpus}`, `availability` always/idle/scheduled, `idle_after_minutes` 1 to 1440, `schedule` (needed for scheduled), `local_user_first` (true), `cloud {provider, gpu_type, region, max_hourly_cost}` (needed for cloud). | `id`, `computers` |
| `worker_group` | `pool` (reference to a compute_pool), `role`, `count` (1, at most 256), `max`, `model` (reference to a model_service), `environment` (reference to an environment: the isolated sandbox each worker gets), `source` (binding of type folder), `limits`, `budget {time_minutes, cost_cap, currency}`. | `id`, `count` |
| `model_service` | `model` (required), `revision`, `format`, `quantization`, `backend`, `compute` (reference to a compute_pool or environment), `replicas` (1, at most 64), `gpu`, `memory_gb`, `placement` remaining/all, `share_percent` 1 to 100, `api {protocol: openai, keys, first_key}`, `network {listing: free|paid, enabled}`, `team {strategy plan|mixture, lead (reference), workers [references], computers 1 to 32, rounds}`. | `id`, `endpoint`, `model`, `first_key` |
| `workspace_pool` | `compute` (reference to a compute_pool), `allocation` per_person/shared, `runtime` container/microvm/vm, `image` (optional; a VM needs one), `count` (1, at most 1024), `quota`, `resources {cpu, memory_gb, disk_gb, gpus}`, `gpu` (bool), `parking`, `backup`, `cloud_fallback`, `data` (reference to a volume), `drive` (binding of type drive). | `id`, `access_url` |
| `access_binding` | `grid` (reference), `people` just_me/team, `roles` [owner, admin, member], `admin {username, display_name, email}` (needs `secrets.admin_password`), `person {username, display_name}` (needs `secrets.password` unless `sso`), `workspace_pool` (reference), `invitations`, `sso {issuer, client_id, username_claim, passwordless}`, `mfa` (require two-step for everyone), `workspaces` individual/shared. | `id`, `join_method`, `page` |
| `credential_broker` | `grid` (reference), `credentials [{name, kind bearer/header/basic/query/oauth/github_app/aws, field, value, destinations, methods, paths, approval ask/standing/never, per_hour (standing only), expires_hours 1 to 8760}]` (unique names, at most 256; `value` names a key under the broker's `secrets:`), `rotation_days`, `audit_export`, `agents [mcp, api, cli]`. | `id`, `endpoint` |
| `service_publication` | `target` (reference to an environment, model_service or workspace_pool), `port` (required), `access` quick/domain/lan/private/none (quick; domain needs `domain`), `domain`, `health {path, expected_status}`. | `url`, `port` |
| `volume` | `size_gb`, `retention`, `shared`, `drive` (binding), and the scheduled backup of section 17: `backup_schedule`, `backup_timezone`, `backup_keep`, `backup_consistency`, `backup_missed`, `backup_overlap`, `backup_retries`, `backup_through` (reference to an environment). | `id`, `name` |
| `connection` | `from`, `to` (references, different), `ports`, `permissions` [network, ports, files, volumes, data, secrets], `direction` one_way/two_way. Connectivity is declared here and nowhere else. | `id` |
| `job` | `compute` (reference to a compute_pool or environment), `image`, `command` (1 to 64 parts), `inputs` [references to artifact_store or volume], `outputs` (reference to an artifact_store), `source` (binding of type folder), `timeout_seconds` (3600, at most 7 days), `resources`, `retry {attempts (at most 10), backoff_seconds}`, `checkpoint`, `idempotent`, `reconcile` none/manual, `schedule`. A job that may run again (`attempts > 1`) must say `idempotent: true` or `reconcile: manual`. | `id`, `status` |
| `artifact_store` | `max_gb` (10), `retention_days`, `access` setup/grid, `drive` (binding). | `id`, `path` |

## 5. Conditions

The v1 shorthand stays: a mapping is AND between its inputs, and a list of answers is membership
(`{mode: create, providers: [codex, claude]}`). Format 2 adds `{all: [...]}`, `{any: [...]}` and
`{not: {...}}`, which stand alone and nest at most 8 deep, with at most 32 conditions under one
`all` or `any` and at most 12 answers per input.

A condition may only name an input that comes earlier (for an input's own `when`) or any input
(for capabilities, bindings, resources, list entries, tools, steps and outputs), and never a
secret. An unknown, forward, secret or self-referencing input is refused when the template is
checked: `unknown_input`, `secret_in_condition`, `condition_too_deep`. Answers in a condition are
checked against the input's choices. An input with no answer never matches.

## 6. Placeholders and references

| Form | Where | Meaning |
| --- | --- | --- |
| `{{inputs.ID}}` | any spec string, steps, outputs | The answer. In a typed spec a string that is exactly one placeholder takes the answer's own type: a number question gives a number, a yes/no question `true`/`false`, a multiple-choice question a list; inside longer text it stays text. If the input was not asked, the field or list item is left out and the kind's default applies. In a v1-style environment every answer is text, as in v1. |
| `{{secrets.ID}}` | a `secrets:` value, as a whole | The name of the binding that holds the secret, never its value. An optional secret that was not given leaves its key out. |
| `{{instance}}` | anywhere | The setup's name. |
| `{{env.NAME}}`, `{{public.NAME}}` | steps, outputs (v1 places) | As in v1; the engine fills them after the setup exists. |
| `{{outputs.RESOURCE.NAME}}` | steps, outputs | A resource's output once it exists; `NAME` must be one of the kind's outputs. |
| `{resource: ID}`, `{resource: ID, output: NAME}` | typed reference fields | Another resource of this setup. It adds a readiness edge; it grants no connectivity. |
| `{binding: ID}`, `{binding: ID, output: NAME}` | the same fields | An existing resource of another setup, chosen when the setup is applied through a binding of type resource whose kind is allowed in that field. The public package never holds an installation id. |

No placeholder may appear in a path on this computer: `files[].source`, `volumes[].source`,
`pc_access[].path`, `source`, `storage_drive`, `depends_on`. Placeholders work in values, never
in keys. Every spec is checked twice: with sample answers when the template is checked, and with
the real answers when it is planned.

## 7. Limits

All in `setup/src/limits.rs`, one place, and a refusal names the limit and the count:
dependency depth 8, 256 resources in a plan, 512 dependency edges, 32 dependencies per resource,
condition depth 8, 32 conditions under all/any, 12 answers per condition; 50 inputs, 12 choices,
64 capabilities, 16 imports (one level), 16 aliases of 64 characters, 16 views, 20 steps, 20
outputs, 10 topics; review text 4000 characters, review depth 4, review 128 KiB; template file 64
KiB, project file 1 MiB, 1000 files of 5 MiB in a 25 MiB package, paths of 512 characters with
255 per name.

## 8. Imports and the lock

`imports: {NAMESPACE: {item: publisher/name, version, digest, inputs, capabilities}}` pins one
version of one Hub template by the SHA-256 of its files. The planner receives the resolved
component (its checked files and digest) from the client; a component whose item, version or
digest differs from the pin is refused with `digest_mismatch` and nothing is created (F08). The
component's resources are flattened under `NAMESPACE.ID`, so two imports with the same inner
names never collide (F09). Its questions are answered by the import's `inputs` (fixed values, or
`{{inputs.ID}}` / `{{secrets.ID}}` of the parent) and never asked again; its optional
capabilities are on only when listed under `capabilities`. A component that imports components
of its own is refused: one level only, as the website stores one namespace level.

`lock::Lock` (`yougori-lock.yaml`, `formatVersion: 1`) records the template's name, version, item
and digest, every component's pin, the capabilities that were on, every resource of the expanded
graph with its kind and namespace, the images and artifacts the review listed, the required
Yougori and the plan digest. It holds no secret, no binding and nothing about the computer, so it
can be public. `Lock::verify` refuses a changed component digest and reports a changed template
version; nothing follows a moving "latest" on its own.

## 9. The plan

`plan::plan(&Package, &Answers, &Host)` returns `plan::Plan` or every reason there is none. It
checks this computer (Yougori version, platform, GPU), resolves the answers (defaults, fixed
values, `awaiting_input` for each unanswered required question, binding names for secrets),
decides the capabilities (selection, locked, `when`, the registry's `enableable`, `requires` and
`conflicts`; planned capabilities are `capability_not_enableable`), resolves the imports, builds
the graph, keeps only the resources whose capability is on and whose condition holds (a kept
resource that needs a dropped one is `dependency_left_out`), orders it (dependency order with the
smaller id first among ready nodes), renders and types every spec, validates references,
outputs and bindings, and writes the review.

`Plan` is camelCase on the wire; specs keep their YAML field names. It carries `formatVersion`,
`instance`, `template` (name, version, format, item, digest, profile, component pins),
`requires`, `capabilities` (id, selection, locked, applies, enabled, group, name, permissions),
`inputs` (public answers), `secrets` (input id to binding name), `bindings` (private, by id),
`resources` in order (id, kind, title, capability, component, dependsOn, borrow, retention,
placement, spec as JSON, outputs), `order`, `steps` and `outputs` (answers filled in; what exists
only after apply stays as written), `retention`, `views`, `review` and `digest`. The digest is the
SHA-256 of the plan's canonical JSON with the digest field empty; the same package and answers
give the same digest.

`review` lists what is created and borrowed with its placement, downloads (images, models, tools,
installer addresses), permissions (per resource and per enabled capability, in the registry's
words), costs (rented compute, budgets, cloud fallback), warnings (most serious first, the v1
sentences), notes about this computer, totals (sandboxes, cpu, memory, storage, gpu), the asked
questions with their public answers (never a secret's), PC folders, public addresses and the
retention defaults.

## 10. The review a publisher uploads

`plan::published_review(&Package, notices)` is pure and deterministic, holds no binding, no
secret and no path of the publisher's computer, and is what the CLI sends to the Hub for a
format 2 package. The website never parses YAML; it stores this JSON and shows it.

Shape: `format: 2`, plus every v1 key still filled (`environments`, `public`, `connections`,
`tools`, `inputs`, `steps`, `pcAccess`, `warnings`, `totals`, `requires`), so a client that only
knows format 1 keys still shows the grants; plus:

- `resources: [{id, kind, dependsOn: [ids], when: [sentences], summary: {scalar values}}]`: one
  entry per `resources:` entry, as written (placeholders included). `summary` holds the spec's
  top-level scalar fields, a list of scalars joined with commas, a reference as `resource:ID` or
  `binding:ID`, the secret names as text, and `capability` and `borrowed` when set. At most 32
  summary fields, 32 `dependsOn`, 32 `when` sentences.
- `capabilities: [{id, selection, locked}]`.
- `subtitle`, `aliases` (at most 16 of 64 characters), `retention: {onStop, onRemove}`.
- `inputs[]` gain `group` and `editable: false` where set; `public[]` and `connections[]` entries
  from resources carry `resource`.

Bounds (shared with the website): text 4000 UTF-16 units, nesting 4, 256 resources, 64
capabilities, 128 KiB in all. `plan::review_shape_problem` checks them the way the website does;
`plan::review_differs` compares a page's review with the files' in the parts that matter and
never compares across formats.

## 11. Diagnostics

Every refusal is a `dto::Diagnostic` with a stable code, a plain sentence and, where it has a
place, a field path (`inputs[2].group`, `yougori.yaml.resources.company.spec.profile`). Codes
used by this crate: `needs_newer_yougori`, `v1_format`, `invalid_yaml`, `invalid_format`,
`missing_file`, `missing_field`, `invalid_value`, `invalid_path`, `host_path`, `duplicate_id`,
`unknown_input`, `unknown_group`, `unknown_capability`, `capability_requires`,
`capability_conflict`, `capability_not_enableable`, `locked_capability`, `fixed_value`,
`unknown_kind`, `unknown_resource`, `unknown_output`, `unknown_binding`, `unknown_view`,
`invalid_placeholder`, `invalid_condition`, `secret_in_condition`, `condition_too_deep`,
`dependency_cycle`, `dependency_left_out`, `limit_exceeded`, `digest_mismatch`,
`missing_component`, `missing_import_input`, `awaiting_input`, `awaiting_binding`,
`invalid_answer`, `unsupported_here`, `template_changed`.

## 12. Verification

`setup/tests/planning.rs` covers F03 to F10, F17 and F19 of the plan's matrix plus cycles,
limits, determinism and placeholder typing; `setup/tests/v1.rs` covers F01 (hello-site compiles
to the same setup with no new questions); `setup/tests/packages.rs` runs
`examples/hub/{sandbox-grid,neo-grid,access-grid}` as golden fixtures: each checks clean, plans
with its `answers/*.json`, gives the same digest twice, and publishes a review the website
accepts; the plans and reviews are kept under `setup/tests/fixtures/` and refreshed with
`UPDATE_FIXTURES=1`.

## 13. The update merge

Updating an installed setup is a three-way merge between the installed base (its template
version and the answers it was applied with), the setup's recorded local customizations
(capability choices, answers, and capabilities the person added through "Add capability") and
the new template version. `merge::merge` is pure and deterministic: it returns the capability
selections and answers to apply plus a list of typed conflicts, and it never overwrites a local
choice. An upstream default applies only where the person never chose. A question removed or
retyped upstream while answered locally, a capability turned off locally but now required
upstream, a value locked to a new one upstream, a new required question, and a new grant or
download each become a conflict (`question_removed`, `question_retyped`,
`capability_now_required`, `locked_value_changed`, `new_required_question`,
`new_grant_to_review`), kept visible for the person to resolve; a resource removed upstream that
still holds data is retained (`resource_removed_with_data`), never deleted. Conflicts come out
sorted with data safety first. The engine asks only the newly required questions (section 8)
and shows new grants for review before applying.

## 14. The CLI's part

`yougori template check FOLDER` reads either format: a format 2 package is checked by the crate
and shown with its resources, capabilities, data retention and aliases. `template publish`
uploads the format 2 review for a format 2 package and refuses, before sending, a licence the
Hub does not accept or a `format_version` line that does not match the package; the website's
own refusals (`format_unsupported`, `review_required`, `alias_reserved`,
`review_format_unsupported`) are shown as the website words them. `yougori run hub/…` and
`template run` of a format 2 package go through the engine's setup service: the plan is worked
out with the answers (every input, `capabilities.ID` for optional ones, binding ids for folders,
drives, files and existing resources as `SETUP/RESOURCE`), reviewed and confirmed, then applied
with the secrets only in the apply, and the run follows the operation to its end; `--dry-run`
plans and creates nothing. Format 1 packages run exactly as before. `cli/src/hub/plan.rs` holds
the pure entry points (`check_folder`, `plan_folder`, `host_here`) and the v1 adapter filler
`legacy_of`. `cli/src/hub/components.rs` resolves a package's imports: each pin is downloaded
through the hub client (or reused from the checked copy on this computer), a digest that differs
from the pin is refused and never substituted, a nested import or a format 1 component is
refused, and the planner gets the flattened package; the engine resolves through the same
function. `template check` lists the pins as resolved, `template plan` returns the lock. In an
interactive run a binding of type resource offers the existing resources of the person's setups
(owned ones and borrowed ones, by kind and profile) from the engine's setup list; scripts give
bindings with `--binding ID=VALUE` (a folder, a drive, a file, or `SETUP/RESOURCE`). `scripts/test-hub-contract.mjs` runs the CLI against the website's real server:
it publishes the CLI's real reviews in both formats and reads them back, and checks that a
format 1 page and a format 2 page are compared on the grants both write (F12, F13).

## 15. Review hardening (2026-10-26)

The setup crate review and the engine handler review changed these rules. Each has a test in
`setup/tests/review_fixes.rs` (or the suite named).

- Folders of this computer belong to the template. In an environment, `volumes[].source`,
  `volumes[].bind`, `volumes[].read_only`, `pc_access[].path` and `pc_access[].read_only` take no
  placeholder, and a rendered environment may not mount a host folder its written form doesn't
  name, nor make one writable that it gives read only.
- `files:` sources are package paths, and tool installs come only from `tools:` and
  `tool_options:`; a spec's own `tools:` is refused. Secrets are `{{secrets.ID}}` of a secret
  input or the planner's own tool keys; a literal vault name is refused at check and at plan.
- A host sign-in copy comes only from the person's answer to a sign-in source input, which has
  no default and stays editable (v1: never a default of `computer`). `--yes` takes defaults, so
  it never copies a sign-in.
- YAML is read through one gate (`format::read_yaml`): at most 100,000 values with every alias
  counted in full, before any tree is built.
- A question's `pattern` refuses nested counts that must repeat more than 10,000 times, and
  matching runs on its own stack with a nesting bound, so no answer can crash a client.
- An environment name in format 2 is a resource id. The v1 adapter keeps `public_web` and
  `connection_web_db`; two entries that read alike get the same base plus a short digest of what
  they stand for, the first keeping the plain id.
- A locked optional capability is never on and satisfies nothing; a locked default one is always
  on and conflicts like a required one. Private-build capabilities never go in a template.
  Input ids `all`, `any` and `not` are reserved. A condition reads as at most 32 review sentences.
- `yougori template check` builds the graph, so a dependency cycle is refused before publishing.
- The published review renders typed sample answers, keeps every conditional list entry, shows
  an image chosen by an answer as written, includes each imported component under its namespace
  (an unresolved import is an error, never a partial review) and is checked against the
  website's closed format 2 rules (`checkClosed`) before upload.
- The lock's `plan_digest` covers only what the lock pins, so it is the same on every computer.
- Paths and names follow the website's rules: COM0 to COM9, LPT0 to LPT9, the superscript forms,
  CONIN$ and CONOUT$ are device names; two paths clash once composed (NFC) and lowercased;
  subtitles and aliases keep the title's badge rule and the stacked-accent rule over every
  combining mark; the soft hyphen, U+180E and the tag characters count as invisible.

## 16. Folder bindings into a sandbox (2026-10-26)

Section 15's first rule stands: a folder of this computer is never an answer. It says where a
folder may come from, and this adds the second source, which is not an answer either.

A folder of this computer reaches a sandbox in exactly two ways:

1. **The template's own folder**, a fixed path inside the package (`pc_access[].path`,
   `volumes[].source`), as before. No placeholder, checked against the package's files.
2. **A folder the person chooses**, through a binding of `type: folder` the template declares.
   The template says what it wants a folder *for*; the person says *which* folder, on their own
   computer, when the setup is applied. The planner resolves it, and only at plan time.

A binding is not a placeholder. It is not read from `inputs`, it cannot appear in a condition, and
an answer carrying the binding's id is an ordinary answer that resolves nothing: a plan with no
folder chosen for a required binding is refused with `awaiting_binding`. Tests:
`setup/tests/folder_bindings.rs`.

### 16.1 What a folder binding declares

| Field | Meaning |
| --- | --- |
| `read_only` | Default `true`. `false` lets the sandbox change files in the folder, and needs the person's explicit agreement when the setup is applied (section 16.4). Only a `folder` binding takes it. |
| `mode` | `mount` (default): the sandbox reaches the folder itself, through `pc_access`. `sync`: the sandbox keeps its own copy, and Yougori keeps the two in step (section 16.3). Only a `folder` binding takes it. |

### 16.2 Where a binding is used

An environment's `pc_access` entry takes `{binding: ID}` in place of `path:`, and a new
`sync:` list takes `{binding: ID, target: /inside, continuous, conflicts}`. The entry writes
neither the path nor the access: the person's choice fills `path`, and the binding's `read_only`
fills the access. Writing either in the entry is refused, so a read-only binding can never be made
writable where it is used. `pc_access` needs a binding of mode `mount` and `sync` one of mode
`sync`; using one the other way is refused by name.

Everything the review shows is unchanged in kind. A published review renders a bound folder as
"the folder you choose for ID", so it holds no path of the publisher's computer; a plan's review
shows the folder the person actually chose, with its access, as a permission and a warning. The
lock holds no folder: bindings stay private to the installation (section 3).

`format::bind_folders` is the one place that fills a folder in, and `host_access_widened` now
also refuses a rendered environment that adds a bound folder its written form did not name, or
that gives one a path or an access of its own. An imported component may not reach a folder of
this computer at all: the template that imports it binds the folder itself.

A chosen folder is checked as a folder: a full path, written plainly, no `..`, no control
characters. Whether it exists is the engine's to say, where the folder is.

### 16.3 Syncing a bound folder

`mode: sync` means the sandbox holds its own copy at `target`, and Yougori keeps the two in step —
both ways for a writable binding, from this computer only for a read-only one. The rules are the
launcher's own, moved to `cli/src/launcher/reconcile.rs` and read from there by both
`cli/src/launcher/live/two_way.rs` and the engine's `src-tauri/src/setups/folder_sync.rs`, so
`yougori launch` and a setup decide every path identically.

Only the side unchanged since the two copies last matched may be overwritten. A file changed in
both places is a conflict and never loses either version:

- `conflicts: keep_both` (default) keeps both. This computer's copy is left exactly as it is, and
  the sandbox's is written beside it as `NAME.from-sandbox`. The file stops syncing, and the
  setup says which file, until only one version is left.
- `conflicts: stop` stops the whole pass before changing anything, and says which file to look at.

Deletions follow the same rule, so a deletion never silently removes an edit. A record that
cannot be read decides nothing: every file that differs keeps both copies until they match again.
Nothing in the person's folder is deleted when the setup is stopped or removed.

### 16.4 The consent a writable folder needs

A template declaring `read_only: false` asks for permission; it does not grant it. The engine
adds a `write_folder:RESOURCE/BINDING` consent to the plan's review, beside the existing
`copy_signin:` ones, naming the folder and the sandbox in plain words. `setup_apply` carries back
only what the person agreed to, and the handler refuses the step with `folder_consent_needed`
when the agreement is missing: the folder is left alone rather than changed unseen.

A read-only bound folder needs no consent beyond the review it already appears in, because
nothing in it is ever changed.

## 17. A volume's scheduled backup (2026-10-26)

A template declares a backup as fields on the `volume` it is a backup of, rather than as a kind of
its own. A backup is not a resource a setup owns: it is a thing that happens to one, on a schedule,
and the person asks for it where the data is. The fields are flat scalars so every one of them
appears in the published review, which holds only top-level scalars (section 10).

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `backup_schedule` | text | — | The times, in words: `daily 02:00`, `weekdays 01:30`, `Mon-Fri 01:30; Sun 04:00`, `daily 02:00,14:00`. Entries are separated by `;`, each naming its days and one or more 24-hour times. Days are `daily`, `weekdays`, `weekends`, a day (`Mon`), a range that may wrap (`Sat-Mon`) or a list (`Mon,Thu`); the times alone mean every day. At most 200 characters, 8 entries, 24 times per entry, no time twice. Declaring it turns the backup on; everything else below works only with it. |
| `backup_timezone` | text | `local` | `local` (this computer's clock and its summer-time changes), `UTC`, a fixed offset from `UTC-12:00` to `UTC+14:00` in quarter hours, or a named zone from the table in `setup/src/resource/schedule.rs`. An unknown name is refused, naming the forms that work. |
| `backup_keep` | number | 7 | 1 to 90. Once a newer backup is complete, anything older than this is deleted. |
| `backup_consistency` | `stop` or `live` | `stop` | `stop`: the setup's other sandboxes that mount the volume are stopped while it is copied and started again after. `live`: nothing is stopped, and a file being written then can be copied half-written. |
| `backup_missed` | `run_once` or `skip` | `run_once` | What happens to a backup whose time passed while Yougori was not running. `run_once` makes one, however many were missed. |
| `backup_overlap` | `skip` or `queue` | `skip` | What happens when one is due while the previous is still running. `queue` runs one more straight after, and never more than one. |
| `backup_retries` | number | 2 | 0 to 5. A failed backup is tried again this many times, waiting longer each time, then waits for its next time. |
| `backup_through` | `{resource: ID}` | — | Required with `backup_schedule`. The sandbox of this setup that Yougori reads the volume out of and puts a restore back through. A binding (another setup's sandbox) is refused. |

Checked when the template is checked and again when it is planned, each with one plain sentence:

- The schedule and the time zone must read (`invalid_value`, quoting what was written and the forms
  that work). `backup_keep` and `backup_retries` must be in range.
- Any `backup_*` field without `backup_schedule` is refused, naming the fields that were set.
- `backup_through` must name a resource, not a binding or an output, and that resource must be an
  `environment` of this setup, of type `container` or `gpu`, that mounts this volume as a named
  volume (`unsupported_here` or `invalid_value`).
- With `backup_consistency: stop`, some sandbox other than `backup_through` must mount the volume;
  otherwise the setting stops nothing and is refused, pointing at a separate backup sandbox or at
  `live`.
- A volume with `backup_schedule` needs both `run.backups` and `run.schedule` declared with
  `selection: required` (`capability_requires`), so a published template cannot offer a backup that
  the person can turn off without the template saying so.

Golden and negative coverage is in `setup/tests/review_fixes.rs` and `setup/src/resource.rs`; the
time arithmetic, the named zones and the daylight-saving rules have their own tests in
`setup/src/resource/schedule.rs`. `examples/hub/backup-workflow/` is the worked package.

### Daylight saving, as RFC 5545 has it

The schedule is wall-clock time in its zone, and the engine keeps the moments in UTC. On the day
the clocks go forward, a time that does not exist is read with the offset in force before the
change, so `02:30` runs when the clocks show `03:30`. On the day they go back, a time that happens
twice runs once, the first time. Two times in one schedule that land on the same moment run once.
A fixed offset never changes, which is what a person who writes `UTC+02:00` is asking for.

### What the engine does with it

`src-tauri/src/setups/schedules.rs` keeps one record per backed-up volume in the setup registry
(`store::Registry::schedules`, schema 2), with the moment it is next due, so a restart knows what
was missed. `src-tauri/src/setups/backups.rs` takes the copy, checksums every file and the whole
set, keeps it under `<data>/setups/backups/<setup>/<volume>/<backup>` — never a folder a template
names — and puts one back, into a disposable copy by default or over the volume after a review.
A backup that no longer matches its own record is refused rather than restored.

The registry's schedules follow the setup: stopping it pauses them and keeps their place, starting
it resumes, removing it drops them. The backups already taken are **not** deleted with it; deleting
data stays a separate, explicit step. Nothing starts while the engine is shutting down.
