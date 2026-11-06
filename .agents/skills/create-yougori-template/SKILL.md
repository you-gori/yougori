---
name: create-yougori-template
description: Create or extend a Yougori Hub template using the shared format-2 planner, typed resources and model receiver contract, including template-local editing instructions.
---

# Create a Yougori template

Read `docs/hub.md` before editing the package format. Use a current example matching
the workload: `examples/hub/hello-site`, `model-server`, or `inference-solver`.
Check `setup/src/resource.rs` and the relevant `src-tauri/src/setups/` handler for
what the engine actually executes. A schema accepting a resource is not proof
that every backend supports it.

For templates built from existing Sandbox VMs, use the code-authored flow in
`docs/code-authored-vm-templates.md`. Each new local VM contains the Python/JS/TS
`yougori` package and `.agents/skills/yougori-setup/SKILL.md`. Declare inputs,
setup hooks, explicit source files and GPU/Sandbox Grid choices there, then
capture the selected VMs and their connections. Never export runtime answers,
grid identities or application databases. Do not restore the removed Hub
capability checklist. Use the shared format-2 compiler and installer.

Use format 2 for new multi-resource templates. Declare capabilities visibly,
group questions by the decisions they make, and link resources with typed
references. Put inclusion conditions on resources as well as questions. Let the
planner derive dependency order and reverse removal. Use dynamic host ports,
explicit publication modes, persistent volumes and retention choices.

For local model attachment, declare a `model_service`, an owned receiving
environment, `yougori-models.yaml`, and a connection with `model_request: true`,
`ports: [8000]`, and one-way access only. The reviewed receiver argv is pinned in
the plan. Implement both idempotent attach and detach; receive credentials through
the temporary request file and print no secrets. Borrowed and grid model targets
are not supported by this connection handler. Inference Solver is the reference.

Reuse the shared runner, publications, secrets, connections and setup recovery.
When a missing primitive prevents an authorized product feature, implement it in
the shared engine with validation and failure-path evidence. Do not create a
template-specific privileged command tunnel or silently accept ignored inputs.
There is no user migration requirement in this repository.

Include a package-local `.agents/skills/edit-NAME/SKILL.md` describing the actual
files, invariants and verification commands that an editing agent needs. Document
the difference between local preview, real runtime validation, and publication.
Keep provider purchases, public deployment and data deletion within the user's
authorized scope. A private invitation service is not public paid inference.

Validate the package with `yougori template check FOLDER`. Add representative
`answers/*.json` without credentials and review deterministic plans using
`setup/tests/packages.rs`. Keep fixtures specific to the new package; do not
rewrite unrelated goldens. Exercise real HTTP/database behavior with isolated
fixtures before runtime work. Package no tokens, runtime state or build output.
