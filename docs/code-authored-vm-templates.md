# Templates authored inside Sandbox VMs

Hub **Create template** selects existing Sandbox VMs. It no longer offers the
capability checklist. The selected VMs supply their code, CPU/memory settings,
network setting, service endpoints and active connections to one another.
Capture produces an ordinary format-2 Hub package using the shared planner.

The environment selection toolbar has **Create template** beside **Configure**;
it opens the creator with the selection, including mixed model/VM selections.
The creator keeps registered VMs selected and visibly lists items that cannot be
included; model IDs and unavailable VM IDs are never sent to capture. An invalid
name or an empty VM selection has a visible explanation beside the form rather
than an unexplained disabled action. Hub keeps **Create template**, and individual template cards
provide their run action. The redundant top-level Run/Publish template buttons
are removed. The creator still offers publishing after a reviewed export.

Expand **Template code & examples** in the Hub, VM configuration or template
creator for copyable Python and JavaScript/TypeScript examples and install steps.

Every newly launched local owner VM receives an offline package in
`/run/yougori/workspace`:

- Python: `yougori.py`, imported with `from yougori import Setup`.
- JavaScript/TypeScript: `node_modules/yougori`, imported with `import { Setup } from 'yougori'`.
- Authoring skill: `.agents/skills/yougori-setup/SKILL.md`.

The base image must contain the language runtime and application dependencies.
It must also pass the existing OCI import policy; images containing setuid/setgid
executables are refused. The examples use Alpine runtime images.
Yougori installs the SDK without pip/npm or an external download. Use a portable
OCI registry reference for the recipient image, preferably a pinned digest.
TypeScript authors compile their app with their normal build tools and include
the resulting files in the source list.

## Python example

Run this from the workspace inside a VM with Python installed:

```python
from yougori import Setup

setup = Setup("website", image="python:3.12-alpine",
              files=["app.py", "website.py"], command=["python", "app.py"])
setup.admin()
workers = setup.checkbox("workers", "Enable Sandbox Grid?")
setup.grid("sandbox", when=workers)
setup.input("provider", "Model provider", type="choice", default="local",
            choices=[{"value": "local", "label": "Local models"},
                     {"value": "api", "label": "Provider API"}])
setup.password("api_key", "Provider API key", when={"provider": "api"})

@setup.on_setup
def initialize(values):
    from website import create_admin_if_missing
    create_admin_if_missing(values["admin_email"], values["admin_password"])

def start(values):
    from website import serve
    serve(values)

setup.run(start)
```

Without installer answers this writes `.yougori/setup.json` and exits, without
calling the hook or starting the app. Capture reads the declaration; it never
evaluates author code on the host. The installation supplies fresh private
answers and starts the declared command **inside the VM**. Its default OCI
entrypoint is suppressed, so it cannot start ahead of setup.

`admin()` declares questions; the application's setup hook creates the account
using its own database and password hashing. It does not assume a framework or
silently create a second user database.

## JavaScript / TypeScript

```javascript
import { Setup } from 'yougori';
import { createAdminIfMissing, serve } from './site.mjs';

const setup = new Setup({ name: 'website', image: 'node:22-alpine',
  files: ['app.mjs', 'site.mjs'], command: ['node', 'app.mjs'] });
setup.admin();
const workers = setup.checkbox('workers', 'Enable Sandbox Grid?');
setup.grid('sandbox', { when: workers });
setup.onSetup(async values => {
  await createAdminIfMissing(values.admin_email, values.admin_password);
});
await setup.run(values => serve(values));
```

Both SDKs support text, secret, number, yes/no, choice and multiple-choice inputs,
email patterns, length/range constraints, hints, defaults for non-secrets, and
conditional questions (`when`, including `all`, `any`, `not`). At runtime numbers
are numbers, checkboxes are booleans, and multiple choices are lists. The app
decides what its custom questions enable. Secret questions cannot have defaults.

## Grids and permissions

The two selections are **GPU Grid** (`gpu`) and **Sandbox Grid** (`sandbox`).
Sandbox Grid includes CPU and memory together. A declared enabled grid installs
the existing guest controller and skill and starts the controller with the app.
It uses the existing contributor/job protocol, not a privileged host command
channel. Models and API providers can be configured through app code and private
inputs; the SDK does not rent GPUs, copy local provider accounts or grant CUDA
passthrough. GPU contributors still use the existing grid enrollment flow.

Capture preserves active connections only between selected VMs. A dependency
is installed before the app that calls it. Cyclic startup dependencies are
refused by the shared planner instead of being silently broken. Host file
permissions, custom relay routes (including enrolled credentials), public links, runtime answers and
application databases are not transferred. Recipients explicitly review
permissions before installation. Declared services can be published using the
existing VM publication controls; capture does not recreate a public exposure.

## Export, install and lifecycle

1. Build and run the setup declaration inside each VM's workspace.
2. Select the VMs in **Hub → Create template**, or select them under **My computer**
   and choose **Create template**.
3. Review the captured source/connections/questions, then save into an empty folder.
   A source or connection change invalidates that review.
4. Run the saved package with `yougori template run FOLDER`. The shared installer
   asks questions and keeps secrets as private bindings. The application receives
   those answers in its own `.yougori/answers.json`, not its command line.
5. Publish the reviewed folder with `yougori template publish FOLDER` when ready.

Source files are an explicit allowlist (individual paths, not directory globs).
Private locations and known credential/data filenames are refused, and the Hub
credential scan checks the resulting package. Review source before publishing:
a scan cannot recognize every possible application secret embedded in code.

Setup hooks must be bounded and idempotent. They run once per configuration;
an interrupted hook may be retried. A failed hook or immediate startup exit fails
installation and stops the new VM. Setup acknowledgement has a 60-second bound;
the application itself has no added execution timeout. Acknowledgement means the
hook finished and the app stayed running at startup, not that arbitrary HTTP
endpoints have been checked.

Application output stays inside the VM in `.yougori/application.log` and
`.yougori/application.previous.log` (256 KiB each). Verbose output does not cancel
the service or get copied into installer errors.

Stop/start stages the previous private workspace, preserving application data
and the initialization marker. Reconfiguration overlays only declared source
files, retaining undeclared data; new answers run the setup hook again. Existing
workspace quotas and connection budgets/leases still apply. The removal flow
keeps the private workspace unless its deletion is explicitly selected.

## Verification

```text
node --test scripts/test-setup-sdk.mjs scripts/check-guest-source.test.mjs
cargo test --manifest-path setup/Cargo.toml
cargo test --manifest-path src-tauri/Cargo.toml --lib setups::vm_sandbox::tests
npx vitest run src/components/setups/vm-template-creator.test.tsx src/pages/hub-page.test.tsx src/components/sandbox-configuration.test.tsx
```

SDK changes require rebuilding the guest and its source/checksum records. Updating
only the frontend does not update the native engine or the guest image.

The real Windows VM run on 5 November 2026 passed all seven checks in
[`runtime.json`](vm-sandbox/evidence/code-authored-templates-2026-11-05/runtime.json):
two-VM capture and connection, stale-review refusal, fresh private setup answers,
automatic application start, conditional Sandbox Grid, restart preserving data
and grid identity without repeating hooks, and failed-hook refusal. Both services
were disposable HTTP fixtures. All test VMs were stopped and their staged copies
removed. No Hub publication, cloud rental or GPU benchmark was performed.

The opt-in reproduction harness is `scripts/acceptance/code-authored-vm-template.py`;
pass `--cli PATH_TO_DEVELOPMENT_CLI --output NEW_EMPTY_DIRECTORY`. It imports its
Python Alpine image and creates temporary local VMs using the running engine.
