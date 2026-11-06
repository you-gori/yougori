# Sandbox page, token billing and operator control panel

The template keeps its existing visual design. Sandboxes follows Models in the
navigation. It shows owner-contributed CPU cores, RAM and slots and their remaining
capacity; VM launch, commands and stop are inline. Admin retains an enable switch
and contribution limits. Compute activity is the final full-width admin panel.

Pricing is USD per million input/output tokens. Atomic reservations snapshot both
rates. Actual upstream usage determines the charge; missing/invalid usage is
unbilled. Usage history and balance now commit in the same transaction. This fixes
a race found by the HTTP billing test. Existing administrators may invite or
promote other administrators; public signup cannot grant that role, and the last
administrator is protected transactionally.

The admin Usage page displays bounded hardware history, individual GPU sensors,
workloads, sandbox allocations, request/token totals, user presence, revenue,
top-ups and the latest cloud account values. Queued VMs are separate from running
VMs; allocations are not presented as measured consumption. Cached engine state
is not reused as a fresh host measurement. Unknown usage is explicitly counted.

The desktop Hub's Create my inference action resolves a bundled first-party
template and opens the shared builder with its source preselected. Permissions,
inputs and costs still pass through the existing review flow. Windows, Linux and
macOS resource maps include the template; only Windows was built here.

## Verification

- Final full Python suite: 186 passed, zero failures. This includes real local
  HTTP/SQLite tests for authorization, role races, billing, capacity and telemetry.
- Desktop Hub/builder tests: 59 passed. This covers preselection without starting
  a workload. ESLint and frontend build passed (existing bundle-size warning).
- Native template tests: 10 passed; built-in locator: 1 passed; desktop command
  contract: 1 passed. All-target native check passed with six existing warnings.
- `tests/control-browser.mjs`: passed against disposable HTTP/SQLite services,
  including capacity, price editing, admin promotion, hardware charts, VM
  allocations, bottom activity placement, and 768/390-pixel layouts. No screenshots.
  Hardware values and queued VM execution in this browser fixture are synthetic.
- Template format check passed. Its wallet-address warning concerns pinned token
  contract documentation/code; it is not a creator-payment destination.
- The restarted preview at `http://127.0.0.1:3002` returned real CPU and RAM
  measurements, RTX 5090 Laptop GPU utilization, VRAM, temperature and power,
  and a growing hardware history. A request to the existing Qwen2.5-0.5B model
  succeeded before and after the desktop restart. These are live integration
  checks, not a performance benchmark.
- Installed desktop replaced with the source-built 1.2.0 binary, hashes compared,
  previous binary retained locally. The existing model was restored. The CLI
  was already on 1.2.0 and did not need a behavior change for this work.

The first full Python run found one stale adapter fixture: it recognized only
get_platform_state, while production now uses refresh_host_metrics. The fixture
now follows the real command contract and also verifies the older-engine fallback
does not invent fresh CPU telemetry. The focused compute suite passed 33/33.

Raw verification logs are local under
`C:/YougoriBuildCache/scratch/solver/control-*`; they are not release artifacts.

## Limits

- Sandbox contributions remain owner opt-in; the live preview was not enabled
  or assigned resources by these checks. Enable and configure them in Admin.
- CPU temperature and cloud sensors remain unavailable where the engine/provider
  has no measurements. RunPod account spending is from its latest Admin check.
- Hardware history is one hour; request aggregates cover 24 hours. Account tables
  show at most 500 entries, while account/online totals count all users.
- No cloud rental or cryptocurrency transfer was made. No source was committed,
  pushed or released. The installed build uses runtime resources from this checkout.
- This does not add automatic host-controller attachment to sandbox-hosted sites;
  that deployment limitation remains described in README.md.
