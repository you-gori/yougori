---
name: edit-my-api
description: Edit the two-sandbox My API Hub template and its website/provider services.
---

# Edit My API

Work in this package. Read `README.md`, `TESTING.md` and the repository's
`docs/hub.md` before changing its format. Preserve other agents' changes.

- `yougori.yaml`: exactly `web` and `models` environments, one private one-way
  connection from web to models, and one website publication. Model services are
  never host-published. Accounts live in `my-api-data`; weights in `my-api-models`.
- `yougori-template.yaml`: questions, conditional tool installation/sign-in and
  next steps. All tool targets are `models`. No credentials in answer fixtures.
- `site/start-models.py`: supervises selected paid (8080), gateway (8081) and Ollama
  (11434) services, restarts independently and stops all child processes.
- `site/start-ollama.sh`: waits for the Hub tool installer, then serves Ollama.
- `site/server.py`: website, admin bootstrap, discovery and request routing. The
  logical paid/free/local provider groups share the same host on different ports.
- `site/bridge.py`, `tool_models.py`: provider APIs and signed-in tool catalogues.
  Free-only models must be rechecked; unknown prices never qualify as free.
- `site/store.py`, `prices.py`, `chain.py`: database, pricing and manual payments.
- `site/pages.py`: existing website design; do not redesign during backend edits.

Verify from the repository root:

```
yougori template check examples/hub/my-api --format text
python -B examples/hub/my-api/tests/test_service.py
python -B examples/hub/my-api/tests/test_models_sandbox.py
python -B examples/hub/my-api/tests/test_tool_models.py
python -B examples/hub/my-api/tests/test_prices.py
cargo test --manifest-path setup/Cargo.toml --test packages my_api_always_has_two_sandboxes
```

Use the shared build target from the repository editing skill. The package test
accepts `UPDATE_FIXTURES=1` to refresh **only My API** plans/review after inspecting
changes. Loopback tests use disposable data and fake upstreams; they do not prove
real provider sign-in, GPU inference, or engine provisioning. A local source edit
does not change the published Hub download. Do not add migration work.
