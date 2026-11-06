# Host My App: maintainer test specification

Record each result with its evidence level (static review, compile, unit or contract test, mocked integration, isolated runtime acceptance, publication and download verification), the command, the commit, the platform and the outcome. Skipped or blocked checks are recorded as such.

Use a disposable Yougori state directory and a small public test image that listens on 8080 (for example a pinned `traefik/whoami` with `--port 8080` baked into a test image you build). Never test against an app someone uses.

## 1. Package checks

| ID | Check | Pass when |
| --- | --- | --- |
| HA-P01 | `yougori template check ./examples/hub/host-my-app --format text` with a 1.2.0 candidate | No errors |
| HA-P02 | Same with a 1.1.x CLI | Early "requires Yougori 1.2.0"; nothing created |
| HA-P03 | Publish scan and manual read | No secrets, real domains or personal paths |
| HA-P04 | Every question is used | No unused input |

## 2. Plan checks

| ID | Answers | Expected |
| --- | --- | --- |
| HA-L01 | `answers/private.json` | `app` and `web` with access none; no domain asked |
| HA-L02 | `access: domain` without a saved domain | Refused with a pointer to `yougori domain add` |
| HA-L03 | `image: latest` | Refused by the pattern |
| HA-L04 | `storage_gb: 2.5` | Refused: whole GB only |
| HA-L05 | Same answers twice | Same plan digest |

## 3. Runtime acceptance (plan 14)

| ID | Scenario | Pass when |
| --- | --- | --- |
| HA-R01 | Run `answers/private.json` with the test image | Ready only after the health path answers 200; reachable on this computer only |
| HA-R02 | `access: quick` | Reachable through the quick link; local and public readiness shown separately |
| HA-R03 | Image that never answers 200 | Not ready; the failed step and recovery are shown; nothing is reported ready |
| HA-R04 | Write a file to `/data`, restart, update to a new image | The file survives both |
| HA-R05 | Update to an image that fails | `/data` kept; the setup explains how to go back |
| HA-R06 | Remove the setup | Container removed; `/data` volume kept until deleted separately |
| HA-R07 | Run twice on one computer | Separate containers, ports, volumes and secrets (plan L01) |
| HA-R08 | Run the published download through the desktop app and the CLI | Both reach a healthy app |
