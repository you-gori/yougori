# Inference Endpoint: maintainer test specification

Record each result with its evidence level, command, commit, platform and outcome. Skipped or blocked checks are recorded as such. Use a disposable Yougori state directory on a Windows x64 computer with a supported NVIDIA GPU, a small public safetensors model and a test key.

## 1. Package checks

| ID | Check | Pass when |
| --- | --- | --- |
| IE-P01 | `yougori template check ./examples/hub/inference-endpoint --format text` with a 1.2.0 candidate | No errors |
| IE-P02 | Same with a 1.1.x CLI | Early "requires Yougori 1.2.0" |
| IE-P03 | Publish scan | Clean; no key in any file |

## 2. Plan checks

| ID | Answers | Expected |
| --- | --- | --- |
| IE-L01 | `answers/private.json` | `server` and `endpoint` with access none |
| IE-L02 | Computer without a supported GPU | Refused before anything is created (`gpu: required`) |
| IE-L03 | `api_key` shorter than 32 characters | Refused |
| IE-L04 | Same answers twice | Same plan digest |

## 3. Runtime acceptance (plan 14)

| ID | Scenario | Pass when |
| --- | --- | --- |
| IE-R01 | Small model, access none | Ready only after `/health` answers; a chat completion with the key answers |
| IE-R02 | Request without or with a wrong key | HTTP 401 |
| IE-R03 | `access: quick` | Same through the quick link; local and public readiness shown separately |
| IE-R04 | More requests than `max_concurrent` | Extra requests wait; none fails for that reason alone |
| IE-R05 | Restart and update | Model files reused from `/models` |
| IE-R06 | Model too large for the GPU | Not ready; the out-of-memory reason shown; nothing reported ready |
| IE-R07 | Remove the setup | Sandbox removed; `/models` volume kept until deleted separately |
