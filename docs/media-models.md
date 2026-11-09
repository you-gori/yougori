# Media models

A media model makes images, video, sound or speech instead of text. Yougori runs one the way it
runs a chat model: the same `yougori model run`, the same environment with its own volume,
verified download, API key and owner credential, the same `model status`, `model api`,
`model access`, `model usage` and `model stop`, the same app dialog, and the same publication
to a hosted inference. What differs is the API: a media model takes jobs, not conversation.

```text
yougori model run hf.co/stabilityai/sd-turbo --api --port 8000
yougori model generate sd-turbo --prompt "a red bicycle leaning on a white wall" --steps 2 --guidance 0 --size 512x512
yougori model generate ltx-video --prompt "waves at sunset" --seconds 3 --output D:/clips
yougori model generate mms-tts-eng --prompt "Hello from Yougori."
yougori model jobs sd-turbo                    # recent jobs
yougori model jobs sd-turbo JOB --save D:/out   # one job's files
yougori model optimize sd-turbo --keep-outputs 48
```

## What runs

| Kind (the model's `task`) | What loads | Where it comes from |
| --- | --- | --- |
| text-to-image, image-to-image | A Diffusers pipeline (Stable Diffusion, SDXL, SD3, FLUX, Qwen-Image, ...) | A Hugging Face repository with `model_index.json` |
| text-to-video, image-to-video | A Diffusers video pipeline (ModelScope, Wan, LTX, CogVideoX, HunyuanVideo, Stable Video Diffusion, ...) | The same |
| text-to-audio | A Diffusers sound pipeline (AudioLDM, AudioLDM2, MusicLDM, Stable Audio) | The same |
| text-to-speech | A Transformers text-to-speech checkpoint: VITS (the MMS voices) or Bark | A repository with `config.json` of that type |

`yougori model preflight hf.co/OWNER/MODEL` says the kind, the pipeline class, the files the
download takes and the memory it needs. The pipeline class decides the kind, not the
repository's tag, because the class decides what the runner can give it. Pipelines that need
inputs the runner does not give (inpainting masks, ControlNet conditions, upscalers, adapters)
are refused before anything downloads, and so are repositories without safetensors weights:
the runner loads no pickle checkpoints and runs no repository code.

The download takes each component folder that `model_index.json` names, in one precision for
all of them: the `fp16` variant where every component has one (half the bytes), otherwise the
plain files. Single-file checkpoints at the root and folders the index does not name (ComfyUI
copies, LoRAs) stay on the Hub. Every safetensors file is verified against its pinned checksum
before it is loaded. A speech checkpoint takes its root safetensors file.

At the first start the runner installs pinned `diffusers`, `imageio`, `imageio-ffmpeg`,
`soundfile`, `sentencepiece` and `protobuf` beside the pinned `transformers` and `accelerate`
into the Transformers image (`model_runner/media_backends.py`, `MEDIA_DEPENDENCIES`). The
pipeline loads in fp16 when it downloaded the fp16 variant and in bf16 otherwise
(`YOUGORI_MEDIA_DTYPE` overrides it); speech runs at full precision. When the weights fit the
free GPU memory with 2 GB to spare the whole pipeline moves to the GPU, otherwise its components
are offloaded to the CPU between uses and health says `offload: true`. A media model stays loaded
while it runs: automatic GPU memory does not apply, and stopping the model frees the GPU.

## The job API

The model server answers at its usual address (`model access`) with the model's API key.

| Route | What it does |
| --- | --- |
| `POST /v1/jobs` | Submits one job: `{"input": {...}}`. Answers 202 with the job: `id`, `status` (`queued`), `position`. |
| `GET /v1/jobs/ID` | The job: `status` (`queued`, `running`, `succeeded`, `failed`, `cancelled`), `progress` (0 to 1), `error`, `output`, `usage`, `expires`. `?wait=30` waits up to that many seconds (at most 600) for it to end. |
| `GET /v1/jobs/ID/result` | The output alone; 409 while it runs, 410 when it failed. |
| `GET /v1/files/ID` | One output file (`JOB.N`), with byte ranges for players. |
| `POST /v1/jobs/ID/cancel` | Stops a waiting or running job. |
| `GET /v1/jobs?limit=20` | The recent jobs, newest first (at most 100). |
| `POST /v1/files` | Uploads an input image: `{"data": "data:image/png;base64,..."}`; answers its id (`in_...`) for a job's `image`. Kept a day. |

The input fields: `prompt` (or `text` for speech), `negative_prompt`, `width` and `height`
(multiples of 8), `steps`, `guidance`, `seed` (random when omitted; the one used is in the
output), `count` (images, 1 to 8), `seconds` and `fps` (video), `seconds` (sound), `voice`
(speech; noted, not applied: each speech checkpoint has one voice), `image` (a data URL of at most 20 MiB or an uploaded file id, for the
image-to kinds), `strength` (image-to-image) and `format` (`png`, `jpeg` or `webp` for images;
video is MP4 and sound is WAV). A field a pipeline does not take is left out and named in the
job's `notes`. A video's frame count is the nearest its architecture renders (LTX in steps of
8, Wan and CogVideoX in steps of 4), so the output's `seconds` can differ a little from the
request. Inputs are checked before anything is queued; a wrong one answers 400 with the code
`media_input` and a fixed sentence.

The output: `images` (each with `width`, `height`, `file`, `url`), `video` (`seconds`, `fps`,
`frames`, `width`, `height`, `audio`), or `audio` (`seconds`, `sample_rate`), plus `files` and
`seed`. The usage: `images`, `output_seconds` (video or audio), `compute_seconds` (the GPU time).

One job generates at a time; up to 16 wait in order, and a 17th is refused with 429 and the
code `media_queue_full`. A job is stopped after 30 minutes. A request for a job the model does
not know, or whose files are gone, answers 404.

Finished jobs' files are kept 24 hours by default, in the model's own volume, under a cap of
20 GB with the oldest out first. `yougori model optimize ENV --keep-outputs HOURS` (1 to 720)
changes the time for the running model and its next starts. A restart marks the jobs it was
running as failed rather than guessing their state.

## OpenAI's shapes

Where OpenAI has an endpoint for the kind, the model server answers in that shape too, so the
official clients work with the model's address and key:

- `POST /v1/images/generations` (`prompt`, `n`, `size`, `response_format` `b64_json` or `url`,
  `output_format`, `seed`, `steps`, `guidance`, `negative_prompt`): one request, the images
  inline or as links to `/v1/files`, with `usage.images`; waits up to ten minutes.
- `POST /v1/audio/speech` (`input`, `voice`, `response_format` `wav`): the WAV bytes.
- `POST /v1/videos` (`prompt`, `seconds`, `size`, `fps`, `input_reference`, `seed`, `steps`),
  `GET /v1/videos/ID` (OpenAI's video object with `status` `queued`, `in_progress`,
  `completed` or `failed` and `progress` 0 to 100), `GET /v1/videos/ID/content` (the MP4),
  `DELETE /v1/videos/ID`.

`POST /v1/chat/completions` on a media model answers 404 with the code `task_mismatch`.

## What the engine, CLI and app show

Health (`model status`) adds `task`, `pipeline`, `offload`, `queue` (`waiting`, `running`),
`outputs` (`keptHours`, `capGb`, `bytes`, `jobs`) and `speed` (`secondsPerImage` or
`secondsPerOutputSecond` from the last jobs). `/v1/models` lists `task` and
`capabilities.media`, which a hosted inference reads to route jobs. Usage (`model usage`, the
app's Usage tab, `/v1/usage`) counts `images`, `output_ms` and `compute_ms` beside the request
counts; the token counters stay at zero.

`yougori model generate` submits a job, follows it (progress on stderr in a terminal) and saves
the files into `--output FOLDER`, or into `~/.yougori/outputs/MODEL/JOB`; `--no-wait` returns
the job at once. `--input FILE.json` reads a saved request and the flags change it.
`yougori model jobs ENV` lists the recent jobs; with a job id it shows one, `--cancel` stops it
and `--save FOLDER` downloads its files (`--wait SECONDS` first). `yougori model chat` on a
media model says to use generate.

The app's model dialog shows Generate in place of Chat: the prompt and the kind's options, the
jobs with their progress, previews of the files (images, a video player, an audio player) and
Save to folder. The API access tab shows the job routes and the OpenAI-shaped route of the
kind in Python, JavaScript, curl, PowerShell and as an agent skill.

## Adapters and pipeline runners

A media model may start with a LoRA adapter and with a pipeline of its own, each a public
Hugging Face repository at an immutable commit (`hf:OWNER/REPO@COMMIT`), so what loads is what
was named:

```
yougori model run hf.co/OWNER/BASE --adapter hf:OWNER/LORA@COMMIT
yougori model run hf.co/OWNER/BASE --runner hf:OWNER/PIPELINE@COMMIT
yougori model run hf.co/OWNER/BASE --adapter ... --runner ... --neocloud --environment POD
```

`--adapter` downloads the adapter's safetensors at that commit and loads them onto the pipeline
with Diffusers' PEFT loading (`load_lora_weights`; `peft` is installed first). `--runner` (for
a media model) downloads the repository and runs its `pipeline.py` as the pipeline, a Diffusers
custom pipeline, after installing the packages its `requirements.txt` pins: `NAME==VERSION`, or
`NAME @ git+https://github.com/OWNER/REPO@COMMIT` for a Diffusers commit newer than the pinned
release, which a new pipeline may need. Anything else in that file is refused before anything
is installed. This is the shape of an adapter on a large Diffusers base at a pinned Diffusers
commit: the base is the model, the adapter and the pipeline source are the two references.
Health, `model status` and the app name them (`adapter`, `pipelineSource`). Neither applies to
text-to-speech models or to chat models (a vLLM model's adapters attach at run time with
`model adapters`). The app's run form shows both fields once the compatibility check says the
model generates media.

## Pods

`yougori model run hf.co/OWNER/MODEL --neocloud --environment POD` runs a media model on a
rented RunPod GPU pod the way a chat model runs there: the preflight says the task, the pod
agent gets the model server with the media loaders delivered beside it (they are not in the
server bundle, which stays under the pod agent's size limit), and the same adapter and pipeline
runner flags. The pod's API is reached through the engine like a local model's, so `model
generate`, `model jobs`, the app's Generate view and a hosted inference's connector serve it
the same way.

## Hosted inference

The Inference Solver template (`examples/hub/inference-solver`, the engine of yougori.com's
hosted inferences) serves media models beside chat models. A connected server or computer
whose model is a media runner is listed with its task; chat on it answers `task_mismatch`, and
the website serves the job API and OpenAI's shapes under the inference's own address with its
API keys:

```
POST https://NAME.yougori.com/v1/jobs            {"model": "...", "input": {"prompt": "..."}}
GET  https://NAME.yougori.com/v1/jobs/JOB?wait=30
GET  https://NAME.yougori.com/v1/files/JOB.1
POST https://NAME.yougori.com/v1/images/generations, /v1/audio/speech, /v1/videos
```

The website submits each job to one replica of the model, like a chat request, reads its
state while it runs, and copies the files to itself when the job ends, so a result outlives the
computer that made it; the computer's copy is removed. Each job is a request in Usage, counted
by what it made (images, seconds of video or sound) and charged at the model's per-image and
per-second prices, which the administrator sets beside the token prices; a failed or cancelled
job is not charged. Outputs stay for the retention period and within the storage cap the
administrator sets (a day and 20 GB by default). Contributing computers relay jobs and files
through `yougori inference connect`; a connector from an earlier release is not sent media
jobs. Model pages carry a Try it box for signed-in members.

## Checks

`python -I -B scripts/model-server.test.py MediaRunnerTests` runs the runner with a fake
pipeline: file selection, input checks, the job API with files and byte ranges, the OpenAI
shapes, cancellation, the queue limit, retention and the restart rule.
`scripts/acceptance/media-check.py` runs four small open models on this computer's GPU
through a disposable engine, the real CLI and the real routes (sd-turbo, facebook/mms-tts-eng,
ali-vilab/text-to-video-ms-1.7b, cvssp/audioldm-s-full-v2). AudioLDM2 does not run on the pinned
Transformers 5 (its Diffusers pipeline calls a GPT-2 internal that was removed); AudioLDM does.
`python -I -B examples/hub/inference-solver/tests/test_media.py` runs the hosted inference's
job routes, OpenAI shapes, billing, retention, connector relay and Try it routes against a
disposable media model server; `scripts/acceptance/media-check.py --hosted` adds the template
in this process, serving the same four live models through the website-host connector.
