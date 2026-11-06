# Host My App

Run your app's container image with a health check and an optional public link.

Give Host My App the image of a web app or API you already build. Yougori runs it in a container on this computer, waits until its health path answers, restarts it if it stops, keeps its files in `/data`, and, if you want, shares it through a quick HTTPS link or your own domain.

```text
yougori template run ./examples/hub/host-my-app
```

From the Hub, search for "Host My App", or run `yougori run hub/PUBLISHER/host-my-app@1.0.0` with the publisher shown on its Hub page.

## What your image needs

- It starts the app by itself (its own `CMD` or entrypoint).
- The app listens on port **8080** on all addresses inside the container. Yougori also sets `PORT=8080`, which many frameworks read.
- A path, `/` unless you choose another, answers HTTP 200 when the app is ready.
- Anything that must survive a restart or an update is written under `/data`.

## Questions it asks

| Input | Type | Default | Notes |
| --- | --- | --- | --- |
| `image` | text | — | An image reference such as `ghcr.io/you/app:1.4.2`; pin a version |
| `health_path` | text | `/` | Must answer HTTP 200 |
| `cpu` | number | 1 | 0.5 to 16 cores |
| `memory_gb` | number | 1 | 0.5 to 64 GB |
| `storage_gb` | number | 10 | 1 to 512 whole GB |
| `app_secret` | secret | none | Optional; your app reads it as `APP_SECRET` |
| `access` | choice | none | none (only this computer), quick or domain |
| `domain` | domain | — | When `access` is domain; a domain saved with `yougori domain add` |

Example answers without secrets are in [`answers/`](answers).

## What it creates

- One container from your image, with the cores, memory and disk you chose, restarted when it stops.
- A persistent volume mounted at `/data`.
- A health check on port 8080 at your health path; the app counts as ready only once it answers 200.
- Its address: a port on this computer that Yougori chooses, and, if you asked, a quick link or your domain in front of it.

## Outputs

| Output | Value |
| --- | --- |
| Address | The app's address: on this computer, or its public link |
| Sandbox | The container's name, for `yougori logs` and `yougori terminal` |

## Managing it

Stop and start it from My setups. Updating the template version or your answers plans the change first; a new image replaces the container and keeps `/data`. Removing the setup removes the container and keeps the `/data` volume; deleting that data is a separate step that names it first.

## Known limits

- **Image only.** Building from your source folder is not part of this template yet. Build and push an image, or use `yougori up` in your project folder for a source-based project.
- **One container.** Databases or caches beside the app are not included; a separate recipe will add them.
- **Port 8080 inside the container.** The port inside the container is fixed so the public link can always find it. The port on this computer is chosen for you.
- **One secret.** More environment variables or secrets are set in the sandbox's settings after setup.
- **Health check** expects exactly HTTP 200 from a GET request.
- **Quick links** can change after a restart; the Address output is refreshed when it does.
- **No automatic rollback.** If a new image fails its health check, the setup reports which step failed and keeps `/data`; choose the previous image again to go back.
- **Health watching is planned.** The service's health path is checked when it starts. Watching it afterwards (Health check) and the Health and logs view are listed as planned in setup and can't be turned on yet; `yougori template status NAME` and `yougori template logs NAME` show the setup's state and activity meanwhile.
- **Platforms**: Windows x64 and Linux x64 builds; images must be for the computer's architecture.

## Files

| File | Purpose |
| --- | --- |
| `yougori-template.yaml` | Questions, capabilities, steps and outputs |
| `yougori.yaml` | The container and its publication |
| `answers/` | Example answers without secrets |
| `TESTING.md` | What maintainers check before publishing a version |
| `CHANGELOG.md` | Version history |
| `LICENSE` | MIT |
