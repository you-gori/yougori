# App Backend

Your app with a PostgreSQL database and an optional Redis cache, privately connected.

App Backend runs your app's container image beside PostgreSQL 16.4 and, if you want, Redis 7.4.1. Only your app can reach them, over one-way private connections; their data lives on volumes that survive restarts and updates. Your app can stay on this computer or go public through a quick link or your own domain.

```text
yougori template run ./examples/hub/app-backend
```

From the Hub, search for "App Backend", or run `yougori run hub/PUBLISHER/app-backend@1.0.0` with the publisher shown on its Hub page.

## What your image needs

- It starts the app by itself and listens on port **8080** (Yougori sets `PORT=8080`).
- A path, `/` unless you choose another, answers HTTP 200 when the app is ready.
- It reads its database settings from these variables:

| Variable | Value |
| --- | --- |
| `DATABASE_HOST` | `db` |
| `DATABASE_PORT` | `5432` |
| `DATABASE_NAME` | `app` |
| `DATABASE_USER` | `app` |
| `DATABASE_PASSWORD` | the password you chose |
| `REDIS_HOST`, `REDIS_PORT` | `cache`, `6379` (only when you add Redis) |

- It creates its own tables or runs its own migrations at start; the database starts empty.
- Files it must keep go under `/data`.

## Questions it asks

| Input | Type | Default | Notes |
| --- | --- | --- | --- |
| `image` | text | — | Your app's image, with a pinned version |
| `health_path` | text | `/` | Must answer HTTP 200 |
| `app_cpu` | number | 1 | 0.5 to 16 cores |
| `app_memory_gb` | number | 1 | 0.5 to 64 GB |
| `db_password` | secret | — | At least 16 characters |
| `db_storage_gb` | number | 20 | 2 to 1024 whole GB |
| `cache` | yes/no | no | Add Redis |
| `cache_host` | text, locked | `cache` | Shown so you know the host name; not editable |
| `access` | choice | none | none, quick or domain |
| `domain` | domain | — | When `access` is domain |

Example answers without secrets are in [`answers/`](answers).

## What it creates

| Part | Image | Data | Reachable from |
| --- | --- | --- | --- |
| `app` | your image | `/data` volume | this computer, or the link you chose |
| `db` | `postgres:16.4-alpine` | database volume | your app only, port 5432 |
| `cache` (optional) | `redis:7.4.1-alpine`, append-only file on | Redis volume | your app only, port 6379 |

Connections go one way: the app reaches the database and the cache; they cannot reach the app or each other.

## Outputs

| Output | Value |
| --- | --- |
| App address | On this computer, or its public link |
| App sandbox | For `yougori logs` and `yougori terminal` |
| Database sandbox | For a database shell with `yougori terminal` |

## Managing it

Stop and start it from My setups. A new image replaces the app's container and keeps every volume. Turning Redis off plans removing its container and keeps its volume until you delete it. Removing the setup removes the containers and keeps all three volumes; deleting the data is a separate step that names each volume first.

## Known limits

- **No backups yet.** Copy the database yourself, for example with `pg_dump` in the database shell, before risky changes.
- **No automatic migrations or rollback.** Your app owns its schema. If an update breaks it, the volumes are kept; choose the previous image again and repair forward.
- **PostgreSQL and Redis only**, at the versions above. Other databases are not part of this recipe.
- **Port 8080 inside the app container** is fixed so the public link can always find it.
- **Sizes**: the database gets 1 core and 1 GB of memory, Redis half of each; change them in the sandbox settings after setup if needed.
- **Quick links** can change after a restart; the address output is refreshed when it does.
- **Health watching is planned.** The service's health path is checked when it starts. Watching it afterwards (Health check) and the Health and logs view are listed as planned in setup and can't be turned on yet; `yougori template status NAME` and `yougori template logs NAME` show the setup's state and activity meanwhile.

## Files

| File | Purpose |
| --- | --- |
| `yougori-template.yaml` | Questions, steps and outputs |
| `yougori.yaml` | The app, database, cache, connections and publication |
| `answers/` | Example answers without secrets |
| `TESTING.md` | What maintainers check before publishing a version |
| `CHANGELOG.md` | Version history |
| `LICENSE` | MIT |
