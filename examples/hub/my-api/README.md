# My API

A model API website with accounts, model-scoped keys, default token prices from
the providers' list prices, prepaid credits and payments to the admin's wallet.
Python standard library only. The website's look follows The Design Society
(thedesignsociety.fr): lavender, acid lime and electric blue, pixel titles, small
browser windows and a soft CRT screen. Its fonts are open-licensed and served by the
website itself (see Fonts), so nothing loads from outside the sandbox.

## Run this copy

From the repository root, using the CLI built from this checkout with checkbox and conditional tool setup support (the original 1.1.1 preview lacks these additions):

```sh
yougori template check examples/hub/my-api --format text
yougori run ./examples/hub/my-api
```

This folder must be published separately before a remote Hub reference can fetch
it. Editing these files does not update an installed instance.

The wizard first creates the website admin account: enter its email and a password
of 12 to 1024 characters. For an existing installation, choose **Keep my existing
admin**; no account or password is changed. Then check the tools you want: Codex,
Anthropic API, Gemini, OpenCode, Kilo Code and Ollama. Space toggles; Enter continues.

- Anthropic API: asks for an Anthropic API key, used only by the website API.
  This template does not install Claude Code or offer a Claude subscription sign-in.
- Codex and Gemini: choose **Subscription**, **API key** or **Both**.
  Only API/Both asks for a provider API key. Subscription/Both immediately asks
  **Use credentials from this computer** or **Sign in with a new account**, before
  creating any sandboxes. After installation it applies that choice and opens
  a separate sign-in window without asking the same question again.
  Copying is opt-in; a missing/expired sign-in can be replaced in that terminal.
  Setup stays in its original terminal and continues. Finish signing in and close
  each provider window when done. Setup prints a command to reopen each window;
  opening it does not mean the provider has verified your subscription.
- Kilo and OpenCode: choose **Free models only** or **Free and paid models**.
  Paid access then asks for account/subscription, gateway API key, or both, and
  which account to connect. A gateway key is asked for only in API/Both mode.
  The tool's `/connect` screen performs the actual account/provider selection.
- Kilo free-only API access is anonymous where the provider permits it. The bridge
  verifies every price component is zero again before inference. Paid/unknown-price
  models are excluded. Paid Kilo API access requires a gateway API key.
- OpenCode free chat stays in the OpenCode client. Paid website API access uses an
  OpenCode Console key and the documented Chat Completions subset listed in
  `bridge.py`; Responses, Messages, Gemini and System One models are not exported.
  OpenCode Go and other subscriptions are configured inside the tool.

Then choose who can open the website, in the same list `yougori launch` shows: **Quick public
link** (a temporary trycloudflare.com address), **Your own domain** (enter the public domain,
the tunnel origin port and your Cloudflare tunnel token or install command; it is saved for
next time), or any domain already saved on this computer. Add the route Cloudflare needs as the
setup shows (hostname, type HTTP, `http://localhost:PORT`).

Choose a private bridge secret of at least 16 characters, separate from your admin
password. Passwords, bridge secrets and API keys use the credential vault and hidden
CLI prompts; never put them on command-line arguments. The website creates the
admin from those protected bindings before listening for requests, and keeps only
the password hash in SQLite. It consumes the bootstrap values from its process
environment. Restarting or updating never overwrites an existing admin password.
There is no web endpoint for creating or promoting an admin.

Payment network and wallet selection happen only in the website after admin
sign-in. No network is preselected and buying credits stays disabled until the
admin saves a network and wallet. Existing wallet settings survive updates.

To change providers on an existing instance, run `yougori template update my-api`.
It revisits choices using your previous answers without asking for stored API
keys again. Deselecting a provider removes its secret binding from the next
project configuration; it keeps data and already-installed tool files. The UI
redesign and price settings are preserved. Hub stops and restarts the instance
when applying updates, and automatically retries once if the runtime still says
a container must be stopped. Model discovery starts automatically after setup.

Noninteractive runs use `--input providers=codex,kilo` (or a JSON array in an
inputs file), per-provider access/scope answers, `--input admin_email=EMAIL`, and
`admin_password` plus `bridge_key` through `--secrets -` on stdin. Use
`--input admin_account=existing` to preserve an existing admin without new credentials.
They leave terminal commands for sign-in; they never silently copy host accounts.

Yougori creates all four sandboxes, installs the selected tools and publishes the website
through a Cloudflare HTTPS quick link. Keep the host running. The quick link is
temporary and may change when republished. GPU use is optional at the Hub GPU
choice; CPU inference is slower. No weights are downloaded automatically.

## Services

| Sandbox | Service | Setup |
| --- | --- | --- |
| `web` | Website and text chat API on port 3000 | Sign in with the admin email and password entered in the CLI. |
| `paid` | Provider bridge on port 8080 and selected coding tools | Subscription sign-in, API keys or both, per selected provider. |
| `local` | Ollama on port 11434, GPU when available | When selected, install Ollama and run `ollama pull MODEL`. Otherwise the reserved sandbox stays idle. |
| `free` | Gateway bridge on port 8080 and selected OpenCode/Kilo tools | Free-only or explicit paid API access; paid gateway models need a selling price before use. |

Only the website is published. Connections are `web -> paid`, `web -> local` and
`web -> free`, with no peer-to-peer connections. Provider credentials stay in the
model sandbox; the web service knows only the bridge secret. Bridges reach
external providers over HTTPS.

Codex, Gemini, OpenCode and Kilo also have terminal shortcuts in the
next steps. Personal subscription logins are **not** converted into shared APIs.
Subscription access can restrict resale; use provider API keys with appropriate
provider permission for paying users. OpenCode's current free chat models require
its client: they are available in its terminal, not exported by this API.

Model discovery also reads the signed-in Codex model picker through its app-server
`account/read` and `model/list` methods. No conversation, tool run
or inference is started. These models appear under **Connected coding tools**;
they do not become shared API models or billable website keys. Discovery omits
signed-out tools and retries automatically after their sign-in window completes.
Model pickers describe the tool's offered models, not a guarantee of remaining quota.

OpenCode's free catalogue comes from `opencode models opencode --verbose --refresh
--pure`. Every refresh checks input, output and all other reported cost components;
unknown or nonzero prices are excluded in free-only mode. Kilo uses its current
gateway catalogue, with the same fail-closed price rule and another check before
each API call. Removed or formerly-free models disappear on the next refresh.
No fixed list of free model names is maintained. Discovery failures remove stale
availability until the next successful check; admin price overrides are preserved.

## Admin setup

1. Sign in with the email and password chosen in CLI setup (or your existing admin
   credentials after an update). An admin with no wallet is taken to Admin settings.
   Choose the payment network and receiving wallet there. All website signups are
   ordinary users; only CLI provisioning can create the initial admin.
2. Models appear automatically as their sandboxes become ready. Discovery runs on
   startup and every 30 seconds (a slow provider can extend a pass); the open Models
   page updates every five seconds. **Provider connections** in Admin explains
   missing keys, unfinished sign-ins and unavailable services. **Refresh now** is
   optional. Signing in later or pulling weights does not need a manual refresh.
3. Review **Models and prices**. Known paid models start at their provider's
   published list price and can be called at once. Add a **markup** (one
   percentage on every list price) or set your own price per model; your own
   prices survive later refreshes, and **[default]** puts a model back on its
   default price. Saving a price below your cost asks first. Models on your GPU
   start at the market rate for their size, and a gateway's free-tier models at
   the market price of the same model. A model is free only when you set both of
   its prices to 0. Prices are USDT per million tokens.
4. Attach your **Receiving wallet**. Buying credits stays disabled until you do.
5. Create an API key, optionally limited to one model. Copy it immediately; only
   its hash is kept. Delete it to revoke access.

Model IDs are the model's own name: `openai/MODEL_ID` for a provider's model,
and the plain model name for a model on your GPU or a gateway (`llama3.3:70b`,
`minimax/minimax-m2`). Buyers see each model's name, maker and price, never
where it runs. Use the exact ID from `/v1/models`. Legacy example rows are
labeled as examples, not promises of access. Provider listing alone does not
establish that every model supports this text chat subset or has available quota.

Default prices live in `site/prices.py`: each provider's published standard
price per million input and output tokens for its text chat models, checked on
24 October 2026 against the pricing pages linked below. Where a provider runs an
introductory rate, the default is the price after it ends, so a default never
sells below cost when the offer stops. Where the market (OpenRouter) charges
more than the provider, the default follows the market. Image, audio and
realtime models get no default and wait for your price; chat models nobody
prices publicly get a cautious estimate, marked for review. Dated snapshots of a
listed model (such as `gpt-4o-mini-2024-07-18`) use that model's price. Costs,
market prices and the markup are shown only to the admin.
Providers change prices: check their pages and adjust. Requests are capped at
64 KiB, below the long-context thresholds where some providers charge more;
cached-token discounts and other provider charges can differ from this site's
flat rates. A gateway's free tier is sold at its default price, but its zero pricing is still checked again before every call, with no paid fallback.
A provider can change prices after that check; provider-side spending controls
remain useful.

## Sell models you run yourself

```bash
yougori run hf.co/OWNER/MODEL --template my-api
yougori model run hf.co/OWNER/MODEL --neocloud --environment POD_ID --template my-api
```

The first runs the model on this computer's GPU, the second on a rented Neocloud pod.
Either way the CLI checks that the installed `my-api` takes models
(`yougori-models.yaml`) before anything starts, starts the model as usual, links the
website's sandbox to it with a private one-way connection, and runs
`site/attached.py` there with one request file holding the model's private address and
API key. The file is deleted as soon as it is read; the key stays in the website's
database and never reaches buyers. The model is listed under its repository name
(`Qwen/Qwen3-8B`) at the market price for that model, or the market rate for its size,
plus your markup; change it in **Models and prices** like any other.

The website checks each such model every 30 seconds and lists it only while its API
answers, so a stopped model disappears and comes back by itself. Starting the same model
again moves it to the newest environment. A model started by Yougori answers one request
at a time, up to 4,096 tokens; a busy model returns HTTP 429.

## Payments and accounting

Prices, balances and payments are all in USDT. The admin chooses the network:
Tron (TRC-20), Ethereum (ERC-20), BNB Smart Chain (BEP-20), Solana, Polygon or
Arbitrum One. Address checks validate format, not ownership or receipt. A wallet
saved earlier on a network that no longer takes payments (Base or Bitcoin) must
be chosen again before anyone can pay.

On the **API keys** page a user asks for 1–10,000 USDT of balance, sends exactly
that amount to the displayed wallet and keeps the reference. **There is no
on-chain watcher or wallet signing.** The admin independently verifies the
asset, network, transaction, amount and confirmations before marking it
received. A reference is not proof of payment. The API keys page checks waiting
payments every few seconds, so the balance goes up there by itself once the
admin confirms.
Confirmation adds credits exactly once, even with concurrent clicks. Payment
history retains the original wallet/network after wallet changes. No private
wallet keys are requested or stored.

Before inference, the website reserves a conservative maximum charge from message
byte length plus overhead and the output limit. Insufficient credit returns 402
before calling a provider. Success bills actual reported token usage and returns
unused credit. Prices are frozen for the request. Invalid usage or provider
failure refunds the reservation. Explicit quota exhaustion is shown on the key;
ordinary rate limits are not labeled exhausted credit. Success clears the note.

Interrupted reservations are refunded on startup. A provider request may still
have incurred costs; the operator absorbs uncertain outcomes. Run exactly one
website process per database: recovery assumes a single owner. Accounting uses
integer millionths of a USDT, rounded up per request.

## API

Both endpoints require a site API key:

```sh
curl https://YOUR-LINK/v1/models \
  -H "Authorization: Bearer YOUR_SITE_API_KEY"

curl https://YOUR-LINK/v1/chat/completions \
  -H "Authorization: Bearer YOUR_SITE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"EXACT_ID_FROM_MODELS","messages":[{"role":"user","content":"Hello"}],"max_tokens":256}'
```

Supported: text messages, `model`, `max_tokens` or `max_completion_tokens`, `stream`,
and `stream_options.include_usage`. Output is limited to 1–8192 tokens (default
1024), with at most 100 messages and a 64 KiB request body. Tool calls, images,
audio, embeddings, Responses API and other sampling parameters are not implemented;
unsupported parameters return errors. SSE output is buffered until the upstream
completion finishes, rather than streamed token by token.

## Persistence and operation

The `my-api-data` volume at `/data` holds SQLite accounts, sessions, hashed
passwords/API keys, wallet settings, prices, balances and usage. The
`my-api-models` volume at `/models` holds Ollama weights. Preserve both volumes;
back up SQLite with its backup mechanism or while stopped. Keep credentials in
Yougori's secret vault.

Public deployment requires secure cookies, a valid bridge secret and a provisioned admin. Sign in over
the HTTPS link, not a plain HTTP forwarded address. Auth attempts are limited by
direct peer address, so users behind a tunnel can share the limit. Each service
accepts at most 16 concurrent requests. This example has no email verification,
password recovery, automatic payment reconciliation or multi-process deployment.

If models are missing, check **Admin → Provider connections**, ensure the Hub
installer finished, pull Ollama weights or finish provider sign-in. Discovery retries automatically.
Signing in to a coding CLI alone does not enable its provider API. Invalid initial
admin credentials or a short bridge secret stop startup before HTTP requests are served.

## Offline verification

From the repository root:

```sh
python -B examples/hub/my-api/tests/test_service.py
python -B examples/hub/my-api/tests/test_prices.py
yougori template check examples/hub/my-api --format text
```

Tests use disposable SQLite databases and loopback HTTP servers. They exercise
successful website → bridge → provider requests, local inference, provider errors,
access controls and concurrent accounting, with no real accounts or payments.
Real engine creation, GPU inference, Cloudflare publication and authenticated
provider acceptance still need a deployment check on the intended host. Offline
success does not establish those outcomes.

## Fonts

The reference site's fonts are commercial, so the website ships close open-licensed
stand-ins in `site/fonts`, each with its licence file beside it:

| Role | Reference font | Font used here | Licence |
| --- | --- | --- | --- |
| Text and large statements | KH Teka | [Geist](https://vercel.com/font) | SIL OFL 1.1 |
| Uppercase labels, buttons, code | KH Interference | [Kode Mono](https://github.com/isaozler/kode-mono) | SIL OFL 1.1 |
| Pixel serif titles | FK Raster Roman Compact Smooth | [Tinos](https://github.com/googlefonts/tinos), rasterised in the browser | SIL OFL 1.1 |
| Numbers and the footer word | Geist Pixel Line | [Geist Pixel](https://vercel.com/font) Line and Square | SIL OFL 1.1 |

The files are unmodified copies from the official `geist` 1.8.2 package and the
Fontsource packages built from Google Fonts (Kode Mono latin, Tinos latin 400). The
website serves exactly these files under `/fonts/` and nothing else from that folder.

## Provider references

- [OpenAI Chat Completions](https://developers.openai.com/api/reference/resources/chat) and [pricing](https://developers.openai.com/api/docs/pricing)
- [Anthropic Messages](https://platform.claude.com/docs/en/api/messages/create) and [pricing](https://platform.claude.com/docs/en/about-claude/pricing)
- [Gemini compatibility](https://ai.google.dev/gemini-api/docs/openai/) and [pricing](https://ai.google.dev/gemini-api/docs/pricing)
- [Kilo Gateway models](https://kilo.ai/docs/gateway/models-and-providers)
- [OpenCode models and client restrictions](https://opencode.ai/v2/docs/console/models/)
- [Ollama compatibility](https://docs.ollama.com/api/openai-compatibility)

## Connection references

- [Kilo account and gateway authentication](https://kilo.ai/docs/getting-started/setup-authentication)
- [Kilo anonymous and paid API access](https://kilo.ai/docs/gateway/authentication)
- [OpenCode models and API protocols](https://opencode.ai/v2/docs/console/models/)

Subscription login connects a coding tool; it does not turn that subscription
into a resellable API. The first setup opens each selected subscription terminal
in sequence. Completion records that the terminal was opened, not that the
provider accepted the account. Reopen the tool to verify its account and plan.
The free/paid bridge restriction applies to the website API; a user controlling
an interactive coding tool can change its provider/model choices there.
