# My API

A model API website with accounts, model-scoped keys, default token prices from
the providers' list prices, prepaid credits and payments to the admin's wallet.
Python standard library only. The website's look follows The Design Society
(thedesignsociety.fr): lavender, acid lime and electric blue, pixel titles, small
browser windows and a soft CRT screen. Its fonts are open-licensed and served by the
website itself (see Fonts), so nothing loads from outside the sandbox.

Version 2.1.0 is a format 2 template and needs Yougori 1.2.0 or newer. Instances
installed from 1.6.0 keep running on 1.6.0; see [Updating from 1.6.0](#updating-from-160).

## Run this copy

From the repository root:

```sh
yougori template check examples/hub/my-api --format text
yougori template run ./examples/hub/my-api
```

Yougori plans the setup, shows the review (sandboxes, downloads, secrets, what becomes
public) and asks before it creates anything. This folder must be published separately
before a remote Hub reference can fetch it. Editing these files does not update an
installed setup.

The questions first create the website admin account: enter its email and a password
of 12 to 1024 characters. For an existing installation, choose **Keep my existing
admin**; no account or password is changed. Then check the tools you want: Codex,
Anthropic API, Gemini, OpenCode, Kilo Code and Ollama. Space toggles; Enter continues.

- Anthropic API: asks for an Anthropic API key, used only by the website API.
  This template does not install Claude Code or offer a Claude subscription sign-in.
- Codex and Gemini: choose **Subscription**, **API key** or **Both**.
  Only API/Both asks for a provider API key. Subscription/Both asks
  **Use credentials from this computer** or **Sign in with a new account**, with no
  answer chosen for you, before creating any sandboxes. After installation it applies
  that choice and opens a separate sign-in window without asking again.
  Copying is opt-in; a missing or expired sign-in can be replaced in that terminal.
  Setup stays in its original terminal and continues. Finish signing in and close
  each provider window when done. Opening a window does not mean the provider has
  verified your subscription.
- Kilo and OpenCode: choose **Free models only** or **Free and paid models**.
  Paid access then asks for account/subscription, gateway API key, or both. A gateway
  key is asked for only in API/Both mode. The tool's `/connect` screen performs the
  actual account and provider selection.
- Kilo free-only API access is anonymous where the provider permits it. The bridge
  verifies every price component is zero again before inference. Paid and
  unknown-price models are excluded. Paid Kilo API access requires a gateway API key.
- OpenCode free chat stays in the OpenCode client. Paid website API access uses an
  OpenCode Console key and the documented Chat Completions subset listed in
  `bridge.py`; Responses, Messages, Gemini and System One models are not exported.
  OpenCode Go and other subscriptions are configured inside the tool.

Then choose who can open the website: **Quick public link** (a temporary
trycloudflare.com address) or **Your own domain** (a domain saved on this computer
with `yougori domain add`).

Choose a private bridge secret of at least 16 characters, separate from your admin
password. Passwords, bridge secrets and API keys go to the credential vault and are
asked privately; never put them on command-line arguments. The website creates the
admin from those protected values before listening for requests, and keeps only the
password hash in SQLite. It removes the bootstrap values from its process
environment once read. Restarting or updating never overwrites an existing admin
password. There is no web endpoint for creating or promoting an admin.

Payment network and wallet selection happen only in the website after admin
sign-in. No network is preselected and buying credits stays disabled until the
admin saves a network and wallet. Existing wallet settings survive updates.

Scripted runs use `--input providers=codex,kilo` (or a JSON array in an inputs
file), the per-provider access and scope answers, `--input admin_email=EMAIL`, and
`admin_password` plus `bridge_key` as a JSON object on stdin with `--secrets -`. Use
`--input admin_account=existing` to keep an existing admin without new credentials.
Scripts leave terminal commands for sign-in; they never copy this computer's
accounts.

## What it creates

Exactly two sandboxes are created, whichever providers you select:

| Sandbox | Resources | What runs there |
| --- | --- | --- |
| `web` | 2 CPU, 2 GB RAM, up to 10 GB storage | Website and chat API on port 3000; accounts, prices, credits and wallet settings in `my-api-data`. |
| `models` | 4 CPU, 8 GB RAM, up to 60 GB storage; GPU optional | All selected provider bridges and coding tools, plus Ollama when selected. Model weights persist in `my-api-models` at `/models`. |

Only the website is published. One private connection goes from `web` to `models`:
paid providers on port 8080, free/paid gateways on 8081 and Ollama on 11434. The
models sandbox cannot initiate connections to the website. These provider services
share one sandbox and its resource allocation; they are not isolated from each other.
Provider credentials stay in `models`; the website knows only the bridge secret.
Bridges reach external providers over HTTPS. Each selected service restarts
independently if it stops, and stopping the sandbox stops all of its services.

Keep this computer running. A quick link is temporary and can change when the site
is published again. GPU use is optional; CPU inference is slower. No model weights
are downloaded automatically. Run `ollama pull MODEL` in the models terminal when
Ollama is selected. Its service waits for the tool installation without blocking the
provider bridges.

To add or remove providers later, run `yougori template configure INSTANCE`. This
changes the selected services and tools inside `models`; it does not add another
provider sandbox. Stored API keys are not asked again. Model discovery starts by
itself after setup. The published Hub version 1.6.0 still has its original layout;
use the local command above to try this two-sandbox version before publication.

Codex, Gemini, OpenCode and Kilo also have terminal shortcuts in the next steps.
Personal subscription logins are **not** converted into shared APIs. Subscription
access can restrict resale; use provider API keys with appropriate provider
permission for paying users. OpenCode's current free chat models require its client:
they are available in its terminal, not exported by this API.

Model discovery also reads the signed-in Codex model picker through its app-server
`account/read` and `model/list` methods. No conversation, tool run or inference is
started. These models appear in Admin under **Connected coding tools**; they do not
become shared API models or billable website keys. A signed-out tool shows in
**Provider connections** with how to sign in again, and discovery retries by itself
after its sign-in window completes. Model pickers describe the tool's offered models,
not a guarantee of remaining quota.

OpenCode's free catalogue comes from `opencode models opencode --verbose --refresh
--pure`. Every refresh checks input, output and all other reported cost components;
unknown or nonzero prices are excluded in free-only mode. Kilo uses its current
gateway catalogue, with the same fail-closed price rule and another check before
each API call. No fixed list of free model names is maintained. Each model records
when discovery last found it and when its price last changed.

Availability follows what the providers report:

- A provider whose sign-in or API key fails during a request has its models taken
  off sale at once, and **Provider connections** shows the fix. They come back when
  discovery finds them again.
- A provider that is only rate-limited keeps its models listed; buyers get the
  provider's rate-limit error until it answers again.
- A free-only gateway model is refused, with the reason, when the catalogue is more
  than three minutes old, before any provider call. A model the bridge finds is no
  longer free, or no longer listed, is taken off sale and the buyer is told why.
  Admin price overrides are preserved.

## Admin setup

1. Sign in with the email and password chosen during setup (or your existing admin
   credentials after an update). An admin with no wallet is taken to Admin. All
   website signups are ordinary users; only setup can create the first admin. The
   Admin link stays in the top bar on every screen size.
2. Models appear as their sandboxes become ready. Discovery runs on startup and every
   30 seconds (a slow provider can extend a pass); the open Models page updates every
   five seconds. **Provider connections** in Admin lists missing keys, unfinished
   sign-ins and unavailable services, each with the exact fix and a button to copy
   its command. **Refresh now** is optional.
3. Review **Models and prices**. Known paid models start at their provider's
   published list price and can be called at once. Paid models without a published
   price start at a cautious estimate, marked for review. Add a **markup** (one
   percentage on every list price) or set your own price per model; your own prices
   survive later refreshes, and **[default]** puts a model back on its default price.
   Saving a price below your cost asks first. Models on your GPU start at the market
   rate for their size, and a gateway's free-tier models at the market price of the
   same model. A model is free only when you set both of its prices to 0. Prices are
   USDT per million tokens.
4. Attach your **Receiving wallet**: the network, your address and, optionally, the
   USDT token contract or mint on that network. Copy the token from Tether's official
   list of supported networks, never from a message or another website. Buyers then
   see it next to your address with "Check that the token is Tether USD (USDT) on
   NETWORK before sending." Buying credits stays disabled until a wallet is saved.
5. Create an API key, optionally limited to one model. Copy it immediately; only its
   hash is kept. Delete it to revoke access.

Model IDs are the model's own name: `openai/MODEL_ID` for a provider's model, and the
plain model name for a model on your GPU or a gateway (`llama3.3:70b`,
`minimax/minimax-m2`). Buyers see each model's name, maker and price, never where it
runs. Use the exact ID from `/v1/models`. A provider listing a model does not prove
that it supports this text chat subset or has quota left.

Default prices live in `site/prices.py`: each provider's published standard price per
million input and output tokens for its text chat models, checked on 24 October 2026
against the pricing pages linked below. Where a provider runs an introductory rate,
the default is the price after it ends, so a default never sells below cost when the
offer stops. Where the market (OpenRouter) charges more than the provider, the
default follows the market. Image, audio and realtime models get no default and wait
for your price; chat models nobody prices publicly get a cautious estimate, marked
for review. Dated snapshots of a listed model (such as `gpt-4o-mini-2024-07-18`) use
that model's price. Costs, market prices and the markup are shown only to the admin.
Providers change prices: check their pages and adjust. Requests are capped at 64 KiB,
below the long-context thresholds where some providers charge more; cached-token
discounts and other provider charges can differ from this site's flat rates. A
gateway's free tier is sold at its default price, but its zero pricing is checked
again before every call, with no paid fallback. A provider can change prices after
that check; provider-side spending controls remain useful.

## Payments and accounting

Prices, balances and payments are all in USDT. The admin chooses the network:
Tron (TRC-20), Ethereum (ERC-20), BNB Smart Chain (BEP-20), Solana, Polygon or
Arbitrum One. Addresses are checked for their network's shape and checksum
(Base58Check for Tron, EIP-55 for a mixed-case EVM address, 32 bytes for Solana), so a
typo is caught before anyone pays to it. The checks cannot tell who owns an address.
A wallet saved earlier on a network that no longer takes payments (Base or Bitcoin)
must be chosen again before anyone can pay.

On the **API keys** page a buyer asks for 1–10,000 USDT of balance, sends exactly that
amount to the displayed wallet and keeps the reference. **There is no on-chain watcher
or wallet signing: the owner checks the wallet and confirms each payment by hand.**
The buyer is told so. A buyer can have at most five requests waiting, and can cancel
one they have not paid.

In Admin, **Payments waiting** lists each request. Before marking one received, check
the asset, network, transaction, amount and confirmations in your wallet. Paste the
transaction id when you confirm: the site then refuses to count the same transfer for
a second request, and names the request it already paid. **Reject** closes a request
with no matching payment. Confirmation adds credits exactly once, even with
concurrent clicks, and records which admin confirmed it. The buyer's API keys page
checks waiting payments every few seconds, so their balance goes up by itself.
Payment history keeps the original wallet and network after wallet changes. No
private wallet keys are requested or stored.

Before inference, the website reserves a conservative maximum charge from message byte
length plus overhead and the output limit. Insufficient credit returns 402 before
calling a provider. Success bills actual reported token usage and returns unused
credit. Prices are frozen for the request. Invalid usage or provider failure refunds
the reservation. Explicit quota exhaustion is shown on the key; ordinary rate limits
are not labelled exhausted credit. Success clears the note.

Interrupted reservations are refunded on startup. A provider request may still have
incurred costs; the operator absorbs uncertain outcomes. Run exactly one website
process per database: recovery assumes a single owner. Accounting uses integer
millionths of a USDT, rounded up per request.

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
passwords and API keys, wallet settings, prices, balances, payments and usage. The
`my-api-models` volume at `/models` holds Ollama weights. Keep both volumes; back up
SQLite with its backup mechanism or while stopped. Keep credentials in Yougori's
secret vault.

The database carries a layout version. When a newer website starts on an older
database, it first copies the database to
`/data/backups/my-api-vOLD-before-v2-TIME.db` and checks the copy. If the copy cannot
be written or fails its check, the website stops with a plain message and changes
nothing; free some space under `/data` and start it again.

Public deployment needs secure cookies, a bridge secret of at least 16 characters
(the website refuses to start without one) and an admin. Sign in over the HTTPS link,
not a plain HTTP forwarded address. Sign-in attempts are limited by direct peer
address, so users behind a tunnel can share the limit. Each service accepts at most
16 concurrent requests. This example has no email verification, password recovery,
automatic payment reconciliation or multi-process deployment.

If the admin credentials given at setup are missing or invalid, the website still
starts, its pages say the admin setup is not finished, and its log says to choose
**Create admin account** with `yougori template configure INSTANCE`.

If models are missing, check **Admin → Provider connections**: each problem shows its
fix. Pull Ollama weights or finish provider sign-in; discovery retries by itself.
Signing in to a coding CLI alone does not enable its provider API.

## Updating from 1.6.0

Instances installed from 1.6.0 keep running, pinned to 1.6.0; nothing updates them
behind your back, and 1.6.0 stays on the Hub unchanged. The engine cannot yet move a
1.6.0 instance to 2.0.0 in place: 1.6.0 instances are kept by the CLI, while 2.0.0
setups are run by the engine, and the engine has no step that takes over a 1.6.0
instance. To use 2.0.0 now, either keep the 1.6.0 instance as it is, or start a new
2.0.0 setup and leave the old one in place until you have moved your buyers over. The
questions are the same (each now belongs to a group), so your answers carry over. A
new setup starts with an empty `my-api-data` volume of its own; accounts, balances,
keys, prices, payments and the wallet stay in the 1.6.0 instance's `my-api-data`
volume. Do not delete that volume until you no longer need its records. When a 2.0.0
website first opens a database written by 1.6.0, it copies it to `/data/backups`
before upgrading it, as described above.

## Known limits

- **No in-place update from 1.6.0.** See Updating from 1.6.0.
- **Selling a model you run yourself** with `yougori run hf.co/OWNER/MODEL --template
  INSTANCE` works with instances installed from 1.6.0. A 2.0.0 setup cannot take a
  model this way yet: setups do not deliver a connection from the website to another
  setup's model, so this template asks no question about it. The website's support for
  such models (`site/attached.py`, `yougori-models.yaml`) is kept for when they do.
- **Health watching is planned.** The website's `/health` path is checked when it
  starts. Watching it afterwards (Health check) and the Health and logs view are
  listed as planned in setup and can't be turned on yet; `yougori template status
  INSTANCE` and `yougori template logs INSTANCE` show the setup's state and activity
  meanwhile.
- **Gemini subscription** connects the Gemini coding tool only. Its models are not
  read into **Connected coding tools**, and a subscription never becomes a website
  API; the website sells Gemini through an API key.
- **Duplicate model names**: when two sources offer a model under the same name, the
  source that listed it first keeps the name and the other is not listed. **Provider
  connections** in Admin names each model left out and which source kept it.
- **Gateway costs** follow the gateway's own catalogue. A gateway's prices can differ
  from the model maker's list price; review them in **Models and prices**.
- **Payments are checked by hand.** There is no watcher for the networks; a
  transaction id is checked for its shape, not looked up.
- **Platforms**: Windows x64 and Linux x64 builds. GPU inference needs a supported
  NVIDIA GPU; otherwise Ollama runs on the processor.

## Offline verification

From the repository root:

```sh
python -B examples/hub/my-api/tests/test_service.py
python -B examples/hub/my-api/tests/test_prices.py
python -B examples/hub/my-api/tests/test_tool_models.py
node examples/hub/my-api/tests/models-ui.cjs
node examples/hub/my-api/tests/theme-ui.cjs
yougori template check examples/hub/my-api --format text
```

The Python suites use disposable SQLite databases and loopback HTTP servers, and clear
any provider settings the shell exports, so nothing reaches a real provider. They
exercise website → bridge → provider requests, local and attached models, provider
errors, address and transaction checks against published test vectors, payments,
database upgrades, access controls and concurrent accounting, with no real accounts
or payments. The two `.cjs` checks drive the pages in a headless Chromium through
Playwright (the repository's `@playwright/test`), against fixture data on a fake
origin. Real engine creation, GPU inference, Cloudflare publication and
authenticated provider acceptance still need a check on the intended host; offline
success does not establish those. `TESTING.md` lists what maintainers check before
publishing a version.

## Files

| File | Purpose |
| --- | --- |
| `yougori-template.yaml` | Questions, capabilities, tools, steps and outputs |
| `yougori.yaml` | The website, the optional provider sandboxes, their connections and the publication |
| `yougori-models.yaml` | How an instance from 1.6.0 takes models started with `yougori run --template` |
| `site/` | The website, the bridges and their checks (Python standard library) |
| `tests/` | Offline suites and the two page checks |
| `answers/` | Example answers without secrets |
| `TESTING.md` | What maintainers check before publishing a version |
| `CHANGELOG.md` | Version history |
| `LICENSE` | MIT |

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
