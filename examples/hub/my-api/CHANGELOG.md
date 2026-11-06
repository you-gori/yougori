# Changelog

## 2.1.0

- Exactly two sandboxes: `web` for the website and `models` for all selected providers.
- Provider bridges use separate private ports, with independent service restarts.
- Ollama shares the models sandbox and retains its persistent weights volume.
- Tool selections, sign-in methods, free-only checks and website appearance are unchanged.

## 2.0.0

Format 2; needs Yougori 1.2.0. Instances from 1.6.0 keep running on 1.6.0 and are not
updated in place (see Updating from 1.6.0 in the README).

- Provider sandboxes are optional parts: `paid`, `local` and `free` are created only
  when one of their providers is chosen, each with its own one-way connection from the
  website. Unselected providers' sandboxes are never asked for models.
- Every question belongs to a group; the sign-in source questions have no preset
  answer. The two "which account" questions for OpenCode and Kilo are gone; the tool's
  `/connect` screen makes that choice.
- Wallet addresses are checked for their network's checksum (Tron Base58Check,
  EIP-55, Solana's 32 bytes). An optional USDT token contract or mint per network,
  entered by the admin from Tether's official list, is shown to buyers next to the
  address.
- Payments: the buyer is told plainly that the owner confirms by hand. A buyer can
  have five requests waiting and can cancel one. The admin can reject a request, and
  confirming takes the transaction id, so one transfer pays for one request. Each
  confirmation records the admin who made it.
- The database has a layout version. It is copied to `/data/backups` and checked
  before it is upgraded; if the copy can't be made, the website stops and changes
  nothing.
- Free-only gateway models are refused, with the reason, when the catalogue is more
  than three minutes old. A model that stopped being free or listed is taken off sale
  and the buyer is told why. Each model records when it was last found and priced.
- A failed provider sign-in takes that provider's models off sale at once; a
  rate-limited provider keeps its models listed.
- Admin: the Admin link stays in the top bar on small screens; every provider problem
  shows its exact fix with a command to copy; a signed-out Codex is shown; the coding
  tools' own models are listed under Connected coding tools; models left out because
  another source already uses their name are named.
- Tests no longer read provider settings from the shell that runs them.
- Not yet in 2.0.0: selling a model you start with `yougori run --template`. Setups
  don't deliver a connection to another setup's model yet; instances from 1.6.0 still
  take models this way.

## 1.6.0

Sell models you start with `yougori run --template`; prices in USDT; Claude Code is no
longer installed. Published on the Hub; unchanged by 2.0.0.
