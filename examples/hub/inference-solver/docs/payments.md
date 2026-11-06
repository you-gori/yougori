# Payments and dollar balances

Admin → Crypto payments sets receiving wallets. Users open **Usage → Balance**,
create an invoice and approve a transfer in their own wallet. Funds go directly to
the receiving wallet; this server never takes custody or stores signing keys.
One supported stablecoin unit adds $1 of service balance; network fees are additional.
This is a fixed service-credit denomination, not a live exchange rate or withdrawal balance.

| Network | Accepted token | Finality required |
| --- | --- | --- |
| Ethereum | Native USDC | Canonical block at or below `finalized` |
| Base | Native USDC | Canonical block at or below `finalized` |
| Arbitrum | Native USDC | Canonical block at or below `finalized` |
| Polygon | Native USDC | Canonical block at or below `finalized` |
| BNB Smart Chain | Binance-Peg USDT, 18 decimals | Canonical block at or below `finalized` |
| Solana | Native USDC | `getTransaction` at `finalized` commitment |
| Tron | TRC-20 USDT | Successful receipt from SolidityNode |

BNB's accepted asset is Binance's pegged token, not native Circle USDC or a
Tether-issued BNB token. The exact accepted contracts/mints are pinned in
`site/payment_chain.py` and displayed on each invoice. Other tokens and bridged
USDC representations are rejected.

## Checkout

- EVM wallets: the inline button switches to the invoice's chain and asks the
  wallet to approve a token transfer. The unsigned calldata contains the exact
  recipient, amount and a 256-bit random invoice reference. Standard ERC-20 ABI
  decoding permits the trailing reference; read-only simulations against all five
  configured mainnet contracts passed. The transfer hash is submitted automatically.
- Solana: the inline Solana Pay link includes the SPL USDC mint and invoice memo.
  Use a wallet that preserves that memo, then submit its transaction signature.
- Tron: send TRC-20 USDT with the displayed transaction memo, then submit the ID.
  A wallet without transaction-memo support cannot pay these invoices correctly.
- Do not send directly from an exchange or omit the reference. The invoice cannot
  be matched safely from amount/address alone. Users can re-submit a hash after a
  browser interruption; an already-settled invoice returns its existing result.

The worker retries submitted transactions automatically, including after a
website restart. It does not scan unrelated deposits or require admin approval.
Pending means that the transfer has not met the finality checks; finality can take
minutes, particularly on Ethereum and rollups. A rejected transaction can be
replaced by a corrected hash on the same invoice. Cancelling an unused invoice
does not prevent recovery of a later valid payment to it.

Invoices retain their original token, amount and receiving wallet even if the
admin changes wallet settings. Only the invoice owner can submit a hash. A signed
reference binds a transfer to its invoice. Chain/token/recipient/amount/reference,
execution success and finality must all match. Solana checks the actual net token
balance increase for the receiving owner; EVM and Tron check emitted transfer
events. Testnet identities are refused. Network errors never produce credits.

Verification happens outside the SQLite write transaction. Settlement then
rechecks the current submitted hash and atomically inserts a unique
`(network, transaction ID)` ledger entry together with the settled state. Concurrent
workers, repeated submissions, stale work and restarts cannot credit it twice.
Amounts are integers in millionths of a dollar; token amounts use each token's
actual decimals. Invoices accept $1–$1,000 and each user has at most ten
created/pending invoices. Payment endpoints are rate limited.

## Model pricing

Admin → Model pricing sets separate **USD per million input tokens**, **cached input
tokens** and **output tokens**, from zero to $1,000 with six decimal places. New models
default to free. Cached input is the part of a prompt the model server reused from its
cache, as it reports it; it can cost at most the input price, and without a price of its
own it costs the input price. In the form it follows the input price until it is changed.
Model details expose the prices before use. A model's price applies to every computer or
model server that serves it.

The shared gateway enforces the same balance check for Chat Completions and the
Responses, Anthropic and Gemini adapters. It atomically reserves a conservative
financial ceiling before contacting the model; concurrent requests cannot spend
the same balance. This ceiling uses serialized request size plus overhead, and the
requested output cap (1,024 tokens when omitted on a paid request). It is not a
measured token count. Insufficient balance for this temporary reservation returns
HTTP 402. Successful completion charges only the upstream's actual input/output
token counts, its reported cached input tokens at the cached rate, at the snapshotted
rates, rounding the combined cost once to the next
millionth of a dollar. The remaining reservation is released. Usage and balance
commit together. Missing, invalid or above-ceiling counts are marked unbilled and
refunded; the server never invents token usage. Failure, cancellation and truncated
streams also release the reservation. Price changes do not change an already-reserved
request. After a process crash, abandoned holds
cease reducing the available balance after ten minutes; an expired hold cannot
be charged later. A crash after delivery but before accounting can result in a
free request, never a second charge.

## RPC operations

Defaults use public mainnet RPC services; rate limits or outages leave payments
pending and retry. For a busy installation, set the server's authenticated HTTPS
provider URLs using `SOLVER_PAYMENT_RPC_ETHEREUM`, `_BASE`, `_ARBITRUM`, `_POLYGON`,
`_BSC`, `_SOLANA`, or `_TRON`. A Tron URL is the API root, without `/walletsolidity`.
`SOLVER_TRONGRID_KEY` is an optional server-side TronGrid API key. Keep those values
out of source control. They are never returned in snapshots. Browser users cannot
choose an RPC URL. Connections pin a public IP, verify TLS and refuse redirects.

This relies on the selected RPC provider's chain evidence and finality reports;
it is not a locally validated full node or a light-client proof. Configure providers
you trust. The server does not convert, withdraw or refund cryptocurrency.

## Verification and sources

Run `python -I -B -m unittest discover -s tests -p test_payments.py` and
`node tests/browser.mjs` from the template. These use disposable accounts and RPC
fixtures, never real payments. Optional read-only mainnet probes:
`python -I -B tests/payment_probe.py --output PATH/payment-probe.json`.
No paid end-to-end transfer has been made during implementation.

- [Circle mainnet USDC addresses](https://developers.circle.com/stablecoins/usdc-contract-addresses)
- [Tether supported protocols and Tron contract](https://tether.to/en/supported-protocols/)
- [BNB contract's verified source](https://bscscan.com/address/0x55d398326f99059ff775485246999027b3197955#code)
- [Ethereum JSON-RPC receipts and finalized blocks](https://ethereum.org/en/developers/docs/apis/json-rpc/)
- [Solana transaction RPC](https://solana.com/docs/rpc/http/gettransaction)
- [Tron SolidityNode transaction receipts](https://developers.tron.network/reference/gettransactioninfobyid-1)
