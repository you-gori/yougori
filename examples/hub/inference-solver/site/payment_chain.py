"""Read-only, mainnet stablecoin settlement. No wallet keys or broadcasts.

Token provenance and finality policy: ../docs/payments.md.
RPC URLs are operator environment settings, never browser-supplied URLs.
"""
import http.client
import ipaddress
import json
import os
import socket
import ssl
from urllib.parse import urlsplit

from chain import base58_decode, keccak256

ASSETS = {
    "ethereum": {"chain_id": 1, "token": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", "rpc": "https://ethereum-rpc.publicnode.com"},
    "base": {"chain_id": 8453, "token": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", "rpc": "https://base-rpc.publicnode.com"},
    "arbitrum": {"chain_id": 42161, "token": "0xaf88d065e77c8cc2239327c5edb3a432268e5831", "rpc": "https://arb1.arbitrum.io/rpc"},
    "polygon": {"chain_id": 137, "token": "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359", "rpc": "https://polygon-bor-rpc.publicnode.com"},
    "bsc": {"chain_id": 56, "token": "0x55d398326f99059ff775485246999027b3197955", "rpc": "https://bsc-rpc.publicnode.com", "symbol": "Binance-Peg USDT", "decimals": 18},
    "solana": {"token": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "rpc": "https://api.mainnet-beta.solana.com"},
    "tron": {"token": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", "rpc": "https://api.trongrid.io", "symbol": "USDT"},
}
for _asset in ASSETS.values():
    _asset.setdefault("symbol", "USDC")
    _asset.setdefault("decimals", 6)
TRANSFER = "0x" + keccak256(b"Transfer(address,address,uint256)").hex()
MEMO_PROGRAM = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"


class Pending(Exception):
    """Retryable RPC or finality state; public message only."""


class Rejected(Exception):
    """The submitted transaction cannot pay this invoice."""


def post(url, data, headers=None):
    """Pinned public IP, verified TLS, no proxies/redirects, bounded response."""
    conn = None
    try:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise ValueError()
        port = parsed.port or 443
        ips = [a[4][0] for a in socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)]
        ips = [ip for ip in ips if ipaddress.ip_address(ip).is_global]
        if not ips:
            raise ValueError()
        conn = http.client.HTTPSConnection(parsed.hostname, port, timeout=8)
        raw = socket.create_connection((ips[0], port), timeout=8)
        try:
            conn.sock = ssl.create_default_context().wrap_socket(raw, server_hostname=parsed.hostname)
        except BaseException:
            raw.close()
            raise
        conn.request("POST", (parsed.path or "/") + ("?" + parsed.query if parsed.query else ""),
                     json.dumps(data).encode(), {"Content-Type": "application/json", "Connection": "close", **(headers or {})})
        response = conn.getresponse()
        body = response.read(2 * 1024 * 1024 + 1)
        if response.status != 200 or len(body) > 2 * 1024 * 1024:
            raise ValueError()
        return json.loads(body)
    except (OSError, ValueError, http.client.HTTPException):
        raise Pending("Payment network temporarily unavailable; verification will retry.") from None
    finally:
        if conn:
            conn.close()


def rpc(network, method, params):
    base = os.getenv("SOLVER_PAYMENT_RPC_" + network.upper(), ASSETS[network]["rpc"])
    if network == "tron":
        headers = {}
        if os.getenv("SOLVER_TRONGRID_KEY"):
            headers["TRON-PRO-API-KEY"] = os.environ["SOLVER_TRONGRID_KEY"]
        return post(base.rstrip("/") + "/walletsolidity/" + method, params, headers)
    result = post(base, {"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    if not isinstance(result, dict) or "error" in result or "result" not in result:
        raise Pending("The payment RPC could not verify finality; retrying.")
    return result["result"]


def calldata(invoice):
    recipient = invoice["recipient"][2:] if invoice["network"] != "tron" else base58_decode(invoice["recipient"])[1:21].hex()
    return "0xa9059cbb" + recipient.lower().zfill(64) + format(int(invoice["units"]), "064x")


def payment_data(invoice):
    asset = ASSETS[invoice["network"]]
    return {"token": invoice["token"], "symbol": asset["symbol"], "decimals": asset["decimals"],
            "chain_id": asset.get("chain_id"), "memo": "solver:" + invoice["id"],
            "data": calldata(invoice) + invoice["id"] if asset.get("chain_id") else None}


def _check(ok, message="The transaction does not match this invoice's token, recipient, amount and reference."):
    if not ok:
        raise Rejected(message)


def _evm(invoice, call):
    asset, txid = ASSETS[invoice["network"]], invoice["txid"]
    if int(call("eth_chainId", []), 16) != asset["chain_id"]:
        raise Pending("Payment RPC is connected to the wrong chain; administrator attention needed.")
    tx = call("eth_getTransactionByHash", [txid])
    receipt = call("eth_getTransactionReceipt", [txid])
    if not tx or not receipt:
        raise Pending("Waiting for the transaction to be included and finalized.")
    _check(tx["hash"].lower() == txid and receipt["transactionHash"].lower() == txid)
    _check(tx["to"].lower() == invoice["token"].lower() and int(tx.get("value", "0x0"), 16) == 0)
    _check(tx["input"].lower() == calldata(invoice) + invoice["id"])
    _check(int(receipt["status"], 16) == 1, "The transaction failed on-chain. No credits were added.")
    number = int(receipt["blockNumber"], 16)
    final = call("eth_getBlockByNumber", ["finalized", False])
    if not final or int(final["number"], 16) < number:
        raise Pending("Transfer included; waiting for chain finality.")
    block = call("eth_getBlockByNumber", [receipt["blockNumber"], False])
    if not block or block["hash"].lower() != receipt["blockHash"].lower() or tx["blockHash"].lower() != block["hash"].lower():
        raise Pending("The chain reorganized this transfer; checking its canonical block again.")
    _check(int(block["timestamp"], 16) >= invoice["created"] - 120)
    recipient = "0x" + invoice["recipient"][2:].lower().zfill(64)
    transfers = [log for log in receipt["logs"] if not log.get("removed") and log["address"].lower() == invoice["token"].lower()
                 and len(log.get("topics", [])) == 3 and log["topics"][0].lower() == TRANSFER and log["topics"][2].lower() == recipient]
    _check(len(transfers) == 1 and int(transfers[0]["data"], 16) == int(invoice["units"]))
    return {"block": number, "block_hash": block["hash"]}


def _solana(invoice, call):
    if call("getGenesisHash", []) != "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d":
        raise Pending("Payment RPC is not Solana mainnet.")
    result = call("getTransaction", [invoice["txid"], {"encoding": "jsonParsed", "commitment": "finalized", "maxSupportedTransactionVersion": 0}])
    if not result:
        raise Pending("Waiting for a finalized Solana transaction.")
    _check(result["meta"]["err"] is None, "The transaction failed on-chain. No credits were added.")
    _check(result["transaction"]["signatures"][0] == invoice["txid"] and (result.get("blockTime") or 0) >= invoice["created"] - 120)
    instructions = result["transaction"]["message"]["instructions"]
    memos = [i.get("parsed") for i in instructions if i.get("programId") == MEMO_PROGRAM]
    _check(memos == ["solver:" + invoice["id"]])
    before = {b["accountIndex"]: b for b in result["meta"].get("preTokenBalances", [])}
    after = [b for b in result["meta"].get("postTokenBalances", []) if b.get("mint") == invoice["token"] and b.get("owner") == invoice["recipient"]]
    _check(bool(after))
    delta = 0
    for balance in after:
        previous = before.get(balance["accountIndex"])
        _check(not previous or (previous.get("mint") == invoice["token"] and previous.get("owner") == invoice["recipient"]))
        _check(balance["uiTokenAmount"]["decimals"] == 6)
        delta += int(balance["uiTokenAmount"]["amount"]) - (int(previous["uiTokenAmount"]["amount"]) if previous else 0)
    _check(delta == int(invoice["units"]))
    return {"slot": result["slot"]}


def _tron(invoice, call):
    # SolidityNode only returns solidified blocks/receipts. Pin mainnet genesis.
    genesis = call("getblockbynum", {"num": 0})
    if genesis.get("blockID") != "00000000000000001ebf88508a03865c71d452e25f4d51194196a1d22b6653dc":
        raise Pending("Payment RPC mainnet identity has not been verified.")
    tx = call("gettransactionbyid", {"value": invoice["txid"]})
    receipt = call("gettransactioninfobyid", {"value": invoice["txid"]})
    if not receipt or not tx:
        raise Pending("Waiting for the Tron transaction to be solidified.")
    _check(tx["txID"] == invoice["txid"] and receipt["id"] == invoice["txid"])
    _check(receipt.get("receipt", {}).get("result") == "SUCCESS", "The transaction failed on-chain. No credits were added.")
    _check(bytes.fromhex(tx["raw_data"].get("data", "")).decode() == "solver:" + invoice["id"])
    _check(receipt["blockTimeStamp"] // 1000 >= invoice["created"] - 120)
    contracts = tx["raw_data"]["contract"]
    _check(len(contracts) == 1 and contracts[0]["type"] == "TriggerSmartContract")
    value = contracts[0]["parameter"]["value"]
    token = base58_decode(invoice["token"])[1:21].hex()
    _check(value["contract_address"].lower() == "41" + token and value["data"].lower() == calldata(invoice)[2:])
    recipient = base58_decode(invoice["recipient"])[1:21].hex().zfill(64)
    logs = [l for l in receipt.get("log", []) if l["address"].lower() == token and len(l.get("topics", [])) == 3
            and l["topics"][0].lower() == TRANSFER[2:] and l["topics"][2].lower() == recipient]
    _check(len(logs) == 1 and int(logs[0]["data"], 16) == int(invoice["units"]))
    return {"block": receipt["blockNumber"]}


def verify(invoice, call=None):
    call = call or (lambda method, params: rpc(invoice["network"], method, params))
    try:
        if invoice["network"] == "solana":
            return _solana(invoice, call)
        if invoice["network"] == "tron":
            return _tron(invoice, call)
        return _evm(invoice, call)
    except (KeyError, TypeError, ValueError, IndexError, AttributeError):
        raise Pending("Payment RPC returned incomplete evidence; verification will retry.") from None
