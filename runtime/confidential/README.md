# Confidential inference prototype

This implementation provides native age/X25519 encryption, Intel Trust Authority
composite TDX/NVIDIA token validation, an encrypted-only reference runner, and
signed response/usage receipts. It has not been accepted on real confidential GPU
hardware. The shipped policy has **no trusted keys or images**, and refuses every
request before network access. Do not replace it with the synthetic test fixtures.

The CLI reads a chat JSON object from stdin and an API key from the
`YOUGORI_NETWORK_API_KEY` environment variable:

```
yougori confidential --model OWNER/MODEL --provider nd_PROVIDER --policy LOCAL_POLICY.json
```

An optional `--endpoint https://yougori.com/v1` changes the ciphertext relay.
The App's Network dialog uses the same native client. It does not save the prompt,
reply or API key in conversation history or browser storage. No plaintext fallback
exists. Ordinary `model run --now` does not become confidential through this feature.

A locally provisioned policy pins independent verifier RSA keys/issuer, an expiry,
revoked key IDs, exact MRTD/RTMR image measurements, the model repository and immutable
revision, and an independent composite appraisal policy. Website/provider responses
cannot change these pins. JWT key-discovery headers are never used. The pinned
key must remain published at the independently fixed Intel portal `/certs` endpoint;
an operator-provided key cannot replace a vendor key. Fresh challenges bind the
exact runner age recipient and Ed25519 signing key to the verified CPU
runtime data. All GPU claims must pass. Debug, perfmon, migration, stale TCB, bad
revocation status, different images/keys and mismatched nonces are rejected.

The runner generates both keys in memory. It sends only public descriptor data to
the attestation collector, connects only to the fixed loopback model API, disables
environment proxies/redirects, bounds payloads, rejects repeat IDs and encrypts
responses. Receipts bind the request ciphertext, response ciphertext, provider,
request ID and token counts. The native client verifies the receipt before decrypting.
Traffic timing, model selection, token counts and approximate lengths remain metadata.

The runner must be built into an independently reviewed, immutable confidential VM
image with protected CPU/GPU execution. Its collector must bind the exact descriptor
to verified CPU evidence and all locally attached GPUs in CC-On mode. Signing a JSON
document with an operator key, checking a GPU name or running this binary inside an
ordinary container does not provide host privacy. Readiness proves only that its
internal model verified its checkpoint, never hardware attestation.

Runner configuration uses `YOUGORI_MODEL`, `YOUGORI_MODEL_REVISION`,
`YOUGORI_MODEL_TOKEN`, `YOUGORI_CONFIDENTIAL_NODE_ID`,
`YOUGORI_CONFIDENTIAL_RELAY_TOKEN`, and `YOUGORI_CONFIDENTIAL_ATTESTER`.
The collector receives one descriptor JSON on stdin and must return only the composite
vendor JWT on stdout. It must be part of the measured image, not downloaded at runtime.
`collect-attestation.py` adapts this contract to a locally pinned Intel CLI binary,
requiring both TDX and NVIDIA evidence, all policy matches and a verifier nonce.
Its `YOUGORI_ATTESTATION_MANIFEST` names that binary/SHA256, protected vendor config
and approved composite policy IDs. No vendor binary or credential is installed here.

The website relay is experimental, free-only and disabled in production even if its
development flag is set. It cannot validate or charge unverified receipts. Production
activation also needs independent hardware/image validation and verified billing.

Primary references: [Intel token claims](https://docs.trustauthority.intel.com/main/articles/articles/ita/concept-attestation-tokens.html),
[Intel composite evidence](https://docs.trustauthority.intel.com/main/articles/articles/ita/integrate-go-client.html),
[NVIDIA GPU claims](https://docs.nvidia.com/attestation/advanced-documentation/latest/claims-guide/gpu_claims.html),
and [age encryption](https://age-encryption.org/).
