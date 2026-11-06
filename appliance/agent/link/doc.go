// Package link is the guest side of the Yougori guest link protocol, byte-compatible with
// the host side committed in Rust (src-tauri/src/sandbox/link/): bounded versioned frames,
// flat tag-length-value fields read in one linear pass, per-direction HMAC-SHA256 keys
// derived from the per-instance bootstrap secret, monotonic sequences per direction, the
// handshake, liveness, per-channel windows, revocation, shutdown and close
// (docs/combined-gpu-memory-and-vm-sandbox-plan.md §3.2 lines 2059–2077, §3.3, VM-W05 and
// VM-W06 lines 2590–2591, §16.1 "one shared conformance corpus", VM-CP-25; work items M01
// and M06, guest side).
//
//   - wire.go: the frame header, the five channels and the closed operation set with its
//     directionality table, the framing refusals.
//   - fields.go: payload fields, refused with the host's typed reasons.
//   - limits.go: the documented default limits, identical to the host's.
//   - secret.go: the bootstrap secret, the per-direction keys and the binding of a link to
//     one VM instance and boot generation; the secret is never printed or serialized.
//   - sequence.go: monotonic sequence state per direction.
//   - messages.go: the typed message of every operation and its payload codec.
//   - decoder.go: the incremental frame decoder holding at most one frame.
//   - endpoint.go: one end of a link. The same state machine runs as the guest (the agent)
//     or as the host (the conformance replay and the host-side test client), so the guest
//     refuses everything the host would refuse from it, mirrored.
//   - bootstrap.go: the bootstrap file v1 the host launcher writes into fw_cfg.
//
// Nothing here opens a device, spawns a process or reads a clock by itself: bytes and time
// come from the caller.
package link
