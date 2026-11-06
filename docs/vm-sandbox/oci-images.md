# OCI images in restricted VMs

Import an image exported as a local OCI layout (`oci-layout`, `index.json`, and
`blobs/sha256`). Choose it explicitly for your own catalog:

```powershell
yougori sandbox image import --layout C:/images/my-app --owner-selected true --root-gb 0.5 --yes
yougori sandbox image list
yougori sandbox launch --image sha256:MANIFEST_DIGEST --memory 1 --yes
```

Use the complete manifest ID returned by import. In the desktop, **VM sandboxes →
OCI workload image → Import an OCI image** offers the same operation.
The image's entrypoint and command run as literal arguments, without a shell.
Status shows the command's result. Images without a command wait for an explicit
`sandbox exec` (which requires a shell in the image).

The host verifies the OCI documents and compressed bytes. A disposable, reserved
VM inspects the archive. Its result and the layers enter the catalog under the
owner's scope. A consumer receives a read-only grant and repeats integrity checks
inside its VM. Each consumer materializes a separate, size-limited writable root.
Stopping it discards that root; a staged workspace retains the existing review
and promotion behavior. There is no host extraction or container hook execution.
The catalog leases and private writable state use the common overlay registry,
bound to the consumer's execution ID and boot generation. At most 128 image
overlays can be held at once. Image records from the initial development format
must be re-imported from the original layout to record the importer identity;
the manifest ID and template reference stay the same.

The current production importer supports Linux/amd64 OCI tar, gzip and zstd layers and Docker schema-2 gzip layers,
up to 256 MiB compressed in total, 2 GiB expanded, and 8,000 entries. Its inspection
reserves 2 GiB for the importer VM plus 1 GiB for the host's bounded transfer and
publication buffers, both on the common host ledger. Writable roots range from 64 MiB to 8 GiB; launch
must reserve at least that root plus 512 MiB for the VM. Consumer staging also
holds a temporary 1 GiB host-buffer reservation until its bounded copies finish.
Workloads run as uid/gid 1000;
privileged image users are refused. Image contents use case-sensitive UTF-8 Linux
names, including colons, Windows-reserved spellings, trailing dots/spaces and distinct
Unicode spellings. These names have a separate type and never become host paths;
host-file grants retain their portable-name restrictions. Image names still reject
controls, backslashes, traversal and absolute entry paths, with 255-byte components,
64 components and 1,024 bytes total. Whiteouts match exact case.

Each gzip layer has exactly one member; each zstd layer has exactly one frame with
at most a 128 MiB decoder window. External dictionaries, skippable/extra frames,
trailing data, checksum failures and expansion beyond the existing byte/ratio
limits are refused. Importer and consumer use the same streaming decoder. Schema-1
manifests, artifacts and foreign/non-distributable layers remain unsupported. Image symlinks
may use absolute targets or bounded contained chains: validation resolves them in
a virtual image root without opening host paths. Cycles, excessive traversal,
root escapes and archive entries written through symlinks are refused. Original
targets are preserved for the guest chroot; host-file imports retain their stricter
link policy. Publication
and connection budgets remain those of the restricted VM service.

Templates can name an already imported image in a `vm_sandbox` resource:

```yaml
image: sha256:FULL_64_CHARACTER_MANIFEST_DIGEST
memory_gb: 1
```

The template builder exposes this optional choice when VM sandbox is selected.
The setup review includes the digest. An empty image or `minimal` uses the minimal guest;
a missing or unreadable image is refused, without fetching or trusting it on
the template's behalf. Import remains a separate, explicit owner action on each
computer.

## Registry source

Use a complete digest-pinned reference instead of a layout:

```text
yougori sandbox image import --reference https://registry.example/team/app@sha256:FULL_DIGEST --owner-selected true --yes
```

Downloads use the [OCI Distribution pull protocol](https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md).
Tags are refused. The root and every selected-platform descriptor are checked for
size and SHA-256 before archive inspection; the same importer VM and catalog policy
apply. Records retain the registry origin, repository and pinned root digest.
This is source provenance and explicit owner selection, not a publisher signature.

The [Bearer challenge flow](https://distribution.github.io/distribution/spec/auth/token/)
requests only anonymous pull access. Its token service must be on the registry's
origin unless you explicitly choose `--auth-origin https://AUTH-HOST`. For Docker
Hub, the registry origin is `https://registry-1.docker.io` and the token-service
origin is `https://auth.docker.io`; use a compatible OCI or Docker schema-2 manifest/index digest.
A private registry's bearer token may be supplied as `secret` through protected
JSON input (`--file -`), or the desktop's password field, never as a CLI argument.
Tokens are not stored in the image record, passed to a guest, or sent to token
services. The desktop clears its token field after each attempt.

All requests require HTTPS. Redirects are bounded; leaving the registry origin
permanently removes its credential for that redirect chain. There are no ambient
proxies, cookies, login-store reads or referrers. The total transfer has a five-minute
deadline and stops when its importer VM stops. Network reads never hold the shared
catalog mutex, and every response is bounded while streaming. Failed transfers
publish no image. Provider outages and missing authentication return explicit errors.

The decoder is pinned to `github.com/klauspost/compress v1.18.4` (BSD-3-Clause).
Its [streaming decoder controls](https://pkg.go.dev/github.com/klauspost/compress@v1.18.4/zstd)
limit concurrency and memory; a framing reader prevents consuming a second frame.
Docker media types follow the [schema-2 image specification](https://distribution.github.io/distribution/spec/manifest-v2-2/).
