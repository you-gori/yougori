#!/usr/bin/env python3
"""Compactness evidence for the combined GPU-memory and VM-sandbox plan.

Plan references: docs/combined-plan-remaining-only.md section 8, "U05 / G08 / E05 -
Compactness evidence" ("Record before/after production lines, duplicate policy/parsers,
active execution paths, maintained state machines/backends, polling loops, dependency
count, build/package size and change surface"); docs/combined-gpu-memory-and-vm-sandbox-
plan.md section 7 (per-package record of production lines, persistent state machines,
polling loops, duplicated parsers and native dependencies) and section 11.4 ("Track
compactness with duplicated policy logic, active execution paths, maintained backend
adapters, dependency count, build/package size and change surface. Raw line count alone
can reward unreadable or unsafe code."), and VM-D9 / INT-12 for the retirement inventory.

Usage (read-only; run from anywhere, Python 3.11 or newer for tomllib):

    python -I scripts/compactness/measure.py --repo . \
        [--base REV] [--head REV|WORKTREE] [--json OUT.json] [--markdown OUT.md] \
        [--no-artifacts] [--artifact-root DIR ...]

Without --json/--markdown the Markdown summary goes to stdout. Nothing is written into
the repository unless an output path inside it is given.

Read-only guarantees
--------------------
* Committed trees are read with `git ls-tree -r -l -z` and `git cat-file --batch`; no
  checkout, index write or ref update. Every git call runs with GIT_OPTIONAL_LOCKS=0, so
  even `git diff` against the working tree does not refresh (write) the index.
* The pseudo-revision WORKTREE reads tracked and untracked, non-ignored files
  (`git ls-files -z -c -o --exclude-standard`) from disk. Its numbers are NOT
  reproducible: other sessions change the working tree.
* Build/package sizes are `os.stat` of artifacts that already exist on disk. Nothing is
  built. That section is a disk snapshot, not bound to a revision; --no-artifacts drops
  it and then two runs over the same two commits give byte-identical JSON.
* No network access.

Default revisions
-----------------
--base defaults to 6d2358f80192576cd6b0a2333a9da4bcd3ea7153 ("Plan fast serving
techniques ...", 2026-10-27 18:06 +0100): the parent of 7e92f98, "Add the shared
vocabulary for the combined GPU memory and VM sandbox plan", which is the combined plan's
first implementation commit (Wave 0: src-tauri/src/foundation and model_memory roots).
Its code equals the 1.1.2 release-evidence commit da2b00c; 6d2358f only adds
docs/fast-serving-techniques-plan.md. --head defaults to HEAD.

Counting rules (every number in the report follows exactly these rules)
-----------------------------------------------------------------------
Files in scope. Every blob of the revision except: paths under vendor/, and paths with a
component node_modules or target; symlinks and submodules. A *source file* has one of
the extensions in SOURCE_LANGS (Rust, Go, TypeScript/JavaScript, Python, shell,
PowerShell, C/Objective-C, Swift, CSS, HTML). JSON, YAML, TOML, Markdown, text and
binaries are not counted as lines; they count only in tracked bytes. Content containing
a NUL byte in its first 8 KiB is binary and is skipped.

Lines. Physical lines from str.splitlines(). Each line is blank (only whitespace),
comment (starts, after leading whitespace, with the language's line-comment marker, or
lies in a block comment that started at the beginning of a line: `/* */` for C-like
languages and CSS, `<!-- -->` for HTML, `<# #>` for PowerShell) or code (everything
else). Python docstrings and comments after code count as code. "Code lines" are the
headline: non-blank, non-comment.

Areas. src-tauri/src/<module>, where <module> is the first path component below
src-tauri/src with the suffixes _tests.rs, _test.rs, .rs, _test.py, .py, .html removed
(so duplication_tests.rs belongs to duplication); "src-tauri (other)" for the rest of
src-tauri; cli; "src (UI)" for src/; grid; setup; vault; appliance/agent;
"appliance (other)"; runtime; engine; scripts; e2e; examples; other. The row
"src-tauri/src (all)" sums the src-tauri/src modules.

Test versus production. A source file is a test file when any of these holds:
  1. a directory component is tests, test, __tests__, testdata, fixtures, e2e or
     __mocks__;
  2. its name matches *.test.*, *.spec.*, *.fixture.*, *-fixture.*, *_test.go,
     *_test.py, test_*.py, conftest.py, tests.rs, *_tests.rs, *_test.rs, tests_*.rs or
     test_*.rs;
  3. (Rust) it is the file of a module declared out of line under #[cfg(test)]
     (`#[cfg(test)] [#[path = "p"]] mod name;` resolves to dir/name.rs or
     dir/name/mod.rs, or to p relative to the declaring file's directory), or it lies
     below that module's directory dir/name/.
In production Rust files, an item preceded by `#[cfg(test)]` or `#[cfg(all(test, ...))]`
(mod, fn, impl, struct, enum, trait, use, const, static, type, macro_rules!) is test
code from the attribute line to the line holding only `}` (optionally `};`) at the
attribute's indentation (rustfmt layout), or to the item's `;` for one-line items. The
compact form `#[cfg(test)] mod name {` on one line is handled the same way. An inline
test module without such a closing line extends to the end of the file.
`#[cfg(any(test, ...))]` items count as production. Files counted as production may
therefore hold test-only helpers (fakes, fixtures, goldens) that are compiled only for
tests through other means; rule 3 catches only the `#[cfg(test)] mod x;` form.

Duplicated policy and parsers (production code lines only):
  * macro_rules! definitions: the body runs from the `macro_rules! name {` line to the
    line holding only `}` at the same indentation. The body is normalised (line
    comments removed, whitespace collapsed, the macro's own name replaced by $M) and
    hashed (SHA-256, first 12 hex digits). A *strict serde enum macro* is a definition
    whose body contains `deny_unknown_fields`, `serde` and the word `enum`. Macro
    *families* are connected components of the graph whose edges join two definitions
    with difflib.SequenceMatcher(autojunk=False) token ratio >= 0.75, or with the same
    name in different files; *near-identical groups* inside a family use ratio >= 0.9.
    "Lines beyond one copy" of a family is the sum of its definitions' lines minus the
    longest definition: an upper bound on what one shared definition could remove, not a
    measured or achieved reduction.
  * Hazardous-text checks: production files with a code line holding at least two
    code-point literals of zero-width or bidirectional control characters
    (U+200B-U+200F, U+202A-U+202E, U+2066-U+2069, written \\u{...}, \\uXXXX, \\x{...},
    0x... or \\U0000...., or the raw character), i.e. a range or set of them. A lone
    literal (a byte-order mark strip, one isolate constant, a test string) does not
    count. Functions of a qualifying file whose names contain hazard, bidi, invisible,
    control_char or unprintable are listed. "Adopters" are production Rust files that
    reference foundation::text.
  * Strict JSON readers: production Rust files that (a) define `fn visit_map` and
    mention a duplicate key/field refusal (DuplicateKey, DuplicateField, "duplicate
    key", "appears twice", ...), or (b) define a generic reader function named
    *read_json*, *parse_json*, *load_json*, *decode_json*, *strict_json*,
    *json_strict* or from_json_* with type parameters, in a file that uses serde_json.
    Per-type `fn from_json(` methods are counted separately (entry points that may
    delegate). Go: files calling `.DisallowUnknownFields()`.
  * Digest helpers: production functions (the production code lines from a function
    definition line to the next definition, at most 80 lines on) whose text both computes
    SHA-256 (Rust Sha256::new/digest/default; Go sha256.New/Sum256; TS/JS
    createHash("sha256") or subtle.digest; Python hashlib.sha256) and hex-encodes
    (hex::encode, {:02x}, {:x}, to_hex(, hex.EncodeToString, %x, digest("hex"),
    toString(16), hexdigest(), .hex()). A *helper* has a name matching sha<digit>,
    a whole-word sha, digest, hash, checksum or fingerprint (case-insensitive) and at
    most 30 such code lines; every other match is an *inline site*.

Active execution paths and backends. EXECUTION_PATHS below names each path with its
implementation files (`defs`, a file or a directory prefix) and an `anchors` regular
expression of its entry points and persisted wire names. Per revision: implementation
files and production code lines; *caller files* = production source files outside the
defs with a production code line matching the anchors, and the matching line count;
*API callers* = production Rust files outside the defs but in the same crate (the
deepest directory with a Cargo.toml) calling (`name(` or `name::<`) a `pub`/
`pub(crate)`/`pub(super)` Rust function of the defs whose name has at least ten
characters, has at least two underscores (or one, when one of its words is in the path's
API_TOKENS entry, such as `appliance_endpoint` for the appliance), and is not also
defined as a function in a production file outside the defs (ambiguous names are
dropped); *product surface* = caller or API-caller files under src-tauri/src/commands*,
src-tauri/src/lib.rs, src-tauri/src/main.rs, src-tauri/src/automation/dispatch.rs (the
engine method table), cli/src/ or src/.
Test files that match the anchors are counted apart. Variants of the enums in
BACKEND_ENUMS are listed as declared (a variant is a line inside the enum body that
starts with an upper-case identifier).

Maintained state machines. A Rust enum whose name is State, Phase or Lifecycle or ends
with one of them (a line `[pub[(...)]] enum Name`, which also matches the strict macro
invocations), in production code. It counts "with transitions" when its file's
production code has (T1) a fn whose name contains transition, advance, next_state,
apply_event or step; (T2) an assignment `<name containing state|phase|lifecycle> =
Enum::Variant` or `= Self::Variant`; or (T3) a match arm on a tuple pattern that names
`Enum::Variant` or `Self::Variant` (`(A::X, ...) =>`). TypeScript `type XState =`
string unions and Go `type XState int|string|uint8|int32` are counted as declared only.

Polling loops. A sleep marker on a production code line (Rust `sleep(`, `sleep_until(`,
`.tick().await`; Go `time.Sleep(`, `<-x.C`, `<-time.After(`; TS/JS `await sleep|delay|
wait|pause(` or `setTimeout(resolve`; Python `time.sleep(`, `asyncio.sleep(`, `sleep(`;
shell `sleep N`; PowerShell Start-Sleep) inside a loop. The enclosing loop is found by
walking up to 400 lines back: each code line with less indentation than everything
seen so far is an enclosing header; the first header that is a loop (Rust loop/while/
for, Go for, TS/JS while/for/do, Python while/for, shell while/until/for, PowerShell
while/do/for/foreach) is the polling loop; a function header or column 0 ends the walk.
Each loop counts once however many markers it holds. TS/JS `setInterval(` calls count as
polling loops directly. Retry loops with back-off count too.

Dependencies. Per Cargo.lock: [[package]] entries, split into registry/git packages
(with `source`) and path packages; the union of external (name, version) pairs across
all lockfiles. Per Cargo.toml: direct dependency keys in [dependencies],
[dev-dependencies], [build-dependencies] and [target.*.*dependencies]. package.json:
dependencies and devDependencies; package-lock.json: entries under "packages" except the
root. go.mod: require entries, direct versus `// indirect`. vendor/ is excluded.

Build/package size. Revision-bound proxy: bytes of tracked blobs per area (from
`git ls-tree -l`; WORKTREE uses os.stat) including binaries and resources. Disk
snapshot: sizes of existing files directly inside <crate>/target/{release,debug} for
crate in src-tauri, cli, engine, grid, vault, setup and any --artifact-root (extensions
.exe, .dll, .so, .dylib, or none with an ELF, Mach-O or PE magic in the first bytes;
dot-files skipped), installers below src-tauri/target/release/bundle, and the total
size of dist/. Which revision built an artifact is unknown; the modification time is
reported.

Change surface. `git diff --numstat --no-renames -z BASE HEAD` (BASE against the working
tree for WORKTREE, plus untracked non-ignored files counted as wholly added). Per area:
files changed, lines added and deleted, split into test and production by the path
rules 1-3 above (whole files; inline test regions are not separated). Binary files count
as changed files with no lines. Renames appear as a deletion plus an addition.
"""

from __future__ import annotations

import argparse
import datetime
import difflib
import hashlib
import json
import os
import posixpath
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

RULES_VERSION = 1
DEFAULT_BASE = "6d2358f80192576cd6b0a2333a9da4bcd3ea7153"
WORKTREE = "WORKTREE"

SOURCE_LANGS = {
    ".rs": "rust",
    ".go": "go",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".py": "python",
    ".sh": "shell",
    ".ps1": "powershell",
    ".psm1": "powershell",
    ".c": "c",
    ".h": "c",
    ".cc": "c",
    ".cpp": "c",
    ".m": "c",
    ".mm": "c",
    ".swift": "swift",
    ".css": "css",
    ".html": "html",
}
C_LIKE = {"rust", "go", "typescript", "javascript", "c", "swift", "css"}
SCRIPT_LIKE = {"typescript", "javascript"}

EXCLUDED_PREFIXES = ("vendor/",)
EXCLUDED_COMPONENTS = {"node_modules", "target"}
TEST_DIRS = {"tests", "test", "__tests__", "testdata", "fixtures", "e2e", "__mocks__"}
TEST_NAME = re.compile(
    r"(?:\.test\.|\.spec\.|\.fixture\.|-fixture\.|_test\.go$|_test\.py$|^test_.*\.py$"
    r"|^conftest\.py$|^tests\.rs$|_tests\.rs$|_test\.rs$|^tests_.*\.rs$|^test_.*\.rs$)"
)
MANIFEST_NAMES = {"Cargo.toml", "Cargo.lock", "package.json", "package-lock.json", "go.mod"}

TOP_AREAS = [
    ("src-tauri/", "src-tauri (other)"),
    ("cli/", "cli"),
    ("src/", "src (UI)"),
    ("grid/", "grid"),
    ("setup/", "setup"),
    ("vault/", "vault"),
    ("appliance/agent/", "appliance/agent"),
    ("appliance/", "appliance (other)"),
    ("runtime/", "runtime"),
    ("engine/", "engine"),
    ("scripts/", "scripts"),
    ("e2e/", "e2e"),
    ("examples/", "examples"),
]
SRC_TAURI = "src-tauri/src/"
MODULE_SUFFIXES = ("_tests.rs", "_test.rs", ".rs", "_test.py", ".py", ".html")
PRODUCT_SURFACES = ("src-tauri/src/commands", "src-tauri/src/lib.rs", "src-tauri/src/main.rs",
                    "src-tauri/src/automation/dispatch.rs", "cli/src/", "src/")

# --- execution paths -------------------------------------------------------------------

EXECUTION_PATHS = [
    # VM-D9: retire all four (docs/combined-gpu-memory-and-vm-sandbox-plan.md, VM-D9 row).
    dict(id="isolation_container", group="VM-D9 retire",
         label="`--isolation container` (CLI tool sandbox as a container in the shared appliance)",
         defs=[], anchors=r"Isolation::Container\b|--isolation container|isolation container"),
    dict(id="shared_appliance", group="VM-D9 retire",
         label="Shared appliance (yougoriOci containers in one Linux VM)",
         defs=["src-tauri/src/runtime/appliance.rs", "src-tauri/src/runtime/appliance_capacity.rs"],
         anchors=r"\bYougoriOci\b|\byougoriOci\b|\bappliance::"),
    dict(id="computer_branch", group="VM-D9 retire",
         label="Computer Branch",
         defs=["src-tauri/src/runtime/branch.rs"],
         anchors=r"\bComputerBranch\b|\bcomputerBranch\b|computer_branch|Computer Branch"),
    dict(id="native_sandbox", group="VM-D9 retire",
         label="Host-process native sandbox (AppContainer)",
         defs=["src-tauri/src/runtime/native_sandbox.rs"],
         anchors=r"\bNativeSandbox\b|\bnativeSandbox\b|native_sandbox"),
    # VM-W56 lists these two with the appliance files (retired after parity).
    dict(id="legacy_relay_network", group="VM-W56 retire after parity",
         label="Legacy host relay and microVM network tables",
         defs=["src-tauri/src/runtime/host_relay.rs", "src-tauri/src/runtime/microvm_network.rs"],
         anchors=r"\bhost_relay::|\bmicrovm_network::"),
    dict(id="legacy_vm", group="current product path",
         label="Current microVM / full VM path (runtime/vm.rs on QEMU)",
         defs=["src-tauri/src/runtime/vm.rs", "src-tauri/src/runtime/vm_memory.rs",
               "src-tauri/src/runtime/vm_security.rs", "src-tauri/src/runtime/boot_media.rs",
               "src-tauri/src/runtime/qmp_socket.rs", "src-tauri/src/runtime/guest_job.rs"],
         anchors=r"RuntimeProviderKind::Qemu\b|EnvironmentKind::(?:MicroVm|FullVm)\b|\bmicroVm\b|\bfullVm\b"),
    dict(id="guest_agent", group="guest side (VM-W06 relinks)",
         label="Guest agent in Go (appliance and microVMs)",
         defs=["appliance/agent/"], anchors=r"\byougori-agent\b|appliance/agent"),
    # Labelled runtimes kept by VM-D4..VM-D6; not VM sandboxes and not retired by VM-D9.
    dict(id="wsl_cuda", group="labelled runtime kept (VM-D4)",
         label="WSL2 CUDA runtime (yougoriCuda)",
         defs=["src-tauri/src/runtime/cuda.rs", "runtime/cuda/"],
         anchors=r"\bYougoriCuda\b|\byougoriCuda\b|SharedKernelGpuRuntime"),
    dict(id="runpod", group="labelled runtime kept (VM-D5)",
         label="RunPod provider container (NeoCloud)",
         defs=["src-tauri/src/neocloud.rs", "src-tauri/src/neocloud/", "src-tauri/src/model_runner/neocloud.rs"],
         anchors=r"ProviderContainerRuntime|(?i:\brunpod)"),
    dict(id="metal_native", group="labelled runtime kept (VM-D6)",
         label="Native macOS Metal model runner",
         defs=["src-tauri/src/runtime/native_model.rs", "src-tauri/src/model_runner/macos.rs"],
         anchors=r"HostProcessModelRuntime|\bnative_model::|\bNativeModel\w*"),
    dict(id="cloud_ssh", group="other product path",
         label="Cloud SSH environments",
         defs=["src-tauri/src/runtime/cloud/"], anchors=r"\bCloudSsh\b|\bcloudSsh\b"),
    # VM sandbox backends behind the backend contract (sandbox/backend/contract.rs).
    dict(id="vm_fake", group="VM sandbox backend",
         label="Fake backend (certifies nothing)",
         defs=["src-tauri/src/sandbox/backend/fake.rs"], anchors=r"BackendKind::Fake\b"),
    dict(id="vm_firecracker", group="VM sandbox backend",
         label="Firecracker and jailer",
         defs=["src-tauri/src/sandbox/firecracker/"], anchors=r"BackendKind::Firecracker\b|\bfirecracker::"),
    dict(id="vm_qemu", group="VM sandbox backend",
         label="QEMU (hardened profile)",
         defs=["src-tauri/src/sandbox/qemu/"], anchors=r"BackendKind::Qemu\b|\bsandbox::qemu\b|\bqemu::"),
    dict(id="vm_cloud_hypervisor", group="VM sandbox backend",
         label="Cloud Hypervisor", defs=[], anchors=r"BackendKind::CloudHypervisor\b"),
    dict(id="vm_hcs", group="VM sandbox backend",
         label="Windows HCS", defs=[], anchors=r"BackendKind::Hcs\b"),
    dict(id="vm_vz", group="VM sandbox backend",
         label="macOS Virtualization.framework", defs=[], anchors=r"BackendKind::VirtualizationFramework\b"),
    dict(id="vm_remote", group="VM sandbox backend",
         label="Remote VM over SSH (VM-D5 offerings)",
         defs=["src-tauri/src/sandbox_contract/remote/", "src-tauri/src/sandbox_contract/remote_ssh/"],
         anchors=r"\bremote_ssh::|\bsandbox_contract::remote\b"),
    # Model inference runtimes.
    dict(id="model_server", group="model runtime",
         label="model_server.py and engine_backends.py (engine selection by FORMAT)",
         defs=["src-tauri/src/model_server.py", "src-tauri/src/model_runner/engine_backends.py"],
         anchors=r"model_server\.py|engine_backends\.py"),
    dict(id="engine_vllm", group="model runtime", label="vLLM",
         defs=["src-tauri/src/model_runner/vllm.rs"], anchors=r"Backend::Vllm\b|(?i:\bvllm\b)"),
    dict(id="engine_llama_cpp", group="model runtime", label="llama.cpp / GGUF",
         defs=[], anchors=r"Backend::LlamaCpp\b|(?i:llama[._-]?cpp)|(?i:\bgguf\b)"),
    dict(id="engine_transformers", group="model runtime", label="Transformers",
         defs=[], anchors=r"Backend::Transformers\b|(?i:\btransformers\b)"),
    dict(id="engine_sglang", group="model runtime", label="SGLang (declared only)",
         defs=[], anchors=r"Engine::Sglang\b|(?i:\bsglang\b)"),
]
# Domain words that let a two-word public function name count as that path's API.
API_TOKENS = {
    "shared_appliance": ("appliance", "container"),
    "computer_branch": ("branch",),
    "native_sandbox": ("native", "sandbox"),
    "legacy_relay_network": ("relay", "qemu", "folder", "service"),
    "legacy_vm": ("vm", "qemu", "microvm", "guest"),
    "wsl_cuda": ("cuda",),
    "runpod": ("runpod", "neocloud", "pod"),
    "metal_native": ("native", "metal"),
    "cloud_ssh": ("cloud", "ssh"),
    "vm_firecracker": ("firecracker", "jailer"),
    "vm_qemu": ("qemu",),
    "vm_remote": ("remote", "ssh"),
    "engine_vllm": ("vllm",),
}
BACKEND_ENUMS = ["EnvironmentKind", "RuntimeProviderKind", "ExecutionCategory", "BackendKind", "Backend", "Engine"]

# --- detector patterns -----------------------------------------------------------------

CFG_TEST = re.compile(r"^(\s*)#\[cfg\(\s*(?:test|all\(\s*test\s*,[^\]]*)\s*\)\]\s*$")
CFG_TEST_SAME_LINE = re.compile(r"^(\s*)#\[cfg\(\s*test\s*\)\]\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*(\{|;)")
ATTR = re.compile(r"^\s*#\[")
PATH_ATTR = re.compile(r'^\s*#\[path\s*=\s*"([^"]+)"\s*\]')
TEST_ITEM = re.compile(
    r"^(\s*)(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?"
    r"(mod|fn|impl|struct|enum|trait|use|const|static|type|macro_rules!)\b\s*(\w*)"
)
MACRO_DEF = re.compile(r"^(\s*)macro_rules!\s*([A-Za-z_]\w*)\s*\{")
STRICT_INVOCATION = re.compile(r"\bstrict_\w*enum!\s*\{")

HAZARD_CODEPOINT = re.compile(
    r"(?i)(?:\\u\{0*(?:200[b-f]|202[a-e]|206[6-9])\}|\\u(?:200[b-f]|202[a-e]|206[6-9])\b"
    r"|\\x\{0*(?:200[b-f]|202[a-e]|206[6-9])\}|\b0x0*(?:200[b-f]|202[a-e]|206[6-9])\b"
    r"|\\U0000(?:200[b-f]|202[a-e]|206[6-9]))"
    "|[\u200b-\u200f\u202a-\u202e\u2066-\u2069]"
)
HAZARD_FN = re.compile(r"\b(?:fn|func|function|def)\s+(\w*(?:hazard|bidi|invisible|control_char|unprintable)\w*)", re.I)
TEXT_ADOPTER = re.compile(r"\bfoundation::text\b|\bfoundation::\{[^}]*\btext\b")

VISIT_MAP = re.compile(r"\bfn\s+visit_map\b")
DUP_REFUSAL = re.compile(r"(?i)duplicate[ _-]?(?:key|field)|appears (?:twice|more than once)|DuplicateKey|DuplicateField")
JSON_USE = re.compile(r"\bserde_json::")
GENERIC_JSON_FN = re.compile(
    r"\bfn\s+(\w*(?:read|parse|load|decode)_json\w*|\w*strict_json\w*|\w*json_strict\w*|from_json_\w+)\s*<"
)
FROM_JSON_METHOD = re.compile(r"\bfn\s+from_json\s*\(")
GO_STRICT_JSON = re.compile(r"\.DisallowUnknownFields\(\)")

SHA_CALL = {
    "rust": re.compile(r"Sha256::(?:new|digest|default)\b"),
    "go": re.compile(r"\bsha256\.(?:New|Sum256)\("),
    "script": re.compile(r"createHash\(\s*['\"]sha256|subtle\.digest\("),
    "python": re.compile(r"\bhashlib\.sha256\b|hashlib\.new\(\s*['\"]sha256"),
}
HEX_ENCODE = {
    "rust": re.compile(r"\bhex::encode\b|:02x\}|\{:x\}|:064x\}|\bto_hex\(|encode_hex"),
    "go": re.compile(r"\bhex\.EncodeToString\(|%x|%064x"),
    "script": re.compile(r"digest\(\s*['\"]hex|toString\(16\)"),
    "python": re.compile(r"\bhexdigest\(|\.hex\(\)"),
}
FN_DEF = {
    "rust": re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+(\w+)"),
    "go": re.compile(r"^func\s+(?:\([^)]*\)\s*)?(\w+)"),
    "script": re.compile(r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*(\w+)"
                         r"|^\s*(?:export\s+)?const\s+(\w+)\s*=\s*(?:async\s*)?(?:\([^)]*\)|\w+)\s*(?::[^=]+)?=>"),
    "python": re.compile(r"^\s*(?:async\s+)?def\s+(\w+)"),
}
DIGEST_HELPER_NAME = re.compile(r"(?i)sha\d|(?:^|_)sha(?:_|$)|digest|hash|checksum|fingerprint")
DIGEST_HELPER_MAX_LINES = 30
API_NAME_MIN = 10
PUB_FN = re.compile(r"^\s*pub(?:\((?:crate|super)\))?\s+(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+(\w+)")
ANY_FN = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+(\w+)")

SM_ENUM = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?enum\s+((?:[A-Z]\w*)?(?:State|Phase|Lifecycle))\b")
SM_T1 = re.compile(r"\bfn\s+\w*(?:transition|advance|next_state|apply_event|step)\w*\s*[<(]")
TS_SM = re.compile(r"^\s*(?:export\s+)?type\s+((?:[A-Z]\w*)?(?:State|Phase|Lifecycle))\s*=\s*(?:\|\s*)?(?:['\"]|$)")
GO_SM = re.compile(r"^type\s+((?:[A-Z]\w*)?(?:State|Phase|Lifecycle))\s+(?:int|int32|uint8|string)\b")

SLEEP_MARKER = {
    "rust": re.compile(r"\bsleep(?:_until)?\s*\(|\.tick\(\)\s*\.await"),
    "go": re.compile(r"\btime\.Sleep\(|<-\s*[\w.]+\.C\b|<-\s*time\.After\("),
    "script": re.compile(r"\bawait\s+(?:sleep|delay|wait|pause)\s*\(|setTimeout\(\s*(?:resolve|res|r)\b"),
    "python": re.compile(r"\b(?:time\.sleep|asyncio\.sleep|sleep)\s*\("),
    "shell": re.compile(r"^\s*sleep\s+[\d$]"),
    "powershell": re.compile(r"(?i)\bStart-Sleep\b"),
}
LOOP_HEADER = {
    "rust": re.compile(r"^\s*(?:'\w+:\s*)?(?:loop\b|while\b|for\b)"),
    "go": re.compile(r"^\s*for\b"),
    "script": re.compile(r"^\s*(?:\}\s*)?(?:while\s*\(|for\s*(?:await\s*)?\(|do\s*\{)"),
    "python": re.compile(r"^\s*(?:async\s+)?(?:while\b|for\b)"),
    "shell": re.compile(r"^\s*(?:while\b|until\b|for\b)"),
    "powershell": re.compile(r"(?i)^\s*(?:while\b|do\b|for\b|foreach\b)"),
}
FUNC_HEADER = {
    "rust": re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern\s+\"[^\"]*\"\s+)?fn\b"),
    "go": re.compile(r"^func\b"),
    "script": re.compile(r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\b|=>\s*\{\s*$"
                         r"|^\s*(?:(?:public|private|protected|static|async)\s+)*[A-Za-z_$][\w$]*\s*\([^)]*\)\s*(?::[^={]+)?\{\s*$"),
    "python": re.compile(r"^\s*(?:async\s+)?def\b"),
    "shell": re.compile(r"^\s*(?:function\s+)?[A-Za-z_][\w-]*\s*\(\)\s*\{"),
    "powershell": re.compile(r"(?i)^\s*function\b"),
}
SET_INTERVAL = re.compile(r"\bsetInterval\s*\(")


def family(lang: str) -> str:
    return "script" if lang in SCRIPT_LIKE else lang


# --- git access ------------------------------------------------------------------------


class Git:
    def __init__(self, repo: Path):
        self.repo = repo
        self.env = dict(os.environ, GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0", LC_ALL="C")

    def run(self, *args: str, data: bytes | None = None) -> bytes:
        command = ["git", "-C", str(self.repo), "-c", "core.quotepath=off", *args]
        result = subprocess.run(command, input=data, capture_output=True, env=self.env, check=False)
        if result.returncode != 0:
            raise SystemExit(f"git {' '.join(args[:3])} failed: {result.stderr.decode('utf-8', 'replace').strip()}")
        return result.stdout

    def commit(self, rev: str) -> dict:
        try:
            sha = self.run("rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}").decode().strip()
        except SystemExit:
            raise SystemExit(f"{rev!r} is not a commit in {self.repo}") from None
        meta = self.run("show", "-s", "--no-show-signature", "--format=%H%x00%cI%x00%s", sha).decode("utf-8", "replace")
        full, date, subject = meta.rstrip("\n").split("\x00", 2)
        return {"rev": rev, "sha": full, "date": date, "subject": subject}

    def tree(self, sha: str) -> dict[str, tuple[str, int]]:
        entries = {}
        for record in self.run("ls-tree", "-r", "-l", "-z", sha).split(b"\0"):
            if not record:
                continue
            head, path = record.split(b"\t", 1)
            mode, kind, blob, size = head.decode().split()
            if kind != "blob" or mode == "120000":
                continue
            entries[path.decode("utf-8", "replace")] = (blob, int(size) if size != "-" else 0)
        return entries

    def blobs(self, shas: list[str]) -> dict[str, bytes]:
        out: dict[str, bytes] = {}
        if not shas:
            return out
        raw = self.run("cat-file", "--batch", data=("\n".join(shas) + "\n").encode())
        position = 0
        while position < len(raw):
            newline = raw.index(b"\n", position)
            header = raw[position:newline].decode().split()
            position = newline + 1
            if len(header) < 3 or header[1] == "missing":
                continue
            size = int(header[2])
            out[header[0]] = raw[position:position + size]
            position += size + 1
        return out


# --- file model ------------------------------------------------------------------------


@dataclass
class FileInfo:
    path: str
    lang: str
    area: str
    size: int
    test_path: bool
    lines: list[str]
    kinds: list[str]
    test_mask: list[bool]

    def prod_code(self):
        for index, line in enumerate(self.lines):
            if self.kinds[index] == "k" and not self.test_mask[index]:
                yield index, line


@dataclass
class Snapshot:
    label: str
    meta: dict
    sizes: dict[str, int]
    files: dict[str, FileInfo] = field(default_factory=dict)
    manifests: dict[str, str] = field(default_factory=dict)
    test_paths: set[str] = field(default_factory=set)


def excluded(path: str) -> bool:
    if path.startswith(EXCLUDED_PREFIXES):
        return True
    return any(part in EXCLUDED_COMPONENTS for part in path.split("/")[:-1])


def lang_of(path: str) -> str | None:
    return SOURCE_LANGS.get(posixpath.splitext(path)[1].lower())


def area_of(path: str) -> str:
    if path.startswith(SRC_TAURI):
        rest = path[len(SRC_TAURI):]
        first = rest.split("/", 1)[0]
        if "/" not in rest:
            for suffix in MODULE_SUFFIXES:
                if first.endswith(suffix):
                    first = first[: -len(suffix)]
                    break
        return SRC_TAURI + first
    for prefix, name in TOP_AREAS:
        if path.startswith(prefix):
            return name
    return "other"


def path_is_test(path: str) -> bool:
    parts = path.split("/")
    if any(part in TEST_DIRS for part in parts[:-1]):
        return True
    return bool(TEST_NAME.search(parts[-1]))


def decode(data: bytes) -> str | None:
    if b"\0" in data[:8192]:
        return None
    return data.decode("utf-8", "replace")


def classify_lines(lines: list[str], lang: str) -> list[str]:
    if lang in C_LIKE:
        block_open, block_close, line_comment = "/*", "*/", None if lang == "css" else "//"
    elif lang == "html":
        block_open, block_close, line_comment = "<!--", "-->", None
    elif lang == "powershell":
        block_open, block_close, line_comment = "<#", "#>", "#"
    else:
        block_open, block_close, line_comment = None, None, "#"
    kinds = []
    in_block = False
    for raw in lines:
        text = raw.strip()
        if in_block:
            if block_close in text:
                in_block = False
                rest = text.split(block_close, 1)[1].strip()
                kinds.append("k" if rest else "c")
            else:
                kinds.append("c" if text else "b")
            continue
        if not text:
            kinds.append("b")
        elif line_comment and text.startswith(line_comment):
            kinds.append("c")
        elif block_open and text.startswith(block_open):
            after = text[len(block_open):]
            if block_close in after:
                kinds.append("k" if after.split(block_close, 1)[1].strip() else "c")
            else:
                in_block = True
                kinds.append("c")
        else:
            kinds.append("k")
    return kinds


def indent_of(line: str) -> int:
    count = 0
    for char in line:
        if char == " ":
            count += 1
        elif char == "\t":
            count += 4
        else:
            break
    return count


def closing_line(lines: list[str], start: int, indent: str) -> int | None:
    pattern = re.compile("^" + re.escape(indent) + r"\}\s*;?\s*$")
    for index in range(start, len(lines)):
        if pattern.match(lines[index]):
            return index
    return None


def rust_test_regions(lines: list[str]) -> tuple[list[bool], list[tuple[str, str | None]]]:
    """Marks #[cfg(test)] items; returns the mask and out-of-line test module declarations."""
    mask = [False] * len(lines)
    declarations: list[tuple[str, str | None]] = []
    index = 0
    while index < len(lines):
        inline = CFG_TEST_SAME_LINE.match(lines[index])
        if inline:
            if inline.group(3) == ";":
                declarations.append((inline.group(2), None))
                end = index
            else:
                close = closing_line(lines, index + 1, inline.group(1))
                end = close if close is not None else len(lines) - 1
            for position in range(index, end + 1):
                mask[position] = True
            index = end + 1
            continue
        match = CFG_TEST.match(lines[index])
        if not match:
            index += 1
            continue
        indent = match.group(1)
        path_attr = None
        cursor = index + 1
        while cursor < len(lines) and (ATTR.match(lines[cursor]) or not lines[cursor].strip()
                                       or lines[cursor].strip().startswith("//")):
            attr = PATH_ATTR.match(lines[cursor])
            if attr:
                path_attr = attr.group(1)
            cursor += 1
        if cursor >= len(lines):
            break
        item = TEST_ITEM.match(lines[cursor])
        end = cursor
        if item:
            keyword = item.group(2)
            # Find the line that opens the body or ends the item.
            opener = cursor
            while opener < len(lines) and not lines[opener].rstrip().endswith(("{", ";", "}")):
                opener += 1
            if opener < len(lines):
                tail = lines[opener].rstrip()
                if tail.endswith(";") and "{" not in lines[opener]:
                    end = opener
                    if keyword == "mod":
                        declarations.append((item.group(3), path_attr))
                elif tail.endswith("}") and lines[opener].count("{") <= lines[opener].count("}"):
                    end = opener
                else:
                    close = closing_line(lines, opener + 1, indent)
                    if close is not None:
                        end = close
                    elif keyword == "mod":
                        end = len(lines) - 1
                    else:
                        end = opener
        for position in range(index, end + 1):
            mask[position] = True
        index = end + 1
    return mask, declarations


def resolve_test_modules(path: str, declarations, test_files: set[str], test_dirs: set[str]) -> None:
    directory = posixpath.dirname(path)
    stem = posixpath.splitext(posixpath.basename(path))[0]
    module_dir = directory if stem in ("mod", "lib", "main") else posixpath.join(directory, stem)
    for name, path_attr in declarations:
        if path_attr:
            test_files.add(posixpath.normpath(posixpath.join(directory, path_attr)))
            continue
        test_files.add(posixpath.join(module_dir, name + ".rs"))
        test_files.add(posixpath.join(module_dir, name, "mod.rs"))
        test_dirs.add(posixpath.join(module_dir, name) + "/")


def build_snapshot(git: Git, label: str, rev: str) -> Snapshot:
    if rev == WORKTREE:
        head = git.commit("HEAD")
        meta = {"rev": WORKTREE, "sha": None, "date": None,
                "subject": f"working tree (tracked and untracked, not ignored) over HEAD {head['sha']}",
                "head_sha": head["sha"], "reproducible": False}
        listed = git.run("ls-files", "-z", "-c", "-o", "--exclude-standard").split(b"\0")
        paths = sorted({item.decode("utf-8", "replace") for item in listed if item})
        sizes, contents = {}, {}
        for path in paths:
            if excluded(path):
                continue
            full = git.repo / path
            if full.is_symlink() or not full.is_file():
                continue
            sizes[path] = full.stat().st_size
            name = posixpath.basename(path)
            if lang_of(path) or name in MANIFEST_NAMES:
                contents[path] = full.read_bytes()
    else:
        meta = dict(git.commit(rev), reproducible=True)
        tree = {path: entry for path, entry in git.tree(meta["sha"]).items() if not excluded(path)}
        sizes = {path: size for path, (_, size) in tree.items()}
        wanted = {path: blob for path, (blob, _) in tree.items()
                  if lang_of(path) or posixpath.basename(path) in MANIFEST_NAMES}
        blobs = git.blobs(sorted(set(wanted.values())))
        contents = {path: blobs[blob] for path, blob in wanted.items() if blob in blobs}
    snapshot = Snapshot(label=label, meta=meta, sizes=dict(sorted(sizes.items())))
    texts = {}
    for path in sorted(contents):
        text = decode(contents[path])
        if text is None:
            continue
        if posixpath.basename(path) in MANIFEST_NAMES:
            snapshot.manifests[path] = text
        if lang_of(path):
            texts[path] = text
    test_files: set[str] = set()
    test_dirs: set[str] = set()
    rust_masks = {}
    for path, text in texts.items():
        if lang_of(path) == "rust":
            mask, declarations = rust_test_regions(text.splitlines())
            rust_masks[path] = mask
            resolve_test_modules(path, declarations, test_files, test_dirs)
    for path, text in texts.items():
        lang = lang_of(path)
        lines = text.splitlines()
        is_test = path_is_test(path) or path in test_files or any(path.startswith(d) for d in test_dirs)
        if is_test:
            mask = [True] * len(lines)
            snapshot.test_paths.add(path)
        else:
            mask = rust_masks.get(path, [False] * len(lines))
        snapshot.files[path] = FileInfo(path, lang, area_of(path), sizes.get(path, 0), is_test,
                                        lines, classify_lines(lines, lang), mask)
    return snapshot


# --- measurements ----------------------------------------------------------------------


def measure_lines(snapshot: Snapshot) -> dict:
    areas: dict[str, dict] = {}

    def bucket(name: str) -> dict:
        return areas.setdefault(name, {
            "prod_files": 0, "test_files": 0, "prod_lines": 0, "test_lines": 0,
            "prod_code": 0, "test_code": 0, "prod_comment": 0, "test_comment": 0,
            "inline_test_code": 0, "prod_code_by_lang": {}, "tracked_bytes": 0,
        })

    for path, size in snapshot.sizes.items():
        bucket(area_of(path))["tracked_bytes"] += size
        if path.startswith(SRC_TAURI):
            bucket("src-tauri/src (all)")["tracked_bytes"] += size
        bucket("TOTAL")["tracked_bytes"] += size
    for info in snapshot.files.values():
        targets = [info.area, "TOTAL"] + (["src-tauri/src (all)"] if info.path.startswith(SRC_TAURI) else [])
        counts = {"prod_lines": 0, "test_lines": 0, "prod_code": 0, "test_code": 0,
                  "prod_comment": 0, "test_comment": 0, "inline_test_code": 0}
        for index, kind in enumerate(info.kinds):
            side = "test" if info.test_mask[index] else "prod"
            counts[f"{side}_lines"] += 1
            if kind == "k":
                counts[f"{side}_code"] += 1
                if side == "test" and not info.test_path:
                    counts["inline_test_code"] += 1
            elif kind == "c":
                counts[f"{side}_comment"] += 1
        for name in targets:
            target = bucket(name)
            target["test_files" if info.test_path else "prod_files"] += 1
            for key, value in counts.items():
                target[key] += value
            if counts["prod_code"]:
                by_lang = target["prod_code_by_lang"]
                by_lang[info.lang] = by_lang.get(info.lang, 0) + counts["prod_code"]
    for value in areas.values():
        value["prod_code_by_lang"] = dict(sorted(value["prod_code_by_lang"].items()))
    return dict(sorted(areas.items()))


def macro_definitions(snapshot: Snapshot) -> list[dict]:
    found = []
    for path in sorted(snapshot.files):
        info = snapshot.files[path]
        if info.lang != "rust" or info.test_path:
            continue
        for index, line in enumerate(info.lines):
            if info.test_mask[index] or info.kinds[index] != "k":
                continue
            match = MACRO_DEF.match(line)
            if not match:
                continue
            end = closing_line(info.lines, index + 1, match.group(1))
            if end is None:
                end = index
            body_lines = [re.sub(r"//.*$", "", text) for text in info.lines[index:end + 1]]
            name = match.group(2)
            normalised = re.sub(r"\s+", " ", " ".join(body_lines)).strip()
            normalised = re.sub(r"\b" + re.escape(name) + r"\b", "$M", normalised)
            found.append({
                "name": name, "path": path, "line": index + 1, "lines": end - index + 1,
                "hash": hashlib.sha256(normalised.encode()).hexdigest()[:12],
                "strict_serde_enum": ("deny_unknown_fields" in normalised and "serde" in normalised
                                      and re.search(r"\benum\b", normalised) is not None),
                "_tokens": re.findall(r"\$?\w+|[^\s\w]", normalised),
            })
    return found


FAMILY_RATIO = 0.75
NEAR_IDENTICAL_RATIO = 0.9


def similarity(definitions: list[dict]) -> dict[tuple[int, int], float]:
    ratios = {}
    for left in range(len(definitions)):
        for right in range(left + 1, len(definitions)):
            matcher = difflib.SequenceMatcher(None, definitions[left]["_tokens"], definitions[right]["_tokens"],
                                              autojunk=False)
            if matcher.real_quick_ratio() >= FAMILY_RATIO and matcher.quick_ratio() >= FAMILY_RATIO:
                ratios[(left, right)] = matcher.ratio()
    return ratios


def components(count: int, edges) -> list[list[int]]:
    parent = list(range(count))

    def find(item: int) -> int:
        while parent[item] != item:
            parent[item] = parent[parent[item]]
            item = parent[item]
        return item

    for left, right in edges:
        parent[find(left)] = find(right)
    groups: dict[int, list[int]] = {}
    for index in range(count):
        groups.setdefault(find(index), []).append(index)
    return [sorted(group) for group in groups.values() if len(group) > 1]


def macro_families(definitions: list[dict]) -> list[dict]:
    ratios = similarity(definitions)
    same_name = [(a, b) for a in range(len(definitions)) for b in range(a + 1, len(definitions))
                 if definitions[a]["name"] == definitions[b]["name"] and definitions[a]["path"] != definitions[b]["path"]]
    family_edges = same_name + [pair for pair, ratio in ratios.items() if ratio >= FAMILY_RATIO]
    near_edges = [pair for pair, ratio in ratios.items() if ratio >= NEAR_IDENTICAL_RATIO]
    families = []
    for group in components(len(definitions), family_edges):
        members = sorted((definitions[i] for i in group), key=lambda d: (d["path"], d["line"]))
        total = sum(d["lines"] for d in members)
        near = []
        for sub in components(len(definitions), [(a, b) for a, b in near_edges if a in group and b in group]):
            near.append(sorted({definitions[i]["name"] for i in sub}) + [f"x{len(sub)}"])
        families.append({
            "names": sorted({d["name"] for d in members}),
            "definitions": len(members),
            "distinct_bodies": len({d["hash"] for d in members}),
            "total_lines": total,
            "lines_beyond_one_copy": total - max(d["lines"] for d in members),
            "strict_serde_enum": all(d["strict_serde_enum"] for d in members),
            "near_identical_groups": sorted(near, key=lambda item: (-int(item[-1][1:]), item)),
            "members": [f"{d['path']}:{d['line']} {d['name']} ({d['lines']} lines, body {d['hash']})" for d in members],
        })
    return sorted(families, key=lambda f: (-f["definitions"], -f["total_lines"], f["names"]))


def measure_duplicates(snapshot: Snapshot) -> dict:
    definitions = macro_definitions(snapshot)
    strict = [d for d in definitions if d["strict_serde_enum"]]
    by_name: dict[str, list[str]] = {}
    for d in definitions:
        by_name.setdefault(d["name"], []).append(f"{d['path']}:{d['line']}")
    invocations = 0
    hazard_files, adopters, json_readers, go_strict, from_json = [], [], [], [], []
    digest_helpers, digest_inline, sha_files = [], [], []
    for path in sorted(snapshot.files):
        info = snapshot.files[path]
        if info.test_path:
            continue
        code = list(info.prod_code())
        text = "\n".join(line for _, line in code)
        if info.lang == "rust":
            invocations += len(STRICT_INVOCATION.findall(text))
        hazard_lines = [index + 1 for index, line in code if len(HAZARD_CODEPOINT.findall(line)) >= 2]
        if hazard_lines:
            hazard_fns = sorted({m.group(1) for _, line in code for m in HAZARD_FN.finditer(line)})
            hazard_files.append({"path": path, "codepoint_lines": len(hazard_lines),
                                 "functions": hazard_fns,
                                 "canonical": path == "src-tauri/src/foundation/text.rs"})
        if info.lang == "rust" and path != "src-tauri/src/foundation/text.rs" and TEXT_ADOPTER.search(text):
            adopters.append(path)
        if info.lang == "rust":
            signals = []
            if VISIT_MAP.search(text) and DUP_REFUSAL.search(text):
                signals.append("visit_map with duplicate refusal")
            generic = sorted({m.group(1) for m in GENERIC_JSON_FN.finditer(text)})
            if generic and JSON_USE.search(text):
                signals.append("generic reader fn " + ", ".join(generic))
            if signals:
                json_readers.append({"path": path, "signals": signals})
            count = len(FROM_JSON_METHOD.findall(text))
            if count:
                from_json.append({"path": path, "methods": count})
        if info.lang == "go" and GO_STRICT_JSON.search(text):
            go_strict.append(path)
        fam = family(info.lang)
        if fam in SHA_CALL:
            if SHA_CALL[fam].search(text):
                sha_files.append(path)
                for name, line_number, length in digest_functions(info, code, fam):
                    entry = f"{path}:{line_number} {name}"
                    if DIGEST_HELPER_NAME.search(name) and length <= DIGEST_HELPER_MAX_LINES:
                        digest_helpers.append({"function": entry, "area": info.area})
                    else:
                        digest_inline.append(entry)
    helper_areas: dict[str, int] = {}
    for item in digest_helpers:
        helper_areas[item["area"]] = helper_areas.get(item["area"], 0) + 1
    return {
        "strict_serde_enum_macros": {
            "definitions": len(strict),
            "distinct_names": len({d["name"] for d in strict}),
            "distinct_bodies": len({d["hash"] for d in strict}),
            "total_lines": sum(d["lines"] for d in strict),
            "invocations": invocations,
            "list": [f"{d['path']}:{d['line']} {d['name']} ({d['lines']} lines, body {d['hash']})" for d in strict],
        },
        "macro_rules": {
            "definitions": len(definitions),
            "names_defined_more_than_once": {name: paths for name, paths in sorted(by_name.items()) if len(paths) > 1},
            "families": macro_families(definitions),
        },
        "hazardous_text_checks": {"files": hazard_files, "count": len(hazard_files),
                                  "foundation_text_adopters": adopters},
        "strict_json_readers": {"rust_files": json_readers, "count": len(json_readers),
                                "from_json_methods": sum(item["methods"] for item in from_json),
                                "from_json_files": len(from_json), "go_disallow_unknown_fields_files": go_strict},
        "digest_helpers": {"functions": [item["function"] for item in digest_helpers], "count": len(digest_helpers),
                           "by_area": dict(sorted(helper_areas.items())),
                           "inline_sites": len(digest_inline), "inline_site_list": digest_inline,
                           "files_computing_sha256": len(sha_files)},
    }


def digest_functions(info: FileInfo, code: list[tuple[int, str]], fam: str) -> list[tuple[str, int, int]]:
    """Functions that compute SHA-256 and hex-encode: (name, first line, code lines)."""
    pattern = FN_DEF[fam]
    starts = []
    for position, (index, line) in enumerate(code):
        match = pattern.match(line)
        if match:
            starts.append((position, index, next(group for group in match.groups() if group)))
    found = []
    for number, (position, index, name) in enumerate(starts):
        stop = starts[number + 1][0] if number + 1 < len(starts) else len(code)
        chunk = [line for (line_index, line) in code[position:stop] if line_index - index < 80]
        body = "\n".join(chunk)
        if SHA_CALL[fam].search(body) and HEX_ENCODE[fam].search(body):
            found.append((name, index + 1, len(chunk)))
    return found


def path_in(path: str, defs: list[str]) -> bool:
    return any(path == d or (d.endswith("/") and path.startswith(d)) for d in defs)


def in_surface(path: str) -> bool:
    return path.startswith(PRODUCT_SURFACES)


def crate_of(path: str, roots: list[str]) -> str:
    """The deepest directory holding a Cargo.toml that contains `path` ("" if none)."""
    for root in roots:
        if path.startswith(root + "/"):
            return root
    return ""


def measure_paths(snapshot: Snapshot) -> list[dict]:
    roots = sorted({posixpath.dirname(path) for path in snapshot.manifests
                    if posixpath.basename(path) == "Cargo.toml"}, key=lambda root: (-len(root), root))
    defined_elsewhere: dict[str, set[str]] = {}
    for path, info in snapshot.files.items():
        if info.lang == "rust" and not info.test_path:
            for _, line in info.prod_code():
                match = ANY_FN.match(line)
                if match:
                    defined_elsewhere.setdefault(match.group(1), set()).add(path)
    results = []
    for spec in EXECUTION_PATHS:
        defs = spec["defs"]
        anchors = re.compile(spec["anchors"]) if spec["anchors"] else None
        impl_files, impl_code, api_names = [], 0, set()
        for path in sorted(snapshot.files):
            info = snapshot.files[path]
            if path_in(path, defs) and not info.test_path:
                impl_files.append(path)
                for _, line in info.prod_code():
                    impl_code += 1
                    match = PUB_FN.match(line) if info.lang == "rust" else None
                    if match:
                        api_names.add(match.group(1))
        tokens = API_TOKENS.get(spec["id"], ())
        api_names = {name for name in api_names if len(name) >= API_NAME_MIN
                     and (name.count("_") >= 2 or ("_" in name and any(t in name.split("_") for t in tokens)))
                     and all(path_in(p, defs) for p in defined_elsewhere.get(name, ()))}
        api_pattern = (re.compile(r"\b(?:" + "|".join(sorted(api_names)) + r")\s*(?:\(|::<)")
                       if api_names else None)
        crates = {crate_of(path, roots) for path in impl_files}
        callers, caller_lines, test_refs, api_callers = [], 0, [], []
        for path in sorted(snapshot.files):
            info = snapshot.files[path]
            if path_in(path, defs):
                continue
            if info.test_path:
                if anchors and any(anchors.search(line) for line in info.lines):
                    test_refs.append(path)
                continue
            hits = 0
            api_hit = False
            same_crate = info.lang == "rust" and crate_of(path, roots) in crates
            for _, line in info.prod_code():
                if anchors and anchors.search(line):
                    hits += 1
                if api_pattern and same_crate and api_pattern.search(line):
                    api_hit = True
            if hits:
                callers.append(path)
                caller_lines += hits
            if api_hit:
                api_callers.append(path)
        surface = sorted({p for p in callers + api_callers if in_surface(p)})
        by_area: dict[str, int] = {}
        for path in callers:
            by_area[area_of(path)] = by_area.get(area_of(path), 0) + 1
        results.append({
            "id": spec["id"], "group": spec["group"], "label": spec["label"],
            "implementation_files": len(impl_files), "implementation_prod_code": impl_code,
            "caller_files": len(callers), "caller_lines": caller_lines,
            "api_names": len(api_names), "api_caller_files": len(api_callers),
            "product_surface_files": len(surface), "test_reference_files": len(test_refs),
            "callers_by_area": dict(sorted(by_area.items())),
            "implementation": impl_files, "callers": callers, "api_callers": api_callers,
            "product_surface": surface,
        })
    return results


def enum_variants(snapshot: Snapshot) -> dict:
    out = {}
    for name in BACKEND_ENUMS:
        header = re.compile(r"^(\s*)(?:pub(?:\([^)]*\))?\s+)?enum\s+" + name + r"\b[^{;]*\{\s*$")
        for path in sorted(snapshot.files):
            info = snapshot.files[path]
            if info.lang != "rust" or info.test_path:
                continue
            for index, line in info.prod_code():
                match = header.match(line)
                if not match:
                    continue
                end = closing_line(info.lines, index + 1, match.group(1)) or index
                variants = []
                for body_index in range(index + 1, end):
                    if info.kinds[body_index] != "k":
                        continue
                    variant = re.match(r"^\s*([A-Z]\w*)\s*(?:[,({=]|$)", info.lines[body_index])
                    if variant and indent_of(info.lines[body_index]) == indent_of(line) + 4:
                        variants.append(variant.group(1))
                out.setdefault(name, []).append({"path": f"{path}:{index + 1}", "variants": variants})
    return out


def measure_state_machines(snapshot: Snapshot) -> dict:
    rust, other = [], []
    for path in sorted(snapshot.files):
        info = snapshot.files[path]
        if info.test_path:
            continue
        code = list(info.prod_code())
        if info.lang == "rust":
            names = [(index, SM_ENUM.match(line).group(1)) for index, line in code if SM_ENUM.match(line)]
            if not names:
                continue
            text = "\n".join(line for _, line in code)
            has_t1 = SM_T1.search(text) is not None
            for index, name in names:
                target = r"(?:" + re.escape(name) + r"|Self)::[A-Z]\w*"
                signals = []
                if has_t1:
                    signals.append("T1")
                if re.search(r"(?i:\b\w*(?:state|phase|lifecycle)\w*)\s*=\s*(?:Some\()?" + target, text):
                    signals.append("T2")
                if re.search(r"\(\s*" + target + r"[^()]*(?:\([^()]*\))?[^()]*,[^()]*\)\s*(?:if\b[^=]*)?=>", text) or \
                        re.search(r"\([^()]*,\s*" + target + r"[^()]*\)\s*(?:if\b[^=]*)?=>", text):
                    signals.append("T3")
                rust.append({"name": name, "path": f"{path}:{index + 1}", "area": info.area, "signals": signals})
        elif info.lang in SCRIPT_LIKE or info.lang == "go":
            pattern = GO_SM if info.lang == "go" else TS_SM
            for index, line in code:
                match = pattern.match(line)
                if match:
                    other.append({"name": match.group(1), "path": f"{path}:{index + 1}", "area": info.area})
    by_area: dict[str, dict] = {}
    for item in rust:
        bucket = by_area.setdefault(item["area"], {"enums": 0, "with_transitions": 0})
        bucket["enums"] += 1
        bucket["with_transitions"] += 1 if item["signals"] else 0
    return {
        "rust_enums": len(rust),
        "rust_with_transitions": sum(1 for item in rust if item["signals"]),
        "by_area": dict(sorted(by_area.items())),
        "rust": rust,
        "ts_go_declared": other,
    }


def enclosing_loop(info: FileInfo, index: int, fam: str) -> int | None:
    loop, func = LOOP_HEADER[fam], FUNC_HEADER[fam]
    if loop.match(info.lines[index]):
        return index
    current = indent_of(info.lines[index])
    for back in range(index - 1, max(-1, index - 400), -1):
        if info.kinds[back] != "k":
            continue
        line = info.lines[back]
        level = indent_of(line)
        if level >= current:
            continue
        current = level
        if loop.match(line):
            return back
        if func.search(line) and "new Promise" not in line:
            return None
        if level == 0:
            return None
    return None


def measure_polling(snapshot: Snapshot) -> dict:
    loops = {"prod": [], "test": []}
    for path in sorted(snapshot.files):
        info = snapshot.files[path]
        fam = family(info.lang)
        if fam not in SLEEP_MARKER:
            continue
        seen = set()
        for index, line in enumerate(info.lines):
            if info.kinds[index] != "k":
                continue
            side = "test" if info.test_mask[index] else "prod"
            if fam == "script" and SET_INTERVAL.search(line):
                loops[side].append({"path": f"{path}:{index + 1}", "area": info.area, "kind": "setInterval"})
                continue
            if not SLEEP_MARKER[fam].search(line):
                continue
            header = enclosing_loop(info, index, fam)
            if header is None or header in seen:
                continue
            seen.add(header)
            loops[side].append({"path": f"{path}:{header + 1}", "area": info.area, "kind": "loop with sleep"})
    by_area: dict[str, int] = {}
    for item in loops["prod"]:
        by_area[item["area"]] = by_area.get(item["area"], 0) + 1
    return {"prod": len(loops["prod"]), "test": len(loops["test"]),
            "prod_by_area": dict(sorted(by_area.items())), "prod_list": loops["prod"]}


def measure_dependencies(snapshot: Snapshot) -> dict:
    lockfiles, manifests, npm, gomods = {}, {}, {}, {}
    external_union = set()
    for path in sorted(snapshot.manifests):
        text = snapshot.manifests[path]
        name = posixpath.basename(path)
        try:
            if name == "Cargo.lock":
                packages = tomllib.loads(text).get("package", [])
                external = [p for p in packages if p.get("source")]
                external_union.update((p["name"], p["version"]) for p in external)
                lockfiles[path] = {"packages": len(packages), "external": len(external),
                                   "path_packages": len(packages) - len(external)}
            elif name == "Cargo.toml":
                data = tomllib.loads(text)
                direct = set()
                for key in ("dependencies", "dev-dependencies", "build-dependencies"):
                    direct.update(f"{key}:{dep}" for dep in data.get(key, {}))
                for target in data.get("target", {}).values():
                    for key in ("dependencies", "dev-dependencies", "build-dependencies"):
                        direct.update(f"{key}:{dep}" for dep in target.get(key, {}))
                manifests[path] = {"direct": len({entry.split(":", 1)[1] for entry in direct}),
                                   "entries": len(direct)}
            elif name == "package.json":
                data = json.loads(text)
                npm[path] = {"dependencies": len(data.get("dependencies", {})),
                             "devDependencies": len(data.get("devDependencies", {}))}
            elif name == "package-lock.json":
                data = json.loads(text)
                npm[path] = {"locked_packages": len([k for k in data.get("packages", {}) if k])}
            elif name == "go.mod":
                direct = indirect = 0
                in_block = False
                for line in text.splitlines():
                    stripped = line.strip()
                    if stripped.startswith("require ("):
                        in_block = True
                        continue
                    if in_block and stripped == ")":
                        in_block = False
                        continue
                    if (in_block and stripped and not stripped.startswith("//")) or stripped.startswith("require "):
                        if "// indirect" in stripped:
                            indirect += 1
                        else:
                            direct += 1
                gomods[path] = {"direct": direct, "indirect": indirect}
        except (tomllib.TOMLDecodeError, json.JSONDecodeError, KeyError, AttributeError) as error:
            manifests[path] = {"error": type(error).__name__}
    return {"cargo_lock": lockfiles, "cargo_toml": manifests, "npm": npm, "go_mod": gomods,
            "cargo_external_union": len(external_union)}


def change_surface(git: Git, base: Snapshot, head: Snapshot) -> dict:
    test_paths = base.test_paths | head.test_paths
    if head.meta["rev"] == WORKTREE:
        raw = git.run("diff", "--numstat", "--no-renames", "--no-ext-diff", "--no-textconv", "-z", base.meta["sha"], "--")
        untracked = {item.decode("utf-8", "replace") for item in
                     git.run("ls-files", "-z", "-o", "--exclude-standard").split(b"\0") if item}
    else:
        raw = git.run("diff", "--numstat", "--no-renames", "--no-ext-diff", "--no-textconv", "-z",
                      base.meta["sha"], head.meta["sha"], "--")
        untracked = set()
    rows = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        added, deleted, path = record.decode("utf-8", "replace").split("\t", 2)
        rows.append((path, None if added == "-" else int(added), None if deleted == "-" else int(deleted)))
    for path in sorted(untracked):
        info = head.files.get(path)
        if info is not None:
            rows.append((path, len(info.lines), 0))
        elif path in head.sizes:
            rows.append((path, None, None))
    areas: dict[str, dict] = {}
    for path, added, deleted in rows:
        if excluded(path):
            continue
        side = "test" if (path in test_paths or path_is_test(path)) else "prod"
        for name in [area_of(path), "TOTAL"] + (["src-tauri/src (all)"] if path.startswith(SRC_TAURI) else []):
            bucket = areas.setdefault(name, {"files": 0, "prod_added": 0, "prod_deleted": 0,
                                             "test_added": 0, "test_deleted": 0, "binary_files": 0})
            bucket["files"] += 1
            if added is None:
                bucket["binary_files"] += 1
                continue
            bucket[f"{side}_added"] += added
            bucket[f"{side}_deleted"] += deleted or 0
    added_files = sorted(set(head.sizes) - set(base.sizes))
    deleted_files = sorted(set(base.sizes) - set(head.sizes))
    return {"by_area": dict(sorted(areas.items())), "files_added": len(added_files),
            "files_deleted": len(deleted_files), "deleted_paths": deleted_files}


def artifacts(repo: Path, extra_roots: list[str]) -> list[dict]:
    found = []
    roots = [repo / crate / "target" for crate in ("src-tauri", "cli", "engine", "grid", "vault", "setup")]
    roots += [Path(root) for root in extra_roots]
    for root in roots:
        for profile in ("release", "debug"):
            directory = root / profile
            if not directory.is_dir():
                continue
            for entry in sorted(directory.iterdir()):
                if entry.name.startswith(".") or not entry.is_file():
                    continue
                suffix = entry.suffix.lower()
                if suffix in (".exe", ".dll", ".so", ".dylib") or (suffix == "" and is_executable_image(entry)):
                    found.append(stat_entry(entry))
        bundle = root / "release" / "bundle"
        if bundle.is_dir():
            for entry in sorted(bundle.rglob("*")):
                if entry.is_file() and entry.suffix.lower() in (".exe", ".msi", ".dmg", ".appimage", ".deb", ".rpm"):
                    found.append(stat_entry(entry))
    dist = repo / "dist"
    if dist.is_dir():
        total, count, newest = 0, 0, 0.0
        for entry in dist.rglob("*"):
            if entry.is_file():
                status = entry.stat()
                total += status.st_size
                count += 1
                newest = max(newest, status.st_mtime)
        found.append({"path": str(dist), "bytes": total, "files": count, "modified": iso(newest)})
    return found


EXECUTABLE_MAGIC = (b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"MZ")


def is_executable_image(entry: Path) -> bool:
    """An extensionless file counts only if it starts with an ELF, Mach-O or PE magic."""
    with entry.open("rb") as handle:
        head = handle.read(4)
    return head.startswith(EXECUTABLE_MAGIC)


def iso(timestamp: float) -> str:
    return datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def stat_entry(entry: Path) -> dict:
    status = entry.stat()
    return {"path": str(entry), "bytes": status.st_size, "modified": iso(status.st_mtime)}


# --- report ----------------------------------------------------------------------------


def measure(git: Git, snapshot: Snapshot) -> dict:
    return {
        "revision": snapshot.meta,
        "lines": measure_lines(snapshot),
        "duplicates": measure_duplicates(snapshot),
        "execution_paths": measure_paths(snapshot),
        "backend_enums": enum_variants(snapshot),
        "state_machines": measure_state_machines(snapshot),
        "polling_loops": measure_polling(snapshot),
        "dependencies": measure_dependencies(snapshot),
    }


def delta(before: int, after: int) -> str:
    return f"{after - before:+,}"


def table(header: list[str], rows: list[list]) -> list[str]:
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    out += ["| " + " | ".join(str(cell) for cell in row) + " |" for row in rows]
    return out


def present_paths(side: dict, group_prefix: str) -> int:
    """Execution paths of a group with implementation files or production callers."""
    return sum(1 for item in side["execution_paths"] if item["group"].startswith(group_prefix)
               and (item["implementation_files"] or item["caller_files"]))


def headline_rows(report: dict) -> list[list]:
    base, head, surface = report["base"], report["head"], report["change_surface"]["by_area"].get("TOTAL", {})
    rows = []
    for label, key in (("Production code lines (all areas)", "prod_code"), ("Test code lines (all areas)", "test_code")):
        rows.append([label, f"{base['lines']['TOTAL'][key]:,}", f"{head['lines']['TOTAL'][key]:,}"])
    tauri = "src-tauri/src (all)"
    rows.append(["Production code lines, src-tauri/src", f"{base['lines'].get(tauri, {}).get('prod_code', 0):,}",
                 f"{head['lines'].get(tauri, {}).get('prod_code', 0):,}"])
    duplicates = [
        ("Strict serde enum macro definitions", lambda s: s["duplicates"]["strict_serde_enum_macros"]["definitions"]),
        ("Macro families with 2+ definitions", lambda s: len(s["duplicates"]["macro_rules"]["families"])),
        ("Hazardous-text check files", lambda s: s["duplicates"]["hazardous_text_checks"]["count"]),
        ("Strict JSON reader files (Rust)", lambda s: s["duplicates"]["strict_json_readers"]["count"]),
        ("SHA-256 to hex helper functions", lambda s: s["duplicates"]["digest_helpers"]["count"]),
        ("VM-D9 paths present (of 4)", lambda s: present_paths(s, "VM-D9")),
        ("VM sandbox backends with an implementation", lambda s: sum(
            1 for item in s["execution_paths"] if item["group"] == "VM sandbox backend" and item["implementation_files"])),
        ("Rust state enums / with transition signals",
         lambda s: f"{s['state_machines']['rust_enums']} / {s['state_machines']['rust_with_transitions']}"),
        ("Production polling loops", lambda s: s["polling_loops"]["prod"]),
        ("Cargo external packages (union of lockfiles)", lambda s: s["dependencies"]["cargo_external_union"]),
        ("Bytes of files in scope (tracked blobs)", lambda s: f"{s['lines']['TOTAL']['tracked_bytes']:,}"),
    ]
    rows += [[label, getter(base), getter(head)] for label, getter in duplicates]
    rows.append(["Change surface: files / prod lines added / deleted (raw)", "",
                 f"{surface.get('files', 0):,} / +{surface.get('prod_added', 0):,} / -{surface.get('prod_deleted', 0):,}"])
    return rows


def render_markdown(report: dict) -> str:
    base, head = report["base"], report["head"]
    out = [f"# Compactness measurement (rules v{report['rules_version']})", ""]
    for label, item in (("Base", base), ("Head", head)):
        meta = item["revision"]
        sha = meta["sha"] or f"WORKTREE over {meta['head_sha']}"
        out.append(f"- {label}: `{sha}` {meta['date'] or ''} {meta['subject']}")
    out += ["", "Heuristic counts; the counting rules are in the docstring of scripts/compactness/measure.py.", ""]

    out += ["## Headline", ""]
    out += table(["Measure", "Base", "Head"], headline_rows(report))
    out += ["", "## Production and test code lines", ""]
    rows = []
    areas = sorted(set(base["lines"]) | set(head["lines"]))
    top = [a for a in areas if not a.startswith(SRC_TAURI) or a == "src-tauri/src (all)"]
    zero = {"prod_code": 0, "test_code": 0, "inline_test_code": 0, "prod_files": 0, "test_files": 0, "tracked_bytes": 0}
    for name in [a for a in top if a != "TOTAL"] + ["TOTAL"]:
        b, h = base["lines"].get(name, zero), head["lines"].get(name, zero)
        rows.append([name, f"{b['prod_code']:,}", f"{h['prod_code']:,}", delta(b["prod_code"], h["prod_code"]),
                     f"{b['test_code']:,}", f"{h['test_code']:,}", delta(b["test_code"], h["test_code"]),
                     f"{h['inline_test_code']:,}"])
    out += table(["Area", "Prod code (base)", "Prod code (head)", "Δ", "Test code (base)", "Test code (head)", "Δ",
                  "Inline test (head)"], rows)
    out += ["", "src-tauri/src modules with a change (sorted by production change):", ""]
    rows = []
    modules = [a for a in areas if a.startswith(SRC_TAURI) and a != "src-tauri/src (all)"]
    changes = []
    for name in modules:
        b, h = base["lines"].get(name, zero), head["lines"].get(name, zero)
        if b["prod_code"] != h["prod_code"] or b["test_code"] != h["test_code"]:
            changes.append((-(abs(h["prod_code"] - b["prod_code"])), name, b, h))
    for _, name, b, h in sorted(changes):
        rows.append([name, f"{b['prod_code']:,}", f"{h['prod_code']:,}", delta(b["prod_code"], h["prod_code"]),
                     f"{b['test_code']:,}", f"{h['test_code']:,}", delta(b["test_code"], h["test_code"])])
    out += table(["Module", "Prod (base)", "Prod (head)", "Δ", "Test (base)", "Test (head)", "Δ"], rows)

    out += ["", "## Duplicated policy and parsers", ""]
    bd, hd = base["duplicates"], head["duplicates"]
    rows = [
        ["Strict serde enum macro definitions", bd["strict_serde_enum_macros"]["definitions"],
         hd["strict_serde_enum_macros"]["definitions"]],
        ["  distinct bodies", bd["strict_serde_enum_macros"]["distinct_bodies"],
         hd["strict_serde_enum_macros"]["distinct_bodies"]],
        ["  lines in definitions", bd["strict_serde_enum_macros"]["total_lines"],
         hd["strict_serde_enum_macros"]["total_lines"]],
        ["  invocations (strict_*enum!)", bd["strict_serde_enum_macros"]["invocations"],
         hd["strict_serde_enum_macros"]["invocations"]],
        ["macro_rules! definitions", bd["macro_rules"]["definitions"], hd["macro_rules"]["definitions"]],
        ["Macro families (2+ similar definitions)", len(bd["macro_rules"]["families"]), len(hd["macro_rules"]["families"])],
        ["Hazardous-text check files", bd["hazardous_text_checks"]["count"], hd["hazardous_text_checks"]["count"]],
        ["foundation::text adopters", len(bd["hazardous_text_checks"]["foundation_text_adopters"]),
         len(hd["hazardous_text_checks"]["foundation_text_adopters"])],
        ["Strict JSON reader files (Rust)", bd["strict_json_readers"]["count"], hd["strict_json_readers"]["count"]],
        ["Per-type from_json methods", bd["strict_json_readers"]["from_json_methods"],
         hd["strict_json_readers"]["from_json_methods"]],
        ["Go files with DisallowUnknownFields", len(bd["strict_json_readers"]["go_disallow_unknown_fields_files"]),
         len(hd["strict_json_readers"]["go_disallow_unknown_fields_files"])],
        ["SHA-256 to hex helper functions (named, <= 30 lines)", bd["digest_helpers"]["count"],
         hd["digest_helpers"]["count"]],
        ["Other functions hashing to hex inline", bd["digest_helpers"]["inline_sites"],
         hd["digest_helpers"]["inline_sites"]],
        ["Files computing SHA-256", bd["digest_helpers"]["files_computing_sha256"],
         hd["digest_helpers"]["files_computing_sha256"]],
    ]
    out += table(["Measure", "Base", "Head"], rows)
    out += ["", "Macro families at head:", ""]
    for fam in hd["macro_rules"]["families"]:
        near = "; ".join(" ".join(group) for group in fam["near_identical_groups"]) or "none"
        out.append(f"- {', '.join(fam['names'])}: {fam['definitions']} definitions, {fam['distinct_bodies']} distinct "
                   f"bodies, {fam['total_lines']} lines ({fam['lines_beyond_one_copy']} beyond one copy); "
                   f"near-identical groups: {near}")
    out += ["", "Hazardous-text check files at head:", ""]
    for item in hd["hazardous_text_checks"]["files"]:
        tag = " (canonical)" if item["canonical"] else ""
        out.append(f"- {item['path']}{tag}: {item['codepoint_lines']} code-point lines; functions "
                   f"{', '.join(item['functions']) or 'none'}")
    out += ["", "Strict JSON reader files at head:", ""]
    out += [f"- {item['path']}: {'; '.join(item['signals'])}" for item in hd["strict_json_readers"]["rust_files"]]
    out += ["", "SHA-256 to hex helper functions at head (by area: "
            + ", ".join(f"{k} {v}" for k, v in hd["digest_helpers"]["by_area"].items()) + "):", ""]
    out += [f"- {item}" for item in hd["digest_helpers"]["functions"]]

    out += ["", "## Execution paths and backends", ""]
    rows = []
    base_paths = {item["id"]: item for item in base["execution_paths"]}
    for item in head["execution_paths"]:
        b = base_paths[item["id"]]
        rows.append([item["label"], item["group"],
                     f"{b['implementation_files']}/{b['implementation_prod_code']:,} → "
                     f"{item['implementation_files']}/{item['implementation_prod_code']:,}",
                     f"{b['caller_files']} → {item['caller_files']}",
                     f"{b['api_caller_files']} → {item['api_caller_files']}",
                     f"{b['product_surface_files']} → {item['product_surface_files']}",
                     f"{b['test_reference_files']} → {item['test_reference_files']}"])
    out += table(["Path", "Group", "Impl files/prod code", "Caller files", "API caller files",
                  "Product-surface files", "Test files"], rows)
    out += ["", "Backend enums at head:", ""]
    for name, entries in head["backend_enums"].items():
        for entry in entries:
            out.append(f"- {name} ({entry['path']}): {', '.join(entry['variants'])}")

    out += ["", "## Maintained state machines", ""]
    bs, hs = base["state_machines"], head["state_machines"]
    out += table(["Measure", "Base", "Head"], [
        ["Rust *State/*Phase/*Lifecycle enums", bs["rust_enums"], hs["rust_enums"]],
        ["  with transition signals", bs["rust_with_transitions"], hs["rust_with_transitions"]],
        ["TS/Go declared state types", len(bs["ts_go_declared"]), len(hs["ts_go_declared"])],
    ])
    out += ["", "By area (enums / with transitions):", ""]
    rows = []
    for name in sorted(set(bs["by_area"]) | set(hs["by_area"])):
        b = bs["by_area"].get(name, {"enums": 0, "with_transitions": 0})
        h = hs["by_area"].get(name, {"enums": 0, "with_transitions": 0})
        rows.append([name, f"{b['enums']} / {b['with_transitions']}", f"{h['enums']} / {h['with_transitions']}"])
    out += table(["Area", "Base", "Head"], rows)

    out += ["", "## Polling loops", ""]
    bp, hp = base["polling_loops"], head["polling_loops"]
    rows = [[name, bp["prod_by_area"].get(name, 0), hp["prod_by_area"].get(name, 0)]
            for name in sorted(set(bp["prod_by_area"]) | set(hp["prod_by_area"]))]
    rows.append(["TOTAL (production)", bp["prod"], hp["prod"]])
    rows.append(["TOTAL (test code)", bp["test"], hp["test"]])
    out += table(["Area", "Base", "Head"], rows)

    out += ["", "## Dependencies", ""]
    rows = []
    bdep, hdep = base["dependencies"], head["dependencies"]
    for path in sorted(set(bdep["cargo_lock"]) | set(hdep["cargo_lock"])):
        b, h = bdep["cargo_lock"].get(path, {}), hdep["cargo_lock"].get(path, {})
        rows.append([path, f"{b.get('packages', '-')} ({b.get('external', '-')} external)",
                     f"{h.get('packages', '-')} ({h.get('external', '-')} external)"])
    rows.append(["Cargo external (name, version) union", bdep["cargo_external_union"], hdep["cargo_external_union"]])
    for path in sorted(set(bdep["cargo_toml"]) | set(hdep["cargo_toml"])):
        rows.append([path + " direct", bdep["cargo_toml"].get(path, {}).get("direct", "-"),
                     hdep["cargo_toml"].get(path, {}).get("direct", "-")])
    for path in sorted(set(bdep["npm"]) | set(hdep["npm"])):
        b, h = bdep["npm"].get(path, {}), hdep["npm"].get(path, {})
        rows.append([path, ", ".join(f"{k} {v}" for k, v in b.items()) or "-",
                     ", ".join(f"{k} {v}" for k, v in h.items()) or "-"])
    for path in sorted(set(bdep["go_mod"]) | set(hdep["go_mod"])):
        b, h = bdep["go_mod"].get(path, {}), hdep["go_mod"].get(path, {})
        rows.append([path, f"{b.get('direct', '-')} direct, {b.get('indirect', '-')} indirect",
                     f"{h.get('direct', '-')} direct, {h.get('indirect', '-')} indirect"])
    out += table(["Manifest", "Base", "Head"], rows)

    out += ["", "## Build and package size", "", "Tracked bytes (revision-bound proxy):", ""]
    rows = []
    for name in [a for a in top if a != "TOTAL"] + ["TOTAL"]:
        b, h = base["lines"].get(name, zero), head["lines"].get(name, zero)
        rows.append([name, f"{b['tracked_bytes']:,}", f"{h['tracked_bytes']:,}", delta(b["tracked_bytes"], h["tracked_bytes"])])
    out += table(["Area", "Base bytes", "Head bytes", "Δ"], rows)
    if report.get("artifacts") is not None:
        out += ["", "Artifacts on disk (not bound to a revision):", ""]
        out += table(["Path", "Bytes", "Modified (UTC)"],
                     [[item["path"], f"{item['bytes']:,}", item["modified"]] for item in report["artifacts"]])

    out += ["", "## Change surface", ""]
    surface = report["change_surface"]
    rows = []
    for name, item in surface["by_area"].items():
        if name.startswith(SRC_TAURI) and name != "src-tauri/src (all)":
            continue
        rows.append([name, item["files"], f"+{item['prod_added']:,} / -{item['prod_deleted']:,}",
                     f"+{item['test_added']:,} / -{item['test_deleted']:,}", item["binary_files"]])
    out += table(["Area", "Files changed", "Prod lines (raw)", "Test lines (raw)", "Binary files"], rows)
    out += ["", f"Files added: {surface['files_added']}; files deleted: {surface['files_deleted']}.", ""]
    return "\n".join(out)


def strip_private(value):
    if isinstance(value, dict):
        return {key: strip_private(item) for key, item in value.items() if not key.startswith("_")}
    if isinstance(value, list):
        return [strip_private(item) for item in value]
    return value


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Read-only compactness measurement between two revisions.")
    parser.add_argument("--repo", default=".", help="repository root (default: current directory)")
    parser.add_argument("--base", default=DEFAULT_BASE, help="baseline revision (default: the combined plan's start)")
    parser.add_argument("--head", default="HEAD", help=f"revision to compare, or {WORKTREE}")
    parser.add_argument("--json", help="write the full JSON report here")
    parser.add_argument("--markdown", help="write the Markdown summary here (default: stdout)")
    parser.add_argument("--no-artifacts", action="store_true", help="skip the on-disk artifact sizes")
    parser.add_argument("--artifact-root", action="append", default=[],
                        help="extra cargo target directory to scan (repeatable)")
    args = parser.parse_args(argv)
    repo = Path(args.repo).resolve()
    git = Git(Path(git_toplevel(repo)))
    base = build_snapshot(git, "base", args.base)
    head = build_snapshot(git, "head", args.head)
    report = {
        "rules_version": RULES_VERSION,
        "base": measure(git, base),
        "head": measure(git, head),
        "change_surface": change_surface(git, base, head),
        "artifacts": None if args.no_artifacts else artifacts(git.repo, args.artifact_root),
    }
    report = strip_private(report)
    markdown = render_markdown(report) + "\n"
    if args.json:
        with open(args.json, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(report, handle, indent=1, ensure_ascii=False)
            handle.write("\n")
    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(markdown)
    else:
        sys.stdout.buffer.write(markdown.encode("utf-8"))
        sys.stdout.buffer.flush()
    return 0


def git_toplevel(path: Path) -> str:
    result = subprocess.run(["git", "-C", str(path), "rev-parse", "--show-toplevel"], capture_output=True,
                            env=dict(os.environ, GIT_OPTIONAL_LOCKS="0"), check=False)
    if result.returncode != 0:
        raise SystemExit(f"{path} is not inside a git repository")
    return result.stdout.decode().strip()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
