#!/usr/bin/env python3
"""Check docs/acceptance-inventory.md against the repository, read-only.

The inventory lists every acceptance ID of GPU-T01-GPU-T48, INT-01-INT-12,
VM-P01-VM-P50, VM-CP-01-VM-CP-35 and VM-R01-VM-R110 with its evidence, existing
coverage, status and open owner. This script verifies that:

- every ID of every range appears exactly once, and no other ID appears;
- every status is one of the allowed values, and a "not applicable" status
  carries a reason;
- every evidence kind is one of host, guest, hardware, offline fake/model,
  benchmark or release;
- every referenced file or directory exists at the revision, and every
  referenced test function exists there and is marked as a test;
- "covered offline" rows rest on offline evidence alone and name at least one
  test, "partially covered" rows name at least one test, "not covered" rows name
  none, open rows name an owning task, and "via" rows exist;
- the summary counts match the rows.

It only reads: git rev-parse and git cat-file. It builds, runs and changes
nothing. Exit status: 0 when the inventory is consistent, 1 when problems were
found (listed on standard output), 2 when the check could not run.

Usage:
    python -I scripts/acceptance/check_inventory.py [--rev REV] [--repo DIR]
                                                     [--inventory FILE]
"""

import argparse
import os
import re
import subprocess
import sys
from collections import Counter, OrderedDict

SHORT = {"GPU-T01–GPU-T48": "GPU-T", "INT-01–INT-12": "INT", "VM-P01–VM-P50": "VM-P",
         "VM-CP-01–VM-CP-35": "VM-CP", "VM-R01–VM-R110": "VM-R"}
RANGES = [
    ("GPU-T01–GPU-T48", ["GPU-T%02d" % i for i in range(1, 49)]),
    ("INT-01–INT-12", ["INT-%02d" % i for i in range(1, 13)]),
    ("VM-P01–VM-P50", ["VM-P%02d" % i for i in range(1, 51)]),
    ("VM-CP-01–VM-CP-35", ["VM-CP-%02d" % i for i in range(1, 36)]),
    ("VM-R01–VM-R110", ["VM-R%02d" % i for i in range(1, 111)]),
]
EXPECTED = OrderedDict((i, name) for name, ids in RANGES for i in ids)
ID_RE = re.compile(r"^(?:GPU-T\d{2}|INT-\d{2}|VM-P\d{2}|VM-CP-\d{2}|VM-R\d{2,3})$")
VIA_ID_RE = re.compile(r"\b(?:GPU-T\d{2}|INT-\d{2}|VM-P\d{2}|VM-CP-\d{2}|VM-R\d{2,3})\b")
STATUSES = ["covered offline", "partially covered", "not covered", "needs hardware/host", "not applicable"]
EVIDENCE = {"host", "guest", "hardware", "offline fake/model", "benchmark", "release"}
DISPOSITIONS = {"Adopt", "Adapt", "Evaluate", "Reject", "Retain"}
TASK_RE = re.compile(r"\b(?:[HSGMUO]\d{2}|E0[1-5]Z?)\b")
TOP_LEVEL = ("src-tauri/", "cli/", "appliance/", "grid/", "scripts/", "docs/", "e2e/")
DEFAULT_BASE = "src-tauri/src/"
IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class Fatal(Exception):
    pass


def git(repo, *args, data=None):
    try:
        done = subprocess.run(["git", "-C", repo, *args], input=data, capture_output=True, check=False)
    except OSError as err:
        raise Fatal("cannot run git: %s" % err)
    return done


def resolve_repo(arg):
    if arg:
        start = arg
    else:
        start = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    done = git(start, "rev-parse", "--show-toplevel")
    if done.returncode != 0:
        raise Fatal("not a git repository: %s" % start)
    return done.stdout.decode("utf-8", "replace").strip()


def split_row(line):
    """Split a markdown table row on pipes outside code spans."""
    body = line.strip()
    if body.startswith("|"):
        body = body[1:]
    if body.endswith("|") and not body.endswith("\\|"):
        body = body[:-1]
    cells, cur, in_code, i = [], [], False, 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body) and body[i + 1] == "|":
            cur.append("|")
            i += 2
            continue
        if ch == "`":
            in_code = not in_code
        if ch == "|" and not in_code:
            cells.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
        i += 1
    cells.append("".join(cur).strip())
    return cells


def tables(lines):
    """Yield (header_cells, [(line_number, cells)]) for each markdown table."""
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.lstrip().startswith("|") and i + 1 < len(lines) and re.match(r"^\s*\|(\s*:?-{3,}:?\s*\|)+\s*$", lines[i + 1]):
            header = split_row(line)
            body = []
            j = i + 2
            while j < len(lines) and lines[j].lstrip().startswith("|"):
                body.append((j + 1, split_row(lines[j])))
                j += 1
            yield header, body
            i = j
        else:
            i += 1


def code_spans(cell):
    return re.findall(r"`([^`]+)`", cell)


def classify(span):
    """Return ('test', path, name), ('path', path, None) or None."""
    span = span.strip()
    if "::" in span:
        path, name = span.split("::", 1)
        return ("test", path.strip(), name.strip())
    if "/" in span or re.search(r"\.(rs|go|py|json|md|toml|ts|js)$", span):
        if " " in span:
            return None
        return ("path", span, None)
    return None


def repo_path(path):
    return path if path.startswith(TOP_LEVEL) else DEFAULT_BASE + path


def read_objects(repo, sha, paths):
    """Fetch type and content of each path at sha with one git cat-file --batch."""
    paths = sorted(set(paths))
    if not paths:
        return {}
    request = "".join("%s:%s\n" % (sha, p.rstrip("/")) for p in paths).encode("utf-8")
    done = git(repo, "cat-file", "--batch", data=request)
    if done.returncode != 0:
        raise Fatal("git cat-file failed: %s" % done.stderr.decode("utf-8", "replace").strip())
    out, pos, result = done.stdout, 0, {}
    for p in paths:
        end = out.index(b"\n", pos)
        head = out[pos:end].decode("utf-8", "replace")
        pos = end + 1
        if head.endswith(" missing") or head.endswith(" ambiguous"):
            result[p] = (None, None)
            continue
        _, kind, size = head.rsplit(" ", 2)
        size = int(size)
        body = out[pos:pos + size]
        pos += size + 1
        result[p] = (kind, body.decode("utf-8", "replace") if kind == "blob" else None)
    return result


def find_test(path, text, name):
    """Return (found, is_test, ignored)."""
    lines = text.splitlines()
    if path.endswith(".go"):
        rx = re.compile(r"^func\s+%s\s*\(" % re.escape(name))
        for line in lines:
            if rx.match(line):
                is_test = path.endswith("_test.go") and name.startswith(("Test", "Fuzz", "Benchmark", "Example"))
                return True, is_test, False
        return False, False, False
    if path.endswith(".py"):
        rx = re.compile(r"^\s*(?:async\s+)?def\s+%s\s*\(" % re.escape(name))
        for line in lines:
            if rx.match(line):
                return True, name.startswith("test"), False
        return False, False, False
    # A name can be defined more than once (for example a generic body and the
    # #[test] wrapper a macro generates); the reference holds if any is a test.
    rx = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+%s\s*[<(]" % re.escape(name))
    found, best = False, (False, False)
    for idx, line in enumerate(lines):
        if not rx.match(line):
            continue
        found = True
        attrs = []
        j = idx - 1
        while j >= 0:
            s = lines[j].strip()
            if s.startswith(("#[", "//")) or (s.endswith(("]", ")]")) and not s.endswith(("{", ";", "}"))):
                attrs.append(s)
                j -= 1
                continue
            break
        joined = "\n".join(attrs)
        is_test = bool(re.search(r"#\[(?:[a-z_]+::)?test\b|#\[test_case|#\[rstest", joined))
        ignored = "#[ignore" in joined
        if is_test and (not best[0] or (best[1] and not ignored)):
            best = (True, ignored)
    return found, best[0], best[1]


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description="Check the acceptance inventory, read-only.")
    parser.add_argument("--rev", default="HEAD", help="revision whose tests are checked (default HEAD)")
    parser.add_argument("--repo", default=None, help="repository root (default: the one holding this script)")
    parser.add_argument("--inventory", default=None, help="inventory file (default: <repo>/docs/acceptance-inventory.md)")
    args = parser.parse_args()

    repo = resolve_repo(args.repo)
    inv_path = args.inventory or os.path.join(repo, "docs", "acceptance-inventory.md")
    try:
        with open(inv_path, encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except OSError as err:
        raise Fatal("cannot read the inventory: %s" % err)
    done = git(repo, "rev-parse", "--verify", "--quiet", args.rev + "^{commit}")
    if done.returncode != 0:
        raise Fatal("unknown revision: %s" % args.rev)
    sha = done.stdout.decode().strip()

    problems, warnings = [], []
    rows = OrderedDict()  # id -> list of row dicts (duplicates kept)
    refs = []  # (line, id or None, kind, path, name)
    summary = None

    for header, body in tables(lines):
        lower = [h.lower() for h in header]
        if lower and lower[0] == "range":
            summary = (header, body)
            continue
        col = {}
        for k, h in enumerate(lower):
            if h == "id":
                col["id"] = k
            elif h == "status":
                col["status"] = k
            elif h == "evidence":
                col["evidence"] = k
            elif "coverage" in h or h == "model tests":
                col["coverage"] = k
            elif h.startswith("owner"):
                col["owner"] = k
            elif h.startswith("disposition"):
                col["disposition"] = k
        for line_no, cells in body:
            rid = cells[col["id"]] if "id" in col and col["id"] < len(cells) else None
            for k, cell in enumerate(cells):
                for span in code_spans(cell):
                    kind = classify(span)
                    if kind:
                        refs.append((line_no, rid, kind[0], kind[1], kind[2]))
            if "id" not in col or "status" not in col:
                continue
            if len(cells) != len(header):
                problems.append("line %d: row has %d cells, its table has %d columns" % (line_no, len(cells), len(header)))
                continue
            row = {"line": line_no, "id": rid, "status": cells[col["status"]],
                   "evidence": cells[col["evidence"]] if "evidence" in col else "",
                   "coverage": cells[col["coverage"]] if "coverage" in col else "",
                   "owner": cells[col["owner"]] if "owner" in col else "",
                   "disposition": cells[col["disposition"]] if "disposition" in col else None}
            rows.setdefault(rid, []).append(row)

    # IDs: each exactly once, none unexpected
    for rid, found in rows.items():
        if not ID_RE.match(rid or ""):
            problems.append("line %d: '%s' is not an acceptance ID" % (found[0]["line"], rid))
        elif rid not in EXPECTED:
            problems.append("line %d: %s is outside the five ranges" % (found[0]["line"], rid))
        if len(found) > 1:
            problems.append("%s appears %d times (lines %s)" % (rid, len(found), ", ".join(str(r["line"]) for r in found)))
    for name, ids in RANGES:
        missing = [i for i in ids if i not in rows]
        if missing:
            problems.append("%s: missing %s" % (name, ", ".join(missing)))

    # test and file references at the revision
    objects = read_objects(repo, sha, [repo_path(p) for _, _, _, p, _ in refs])
    tests_per_row = Counter()
    checked_tests, checked_paths = set(), set()
    for line_no, rid, kind, path, name in refs:
        where = "line %d%s" % (line_no, ", " + rid if rid else "")
        full = repo_path(path)
        otype, text = objects.get(full, (None, None))
        if otype is None:
            problems.append("%s: `%s` does not exist at %s" % (where, full, args.rev))
            continue
        if kind == "path":
            if path.endswith("/") and otype != "tree":
                problems.append("%s: `%s` is not a directory at %s" % (where, full, args.rev))
            checked_paths.add(full)
            continue
        if otype != "blob":
            problems.append("%s: `%s` is not a file at %s" % (where, full, args.rev))
            continue
        if not IDENT_RE.match(name):
            problems.append("%s: `%s::%s` does not name one function" % (where, path, name))
            continue
        found, is_test, ignored = find_test(full, text, name)
        if not found:
            problems.append("%s: test `%s` not found in `%s` at %s" % (where, name, full, args.rev))
            continue
        if not is_test:
            problems.append("%s: `%s` in `%s` is not marked as a test" % (where, name, full))
            continue
        checked_tests.add((full, name))
        if rid:
            tests_per_row[rid] += 1
            status = rows.get(rid, [{}])[0].get("status", "")
            if ignored:
                msg = "%s: test `%s` is marked #[ignore]" % (where, name)
                (problems if status == "covered offline" else warnings).append(msg)

    # row consistency
    counts = {name: Counter() for name, _ in RANGES}
    for rid, found in rows.items():
        r = found[0]
        where = "line %d, %s" % (r["line"], rid)
        status = r["status"]
        bucket = None
        if status in STATUSES[:4]:
            bucket = status
        elif re.match(r"^not applicable: \S", status):
            bucket = "not applicable"
        else:
            problems.append("%s: status '%s' is not one of: %s, or 'not applicable: <reason>'" % (where, status, ", ".join(STATUSES[:4])))
        if rid in EXPECTED and bucket:
            counts[EXPECTED[rid]][bucket] += 1
        kinds = [k.strip() for k in r["evidence"].split(" + ")] if r["evidence"] else []
        bad = [k for k in kinds if k not in EVIDENCE]
        if not kinds or bad:
            problems.append("%s: evidence '%s' must be kinds from: %s" % (where, r["evidence"], ", ".join(sorted(EVIDENCE))))
        n_tests = tests_per_row[rid]
        if bucket == "covered offline":
            if kinds != ["offline fake/model"]:
                problems.append("%s: covered offline, but its evidence needs more than offline fakes or models ('%s')" % (where, r["evidence"]))
            if n_tests == 0:
                problems.append("%s: covered offline without a verified test reference" % where)
        if bucket == "partially covered" and n_tests == 0:
            problems.append("%s: partially covered without a verified test reference" % where)
        if bucket == "not covered" and n_tests:
            problems.append("%s: not covered, yet it names %d test(s); update its status" % (where, n_tests))
        if bucket and bucket != "not applicable" and not TASK_RE.search(r["owner"]):
            problems.append("%s: no open task named as owner ('%s')" % (where, r["owner"]))
        via = re.search(r"\bvia ([^<]*)", r["coverage"])
        if via:
            for target in VIA_ID_RE.findall(via.group(1)):
                if target not in rows:
                    problems.append("%s: via %s, which is not in the inventory" % (where, target))
        if r["disposition"] is not None:
            parts = [p.strip() for p in r["disposition"].split(" + ")]
            if not parts or any(p not in DISPOSITIONS for p in parts):
                problems.append("%s: disposition '%s' is not from %s" % (where, r["disposition"], ", ".join(sorted(DISPOSITIONS))))

    # summary table
    if summary is None:
        problems.append("the summary table (first column 'Range') is missing")
    else:
        header, body = summary
        names = [h.lower() for h in header]
        stated = {cells[0]: cells for _, cells in body}
        total = Counter()
        for name, ids in RANGES:
            total.update(counts[name])
            cells = stated.get(name)
            if cells is None:
                problems.append("summary: no line for %s" % name)
                continue
            for s in STATUSES:
                if s in names:
                    got = cells[names.index(s)]
                    if got != str(counts[name][s]):
                        problems.append("summary: %s %s says %s, the rows give %d" % (name, s, got, counts[name][s]))
            if "total" in names and cells[names.index("total")] != str(len(ids)):
                problems.append("summary: %s total says %s, expected %d" % (name, cells[names.index("total")], len(ids)))
        cells = stated.get("All")
        if cells is not None:
            for s in STATUSES:
                if s in names and cells[names.index(s)] != str(total[s]):
                    problems.append("summary: All %s says %s, the rows give %d" % (s, cells[names.index(s)], total[s]))

    print("Inventory: %s" % inv_path)
    print("Revision:  %s (%s)" % (args.rev, sha))
    print("Rows:      %s" % ", ".join("%s %d/%d" % (SHORT[n], sum(1 for i in ids if i in rows), len(ids)) for n, ids in RANGES))
    print("Verified:  %d test functions, %d files or directories" % (len(checked_tests), len(checked_paths)))
    print("Status counts:")
    for name, _ in RANGES:
        print("  %-18s %s" % (name, ", ".join("%s %d" % (s, counts[name][s]) for s in STATUSES if counts[name][s])))
    if warnings:
        print("Warnings (%d):" % len(warnings))
        for w in warnings:
            print("  - " + w)
    if problems:
        print("Problems (%d):" % len(problems))
        for p in problems:
            print("  - " + p)
        print("FAILED")
        return 1
    print("OK: every ID of every range appears once, every status is allowed and every reference exists at %s." % args.rev)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Fatal as err:
        print("check_inventory: %s" % err, file=sys.stderr)
        sys.exit(2)
