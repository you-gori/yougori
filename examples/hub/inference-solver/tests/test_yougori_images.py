"""The Yougori harness's images: one base image in a few variants and a pack per harness, listed in
vm-images/yougori/image.json, checked and served by the website, and planned by the build script.

Run: python -I -B examples/hub/inference-solver/tests/test_yougori_images.py
"""
import argparse
import ast
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SITE = Path(__file__).resolve().parents[1] / "site"
sys.path.insert(0, str(SITE))
sys.path.insert(0, str(Path(__file__).resolve().parent))
# The launcher's own modules, for its preflight as launchers run it.
sys.path.append(str(SITE / "harnesses"))
import harness_download
from harness_download import INCOMPLETE, OWN_AGENT, STALE, UNPUBLISHED, UNREADABLE, YOUGORI
from artifact_fixture import RAW, publish_catalog_fixtures, unpublish_catalog_fixtures
import test_service
from server import NOT_OFFERED
import vm_host

loader = importlib.util.spec_from_file_location("build_vm_images", SITE.parent / "scripts/build-vm-images.py")
builder = importlib.util.module_from_spec(loader)
loader.loader.exec_module(builder)

SPECS = harness_download.catalog()
BASE, CHROMIUM, PACK, SHANNON = "a" * 64, "b" * 64, "c" * 64, "d" * 64
# What Containerfile.yougori's pack stage copies in: the installer and the adapter sources.
PACK_FILES = {"installer.py", "install_shannon.py", "install_pentagi.py", "pentagi_vm.go", "pentagi_vm_test.go"}


def listing(**changes):
    """An image.json with a base, a chromium variant, Yougori's own agent and two packs."""
    image = {"runtime": "yougori-sandbox-vm", "platform": "linux/amd64", "version": SPECS[YOUGORI]["version"],
             "bases": {"base": {"sha256": BASE, "bytes": 5, "disk": 2}, "chromium": {"sha256": CHROMIUM, "bytes": 6, "disk": 3}},
             "packs": {YOUGORI: {"base": "base", "disk": 2, "memory": 4},
                       "opencode": {"sha256": PACK, "bytes": 3, "version": SPECS["opencode"]["version"], "base": "base", "disk": 2, "memory": 4},
                       "shannon": {"sha256": SHANNON, "bytes": 4, "version": SPECS["shannon"]["version"], "base": "chromium", "disk": 3, "memory": 6}}}
    image.update(changes)
    return image


class Listing(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name) / YOUGORI
        self.folder.mkdir()
        patcher = patch.dict(os.environ, {"SOLVER_VM_IMAGES": self.temp.name})
        patcher.start()
        self.addCleanup(patcher.stop)

    def publish(self, image=None, files=(BASE, CHROMIUM, PACK, SHANNON)):
        (self.folder / "image.json").write_text(json.dumps(image or listing()))
        sizes = {BASE: 5, CHROMIUM: 6, PACK: 3, SHANNON: 4}
        for digest in files:
            suffix = ".zip" if digest in (BASE, CHROMIUM) else ".tar.gz"
            (self.folder / (digest + suffix)).write_bytes(b"x" * sizes[digest])

    def reason(self, name):
        return harness_download.held(name)["reason"]

    def test_a_harness_starts_once_its_base_and_pack_are_published(self):
        self.assertEqual(self.reason("opencode"), UNPUBLISHED)
        self.assertEqual(harness_download.held(YOUGORI), {"available": False, "reason": UNPUBLISHED, "version": SPECS[YOUGORI]["version"]})
        self.publish(files=())
        for name in (YOUGORI, "opencode", "shannon"):
            self.assertEqual(self.reason(name), INCOMPLETE, name)
        self.publish(files=(BASE,))
        self.assertEqual(harness_download.held(YOUGORI), {"available": True, "reason": "", "version": SPECS[YOUGORI]["version"]})
        self.assertEqual(self.reason("opencode"), INCOMPLETE)
        self.publish(files=(BASE, PACK))
        self.assertEqual(harness_download.held("opencode"), {"available": True, "reason": "", "version": SPECS["opencode"]["version"]})
        # Shannon needs the chromium base as well as its pack.
        self.assertEqual(self.reason("shannon"), INCOMPLETE)
        self.publish(files=(BASE, PACK, SHANNON))
        self.assertEqual(self.reason("shannon"), INCOMPLETE)
        self.publish()
        self.assertTrue(harness_download.held("shannon")["available"])
        # A file of another size is not the published one; a harness without a pack is not published.
        (self.folder / (PACK + ".tar.gz")).write_bytes(b"xx")
        self.assertEqual(self.reason("opencode"), INCOMPLETE)
        self.assertEqual(self.reason("kilo"), UNPUBLISHED)
        # Yougori's own agent has no image of its own: a launcher that starts each harness from its
        # own image cannot start it, whatever is published.
        self.assertEqual(harness_download.availability(YOUGORI), {"available": False, "reason": OWN_AGENT, "version": SPECS[YOUGORI]["version"]})
        self.assertEqual(harness_download.availability(YOUGORI, {"images": {YOUGORI: listing()}})["reason"], OWN_AGENT)

    def test_pins_newer_than_the_published_images_need_new_ones(self):
        self.publish(listing(version="0.0.1"))
        self.assertEqual(self.reason(YOUGORI), STALE)
        self.assertEqual(self.reason("opencode"), STALE)
        image = listing()
        image["packs"]["opencode"]["version"] = "0.0.1"
        self.publish(image)
        self.assertEqual(self.reason("opencode"), STALE)
        self.assertTrue(harness_download.held("shannon")["available"])
        specs = {**SPECS, "shannon": {**SPECS["shannon"], "blocked": "Awaiting validation"}}
        with patch.object(harness_download, "catalog", return_value=specs):
            self.assertEqual(harness_download.held("shannon"), {"available": False, "reason": "Awaiting validation", "version": SPECS["shannon"]["version"]})
        self.assertEqual(harness_download.held("nope"), {"available": False, "reason": UNPUBLISHED, "version": None})

    def test_a_listing_out_of_bounds_is_refused(self):
        def pack(**changes):
            image = listing()
            image["packs"]["opencode"].update(changes)
            return image
        def own(**changes):
            image = listing()
            image["packs"][YOUGORI].update(changes)
            return image
        def base(**changes):
            image = listing()
            image["bases"]["base"].update(changes)
            return image
        bad = [listing(runtime="other"), listing(platform="linux/arm64"), listing(version=""), listing(bases={}),
               listing(bases=[]), listing(packs=[]), base(sha256="A" * 64), base(bytes=0), base(bytes=(300 << 20) + 1),
               base(bytes=True), base(disk=9), base(disk=0), pack(base="postgres"), pack(base=None), pack(disk=3),
               pack(memory=2), pack(memory=1025), pack(sha256="e"), pack(bytes=(512 << 20) + 1), pack(version=""),
               pack(version=None), own(sha256=PACK), own(version="1"), own(memory=2)]
        image = listing()
        image["bases"]["Bad Name"] = image["bases"]["base"]
        bad.append(image)
        image = listing()
        del image["packs"]["opencode"]["sha256"]
        bad.append(image)
        for value in bad:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    harness_download.yougori_image(value)
                self.publish(value)
                self.assertEqual(self.reason("opencode"), UNREADABLE)
        (self.folder / "image.json").write_text("[1]")
        self.assertEqual(self.reason(YOUGORI), UNREADABLE)

    def test_files_and_the_listing_as_the_website_finds_them(self):
        self.assertIsNone(harness_download.vm_image(YOUGORI))
        self.publish()
        self.assertEqual(harness_download.vm_image(YOUGORI), listing())
        self.assertEqual(harness_download.vm_image(YOUGORI, BASE), self.folder / (BASE + ".zip"))
        self.assertEqual(harness_download.vm_image(YOUGORI, PACK, "tool"), self.folder / (PACK + ".tar.gz"))
        self.assertIsNone(harness_download.vm_image(YOUGORI, PACK))
        for digest, kind in ((BASE.upper(), None), ("../image", None), (BASE, "image")):
            with self.assertRaises(ValueError):
                harness_download.vm_image(YOUGORI, digest, kind)

    def test_only_the_offered_harnesses_packs_and_their_bases_are_handed_out(self):
        shown = harness_download.offered_image(listing(), {"opencode", "kilo"})
        self.assertEqual(set(shown["packs"]), {"opencode"})
        self.assertEqual(set(shown["bases"]), {"base"})
        shown = harness_download.offered_image(listing(), {"shannon", YOUGORI})
        self.assertEqual((set(shown["packs"]), set(shown["bases"])), ({"shannon", YOUGORI}, {"base", "chromium"}))
        self.assertEqual(harness_download.offered_image(listing(), set())["packs"], {})

    def test_a_hosted_instance_checks_the_listing_it_was_given(self):
        published = {"base": "http://127.0.0.1:9/api/inference/artifacts", "images": {YOUGORI: listing()}}
        self.assertTrue(harness_download.held("opencode", published)["available"])
        self.assertTrue(harness_download.held("shannon", published)["available"])
        self.assertEqual(harness_download.held("kilo", published)["reason"], UNPUBLISHED)
        self.assertEqual(harness_download.held("opencode", {"images": {}})["reason"], UNPUBLISHED)
        self.assertEqual(harness_download.held("opencode", {"images": {YOUGORI: listing(version="0")}})["reason"], STALE)
        self.assertEqual(harness_download.held("opencode", {"images": {YOUGORI: {"bad": True}}})["reason"], UNREADABLE)
        self.assertEqual(harness_download.held("opencode", {"images": []})["reason"], UNREADABLE)

    def test_catalog_fixtures_publish_and_unpublish_as_the_administrator_would(self):
        publish_catalog_fixtures(self.temp.name)
        names = [name for name in SPECS if not SPECS[name].get("blocked")]
        # Every harness but Yougori's own agent also has its own image.
        own = [name for name in names if name != YOUGORI]
        self.assertTrue(all(harness_download.held(name)["available"] for name in names))
        self.assertTrue(all(harness_download.availability(name)["available"] for name in own))
        unpublish_catalog_fixtures(self.temp.name, ["strix", "aider"])
        self.assertEqual([name for name in names if not harness_download.held(name)["available"]], ["aider", "strix"])
        self.assertEqual([name for name in own if not harness_download.availability(name)["available"]], ["aider", "strix"])
        self.assertTrue(harness_download.held(YOUGORI)["available"])
        unpublish_catalog_fixtures(self.temp.name)
        self.assertEqual({harness_download.held(name)["reason"] for name in names}, {UNPUBLISHED})
        self.assertEqual({harness_download.availability(name)["reason"] for name in own}, {UNPUBLISHED})


class Website(unittest.TestCase):
    """What /api/harnesses and /api/harness-image/yougori say and serve."""

    def setUp(self):
        patcher = patch.dict(os.environ)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.flow = test_service.Flow()
        self.flow.setUp()
        self.addCleanup(self.flow.tearDown)
        self.folder = self.flow.temp.name
        publish_catalog_fixtures(self.folder)
        self.digest = hashlib.sha256(RAW).hexdigest()

    def download(self, path):
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", self.flow.web.server_port, timeout=10)
        try:
            conn.request("GET", path)
            response = conn.getresponse()
            return response.status, response.read()
        finally:
            conn.close()

    def listed(self):
        return {h["id"]: h for h in self.flow.call("/api/harnesses")[1]["harnesses"]}

    def images(self, name):
        """A harness's own image.json, or the Yougori harness's listing, as published here."""
        return Path(self.folder) / "catalog-images" / name / "image.json"

    def test_setup_is_each_harness_own_image_and_held_says_it_starts_inside_yougori(self):
        listed = self.listed()
        others = set(listed) - {YOUGORI}
        self.assertTrue(all(listed[name]["setup"]["available"] and listed[name]["held"]["available"] for name in others),
                        {name: (listed[name]["setup"], listed[name]["held"]) for name in others})
        # Yougori's own agent has no image of its own: only a launcher that starts harnesses inside
        # the Yougori harness starts it.
        self.assertEqual(listed[YOUGORI]["setup"], {"available": False, "reason": OWN_AGENT, "version": SPECS[YOUGORI]["version"]})
        self.assertEqual(listed[YOUGORI]["held"], {"available": True, "reason": "", "version": SPECS[YOUGORI]["version"]})
        # A harness's pack missing from the Yougori harness's images: its own image still starts.
        image = json.loads(self.images(YOUGORI).read_text())
        del image["packs"]["aider"]
        self.images(YOUGORI).write_text(json.dumps(image))
        listed = self.listed()
        self.assertTrue(listed["aider"]["setup"]["available"])
        self.assertEqual(listed["aider"]["held"], {"available": False, "reason": UNPUBLISHED, "version": SPECS["aider"]["version"]})
        self.assertEqual(self.flow.call("/api/harness-image/aider")[1]["sha256"], self.digest)
        self.assertEqual(self.download("/api/harness-image/aider/" + self.digest), (200, RAW))
        # A harness's own image older than its pin needs updating, whatever the Yougori harness's
        # images hold: launchers that start it check no version of their own.
        own = json.loads(self.images("opencode").read_text())
        own["version"] = "1.0.0-old"
        self.images("opencode").write_text(json.dumps(own))
        listed = self.listed()
        self.assertEqual(listed["opencode"]["setup"], {"available": False, "reason": STALE, "version": SPECS["opencode"]["version"]})
        self.assertTrue(listed["opencode"]["held"]["available"])
        # Before the Yougori harness's images are published, each harness starts from its own as before.
        self.images(YOUGORI).unlink()
        listed = self.listed()
        self.assertEqual({name for name in others if listed[name]["setup"]["available"]}, others - {"opencode"})
        self.assertEqual({h["held"]["reason"] for h in listed.values()}, {UNPUBLISHED})

    def test_launchers_that_start_a_harness_from_its_own_image_check_it_as_before(self):
        """The launcher's preflight reads `setup` alone, as Yougori 1.2.4's does."""
        with patch.object(vm_host, "ready") as ready:
            vm_host.preflight("opencode", self.flow.url)
            self.images(YOUGORI).unlink()
            vm_host.preflight("opencode", self.flow.url)
            own = json.loads(self.images("opencode").read_text())
            own["version"] = "1.0.0-old"
            self.images("opencode").write_text(json.dumps(own))
            with self.assertRaises(ValueError) as refused:
                vm_host.preflight("opencode", self.flow.url)
            self.assertEqual(str(refused.exception), STALE)
            # Yougori's own agent stops here, before any sign-in, model or question, even with
            # everything published.
            publish_catalog_fixtures(self.folder)
            with self.assertRaises(ValueError) as refused:
                vm_host.preflight(YOUGORI, self.flow.url)
            self.assertEqual(str(refused.exception), OWN_AGENT)
        self.assertEqual(ready.call_count, 4)

    def test_a_blocked_harness_pack_and_a_base_only_it_needs_are_neither_listed_nor_served(self):
        folder = self.images(YOUGORI).parent
        base, pack = b"chromium base fixture", b"shannon pack fixture"
        chromium, shannon = hashlib.sha256(base).hexdigest(), hashlib.sha256(pack).hexdigest()
        (folder / (chromium + ".zip")).write_bytes(base)
        (folder / (shannon + ".tar.gz")).write_bytes(pack)
        image = json.loads(self.images(YOUGORI).read_text())
        image["bases"]["chromium"] = {"sha256": chromium, "bytes": len(base), "disk": 3}
        image["packs"]["shannon"].update(sha256=shannon, bytes=len(pack), base="chromium", disk=3, memory=6)
        self.images(YOUGORI).write_text(json.dumps(image))

        def served():
            listing = self.flow.call("/api/harness-image/yougori")[1]
            return ("shannon" in listing["packs"], "chromium" in listing["bases"],
                    self.download("/api/harness-image/yougori/" + chromium)[0],
                    self.download("/api/harness-image/yougori/" + shannon + "/tool")[0])
        self.assertEqual(served(), (True, True, 200, 200))
        blocked = {**SPECS, "shannon": {**SPECS["shannon"], "blocked": "Awaiting validation"}}
        with patch.object(harness_download, "catalog", return_value=blocked):
            self.assertEqual(served(), (False, False, 404, 404))
            self.assertEqual(self.listed()["shannon"]["held"]["reason"], "Awaiting validation")
            # The others still start inside the Yougori harness, from the base they share.
            self.assertEqual(self.download("/api/harness-image/yougori/" + self.digest + "/tool"), (200, RAW))
        # With the Yougori harness itself blocked, or out of the catalogue, none of its images.
        for specs in ({**SPECS, YOUGORI: {**SPECS[YOUGORI], "blocked": "Awaiting validation"}},
                      {name: spec for name, spec in SPECS.items() if name != YOUGORI}):
            with patch.object(harness_download, "catalog", return_value=specs):
                self.assertEqual(self.flow.call("/api/harness-image/yougori")[0], 404)
                self.assertEqual(self.download("/api/harness-image/yougori/" + self.digest)[0], 404)
                self.assertFalse(self.listed()["opencode"]["held"]["available"])

    def test_the_images_list_and_serve_only_what_offered_harnesses_need(self):
        status, image, _ = self.flow.call("/api/harness-image/yougori")
        self.assertEqual(status, 200)
        self.assertEqual(set(image["packs"]), set(SPECS))
        self.assertEqual(self.download("/api/harness-image/yougori/" + self.digest), (200, RAW))
        self.assertEqual(self.download("/api/harness-image/yougori/" + self.digest + "/tool"), (200, RAW))
        self.assertEqual(self.download("/api/harness-image/yougori/" + "e" * 64)[0], 404)
        self.assertEqual(self.download("/api/harness-image/yougori/" + self.digest + "/other")[0], 400)
        # Yougori's own agent hidden: the others still start inside the Yougori harness.
        self.assertEqual(self.flow.call("/api/admin/choices", {"home": "harnesses", "harnesses": ["strix", "pi"]}, self.flow.admin)[0], 200)
        image = self.flow.call("/api/harness-image/yougori")[1]
        self.assertEqual((set(image["packs"]), set(image["bases"])), ({"strix", "pi"}, {"base"}))
        self.assertEqual(self.download("/api/harness-image/yougori/" + self.digest + "/tool"), (200, RAW))
        self.assertEqual(self.flow.call("/api/harness-image/aider")[1]["error"]["message"], NOT_OFFERED)
        # A listing without the offered harnesses' packs serves none of its files.
        unpublish_catalog_fixtures(self.folder, ["strix", "pi"])
        code, body, _ = self.flow.call("/api/harness-image/yougori")
        self.assertEqual((code, body["error"]["message"]), (404, NOT_OFFERED))
        self.assertEqual(self.download("/api/harness-image/yougori/" + self.digest)[0], 404)
        unpublish_catalog_fixtures(self.folder)
        self.assertEqual(self.flow.call("/api/harness-image/yougori")[0], 404)

    def test_a_hosted_instance_hands_out_the_listing_with_its_publisher(self):
        published = {"base": "http://127.0.0.1:9/api/inference/artifacts", "images": {YOUGORI: listing()}}
        self.flow.service.hosted = {"authority": "127.0.0.1:%d" % self.flow.web.server_port, "artifacts": published}
        code, image, _ = self.flow.call("/api/harness-image/yougori")
        self.assertEqual(code, 200, image)
        self.assertEqual((image["download_base"], set(image["packs"])), (published["base"], {YOUGORI, "opencode", "shannon"}))
        self.assertEqual(self.flow.call("/api/harness-image/yougori/" + BASE)[0], 404)
        listed = self.listed()
        self.assertEqual((listed["opencode"]["held"]["available"], listed["kilo"]["held"]["reason"]), (True, UNPUBLISHED))
        # This instance's publisher lists no harness's own image: launchers that start one are told so.
        self.assertEqual((listed["opencode"]["setup"]["reason"], listed[YOUGORI]["setup"]["reason"]), (UNPUBLISHED, OWN_AGENT))
        blocked = {**SPECS, "shannon": {**SPECS["shannon"], "blocked": "Awaiting validation"}}
        with patch.object(harness_download, "catalog", return_value=blocked):
            image = self.flow.call("/api/harness-image/yougori")[1]
            self.assertEqual((set(image["packs"]), set(image["bases"])), ({YOUGORI, "opencode"}, {"base"}))
        # A publisher that lists only each harness's own image, as one from before the Yougori harness.
        own = {"sha256": BASE, "bytes": 5, "version": SPECS["opencode"]["version"], "runtime": "yougori-sandbox-vm", "platform": "linux/amd64"}
        self.flow.service.hosted["artifacts"] = {"base": published["base"], "images": {"opencode": own}}
        listed = self.listed()
        self.assertEqual((listed["opencode"]["setup"]["available"], listed["opencode"]["held"]["reason"]), (True, UNPUBLISHED))
        self.assertEqual(self.flow.call("/api/harness-image/yougori")[0], 404)


class Build(unittest.TestCase):
    """The build script's own checks, without Buildah."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def pack(self, members):
        path = self.root / "pack.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            for name, kind, target in members:
                info = tarfile.TarInfo(name)
                if kind == "dir":
                    info.type = tarfile.DIRTYPE
                    archive.addfile(info)
                elif kind == "link":
                    info.type = tarfile.SYMTYPE
                    info.linkname = target
                    archive.addfile(info)
                elif kind == "fifo":
                    info.type = tarfile.FIFOTYPE
                    archive.addfile(info)
                else:
                    info.size = len(target)
                    archive.addfile(info, io.BytesIO(target))
        return path

    def test_a_pack_holds_tool_and_source_only(self):
        path = self.pack([("tool", "dir", None), ("tool/bin/app", "file", b"OK"), ("source/LICENSE", "file", b"MIT"),
                          ("tool/bin/link", "link", "app")])
        measured = builder.check_pack(path)
        self.assertEqual((measured["entries"], measured["unpacked"], measured["bytes"]), (4, 5, path.stat().st_size))
        self.assertEqual(measured["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
        for bad in ([("other/app", "file", b"x")], [("tool/../escape", "file", b"x")], [("/tool/app", "file", b"x")],
                    [("tool/link", "link", "/etc/passwd")], [("tool/link", "link", "../../etc/passwd")], [("tool/fifo", "fifo", None)]):
            with self.subTest(bad=bad), self.assertRaises((ValueError, tarfile.TarError)):
                builder.check_pack(self.pack(bad))
        with patch.object(builder, "PACK_EXPANDED", 4), self.assertRaises(ValueError):
            builder.check_pack(self.pack([("tool/a", "file", b"12345")]))
        with patch.object(builder, "PACK_ENTRIES", 1), self.assertRaises(ValueError):
            builder.check_pack(self.pack([("tool/a", "file", b"1"), ("tool/b", "file", b"2")]))

    def layout(self, members):
        """An OCI layout of one gzip layer holding `members` (name, bytes)."""
        blobs = self.root / "layout/blobs/sha256"
        blobs.mkdir(parents=True, exist_ok=True)
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w") as archive:
            for name, data in members:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        layer = gzip.compress(raw.getvalue())
        (blobs / hashlib.sha256(layer).hexdigest()).write_bytes(layer)
        manifest = json.dumps({"layers": [{"digest": "sha256:" + hashlib.sha256(layer).hexdigest()}]}).encode()
        (blobs / hashlib.sha256(manifest).hexdigest()).write_bytes(manifest)
        (self.root / "layout/index.json").write_text(json.dumps({"manifests": [{"digest": "sha256:" + hashlib.sha256(manifest).hexdigest()}]}))
        return self.root / "layout", len(raw.getvalue())

    def test_an_image_within_yougoris_import_bounds(self):
        folder, expanded = self.layout([("opt/a", b"12345"), ("opt/b", b"")])
        measured = builder.layout_size(folder, "The base")
        self.assertEqual((measured["entries"], measured["files"], measured["expanded"]), (2, 5, expanded))
        for limit, value in (("IMAGE_ENTRIES", 1), ("IMAGE_FILE", 4), ("IMAGE_EXPANDED", 100), ("IMAGE_BYTES", 10)):
            with self.subTest(limit=limit), patch.object(builder, limit, value), self.assertRaises(ValueError):
                builder.layout_size(folder, "The base")

    def test_the_plan_gives_each_harness_root_and_memory_for_its_base(self):
        gib = 1 << 30
        bases = {"base": {"sha256": BASE, "bytes": 5, "files": gib // 2, "entries": 7000},
                 "chromium": {"sha256": CHROMIUM, "bytes": 6, "files": gib // 2, "entries": 7000}}
        packs = {"opencode": {"sha256": PACK, "bytes": 3, "unpacked": gib // 4, "entries": 20},
                 "swe": {"sha256": "e" * 64, "bytes": 3, "unpacked": gib + gib // 4, "entries": 30000},
                 "shannon": {"sha256": SHANNON, "bytes": 4, "unpacked": gib + gib // 3, "entries": 35000}}
        image = builder.plan("1.2.5", SPECS, {"shannon": "chromium"}, bases, packs, {"shannon": 6})
        harness_download.yougori_image(image)
        self.assertEqual({name: (pack["disk"], pack["memory"]) for name, pack in image["packs"].items()},
                         {YOUGORI: (2, 4), "opencode": (2, 4), "swe": (3, 4), "shannon": (3, 6)})
        self.assertEqual({name: base["disk"] for name, base in image["bases"].items()}, {"base": 3, "chromium": 3})
        self.assertEqual(image["packs"]["swe"]["version"], SPECS["swe"]["version"])
        packs["swe"]["unpacked"] = 8 * gib
        with self.assertRaises(ValueError):
            builder.plan("1.2.5", SPECS, {"shannon": "chromium"}, bases, packs, {"shannon": 6})

    def test_a_harness_own_image_is_packaged_as_before(self):
        # Buildah stands in: `buildah mount` gives a folder holding the image's tool archive.
        mounted = self.root / "mounted"
        (mounted / "opt/solver").mkdir(parents=True)
        tool = b"tool archive"
        (mounted / "opt/solver/tool.tar.gz").write_bytes(tool)
        calls = []

        def check_output(argv, text=True):
            calls.append(argv)
            if argv[:2] == ["buildah", "inspect"]:
                return json.dumps({"OCIv1": {"config": {"Env": ["TOOL_SPEC=" + json.dumps(SPECS["gemini"])]}}})
            if argv[:2] == ["buildah", "from"]:
                return "container\n"
            if argv[:2] == ["buildah", "mount"]:
                return str(mounted) + "\n"
            raise AssertionError(argv)

        def run(argv, check=True, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0)

        def package(flat, temp, destination, name):
            calls.append(["package", flat, name])
            destination.mkdir(parents=True, exist_ok=True)
            (destination / ("f" * 64 + ".zip")).write_bytes(b"zip")
            return {"sha256": "f" * 64, "bytes": 3, "compressed": 3, "expanded": 9, "entries": 1, "files": 1}

        args = argparse.Namespace(output=self.root / "out", draft=False, split_tools=True, reuse_tools=True)
        args.output.mkdir()
        with patch.object(subprocess, "check_output", check_output), patch.object(subprocess, "run", run), \
                patch.object(builder, "package_image", package), patch.object(sys, "stdout", io.StringIO()):
            builder.harness_image(args, SPECS, "gemini")
            with self.assertRaisesRegex(ValueError, "no image of its own"):
                builder.harness_image(args, SPECS, YOUGORI)
        digest = hashlib.sha256(tool).hexdigest()
        self.assertEqual(json.loads((args.output / "gemini/image.json").read_text()),
                         {"sha256": "f" * 64, "bytes": 3, "version": SPECS["gemini"]["version"], "platform": "linux/amd64",
                          "runtime": "yougori-sandbox-vm", "tool": {"sha256": digest, "bytes": len(tool)}})
        self.assertEqual((args.output / "gemini" / (digest + ".tar.gz")).read_bytes(), tool)
        self.assertEqual(json.loads((mounted / "opt/solver/tool-package.json").read_text()), {"sha256": digest, "bytes": len(tool)})
        self.assertFalse((mounted / "opt/solver/tool.tar.gz").exists())
        self.assertIn(["buildah", "commit", "--squash", "--format", "oci", "container", "localhost/inference-solver-vm-gemini-flat"], calls)
        self.assertEqual(calls[-1], ["package", "localhost/inference-solver-vm-gemini-flat", "gemini"])

    def test_every_build_uses_the_layer_cache_and_leaves_no_working_container(self):
        # Buildah stands in. Without --force-rm, Buildah 1.33 leaves the node stage's working
        # container behind on each build.
        calls = []

        def run(argv, check=True, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0)

        def check_output(argv, text=True):
            calls.append(argv)
            return "container\n"

        def package(flat, temp, destination, name):
            destination.mkdir(parents=True, exist_ok=True)
            return {"sha256": "f" * 64, "bytes": 3, "compressed": 3, "expanded": 9, "entries": 1, "files": 1}
        args = argparse.Namespace(output=self.root / "out", draft=False, split_tools=False, reuse_tools=False)
        args.output.mkdir()
        with patch.object(subprocess, "run", run), patch.object(subprocess, "check_output", check_output), \
                patch.object(builder, "package_image", package), patch.object(sys, "stdout", io.StringIO()):
            builder.build("pack", "localhost/yougori-pack-gemini", {"HARNESS": "gemini"})
            builder.harness_image(args, SPECS, "gemini")
        builds = [argv for argv in calls if argv[:2] == ["buildah", "bud"]]
        self.assertEqual(len(builds), 2)
        for argv in builds:
            self.assertTrue({"--layers", "--force-rm"} <= set(argv), argv)

    def test_the_yougori_images_are_built_alone_with_the_harness_binary(self):
        for argv in (["yougori", "--output", str(self.root)], ["yougori", "pi", "--output", str(self.root), "--binary", "x"],
                     ["yougori", "--output", str(self.root), "--binary", "x", "--split-tools"], ["pi", "--output", str(self.root), "--binary", "x"]):
            with self.subTest(argv=argv), patch.object(sys, "argv", ["build-vm-images.py", *argv]), \
                    patch.object(sys, "stderr", io.StringIO()), self.assertRaises(SystemExit):
                builder.main()
        binary = self.root / "yougori-harness"
        binary.write_bytes(b"MZ not an ELF")
        with self.assertRaisesRegex(ValueError, "not a Linux x86-64 executable"):
            builder.check_binary(binary, "1.2.5")
        # --rebuild builds packs, which --reuse-tools never does, and only the Yougori harness has packs.
        for argv in (["yougori", "--output", str(self.root), "--binary", "x", "--reuse-tools", "--rebuild", "pi"],
                     ["pi", "--output", str(self.root), "--rebuild", "pi"]):
            with self.subTest(argv=argv), patch.object(sys, "argv", ["build-vm-images.py", *argv]), \
                    patch.object(sys, "stderr", io.StringIO()), self.assertRaises(SystemExit):
                builder.main()
        # It names harnesses with a pack, before anything is built.
        for names in (["yougori"], ["pi", "nope"]):
            args = argparse.Namespace(output=self.root, binary=self.root / "missing", rebuild=names, reuse_tools=False)
            with self.subTest(names=names), self.assertRaisesRegex(ValueError, "--rebuild names no pack built here"):
                builder.yougori_images(args, SPECS)

    def context(self):
        """A copy of the pack stage's build context: Containerfile.yougori and the files it copies."""
        root = self.root / "context"
        root.mkdir()
        for name in PACK_FILES | {"Containerfile.yougori"}:
            shutil.copyfile(SITE / "harnesses" / name, root / name)
        return root

    def test_a_pack_is_known_by_the_pack_stage_and_the_files_it_copies(self):
        inputs = builder.pack_stage()
        self.assertEqual(set(inputs["files"]), PACK_FILES)
        self.assertEqual(inputs["files"]["pentagi_vm.go"], hashlib.sha256((SITE / "harnesses/pentagi_vm.go").read_bytes()).hexdigest())
        root = self.context()
        self.assertEqual(builder.pack_stage(root), inputs)
        containerfile = root / "Containerfile.yougori"
        text = containerfile.read_text(encoding="utf-8")
        # Comments, blank lines, layout, line endings and the other stages are not what a pack is built from.
        self.assertEqual(text.count("WORKDIR /opt/solver\nCOPY installer.py"), 1)
        moved = (text.replace("WORKDIR /opt/solver\nCOPY installer.py", "WORKDIR   /opt/solver\n# Its installer.\n\nCOPY installer.py")
                 + "\nFROM runtime AS later\nRUN true\n")
        containerfile.write_text(moved.replace("\n", "\r\n"), encoding="utf-8", newline="")
        self.assertEqual(builder.pack_stage(root), inputs)
        # A changed step of the pack stage: every pack is built from something else.
        self.assertEqual(text.count("golang-go && rm -rf /var/lib/apt/lists/*; fi"), 1)
        containerfile.write_text(text.replace("golang-go && rm -rf", "golang-go gcc && rm -rf"), encoding="utf-8", newline="")
        changed = builder.pack_stage(root)
        self.assertNotEqual(changed["containerfile"], inputs["containerfile"])
        self.assertEqual(changed["files"], inputs["files"])
        # An installer or adapter fix: that file is.
        containerfile.write_text(text, encoding="utf-8", newline="")
        (root / "pentagi_vm.go").write_bytes((root / "pentagi_vm.go").read_bytes() + b"\n// A fix.\n")
        changed = builder.pack_stage(root)
        self.assertEqual(changed["containerfile"], inputs["containerfile"])
        self.assertEqual({name for name in PACK_FILES if changed["files"][name] != inputs["files"][name]}, {"pentagi_vm.go"})
        # A file it copies that is not there, or a Containerfile without the stage, is not built from a guess.
        (root / "install_pentagi.py").unlink()
        with self.assertRaisesRegex(ValueError, "install_pentagi.py"):
            builder.pack_stage(root)
        containerfile.write_text(text.replace(" AS pack\n", " AS packs\n"), encoding="utf-8", newline="")
        with self.assertRaisesRegex(ValueError, "no pack stage"):
            builder.pack_stage(root)

    def test_a_pack_is_kept_or_reused_only_when_built_from_the_same(self):
        folder = self.root / "out"
        folder.mkdir()
        path = self.pack([("tool/bin/app", "file", b"OK")])
        measured = builder.check_pack(path)
        path.replace(folder / (measured["sha256"] + ".tar.gz"))
        spec, stage = SPECS["gemini"], ["sha256:" + "1" * 64]
        inputs = builder.pack_inputs(builder.pack_stage(), spec["kind"])
        previous = {"packs": {"gemini": {**measured, "pins": spec, "from": stage, "inputs": inputs, "origin": "localhost/yougori-pack-gemini"}}}
        own = {"pins": spec, "layers": stage + ["sha256:" + "2" * 64], "installer": True}
        looked = []

        def same_installer(image, files):
            looked.append((image, files))
            return own["installer"]

        def reuse(current, known=previous):
            return builder.reuse_pack("gemini", spec, stage, current, folder, known)
        taken = ({"sha256": "f" * 64, "bytes": 1, "entries": 1, "unpacked": 1})
        with patch.object(builder, "pins", lambda image: own["pins"]), patch.object(builder, "layers", lambda image: own["layers"]), \
                patch.object(builder, "same_installer", same_installer), patch.object(builder, "take_pack", lambda image, into: taken):
            # Built from all the same: kept from this output.
            self.assertEqual(reuse(inputs), (measured, "localhost/yougori-pack-gemini", "kept"))
            self.assertEqual(looked, [])
            # An installer or adapter fix: not kept, and the harness's own image gives the pack only
            # when it installed the harness from the fixed files.
            fixed = {**inputs, "files": {**inputs["files"], "installer.py": "0" * 64}}
            own["installer"] = False
            self.assertIsNone(reuse(fixed))
            self.assertEqual(looked, [("localhost/inference-solver-vm-gemini", fixed["files"])])
            own["installer"] = True
            self.assertEqual(reuse(fixed), (taken, "localhost/inference-solver-vm-gemini", "reused"))
            # The pack stage changed since this output's last pack: it is built, whatever the
            # harness's own image holds.
            looked.clear()
            self.assertIsNone(reuse({**inputs, "containerfile": "0" * 64}))
            self.assertEqual(looked, [])
            # No pack here yet: the harness's own image when it has these pins, this OS and these files.
            self.assertEqual(reuse(inputs, {})[2], "reused")
            own["pins"] = {**spec, "version": "0.0.1"}
            self.assertIsNone(reuse(inputs, {}))
            own["pins"], own["layers"] = spec, ["sha256:" + "3" * 64]
            self.assertIsNone(reuse(inputs, {}))
            # Another build OS, or a record naming a file outside the output, keeps nothing.
            self.assertIsNone(reuse(inputs, {"packs": {"gemini": {**previous["packs"]["gemini"], "from": own["layers"]}}}))
            self.assertIsNone(reuse(inputs, {"packs": {"gemini": {**previous["packs"]["gemini"], "sha256": "../" + measured["sha256"]}}}))
            self.assertIsNone(reuse(inputs, {"packs": []}))

    def test_a_harness_own_image_is_checked_for_the_installer_files(self):
        # Buildah stands in: `buildah mount` gives a folder holding the image's /opt/solver.
        mounted = self.root / "mounted"
        (mounted / "opt/solver").mkdir(parents=True)
        files = builder.pack_stage()["files"]
        for name in files:
            shutil.copyfile(SITE / "harnesses" / name, mounted / "opt/solver" / name)
        calls = []

        def check_output(argv, text=True):
            calls.append(argv)
            return {"from": "container\n", "mount": str(mounted) + "\n"}[argv[1]]

        def run(argv, check=False, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0)
        image = "localhost/inference-solver-vm-pentagi"
        with patch.object(subprocess, "check_output", check_output), patch.object(subprocess, "run", run):
            self.assertTrue(builder.same_installer(image, files))
            (mounted / "opt/solver/pentagi_vm.go").write_bytes(b"// The adapter before its fix.\n")
            self.assertFalse(builder.same_installer(image, files))
            (mounted / "opt/solver/pentagi_vm.go").unlink()
            self.assertFalse(builder.same_installer(image, files))
            try:
                (mounted / "opt/solver/pentagi_vm.go").symlink_to(SITE / "harnesses/pentagi_vm.go")
            except OSError:
                pass  # This account may not make links; the other checks stand.
            else:
                self.assertFalse(builder.same_installer(image, files))
        self.assertIn(["buildah", "from", "--pull=never", image], calls)
        # Each look removes the container it made.
        self.assertEqual(sum(argv[:2] == ["buildah", "from"] for argv in calls), sum(argv[:2] == ["buildah", "rm"] for argv in calls))

    def test_named_packs_are_built_again_and_reuse_tools_builds_none(self):
        found = {"sha256": "e" * 64, "bytes": 1, "entries": 1, "unpacked": 1}
        inputs = {"containerfile": "1" * 64, "files": {"installer.py": "2" * 64}}
        stages = {"os": ["sha256:" + "1" * 64], "os-chromium": ["sha256:" + "2" * 64]}
        calls = []

        def reuse(name, spec, base_layers, current, folder, previous):
            calls.append(("reuse", name))
            return (found, "localhost/inference-solver-vm-" + name, "reused")

        def build(name, spec, stage, base_layers, folder):
            calls.append(("build", name, stage))
            return (found, "localhost/yougori-pack-" + name, "built")
        with patch.object(builder, "reuse_pack", reuse), patch.object(builder, "build_pack", build), patch.object(sys, "stdout", io.StringIO()):
            packs = builder.make_packs(["gemini", "shannon"], SPECS, {"shannon": "chromium"}, stages, inputs, self.root, {}, {"shannon"}, False)
            self.assertEqual(calls, [("reuse", "gemini"), ("build", "shannon", "os-chromium")])
            self.assertEqual({name: (pack["how"], pack["from"], pack["inputs"], pack["pins"]) for name, pack in packs.items()},
                             {"gemini": ("reused", stages["os"], inputs, SPECS["gemini"]),
                              "shannon": ("built", stages["os-chromium"], inputs, SPECS["shannon"])})
        with patch.object(builder, "reuse_pack", lambda *args: None), patch.object(builder, "build_pack", build), \
                patch.object(sys, "stdout", io.StringIO()), self.assertRaisesRegex(ValueError, "without --reuse-tools"):
            builder.make_packs(["gemini"], SPECS, {}, stages, inputs, self.root, {}, set(), True)

    def builds(self, built, fail=None):
        """build_pack as Buildah does it: a new pack in the output, checked. `fail` stops the build."""
        def build(name, spec, stage, base_layers, folder):
            built.append(name)
            if name == fail:
                raise subprocess.CalledProcessError(1, ["buildah", "bud"])
            path = self.pack([("tool/" + name, "file", f"{name} {len(built)}".encode())])
            measured = builder.check_pack(path)
            path.replace(folder / (measured["sha256"] + ".tar.gz"))
            return measured, "localhost/yougori-pack-" + name, "built"
        return build

    def test_each_pack_is_recorded_as_soon_as_it_is_in_the_output(self):
        # Buildah stands in, and no harness's own image gives a pack. A build that stops partway keeps
        # the packs it made: build.json records each as the finished build records it, and the next
        # build keeps them.
        folder = self.root / "out"
        folder.mkdir()
        names, stages, inputs = ["gemini", "pi", "opencode"], {"os": ["sha256:" + "1" * 64]}, builder.pack_stage()
        built, written, write = [], [], builder.write_json

        def recorded(path, value):
            write(path, value)
            written.append(json.loads(path.read_text(encoding="utf-8")))
        with patch.object(builder, "pins", lambda image: None), patch.object(builder, "write_json", recorded), \
                patch.object(sys, "stdout", io.StringIO()):
            with patch.object(builder, "build_pack", self.builds(built, fail="opencode")), self.assertRaises(subprocess.CalledProcessError):
                builder.make_packs(names, SPECS, {}, stages, inputs, folder, {}, set(), False)
            stopped = json.loads((folder / "build.json").read_text(encoding="utf-8"))
            self.assertEqual((built, [set(record["packs"]) for record in written]), (names, [{"gemini"}, {"gemini", "pi"}]))
            self.assertEqual(stopped, written[-1])
            self.assertEqual(sorted(path.name for path in folder.iterdir()),
                             sorted(["build.json", *(stopped["packs"][name]["sha256"] + ".tar.gz" for name in ("gemini", "pi"))]))
            built.clear()
            written.clear()
            with patch.object(builder, "build_pack", self.builds(built)):
                packs = builder.make_packs(names, SPECS, {}, stages, inputs, folder, stopped, set(), False)
        self.assertEqual(built, ["opencode"])
        self.assertEqual({name: pack["how"] for name, pack in packs.items()}, {"gemini": "kept", "pi": "kept", "opencode": "built"})
        for name in ("gemini", "pi"):
            self.assertEqual({key: value for key, value in packs[name].items() if key not in ("how", "seconds")},
                             {key: value for key, value in stopped["packs"][name].items() if key not in ("how", "seconds")})
        # From the first record on, each pack's is the one the finished build gives it.
        for count, record in enumerate(written, 1):
            self.assertEqual({name: record["packs"][name] for name in names[:count]}, {name: packs[name] for name in names[:count]})
        self.assertEqual(written[-1]["packs"], packs)
        # A record is written whole or not at all: one that fails while it is written leaves the last.
        before = (folder / "build.json").read_bytes()
        with patch.object(builder.os, "fsync", side_effect=OSError("No space left on device")), self.assertRaises(OSError):
            builder.write_json(folder / "build.json", {"packs": {}})
        self.assertEqual((folder / "build.json").read_bytes(), before)
        self.assertFalse((folder / "build.json.partial").exists())

    def test_a_fix_to_one_harness_install_rebuilds_its_pack_alone(self):
        # Buildah stands in, and no harness's own image gives a pack. A pack is known by the files its
        # install reads: installer.py for every harness, a kind's own helper and adapter for that kind.
        root, folder = self.context(), self.root / "out"
        folder.mkdir()
        names, variants = ["gemini", "shannon", "pentagi"], {"shannon": "chromium", "pentagi": "postgres"}
        stages = {"os": ["sha256:" + "1" * 64], "os-chromium": ["sha256:" + "2" * 64]}
        built = []

        def build():
            built.clear()
            previous = json.loads((folder / "build.json").read_text(encoding="utf-8")) if (folder / "build.json").exists() else {}
            packs = builder.make_packs(names, SPECS, variants, stages, builder.pack_stage(root), folder, previous, set(), False)
            return list(built), packs
        with patch.object(builder, "pins", lambda image: None), patch.object(builder, "build_pack", self.builds(built)), \
                patch.object(sys, "stdout", io.StringIO()):
            made, packs = build()
            self.assertEqual(made, names)
            self.assertEqual({name: set(pack["inputs"]["files"]) for name, pack in packs.items()},
                             {"gemini": {"installer.py"}, "shannon": {"installer.py", "install_shannon.py"},
                              "pentagi": {"installer.py", "install_pentagi.py", "pentagi_vm.go", "pentagi_vm_test.go"}})
            self.assertEqual(build()[0], [])
            for changed, rebuilt in (("pentagi_vm.go", ["pentagi"]), ("pentagi_vm_test.go", ["pentagi"]), ("install_pentagi.py", ["pentagi"]),
                                     ("install_shannon.py", ["shannon"]), ("installer.py", names)):
                (root / changed).write_bytes((root / changed).read_bytes() + b"\n")
                with self.subTest(changed=changed):
                    self.assertEqual(build()[0], rebuilt)
            # A changed step of the pack stage changes every pack.
            containerfile = root / "Containerfile.yougori"
            text = containerfile.read_text(encoding="utf-8")
            self.assertEqual(text.count("golang-go && rm -rf"), 1)
            containerfile.write_text(text.replace("golang-go && rm -rf", "golang-go gcc && rm -rf"), encoding="utf-8", newline="")
            self.assertEqual(build()[0], names)

    def test_files_kept_out_of_a_pack_inputs_are_read_by_one_kind_install_alone(self):
        # A pack is not built again for a change to a file KIND_FILES gives to another kind, so only
        # that kind's install may read it: installer.py imports a kind's helper only in that kind's
        # branch, and a helper names only its own kind's files. A file named anywhere else is read by
        # every harness's install.
        harnesses, copied = SITE / "harnesses", set(builder.pack_stage()["files"])
        modules = {PurePosixPath(name).stem: name for name in copied if name.endswith(".py")}
        named = {}  # A copied file: the kinds whose branch names it, None for outside any one kind's.

        def visit(node, kind):
            if isinstance(node, ast.If):
                test, branch = node.test, kind
                if (isinstance(test, ast.Compare) and [type(op) for op in test.ops] == [ast.Eq] and ast.unparse(test.left) == "spec['kind']"
                        and isinstance(test.comparators[0], ast.Constant)):
                    branch = test.comparators[0].value
                visit(test, kind)
                for child in node.body:
                    visit(child, branch)
                for child in node.orelse:
                    visit(child, kind)
                return
            if isinstance(node, ast.ImportFrom):
                found = [node.module or ""]
            elif isinstance(node, ast.Import):
                found = [alias.name for alias in node.names]
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                found = [PurePosixPath(node.value).name]
            else:
                found = []
            for item in found:
                file = modules.get(item) or (item if item in copied else None)
                if file:
                    named.setdefault(file, set()).add(kind)
            for child in ast.iter_child_nodes(node):
                visit(child, kind)
        visit(ast.parse((harnesses / "installer.py").read_text(encoding="utf-8")), None)
        # What a kind's helper names, that kind's install reads.
        for file, kinds in list(named.items()):
            if file.endswith(".py") and len(kinds) == 1 and None not in kinds:
                visit(ast.parse((harnesses / file).read_text(encoding="utf-8")), next(iter(kinds)))
        alone = {}
        for file, kinds in named.items():
            if len(kinds) == 1 and None not in kinds:
                alone.setdefault(next(iter(kinds)), set()).add(file)
        self.assertEqual(alone, builder.KIND_FILES)
        self.assertTrue(set().union(*builder.KIND_FILES.values()) < copied)
        self.assertTrue({kind for kind in builder.KIND_FILES} <= {spec.get("kind") for spec in SPECS.values()})

    def test_the_pack_stage_gives_pentagis_adapter_tests_their_work_folder(self):
        # install_pentagi.py runs the adapter's Go tests in the pack stage as the VM's user, and they
        # work in /work, which that user cannot make in /. The stage makes it for node first, as the
        # per-harness Containerfile does.
        self.assertIn('os.MkdirTemp("/work"', (SITE / "harnesses/pentagi_vm_test.go").read_text(encoding="utf-8"))
        steps = builder.stage_instructions(builder.ROOT, "pack")
        self.assertTrue(any(step.startswith("RUN python3 installer.py") for step in steps[steps.index("USER 1000:1000"):]), steps)
        commands = [command.split() for step in steps[:steps.index("USER 1000:1000")] if step.startswith("RUN ") for command in step[4:].split("&&")]
        self.assertIn(True, [words[:2] == ["mkdir", "-p"] and "/work" in words for words in commands], commands)
        self.assertIn(True, [words[:3] == ["chown", "-R", "node:node"] and "/work" in words for words in commands], commands)
        with self.assertRaisesRegex(ValueError, "no nope stage"):
            builder.stage_instructions(builder.ROOT, "nope")

    def test_packages_name_the_variants_the_containerfile_builds(self):
        entry = SPECS[YOUGORI]
        self.assertEqual(entry["kind"], YOUGORI)
        self.assertTrue(set(entry["bases"]) <= set(builder.VARIANTS) - {"base"})
        self.assertTrue(all(name in SPECS and name != YOUGORI for names in entry["bases"].values() for name in names))
        containerfile = (SITE / "harnesses/Containerfile.yougori").read_text()
        for stage in builder.VARIANTS.values():
            self.assertIn(" AS " + stage + "\n", containerfile)
        # The per-harness images and the Yougori harness's start from the same pinned OS.
        own = (SITE / "harnesses/Containerfile").read_text()
        for line in containerfile.splitlines():
            if line.startswith("FROM docker.io/"):
                self.assertIn(line.split(" AS ")[0].split("@sha256:")[1], own)


if __name__ == "__main__":
    unittest.main()
