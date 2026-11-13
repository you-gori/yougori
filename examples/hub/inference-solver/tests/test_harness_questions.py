"""The harness catalogue's questions, which `yougori inference run` asks before a harness starts:
each one a question the CLI can ask, the owner's security questions in the owner's words, and the
website listing them with Yougori's own agent."""
import json
from pathlib import Path
import re
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_service

SITE = HERE.parent / "site"
CATALOG = json.loads((SITE / "harnesses.json").read_text(encoding="utf-8"))
PACKAGES = json.loads((SITE / "harnesses/packages.json").read_text(encoding="utf-8"))
TYPES = {"text", "choice", "confirm", "folder", "secret", "list", "target"}
CHECKS = {"url", "host", "target", "path", "text"}
FIELDS = {"id", "type", "question", "note", "required", "placeholder", "validate", "choices", "default", "must",
          "refusal", "when", "workspace", "reach"}
SECURITY = ["target", "permission", "off_limits", "depth", "login_user", "login_password", "source", "focus"]
ID = re.compile(r"[a-z][a-z0-9_]{0,31}")
VALUE = re.compile(r"[A-Za-z0-9_-]{1,64}")


def words(value):
    return isinstance(value, str) and 0 < len(value.strip()) <= 300 and not any(ord(c) < 32 for c in value)


class Catalogue(unittest.TestCase):
    def test_every_harness_has_questions_and_a_vm_size(self):
        ids = [harness["id"] for harness in CATALOG]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(ids[0], "yougori")
        # Yougori holds every harness its launcher can start.
        self.assertEqual(set(ids) - {"yougori"}, set(PACKAGES) - {"yougori"})
        for harness in CATALOG:
            for key in ("id", "name", "mark", "category", "interface", "description", "source", "protocol"):
                self.assertTrue(words(harness[key]), (harness["id"], key))
            self.assertIn(harness["category"], ("coding", "security"))
            self.assertIsInstance(harness["questions"], list)
            security = harness["category"] == "security"
            self.assertEqual(harness["size"], {"cpu": 4, "memory": 8} if security else {"cpu": 2, "memory": 4}, harness["id"])
        yougori = CATALOG[0]
        self.assertEqual((yougori["name"], yougori["category"], yougori["questions"]), ("Yougori", "coding", []))

    def test_every_question_is_one_the_cli_can_ask(self):
        for harness in CATALOG:
            asked = []
            for question in harness["questions"]:
                where = harness["id"] + "." + str(question.get("id"))
                self.assertLessEqual(set(question), FIELDS, where)
                self.assertTrue(ID.fullmatch(question["id"]), where)
                self.assertNotIn(question["id"], [q["id"] for q in asked], where)
                self.assertIn(question["type"], TYPES, where)
                self.assertTrue(words(question["question"]), where)
                for key in ("note", "placeholder", "refusal"):
                    if key in question:
                        self.assertTrue(words(question[key]), where + " " + key)
                for key in ("required", "must", "workspace"):
                    self.assertIsInstance(question.get(key, False), bool, where + " " + key)
                if "validate" in question:
                    self.assertIn(question["validate"], CHECKS, where)
                choices = question.get("choices", [])
                values = [choice["value"] for choice in choices]
                self.assertEqual(len(values), len(set(values)), where)
                for choice in choices:
                    self.assertLessEqual(set(choice), {"value", "label", "note"}, where)
                    self.assertTrue(VALUE.fullmatch(choice["value"]) and words(choice["label"]), where)
                    self.assertTrue(words(choice.get("note", "x")), where)
                if question["type"] == "choice":
                    self.assertTrue(choices, where)
                    self.assertIn(question.get("default", values[0]), values, where)
                if question["type"] == "target":
                    self.assertIn("practice", values, where)
                    self.assertTrue(any(value != "practice" for value in values), where)
                if question.get("must"):
                    # Nothing starts without the yes: never a default, always the refusal's words.
                    self.assertEqual(question["type"], "confirm", where)
                    self.assertTrue(question["required"] and words(question["refusal"]), where)
                    self.assertNotIn("default", question, where)
                if (question["type"] in ("folder", "target", "secret") or "reach" in question
                        or question.get("validate") in ("path", "target")):
                    # No answer chosen in advance for a secret or for what the VM gets or reaches:
                    # `yougori inference run` takes a harness with one for not ready (takes_default).
                    self.assertNotIn("default", question, where)
                if "when" in question:
                    when = question["when"]
                    self.assertIn(set(when), ({"id", "present"}, {"id", "not"}), where)
                    self.assertIn(when["id"], [q["id"] for q in asked], where + ": a condition names an earlier question")
                    self.assertIsInstance(when.get("present", True), bool, where)
                # A folder reaches the VM only as its workspace copy, once.
                self.assertEqual(question["type"] == "folder", question.get("workspace", False), where)
                if "reach" in question:
                    self.assertEqual((question["type"], question["reach"]), ("target", "targets"), where)
                asked.append(question)
            self.assertLessEqual(sum(bool(q.get("workspace")) for q in asked), 1, harness["id"])

    def test_security_harnesses_ask_the_owners_questions(self):
        security = [harness for harness in CATALOG if harness["category"] == "security"]
        self.assertEqual({harness["id"] for harness in security}, {"strix", "shannon", "pentagi", "pentestgpt", "hexstrike"})
        for harness in security:
            asked = {question["id"]: question for question in harness["questions"]}
            self.assertEqual([question["id"] for question in harness["questions"]], SECURITY, harness["id"])
            self.assertEqual({key: question["question"] for key, question in asked.items()}, {
                "target": "What should it test?",
                "permission": "Do you own this target or have written permission to test it?",
                "off_limits": "What is off limits?",
                "depth": "How far may it go?",
                "login_user": "Login for the test?",
                "login_password": "Password for that login?",
                "source": "Source code?",
                "focus": "Focus?",
            })
            self.assertEqual({key: question["type"] for key, question in asked.items()}, {
                "target": "target", "permission": "confirm", "off_limits": "list", "depth": "choice",
                "login_user": "text", "login_password": "secret", "source": "folder", "focus": "text"})
            target = asked["target"]
            self.assertTrue(target["required"])
            self.assertEqual((target["validate"], target["reach"]), ("target", "targets"))
            self.assertEqual([choice["label"] for choice in target["choices"]], ["A practice app inside the VM", "A website or address I give"])
            # Permission first: a must-yes for any target but the practice app inside the VM.
            permission = asked["permission"]
            self.assertTrue(permission["must"] and permission["required"])
            self.assertEqual(permission["when"], {"id": "target", "not": "practice"})
            depth = asked["depth"]
            self.assertEqual([(c["value"], c["label"]) for c in depth["choices"]],
                             [("look", "Look only"), ("safe", "Test safely"), ("full", "Full exploitation")])
            self.assertEqual(depth["default"], "safe")
            self.assertEqual(asked["login_password"]["when"], {"id": "login_user", "present": True})
            self.assertFalse(asked["login_user"]["required"] or asked["off_limits"]["required"] or asked["focus"]["required"])
            self.assertTrue(asked["source"]["workspace"])
            # Shannon's engine reads the source code; the others can do without it.
            self.assertEqual(asked["source"]["required"], harness["id"] == "shannon", harness["id"])

    def test_coding_harnesses_ask_only_what_they_need(self):
        for harness in CATALOG:
            if harness["category"] == "coding":
                expected = ["issue"] if harness["id"] == "swe" else []
                self.assertEqual([question["id"] for question in harness["questions"]], expected, harness["id"])
        issue = next(harness for harness in CATALOG if harness["id"] == "swe")["questions"][0]
        self.assertEqual((issue["type"], issue["question"], issue["required"]), ("text", "What should SWE-agent fix?", True))


class Listing(unittest.TestCase):
    """The website lists the questions as the catalogue has them; Yougori's own agent waits for its
    launcher package without breaking the list, and the Admin can offer or hide it."""

    def setUp(self):
        self.flow = test_service.Flow()
        self.flow.setUp()
        self.addCleanup(self.flow.tearDown)

    def test_the_website_passes_the_questions_through(self):
        status, listed, _ = self.flow.call("/api/harnesses")
        self.assertEqual(status, 200)
        self.assertEqual([harness["id"] for harness in listed["harnesses"]], [harness["id"] for harness in CATALOG])
        for harness, entry in zip(listed["harnesses"], CATALOG):
            self.assertEqual((harness["questions"], harness["size"]), (entry["questions"], entry["size"]), harness["id"])
            self.assertTrue(harness["offered"])
        yougori = listed["harnesses"][0]
        if "yougori" not in PACKAGES:
            self.assertEqual(yougori["setup"], {"available": False, "version": None,
                                                "reason": "The administrator has not published this harness's Sandbox VM image yet."})

    def test_the_admin_offers_or_hides_yougori(self):
        choice = {"home": "harnesses", "harnesses": ["yougori", "strix"]}
        status, body, _ = self.flow.call("/api/admin/choices", choice, self.flow.admin)
        self.assertEqual(status, 200, body)
        listed = {harness["id"]: harness for harness in self.flow.call("/api/harnesses")[1]["harnesses"]}
        self.assertEqual({name for name, harness in listed.items() if harness["offered"]}, {"yougori", "strix"})
        self.assertEqual(self.flow.call("/api/admin/choices", {"home": "harnesses", "harnesses": ["pi"]}, self.flow.admin)[0], 200)
        listed = {harness["id"]: harness for harness in self.flow.call("/api/harnesses")[1]["harnesses"]}
        self.assertFalse(listed["yougori"]["offered"])
        self.assertEqual(listed["yougori"]["setup"]["reason"], "The administrator of this inference has not offered this harness.")


if __name__ == "__main__":
    unittest.main()
