"""Yougori's offline authoring SDK. Setup hooks execute only inside the VM."""
import json
import os
from pathlib import Path
import re
import subprocess


class Setup:
    def __init__(self, name, *, image, files, command):
        self.definition = {"version": 1, "name": name, "image": image,
                           "files": files, "command": command, "questions": [], "grids": []}
        self.hooks = []

    def input(self, name, question, *, type="text", **options):
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,23}", name):
            raise ValueError("Use a lowercase input name of at most 24 characters")
        if any(q["id"] == name for q in self.definition["questions"]):
            raise ValueError("Duplicate setup input: " + name)
        if type == "secret" and "default" in options:
            raise ValueError("Secret values never belong in a template")
        self.definition["questions"].append({**options, "id": name, "question": question, "type": type})
        return name

    def email(self, name="admin_email", question="Administrator email", **options):
        return self.input(name, question, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$", **options)

    def password(self, name="admin_password", question="Administrator password", **options):
        return self.input(name, question, type="secret", min_length=options.pop("min_length", 12), **options)

    def admin(self):
        return {"email": self.email(), "password": self.password()}

    def checkbox(self, name, question, *, default=False, **options):
        return self.input(name, question, type="yesno", default="yes" if default else "no", **options)

    def grid(self, kind, *, when=None):
        if kind not in ("gpu", "sandbox"):
            raise ValueError("Grid kind is gpu or sandbox (CPU and memory)")
        self.definition["grids"].append({"kind": kind, **({"when": when} if when else {})})
        return kind

    def on_setup(self, callback):
        self.hooks.append(callback)
        return callback

    def declare(self):
        directory = Path(".yougori")
        directory.mkdir(mode=0o700, exist_ok=True)
        target = directory / "setup.json"
        temporary = directory / "setup.json.tmp"
        temporary.write_text(json.dumps(self.definition, indent=2), encoding="utf-8")
        temporary.replace(target)

    def run(self, start):
        """Declare the install questions; after installation run hooks, then the app.

        Hooks must be idempotent (for example, create an admin only when absent).
        They run for each fresh installation/explicit reconfiguration, never during capture.
        Answers are private local files and are never part of the exported package.
        """
        self.declare()
        answer_file = Path(os.environ.get("YOUGORI_SETUP_FILE", ".yougori/answers.json"))
        if not answer_file.is_file():
            print("Setup declared. Select this VM and create a template in Yougori.")
            return False
        values = json.loads(answer_file.read_text(encoding="utf-8"))
        if not isinstance(values, dict):
            raise ValueError("Invalid setup answers")
        generation = values.get("_yougori_generation")
        launch = values.get("_yougori_launch")
        def converted(question):
            value = values.get(question["id"])
            kind = question["type"]
            if kind == "yesno":
                return value in (True, "yes", "true")
            if kind == "multichoice":
                return value if isinstance(value, list) else [item for item in (value or "").split(",") if item]
            if kind == "number" and value not in (None, ""):
                return float(value)
            return value
        values = {q["id"]: converted(q) for q in self.definition["questions"]}
        marker = Path(".yougori/initialized")
        if not generation or not marker.is_file() or marker.read_text() != generation:
            for hook in self.hooks:
                hook(values)
            if generation:
                marker.write_text(generation)
        grid = None
        if any(not item.get("when") or values.get(item["when"]) for item in self.definition["grids"]):
            grid = subprocess.Popen(["/run/yougori/bin/yougori-probe", "grid", "serve"])
        try:
            if launch:
                Path(".yougori/launch-ready").write_text(launch)
            return start(values)
        finally:
            if grid is not None:
                grid.terminate()
                try:
                    grid.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    grid.kill()
                    grid.wait()
