#!/usr/bin/env python3
"""Writes a small resident composition for a development box.

    make_config.py <repo> <box-dir>

It starts `conversation`, `projects` and `ui`, the UI on a development socket
(`<box-dir>/run/ui.sock`, labelled) rather than a platform link. It is derived
from deploy/vm/nucleus.json and keeps only what these three need: the grants
that stay are the VM's, minus project identities (identities off, so no
spawn_as or stop_project) and minus the UI's deletion and archive authority,
whose workflow needs every service's stop grant. Nothing else changes, and
the VM's composition is not modified.

Authority: this composition is for one person on one machine. The socket's
owner window may do everything the three services grant; anyone who can
connect to the socket holds that. Keep the socket inside the box.
"""
import json
import sys
from pathlib import Path

REPO = Path(sys.argv[1]).resolve()
BOX = Path(sys.argv[2]).resolve()
BIN = REPO / "target" / "debug"
SRC = json.loads((REPO / "deploy" / "vm" / "nucleus.json").read_text())
ARCHIVE = {"delete", "purge", "begin_archive", "archive", "unarchive"}
UI_ENDPOINTS = {"conversation", "projects", "files", "diffs"}

programs = {
    "conversation": {
        "executable": str(BIN / "nucleus-conversation"),
        "args": ["--root", "/sessions", "--projects", "/ws/projects"],
        "binds": [
            {"host": str(BOX / "state/sessions"), "guest": "/sessions", "writable": True},
            {"host": str(BOX / "state/projects"), "guest": "/ws/projects", "writable": False},
        ],
    },
    "projects": {
        "executable": str(BIN / "nucleus-projects"),
        "args": ["--root", "/ws/projects", "--home", "/ws/home", "--programs", "/programs",
                 "--jobs", "/jobs", "--identities", "off"],
        "binds": [
            {"host": str(BOX / "state/projects"), "guest": "/ws/projects", "writable": True},
            {"host": str(BOX / "state/home"), "guest": "/ws/home", "writable": True},
            {"host": str(BOX / "state/jobs"), "guest": "/jobs", "writable": True},
            {"host": str(BIN), "guest": "/programs", "writable": False},
        ],
    },
    "ui": {
        "executable": str(BIN / "nucleus-ui"),
        "args": ["--socket", "/run/ui/ui.sock", "--labelled"],
        "binds": [{"host": str(BOX / "run"), "guest": "/run/ui", "writable": True}],
    },
}


def boot_entries():
    for entry in SRC["boot"]:
        name = entry["program"]
        if name == "conversation":
            yield {"program": name, "provides": "conversation", "grants": entry["grants"]}
        elif name == "projects":
            grants = [g for g in entry["grants"] if not ({"spawn_as", "stop_project"} & set(g["actions"]))]
            for g in grants:
                # The programs directory is bound at /programs here.
                if g["actions"] == ["spawn_executable"]:
                    g["resource"] = ["executable", "programs"]
            yield {"program": name, "provides": "projects", "grants": grants}
        elif name == "ui":
            grants = [g for g in entry["grants"]
                      if g["endpoint"] in UI_ENDPOINTS and not (ARCHIVE & set(g["actions"]))]
            yield {"program": name, "grants": grants}


config = {
    "lifetime": "resident",
    "grace_ms": 3000,
    "ready_timeout_ms": 60000,
    "programs": programs,
    "boot": list(boot_entries()),
}
out = BOX / "config.json"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(config, indent=2) + "\n")
print(f"wrote {out} ({len(config['boot'])} boot entries)")
