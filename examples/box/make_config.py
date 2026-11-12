#!/usr/bin/env python3
"""Writes a small resident composition for a development box.

    make_config.py <repo> <box-dir> [--base-url URL] [--key-file FILE]

It starts `conversation`, `model`, `projects`, `parent` (the chat agent that
owns the `sessions` endpoint) and `ui`, the UI on a development socket
(`<box-dir>/run/ui.sock`, labelled) rather than a platform link. It is derived
from deploy/vm/nucleus.json and keeps only what these services need:

- Project identities are off, so no spawn_as or stop_project grant remains.
- The programs directory is bound at /programs, so spawn grants name it.
- The chat agent may use the conversation, model and fs endpoints only: its
  repository scope is files, its tool bindings are the file tools, and it
  holds no project, session, approval, memory, web or shell authority.
- The UI keeps no deletion or archiving authority (its deletion workflow
  needs every service's stop grant) and no session `forget`.

Nothing else changes, and the VM's composition is not modified.

Authority: this composition is for one person on one machine. The socket's
owner window may do everything the granted services allow, and anyone who can
connect to the socket holds that. Keep the socket inside the box. The model
key is read from the key file and never written into the configuration.
"""
import argparse
import json
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
parser.add_argument("repo", type=Path)
parser.add_argument("box", type=Path)
parser.add_argument("--base-url", default="https://opencode.ai/inference/openai/v1",
                    help="OpenAI-compatible base URL; the adapter appends /chat/completions")
parser.add_argument("--key-file", type=Path, default=None,
                    help="API key file (default: <box>/secrets/model/key)")
options = parser.parse_args()

REPO = options.repo.resolve()
BOX = options.box.resolve()
KEY_FILE = (options.key_file or BOX / "secrets/model/key").resolve()
BIN = REPO / "target" / "debug"
SRC = json.loads((REPO / "deploy" / "vm" / "nucleus.json").read_text())
ARCHIVE = {"delete", "purge", "begin_archive", "archive", "unarchive", "forget"}
UI_ENDPOINTS = {"conversation", "projects", "files", "diffs", "sessions"}
PARENT_ENDPOINTS = {"conversation", "model", "fs"}
IDENTITY_ACTIONS = {"spawn_as", "stop_project"}


def without_identities(grants):
    return [g for g in grants if not (IDENTITY_ACTIONS & set(g["actions"]))]


def programs_dir(grants):
    for g in grants:
        if g["actions"] == ["spawn_executable"] and g["resource"] and g["resource"][0] == "executable" and len(g["resource"]) > 1:
            g["resource"] = ["executable", "programs"]
    return grants


def resolved(value):
    """A parameter takes its default here, since no platform values file exists;
    the VM's program paths name the box's programs directory instead."""
    if isinstance(value, dict) and "param" in value:
        return str(SRC["parameters"][value["param"]]["default"])
    if isinstance(value, str):
        return value.replace("/opt/nucleus/bin/", "/programs/")
    return value


def parent_args(args):
    """The chat agent's flags with the scopes, projects and tools narrowed."""
    return [resolved(a) for a in narrowed(args)]


def narrowed(args):
    out = []
    i = 0
    while i < len(args):
        flag = args[i]
        value = args[i + 1] if i + 1 < len(args) else None
        if flag in ("--repo-scope", "--project-scope", "--session-scope"):
            if flag == "--repo-scope" and value == "fs":
                out += [flag, value]
            i += 2
        elif flag == "--tool-bindings":
            bindings = [b for b in json.loads(value) if b["service"] == "fs"]
            out += [flag, json.dumps(bindings)]
            i += 2
        elif flag == "--projects":
            out += [flag, "/ws/projects"]
            i += 2
        elif flag == "--execution-context":
            context = json.loads(resolved(value))
            context["programs_dir"] = "/programs"
            out += [flag, json.dumps(context)]
            i += 2
        else:
            out.append(flag)
            i += 1
    return out


def program_of(name):
    return SRC["programs"][name]


programs = {
    "conversation": {
        "executable": str(BIN / "nucleus-conversation"),
        "args": ["--root", "/sessions", "--projects", "/ws/projects"],
        "binds": [
            {"host": str(BOX / "state/sessions"), "guest": "/sessions", "writable": True},
            {"host": str(BOX / "state/projects"), "guest": "/ws/projects", "writable": False},
        ],
    },
    "model": {
        "executable": str(BIN / "nucleus-openrouter"),
        "args": ["--base-url", options.base_url, "--key-file", "/model/key", "--max-timeout-ms", "3600000"],
        "binds": [{"host": str(KEY_FILE.parent), "guest": "/model", "writable": False}],
        "network": True,
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
    "parent": {
        "executable": str(BIN / "nucleus-chat-agent"),
        "args": parent_args(program_of("parent")["args"]),
        "binds": [
            {"host": str(BOX / "state/projects"), "guest": "/ws/projects", "writable": True},
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
        elif name == "model":
            yield {"program": name, "provides": "model", "grants": entry["grants"]}
        elif name == "projects":
            yield {"program": name, "provides": "projects",
                   "grants": programs_dir(without_identities(entry["grants"]))}
        elif name == "parent":
            grants = [g for g in without_identities(entry["grants"])
                      if g["endpoint"] == "kernel" or g["endpoint"] in PARENT_ENDPOINTS]
            yield {"program": name, "provides": "sessions", "grants": programs_dir(grants)}
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
