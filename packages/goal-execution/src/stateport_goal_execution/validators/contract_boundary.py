"""StatePort-owned confined validator: public-safe application contract boundary.

This single file runs INSIDE the bubblewrap sandbox, read-only, under
``/usr/bin/python3 -I`` against a read-only copy of the staged project. It
imports only the standard library and PyYAML (from the read-only system tree),
never project code, and re-checks the same rules as
``stateport_goal_execution.bootstrap._load_public_safe_fixture`` (a parity test
keeps the two in agreement). It prints one JSON line and exits 0 only when every
rule holds.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys

_SECRET_FIELD = re.compile(
    r"(?:api[_-]?key|authorization|cookie|credential|password|secret|access[_-]?token|refresh[_-]?token|private[_-]?key)",
    re.IGNORECASE,
)
_EXPECTED_FILES = ("actions.yaml", "application.yaml")
_MAX_FILE_BYTES = 64 * 1024


def _reject_secret_fields(value, location, depth=0, entries=None):
    entries = entries if entries is not None else [0]
    if depth > 32:
        raise ValueError(f"nested too deeply at {location}")
    if isinstance(value, dict):
        entries[0] += len(value)
        if entries[0] > 4096:
            raise ValueError("structural entry limit exceeded")
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{location} contains a non-string field")
            if _SECRET_FIELD.search(key):
                raise ValueError(f"credential-like field is forbidden at {location}.{key}")
            _reject_secret_fields(item, f"{location}.{key}", depth + 1, entries)
    elif isinstance(value, list):
        entries[0] += len(value)
        if entries[0] > 4096:
            raise ValueError("structural entry limit exceeded")
        for index, item in enumerate(value):
            _reject_secret_fields(item, f"{location}[{index}]", depth + 1, entries)


def check(root: str) -> dict:
    import yaml

    values = {}
    digest = hashlib.sha256()
    for name in _EXPECTED_FILES:
        path = os.path.join(root, name)
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"required file is unavailable or unsafe: {name}")
        if info.st_size <= 0 or info.st_size > _MAX_FILE_BYTES:
            raise ValueError(f"file exceeds the bounded size policy: {name}")
        with open(path, "rb") as handle:
            raw = handle.read()
        value = yaml.safe_load(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError(f"file must contain an object: {name}")
        _reject_secret_fields(value, name)
        values[name] = value
        digest.update(name.encode("utf-8") + b"\0" + raw + b"\0")
    application, actions = values["application.yaml"], values["actions.yaml"]
    if application.get("formatVersion") != "stateport.application/v1":
        raise ValueError("application contract format is unsupported")
    application_id = application.get("applicationId")
    if not isinstance(application_id, str) or actions.get("applicationId") != application_id:
        raise ValueError("application and action identities do not agree")
    if application.get("privacyClassification") != "public_safe" or application.get("productionEligible") is not False:
        raise ValueError("project must be public-safe and production-ineligible")
    if actions.get("formatVersion") != "stateport.application-action/v1" or not isinstance(actions.get("actions"), list):
        raise ValueError("action contract format is unsupported")
    if any(item.get("networkPolicy") != "disabled" for item in actions["actions"] if isinstance(item, dict)):
        raise ValueError("an action requests network access")
    return {
        "validator": "contract_boundary",
        "applicationId": application_id,
        "repositoryDigest": "sha256:" + digest.hexdigest(),
        "actionCount": len(actions["actions"]),
    }


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(json.dumps({"validator": "contract_boundary", "ok": False, "error": "usage: contract_boundary <root>"}))
        return 2
    try:
        result = check(argv[1])
    except Exception as exc:  # noqa: BLE001 - every failure is a typed validator failure
        print(json.dumps({"validator": "contract_boundary", "ok": False, "error": f"{type(exc).__name__}: {exc}"[:300]}))
        return 1
    print(json.dumps({**result, "ok": True}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
