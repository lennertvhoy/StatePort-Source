"""Atomic loading and identity binding for the execution-host contract."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any, Mapping


CONTRACT_PATH = Path(__file__).with_name("identity-contract.v1.json")
CONTRACT_FORMAT = "stateport.execution-host-identity-contract/v1"
_READ_CHUNK_BYTES = 64 * 1024


class IdentityContractError(RuntimeError):
    """The execution-host identity contract was unavailable or changed while read."""


def _atomic_read(path: Path) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise IdentityContractError("identity contract is missing or unsafe") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size < 1:
            raise IdentityContractError("identity contract is not a regular file")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, _READ_CHUNK_BYTES):
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (
            before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
        ):
            raise IdentityContractError("identity contract changed while being read")
        return b"".join(chunks)
    except OSError as exc:
        raise IdentityContractError("identity contract could not be read") from exc
    finally:
        os.close(descriptor)


def load_identity_contract(path: Path | str = CONTRACT_PATH) -> tuple[dict[str, Any], str]:
    """Read one stable contract and return its document plus content digest."""

    data = _atomic_read(Path(path))
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IdentityContractError("identity contract is not valid UTF-8 JSON") from exc
    if not isinstance(document, dict) or document.get("formatVersion") != CONTRACT_FORMAT:
        raise IdentityContractError("identity contract format is unsupported")
    if document.get("contractId") != "stateport-execution-host-identity":
        raise IdentityContractError("identity contract identifier is invalid")
    if not isinstance(document.get("identityFields"), list) or not all(
        isinstance(item, str) and item for item in document["identityFields"]
    ):
        raise IdentityContractError("identity contract identity fields are invalid")
    atomic_read = document.get("atomicRead")
    detector_scan = document.get("detectorScan")
    if not isinstance(atomic_read, Mapping) or atomic_read.get("required") is not True:
        raise IdentityContractError("identity contract does not require atomic reads")
    if not isinstance(detector_scan, Mapping) or detector_scan.get("required") is not True:
        raise IdentityContractError("identity contract does not require detector scanning")
    return document, "sha256:" + hashlib.sha256(data).hexdigest()
