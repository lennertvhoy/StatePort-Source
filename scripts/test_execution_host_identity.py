from __future__ import annotations

import json
from pathlib import Path
import stat
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
EXECUTION_HOST_SRC = ROOT / "packages/execution-host/src"
if str(EXECUTION_HOST_SRC) not in sys.path:
    sys.path.insert(0, str(EXECUTION_HOST_SRC))

from execution_host.identity_contract import (
    CONTRACT_PATH,
    IdentityContractError,
    load_identity_contract,
)


def test_identity_contract_is_public_schema_valid_and_detector_scannable() -> None:
    document, digest = load_identity_contract()
    schema = json.loads((ROOT / "schemas/identity-contract.v1.schema.json").read_text(encoding="utf-8"))
    assert document["formatVersion"] == "stateport.execution-host-identity-contract/v1"
    assert digest.startswith("sha256:")
    assert schema["properties"]["detectorScan"]["properties"]["required"]["const"] is True
    assert CONTRACT_PATH.is_file()


def test_identity_contract_rejects_symlink_and_unstable_read(tmp_path: Path) -> None:
    contract = tmp_path / "identity-contract.v1.json"
    contract.write_bytes(CONTRACT_PATH.read_bytes())
    link = tmp_path / "link.json"
    link.symlink_to(contract)
    with pytest.raises(IdentityContractError, match="missing or unsafe"):
        load_identity_contract(link)
    contract.chmod(stat.S_IRUSR | stat.S_IWUSR)
    document, digest = load_identity_contract(contract)
    assert document["contractId"] == "stateport-execution-host-identity"
    assert len(digest) == len("sha256:") + 64
