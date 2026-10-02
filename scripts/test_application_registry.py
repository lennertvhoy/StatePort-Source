from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def test_public_safe_reference_application_is_not_studydd_hardcoded() -> None:
    root = ROOT / "fixtures/apps/synthetic-reference"
    descriptor = yaml.safe_load((root / "application.yaml").read_text(encoding="utf-8"))
    actions = yaml.safe_load((root / "actions.yaml").read_text(encoding="utf-8"))
    assert descriptor["formatVersion"] == "stateport.application/v1"
    assert descriptor["applicationId"] == "stateport.synthetic-reference"
    assert descriptor["applicationId"] != "studydd"
    assert descriptor["productionEligible"] is False
    assert actions["applicationId"] == descriptor["applicationId"]
    assert actions["actions"][0]["actionId"] == "synthetic.inspect-reference/v1"
    assert actions["actions"][0]["mutationPolicy"] == "none"
