from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts/prepare_provider_runtime_context.py"
spec = importlib.util.spec_from_file_location("prepare_provider_runtime_context", MODULE_PATH)
assert spec and spec.loader
producer = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = producer
spec.loader.exec_module(producer)


def _digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _inputs(tmp_path: Path) -> tuple[Path, Path]:
    payload = tmp_path / "payload"
    payload.mkdir()
    for name in producer.ARTIFACTS:
        path = payload / name
        path.write_bytes((name + " executable bytes\n").encode("utf-8"))
        path.chmod(0o755)
    for name in producer.LICENSES:
        (payload / name).write_text(name + " text\n", encoding="utf-8")
    metadata = {
        "formatVersion": producer.FORMAT,
        "version": "codex-cli 0.146.0+stateport.3",
        "bubblewrapVersion": "bubblewrap 0.12.0",
        "ripgrepVersion": "ripgrep 14.1.1",
        "source": {
            "repository": "https://github.com/openai/codex",
            "commit": "e363b08c9175ac1cbe5893615dd2cb9ddf95043b",
            "sourceArchiveDigest": "sha256:" + "a" * 64,
            "buildContextDigest": "sha256:" + "b" * 64,
        },
        "artifacts": {
            producer.ARTIFACT_METADATA_KEYS[name]: {"digest": _digest(payload / name)}
            for name in producer.ARTIFACTS
        },
        "licenses": list(producer.LICENSES),
    }
    metadata_path = tmp_path / "provider-metadata.json"
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    return metadata_path, payload


@pytest.mark.parametrize("ripgrep_version", ["ripgrep 14.1.1", "ripgrep 15.2.0 (rev e89fff89ac)"])
def test_prepares_fixed_scratch_context_for_both_current_consumers(tmp_path: Path, ripgrep_version: str) -> None:
    metadata, payload = _inputs(tmp_path)
    supplied = json.loads(metadata.read_text())
    supplied["ripgrepVersion"] = ripgrep_version
    metadata.write_text(json.dumps(supplied))
    output = tmp_path / "context"
    result = producer.prepare_context(metadata, payload, output)

    assert result["formatVersion"] == "stateport.provider-runtime-metadata/v1"
    assert result["payload"] == list(producer.PAYLOAD)
    assembled_metadata = json.loads((output / "provider-metadata.json").read_text(encoding="utf-8"))
    assert assembled_metadata["ripgrepVersion"] == ripgrep_version
    assert set(assembled_metadata["artifacts"]) == {"codex", "bubblewrap", "ripgrep"}
    assert (output / "Containerfile").read_text(encoding="utf-8") == "\n".join(
        ["FROM scratch", *(f"COPY {name} /out/{name}" for name in producer.PAYLOAD), ""]
    )
    for name in producer.ARTIFACTS:
        assert (output / name).read_bytes() == (payload / name).read_bytes()
        assert stat.S_IMODE((output / name).stat().st_mode) == 0o555
    for name in ("provider-metadata.json", *producer.LICENSES):
        assert stat.S_IMODE((output / name).stat().st_mode) == 0o444

    for recipe in (ROOT / "apps/web/Dockerfile", ROOT / "images/stateport-dev-workspace/Containerfile"):
        contract = recipe.read_text(encoding="utf-8")
        assert "FROM ${STATEPORT_PROVIDER_IMAGE} AS stateport-provider" in contract
        assert "source=/out,target=/provider-input,readonly" in contract
        assert "/provider-input/provider-metadata.json" in contract
        assert "a.codex?.digest" in contract
        assert "a.bubblewrap?.digest" in contract
        assert "a.ripgrep?.digest" in contract
        for name in producer.ARTIFACTS:
            assert f"/provider-input/{name}" in contract
        for name in producer.LICENSES:
            assert name in contract


@pytest.mark.parametrize("mutation, expected", [
    ("digest", "digest differs"),
    ("schema", "formatVersion"),
    ("extra-payload", "exactly the provider artifacts and licenses"),
])
def test_refuses_normal_metadata_and_payload_drift(tmp_path: Path, mutation: str, expected: str) -> None:
    metadata, payload = _inputs(tmp_path)
    if mutation == "digest":
        value = json.loads(metadata.read_text(encoding="utf-8"))
        value["artifacts"]["codex"]["digest"] = "sha256:" + "0" * 64
        metadata.write_text(json.dumps(value), encoding="utf-8")
    elif mutation == "schema":
        value = json.loads(metadata.read_text(encoding="utf-8"))
        value["formatVersion"] = "stateport.provider-runtime-metadata/v0"
        metadata.write_text(json.dumps(value), encoding="utf-8")
    else:
        (payload / "unrelated.txt").write_text("not a provider payload\n", encoding="utf-8")

    with pytest.raises(producer.ProviderContextError, match=expected):
        producer.prepare_context(metadata, payload, tmp_path / "context")


def test_refuses_existing_output_before_copying(tmp_path: Path) -> None:
    metadata, payload = _inputs(tmp_path)
    output = tmp_path / "context"
    output.mkdir()
    with pytest.raises(producer.ProviderContextError, match="absent absolute path"):
        producer.prepare_context(metadata, payload, output)


def test_copies_the_bytes_that_were_bound_to_metadata(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    metadata, payload = _inputs(tmp_path)
    expected = (payload / "codex").read_bytes()
    original_write = producer._write_context_file

    def write_after_ordinary_input_drift(destination: Path, content: bytes, mode: int) -> None:
        if destination.name == "provider-metadata.json":
            (payload / "codex").write_bytes(b"changed after validation\n")
        original_write(destination, content, mode)

    monkeypatch.setattr(producer, "_write_context_file", write_after_ordinary_input_drift)
    output = tmp_path / "context"
    producer.prepare_context(metadata, payload, output)
    assert (output / "codex").read_bytes() == expected
