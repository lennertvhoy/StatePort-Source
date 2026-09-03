from __future__ import annotations

from pathlib import Path, PurePosixPath
import shlex
import subprocess

import yaml


ROOT = Path(__file__).resolve().parents[1]


def _local_copy_sources(path: Path) -> set[str]:
    sources: set[str] = set()
    logical_lines: list[str] = []
    pending = ""
    for raw in path.read_text().splitlines():
        stripped = raw.strip()
        pending += stripped.removesuffix("\\").strip() + " "
        if not stripped.endswith("\\"):
            logical_lines.append(pending.strip())
            pending = ""
    for line in logical_lines:
        if not line.startswith("COPY ") or line.startswith("COPY --from="):
            continue
        tokens = shlex.split(line)
        while len(tokens) > 1 and tokens[1].startswith("--"):
            tokens.pop(1)
        sources.update(tokens[1:-1])
    return sources


def test_positive_packaged_content_paths_are_tracked_and_safe() -> None:
    value = yaml.safe_load((ROOT / "images/packaged-content.v1.yaml").read_text())
    forbidden = set(value["policy"]["forbiddenPathParts"])
    for profile in value["profiles"].values():
        paths = profile["finalImageSources"] + profile.get("buildOnlySources", [])
        assert len(paths) == len(set(paths))
        for relative in paths:
            parts = PurePosixPath(relative).parts
            assert not (set(parts) & forbidden), relative
            assert not PurePosixPath(relative).is_absolute() and ".." not in parts
            assert (ROOT / relative).exists(), relative
            classified = subprocess.run(
                ["git", "ls-files", "--cached", "--others", "--exclude-standard", "--", relative],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            assert classified.returncode == 0 and classified.stdout.strip(), relative


def test_dockerfile_copy_inventory_matches_positive_profiles() -> None:
    content = yaml.safe_load((ROOT / "images/packaged-content.v1.yaml").read_text())
    images = yaml.safe_load((ROOT / "images/image-set.v1.yaml").read_text())["images"]
    for image_id, image in images.items():
        profile = content["profiles"][image["packagedContentProfile"]]
        expected = set(profile["finalImageSources"] + profile.get("buildOnlySources", []))
        observed = _local_copy_sources(ROOT / image["containerfile"])
        assert observed == expected, (
            image_id,
            sorted(observed - expected),
            sorted(expected - observed),
        )


def test_forbidden_broad_or_private_copies_never_enter_final_runtime_images() -> None:
    forbidden_exact = {
        ".",
        "packages",
        "apps",
        "config",
        "fixtures",
        "instances",
        "sources",
        "templates",
    }
    for path in (
        ROOT / "apps/api/Dockerfile",
        ROOT / "apps/web/Dockerfile",
        ROOT / "apps/worker/Dockerfile",
    ):
        assert not (_local_copy_sources(path) & forbidden_exact), path
        text = path.read_text()
        # No source Git metadata, clone, or mount may enter a runtime image.
        # The web image's synthesized deterministic packaged-content commit
        # (git init of the exact allowlisted tree at build time) is deliberate
        # and covered by scripts/test_packaged_product_identity.py.
        assert "COPY .git" not in text
        assert "/.git:" not in text
        assert "git clone" not in text
        assert "release-output" not in text
        assert "podman.sock" not in text


def test_web_image_packages_only_the_public_builtin_source_contract() -> None:
    content = yaml.safe_load((ROOT / "images/packaged-content.v1.yaml").read_text())
    paths = set(content["profiles"]["stateport-web"]["finalImageSources"])
    assert "sources/canonical/studydd.yaml" in paths
    assert "sources/profiles/studydd-local-alpha.yaml" in paths
    assert all(not path.endswith(".bundle") for path in paths)
