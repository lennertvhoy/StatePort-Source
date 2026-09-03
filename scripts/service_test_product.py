"""Build a disposable product-root projection for service-process tests.

The production service correctly refuses the real ``apps/web`` source tree
when no validated build exists. Backend-only tests must not depend on a stale
or pre-existing ignored ``dist`` directory, so they use this ordinary Git
fixture with the real product capabilities linked read-only by convention and
a minimal non-product static root.
"""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess


def service_product_fixture(tmp_path: Path, source_root: Path) -> Path:
    root = tmp_path / "service-product"
    if root.is_dir():
        return root
    root.mkdir()

    (root / "packages").symlink_to(
        source_root / "packages",
        target_is_directory=True,
    )
    for name in (
        "config",
        "fixtures",
        "instances",
        "schemas",
        "sources",
        "templates",
    ):
        shutil.copytree(source_root / name, root / name)
    shutil.copy2(source_root / "VERSION", root / "VERSION")

    apps = root / "apps"
    apps.mkdir()
    for source in sorted((source_root / "apps").iterdir()):
        if source.name == "web" or not source.is_dir():
            continue
        (apps / source.name).symlink_to(source, target_is_directory=True)
    web = apps / "web"
    web.mkdir()
    (web / "index.html").write_text(
        "<!doctype html><title>test</title>\n",
        encoding="utf-8",
    )

    (root / "README.md").write_text(
        "StatePort service test fixture\n",
        encoding="utf-8",
    )
    environment = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "StatePort service test",
        "GIT_AUTHOR_EMAIL": "service-test@example.invalid",
        "GIT_COMMITTER_NAME": "StatePort service test",
        "GIT_COMMITTER_EMAIL": "service-test@example.invalid",
    }
    for arguments in (
        ("init", "--quiet", "--initial-branch=main", "--template="),
        ("add", "README.md"),
        ("-c", "commit.gpgSign=false", "commit", "--quiet", "-m", "fixture"),
    ):
        subprocess.run(
            ("git", "-C", str(root), *arguments),
            check=True,
            capture_output=True,
            env=environment,
            timeout=10,
        )
    return root
