from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path
import stat
import sys
from urllib.parse import parse_qs, urlsplit

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import assemble_release_index as assembler  # noqa: E402
import verify_public_image_transport as probe  # noqa: E402


TAG = "0.1.0-alpha.17"
REPOSITORY = "ghcr.io/example/stateport"
PROVIDER_ID = "stateport-provider"
CONSUMER_IDS = (
    "stateport-web",
    "stateport-api",
    "stateport-worker",
    "stateport-runner",
    "stateport-dev-workspace",
    "stateport-playwright",
    "stateport-execution-host",
)
TOOL_SHA = "sha256:" + "0" * 64


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _header(headers: dict[str, str], name: str) -> str | None:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def _challenge(repo_path: str) -> str:
    return (
        'Bearer realm="https://ghcr.io/token",service="ghcr.io",'
        f'scope="repository:{repo_path}:pull"'
    )


class FakeRepo:
    def __init__(self, *, private: bool = False) -> None:
        self.private = private
        self.manifests: dict[str, bytes] = {}
        self.blobs: dict[str, bytes] = {}
        self.tags: dict[str, str] = {}

    def add_image(self, tag: str, config: bytes, layers: list[bytes]) -> str:
        config_digest = _digest(config)
        self.blobs[config_digest] = config
        descriptors = []
        for layer in layers:
            layer_digest = _digest(layer)
            self.blobs[layer_digest] = layer
            descriptors.append(
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": layer_digest,
                    "size": len(layer),
                }
            )
        manifest = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": len(config),
            },
            "layers": descriptors,
        }
        body = json.dumps(manifest, separators=(",", ":")).encode()
        digest = _digest(body)
        self.manifests[digest] = body
        if tag:
            self.tags[tag] = digest
        return digest

    def add_index(self, tag: str, leaf_digest: str, *, media_type: str) -> str:
        index = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {
                    "mediaType": media_type,
                    "digest": leaf_digest,
                    "size": len(self.manifests[leaf_digest]),
                    "platform": {"os": "linux", "architecture": "amd64"},
                }
            ],
        }
        body = json.dumps(index, separators=(",", ":")).encode()
        digest = _digest(body)
        self.manifests[digest] = body
        if tag:
            self.tags[tag] = digest
        return digest


class FakeRegistry:
    """In-process GHCR stand-in implementing exactly the probed surfaces."""

    def __init__(self) -> None:
        self.repos: dict[str, FakeRepo] = {}
        self.calls: list[dict[str, object]] = []
        self.storage_calls: list[dict[str, object]] = []
        self.mount_calls: list[dict[str, object]] = []
        self.rate_limit_at: int | None = None
        self.force_bodies: dict[str, bytes] = {}
        self.header_overrides: dict[str, str] = {}
        self.tag_overrides: dict[str, str] = {}
        self.mount_status = 401
        self.absent_status = 404
        self.absent_body = b""
        self.storage_redirect = True
        self.blob_status_override: dict[str, int] = {}
        self.token_expires_in: int | None = 300
        self.redirect_target: str | None = None
        self._pending_storage: dict[str, tuple[str, str]] = {}

    # -- construction ------------------------------------------------------

    def repo(self, path: str, *, private: bool = False) -> FakeRepo:
        created = FakeRepo(private=private)
        self.repos[path] = created
        return created

    # -- fake HTTP ---------------------------------------------------------

    def send(self, method, url, headers, body, max_bytes) -> probe.HttpResponse:
        record: dict[str, object] = {
            "method": method,
            "url": url,
            "headers": dict(headers),
            "body": body,
        }
        self.calls.append(record)
        if self.rate_limit_at == len(self.calls):
            return probe.HttpResponse(
                status=429, headers={"retry-after": "1"}, body=b"", url=url
            )
        parts = urlsplit(url)
        if self.redirect_target is not None and parts.hostname == "ghcr.io":
            return probe.HttpResponse(
                status=302,
                headers={"location": self.redirect_target},
                body=b"",
                url=url,
            )
        if parts.hostname == "ghcr.io" and parts.path == "/token":
            return self._token(parts, url)
        if parts.hostname == "ghcr.io" and "/manifests/" in parts.path:
            return self._manifest(parts, url, headers)
        if parts.hostname == "ghcr.io" and "/blobs/uploads/" in parts.path:
            return self._mount(url, headers, body)
        if parts.hostname == "ghcr.io" and "/blobs/" in parts.path:
            return self._blob(parts, url, headers)
        if parts.hostname == "pkg-containers.githubusercontent.com":
            return self._storage(parts, url, headers)
        raise AssertionError(f"unexpected fake registry URL: {url}")

    def _bearer(self, repo_path: str, headers: dict[str, str]) -> tuple[bool, object]:
        authorization = _header(headers, "authorization")
        if authorization is None:
            return False, probe.HttpResponse(
                status=401,
                headers={"www-authenticate": _challenge(repo_path)},
                body=b"",
                url="",
            )
        if authorization != f"Bearer anon:{repo_path}":
            return False, probe.HttpResponse(
                status=401,
                headers={"www-authenticate": _challenge(repo_path)},
                body=b"",
                url="",
            )
        return True, None

    def _token(self, parts, url) -> probe.HttpResponse:
        query = parse_qs(parts.query)
        scope = query.get("scope", ["repository::pull"])[0]
        repo_path = scope.removeprefix("repository:").removesuffix(":pull")
        repo = self.repos.get(repo_path)
        if repo is None or repo.private:
            return probe.HttpResponse(
                status=401,
                headers={"content-type": "application/json"},
                body=b'{"errors":[{"code":"DENIED"}]}',
                url=url,
            )
        document: dict[str, object] = {"token": f"anon:{repo_path}"}
        if self.token_expires_in is not None:
            document["expires_in"] = self.token_expires_in
        return probe.HttpResponse(
            status=200,
            headers={"content-type": "application/json"},
            body=json.dumps(document).encode(),
            url=url,
        )

    def _manifest(self, parts, url, headers) -> probe.HttpResponse:
        repo_path, reference = parts.path.removeprefix("/v2/").split("/manifests/", 1)
        repo = self.repos.get(repo_path)
        if repo is None:
            return probe.HttpResponse(status=404, headers={}, body=b"", url=url)
        ok, denial = self._bearer(repo_path, headers)
        if not ok:
            return denial  # type: ignore[return-value]
        key = f"{repo_path}|{reference}"
        if reference in repo.tags:
            resolved = self.tag_overrides.get(key, repo.tags[reference])
            body = repo.manifests.get(resolved)
            if body is None:
                return probe.HttpResponse(status=404, headers={}, body=b"", url=url)
        elif reference in repo.manifests:
            body = repo.manifests[reference]
        else:
            return probe.HttpResponse(
                status=self.absent_status,
                headers={},
                body=self.absent_body if self.absent_status == 200 else b"",
                url=url,
            )
        body = self.force_bodies.get(key, body)
        self.force_bodies.pop(key, None)
        digest_header = self.header_overrides.get(key, _digest(body))
        return probe.HttpResponse(
            status=200,
            headers={"docker-content-digest": digest_header, "content-type": "application/json"},
            body=body,
            url=url,
        )

    def _blob(self, parts, url, headers) -> probe.HttpResponse:
        repo_path, digest = parts.path.removeprefix("/v2/").split("/blobs/", 1)
        repo = self.repos.get(repo_path)
        if repo is None:
            return probe.HttpResponse(status=404, headers={}, body=b"", url=url)
        ok, denial = self._bearer(repo_path, headers)
        if not ok:
            return denial  # type: ignore[return-value]
        if digest not in repo.blobs:
            return probe.HttpResponse(status=404, headers={}, body=b"", url=url)
        if self.blob_status_override.get(digest) is not None:
            return probe.HttpResponse(
                status=self.blob_status_override[digest], headers={}, body=b"", url=url
            )
        if self.storage_redirect:
            location = (
                "https://pkg-containers.githubusercontent.com/stateport-blob/"
                f"{len(self._pending_storage)}"
            )
            self._pending_storage[location] = (repo_path, digest)
            return probe.HttpResponse(status=307, headers={"location": location}, body=b"", url=url)
        return self._blob_body(repo_path, digest, headers, url)

    def _blob_body(self, repo_path, digest, headers, url) -> probe.HttpResponse:
        repo = self.repos[repo_path]
        content = repo.blobs[digest]
        range_header = _header(headers, "range")
        if range_header == "bytes=0-0":
            return probe.HttpResponse(
                status=206,
                headers={"content-range": f"bytes 0-0/{len(content)}"},
                body=content[:1],
                url=url,
            )
        if range_header == f"bytes=0-{len(content) - 1}":
            return probe.HttpResponse(
                status=206,
                headers={"content-range": f"bytes 0-{len(content) - 1}/{len(content)}"},
                body=content,
                url=url,
            )
        return probe.HttpResponse(status=416, headers={}, body=b"", url=url)

    def _storage(self, parts, url, headers) -> probe.HttpResponse:
        self.storage_calls.append({"url": url, "headers": dict(headers)})
        if _header(headers, "authorization") is not None:
            return probe.HttpResponse(status=403, headers={}, body=b"", url=url)
        location = f"https://pkg-containers.githubusercontent.com{parts.path}"
        repo_path, digest = self._pending_storage[location]
        return self._blob_body(repo_path, digest, headers, url)

    def _mount(self, url, headers, body=None) -> probe.HttpResponse:
        self.mount_calls.append(
            {"url": url, "headers": dict(headers), "body": body}
        )
        parts = urlsplit(url)
        repo_path = parts.path.removeprefix("/v2/").split("/blobs/uploads/", 1)[0]
        ok, denial = self._bearer(repo_path, headers)
        if not ok:
            return denial  # type: ignore[return-value]
        if self.mount_status in {201, 202}:
            return probe.HttpResponse(
                status=self.mount_status,
                headers={"location": f"/v2/{repo_path}/blobs/uploads/fake-session"},
                body=b"",
                url=url,
            )
        return probe.HttpResponse(status=self.mount_status, headers={}, body=b"{}", url=url)


class World:
    def __init__(self, *, consumer_ids: tuple[str, ...] = CONSUMER_IDS) -> None:
        self.registry = FakeRegistry()
        self.consumer_ids = consumer_ids
        self.consumer_digests: dict[str, str] = {}
        self.consumer_configs: dict[str, str] = {}
        self.consumer_layers: dict[str, list[str]] = {}
        for image_id in consumer_ids:
            repo = self.registry.repo(f"example/stateport/{image_id}")
            config = json.dumps({"image": image_id, "kind": "config"}).encode()
            layers = [
                f"{image_id}-layer-0".encode(),
                f"{image_id}-layer-1".encode(),
            ]
            digest = repo.add_image(TAG, config, layers)
            self.consumer_digests[image_id] = digest
            self.consumer_configs[image_id] = _digest(config)
            self.consumer_layers[image_id] = [_digest(layer) for layer in layers]
        provider_repo = self.registry.repo(f"example/stateport/{PROVIDER_ID}")
        provider_config = b"provider-config"
        provider_layers = [b"provider-layer-0"]
        self.provider_digest = provider_repo.add_image(TAG, provider_config, provider_layers)
        self.provider_config = _digest(provider_config)
        self.provider_layers = [_digest(layer) for layer in provider_layers]
        self.private_repo = self.registry.repo("example/private/base", private=True)
        self.private_digest = self.private_repo.add_image(
            "base", b"secret-config", [b"secret-layer"]
        )
        self.private_package = "ghcr.io/example/private-package"
        self.registry.repo("example/private-package", private=True)

    # -- receipt material --------------------------------------------------

    def build_receipt(self) -> dict:
        images = {}
        for image_id in self.consumer_ids:
            images[image_id] = {
                "acceptedReference": (
                    f"127.0.0.1:5000/stateport-alpha/{image_id}"
                    f"@{self.consumer_digests[image_id]}"
                ),
                "releaseAuthority": {
                    "kind": "retained-oci-archive",
                    "manifestDigest": self.consumer_digests[image_id],
                    "configDigest": self.consumer_configs[image_id],
                    "layerDigests": self.consumer_layers[image_id],
                    "sizeBytes": 1048576,
                    "path": f"oci-archives/{image_id}.oci.tar",
                },
            }
        return {
            "formatVersion": "stateport.release-image-build-receipt/v1",
            "identity": {
                "version": TAG,
                "commit": "b" * 40,
                "tree": "c" * 40,
                "created": "2026-09-12T10:00:00Z",
            },
            "images": images,
        }

    def producer_receipt(self, *, host: str = "local") -> dict:
        if host == "ghcr":
            accepted = f"{REPOSITORY}/{PROVIDER_ID}@{self.provider_digest}"
        else:
            accepted = (
                f"127.0.0.1:5001/stateport-alpha/{PROVIDER_ID}@{self.provider_digest}"
            )
        return {
            "formatVersion": "stateport.producer-build-receipt/v1",
            "result": "succeeded",
            "acceptedReference": accepted,
            "manifestDigest": self.provider_digest,
            "platformManifestDigest": self.provider_digest,
            "image": {
                "imageId": "f" * 64,
                "digest": self.provider_config,
                "os": "linux",
                "architecture": "amd64",
                "platform": "linux/amd64",
            },
        }

    def visibility_review(self) -> dict:
        return {
            "formatVersion": "stateport.registry-visibility-review/v1",
            "repository": REPOSITORY,
            "privateDigests": [
                {"reference": f"ghcr.io/example/private/base@{self.private_digest}"}
            ],
            "privatePackages": [{"repository": self.private_package}],
        }

    def write_receipts(self, tmp_path: Path, *, host: str = "local") -> dict[str, Path]:
        expectations = tmp_path / "build-receipt.json"
        expectations.write_text(json.dumps(self.build_receipt(), indent=2), encoding="utf-8")
        producer = tmp_path / "producer-build-receipt.json"
        producer.write_text(
            json.dumps(self.producer_receipt(host=host), indent=2), encoding="utf-8"
        )
        review = tmp_path / "registry-visibility-review.json"
        review.write_text(json.dumps(self.visibility_review(), indent=2), encoding="utf-8")
        return {"expectations": expectations, "producer": producer, "review": review}


@dataclass
class Harness:
    world: World
    config: probe.RunConfig
    registry: FakeRegistry
    paths: dict[str, Path]


def make_harness(
    tmp_path: Path,
    world: World | None = None,
    *,
    max_requests: int = 400,
    min_delay_s: float = 0.0,
    index_mode: Path | None = None,
    host: str = "local",
) -> Harness:
    world = world or World()
    paths = world.write_receipts(tmp_path, host=host)
    config = probe.RunConfig(
        repository=REPOSITORY,
        tag=TAG,
        expectations_path=paths["expectations"],
        producer_receipt_path=paths["producer"],
        private_review_path=paths["review"],
        receipt_out=tmp_path / "transport-receipt.json",
        max_requests=max_requests,
        min_delay_s=min_delay_s,
        index_mode_path=index_mode,
    )
    return Harness(world=world, config=config, registry=world.registry, paths=paths)


def run_harness(
    tmp_path: Path,
    world: World | None = None,
    *,
    max_requests: int = 400,
    min_delay_s: float = 0.0,
    index_mode: Path | None = None,
    host: str = "local",
    environ: dict[str, str] | None = None,
    clock=None,
    sleep=None,
) -> tuple[dict, Harness]:
    harness = make_harness(
        tmp_path,
        world,
        max_requests=max_requests,
        min_delay_s=min_delay_s,
        index_mode=index_mode,
        host=host,
    )
    kwargs = {}
    if clock is not None:
        kwargs["clock"] = clock
    if sleep is not None:
        kwargs["sleep"] = sleep
    receipt = probe.run_verification(
        harness.config,
        transport=harness.registry,
        environ={} if environ is None else environ,
        tool_sha256=TOOL_SHA,
        **kwargs,
    )
    return receipt, harness


def image_entry(receipt: dict, image_id: str) -> dict:
    for entry in receipt["images"]:
        if entry["imageId"] == image_id:
            return entry
    raise AssertionError(f"missing image entry {image_id}")


def probe_status(entry: dict, probe_id: str) -> str:
    for item in entry["probes"]:
        if item["id"] == probe_id:
            return item["status"]
    raise AssertionError(f"missing probe {probe_id} in {entry['imageId']}")


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def _mutate_json(path: Path, mutate) -> None:
    document = json.loads(path.read_text(encoding="utf-8"))
    mutate(document)
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")


def _argv(harness: Harness, *, min_delay: str = "0") -> list[str]:
    arguments = [
        "--expectations",
        str(harness.config.expectations_path),
        "--producer-receipt",
        str(harness.config.producer_receipt_path),
        "--repository",
        REPOSITORY,
        "--tag",
        TAG,
        "--private-review",
        str(harness.config.private_review_path),
        "--receipt-out",
        str(harness.config.receipt_out),
        "--min-delay-s",
        min_delay,
    ]
    if harness.config.index_mode_path is not None:
        arguments += ["--index-mode", str(harness.config.index_mode_path)]
    return arguments


# ---------------------------------------------------------------------------
# happy path and receipt shape
# ---------------------------------------------------------------------------


def test_happy_path_passes_and_records_full_receipt(tmp_path: Path) -> None:
    receipt, harness = run_harness(tmp_path)

    assert receipt["result"] == "passed"
    assert receipt["formatVersion"] == probe.FORMAT_VERSION
    assert receipt["version"] == TAG
    assert receipt["repository"] == REPOSITORY
    assert receipt["credentials"] == "none"
    assert receipt["tool"]["sha256"] == TOOL_SHA
    assert receipt["blockedReason"] is None
    assert receipt["failures"] == []
    assert len(receipt["images"]) == len(CONSUMER_IDS) + 1
    assert image_entry(receipt, PROVIDER_ID)["role"] == "provider"
    assert image_entry(receipt, PROVIDER_ID)["sourceReference"].startswith("127.0.0.1:5001/")

    for image_id in (*CONSUMER_IDS, PROVIDER_ID):
        entry = image_entry(receipt, image_id)
        assert entry["result"] == "passed", entry
        assert entry["resolvedDigest"] == entry["expectedDigest"]
        assert entry["resolvedTagDigest"] == entry["expectedDigest"]
        assert entry["tag"] == TAG
        assert entry["config"]["digestVerified"] is True
        assert entry["config"]["rangeHonored"] is True
        assert entry["layers"]
        assert all(layer["rangeHonored"] for layer in entry["layers"])
        assert probe_status(entry, "P1") == "passed"
        assert probe_status(entry, "P2") == "passed"
        assert probe_status(entry, "P4") == "passed"
        assert probe_status(entry, "P5") == "passed"
        assert probe_status(entry, "P6") == "passed"
        assert probe_status(entry, "P7") == "passed"

    negatives = receipt["negatives"]
    assert negatives["absentDigest"]["result"] == "passed"
    assert negatives["absentDigest"]["bytesServed"] == 0
    assert negatives["absentDigest"]["status"] in {401, 403, 404}
    assert negatives["absentTag"]["result"] == "passed"
    assert negatives["absentTag"]["bytesServed"] == 0
    assert negatives["privateDigests"][0]["result"] == "passed"
    assert negatives["privateDigests"][0]["bytesServed"] == 0
    assert negatives["privateDigests"][0]["authorization"] == "token-denied"
    assert negatives["privateDigests"][0]["contentMatchesPrivateDigest"] is False
    assert negatives["privateTokenDenials"][0]["result"] == "passed"
    assert negatives["privateTokenDenials"][0]["status"] == 401
    assert negatives["crossRepoMount"]["result"] == "passed"
    assert negatives["crossRepoMount"]["uploadSessionCreated"] is False

    statuses = {item["id"]: item["status"] for item in receipt["probes"]}
    assert statuses["P9"] == "passed"
    assert statuses["P10"] == "passed"
    assert statuses["P11"] == "passed"
    assert statuses["P12"] == "passed"
    assert statuses["P13"] == "passed"
    assert statuses["P14"] == "passed"
    assert statuses["P15"] == "passed"
    assert statuses["P17"] == "passed"
    assert receipt["skippedProbes"][0]["id"] == "P16"

    assert receipt["budget"]["requestsUsed"] == len(harness.registry.calls)
    assert 0 < receipt["budget"]["requestsUsed"] <= receipt["budget"]["maxRequests"]
    assert receipt["rateLimit"] == {"any429": False, "observations": []}
    assert receipt["authentication"]["method"] == "anonymous-bearer-challenge-only"
    acquired = receipt["authentication"]["tokensAcquired"]
    assert acquired
    assert all(token["expiresIn"] == 300 for token in acquired)
    assert len(acquired) == len({token["repository"] for token in acquired})
    assert {token["repository"] for token in acquired} == {
        f"example/stateport/{image_id}" for image_id in (*CONSUMER_IDS, PROVIDER_ID)
    }


def test_provider_reference_on_ghcr_is_accepted(tmp_path: Path) -> None:
    receipt, _harness = run_harness(tmp_path, host="ghcr")
    assert receipt["result"] == "passed"
    entry = image_entry(receipt, PROVIDER_ID)
    assert entry["reference"] == f"{REPOSITORY}/{PROVIDER_ID}@{entry['expectedDigest']}"


def test_blob_redirects_strip_authorization_only_cross_host(tmp_path: Path) -> None:
    receipt, harness = run_harness(tmp_path)
    assert receipt["result"] == "passed"
    assert harness.registry.storage_calls
    for call in harness.registry.storage_calls:
        assert _header(call["headers"], "authorization") is None
        assert _header(call["headers"], "range") is not None
    ghcr_blob_requests = [
        call
        for call in harness.registry.calls
        if "ghcr.io" in str(call["url"])
        and "/blobs/" in str(call["url"])
        and "/uploads/" not in str(call["url"])
    ]
    assert ghcr_blob_requests
    assert all(_header(call["headers"], "authorization") for call in ghcr_blob_requests)
    expected_storage = sum(
        1 + len(entry["layers"]) for entry in receipt["images"] if entry["result"] == "passed"
    )
    assert len(harness.registry.storage_calls) == expected_storage


def test_index_manifest_recursion_is_recorded(tmp_path: Path) -> None:
    world = World()
    repo = world.registry.repos["example/stateport/stateport-web"]
    leaf = world.consumer_digests["stateport-web"]
    index_digest = repo.add_index(
        TAG, leaf, media_type="application/vnd.oci.image.manifest.v1+json"
    )
    world.consumer_digests["stateport-web"] = index_digest
    receipt, _harness = run_harness(tmp_path, world)
    entry = image_entry(receipt, "stateport-web")
    assert receipt["result"] == "passed"
    assert entry["indexDepth"] == 1
    assert entry["platformLeafDigest"] == leaf
    assert probe_status(entry, "P3") == "passed"


def test_index_nesting_beyond_two_fails_p3(tmp_path: Path) -> None:
    world = World()
    repo = world.registry.repos["example/stateport/stateport-web"]
    leaf = world.consumer_digests["stateport-web"]
    first = repo.add_index(TAG, leaf, media_type="application/vnd.oci.image.manifest.v1+json")
    second = repo.add_index(TAG, first, media_type="application/vnd.oci.image.index.v1+json")
    third = repo.add_index(TAG, second, media_type="application/vnd.oci.image.index.v1+json")
    world.consumer_digests["stateport-web"] = third
    receipt, _harness = run_harness(tmp_path, world)
    entry = image_entry(receipt, "stateport-web")
    assert receipt["result"] == "failed"
    assert entry["result"] == "failed"
    assert probe_status(entry, "P3") == "failed"
    assert "nesting" in entry["failure"]


# ---------------------------------------------------------------------------
# per-image premise failures
# ---------------------------------------------------------------------------


def test_manifest_body_digest_mismatch_fails_only_that_image(tmp_path: Path) -> None:
    world = World()
    target = "stateport-web"
    key = f"example/stateport/{target}|{world.consumer_digests[target]}"
    world.registry.force_bodies[key] = b'{"schemaVersion":2,"config":{},"layers":[{}]}'
    receipt, _harness = run_harness(tmp_path, world)
    assert receipt["result"] == "failed"
    entry = image_entry(receipt, target)
    assert entry["result"] == "failed"
    assert probe_status(entry, "P1") == "failed"
    assert image_entry(receipt, "stateport-api")["result"] == "passed"
    assert any(failure.startswith(f"{target}:") for failure in receipt["failures"])


def test_manifest_header_digest_mismatch_fails_p1(tmp_path: Path) -> None:
    world = World()
    target = "stateport-api"
    key = f"example/stateport/{target}|{world.consumer_digests[target]}"
    world.registry.header_overrides[key] = "sha256:" + "9" * 64
    receipt, _harness = run_harness(tmp_path, world)
    entry = image_entry(receipt, target)
    assert receipt["result"] == "failed"
    assert probe_status(entry, "P1") == "failed"
    assert "header" in entry["failure"]


def test_tag_resolution_mismatch_fails_p2(tmp_path: Path) -> None:
    world = World()
    target = "stateport-worker"
    repo = world.registry.repos[f"example/stateport/{target}"]
    other = repo.add_image("other", b"other-config", [b"other-layer"])
    world.registry.tag_overrides[f"example/stateport/{target}|{TAG}"] = other
    receipt, _harness = run_harness(tmp_path, world)
    entry = image_entry(receipt, target)
    assert receipt["result"] == "failed"
    assert probe_status(entry, "P1") == "passed"
    assert probe_status(entry, "P2") == "failed"
    assert "resolves to body" in entry["failure"]


def test_config_blob_corruption_fails_p5(tmp_path: Path) -> None:
    world = World()
    target = "stateport-runner"
    repo = world.registry.repos[f"example/stateport/{target}"]
    config_digest = world.consumer_configs[target]
    original = repo.blobs[config_digest]
    repo.blobs[config_digest] = b"z" * len(original)
    receipt, _harness = run_harness(tmp_path, world)
    entry = image_entry(receipt, target)
    assert receipt["result"] == "failed"
    assert probe_status(entry, "P5") == "failed"
    assert "config blob hashes" in entry["failure"] or "bytes" in entry["failure"]


def test_layer_content_range_mismatch_fails_p6(tmp_path: Path) -> None:
    world = World()
    target = "stateport-dev-workspace"
    repo = world.registry.repos[f"example/stateport/{target}"]
    layer_digest = world.consumer_layers[target][0]
    repo.blobs[layer_digest] = b"short"
    receipt, _harness = run_harness(tmp_path, world)
    entry = image_entry(receipt, target)
    assert receipt["result"] == "failed"
    assert probe_status(entry, "P6") == "failed"
    assert "Content-Range" in entry["failure"]


def test_release_authority_layer_binding_mismatch_fails_p8(tmp_path: Path) -> None:
    harness = make_harness(tmp_path)

    def mutate(document: dict) -> None:
        document["images"]["stateport-playwright"]["releaseAuthority"]["layerDigests"] = [
            "sha256:" + "7" * 64
        ]

    _mutate_json(harness.paths["expectations"], mutate)
    receipt = probe.run_verification(
        harness.config,
        transport=harness.registry,
        environ={},
        tool_sha256=TOOL_SHA,
    )
    entry = image_entry(receipt, "stateport-playwright")
    assert receipt["result"] == "failed"
    assert probe_status(entry, "P8") == "failed"
    assert "layerDigests" in entry["failure"]


def test_receipt_version_must_match_tag(tmp_path: Path) -> None:
    harness = make_harness(tmp_path)

    def mutate(document: dict) -> None:
        document["identity"]["version"] = "0.1.0-alpha.99"

    _mutate_json(harness.paths["expectations"], mutate)
    receipt = probe.run_verification(
        harness.config, transport=harness.registry, environ={}, tool_sha256=TOOL_SHA
    )
    assert receipt["result"] == "blocked"
    assert "does not match --tag" in receipt["blockedReason"]


def test_absent_digest_200_leak_fails_p9(tmp_path: Path) -> None:
    world = World()
    world.registry.absent_status = 200
    world.registry.absent_body = b"leaked-body"
    receipt, _harness = run_harness(tmp_path, world)
    entry = receipt["negatives"]["absentDigest"]
    assert receipt["result"] == "failed"
    assert entry["result"] == "failed"
    assert entry["bytesServed"] == len(b"leaked-body")
    assert entry["bodyDigest"] != entry["digest"]
    assert any(failure.startswith("absentDigest:") for failure in receipt["failures"])
    statuses = {item["id"]: item["status"] for item in receipt["probes"]}
    assert statuses["P9"] == "failed"


def test_private_digest_leak_fails_p11_and_reports_hash(tmp_path: Path) -> None:
    world = World()
    world.private_repo.private = False
    receipt, _harness = run_harness(tmp_path, world)
    entry = receipt["negatives"]["privateDigests"][0]
    assert receipt["result"] == "failed"
    assert entry["result"] == "failed"
    assert entry["bytesServed"] > 0
    assert entry["contentMatchesPrivateDigest"] is True
    assert any(
        failure.startswith("privateDigests[0]") for failure in receipt["failures"]
    )
    statuses = {item["id"]: item["status"] for item in receipt["probes"]}
    assert statuses["P11"] == "failed"


def test_private_package_token_grant_fails_p12(tmp_path: Path) -> None:
    world = World()
    world.registry.repos["example/private-package"].private = False
    receipt, _harness = run_harness(tmp_path, world)
    entry = receipt["negatives"]["privateTokenDenials"][0]
    assert receipt["result"] == "failed"
    assert entry["tokenGranted"] is True
    assert entry["expiresIn"] == 300
    statuses = {item["id"]: item["status"] for item in receipt["probes"]}
    assert statuses["P12"] == "failed"


def test_cross_repo_mount_201_is_a_failure(tmp_path: Path) -> None:
    world = World()
    world.registry.mount_status = 201
    receipt, harness = run_harness(tmp_path, world)
    entry = receipt["negatives"]["crossRepoMount"]
    assert receipt["result"] == "failed"
    assert entry["result"] == "failed"
    assert entry["uploadSessionCreated"] is True
    assert entry["bytesServed"] == 0
    assert harness.registry.mount_calls
    assert harness.registry.mount_calls[0]["body"] is None
    assert any(
        _header(call["headers"], "authorization") is not None
        for call in harness.registry.mount_calls
    )
    statuses = {item["id"]: item["status"] for item in receipt["probes"]}
    assert statuses["P13"] == "failed"


# ---------------------------------------------------------------------------
# budget, rate limit, transport blocking
# ---------------------------------------------------------------------------


def test_429_blocks_immediately_without_retry(tmp_path: Path) -> None:
    world = World()
    world.registry.rate_limit_at = 1
    receipt, harness = run_harness(tmp_path, world)
    assert receipt["result"] == "blocked"
    assert len(harness.registry.calls) == 1
    assert receipt["rateLimit"]["any429"] is True
    assert receipt["rateLimit"]["observations"][0]["retryAfter"] == "1"
    assert "429" in receipt["blockedReason"]
    statuses = {item["id"]: item["status"] for item in receipt["probes"]}
    assert statuses["P14"] == "blocked"
    assert statuses["P9"] == "blocked"


def test_budget_exhaustion_blocks_before_overrun(tmp_path: Path) -> None:
    world = World()
    receipt, harness = run_harness(tmp_path, world, max_requests=2)
    assert receipt["result"] == "blocked"
    assert receipt["budget"]["requestsUsed"] == 2
    assert len(harness.registry.calls) == 2
    assert "budget exhausted" in receipt["blockedReason"]


def test_min_delay_is_enforced_between_sends(tmp_path: Path) -> None:
    world = World()
    clock = FakeClock()
    receipt, _harness = run_harness(
        tmp_path,
        world,
        min_delay_s=1.0,
        clock=clock.monotonic,
        sleep=clock.sleep,
    )
    assert receipt["result"] == "passed"
    assert len(clock.sleeps) == receipt["budget"]["requestsUsed"] - 1
    assert all(abs(value - 1.0) < 1e-9 for value in clock.sleeps)
    assert receipt["budget"]["elapsedSeconds"] == round(sum(clock.sleeps), 3)


def test_redirect_to_unapproved_host_blocks(tmp_path: Path) -> None:
    world = World()
    world.registry.redirect_target = "https://evil.example/steal"
    receipt, _harness = run_harness(tmp_path, world)
    assert receipt["result"] == "blocked"
    assert "approved HTTPS hosts" in receipt["blockedReason"]


def test_redirect_loop_blocks(tmp_path: Path) -> None:
    world = World()
    digest = world.consumer_digests["stateport-web"]
    world.registry.redirect_target = (
        f"https://ghcr.io/v2/example/stateport/stateport-web/manifests/{digest}"
    )
    receipt, harness = run_harness(tmp_path, world)
    assert receipt["result"] == "blocked"
    assert "redirect chain is too long" in receipt["blockedReason"]
    assert len(harness.registry.calls) == probe.MAX_REDIRECTS + 1


def test_token_endpoint_failure_blocks(tmp_path: Path) -> None:
    world = World()
    world.registry._token = lambda parts, url: probe.HttpResponse(500, {}, b"", url)
    receipt, _harness = run_harness(tmp_path, world)
    assert receipt["result"] == "blocked"
    assert "token endpoint returned 500" in receipt["blockedReason"]


def test_unsupported_auth_challenge_blocks(tmp_path: Path) -> None:
    world = World()
    world.registry._manifest = lambda parts, url, headers: probe.HttpResponse(
        401, {"www-authenticate": 'Basic realm="x"'}, b"", url
    )
    receipt, _harness = run_harness(tmp_path, world)
    assert receipt["result"] == "blocked"
    assert "challenge is unusable" in receipt["blockedReason"]


def test_malformed_token_document_blocks(tmp_path: Path) -> None:
    world = World()
    world.registry._token = lambda parts, url: probe.HttpResponse(200, {}, b"not-json", url)
    receipt, _harness = run_harness(tmp_path, world)
    assert receipt["result"] == "blocked"
    assert "malformed" in receipt["blockedReason"]


class _OversizeTransport:
    def send(self, method, url, headers, body, max_bytes):
        return probe.HttpResponse(200, {}, b"x" * (max_bytes + 1), url)


def test_oversized_response_blocks() -> None:
    session = probe.ProbeSession(
        transport=_OversizeTransport(), max_requests=5, min_delay_s=0.0
    )
    with pytest.raises(probe.TransportBlocked, match="exceeded"):
        session.request(
            "GET",
            probe.manifest_url(f"{REPOSITORY}/stateport-web", "sha256:" + "a" * 64),
            scope_repository="example/stateport/stateport-web",
            max_bytes=8,
        )


def test_token_cache_refreshes_after_expiry() -> None:
    registry = FakeRegistry()
    repo = registry.repo("example/cache")
    digest = repo.add_image("t", b"cache-config", [b"cache-layer"])
    clock = FakeClock()
    session = probe.ProbeSession(
        transport=registry,
        max_requests=50,
        min_delay_s=0.0,
        clock=clock.monotonic,
        sleep=clock.sleep,
    )
    url = probe.manifest_url("ghcr.io/example/cache", digest)
    assert session.request("GET", url, scope_repository="example/cache").status == 200
    assert len(session.tokens_acquired) == 1
    clock.now += 400
    assert session.request("GET", url, scope_repository="example/cache").status == 200
    assert len(session.tokens_acquired) == 2


# ---------------------------------------------------------------------------
# environment refusal, CLI, receipt writer
# ---------------------------------------------------------------------------


def test_credential_environment_refuses_without_receipt(tmp_path: Path) -> None:
    harness = make_harness(tmp_path)
    result = probe.main(
        _argv(harness),
        transport_factory=lambda: harness.registry,
        environ={"GH_TOKEN": "secret"},
    )
    assert result == 2
    assert not harness.config.receipt_out.exists()
    assert harness.registry.calls == []


@pytest.mark.parametrize(
    "variable",
    [
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "GHCR_TOKEN",
        "REGISTRY_AUTH_FILE",
        "GH_ENTERPRISE_TOKEN",
        "GH_AUTH_TOKEN",
        "DOCKER_AUTH_CONFIG",
        "gh_enterprise_token",
        "gh_auth_token",
        "docker_auth_config",
    ],
)
def test_each_credential_variable_refuses(tmp_path: Path, variable: str) -> None:
    harness = make_harness(tmp_path)
    result = probe.main(
        _argv(harness),
        transport_factory=lambda: harness.registry,
        environ={variable: ""},
    )
    assert result == 2
    assert not harness.config.receipt_out.exists()


def test_proxy_environment_blocks_before_network(tmp_path: Path) -> None:
    world = World()
    receipt, harness = run_harness(
        tmp_path, world, environ={"HTTPS_PROXY": "http://proxy.local:3128"}
    )
    assert receipt["result"] == "blocked"
    assert "proxy environment variables" in receipt["blockedReason"]
    assert harness.registry.calls == []


def test_cli_writes_create_only_0600_receipt(tmp_path: Path) -> None:
    harness = make_harness(tmp_path)
    assert (
        probe.main(_argv(harness), transport_factory=lambda: harness.registry, environ={})
        == 0
    )
    target = harness.config.receipt_out
    assert target.is_file()
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    document = json.loads(target.read_text(encoding="utf-8"))
    assert document["formatVersion"] == probe.FORMAT_VERSION
    assert document["result"] == "passed"
    original = target.read_bytes()
    assert (
        probe.main(_argv(harness), transport_factory=lambda: harness.registry, environ={})
        == 2
    )
    assert target.read_bytes() == original
    assert not list(tmp_path.glob(".*.tmp-*"))


def test_cli_returns_one_for_failed_run(tmp_path: Path) -> None:
    world = World()
    target = "stateport-web"
    key = f"example/stateport/{target}|{world.consumer_digests[target]}"
    world.registry.force_bodies[key] = b'{"schemaVersion":2,"config":{},"layers":[{}]}'
    harness = make_harness(tmp_path, world)
    assert (
        probe.main(_argv(harness), transport_factory=lambda: harness.registry, environ={})
        == 1
    )
    document = json.loads(harness.config.receipt_out.read_text(encoding="utf-8"))
    assert document["result"] == "failed"


def test_write_receipt_create_only_never_clobbers(tmp_path: Path) -> None:
    target = tmp_path / "receipt.json"
    probe.write_receipt_create_only(target, {"a": 1})
    original = target.read_bytes()
    with pytest.raises(probe.InputError, match="refusing to overwrite"):
        probe.write_receipt_create_only(target, {"a": 2})
    assert target.read_bytes() == original
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert not list(tmp_path.glob(".*.tmp-*"))


def test_index_mode_is_recorded_as_unbound(tmp_path: Path) -> None:
    index_path = tmp_path / "release-index.json"
    index_path.write_text(
        json.dumps({"formatVersion": "stateport.release-index/v1"}), encoding="utf-8"
    )
    receipt, _harness = run_harness(tmp_path, index_mode=index_path)
    assert receipt["result"] == "passed"
    recorded = receipt["expectations"]["indexMode"]
    assert recorded["bound"] is False
    assert recorded["formatVersion"] == "stateport.release-index/v1"
    assert recorded["sha256"] == probe._sha256_file(index_path)
    assert receipt["expectations"]["buildReceipt"]["sha256"] == probe._sha256_file(
        Path(receipt["expectations"]["buildReceipt"]["path"])
    )


# ---------------------------------------------------------------------------
# input validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "ghcr.io",
        "http://ghcr.io/a/b",
        "ghcr.io/UPPER/x",
        "ghcr.io/a/b:c",
        "ghcr.io/a/../b",
        "docker.io/a/b",
        "ghcr.io/a//b",
        "ghcr.io/a/b?x=1",
    ],
)
def test_validate_repository_rejects_unsafe_values(value: str) -> None:
    with pytest.raises(probe.InputError):
        probe.validate_repository(value)


def test_validate_repository_accepts_flat_owner_pattern() -> None:
    # The public flat package pattern used since Alpha.15
    # (ghcr.io/<owner>/<image>) has a single-segment path.
    assert probe.validate_repository("ghcr.io/lennertvhoy") == "ghcr.io/lennertvhoy"


def test_validate_repository_accepts_reviewed_shape() -> None:
    assert (
        probe.validate_repository("ghcr.io/owner/stateport-prefix")
        == "ghcr.io/owner/stateport-prefix"
    )


def test_consumer_loader_rejects_missing_release_authority() -> None:
    world = World()
    document = world.build_receipt()
    del document["images"]["stateport-web"]["releaseAuthority"]
    with pytest.raises(probe.InputError, match="releaseAuthority"):
        probe.load_consumer_images(document, repository=REPOSITORY, tag=TAG)


def test_consumer_loader_rejects_accepted_reference_disagreement() -> None:
    world = World()
    document = world.build_receipt()
    document["images"]["stateport-web"]["acceptedReference"] = (
        f"127.0.0.1:5000/stateport-alpha/stateport-web@{'sha256:' + '1' * 64}"
    )
    with pytest.raises(probe.InputError, match="acceptedReference digest disagrees"):
        probe.load_consumer_images(document, repository=REPOSITORY, tag=TAG)


def test_producer_loader_rejects_manifest_digest_disagreement() -> None:
    world = World()
    document = world.producer_receipt()
    document["manifestDigest"] = "sha256:" + "1" * 64
    with pytest.raises(probe.InputError, match="manifestDigest disagrees"):
        probe.load_producer_image(document, repository=REPOSITORY, tag=TAG)


def test_producer_loader_rejects_foreign_ghcr_path() -> None:
    world = World()
    document = world.producer_receipt()
    document["acceptedReference"] = (
        f"ghcr.io/elsewhere/{PROVIDER_ID}@{world.provider_digest}"
    )
    with pytest.raises(probe.InputError, match="reviewed path"):
        probe.load_producer_image(document, repository=REPOSITORY, tag=TAG)


def test_visibility_review_requires_private_digests(tmp_path: Path) -> None:
    review = tmp_path / "review.json"
    review.write_text(
        json.dumps(
            {
                "formatVersion": probe.VISIBILITY_REVIEW_FORMAT,
                "repository": REPOSITORY,
                "privateDigests": [],
                "privatePackages": [],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(probe.InputError, match="privateDigests"):
        probe.load_visibility_review(review, repository=REPOSITORY)


def test_visibility_review_requires_repository_binding(tmp_path: Path) -> None:
    world = World()
    review = tmp_path / "review.json"
    document = world.visibility_review()
    del document["repository"]
    review.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(probe.InputError, match="must declare the repository"):
        probe.load_visibility_review(review, repository=REPOSITORY)


def test_visibility_review_requires_private_packages(tmp_path: Path) -> None:
    world = World()
    review = tmp_path / "review.json"
    document = world.visibility_review()
    document["privatePackages"] = []
    review.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(probe.InputError, match="non-empty privatePackages"):
        probe.load_visibility_review(review, repository=REPOSITORY)


def test_visibility_review_rejects_foreign_repository(tmp_path: Path) -> None:
    world = World()
    review = tmp_path / "review.json"
    document = world.visibility_review()
    document["repository"] = "ghcr.io/someone/else"
    review.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(probe.InputError, match="different repository"):
        probe.load_visibility_review(review, repository=REPOSITORY)


def test_token_url_parser_is_the_reviewed_assembler_primitive() -> None:
    assert probe._assembler._registry_token_url is assembler._registry_token_url
    challenge = (
        'Basic realm="ignored", Bearer realm="https://ghcr.io/token",'
        'service="ghcr.io",scope="repository:org/image:pull"'
    )
    assert assembler._registry_token_url(challenge, repository="org/image") == (
        "https://ghcr.io/token?service=ghcr.io&scope=repository%3Aorg%2Fimage%3Apull"
    )


