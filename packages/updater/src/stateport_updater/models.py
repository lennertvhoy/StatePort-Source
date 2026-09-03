"""Updater-owned policy and immutable facts derived from a verified release.

The release index package owns release parsing, schema validation, signature
verification, and public release identities.  This module deliberately has no
``VerifiedRelease.from_mapping`` escape hatch.  Updater callers pass an
``UpdaterReleaseEnvelope`` and the engine re-verifies its exact canonical index
bytes before deriving these short-lived facts.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Mapping, Sequence

from stateport_release import (
    UpdaterReleaseEnvelope,
    VerifiedRelease as CanonicalVerifiedRelease,
    canonical_digest,
    image_set_digest,
    release_identity_from_verified,
    service_set_digest,
    update_policy_digest,
)


VERSION = re.compile(
    r"(?P<major>0|[1-9][0-9]*)\.(?P<minor>0|[1-9][0-9]*)\.(?P<patch>0|[1-9][0-9]*)"
    r"(?:-(?P<pre>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z"
)

UPDATE_POLICIES = {
    "manual",
    "notify",
    "download-and-notify",
    "scheduled",
    "automatic-with-rollback",
}
UPDATE_CHANNELS = {"alpha", "stable", "owner-dogfood"}


class ContractError(ValueError):
    """A verified-release consumer contract is invalid."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def version_key(value: str) -> tuple[int, int, int, tuple[tuple[int, object], ...]]:
    """Return a deterministic SemVer comparison key without a runtime extra."""

    matched = VERSION.fullmatch(value)
    if matched is None:
        raise ContractError("version_invalid", f"version is not SemVer: {value}")
    prerelease = matched.group("pre")
    if prerelease is None:
        pre_key: tuple[tuple[int, object], ...] = ((2, ""),)
    else:
        parts: list[tuple[int, object]] = []
        for item in prerelease.split("."):
            if item.isdigit():
                if len(item) > 1 and item.startswith("0"):
                    raise ContractError(
                        "version_invalid",
                        f"version has a zero-padded prerelease: {value}",
                    )
                parts.append((0, int(item)))
            else:
                parts.append((1, item))
        pre_key = tuple(parts)
    return (
        int(matched.group("major")),
        int(matched.group("minor")),
        int(matched.group("patch")),
        pre_key,
    )


@dataclass(frozen=True)
class UpdatePolicy:
    """Exact stateport.release-index/v1 update policy state."""

    mode: str
    channel: str
    schedule_days: tuple[int, ...] | None = None
    schedule_start_minute_utc: int | None = None
    accepted_predecessors: int = 1
    failed_successors: int = 1
    maximum_versions: int = 3
    maximum_age_days: int = 30

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "UpdatePolicy":
        if not isinstance(raw, Mapping):
            raise ContractError("policy_invalid", "update policy must be an object")
        expected = {
            "mode",
            "channel",
            "policyDigest",
            "schedule",
            "retention",
            "downloadAhead",
        }
        if set(raw) != expected:
            raise ContractError("policy_invalid", "update policy has unknown or missing fields")
        mode = raw.get("mode")
        channel = raw.get("channel")
        if mode not in UPDATE_POLICIES:
            raise ContractError("policy_invalid", "update policy mode is unsupported")
        if channel not in UPDATE_CHANNELS:
            raise ContractError("policy_invalid", "update channel is unsupported")

        schedule = raw.get("schedule")
        schedule_days: tuple[int, ...] | None = None
        start_minute: int | None = None
        if schedule is not None:
            if not isinstance(schedule, Mapping) or set(schedule) != {
                "daysOfWeek",
                "startMinuteUtc",
            }:
                raise ContractError("policy_invalid", "update schedule is malformed")
            days = schedule.get("daysOfWeek")
            minute = schedule.get("startMinuteUtc")
            if (
                not isinstance(days, Sequence)
                or isinstance(days, (str, bytes))
                or not days
                or len(days) > 7
                or any(
                    isinstance(day, bool) or not isinstance(day, int) or not 1 <= day <= 7
                    for day in days
                )
                or len(set(days)) != len(days)
                or isinstance(minute, bool)
                or not isinstance(minute, int)
                or not 0 <= minute <= 1439
            ):
                raise ContractError("policy_invalid", "update schedule is malformed")
            schedule_days = tuple(sorted(days))
            start_minute = minute

        scheduled = mode in {"scheduled", "automatic-with-rollback"}
        if scheduled != (schedule_days is not None):
            raise ContractError("policy_invalid", "update schedule does not match policy mode")
        expected_download = mode in {
            "download-and-notify",
            "scheduled",
            "automatic-with-rollback",
        }
        if raw.get("downloadAhead") is not expected_download:
            raise ContractError("policy_invalid", "download-ahead state does not match policy mode")

        retention = raw.get("retention")
        if not isinstance(retention, Mapping) or set(retention) != {
            "acceptedPredecessors",
            "failedSuccessors",
            "maximumVersions",
            "maximumAgeDays",
        }:
            raise ContractError("policy_invalid", "update retention is malformed")
        accepted = retention.get("acceptedPredecessors")
        failed = retention.get("failedSuccessors")
        maximum = retention.get("maximumVersions")
        age = retention.get("maximumAgeDays")
        limits = (
            (accepted, 1, 16, "acceptedPredecessors"),
            (failed, 1, 16, "failedSuccessors"),
            (maximum, 3, 64, "maximumVersions"),
            (age, 1, 3650, "maximumAgeDays"),
        )
        for value, minimum, upper, label in limits:
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not minimum <= value <= upper
            ):
                raise ContractError("policy_invalid", f"{label} is outside its supported range")
        if maximum < 1 + accepted + failed:
            raise ContractError(
                "policy_invalid",
                "retention cannot keep current, predecessor, and failed evidence",
            )
        if raw.get("policyDigest") != update_policy_digest(raw):
            raise ContractError("policy_invalid", "update policy digest is stale or tampered")
        return cls(
            mode=str(mode),
            channel=str(channel),
            schedule_days=schedule_days,
            schedule_start_minute_utc=start_minute,
            accepted_predecessors=int(accepted),
            failed_successors=int(failed),
            maximum_versions=int(maximum),
            maximum_age_days=int(age),
        )

    def to_mapping(self) -> dict[str, Any]:
        schedule = (
            None
            if self.schedule_days is None
            else {
                "daysOfWeek": list(self.schedule_days),
                "startMinuteUtc": self.schedule_start_minute_utc,
            }
        )
        document: dict[str, Any] = {
            "mode": self.mode,
            "channel": self.channel,
            "policyDigest": "",
            "schedule": schedule,
            "retention": {
                "acceptedPredecessors": self.accepted_predecessors,
                "failedSuccessors": self.failed_successors,
                "maximumVersions": self.maximum_versions,
                "maximumAgeDays": self.maximum_age_days,
            },
            "downloadAhead": self.mode
            in {"download-and-notify", "scheduled", "automatic-with-rollback"},
        }
        document["policyDigest"] = update_policy_digest(document)
        # Reuse the strict parser so direct construction cannot serialize an
        # invalid policy state.
        if self.mode not in UPDATE_POLICIES or self.channel not in UPDATE_CHANNELS:
            raise ContractError("policy_invalid", "update policy is unsupported")
        UpdatePolicy.from_mapping(document)
        return document


DEFAULT_ALPHA_POLICY = UpdatePolicy(mode="download-and-notify", channel="alpha")


@dataclass(frozen=True)
class ReleaseFacts:
    """Ephemeral facts produced only from a just-reverified release envelope."""

    envelope: UpdaterReleaseEnvelope
    verified: CanonicalVerifiedRelease
    identity: Mapping[str, Any]
    release_id: str
    version: str
    channel: str
    target_id: str
    platform: str
    signed_digest: str
    index_digest: str
    source_commit: str
    source_tree: str
    images: tuple[Mapping[str, Any], ...]
    target_images: tuple[Mapping[str, Any], ...]
    minimum_updater_version: str
    schema_version: int
    database_migration_version: int
    predecessor: str | None
    rollback_compatible: bool
    topology_digest: str
    quadlet_bundle_digest: str
    service_set_digest: str

    @classmethod
    def from_reverified(
        cls,
        envelope: UpdaterReleaseEnvelope,
        verified: CanonicalVerifiedRelease,
    ) -> "ReleaseFacts":
        document = envelope.document
        target = verified.target
        signed = verified.index.document["signed"]
        identity = release_identity_from_verified(verified)
        images = tuple(signed["images"])
        image_by_id = {item["imageId"]: item for item in images}
        services = tuple(target["services"])
        target_image_ids = {str(service["imageId"]) for service in services}
        target_images = tuple(
            image for image in images if str(image["imageId"]) in target_image_ids
        )
        if len(target_images) != len(target_image_ids):
            raise ContractError(
                "target_images_invalid",
                "verified target does not resolve one exact image per service image identity",
            )
        observed_services = [
            {
                "serviceId": service["serviceId"],
                "imageId": service["imageId"],
                "imageDigest": image_by_id[service["imageId"]]["digest"],
            }
            for service in services
        ]
        predecessor = document["compatibility"]["predecessor"]
        return cls(
            envelope=envelope,
            verified=verified,
            identity=identity,
            release_id=str(identity["releaseId"]),
            version=str(identity["version"]),
            channel=str(identity["channel"]),
            target_id=str(target["targetId"]),
            platform=f"{target['os']}/{target['architecture']}",
            signed_digest=str(identity["signedPayloadDigest"]),
            index_digest=verified.index.index_digest,
            source_commit=str(identity["sourceCommit"]),
            source_tree=str(identity["sourceTree"]),
            images=images,
            target_images=target_images,
            minimum_updater_version=str(document["compatibility"]["updaterMinimumVersion"]),
            schema_version=int(document["compatibility"]["schemaMigrationVersion"]),
            database_migration_version=int(document["compatibility"]["databaseMigrationVersion"]),
            predecessor=None if predecessor is None else str(predecessor["releaseId"]),
            rollback_compatible=bool(document["compatibility"]["rollback"]["supported"]),
            topology_digest=str(target["topologyDigest"]),
            quadlet_bundle_digest=str(target["quadletBundleDigest"]),
            service_set_digest=service_set_digest(observed_services),
        )

    @property
    def expected_pull_bytes(self) -> int:
        return sum(int(item["sizeBytes"]) for item in self.target_images)

    @property
    def target_image_digests(self) -> tuple[str, ...]:
        return tuple(sorted(str(item["digest"]) for item in self.target_images))

    @property
    def image_set_digest(self) -> str:
        return image_set_digest(self.images)

    def status_identity(self) -> dict[str, Any]:
        return {
            "releaseId": self.release_id,
            "version": self.version,
            "signedPayloadDigest": self.signed_digest,
        }

    def expected_revision_digest(self) -> str:
        """Immutable installed revision identity, independent of route role.

        ``accepted`` and ``staged`` are updater relationships.  They are not
        properties of an OCI revision and therefore cannot alter its runtime
        digest during an atomic route activation.
        """

        return canonical_digest(
            {
                "schema": "stateport.runtime-revision-identity/v1",
                "profile": "installed-control-plane",
                "targetId": self.target_id,
                "releaseIndexDigest": self.index_digest,
                "signedPayloadDigest": self.signed_digest,
                "topologyDigest": self.topology_digest,
                "quadletBundleDigest": self.quadlet_bundle_digest,
                "imageSetDigest": self.image_set_digest,
                "serviceSetDigest": self.service_set_digest,
            }
        )
