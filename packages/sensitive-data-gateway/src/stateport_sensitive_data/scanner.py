"""Deterministic local detectors with no remote classifier dependency."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import re
from typing import Callable, Iterable

from .contracts import SensitiveDataPolicy, SensitiveFinding


ExactMatcher = Callable[[str], Iterable[tuple[int, int, str]]]


@dataclass(frozen=True)
class _Match:
    start: int
    end: int
    detector: str
    category: str
    confidence: str
    action: str
    stable_key: str


class DeterministicScanner:
    VERSION = "deterministic-local-v1"
    _PRIVATE = re.compile(
        r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |OPENSSH |EC )?PRIVATE KEY-----"
    )
    _PASSWORD_URL = re.compile(r"\b[a-z][a-z0-9+.-]{1,20}://[^\s/:@]+:[^\s/@]+@[^\s]+", re.I)
    _CREDENTIAL = re.compile(
        r"\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|sk-[A-Za-z0-9_-]{20,255}|AKIA[A-Z0-9]{16})\b"
    )
    _EMAIL = re.compile(r"(?<![\w.+-])[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?![\w.-])")
    _POSSIBLE_NAME = re.compile(r"(?im)\b(?:name|contact)\s*:\s*([A-Z][a-z]{1,40}(?:\s+[A-Z][a-z]{1,40}){1,3})\b")

    def __init__(self, *, exact_matcher: ExactMatcher | None = None) -> None:
        self._exact_matcher = exact_matcher

    @staticmethod
    def _finding_id(source_kind: str, match: _Match) -> str:
        material = f"{source_kind}|{match.detector}|{match.category}|{match.start}|{match.end}|{match.stable_key}"
        return "finding." + sha256(material.encode("utf-8")).hexdigest()[:24]

    def scan(self, text: str, *, source_kind: str, policy: SensitiveDataPolicy) -> tuple[SensitiveFinding, ...]:
        if not isinstance(text, str):
            raise TypeError("scanner input must be text")
        matches: list[_Match] = []

        def collect(pattern: re.Pattern[str], detector: str, category: str, confidence: str, action: str, group: int = 0) -> None:
            for item in pattern.finditer(text):
                start, end = item.span(group)
                digest = sha256(item.group(group).encode("utf-8")).hexdigest()
                matches.append(_Match(start, end, detector, category, confidence, action, digest))

        collect(self._PRIVATE, "private-key-structure", "private_key", "confirmed_sensitive", "block")
        collect(self._PASSWORD_URL, "password-url-structure", "credential", "confirmed_sensitive", "block")
        collect(self._CREDENTIAL, "known-credential-format", "credential", "high_confidence", "block")
        collect(self._EMAIL, "local-email-structure", "email", "possible_sensitive", policy.email_action)
        collect(
            self._POSSIBLE_NAME,
            "local-possible-person",
            "person",
            "possible_sensitive",
            policy.possible_person_action,
            1,
        )
        if self._exact_matcher is not None:
            for start, end, secret_id in self._exact_matcher(text):
                matches.append(
                    _Match(
                        start, end, "stored-secret-exact", "stored_secret", "confirmed_sensitive", "block", secret_id,
                    )
                )

        # Prefer the strongest match for overlapping spans and never expose match text.
        rank = {"confirmed_sensitive": 3, "high_confidence": 2, "possible_sensitive": 1, "user_allowlisted": 0}
        selected: list[_Match] = []
        for match in sorted(matches, key=lambda item: (item.start, -rank[item.confidence], -(item.end - item.start))):
            if any(match.start < current.end and current.start < match.end for current in selected):
                continue
            selected.append(match)
        selected.sort(key=lambda item: (item.start, item.end, item.detector))
        return tuple(
            SensitiveFinding(
                finding_id=self._finding_id(source_kind, item),
                detector=item.detector,
                category=item.category,
                confidence=item.confidence,
                source_kind=source_kind,
                start=item.start,
                end=item.end,
                action=item.action,
                scanner_version=self.VERSION,
                policy_id=policy.policy_id,
            )
            for item in selected
        )
