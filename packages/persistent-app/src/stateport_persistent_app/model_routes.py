"""Keep-up loop, level 1: observed, measured and governed model routes.

Implements docs/design/keep-up-loop.md (ADR-0007 section 3, level L1):

- consent for the zero-account OpenCode free route (``opencode-free``), with
  the exact terms text and its sha256;
- catalogue observation with the bundled ``opencode`` binary, an isolated
  HOME and no credentials; observations are unioned over time because the
  free catalogue changes from call to call;
- a short probe (one tiny prompt) before any measurement, because a listed
  model is often not runnable; a failed probe means "unavailable now", never
  a quality failure;
- the frozen StatePort-owned suite (``fixtures/model-suite/v1``) graded by
  deterministic checkers, run serially through the agent sandbox;
- the decide rule (a candidate must beat the incumbent with no regression);
- apply under an owner lease, or as a proposal; owner pins are never changed;
- a daily schedule whose deterministic gate runs first;
- an append-only, hash-chained receipt log.

Nothing here reads owner data. Model calls happen only through the sandbox
runner (``agent_sandbox.run_in_sandbox``) and only after consent.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import statistics
import tempfile
import threading
import time
from typing import Any, Callable, Iterable, Mapping
import uuid

FORMAT_PROJECTION = "stateport.models-projection/v1"
FORMAT_CONSENT = "stateport.model-route-consent/v1"
FORMAT_CATALOGUE = "stateport.model-catalogue/v1"
FORMAT_POLICY = "stateport.model-route-policy/v1"
FORMAT_RUN = "stateport.model-suite-run/v1"
FORMAT_RECEIPT = "stateport.model-route-receipt/v1"
FORMAT_SUITE = "stateport.model-suite/v1"

DESTINATION_FREE = "opencode-free"
DESTINATIONS = (DESTINATION_FREE,)
ACTION_CLASSES = ("agent.edit-state", "chat")
HARNESS = "opencode"
#: Measured 2026-10-21 with the pinned opencode 1.18.31 (isolated HOME, a
#: logging CONNECT proxy): ``opencode models`` reaches only
#: models.opencode.ai:443 and ``opencode run`` on a free model adds
#: opencode.ai:443 (the Zen API, https://opencode.ai/zen/v1). OpenCode also
#: tries registry.npmjs.org:443 to install ``@opencode-ai/plugin`` into a fresh
#: config directory; that host is deliberately NOT allowed (runtime code
#: download, unpinned).
FREE_ROUTE_ALLOW_HOSTS = ("opencode.ai", "models.opencode.ai")

TERMS_PROVIDER = "OpenCode Zen"
TERMS_URL = "https://opencode.ai/docs/zen"
TERMS_TEXT = (
    "Free models are offered by OpenCode Zen, a service of the OpenCode project, not by StatePort. "
    "When you use a free model, StatePort sends the request, the instance context it includes with it, "
    "and the files the agent works on to OpenCode Zen over the internet, without an account or key. "
    "During a model's free period, OpenCode states that the data it collects may be used to improve that model. "
    "StatePort's practice tasks send only StatePort's own sample files, never your work. "
    "You can withdraw this consent at any time on the Models page; free-model routes then stop. "
    "Provider terms: https://opencode.ai/docs/zen"
)
TERMS_SHA256 = "sha256:" + hashlib.sha256(TERMS_TEXT.encode("utf-8")).hexdigest()

OBSERVE_TIMEOUT_SECONDS = 60
OBSERVE_CALLS = 3
PROBE_TIMEOUT_SECONDS = 30
PROBE_PROMPT = "Reply with exactly the word READY and nothing else. Do not use any tools."
TASK_TIMEOUT_SECONDS = 180
MAX_MODELS_PER_RUN = 3
MAX_PROBES_PER_TICK = 6
SCHEDULE_INTERVAL_SECONDS = 24 * 3600
SCHEDULE_INITIAL_DELAY_SECONDS = 5.0
AVAILABILITY_WINDOW_SECONDS = 7 * 24 * 3600
STALE_MEASUREMENT_SECONDS = 7 * 24 * 3600
PROBE_RETRY_SECONDS = 24 * 3600
LEASE_DEFAULT_DAYS = 30
LEASE_MAX_DAYS = 30
DEFAULT_MAX_SUITE_RUNS_PER_DAY = 1
SPEEDUP_FACTOR = 0.8
RECEIPT_TAIL = 50
MAX_CATALOGUE_MODELS = 500
MAX_RESULT_FILES = 200
MAX_PROPOSALS = 20
MAX_STATE_FILE_BYTES = 4 * 1024 * 1024
MAX_CATALOGUE_CACHE_BYTES = 16 * 1024 * 1024
MAX_OUTPUT_BYTES = 1 << 20
#: A runner call that has not returned this long after its own limit is abandoned
#: (the sandbox's own wall-clock kill should have fired; this is the backstop).
HARD_TIMEOUT_GRACE_SECONDS = 15.0
MAX_ALARMS = 10
#: Environment flags of the pinned opencode 1.18.31 that switch off update
#: checks, default plugin installs, LSP downloads and sharing for observation.
OPENCODE_QUIET_FLAGS = {
    "OPENCODE_DISABLE_AUTOUPDATE": "1",
    "OPENCODE_DISABLE_DEFAULT_PLUGINS": "1",
    "OPENCODE_DISABLE_LSP_DOWNLOAD": "1",
    "OPENCODE_DISABLE_SHARE": "1",
    "OPENCODE_DISABLE_CLAUDE_CODE": "1",
    "OPENCODE_DISABLE_EXTERNAL_SKILLS": "1",
}

_MODEL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,255}$")
_RUN_ID = re.compile(r"^run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$")
_PROPOSAL_ID = re.compile(r"^proposal-[0-9a-f]{12}$")
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_VERSION = re.compile(r"([0-9]+\.[0-9]+\.[0-9]+)")


class ModelRoutesError(Exception):
    """A typed, public-safe refusal (code + message + HTTP status)."""

    def __init__(self, code: str, message: str, status: int = 409) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


class SuiteError(ModelRoutesError):
    def __init__(self, message: str) -> None:
        super().__init__("suite_invalid", message, 503)


# ---------------------------------------------------------------------------
# small helpers


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _iso(moment: float) -> str:
    return datetime.fromtimestamp(moment, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(value: object) -> float | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None


def is_free_model(model_id: str) -> bool:
    """The zero-account free route: OpenCode Zen models whose id ends in ``-free``."""
    return model_id.startswith("opencode/") and model_id.endswith("-free")


def destination_of(model_id: str) -> str:
    if is_free_model(model_id):
        return DESTINATION_FREE
    provider = model_id.split("/", 1)[0] if "/" in model_id else "unknown"
    return f"{provider}-account"


def valid_model_id(value: object) -> bool:
    return isinstance(value, str) and _MODEL_ID.fullmatch(value) is not None and "/" in value


def parse_models_output(text: str) -> list[str]:
    """Model ids from ``opencode models`` stdout: one ``provider/model`` per line."""
    seen: list[str] = []
    for raw in text.splitlines():
        line = _ANSI.sub("", raw).strip()
        if not line or any(character.isspace() for character in line):
            continue
        if valid_model_id(line) and line not in seen:
            seen.append(line)
            if len(seen) >= MAX_CATALOGUE_MODELS:
                break
    return seen


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, raw = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(raw)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(value, sort_keys=True, indent=1, ensure_ascii=False) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        temporary = None  # type: ignore[assignment]
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _read_json(path: Path) -> Any:
    """Return the parsed file, or None when absent, unsafe, oversized or corrupt (fail closed)."""
    try:
        if not os.path.lexists(path) or path.is_symlink() or not path.is_file():
            return None
        if path.stat().st_size > MAX_STATE_FILE_BYTES:
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None


# ---------------------------------------------------------------------------
# receipts


class ReceiptLog:
    """Append-only JSONL receipts, hash-chained (each line names the previous digest)."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._sequence: int | None = None
        self._last_digest: str | None = None

    def _load_tail(self) -> None:
        if self._sequence is not None:
            return
        self._sequence, self._last_digest = 0, None
        for record in self.tail(1):
            sequence = record.get("sequence")
            if isinstance(sequence, int):
                self._sequence = sequence
                self._last_digest = record.get("digest") if isinstance(record.get("digest"), str) else None

    def append(self, receipt_type: str, *, by: str, at: float, **fields: Any) -> dict[str, Any]:
        with self._lock:
            self._load_tail()
            assert self._sequence is not None
            record: dict[str, Any] = {
                "formatVersion": FORMAT_RECEIPT,
                "receiptId": "mr-" + uuid.uuid4().hex[:16],
                "sequence": self._sequence + 1,
                "type": receipt_type,
                "at": _iso(at),
                "by": by,
                "previousDigest": self._last_digest,
                **fields,
            }
            record["digest"] = _digest(record)
            line = _canonical(record) + "\n"
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            descriptor = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            try:
                os.write(descriptor, line.encode("utf-8"))
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            self._sequence = record["sequence"]
            self._last_digest = record["digest"]
            return record

    def tail(self, count: int = RECEIPT_TAIL) -> list[dict[str, Any]]:
        try:
            if not self.path.is_file() or self.path.is_symlink():
                return []
            with self.path.open("rb") as handle:
                handle.seek(0, os.SEEK_END)
                size = handle.tell()
                handle.seek(max(0, size - 512 * 1024))
                data = handle.read()
        except OSError:
            return []
        records: list[dict[str, Any]] = []
        for line in data.decode("utf-8", errors="replace").splitlines()[-count:]:
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                records.append(value)
        return records

    def verify(self) -> tuple[bool, str]:
        """Check the whole chain (tests and diagnostics)."""
        previous: str | None = None
        expected = 1
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines() if self.path.exists() else []
        except OSError:
            return False, "receipt log unreadable"
        for line in lines:
            record = json.loads(line)
            digest = record.pop("digest", None)
            if record.get("sequence") != expected or record.get("previousDigest") != previous:
                return False, f"chain broken at sequence {expected}"
            if digest != _digest(record):
                return False, f"digest mismatch at sequence {expected}"
            previous, expected = digest, expected + 1
        return True, f"{expected - 1} receipts verified"


# ---------------------------------------------------------------------------
# the frozen suite


@dataclass(frozen=True)
class SuiteTask:
    task_id: str
    title: str
    repository: Path
    instruction: str
    checker_name: str
    checker: Callable[[Path, Path], tuple[bool, str]]
    critical: bool


@dataclass(frozen=True)
class Suite:
    suite_id: str
    version: int
    digest: str
    preamble: str
    timeout_seconds: int
    tasks: tuple[SuiteTask, ...]
    root: Path

    def prompt(self, task: SuiteTask) -> str:
        return f"{self.preamble}\n\nTask: {task.instruction}"

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.suite_id,
            "version": self.version,
            "digest": self.digest,
            "taskCount": len(self.tasks),
            "taskTimeoutSeconds": self.timeout_seconds,
            "tasks": [{"id": task.task_id, "title": task.title, "critical": task.critical} for task in self.tasks],
        }


_MANIFEST_NAME = "manifest.json"
_SUITE_BASE_KEYS = ("formatVersion", "suiteId", "version", "actionClasses", "taskTimeoutSeconds", "promptPreamble", "tasks")


def _suite_files(root: Path) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    for current, directories, names in os.walk(root, followlinks=False):
        directories[:] = sorted(name for name in directories if name != "__pycache__")
        for name in sorted(names):
            path = Path(current) / name
            relative = path.relative_to(root).as_posix()
            if relative == _MANIFEST_NAME or name.endswith(".pyc"):
                continue
            if path.is_symlink() or not path.is_file():
                raise SuiteError(f"suite file is not a regular file: {relative}")
            entries.append({"path": relative, "sha256": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()})
    return sorted(entries, key=lambda item: item["path"])


def build_suite_manifest(root: Path, base: Mapping[str, Any]) -> dict[str, Any]:
    """Compute the manifest (file digests + suite digest) for a suite directory."""
    manifest = {key: base[key] for key in _SUITE_BASE_KEYS}
    manifest["files"] = _suite_files(root)
    manifest["suiteDigest"] = _digest(manifest)
    return manifest


def load_suite(root: Path) -> Suite:
    manifest = _read_json(root / _MANIFEST_NAME)
    if not isinstance(manifest, dict) or manifest.get("formatVersion") != FORMAT_SUITE:
        raise SuiteError("the model suite manifest is missing or has the wrong format")
    try:
        expected = build_suite_manifest(root, manifest)
    except KeyError:
        raise SuiteError("the model suite manifest is incomplete") from None
    if expected["files"] != manifest.get("files"):
        raise SuiteError("the model suite files do not match the manifest (the suite is frozen)")
    if expected["suiteDigest"] != manifest.get("suiteDigest"):
        raise SuiteError("the model suite digest does not match its manifest")
    checks_path = root / "checks.py"
    module_name = "stateport_model_suite_" + manifest["suiteDigest"][7:19]
    spec = importlib.util.spec_from_file_location(module_name, checks_path)
    if spec is None or spec.loader is None:
        raise SuiteError("the model suite checkers cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception:  # noqa: BLE001 - a broken checker file is an invalid suite
        raise SuiteError("the model suite checkers failed to load") from None
    checkers = getattr(module, "CHECKERS", None)
    if not isinstance(checkers, dict):
        raise SuiteError("the model suite declares no checkers")
    tasks: list[SuiteTask] = []
    for item in manifest["tasks"]:
        checker = checkers.get(item.get("checker"))
        repository = (root / str(item.get("repository", ""))).resolve()
        if not callable(checker) or not repository.is_dir() or root.resolve() not in repository.parents:
            raise SuiteError(f"model suite task {item.get('id')!r} is incomplete")
        tasks.append(SuiteTask(
            task_id=str(item["id"]), title=str(item["title"]), repository=repository,
            instruction=str(item["instruction"]), checker_name=str(item["checker"]),
            checker=checker, critical=bool(item.get("critical", True)),
        ))
    timeout = manifest["taskTimeoutSeconds"]
    if not isinstance(timeout, int) or not 1 <= timeout <= 600 or not tasks:
        raise SuiteError("the model suite limits are invalid")
    return Suite(
        suite_id=str(manifest["suiteId"]), version=int(manifest["version"]), digest=manifest["suiteDigest"],
        preamble=str(manifest["promptPreamble"]), timeout_seconds=timeout, tasks=tuple(tasks), root=root,
    )


# ---------------------------------------------------------------------------
# the decide rule (pure)


@dataclass(frozen=True)
class Measurement:
    model: str
    passed: frozenset[str]
    total: int
    median_seconds: float
    run_id: str
    finished_at: str
    timeouts: int = 0
    is_retry: bool = False

    def score(self) -> dict[str, Any]:
        return {
            "passed": len(self.passed), "total": self.total, "medianSeconds": round(self.median_seconds, 2),
            "runId": self.run_id, "finishedAt": self.finished_at, "timeouts": self.timeouts,
        }


@dataclass(frozen=True)
class Decision:
    action: str            # "keep" | "switch" | "none"
    model: str | None      # the target of a switch, the kept incumbent, or None
    reason: str
    candidate: Measurement | None = None
    incumbent: Measurement | None = None


def beats(candidate: Measurement, incumbent: Measurement) -> bool:
    """No regression on any task the incumbent passes, then more passes or clearly faster."""
    if not incumbent.passed <= candidate.passed:
        return False
    if len(candidate.passed) > len(incumbent.passed):
        return True
    return candidate.median_seconds < SPEEDUP_FACTOR * incumbent.median_seconds


def _rank(measurement: Measurement) -> tuple[int, float, str]:
    return (-len(measurement.passed), measurement.median_seconds, measurement.model)


def decide(incumbent: str | None, measurements: Mapping[str, Measurement], usable: Iterable[str]) -> Decision:
    """Choose the route for one action class.

    ``measurements`` holds the latest complete result per model for the
    current suite digest; ``usable`` is the set of models currently available
    (recently listed and not failing their last probe). A model without a
    measurement never wins, and a measurement with zero passes never takes a
    route. Ties keep the incumbent.
    """
    usable_set = set(usable)
    eligible = {model: item for model, item in measurements.items() if model in usable_set and item.passed}
    if incumbent is None or incumbent not in usable_set:
        reason = "no_incumbent" if incumbent is None else "incumbent_unavailable"
        if not eligible:
            return Decision("none", None, "no_measured_route")
        best = min(eligible.values(), key=_rank)
        return Decision("switch", best.model, reason, candidate=best)
    current = measurements.get(incumbent)
    if current is None:
        return Decision("keep", incumbent, "incumbent_unmeasured")
    better = [item for model, item in eligible.items() if model != incumbent and beats(item, current)]
    if not better:
        return Decision("keep", incumbent, "incumbent_best", incumbent=current)
    best = min(better, key=_rank)
    return Decision("switch", best.model, "candidate_better", candidate=best, incumbent=current)


# ---------------------------------------------------------------------------
# route resolution types


@dataclass(frozen=True)
class RouteRefusal:
    code: str
    message: str
    status: str = "refused"

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message}


@dataclass(frozen=True)
class ResolvedRoute:
    action_class: str
    model: str
    destination: str
    harness_binary: Path
    policy_digest: str


REFUSAL_MESSAGES = {
    "route_not_consented": (
        "Free models need your consent first: StatePort would send this work to OpenCode Zen. "
        "Accept the terms on the Models page."
    ),
    "no_measured_route": "No measured free model is available yet; evaluate the free models on the Models page.",
    "route_not_configured": (
        "No model is chosen for this action yet. Choose one on the Models page or accept the pending proposal."
    ),
    "harness_unavailable": "The pinned OpenCode executable is not installed in this runtime.",
}


def resolve_harness_binary(environment: Mapping[str, str] | None = None) -> Path | None:
    """The bundled opencode: ``STATEPORT_OPENCODE_BINARY`` when set, else ``opencode`` on PATH."""
    source = os.environ if environment is None else environment
    explicit = str(source.get("STATEPORT_OPENCODE_BINARY", "") or "").strip()
    candidate = explicit or shutil.which("opencode", path=source.get("PATH"))
    if not candidate:
        return None
    path = Path(candidate)
    if not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
        return None
    return path


# ---------------------------------------------------------------------------
# failure classes (measured on the free route, 2026-10-21, opencode 1.18.31)

FAILURE_MODEL_UNAVAILABLE = "model_unavailable"   # 410 deprecated, 402 endpoint unavailable, model not found
FAILURE_UPSTREAM = "upstream_error"               # "Unexpected server error", 5xx
FAILURE_RATE_LIMITED = "rate_limited"             # 429
FAILURE_FREE_LIMIT = "free_usage_limit"           # "Free usage limit reached. Subscribe to OpenCode Go" (2026-10-22)
FAILURE_HARNESS = "harness_misconfigured"         # 403 "free tier can only be used from within OpenCode"
FAILURE_TIMEOUT = "timeout"
FAILURE_REFUSED = "sandbox_refused"
FAILURE_EMPTY = "empty_reply"
FAILURE_UNKNOWN = "failed"
#: Failures that say "not runnable now", never "low quality": the model is dropped
#: from candidates until it is seen working again (a later probe).
UNAVAILABLE_FAILURES = frozenset({FAILURE_MODEL_UNAVAILABLE, FAILURE_UPSTREAM, FAILURE_RATE_LIMITED, FAILURE_FREE_LIMIT})

_FAILURE_CODES = {
    FAILURE_MODEL_UNAVAILABLE: FAILURE_MODEL_UNAVAILABLE, "provider_model_unavailable": FAILURE_MODEL_UNAVAILABLE,
    FAILURE_UPSTREAM: FAILURE_UPSTREAM, "provider_upstream_unavailable": FAILURE_UPSTREAM,
    FAILURE_RATE_LIMITED: FAILURE_RATE_LIMITED, "provider_quota_exceeded": FAILURE_RATE_LIMITED,
    FAILURE_HARNESS: FAILURE_HARNESS, FAILURE_TIMEOUT: FAILURE_TIMEOUT, "provider_timed_out": FAILURE_TIMEOUT,
}
_HARNESS_TEXT = re.compile(r"free tier can only be used from within opencode", re.I)
# The free route's own limit for this computer. It names no model, so it is matched before the patterns that
# would read its HTTP status as "this model is gone".
_FREE_LIMIT_TEXT = re.compile(r"free usage (?:limit|exceeded)|freeusagelimit|subscribe to opencode go", re.I)
_UNAVAILABLE_TEXT = re.compile(
    r"\b410\b|deprecated|\b402\b|endpoint is unavailable|model ?not ?found|did you mean|unknown model|"
    r"modelnotfound", re.I)
_RATE_TEXT = re.compile(r"\b429\b|rate[ _-]?limit|too many requests", re.I)
_UPSTREAM_TEXT = re.compile(r"unexpected server error|internal server error|bad gateway|service unavailable|"
                            r"overloaded|\b50[0-9]\b", re.I)


def classify_run_failure(result: Any) -> str | None:
    """None when a sandbox run completed; otherwise one failure class.

    Integration contract with the sandbox: for ``status == "failed"`` the
    sandbox puts a typed cause in ``refusal`` (one of the codes above or a
    ``provider_failure`` code) and may expose bounded diagnostic text as
    ``error_text``; both are only matched against fixed patterns here.
    """
    status = getattr(result, "status", "failed")
    if status == "completed":
        return None
    if status == "timeout":
        return FAILURE_TIMEOUT
    if status == "refused":
        return FAILURE_REFUSED
    code = getattr(result, "refusal", None)
    text = " ".join(
        str(item) for item in (code or "", getattr(result, "error_text", "") or "", getattr(result, "final_text", "") or "")
    )[:16384]
    if _FREE_LIMIT_TEXT.search(text):
        return FAILURE_FREE_LIMIT
    if isinstance(code, str) and code in _FAILURE_CODES:
        return _FAILURE_CODES[code]
    if _HARNESS_TEXT.search(text):
        return FAILURE_HARNESS
    if _UNAVAILABLE_TEXT.search(text):
        return FAILURE_MODEL_UNAVAILABLE
    if _RATE_TEXT.search(text):
        return FAILURE_RATE_LIMITED
    if _UPSTREAM_TEXT.search(text):
        return FAILURE_UPSTREAM
    return FAILURE_UNKNOWN


class _HardTimeout:
    """Stand-in result for a runner call abandoned past its limit."""

    def __init__(self, seconds: float) -> None:
        self.status = "timeout"
        self.refusal = None
        self.exit_code = None
        self.duration_seconds = seconds
        self.final_text = ""
        self.events = 0
        self.tokens: dict[str, int] = {}
        self.egress: tuple[dict, ...] = ()
        self.sandbox_digest = ""


class _HarnessMisconfigured(Exception):
    pass


Runner = Callable[..., Any]


def _default_runner(**kwargs: Any) -> Any:
    from . import agent_sandbox

    return agent_sandbox.run_in_sandbox(**kwargs)


def _sandbox_route(binary: Path, model: str, tools: str) -> Any:
    from .agent_sandbox import SandboxRoute

    return SandboxRoute(
        harness=HARNESS, harness_binary=binary, model=model,
        allow_hosts=FREE_ROUTE_ALLOW_HOSTS, credential_file=None, tools=tools,
    )


# ---------------------------------------------------------------------------
# the service


class ModelRoutes:
    """State, observation, measurement, decision and apply for model routes."""

    def __init__(
        self,
        root: Path,
        *,
        suite_root: Path,
        runner: Runner | None = None,
        clock: Callable[[], float] = time.time,
        harness_resolver: Callable[[], Path | None] = resolve_harness_binary,
        log_writer: Callable[[str], None] | None = None,
        observe_calls: int = OBSERVE_CALLS,
    ) -> None:
        self.root = Path(root)
        self.suite_root = Path(suite_root)
        self._runner = runner or _default_runner
        self._clock = clock
        self._harness_resolver = harness_resolver
        self._log = log_writer
        self._observe_calls = max(1, int(observe_calls))
        self._lock = threading.RLock()
        self._run_lock = threading.Lock()
        self._active_run: str | None = None
        self._stop = threading.Event()
        self._scheduler: threading.Thread | None = None
        self._last_gate: dict[str, Any] | None = None
        self._next_tick_at: float | None = None
        self.receipts = ReceiptLog(self.root / "receipts.jsonl")
        self._suite: Suite | None = None
        self._suite_error: str | None = None
        self._run_cache: dict[str, tuple[tuple[int, int], Any]] = {}
        self._cache_digest: str | None = None
        self._reconcile_interrupted_runs()

    # -- paths and state files ------------------------------------------------

    @property
    def consent_path(self) -> Path:
        return self.root / "consent.json"

    @property
    def catalogue_path(self) -> Path:
        return self.root / "catalogue.json"

    @property
    def policy_path(self) -> Path:
        return self.root / "policy.json"

    @property
    def results_root(self) -> Path:
        return self.root / "results"

    @property
    def work_root(self) -> Path:
        return self.root / "work"

    def _now(self) -> float:
        return float(self._clock())

    def _emit(self, line: str) -> None:
        if self._log is not None:
            try:
                self._log(f"model_routes {line}\n")
            except Exception:  # noqa: BLE001 - logging never breaks the loop
                pass

    def _receipt(self, receipt_type: str, *, by: str, **fields: Any) -> dict[str, Any]:
        return self.receipts.append(receipt_type, by=by, at=self._now(), **fields)

    # -- suite ---------------------------------------------------------------

    def suite(self) -> Suite:
        with self._lock:
            if self._suite is None:
                try:
                    self._suite = load_suite(self.suite_root)
                    self._suite_error = None
                except SuiteError as exc:
                    self._suite_error = exc.message
                    raise
            return self._suite

    def _suite_projection(self) -> dict[str, Any]:
        try:
            return {"valid": True, **self.suite().summary()}
        except SuiteError as exc:
            return {"valid": False, "reason": exc.message}

    # -- consent ---------------------------------------------------------------

    def _consent(self) -> dict[str, Any]:
        value = _read_json(self.consent_path)
        if not isinstance(value, dict) or value.get("formatVersion") != FORMAT_CONSENT:
            return {"formatVersion": FORMAT_CONSENT, "destinations": {}}
        destinations = value.get("destinations")
        return {"formatVersion": FORMAT_CONSENT, "destinations": destinations if isinstance(destinations, dict) else {}}

    def consent_state(self, destination: str = DESTINATION_FREE) -> str:
        entry = self._consent()["destinations"].get(destination)
        if not isinstance(entry, dict):
            return "not_granted"
        return "granted" if entry.get("termsSha256") == TERMS_SHA256 else "stale"

    def consented(self, destination: str = DESTINATION_FREE) -> bool:
        return self.consent_state(destination) == "granted"

    def terms(self) -> dict[str, str]:
        return {"provider": TERMS_PROVIDER, "url": TERMS_URL, "text": TERMS_TEXT, "sha256": TERMS_SHA256}

    def grant_consent(self, destination: object, terms_sha256: object, *, by: str) -> dict[str, Any]:
        if destination not in DESTINATIONS:
            raise ModelRoutesError("destination_unsupported", "only the opencode-free destination can be consented here", 400)
        if terms_sha256 != TERMS_SHA256:
            raise ModelRoutesError(
                "terms_mismatch",
                "the terms digest does not match the current terms text; reload the Models page and read the terms again",
            )
        with self._lock:
            consent = self._consent()
            consent["destinations"][DESTINATION_FREE] = {
                "grantedAt": _iso(self._now()), "grantedBy": by, "termsText": TERMS_TEXT,
                "termsSha256": TERMS_SHA256, "termsUrl": TERMS_URL, "provider": TERMS_PROVIDER,
            }
            _write_json(self.consent_path, consent)
            self._receipt("consent.granted", by=by, destination=DESTINATION_FREE, termsSha256=TERMS_SHA256, termsUrl=TERMS_URL)
        return self.projection()

    def withdraw_consent(self, destination: object = DESTINATION_FREE, *, by: str) -> dict[str, Any]:
        if destination not in DESTINATIONS:
            raise ModelRoutesError("destination_unsupported", "only the opencode-free destination can be withdrawn here", 400)
        with self._lock:
            consent = self._consent()
            had = consent["destinations"].pop(DESTINATION_FREE, None) is not None
            _write_json(self.consent_path, consent)
            policy = self._policy()
            for action_class, route in policy["routes"].items():
                if route.get("model") and destination_of(route["model"]) == DESTINATION_FREE:
                    previous = route["model"]
                    policy["routes"][action_class] = self._route_entry(None, pinned=False, by=by, why="consent withdrawn")
                    self._receipt("route.changed", by=by, actionClass=action_class, **{"from": previous, "to": None}, why="consent withdrawn")
            if policy["lease"].get("enabled"):
                policy["lease"] = {**policy["lease"], "enabled": False, "revokedAt": _iso(self._now()), "revokedBy": by}
                self._receipt("lease.revoked", by=by, why="consent withdrawn")
            for proposal in policy["proposals"]:
                if proposal.get("status") == "pending":
                    proposal.update(status="superseded", decidedAt=_iso(self._now()), decidedBy=by)
            self._write_policy(policy)
            self._receipt("consent.withdrawn", by=by, destination=DESTINATION_FREE, hadConsent=had)
        return self.projection()

    def _require_consent(self) -> None:
        if not self.consented(DESTINATION_FREE):
            raise ModelRoutesError("route_not_consented", REFUSAL_MESSAGES["route_not_consented"])

    # -- policy ----------------------------------------------------------------

    def _route_entry(self, model: str | None, *, pinned: bool, by: str, why: str) -> dict[str, Any]:
        return {"model": model, "pinned": bool(pinned), "setBy": by, "setAt": _iso(self._now()), "why": why}

    def _default_policy(self) -> dict[str, Any]:
        return {
            "formatVersion": FORMAT_POLICY,
            "routes": {name: {"model": None, "pinned": False, "setBy": None, "setAt": None, "why": "safe default"} for name in ACTION_CLASSES},
            "lease": {"enabled": False, "grantedAt": None, "expiresAt": None, "maxSuiteRunsPerDay": DEFAULT_MAX_SUITE_RUNS_PER_DAY},
            "proposals": [],
        }

    def _policy(self) -> dict[str, Any]:
        """The policy, or the safe default (no route) when absent or unreadable: it never widens."""
        value = _read_json(self.policy_path)
        policy = self._default_policy()
        if not isinstance(value, dict) or value.get("formatVersion") != FORMAT_POLICY:
            return policy
        routes = value.get("routes")
        if isinstance(routes, dict):
            for name in ACTION_CLASSES:
                entry = routes.get(name)
                if isinstance(entry, dict) and (entry.get("model") is None or valid_model_id(entry.get("model"))):
                    policy["routes"][name] = {
                        "model": entry.get("model"), "pinned": entry.get("pinned") is True,
                        "setBy": entry.get("setBy"), "setAt": entry.get("setAt"), "why": entry.get("why"),
                    }
        lease = value.get("lease")
        if isinstance(lease, dict):
            runs = lease.get("maxSuiteRunsPerDay")
            policy["lease"] = {
                **lease,
                "enabled": lease.get("enabled") is True and _parse_iso(lease.get("expiresAt")) is not None,
                "maxSuiteRunsPerDay": runs if isinstance(runs, int) and 0 <= runs <= 4 else DEFAULT_MAX_SUITE_RUNS_PER_DAY,
            }
        proposals = value.get("proposals")
        if isinstance(proposals, list):
            policy["proposals"] = [item for item in proposals if isinstance(item, dict) and isinstance(item.get("id"), str)][-MAX_PROPOSALS:]
        return policy

    def _write_policy(self, policy: dict[str, Any]) -> None:
        policy["proposals"] = policy["proposals"][-MAX_PROPOSALS:]
        _write_json(self.policy_path, policy)

    def policy_digest(self) -> str:
        policy = self._policy()
        return _digest({"routes": policy["routes"], "lease": policy["lease"]})

    def lease_active(self, policy: Mapping[str, Any] | None = None) -> bool:
        lease = (policy or self._policy())["lease"]
        expires = _parse_iso(lease.get("expiresAt"))
        return bool(lease.get("enabled")) and expires is not None and self._now() < expires and self.consented()

    # -- catalogue -------------------------------------------------------------

    def _catalogue(self) -> dict[str, Any]:
        value = _read_json(self.catalogue_path)
        if not isinstance(value, dict) or value.get("formatVersion") != FORMAT_CATALOGUE or not isinstance(value.get("models"), dict):
            return {"formatVersion": FORMAT_CATALOGUE, "observedAt": None, "observations": 0, "harness": None,
                    "lastListed": [], "models": {}, "lastError": None}
        return value

    def usable_models(self, catalogue: Mapping[str, Any] | None = None) -> set[str]:
        """Free models seen within the availability window whose last probe did not fail."""
        catalogue = catalogue or self._catalogue()
        now = self._now()
        usable: set[str] = set()
        for model_id, entry in catalogue["models"].items():
            if not isinstance(entry, dict) or not is_free_model(model_id):
                continue
            seen = _parse_iso(entry.get("lastSeenAt"))
            if seen is None or now - seen > AVAILABILITY_WINDOW_SECONDS:
                continue
            probe = entry.get("lastProbe")
            if isinstance(probe, dict) and probe.get("status") in {"unavailable", "timeout"}:
                continue   # dropped until a later probe sees it working again
            usable.add(model_id)
        return usable

    def _seen_recently(self, catalogue: Mapping[str, Any], model_id: str) -> bool:
        entry = catalogue["models"].get(model_id)
        seen = _parse_iso(entry.get("lastSeenAt")) if isinstance(entry, dict) else None
        return seen is not None and self._now() - seen <= AVAILABILITY_WINDOW_SECONDS

    def _observe_environment(self, home: Path) -> dict[str, str]:
        return {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": str(home),
            "XDG_CONFIG_HOME": str(home / ".config"),
            "XDG_DATA_HOME": str(home / ".local" / "share"),
            "XDG_STATE_HOME": str(home / ".local" / "state"),
            "XDG_CACHE_HOME": str(home / ".cache"),
            "TMPDIR": str(home / "tmp"),
            "LANG": "C.UTF-8",
            **OPENCODE_QUIET_FLAGS,
        }

    def _run_harness(self, binary: Path, arguments: tuple[str, ...], *, timeout: float, harvest: bool = False) -> Any:
        from external_engine_runtime import ProcessSpec, run_process

        self.work_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        home = Path(tempfile.mkdtemp(prefix="observe-", dir=self.work_root))
        try:
            (home / "tmp").mkdir()
            result = run_process(ProcessSpec(
                (str(binary), *arguments), home, timeout_seconds=timeout,
                max_output_bytes=MAX_OUTPUT_BYTES, environment=self._observe_environment(home),
            ))
            if harvest and result.ok:
                self._store_catalogue_cache(home / ".cache" / "opencode" / "models.json")
            return result
        finally:
            shutil.rmtree(home, ignore_errors=True)

    @property
    def _cache_file(self) -> Path:
        return self.root / "cache" / "models.json"

    def catalogue_cache_path(self) -> Path | None:
        """The raw ``models.json`` the last successful observation fetched, or None.

        One shared file: the sandbox pre-seeds each per-run OpenCode HOME from it
        (read-only) so a cold HOME never falls back to the binary's stale bundled
        snapshot. Replaced atomically; never partially written.
        """
        path = self._cache_file
        return path if path.is_file() and not path.is_symlink() else None

    def _store_catalogue_cache(self, source: Path) -> None:
        try:
            if source.is_symlink() or not source.is_file() or source.stat().st_size > MAX_CATALOGUE_CACHE_BYTES:
                return
            data = source.read_bytes()
            if not isinstance(json.loads(data.decode("utf-8")), dict):
                return
        except (OSError, UnicodeError, json.JSONDecodeError):
            return
        target = self._cache_file
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor, raw = tempfile.mkstemp(prefix=".models.json.", suffix=".tmp", dir=target.parent)
        temporary: Path | None = Path(raw)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(raw, 0o644)
            os.replace(raw, target)
            temporary = None
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        self._cache_digest = "sha256:" + hashlib.sha256(data).hexdigest()

    def observe(self, *, by: str) -> dict[str, Any]:
        """Refresh the catalogue: ``opencode models`` with an isolated HOME and no credentials."""
        binary = self._harness_resolver()
        if binary is None:
            raise ModelRoutesError("harness_unavailable", REFUSAL_MESSAGES["harness_unavailable"], 503)
        started = time.monotonic()
        listed: list[str] = []
        version: str | None = None
        failure: str | None = None
        try:
            version_result = self._run_harness(binary, ("--version",), timeout=10)
            match = _VERSION.search(version_result.stdout or "")
            version = match.group(1) if version_result.ok and match else None
            for _ in range(self._observe_calls):
                remaining = OBSERVE_TIMEOUT_SECONDS - (time.monotonic() - started)
                if remaining <= 1:
                    break
                result = self._run_harness(binary, ("models",), timeout=remaining, harvest=True)
                if not result.ok:
                    failure = "observation_timed_out" if result.timed_out else "observation_failed"
                    break
                for model_id in parse_models_output(result.stdout or ""):
                    if model_id not in listed:
                        listed.append(model_id)
        except (OSError, ValueError):
            failure = "observation_failed"
        with self._lock:
            catalogue = self._catalogue()
            now = self._now()
            if failure is not None and not listed:
                catalogue["lastError"] = {"code": failure, "at": _iso(now)}
                _write_json(self.catalogue_path, catalogue)
                self._receipt("catalogue.observation_failed", by=by, code=failure, harnessVersion=version)
                raise ModelRoutesError(failure, "the OpenCode catalogue could not be observed; try again later", 502)
            first = catalogue["observedAt"] is None
            added: list[str] = []
            for model_id in listed:
                entry = catalogue["models"].get(model_id)
                if not isinstance(entry, dict):
                    entry = {"id": model_id, "free": is_free_model(model_id), "destination": destination_of(model_id),
                             "firstSeenAt": _iso(now), "seenCount": 0, "lastProbe": None}
                    added.append(model_id)
                entry["lastSeenAt"] = _iso(now)
                entry["seenCount"] = int(entry.get("seenCount") or 0) + 1
                catalogue["models"][model_id] = entry
            # The catalogue is a union over time: a model vanishes only after it has been
            # unseen for the whole availability window; that is reported once.
            vanished: list[str] = []
            for model_id, entry in sorted(catalogue["models"].items()):
                if not isinstance(entry, dict):
                    continue
                if self._seen_recently(catalogue, model_id):
                    entry.pop("vanishedAt", None)
                elif not entry.get("vanishedAt"):
                    entry["vanishedAt"] = _iso(now)
                    vanished.append(model_id)
            if len(catalogue["models"]) > MAX_CATALOGUE_MODELS:
                ordered = sorted(catalogue["models"].values(), key=lambda item: str(item.get("lastSeenAt")), reverse=True)
                catalogue["models"] = {item["id"]: item for item in ordered[:MAX_CATALOGUE_MODELS]}
            catalogue.update(
                observedAt=_iso(now), observations=int(catalogue.get("observations") or 0) + 1,
                harness={"id": HARNESS, "version": version}, lastListed=listed,
                lastError={"code": failure, "at": _iso(now)} if failure else None,
            )
            if self._cache_digest is not None:
                catalogue["cache"] = {"path": str(self._cache_file), "sha256": self._cache_digest, "storedAt": _iso(now)}
                self._cache_digest = None
            _write_json(self.catalogue_path, catalogue)
            if first or added or vanished:
                self._receipt(
                    "catalogue.observed", by=by, harnessVersion=version, listed=len(listed),
                    added=added, freeAdded=[model for model in added if is_free_model(model)], vanished=vanished,
                )
        return self.projection()

    # -- probing and measurement ------------------------------------------------

    def _require_runnable(self) -> Path:
        self._require_consent()
        binary = self._harness_resolver()
        if binary is None:
            raise ModelRoutesError("harness_unavailable", REFUSAL_MESSAGES["harness_unavailable"], 503)
        return binary

    def _probe_model(self, binary: Path, model: str, *, by: str) -> dict[str, Any]:
        """One tiny prompt through the sandbox (30 s). Failure means unavailable now, not low quality."""
        self.work_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        workdir = Path(tempfile.mkdtemp(prefix="probe-", dir=self.work_root))
        started = time.monotonic()
        failure: str | None
        try:
            result = self._call_runner(
                workdir=workdir, prompt=PROBE_PROMPT, route=_sandbox_route(binary, model, "none"),
                timeout_seconds=PROBE_TIMEOUT_SECONDS, output_limit_bytes=64 * 1024,
            )
            status = str(getattr(result, "status", "failed"))
            text = str(getattr(result, "final_text", "") or "")
            seconds = float(getattr(result, "duration_seconds", time.monotonic() - started) or 0.0)
            refusal = getattr(result, "refusal", None)
            failure = classify_run_failure(result)
        except Exception:  # noqa: BLE001 - a broken runner is an unmeasured probe, never a crash
            status, text, seconds, refusal, failure = "refused", "", time.monotonic() - started, "runner_failed", FAILURE_REFUSED
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
        if failure is None and not text.strip():
            failure = FAILURE_EMPTY
        # ok: answered. unmeasured: the sandbox refused (infrastructure, says nothing about the model).
        # harness_error: our harness setup was rejected (alarm; the model is not penalised).
        # timeout: retried once later. unavailable: deprecated / endpoint gone / not found / upstream error.
        verdict = {None: "ok", FAILURE_REFUSED: "unmeasured", FAILURE_HARNESS: "harness_error",
                   FAILURE_TIMEOUT: "timeout"}.get(failure, "unavailable")
        probe = {"status": verdict, "cause": failure, "at": _iso(self._now()), "seconds": round(seconds, 2),
                 "sandboxStatus": status, "refusal": refusal if isinstance(refusal, str) else None}
        if verdict == "harness_error":
            self._alarm(FAILURE_HARNESS, model=model, by=by,
                        detail="the free route rejected the harness request (for example 403 'free tier can only be used "
                               "from within OpenCode'); this is a StatePort configuration problem, not the model's")
        with self._lock:
            catalogue = self._catalogue()
            entry = catalogue["models"].get(model)
            if isinstance(entry, dict):
                previous = (entry.get("lastProbe") or {}).get("status") if isinstance(entry.get("lastProbe"), dict) else None
                entry["lastProbe"] = probe
                _write_json(self.catalogue_path, catalogue)
                if previous != verdict:
                    self._receipt("model.probed", by=by, model=model, status=verdict, previous=previous,
                                  sandboxStatus=status, refusal=probe["refusal"])
        return probe

    def _call_runner(self, *, timeout_seconds: int, **kwargs: Any) -> Any:
        """Call the sandbox runner with a hard backstop on its wall clock.

        The sandbox kills its own process group at ``timeout_seconds``; if the
        call still has not returned ``HARD_TIMEOUT_GRACE_SECONDS`` later, it is
        abandoned and reported as a timeout so one hung run cannot stall the loop.
        """
        box: dict[str, Any] = {}

        def target() -> None:
            try:
                box["result"] = self._runner(timeout_seconds=timeout_seconds, **kwargs)
            except BaseException as exc:  # noqa: BLE001 - re-raised in the caller
                box["error"] = exc

        thread = threading.Thread(target=target, name="stateport-model-route-runner", daemon=True)
        thread.start()
        thread.join(float(timeout_seconds) + HARD_TIMEOUT_GRACE_SECONDS)
        if thread.is_alive():
            self._emit("event=runner_hard_timeout")
            return _HardTimeout(float(timeout_seconds) + HARD_TIMEOUT_GRACE_SECONDS)
        if "error" in box:
            raise box["error"]
        return box.get("result")

    def _alarm(self, code: str, *, model: str | None, by: str, detail: str) -> None:
        with self._lock:
            catalogue = self._catalogue()
            alarms = [item for item in catalogue.get("alarms") or [] if isinstance(item, dict)]
            alarms.append({"code": code, "model": model, "at": _iso(self._now()), "detail": detail})
            catalogue["alarms"] = alarms[-MAX_ALARMS:]
            _write_json(self.catalogue_path, catalogue)
            self._receipt("harness.alarm", by=by, code=code, model=model, detail=detail)

    def probe(self, model: object, *, by: str) -> dict[str, Any]:
        """Probe one observed free model now (consent required); the result updates the catalogue."""
        if not valid_model_id(model) or str(model) not in self._catalogue()["models"]:
            raise ModelRoutesError("model_unknown", "the model has not been observed in the catalogue; observe first")
        if not is_free_model(str(model)):
            raise ModelRoutesError("destination_unsupported", "only opencode free models can be probed in this release")
        binary = self._require_runnable()
        return self._probe_model(binary, str(model), by=by)

    def _new_run_id(self) -> str:
        return "run-" + datetime.fromtimestamp(self._now(), tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]

    def _run_path(self, run_id: str) -> Path:
        return self.results_root / f"{run_id}.json"

    def _write_run(self, run: dict[str, Any]) -> None:
        _write_json(self._run_path(run["runId"]), run)

    def _validate_models(self, models: object) -> list[str]:
        if not isinstance(models, list) or not models:
            raise ModelRoutesError("models_invalid", "models must be a non-empty list of model ids", 400)
        if len(models) > MAX_MODELS_PER_RUN:
            raise ModelRoutesError("too_many_models", f"at most {MAX_MODELS_PER_RUN} models can be evaluated in one run", 400)
        selected: list[str] = []
        catalogue = self._catalogue()
        for model in models:
            if not valid_model_id(model) or model in selected:
                raise ModelRoutesError("models_invalid", "models must be distinct provider/model ids", 400)
            if model not in catalogue["models"]:
                raise ModelRoutesError("model_unknown", "the model has not been observed in the catalogue; observe first")
            if not is_free_model(model):
                raise ModelRoutesError("destination_unsupported", "only opencode free models can be evaluated in this release")
            selected.append(model)
        return selected

    def start_evaluation(self, models: object, *, by: str, trigger: str = "owner", background: bool = True,
                         retry_models: Iterable[str] = ()) -> dict[str, Any]:
        selected = self._validate_models(models)
        retries = sorted(set(retry_models) & set(selected))
        binary = self._require_runnable()
        suite = self.suite()
        if not self._run_lock.acquire(blocking=False):
            raise ModelRoutesError("evaluation_in_progress", "a suite run is already in progress; wait for it to finish")
        try:
            run_id = self._new_run_id()
            run = {
                "formatVersion": FORMAT_RUN, "runId": run_id, "state": "queued", "trigger": trigger, "by": by,
                "createdAt": _iso(self._now()), "startedAt": None, "finishedAt": None,
                "suite": {"id": suite.suite_id, "version": suite.version, "digest": suite.digest},
                "harness": {"id": HARNESS, "version": (self._catalogue().get("harness") or {}).get("version")},
                "requestedModels": selected, "retryModels": retries,
                "progress": {"completedTasks": 0, "totalTasks": len(selected) * len(suite.tasks), "currentModel": None, "currentTask": None},
                "models": [],
            }
            self._active_run = run_id
            started = self._receipt("suite.run_started", by=by, runId=run_id, trigger=trigger, models=selected,
                                    suiteDigest=suite.digest)
            run["sequence"] = started["sequence"]   # total order of runs, even within one second
            self._write_run(run)
        except BaseException:
            self._active_run = None
            self._run_lock.release()
            raise
        if background:
            threading.Thread(target=self._execute_run, args=(run, suite, binary), name="stateport-model-suite", daemon=True).start()
        else:
            self._execute_run(run, suite, binary)
        return {"runId": run_id, "state": "queued" if background else self.run_status(run_id)["state"]}

    def _measure_model(self, run: dict[str, Any], entry: dict[str, Any], suite: Suite, binary: Path) -> None:
        """Run every suite task serially for one model whose probe answered."""
        model = entry["model"]
        entry["available"] = True
        complete = True
        for task in suite.tasks:
            if self._stop.is_set():
                raise _Interrupted()
            run["progress"]["currentTask"] = task.task_id
            self._write_run(run)
            record = self._run_task(binary, model, suite, task, run["runId"])
            entry["tasks"].append(record)
            run["progress"]["completedTasks"] += 1
            self._write_run(run)
            failure = record.get("failure")
            if failure == FAILURE_HARNESS:
                self._alarm(FAILURE_HARNESS, model=model, by=run["by"],
                            detail="the free route rejected the harness request during a suite task; "
                                   "the run stopped and no model was penalised")
                raise _HarnessMisconfigured()
            if record["status"] == "not_run" or failure in UNAVAILABLE_FAILURES:
                # Not a quality result: the sandbox refused, or the model stopped being served mid-suite.
                complete = False
                if failure in UNAVAILABLE_FAILURES:
                    entry["available"] = False
                    self._mark_unavailable(model, failure, by=run["by"])
                run["progress"]["completedTasks"] += len(suite.tasks) - len(entry["tasks"])
                break
        entry["complete"] = complete
        entry["timeouts"] = sum(1 for item in entry["tasks"] if item.get("failure") == FAILURE_TIMEOUT)
        seconds = [item["seconds"] for item in entry["tasks"]]
        entry["totals"] = {
            "passed": sum(1 for item in entry["tasks"] if item["passed"]),
            "total": len(suite.tasks),
            "medianSeconds": round(statistics.median(seconds), 2) if seconds else None,
        }

    def _mark_unavailable(self, model: str, cause: str, *, by: str) -> None:
        with self._lock:
            catalogue = self._catalogue()
            entry = catalogue["models"].get(model)
            if isinstance(entry, dict):
                entry["lastProbe"] = {"status": "unavailable", "cause": cause, "at": _iso(self._now()), "seconds": 0.0,
                                      "sandboxStatus": "failed", "refusal": None}
                _write_json(self.catalogue_path, catalogue)
                self._receipt("model.probed", by=by, model=model, status="unavailable", cause=cause, during="suite")

    def _execute_run(self, run: dict[str, Any], suite: Suite, binary: Path) -> None:
        try:
            run.update(state="running", startedAt=_iso(self._now()))
            self._write_run(run)
            deferred: list[dict[str, Any]] = []
            for model in run["requestedModels"]:
                entry: dict[str, Any] = {"model": model, "probe": None, "available": False, "complete": False,
                                         "tasks": [], "totals": None, "isRetry": model in run.get("retryModels", [])}
                run["models"].append(entry)
                run["progress"].update(currentModel=model, currentTask="probe")
                self._write_run(run)
                probe = self._probe_model(binary, model, by=run["by"])
                entry["probe"] = probe
                if probe["status"] == "harness_error":
                    raise _HarnessMisconfigured()
                if probe["status"] == "timeout":
                    deferred.append(entry)   # a probe timeout is retried once, after the other models
                    continue
                if probe["status"] != "ok":
                    run["progress"]["completedTasks"] += len(suite.tasks)
                    self._write_run(run)
                    continue
                run["progress"]["currentModel"] = model
                self._measure_model(run, entry, suite, binary)
            for entry in deferred:
                run["progress"].update(currentModel=entry["model"], currentTask="probe")
                self._write_run(run)
                probe = self._probe_model(binary, entry["model"], by=run["by"])
                entry["probe"] = {**probe, "retried": True}
                if probe["status"] == "timeout":
                    # Timed out twice: unavailable now (the schedule tries again in a later window).
                    self._mark_unavailable(entry["model"], FAILURE_TIMEOUT, by=run["by"])
                if probe["status"] != "ok":
                    run["progress"]["completedTasks"] += len(suite.tasks)
                    continue
                self._measure_model(run, entry, suite, binary)
            run.update(state="completed", finishedAt=_iso(self._now()))
            causes = {str((item.get("probe") or {}).get("cause")) for item in run["models"]}
            if run["models"] and causes == {FAILURE_FREE_LIMIT}:
                # Nothing about the models was learned: the free route refused every one of them.
                run["error"] = FAILURE_FREE_LIMIT
            run["progress"].update(currentModel=None, currentTask=None)
            self._write_run(run)
            self._receipt("suite.run_finished", by=run["by"], runId=run["runId"], state="completed",
                          suiteDigest=suite.digest, results=[{"model": item["model"], "available": item["available"],
                                                              "complete": item["complete"], **(item["totals"] or {})}
                                                             for item in run["models"]])
            self._prune_results()
        except _Interrupted:
            run.update(state="interrupted", finishedAt=_iso(self._now()))
            self._write_run(run)
            self._receipt("suite.run_finished", by=run["by"], runId=run["runId"], state="interrupted")
        except _HarnessMisconfigured:
            run.update(state="failed", finishedAt=_iso(self._now()), error=FAILURE_HARNESS)
            self._write_run(run)
            self._receipt("suite.run_finished", by=run["by"], runId=run["runId"], state="failed", error=FAILURE_HARNESS)
        except Exception as exc:  # noqa: BLE001 - a failed run is recorded, never raised into a thread
            run.update(state="failed", finishedAt=_iso(self._now()), error=type(exc).__name__)
            self._write_run(run)
            self._receipt("suite.run_finished", by=run["by"], runId=run["runId"], state="failed", error=type(exc).__name__)
        finally:
            self._active_run = None
            self._run_lock.release()
        if run.get("state") == "completed":
            try:
                self.apply_decisions(by="lease", trigger=run["trigger"])
            except Exception as exc:  # noqa: BLE001
                self._emit(f"event=decide_failed error={type(exc).__name__}")

    def _run_task(self, binary: Path, model: str, suite: Suite, task: SuiteTask, run_id: str) -> dict[str, Any]:
        self.work_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        holder = Path(tempfile.mkdtemp(prefix=f"{run_id[-8:]}-{task.task_id[:24]}-", dir=self.work_root))
        workdir = holder / "work"
        started = time.monotonic()
        record: dict[str, Any] = {"taskId": task.task_id, "passed": False, "seconds": 0.0, "reason": "",
                                  "status": "failed", "failure": None, "sandboxStatus": None, "exitCode": None,
                                  "tokens": {}, "egressDenied": 0}
        try:
            shutil.copytree(task.repository, workdir, symlinks=False)
            try:
                result = self._call_runner(
                    workdir=workdir, prompt=suite.prompt(task), route=_sandbox_route(binary, model, "edit"),
                    timeout_seconds=suite.timeout_seconds, output_limit_bytes=MAX_OUTPUT_BYTES,
                )
            except Exception:  # noqa: BLE001
                record.update(status="not_run", reason="the sandbox runner failed", sandboxStatus="refused",
                              failure=FAILURE_REFUSED)
                return record
            status = str(getattr(result, "status", "failed"))
            failure = classify_run_failure(result)
            record["failure"] = failure
            record["hardTimeout"] = isinstance(result, _HardTimeout)
            record["sandboxStatus"] = status
            record["exitCode"] = getattr(result, "exit_code", None)
            record["seconds"] = round(float(getattr(result, "duration_seconds", time.monotonic() - started) or 0.0), 2)
            tokens = getattr(result, "tokens", None)
            record["tokens"] = {key: int(value) for key, value in tokens.items() if isinstance(value, int)} if isinstance(tokens, dict) else {}
            egress = getattr(result, "egress", ()) or ()
            record["egressDenied"] = sum(1 for item in egress if isinstance(item, dict) and item.get("allowed") is False)
            if status == "refused":
                refusal = getattr(result, "refusal", None)
                record.update(status="not_run", reason=f"sandbox refused: {refusal if isinstance(refusal, str) else 'unknown'}")
                return record
            if failure == FAILURE_HARNESS or failure in UNAVAILABLE_FAILURES:
                record.update(status="not_run", reason=f"not a quality result: {failure}")
                return record
            if status == "timeout":
                record["seconds"] = max(record["seconds"], float(suite.timeout_seconds))
            try:
                passed, reason = task.checker(task.repository, workdir)
            except Exception as exc:  # noqa: BLE001 - CheckError and anything else fail the task
                passed, reason = False, (str(exc)[:200] if type(exc).__name__ == "CheckError" else "checker error")
            # A pass needs both: the run finished inside its limit AND the checker accepts the files.
            if status != "completed":
                reason = f"the run ended with status {status}; checker: {reason}"
                passed = False
            record.update(status="checked", passed=bool(passed), reason=str(reason)[:512])
            return record
        finally:
            shutil.rmtree(holder, ignore_errors=True)

    def _prune_results(self) -> None:
        try:
            files = sorted(self.results_root.glob("run-*.json"))
        except OSError:
            return
        for path in files[:-MAX_RESULT_FILES]:
            path.unlink(missing_ok=True)

    def _reconcile_interrupted_runs(self) -> None:
        if not self.results_root.is_dir():
            return
        for path in sorted(self.results_root.glob("run-*.json"))[-MAX_RESULT_FILES:]:
            run = _read_json(path)
            if isinstance(run, dict) and run.get("state") in {"queued", "running"}:
                run.update(state="interrupted", finishedAt=run.get("finishedAt") or _iso(self._now()))
                _write_json(path, run)
        shutil.rmtree(self.work_root, ignore_errors=True)

    def _runs(self) -> list[dict[str, Any]]:
        runs: list[dict[str, Any]] = []
        if not self.results_root.is_dir():
            return runs
        cache = self._run_cache
        live: set[str] = set()
        for path in sorted(self.results_root.glob("run-*.json"))[-MAX_RESULT_FILES:]:
            try:
                info = path.stat()
            except OSError:
                continue
            key = (info.st_mtime_ns, info.st_size)
            live.add(path.name)
            cached = cache.get(path.name)
            if cached is None or cached[0] != key:
                cached = (key, _read_json(path))
                cache[path.name] = cached
            run = cached[1]
            if isinstance(run, dict) and run.get("formatVersion") == FORMAT_RUN:
                runs.append(run)
        for name in set(cache) - live:
            cache.pop(name, None)
        runs.sort(key=lambda item: (str(item.get("createdAt") or ""), int(item.get("sequence") or 0), str(item.get("runId"))))
        return runs

    def run_status(self, run_id: object) -> dict[str, Any]:
        if not isinstance(run_id, str) or _RUN_ID.fullmatch(run_id) is None:
            raise ModelRoutesError("run_not_found", "the suite run was not found", 404)
        run = _read_json(self._run_path(run_id))
        if not isinstance(run, dict):
            raise ModelRoutesError("run_not_found", "the suite run was not found", 404)
        return run

    def measurements(self, *, suite_digest: str | None = None) -> dict[str, Measurement]:
        """Latest complete, available measurement per model for the current suite digest."""
        if suite_digest is None:
            try:
                suite_digest = self.suite().digest
            except SuiteError:
                return {}
        latest: dict[str, Measurement] = {}
        for run in self._runs():
            if run.get("state") != "completed" or (run.get("suite") or {}).get("digest") != suite_digest:
                continue
            for entry in run.get("models") or []:
                if not isinstance(entry, dict) or not entry.get("complete") or not entry.get("available"):
                    continue
                tasks = [item for item in entry.get("tasks") or [] if isinstance(item, dict)]
                seconds = [float(item.get("seconds") or 0.0) for item in tasks]
                latest[str(entry["model"])] = Measurement(
                    model=str(entry["model"]),
                    passed=frozenset(str(item["taskId"]) for item in tasks if item.get("passed") is True),
                    total=len(tasks), median_seconds=statistics.median(seconds) if seconds else float("inf"),
                    run_id=str(run["runId"]), finished_at=str(run.get("finishedAt")),
                    timeouts=int(entry.get("timeouts") or 0), is_retry=entry.get("isRetry") is True,
                )
        return latest

    def _latest_result_projection(self) -> dict[str, dict[str, Any]]:
        try:
            current_digest = self.suite().digest
        except SuiteError:
            current_digest = None
        latest: dict[str, dict[str, Any]] = {}
        for run in self._runs():
            for entry in run.get("models") or []:
                if not isinstance(entry, dict) or "model" not in entry:
                    continue
                totals = entry.get("totals") or {}
                latest[str(entry["model"])] = {
                    "runId": run.get("runId"), "finishedAt": run.get("finishedAt"), "state": run.get("state"),
                    "available": entry.get("available"), "complete": entry.get("complete"),
                    "passed": totals.get("passed"), "total": totals.get("total"), "medianSeconds": totals.get("medianSeconds"),
                    "suiteDigest": (run.get("suite") or {}).get("digest"),
                    "current": (run.get("suite") or {}).get("digest") == current_digest,
                }
        return latest

    # -- decide and apply --------------------------------------------------------

    def _proposal_view(self, proposal: Mapping[str, Any]) -> dict[str, Any]:
        candidate = proposal.get("candidate") or {}
        incumbent = proposal.get("incumbent") or {}
        summary = f"Switch to {proposal.get('to')}"
        if candidate:
            summary += f": {candidate.get('passed')}/{candidate.get('total')}"
            if incumbent:
                summary += f" vs {incumbent.get('passed')}/{incumbent.get('total')}"
            if candidate.get("medianSeconds") is not None:
                summary += f", {round(float(candidate['medianSeconds']))} s"
                if incumbent.get("medianSeconds") is not None:
                    summary += f" vs {round(float(incumbent['medianSeconds']))} s"
        return {**proposal, "summary": summary}

    def apply_decisions(self, *, by: str = "lease", trigger: str = "schedule") -> list[dict[str, Any]]:
        """Run decide() for every unpinned class; apply under the lease, else propose."""
        outcomes: list[dict[str, Any]] = []
        if not self.consented():
            return outcomes
        binary = self._harness_resolver()
        with self._lock:
            measurements = self.measurements()
            catalogue = self._catalogue()
            usable = self.usable_models(catalogue)
            policy = self._policy()
            leased = self.lease_active(policy)
            for action_class in ACTION_CLASSES:
                route = policy["routes"][action_class]
                if route["pinned"]:
                    continue
                decision = decide(route["model"], measurements, usable)
                if decision.action == "keep" or (decision.action == "none" and route["model"] is None):
                    continue
                if decision.action == "none":
                    # Narrowing only: a route goes to none only when its model really vanished
                    # (unseen for the whole availability window), never on one failed probe.
                    if self._seen_recently(catalogue, str(route["model"])):
                        continue
                    previous = route["model"]
                    policy["routes"][action_class] = self._route_entry(None, pinned=False, by="schedule", why="incumbent vanished; no measured free model")
                    self._receipt("route.changed", by="schedule", actionClass=action_class, **{"from": previous, "to": None},
                                  why="incumbent vanished from the catalogue and no measured free model remains")
                    outcomes.append({"actionClass": action_class, "applied": True, "to": None})
                    continue
                why = {"no_incumbent": "no route yet; best measured free model",
                       "incumbent_unavailable": "incumbent unavailable; best measured remaining free model",
                       "candidate_better": "candidate beats the incumbent with no regression"}[decision.reason]
                score = {"candidate": decision.candidate.score() if decision.candidate else None,
                         "incumbent": decision.incumbent.score() if decision.incumbent else None}
                if leased and binary is not None:
                    previous = route["model"]
                    policy["routes"][action_class] = self._route_entry(decision.model, pinned=False, by="lease", why=why)
                    self._receipt("route.changed", by="lease", actionClass=action_class, **{"from": previous, "to": decision.model},
                                  why=why, trigger=trigger, **score)
                    for proposal in policy["proposals"]:
                        if proposal.get("status") == "pending" and proposal.get("actionClass") == action_class:
                            proposal.update(status="superseded", decidedAt=_iso(self._now()), decidedBy="lease")
                    outcomes.append({"actionClass": action_class, "applied": True, "to": decision.model})
                    continue
                candidate_run = score["candidate"]["runId"] if score["candidate"] else None
                duplicate = any(
                    item.get("actionClass") == action_class and item.get("from") == route["model"]
                    and item.get("to") == decision.model and (item.get("candidate") or {}).get("runId") == candidate_run
                    and item.get("status") in {"pending", "dismissed"}
                    for item in policy["proposals"]
                )
                if duplicate:
                    continue
                for proposal in policy["proposals"]:
                    if proposal.get("status") == "pending" and proposal.get("actionClass") == action_class:
                        proposal.update(status="superseded", decidedAt=_iso(self._now()), decidedBy="schedule")
                proposal = {
                    "id": "proposal-" + uuid.uuid4().hex[:12], "actionClass": action_class,
                    "from": route["model"], "to": decision.model, "reason": decision.reason, "why": why,
                    **score, "suiteDigest": self.suite().digest, "createdAt": _iso(self._now()), "status": "pending",
                }
                policy["proposals"].append(proposal)
                self._receipt("proposal.created", by="schedule", proposalId=proposal["id"], actionClass=action_class,
                              **{"from": route["model"], "to": decision.model}, why=why, trigger=trigger)
                outcomes.append({"actionClass": action_class, "applied": False, "proposalId": proposal["id"]})
            self._write_policy(policy)
        return outcomes

    def set_route(self, action_class: object, model: object, pin: object, *, by: str) -> dict[str, Any]:
        if action_class not in ACTION_CLASSES:
            raise ModelRoutesError("action_class_unknown", "the action class is not one of " + ", ".join(ACTION_CLASSES), 400)
        if not isinstance(pin, bool):
            raise ModelRoutesError("route_invalid", "pin must be true or false", 400)
        if model is not None:
            if not valid_model_id(model):
                raise ModelRoutesError("route_invalid", "model must be a provider/model id or null", 400)
            if not is_free_model(str(model)):
                raise ModelRoutesError("destination_unsupported", "only opencode free models can be routed in this release")
            if str(model) not in self._catalogue()["models"]:
                raise ModelRoutesError("model_unknown", "the model has not been observed in the catalogue; observe first")
            self._require_consent()
        with self._lock:
            policy = self._policy()
            previous = policy["routes"][str(action_class)]
            policy["routes"][str(action_class)] = self._route_entry(model, pinned=pin, by=by, why="owner choice")  # type: ignore[arg-type]
            for proposal in policy["proposals"]:
                if proposal.get("status") == "pending" and proposal.get("actionClass") == action_class:
                    proposal.update(status="superseded", decidedAt=_iso(self._now()), decidedBy=by)
            self._write_policy(policy)
            self._receipt("route.changed", by=by, actionClass=action_class, **{"from": previous["model"], "to": model},
                          why="owner choice", pinned=pin, previouslyPinned=previous["pinned"])
        return self.projection()

    def set_lease(self, enabled: object, days: object = None, *, by: str) -> dict[str, Any]:
        if not isinstance(enabled, bool):
            raise ModelRoutesError("lease_invalid", "enabled must be true or false", 400)
        if days is None:
            days = LEASE_DEFAULT_DAYS
        if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= LEASE_MAX_DAYS:
            raise ModelRoutesError("lease_invalid", f"days must be a whole number from 1 to {LEASE_MAX_DAYS}", 400)
        if enabled:
            self._require_consent()
        with self._lock:
            policy = self._policy()
            now = self._now()
            if enabled:
                policy["lease"] = {
                    "enabled": True, "grantedAt": _iso(now), "grantedBy": by,
                    "expiresAt": _iso(now + days * 86400), "days": days,
                    "maxSuiteRunsPerDay": policy["lease"].get("maxSuiteRunsPerDay", DEFAULT_MAX_SUITE_RUNS_PER_DAY),
                    "scope": {"destinations": [DESTINATION_FREE], "actionClasses": list(ACTION_CLASSES)},
                }
                self._receipt("lease.granted", by=by, expiresAt=policy["lease"]["expiresAt"], days=days,
                              maxSuiteRunsPerDay=policy["lease"]["maxSuiteRunsPerDay"])
            else:
                policy["lease"] = {**policy["lease"], "enabled": False, "revokedAt": _iso(now), "revokedBy": by}
                self._receipt("lease.revoked", by=by, why="owner revoked")
            self._write_policy(policy)
        return self.projection()

    def decide_proposal(self, proposal_id: object, decision: object, *, by: str) -> dict[str, Any]:
        if not isinstance(proposal_id, str) or _PROPOSAL_ID.fullmatch(proposal_id) is None:
            raise ModelRoutesError("proposal_not_found", "the route proposal was not found", 404)
        if decision not in {"switch", "dismiss"}:
            raise ModelRoutesError("proposal_decision_invalid", "decision must be switch or dismiss", 400)
        with self._lock:
            policy = self._policy()
            proposal = next((item for item in policy["proposals"] if item.get("id") == proposal_id), None)
            if proposal is None:
                raise ModelRoutesError("proposal_not_found", "the route proposal was not found", 404)
            if proposal.get("status") != "pending":
                raise ModelRoutesError("proposal_stale", f"the proposal is already {proposal.get('status')}")
            action_class = str(proposal["actionClass"])
            route = policy["routes"].get(action_class)
            now = _iso(self._now())
            if decision == "dismiss":
                proposal.update(status="dismissed", decidedAt=now, decidedBy=by)
                self._write_policy(policy)
                self._receipt("proposal.dismissed", by=by, proposalId=proposal_id, actionClass=action_class)
                return self.projection()
            if route is None or route["model"] != proposal.get("from") or route["pinned"]:
                proposal.update(status="superseded", decidedAt=now, decidedBy=by)
                self._write_policy(policy)
                raise ModelRoutesError("proposal_stale", "the route changed since this proposal was made; review the current route")
            self._require_consent()
            target = proposal.get("to")
            if not valid_model_id(target) or target not in self._catalogue()["models"]:
                raise ModelRoutesError("model_unknown", "the proposed model is no longer in the catalogue")
            policy["routes"][action_class] = self._route_entry(target, pinned=False, by=by, why=f"owner accepted {proposal_id}")
            proposal.update(status="switched", decidedAt=now, decidedBy=by)
            self._write_policy(policy)
            self._receipt("route.changed", by=by, actionClass=action_class, **{"from": proposal.get("from"), "to": target},
                          why=f"owner accepted {proposal_id}", proposalId=proposal_id)
        return self.projection()

    # -- resolution ----------------------------------------------------------------

    def resolve(self, action_class: str) -> ResolvedRoute | RouteRefusal:
        if action_class not in ACTION_CLASSES:
            return RouteRefusal("route_not_configured", "No route is defined for this kind of action.")
        if not self.consented(DESTINATION_FREE):
            return RouteRefusal("route_not_consented", REFUSAL_MESSAGES["route_not_consented"])
        policy = self._policy()
        model = policy["routes"][action_class]["model"]
        if model is None:
            usable = self.usable_models()
            if not any(item.passed for name, item in self.measurements().items() if name in usable):
                return RouteRefusal("no_measured_route", REFUSAL_MESSAGES["no_measured_route"])
            return RouteRefusal("route_not_configured", REFUSAL_MESSAGES["route_not_configured"])
        if destination_of(model) != DESTINATION_FREE:
            return RouteRefusal("route_not_configured", "This route's destination is not supported in this release.")
        binary = self._harness_resolver()
        if binary is None:
            return RouteRefusal("harness_unavailable", REFUSAL_MESSAGES["harness_unavailable"])
        return ResolvedRoute(action_class, model, DESTINATION_FREE, binary, self.policy_digest())

    def status(self) -> dict[str, Any]:
        """Provider readiness for the UI: "ready" only with a consented route AND the executable."""
        binary = self._harness_resolver()
        harness = {"id": HARNESS, "present": binary is not None, "version": (self._catalogue().get("harness") or {}).get("version")}
        consent = self.consent_state()
        if consent != "granted":
            return {"state": "not_consented", "harness": harness,
                    "detail": "Free models are off until you accept the OpenCode Zen terms." if consent == "not_granted"
                    else "The free-model terms changed; read and accept them again."}
        if binary is None:
            return {"state": "harness_unavailable", "harness": harness, "detail": REFUSAL_MESSAGES["harness_unavailable"]}
        resolved = {name: self.resolve(name) for name in ACTION_CLASSES}
        ready = [name for name, item in resolved.items() if isinstance(item, ResolvedRoute)]
        alarms = [item for item in self._catalogue().get("alarms") or [] if isinstance(item, dict)]
        recent = [item for item in alarms if (_parse_iso(item.get("at")) or 0) > self._now() - PROBE_RETRY_SECONDS]
        alarm = recent[-1] if recent else None
        if not ready:
            refusal = next(iter(resolved.values()))
            return {"state": "no_route", "harness": harness, "readyClasses": [], "alarm": alarm,
                    "detail": refusal.message if isinstance(refusal, RouteRefusal) else ""}
        return {"state": "ready", "harness": harness, "readyClasses": ready, "alarm": alarm,
                "detail": "A consented free-model route and the pinned OpenCode executable are present. "
                          "Readiness is not a guarantee: free models can stop answering at any time."}

    # -- projection --------------------------------------------------------------------

    def projection(self) -> dict[str, Any]:
        with self._lock:
            catalogue = self._catalogue()
            policy = self._policy()
            consent = self._consent()["destinations"].get(DESTINATION_FREE)
            latest = self._latest_result_projection()
            measurements = self.measurements()
            usable = self.usable_models(catalogue)
            now = self._now()
            runs_today = self._scheduled_runs_today()
            models = []
            for model_id, entry in sorted(catalogue["models"].items()):
                if not isinstance(entry, dict):
                    continue
                models.append({
                    "id": model_id, "free": is_free_model(model_id), "destination": destination_of(model_id),
                    "listedNow": model_id in (catalogue.get("lastListed") or []), "usable": model_id in usable,
                    "firstSeenAt": entry.get("firstSeenAt"), "lastSeenAt": entry.get("lastSeenAt"),
                    "seenCount": entry.get("seenCount"), "lastProbe": entry.get("lastProbe"),
                    "latestResult": latest.get(model_id),
                })
            routes = []
            for action_class in ACTION_CLASSES:
                route = policy["routes"][action_class]
                resolved = self.resolve(action_class)
                measured = measurements.get(route["model"]) if route["model"] else None
                set_at = _parse_iso(route.get("setAt"))
                routes.append({
                    "actionClass": action_class, "model": route["model"], "pinned": route["pinned"],
                    "setBy": route.get("setBy"), "setAt": route.get("setAt"), "why": route.get("why"),
                    "ageSeconds": int(now - set_at) if set_at is not None else None,
                    "score": measured.score() if measured else None,
                    "usable": route["model"] in usable if route["model"] else None,
                    "refusal": resolved.to_dict() if isinstance(resolved, RouteRefusal) else None,
                })
            lease = policy["lease"]
            expires = _parse_iso(lease.get("expiresAt"))
            lease_state = "off"
            if lease.get("enabled"):
                lease_state = "active" if self.lease_active(policy) else ("expired" if expires is not None and now >= expires else "inactive")
            pending = [self._proposal_view(item) for item in policy["proposals"] if item.get("status") == "pending"]
            return {
                "formatVersion": FORMAT_PROJECTION,
                "status": self.status(),
                "consent": {
                    "destination": DESTINATION_FREE, "state": self.consent_state(),
                    "grantedAt": consent.get("grantedAt") if isinstance(consent, dict) else None,
                    "grantedBy": consent.get("grantedBy") if isinstance(consent, dict) else None,
                    "grantedTermsSha256": consent.get("termsSha256") if isinstance(consent, dict) else None,
                    "terms": self.terms(),
                },
                "catalogue": {
                    "observedAt": catalogue.get("observedAt"), "observations": catalogue.get("observations"),
                    "harness": catalogue.get("harness"), "lastError": catalogue.get("lastError"),
                    "availabilityWindowSeconds": AVAILABILITY_WINDOW_SECONDS, "models": models,
                    "cache": catalogue.get("cache"),
                },
                "alarms": list(reversed([item for item in catalogue.get("alarms") or [] if isinstance(item, dict)])),
                "routes": routes,
                "lease": {
                    "enabled": bool(lease.get("enabled")), "state": lease_state, "grantedAt": lease.get("grantedAt"),
                    "expiresAt": lease.get("expiresAt"), "maxSuiteRunsPerDay": lease.get("maxSuiteRunsPerDay"),
                    "runsToday": runs_today, "maxDays": LEASE_MAX_DAYS, "defaultDays": LEASE_DEFAULT_DAYS,
                },
                "suite": self._suite_projection(),
                "evaluation": {"activeRunId": self._active_run, "maxModels": MAX_MODELS_PER_RUN,
                               "lastRunId": (self._runs() or [{}])[-1].get("runId")},
                "proposal": pending[-1] if pending else None,
                "proposals": pending,
                "schedule": {"running": self._scheduler is not None and self._scheduler.is_alive(),
                             "intervalSeconds": SCHEDULE_INTERVAL_SECONDS,
                             "nextTickAt": _iso(self._next_tick_at) if self._next_tick_at else None,
                             "lastGate": self._last_gate},
                "receipts": list(reversed(self.receipts.tail(RECEIPT_TAIL))),
                "scoresNote": "Scores come from StatePort's practice tasks, not from your work.",
            }

    # -- schedule ----------------------------------------------------------------------

    def _scheduled_runs_today(self) -> int:
        today = _iso(self._now())[:10]
        return sum(1 for run in self._runs() if run.get("trigger") == "schedule" and str(run.get("createdAt", ""))[:10] == today)

    def tick(self) -> dict[str, Any]:
        """One scheduled pass. The deterministic gate runs first; models only if it finds work."""
        now = self._now()
        gate: dict[str, Any] = {"at": _iso(now), "observed": None, "probes": [], "decisions": [], "work": [],
                                "runId": None, "skipped": None}
        try:
            if not self.consented():
                gate["skipped"] = "not_consented"
                return gate
            self._expire_lease()
            try:
                self.observe(by="schedule")
                gate["observed"] = "ok"
            except ModelRoutesError as exc:
                gate["observed"] = exc.code
            binary = self._harness_resolver()
            if binary is None:
                gate["skipped"] = "harness_unavailable"
                return gate
            policy = self._policy()
            incumbents = sorted({route["model"] for route in policy["routes"].values() if route["model"]})
            catalogue = self._catalogue()
            for model in incumbents[:MAX_PROBES_PER_TICK]:
                if model in catalogue["models"]:
                    gate["probes"].append({"model": model, **self._probe_model(binary, model, by="schedule")})
            gate["decisions"] = self._apply_with_probes(binary, gate)
            policy = self._policy()
            if not self.lease_active(policy):
                gate["skipped"] = "lease_off"
                return gate
            if self._scheduled_runs_today() >= int(policy["lease"]["maxSuiteRunsPerDay"]):
                gate["skipped"] = "daily_budget_spent"
                return gate
            candidates, work, retry = self._scheduled_candidates(policy)
            gate["work"] = work
            if not candidates:
                gate["skipped"] = "no_work"
                return gate
            try:
                started = self.start_evaluation(candidates, by="lease", trigger="schedule", background=False,
                                                retry_models=retry)
                gate["runId"] = started["runId"]
            except ModelRoutesError as exc:
                gate["skipped"] = exc.code
            return gate
        finally:
            self._last_gate = gate
            if gate.get("skipped") != "not_consented":
                self._receipt("schedule.tick", by="schedule", gate={key: value for key, value in gate.items() if key != "at"})

    def _apply_with_probes(self, binary: Path, gate: dict[str, Any]) -> list[dict[str, Any]]:
        """Before a switch, probe its target; a target that fails its probe is skipped this window."""
        probes = len(gate["probes"])
        for _ in range(MAX_MODELS_PER_RUN):
            policy = self._policy()
            measurements = self.measurements()
            usable = self.usable_models()
            pending_target = None
            for route in policy["routes"].values():
                if route["pinned"]:
                    continue
                decision = decide(route["model"], measurements, usable)
                if decision.action == "switch" and decision.model:
                    pending_target = decision.model
                    break
            if pending_target is None or probes >= MAX_PROBES_PER_TICK:
                break
            already = any(item.get("model") == pending_target for item in gate["probes"])
            if already:
                break
            probe = self._probe_model(binary, pending_target, by="schedule")
            probes += 1
            gate["probes"].append({"model": pending_target, **probe})
            if probe["status"] == "ok":
                break
        return self.apply_decisions(by="lease", trigger="schedule")

    def _scheduled_candidates(self, policy: Mapping[str, Any]) -> tuple[list[str], list[str], list[str]]:
        catalogue = self._catalogue()
        usable = self.usable_models(catalogue)
        measurements = self.measurements()
        now = self._now()
        work: list[str] = []
        candidates: list[str] = []
        for action_class, route in policy["routes"].items():
            model = route["model"]
            if route["pinned"]:
                continue
            if model and model not in usable:
                work.append(f"incumbent_unavailable:{action_class}")
            elif model:
                measured = measurements.get(model)
                finished = _parse_iso(measured.finished_at) if measured else None
                if finished is None or now - finished > STALE_MEASUREMENT_SECONDS:
                    work.append(f"incumbent_stale:{action_class}")
                    if model not in candidates:
                        candidates.append(model)
            else:
                work.append(f"no_route:{action_class}")

        def recently_failed(model_id: str) -> bool:
            probe = (catalogue["models"].get(model_id) or {}).get("lastProbe")
            at = _parse_iso(probe.get("at")) if isinstance(probe, dict) else None
            return (isinstance(probe, dict) and probe.get("status") in {"unavailable", "timeout"}
                    and at is not None and now - at < PROBE_RETRY_SECONDS)

        # Recently listed free models; a model that failed its probe is skipped until the
        # retry window passes, then the run's own probe decides whether it works again.
        pool = {model for model in catalogue["models"] if is_free_model(model)
                and self._seen_recently(catalogue, model) and not recently_failed(model)}
        retry = sorted(model for model, item in measurements.items()
                       if item.timeouts and not item.is_retry and model in pool)
        if retry:
            work.append("timeout_retry:" + str(len(retry)))
        unmeasured = sorted(
            (model for model in pool if model not in measurements),
            key=lambda model: (str((catalogue["models"].get(model) or {}).get("firstSeenAt")), model), reverse=True,
        )
        if unmeasured:
            work.append("unmeasured_free_models:" + str(len(unmeasured)))
        for model in [*retry, *unmeasured]:
            if len(candidates) >= MAX_MODELS_PER_RUN:
                break
            if model not in candidates:
                candidates.append(model)
        if not any(item.startswith(("incumbent_", "no_route", "unmeasured_", "timeout_retry")) for item in work):
            return [], work, []
        selected = candidates[:MAX_MODELS_PER_RUN]
        return selected, work, [model for model in retry if model in selected]

    def _expire_lease(self) -> None:
        with self._lock:
            policy = self._policy()
            lease = policy["lease"]
            expires = _parse_iso(lease.get("expiresAt"))
            if lease.get("enabled") and expires is not None and self._now() >= expires:
                policy["lease"] = {**lease, "enabled": False, "expiredAt": _iso(self._now())}
                self._write_policy(policy)
                self._receipt("lease.expired", by="schedule", expiresAt=lease.get("expiresAt"))

    def start_scheduler(self, *, interval_seconds: float = SCHEDULE_INTERVAL_SECONDS,
                        initial_delay_seconds: float = SCHEDULE_INITIAL_DELAY_SECONDS) -> None:
        if self._scheduler is not None and self._scheduler.is_alive():
            return
        self._stop.clear()

        def loop() -> None:
            delay = initial_delay_seconds
            while True:
                self._next_tick_at = self._now() + delay
                if self._stop.wait(delay):
                    return
                try:
                    gate = self.tick()
                    self._emit(f"event=schedule_tick skipped={gate.get('skipped')} run={gate.get('runId')}")
                except Exception as exc:  # noqa: BLE001 - the timer never dies on one bad tick
                    self._emit(f"event=schedule_tick_failed error={type(exc).__name__}")
                delay = interval_seconds

        self._scheduler = threading.Thread(target=loop, name="stateport-model-routes-schedule", daemon=True)
        self._scheduler.start()

    def stop_scheduler(self, timeout: float = 2.0) -> None:
        self._stop.set()
        thread = self._scheduler
        if thread is not None and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=timeout)


class _Interrupted(Exception):
    pass


__all__ = [
    "ACTION_CLASSES", "DESTINATION_FREE", "FREE_ROUTE_ALLOW_HOSTS", "Decision", "Measurement", "ModelRoutes",
    "ModelRoutesError", "REFUSAL_MESSAGES", "ResolvedRoute", "RouteRefusal", "SuiteError", "TERMS_SHA256",
    "TERMS_TEXT", "TERMS_URL", "beats", "build_suite_manifest", "decide", "destination_of", "is_free_model",
    "load_suite", "parse_models_output", "resolve_harness_binary",
]
