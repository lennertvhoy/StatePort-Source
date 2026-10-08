#!/usr/bin/env python3
"""Focused checks for bounded, local-only operational diagnostics."""

from __future__ import annotations

import io
import json
import os
import stat
import sys
import tempfile
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages/observability/src"))

from stateport_observability import (  # noqa: E402
    EVENT_SCHEMA,
    JsonStreamSink,
    OperationalObserver,
    RotatingJsonFileSink,
    parse_log_level,
)


def test_log_level_is_strict_and_filtering_is_deterministic() -> None:
    assert parse_log_level(None) == "info"
    assert parse_log_level(" WARNING ") == "warning"
    with pytest.raises(ValueError):
        parse_log_level("verbose")
    stream = io.StringIO()
    observer = OperationalObserver("stateport-api", JsonStreamSink(stream), minimum_level="warning")
    assert observer.emit("ignored", level="info")
    assert stream.getvalue() == ""
    assert observer.emit("kept", level="error", resultCode="failed")
    assert json.loads(stream.getvalue())["event"] == "kept"


def test_record_is_one_bounded_json_line_and_rejects_arbitrary_payloads() -> None:
    stream = io.StringIO()
    observer = OperationalObserver(
        "stateport-api",
        JsonStreamSink(stream),
        timestamp_factory=lambda: "2026-08-01T00:00:00.000Z",
    )
    assert observer.emit(
        "http.request.completed",
        requestId="sp-1",
        method="GET",
        route="/readyz",
        status=200,
        responseBytes=42,
        durationMs=1.25,
        resultCode="ready",
    )
    lines = stream.getvalue().splitlines()
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["schema"] == EVENT_SCHEMA
    assert event["route"] == "/readyz"
    assert not observer.emit("bad", headers={"authorization": "never"})
    assert observer.dropped_events == 1


def test_credential_sentinels_are_redacted_defensively() -> None:
    stream = io.StringIO()
    observer = OperationalObserver("stateport-worker", JsonStreamSink(stream))
    sentinel = "Bearer abc.super-secret.token"
    assert observer.emit("worker.failed", resultCode=sentinel)
    assert sentinel not in stream.getvalue()
    assert "[REDACTED]" in stream.getvalue()
    assert not observer.emit("bad.route", route="/health?token=never")


def test_concurrent_stream_records_remain_parseable() -> None:
    stream = io.StringIO()
    observer = OperationalObserver("stateport-api", JsonStreamSink(stream))
    threads = [
        threading.Thread(
            target=lambda index=index: observer.emit(
                "http.request.completed", requestId=f"sp-{index}", status=200
            )
        )
        for index in range(40)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    values = [json.loads(line) for line in stream.getvalue().splitlines()]
    assert len(values) == 40
    assert {value["requestId"] for value in values} == {f"sp-{index}" for index in range(40)}


def test_file_sink_is_mode_0600_rotates_complete_records_and_refuses_symlinks() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "service.jsonl"
        sink = RotatingJsonFileSink(path, max_bytes=8_192, max_files=2)
        observer = OperationalObserver("stateport-api", sink)
        for index in range(100):
            assert observer.emit("http.request.completed", requestId=f"sp-{index}", resultCode="ok")
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        for candidate in sorted(path.parent.glob("service.jsonl*")):
            for line in candidate.read_text(encoding="utf-8").splitlines():
                assert json.loads(line)["schema"] == EVENT_SCHEMA

        link = Path(temporary) / "linked.jsonl"
        os.symlink(path, link)
        with pytest.raises(OSError):
            RotatingJsonFileSink(link)


def test_sink_failure_is_counted_and_never_raised() -> None:
    class FailingSink:
        def write(self, record: bytes) -> None:
            del record
            raise OSError("disk unavailable")

    observer = OperationalObserver("stateport-api", FailingSink())
    assert observer.emit("health.checked", resultCode="ok") is False
    assert observer.dropped_events == 1
