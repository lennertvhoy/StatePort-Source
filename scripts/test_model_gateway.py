from __future__ import annotations

from pathlib import Path
import sys
import threading

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "tool-gateway" / "src"))

from stateport_tool_gateway import ModelGateway, ModelGatewayError, ModelRoute  # noqa: E402


def test_route_is_provider_and_model_bound_without_prompt_persistence():
    seen = []

    def adapter(provider, model, request):
        seen.append(request)
        return {"text": "ok", "usage": {"tokens": 2, "costMinor": 0}}

    gateway = ModelGateway(
        ModelRoute("run.demo", "provider.demo", "model.demo", max_cost_minor=1),
        adapter,
    )
    token = gateway.issue_token()
    result = gateway.request(
        token,
        provider="provider.demo",
        model="model.demo",
        request={"prompt": "not persisted"},
        estimated_tokens=2,
    )
    assert result["outcome"] == "completed"
    assert seen == [{"prompt": "not persisted"}]
    assert "prompt" not in gateway.usage()
    with pytest.raises(ModelGatewayError, match="outside"):
        gateway.request(
            token,
            provider="other",
            model="model.demo",
            request={},
            estimated_tokens=1,
        )


@pytest.mark.parametrize(
    "route",
    [
        ModelRoute("run.bad", "provider.demo", "model.demo", max_requests=True),
        ModelRoute("run.bad", "provider.demo", "model.demo", max_tokens=True),
        ModelRoute("run.bad", "provider.demo", "model.demo", max_cost_minor=True),
        ModelRoute("run.bad", "provider.demo", "model.demo", expires_after_seconds=True),
        ModelRoute("run.bad", "provider.demo", "model.demo", max_cost_minor=-1),
    ],
)
def test_route_limits_reject_bool_and_negative_values(route):
    with pytest.raises(ModelGatewayError):
        ModelGateway(route, lambda provider, model, request: {})


@pytest.mark.parametrize(
    ("estimated_tokens", "estimated_cost_minor"),
    [(True, 0), (-1, 0), (0, True), (0, -1)],
)
def test_invalid_estimates_refuse_before_provider_effect(
    estimated_tokens,
    estimated_cost_minor,
):
    calls = []
    gateway = ModelGateway(
        ModelRoute(
            "run.estimate",
            "provider.demo",
            "model.demo",
            max_tokens=10,
            max_cost_minor=10,
        ),
        lambda provider, model, request: calls.append(request),
    )
    token = gateway.issue_token()
    with pytest.raises(ModelGatewayError, match="estimate"):
        gateway.request(
            token,
            provider="provider.demo",
            model="model.demo",
            request={},
            estimated_tokens=estimated_tokens,
            estimated_cost_minor=estimated_cost_minor,
        )
    assert calls == []
    assert gateway.usage()["requests"] == 0


def test_authorization_and_reservation_refuse_before_provider_effect():
    calls = []

    def adapter(provider, model, request):
        calls.append(request)
        return {"usage": {"tokens": 1, "costMinor": 0}}

    gateway = ModelGateway(
        ModelRoute("run.budget", "provider.demo", "model.demo", max_tokens=10),
        adapter,
    )
    token = gateway.issue_token()
    with pytest.raises(ModelGatewayError, match="reserved estimate"):
        gateway.request(
            token,
            provider="provider.demo",
            model="model.demo",
            request={},
            estimated_tokens=11,
        )
    assert calls == []
    assert gateway.usage()["requests"] == 0

    unavailable = ModelGateway(ModelRoute("run.none", "provider.demo", "model.demo"))
    unavailable_token = unavailable.issue_token()
    with pytest.raises(ModelGatewayError, match="adapter"):
        unavailable.request(
            unavailable_token,
            provider="provider.demo",
            model="model.demo",
            request={},
            estimated_tokens=1,
        )
    assert unavailable.usage()["requests"] == 0


def test_underestimated_usage_is_charged_and_locks_out_repeated_effects():
    calls = []

    def adapter(provider, model, request):
        calls.append(request)
        return {"usage": {"tokens": 11, "costMinor": 0}}

    gateway = ModelGateway(
        ModelRoute("run.overrun", "provider.demo", "model.demo", max_tokens=10),
        adapter,
    )
    token = gateway.issue_token()
    with pytest.raises(ModelGatewayError, match="exceeded its reserved budget"):
        gateway.request(
            token,
            provider="provider.demo",
            model="model.demo",
            request={"attempt": 1},
            estimated_tokens=5,
        )
    usage = gateway.usage()
    assert usage["requests"] == 1
    assert usage["tokens"] == 11
    assert usage["overruns"] == 1
    assert usage["lockedReason"] == "provider-usage-exceeded-reservation"
    assert usage["reserved"] == {"requests": 0, "tokens": 0, "costMinor": 0}
    with pytest.raises(ModelGatewayError, match="locked"):
        gateway.request(
            token,
            provider="provider.demo",
            model="model.demo",
            request={"attempt": 2},
            estimated_tokens=1,
        )
    assert calls == [{"attempt": 1}]


def test_provider_exception_is_conservatively_accounted_and_locked():
    calls = []

    def adapter(provider, model, request):
        calls.append(request)
        raise RuntimeError("provider exploded after an unknown effect")

    gateway = ModelGateway(
        ModelRoute(
            "run.unknown",
            "provider.demo",
            "model.demo",
            max_tokens=10,
            max_cost_minor=5,
        ),
        adapter,
    )
    token = gateway.issue_token()
    with pytest.raises(RuntimeError, match="exploded"):
        gateway.request(
            token,
            provider="provider.demo",
            model="model.demo",
            request={"attempt": 1},
            estimated_tokens=2,
            estimated_cost_minor=1,
        )
    usage = gateway.usage()
    assert usage["requests"] == 1
    assert usage["tokens"] == 10
    assert usage["costMinor"] == 5
    assert usage["unknownEffects"] == 1
    assert usage["lockedReason"] == "provider-effect-usage-unknown"
    assert usage["reserved"] == {"requests": 0, "tokens": 0, "costMinor": 0}
    with pytest.raises(ModelGatewayError, match="locked"):
        gateway.request(
            token,
            provider="provider.demo",
            model="model.demo",
            request={"attempt": 2},
            estimated_tokens=1,
        )
    assert calls == [{"attempt": 1}]


@pytest.mark.parametrize(
    "result",
    ["not-an-object", {}, {"usage": {"tokens": True, "costMinor": 0}}],
)
def test_malformed_or_unknown_usage_consumes_and_locks_route(result):
    gateway = ModelGateway(
        ModelRoute("run.malformed", "provider.demo", "model.demo", max_tokens=7),
        lambda provider, model, request: result,
    )
    token = gateway.issue_token()
    with pytest.raises(ModelGatewayError):
        gateway.request(
            token,
            provider="provider.demo",
            model="model.demo",
            request={},
            estimated_tokens=1,
        )
    usage = gateway.usage()
    assert usage["requests"] == 1
    assert usage["tokens"] == 7
    assert usage["unknownEffects"] == 1
    assert usage["lockedReason"] == "provider-effect-usage-unknown"


def test_concurrent_actual_overruns_are_all_accounted_after_lockout():
    barrier = threading.Barrier(2)

    def adapter(provider, model, request):
        barrier.wait(timeout=5)
        return {"usage": {"tokens": 6, "costMinor": 0}}

    gateway = ModelGateway(
        ModelRoute(
            "run.concurrent-overrun",
            "provider.demo",
            "model.demo",
            max_requests=2,
            max_tokens=10,
        ),
        adapter,
    )
    token = gateway.issue_token()
    outcomes = []

    def worker():
        try:
            gateway.request(
                token,
                provider="provider.demo",
                model="model.demo",
                request={},
                estimated_tokens=5,
            )
            outcomes.append("completed")
        except ModelGatewayError:
            outcomes.append("overrun")

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
    assert outcomes == ["overrun", "overrun"]
    usage = gateway.usage()
    assert usage["requests"] == 2
    assert usage["tokens"] == 12
    assert usage["overruns"] == 2
    assert usage["reserved"] == {"requests": 0, "tokens": 0, "costMinor": 0}


def test_revocation_blocks_new_admissions_but_settles_admitted_request():
    entered = threading.Event()
    release = threading.Event()

    def adapter(provider, model, request):
        entered.set()
        assert release.wait(timeout=5)
        return {"usage": {"tokens": 1, "costMinor": 0}}

    gateway = ModelGateway(
        ModelRoute("run.revoke", "provider.demo", "model.demo", max_tokens=10),
        adapter,
    )
    token = gateway.issue_token()
    result = []

    def in_flight():
        result.append(
            gateway.request(
                token,
                provider="provider.demo",
                model="model.demo",
                request={},
                estimated_tokens=1,
            )
        )

    thread = threading.Thread(target=in_flight)
    thread.start()
    assert entered.wait(timeout=5)
    gateway.revoke()
    with pytest.raises(ModelGatewayError, match="unavailable"):
        gateway.request(
            token,
            provider="provider.demo",
            model="model.demo",
            request={},
            estimated_tokens=1,
        )
    release.set()
    thread.join(timeout=5)
    assert result[0]["outcome"] == "completed"
    usage = gateway.usage()
    assert usage["revoked"] is True
    assert usage["requests"] == 1
    assert usage["tokens"] == 1
    assert usage["reserved"] == {"requests": 0, "tokens": 0, "costMinor": 0}


def test_request_reservations_are_atomic_under_concurrency():
    gateway = ModelGateway(
        ModelRoute(
            "run.race",
            "provider.demo",
            "model.demo",
            max_requests=10,
            max_tokens=100,
        ),
        lambda provider, model, request: {"usage": {"tokens": 1, "costMinor": 0}},
    )
    token = gateway.issue_token()
    outcomes = []
    lock = threading.Lock()

    def worker():
        try:
            gateway.request(
                token,
                provider="provider.demo",
                model="model.demo",
                request={},
                estimated_tokens=1,
            )
            value = "completed"
        except ModelGatewayError:
            value = "refused"
        with lock:
            outcomes.append(value)

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
    assert outcomes.count("completed") == 10
    assert outcomes.count("refused") == 10
    usage = gateway.usage()
    assert usage["requests"] == 10
    assert usage["tokens"] == 10
    assert usage["reserved"] == {"requests": 0, "tokens": 0, "costMinor": 0}
