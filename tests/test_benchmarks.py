"""Phase 5 — performance benchmarks (blackoutkit.benchmarks)."""
from __future__ import annotations

import blackoutkit.v2_ipc as v2_ipc
from blackoutkit.benchmarks import (
    measure_ipc_latency,
    percentile,
    run_benchmarks,
    summarize,
)


# ── pure helpers ─────────────────────────────────────────────────────────────

def test_percentile_nearest_rank():
    data = [float(i) for i in range(1, 11)]  # 1..10
    assert percentile(data, 50) == 5
    assert percentile(data, 95) == 10
    assert percentile(data, 99) == 10
    assert percentile(data, 0) == 1
    assert percentile(data, 100) == 10


def test_percentile_empty_is_none():
    assert percentile([], 99) is None


def test_summarize_shape_and_values():
    s = summarize([10.0, 20.0, 30.0, 40.0])
    assert s["count"] == 4
    assert s["min_ms"] == 10.0
    assert s["max_ms"] == 40.0
    assert s["mean_ms"] == 25.0
    assert s["p50_ms"] is not None


def test_summarize_empty():
    s = summarize([])
    assert s["count"] == 0
    assert s["p99_ms"] is None


# ── IPC measurement (deterministic via monkeypatch) ──────────────────────────

def test_ipc_latency_unavailable_when_connect_fails(monkeypatch):
    def _boom(self):
        raise OSError("no daemon listening")

    monkeypatch.setattr(v2_ipc.CoreClient, "connect", _boom)
    r = measure_ipc_latency(samples=3, connect_timeout=0.1)
    assert r["available"] is False
    assert "reason" in r


def test_ipc_latency_success(monkeypatch):
    monkeypatch.setattr(v2_ipc.CoreClient, "connect", lambda self: None)
    monkeypatch.setattr(v2_ipc.CoreClient, "ping", lambda self: True)
    monkeypatch.setattr(v2_ipc.CoreClient, "close", lambda self: None)
    r = measure_ipc_latency(samples=10, connect_timeout=0.1)
    assert r["available"] is True
    assert r["count"] == 10
    assert r["p99_ms"] is not None


# ── aggregate run ────────────────────────────────────────────────────────────

def test_run_benchmarks_structure(monkeypatch):
    monkeypatch.setattr(v2_ipc.CoreClient, "connect", lambda self: None)
    monkeypatch.setattr(v2_ipc.CoreClient, "ping", lambda self: True)
    monkeypatch.setattr(v2_ipc.CoreClient, "close", lambda self: None)

    result = run_benchmarks(samples=5, ipc_timeout=0.1)
    assert set(result) >= {"system", "daemon", "ipc", "budgets", "within_budget"}
    assert result["budgets"]["daemon_rss_mb"] == 80.0
    assert result["budgets"]["ipc_p99_ms"] == 10.0
    assert result["ipc"]["available"] is True


def test_bench_command_is_registered():
    from blackoutkit.typer_cli import app

    # @app.command() without an explicit name leaves CommandInfo.name as None;
    # the real name comes from the callback function.
    names = {
        c.name or (c.callback.__name__ if c.callback else None)
        for c in app.registered_commands
    }
    assert "bench" in names
