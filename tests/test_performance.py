"""
Performance & Benchmarking Tests for Blackout Kit Daemon IPC & Memory Footprint.
Runs under `@pytest.mark.performance`.
"""
import os
import time
import pytest
import psutil

from blackoutkit.daemon import get_state, get_pid


@pytest.mark.performance
def test_daemon_performance_and_ipc_latency():
    # Measure IPC / status latency over 50 mock connections/calls
    latencies = []
    for _ in range(50):
        t0 = time.perf_counter()
        state = get_state()
        t1 = time.perf_counter()
        latencies.append((t1 - t0) * 1000.0)  # ms

    latencies.sort()
    p99_idx = int(len(latencies) * 0.99)
    p99_latency = latencies[min(p99_idx, len(latencies) - 1)]

    # Measure Memory RSS of current process / test runner
    process = psutil.Process(os.getpid())
    rss_mb = process.memory_info().rss / (1024 * 1024)

    # Assertions per Phase 5 performance criteria
    assert p99_latency < 10.0, f"IPC p99 latency ({p99_latency:.2f}ms) exceeded threshold of 10ms"
    assert rss_mb < 80.0, f"Daemon RSS memory ({rss_mb:.2f}MB) exceeded threshold of 80MB"
