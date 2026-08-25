# Wave 3 Remediation Record

**Scope:** confirmed defects and operational-reliability hardening only.

## Verified outcomes

- `blackoutkit.daemon` now resolves to the package implementation and exposes the daemon-manager API used by CLI and test consumers.
- The daemon loop no longer shadows the module-level `logging` import in its stdout/stderr fallback, so rotating-log setup and reconnect handling can run.
- Engine shutdown always clears process state and cleans up its per-engine temporary configuration directory; cleanup failures are warning-visible.
- The QoS implementation compiles, and the existing `blackoutkit.tools.qos` specialist-module import path is compatible with the legacy `blackoutkit.tools` toolkit module.
- QoS, traffic, DNS, and neighbor workers use stop-aware waits, reject duplicate live workers, and retain worker references when a bounded shutdown cannot confirm termination.
- DNS queued-query state is capped at 1,000 entries with oldest-first eviction, a drop counter, and warning records for the first and each hundredth dropped query.
- CLI bandwidth monitoring caps both per-interface samples (300) and retained interface names (32), refreshing observed-interface recency deterministically.
- `cmd_panic()` invokes the supported public `daemon.stop()` API and its side effects have isolated regression coverage.
- Neighbor-cache persistence failures are warning-visible, while ordinary discovery failures remain quiet.
- A custom one-label SNI host such as `www` is regression-tested without changing the already-safe rendering logic.

## Deliberately not represented as new fixes

- The latency monitor already had a 300-sample bound before this remediation.
- The routing command already handled an empty candidate list before this remediation.
- The SNI custom-host display logic already guarded a one-label host; it received regression coverage rather than a source change.
- QoS remains monitor/placeholder behavior. This work does not add traffic interception, shaping, enforcement, firewall-policy expansion, or live packet manipulation.

## Verification

Completed on 2026-08-22:

- `python -m compileall -q blackoutkit`
- Focused hermetic pytest suite: **98 passed**

The focused suite covers canonical daemon APIs and launcher payloads, daemon reconnect/state behavior, monitor lifecycle, DNS queue bounds, fake-process engine cleanup, CLI state retention and panic dispatch, neighbor persistence, SNI custom-host handling, and Russia diagnostics. It uses mocks, controlled events, and test doubles—no live network operations or real process termination.

## Follow-up

No Wave 4 audit is included or implied by this record. Any further audit or feature work requires independently verified findings and separately approved scope.
