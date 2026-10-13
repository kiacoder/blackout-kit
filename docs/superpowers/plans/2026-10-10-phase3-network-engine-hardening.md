# Phase 3 Network and Engine Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden Python egress, add verifiable Go transport/FEC reliability primitives, improve evidence-backed data-phase failover, and prepare a truthful 1.3.0 release.

**Architecture:** Keep ISP and DoH behavior in existing Python modules with injectable/request-level test seams. Extend the v2 dialer's existing ClientHello segmentation with deterministic, bounds-checked segmentation behavior, while keeping HyperPulse GF(256) encoding/decoding and adaptive parity selection standalone because no compatible wire protocol or active packet transport exists. Retain the Python daemon's existing proxy health boundary and add timing/sample behavior only where local proxy probes can establish an observable failure.

**Tech Stack:** Python 3.10+, urllib/httpx existing dependencies, pytest, Go 1.26, standard library Go tests.

**Spec:** In-chat approved scope on 2026-10-10: HTTPS ISP lookup with fallback; configurable DoH endpoint list; randomized ClientHello/SNI-aware segmentation without raw flag injection; standalone systematic GF(256) FEC with recovery and adaptive parity policy; honest local-proxy data-phase detection; tests, docs, and version metadata.

## Global Constraints

- ISP lookup requests must be HTTPS-only, keep certificate verification enabled, and retain finite timeouts and a no-result fallback.
- DoH resolver selection may use `BLACKOUT_DOH_RESOLVER`, otherwise use a deterministic Cloudflare/Quad9/Google fallback order; never disable TLS verification.
- No spoofed TCP flags, zero-window packets, raw-packet injection, or decoy packets are in scope.
- FEC is a standalone codec/policy primitive only; do not inject parity into VLESS/Trojan/VMess or other peers without a negotiated compatible framing protocol.
- Python data-phase failover must use actual local proxy probe results and must not claim to observe TLS handshakes or remote packet loss it cannot measure.
- Add tests before production changes and verify each focused test fails for the intended reason before implementation.
- Keep project versions consistent at `1.3.0` in `pyproject.toml` and `blackoutkit/__init__.py`; document actual scope in `CHANGELOG.md`.
- Do not push or tag unless all planned verification passes; tags must only describe shipped, tested behavior.

---

### Task 1: HTTPS-only ISP lookup with provider fallback

**Files:**
- Modify: `blackoutkit/network_switcher.py`
- Modify: `tests/test_network_switcher.py` (create if missing)
- Modify: `NETWORK_PRIVACY.md`
- Modify: `SECURITY.md`

**Interfaces:**
- `get_isp_info(timeout: float = 6.0) -> IspInfo | None` remains the public entry point.
- Replace the cleartext primary with `https://ipapi.co/json/`; keep `https://ipinfo.io/json` as fallback, deriving ASN and display fields from each provider's documented JSON shape.
- The endpoint allowlist contains only the HTTPS hosts actually used.

- [ ] **Step 1: Write the failing test** for a successful HTTPS primary lookup, asserting the HTTPS request URL and parsed ISP/ASN/country result; add fallback and all-providers-fail cases.
- [ ] **Step 2: Run `pytest tests/test_network_switcher.py -q`** and confirm the new expected provider behavior fails before implementation.
- [ ] **Step 3: Implement the smallest HTTPS-only provider loop**, preserving default TLS verification, the supplied timeout, and best-effort `None` behavior for network, HTTP-status, rate-limit, JSON, or schema failures.
- [ ] **Step 4: Update egress/security docs** to describe the actual host order, HTTPS transport, trigger points, and fallback semantics.
- [ ] **Step 5: Run `pytest tests/test_network_switcher.py tests/test_security_boundaries.py -q`** and `git diff --check`.
- [ ] **Step 6: Commit** `fix(egress): use HTTPS for ISP inspection`.

### Task 2: Configurable DoH bootstrap endpoint order

**Files:**
- Modify: `blackoutkit/tools.py`
- Modify: `tests/test_egress_config.py` (create)
- Modify: `tests/test_network_tools.py`
- Modify: `NETWORK_PRIVACY.md`

**Interfaces:**
- Preserve `resolve_doh(domain: str, timeout: float = 5.0) -> str | None` for all current callers.
- Add a private resolver-list function that reads a single HTTPS URL from `BLACKOUT_DOH_RESOLVER`; absent that, use `https://1.1.1.1/dns-query`, then `https://9.9.9.9/dns-query`, then `https://8.8.8.8/dns-query`.
- Query construction must URL-encode the domain and set `Accept: application/dns-json`; return the first IPv4 A answer, otherwise continue to next endpoint.

- [ ] **Step 1: Write failing tests** for domain URL encoding, configured endpoint precedence, ordered fallback after network/invalid-response failures, IPv4 literal passthrough, and final `None` after all endpoints fail. Mock only `urlopen`; exercise actual resolver-selection and response-parsing code.
- [ ] **Step 2: Run `pytest tests/test_egress_config.py -q`** and confirm failures name missing configuration/fallback behavior.
- [ ] **Step 3: Implement endpoint validation and ordered HTTPS requests** with TLS verification left at the standard library default and the caller's timeout applied to each attempt.
- [ ] **Step 4: Update `NETWORK_PRIVACY.md`** to list defaults, environment override, fallback semantics, and the fact that DNS answers remain best-effort.
- [ ] **Step 5: Run `pytest tests/test_egress_config.py tests/test_network_tools.py tests/test_reality.py tests/test_security_boundaries.py -q`** and `git diff --check`.
- [ ] **Step 6: Commit** `fix(egress): configure HTTPS DoH bootstrap resolvers`.

### Task 3: Mirage ClientHello-aware segmentation in v2 dialer

**Files:**
- Modify: `engine/v2/pkg/dialer/fragment.go`
- Modify: `engine/v2/pkg/dialer/fragment_test.go`
- Modify: `engine/v2/pkg/dialer/sni.go` only if a boundary helper is needed

**Interfaces:**
- Preserve existing `Config`, `Split`, `WriteFragmented`, and `WriteHello` callers.
- Add an SNI-boundary-aware split helper with an explicit `*rand.Rand`; choose a segment edge 3–12 bytes into the parsed hostname bytes when a valid partition within configured chunk bounds exists, otherwise use the existing split behavior.
- Existing `WriteHello` remains capable of replayable deterministic tests; no packet flags or raw-socket behavior are added.

- [ ] **Step 1: Write failing Go tests** for ClientHello SNI byte offsets at both segment edges, randomized split offsets bounded to 3–12 bytes around a valid SNI boundary, byte-preserving reassembly, and malformed/no-SNI pass-through.
- [ ] **Step 2: Run `go -C engine/v2 test ./pkg/dialer -run 'Test.*SNI.*Segment|Test.*Boundary' -count=1`** and confirm the new behavior fails.
- [ ] **Step 3: Implement a parser-derived SNI offset** by reusing the existing ClientHello structure parser; choose a deterministic seeded offset in the allowed window and construct segments without changing payload bytes.
- [ ] **Step 4: Keep `WriteHello` behavior compatible** when segmentation is disabled or the ClientHello/SNI cannot be parsed; avoid changing flags, fake sequence/window values, or socket protocol.
- [ ] **Step 5: Run `go -C engine/v2 test ./pkg/dialer -count=1` and `go -C engine/v2 test -race ./pkg/dialer -count=1`**.
- [ ] **Step 6: Commit** `feat(engine): split ClientHello at randomized SNI boundaries`.

### Task 4: Standalone HyperPulse GF(256) FEC codec and parity policy

**Files:**
- Create: `engine/v2/pkg/hyperpulse/gf256.go`
- Create: `engine/v2/pkg/hyperpulse/codec.go`
- Create: `engine/v2/pkg/hyperpulse/adaptive.go`
- Create: `engine/v2/pkg/hyperpulse/hyperpulse_test.go`

**Interfaces:**
- `Encode(data [][]byte, parityCount int) ([][]byte, error)` returns systematic parity rows using GF(256) polynomial `0x11D`.
- `Recover(data [][]byte, parity [][]byte, missing []int) ([][]byte, error)` reconstructs up to the available parity count without mutating non-missing source packets.
- `AdaptivePolicy.Observe(rtt time.Duration, dropped, sent uint64) int` maintains bounded sliding-window RTT/drop measurements and returns a parity count in caller-supplied limits; it is a policy output only and sends no packets.

- [ ] **Step 1: Write failing tests** with hand-checked GF multiplication/inverse vectors, XOR addition, parity output for a fixed 2-source/1-parity fixture, recovery of one and multiple missing shards, malformed lengths/indices, and adaptive policy min/max/clamping behavior.
- [ ] **Step 2: Run `go -C engine/v2 test ./pkg/hyperpulse -count=1`** and confirm tests fail because the package/API is not present.
- [ ] **Step 3: Implement log/exp tables** for primitive polynomial `0x11D`, then multiplication and inverse operations.
- [ ] **Step 4: Implement systematic Cauchy/Vandermonde parity rows and Gaussian-elimination recovery**, validating equal shard lengths and missing-index uniqueness/range at the package boundary.
- [ ] **Step 5: Implement a bounded sliding-window policy** that uses measured drop ratio and RTT variation to choose parity count, without coupling it to transport or external services.
- [ ] **Step 6: Run `go -C engine/v2 test ./pkg/hyperpulse -count=1` and `go -C engine/v2 test -race ./pkg/hyperpulse -count=1`**.
- [ ] **Step 7: Commit** `feat(engine): add standalone GF256 FEC primitives`.

### Task 5: Data-phase health monitor timing and decision behavior

**Files:**
- Modify: `blackoutkit/daemon/__init__.py` (canonical daemon implementation; `blackoutkit.daemon` resolves to this package)
- Modify: `blackoutkit/scanner/proxy_tester.py` (ensure cached HTTP clients honor bounded per-probe timeouts)
- Modify: `tests/test_daemon.py`
- Modify: `tests/test_daemon_lifecycle.py`

**Interfaces:**
- Keep existing heartbeat and config-rotation settings compatible.
- During the first five seconds after engine start, schedule the local proxy probes at 100 ms cadence and bound each HTTP probe to 200 ms; otherwise keep the existing heartbeat path.
- Include timeout in cached HTTP client identity so a client created for a longer timeout cannot defeat the early probe bound.
- Treat two consecutive failed probes as confirmation to avoid reacting to one transient local failure; do not claim a TLS handshake signal or inspect external packet counters.

- [ ] **Step 1: Add a deterministic failing daemon test** with injected monotonic clock/probe outcomes showing that two local proxy failures within the initial five-second window trigger exactly one rotation without waiting for the normal heartbeat interval.
- [ ] **Step 2: Run the exact new test** and confirm it fails because the existing daemon only probes on the regular retry interval.
- [ ] **Step 3: Implement the smallest bounded early-probe schedule** using existing connection start time and injected test seams; preserve shutdown checks and existing maximum-retry semantics.
- [ ] **Step 4: Add tests** proving success resets the counter, one transient failure does not rotate, non-proxy engines remain unchanged, and shutdown prevents another probe.
- [ ] **Step 5: Run `pytest tests/test_daemon.py tests/test_daemon_lifecycle.py tests/test_russia_diagnostics.py -q`**.
- [ ] **Step 6: Commit** `fix(daemon): detect early data-phase proxy drops`.

### Task 6: Release documentation, tests, and v1.3.0 metadata

**Files:**
- Modify: `tests/test_egress_config.py`
- Modify: `tests/test_security_boundaries.py` only for directly relevant guard regression coverage
- Modify: `CHANGELOG.md`
- Modify: `pyproject.toml`
- Modify: `blackoutkit/__init__.py`
- Modify: `README.md`, `SECURITY.md`, `NETWORK_PRIVACY.md`, and `docs/V2_PHASE1_REPORT.md` if their existing claims need correction

**Interfaces:**
- `pyproject.toml` project version and `blackoutkit.__version__` both become `1.3.0`.
- Changelog must call out HTTPS ISP lookup, configurable DoH, ClientHello segmentation, standalone HyperPulse codec/policy (not wire-integrated), and data-phase detection scope accurately.
- No release note may claim TCP flag/zero-window randomization, live FEC transport, or sub-second TLS handshake detection.

- [ ] **Step 1: Add a test** asserting the package metadata version and `blackoutkit.__version__` remain equal to `1.3.0` after the release metadata change.
- [ ] **Step 2: Run the version test** and confirm it fails before the bump.
- [ ] **Step 3: Update version metadata and changelog** with only behaviors that actually pass their tests.
- [ ] **Step 4: Update docs** to state ISP/DoH endpoint order and that FEC is a standalone codec/policy with no peer wire integration.
- [ ] **Step 5: Run focused Python coverage**: `pytest tests/test_egress_config.py tests/test_network_switcher.py tests/test_network_tools.py tests/test_security_boundaries.py tests/test_daemon.py tests/test_daemon_lifecycle.py -q`.
- [ ] **Step 6: Run Go verification**: `go -C engine/v2 test -v ./...`, `go -C engine/v2 test -bench=. ./...`, `go -C engine test ./...`.
- [ ] **Step 7: Run `git diff --check`, inspect `git diff`, and confirm only intended files changed**.
- [ ] **Step 8: Commit** `chore(release): prepare v1.3.0 Phase 3 hardening`.
- [ ] **Step 9: Push `main` and create annotated tag `v1.3.0` only if every targeted check passes and the final diff matches this plan**.
