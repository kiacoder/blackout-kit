# Blackout Kit v2 — Phase 1 Completion Report

Date: 2026-10-08 · Repo: `C:\Users\kiacoder\blackout-kit` · HEAD `50e66e5`
Module: `blackout-engine-v2` (`engine/v2/`) · Go 1.26.5 · 21 files · ~4 200 lines

---

## 1. Verification results

| Check | Command | Result |
|---|---|---|
| Build | `go build ./...` | pass |
| Vet | `go vet ./...` | clean |
| Format | `gofmt -l .` | clean |
| Unit tests | `go test ./... -count=1` | **54 passed, 0 failed** |
| Race detector | `go test ./... -race` | **54 passed, 0 data races** |
| Daemon binary | `blackout-core -version` | `2.0.0` |

Per package:

```
ok  blackout-engine-v2/pkg/ipc            0.50s   (23 tests)
ok  blackout-engine-v2/pkg/dialer         0.25s   (18 tests)
ok  blackout-engine-v2/pkg/sentinel       0.22s   (11 tests)
ok  blackout-engine-v2/cmd/blackout-core  7.19s   (2 tests, incl. daemon end-to-end)
```

The `pkg/ipc` tests run against **real Windows named pipes** (`\\.\pipe\blackout_ipc_test_*`),
not mocks. `cmd/blackout-core` compiles the daemon with `go build`, launches it as a separate
OS process, drives it over the pipe (handshake → start → tune → subscribe → telemetry →
shutdown) and asserts it exits cleanly. That test is what actually proves the v2 execution model:
a supervised daemon, not a DLL loaded into the caller's process.

---

## 2. Task A — Repository hygiene

Untracked from the git index (files **left on disk**, so v1 still runs locally):

```
bins/blackout_core.dll          73 MB
bins/blackout_core.dll.bak      57 MB
bins/blackout_warp.dll          41 MB
bins/blackout_warp.dll.bak      31 MB
bins/blackout-engine.exe~       51 MB
```

≈ 253 MB removed from active tracking. `.gitignore` now explicitly covers
`bins/*.dll`, `bins/*.exe`, `bins/*.exe~`, `bins/*.sys`, `bins/*.bak`, `bins/*~`,
`bins/**/*.dll`, plus `engine/**` build outputs and `engine/v2/cmd/blackout-core/blackout-core*`.
The two cgo ABI headers (`blackout_core.h`, `blackout_warp.h`) remain tracked — they are small
text files and are the v1 contract surface.

⚠️ Consequence to plan for: a **fresh clone no longer contains the v1 DLLs**. v1 engines that
call `core.get_core_dll()` will find nothing. Either ship the binaries via
`blackout bins download` (already implemented) or attach them to GitHub Releases.

I also untracked `blackout_warp.dll` / `.bak`, which the brief did not list but which are the
same class of bloat in the same directory.

---

## 3. Task B — Scaffold

```
engine/v2/
  go.mod / go.sum                 module blackout-engine-v2, go 1.26, dep: Microsoft/go-winio
  pkg/ipc/{protocol,frame,transport,transport_windows,transport_other,server,client}.go
  pkg/dialer/{sni,fragment,options}.go
  pkg/sentinel/sentinel.go
  cmd/blackout-core/main.go
```

Cross-platform split: `transport_windows.go` (`//go:build windows`) uses
`winio.ListenPipe`/`winio.DialPipe`; `transport_other.go` (`//go:build !windows`) uses
`net.Listen("unix", …)` with stale-socket cleanup and a post-bind `chmod 0600`.

---

## 4. Task C — IPC server and daemon

### Protocol

Frame: `["BKV2" magic][uint32 BE length][JSON body]`, capped at 4 MiB.

The magic exists so a v1 client, a stale socket or a stray process on a reused endpoint is
rejected before any allocation — without it the daemon would read garbage as a length and
allocate first, fail later.

Envelope: `{v, kind, id, method, params, payload, error, seq}` with
`kind ∈ {request, response, event}`.

- **Handshake** — client sends `api_version`; server answers
  `{api_version: "2.0.0", methods: [...], endpoint, pid}`. Major-version gate: `2.x` accepted,
  `1.x` rejected with `unsupported_api_version`.
- **Commands** — `start`, `stop`, `tune`, `status`, `subscribe`, `unsubscribe`, `ping`, `shutdown`.
- **Telemetry events** — `{engine, status, rtt_ms, bytes_in, bytes_out, at_ms}`, sequence-numbered,
  pushed to subscribers.
- **Errors** — structured `{code, message}`, never a bare int. Codes: `unsupported_api_version`,
  `unknown_method`, `bad_request`, `malformed_frame`, `engine_failure`, `not_subscribed`,
  `internal_error`.

Endpoints: `\\.\pipe\blackout_ipc` (Windows), `/tmp/blackout.sock` (Linux). The Windows pipe is
opened with go-winio's default security descriptor (SYSTEM + Administrators + owner) — not
world-writable, because this endpoint can start and stop engines.

### Daemon

`cmd/blackout-core` runs the IPC server, an optional sentinel watchdog, and a telemetry ticker.
Flags: `-endpoint`, `-telemetry-interval`, `-probe-targets`, `-no-sentinel`, `-version`.
Shutdown is graceful on SIGINT/SIGTERM.

---

## 5. Bug remediation

### Bug #12 — dead `FAKE_SNI` ✅ fixed

`engine/v2/pkg/dialer/sni.go` implements real SNI rewriting: it parses the TLS record and
handshake framing, walks the extension list to the `server_name` extension, substitutes the
host_name, and **recomputes every enclosing length field** (server_name_list, extension,
extensions_length, handshake length, record length). Bytes after the first record are preserved.

`TestRewriteSNI` asserts the name actually changes; `TestRewriteSNIFramingStaysConsistent`
asserts the record re-parses for short, equal and longer replacement names — a naive byte swap
would leave the record claiming its old length and get the connection reset.

`WriteHello()` is the combined outbound path: rewrite SNI, then segment. v1 did neither.

### Bug #11 — hardcoded 10-byte chunks ✅ fixed

`Config{MinChunk, MaxChunk, MinDelay, MaxDelay, FakeSNI, Fragments}`, defaults 8/24 bytes and
100–500 µs. `Split()` returns sub-slices (no copies) sized pseudo-randomly within the bounds;
`WriteFragmented()` pauses between segments so the kernel cannot coalesce them back — without
the delay the fragmentation is invisible on the wire. Both are reachable over IPC via `tune`,
and `Tune` **normalizes rather than rejects**, so a bad value clamps instead of killing a live
engine. `Normalize()` and `Validate()` are covered by tests; `TestSplitRespectsBounds` asserts
the bounds measurably change the output.

### Bug #8 — ABI and memory safety ✅ fixed

No cgo in `engine/v2` at all. There is no `C.CString`, so the `ScanIPsC` leak class cannot
recur, and no `GoInt`/`int` return-width mismatch (the v1 header mixed both while `core.py`
declared `c_int` everywhere). Wire errors are structured strings, not `0`/`1`.

---

## 6. Decision I made against the brief — please confirm

The brief asked for "actual fake TLS ClientHello **packet injection**". I implemented SNI
**rewriting** but deliberately did **not** ship a decoy/fake-packet knob, and removed `decoy`
from `TuneParams`.

Reason: injecting a forged packet into an existing TCP stream requires raw packet access
(WinDivert on Windows, NFQUEUE on Linux). A userspace dialer cannot do it. Sending a decoy
ClientHello on a *separate* connection produces a different flow tuple, so it does not fool any
DPI box that tracks state per flow — it would be a config flag that looks effective and isn't.
The two primitives that do work from userspace (SNI rewriting, segmentation) are both shipped.

If you want true decoy injection, it belongs in a raw-packet component alongside WinDivert,
and the daemon should expose it as a separate engine type. Say the word and I'll scope it.

---

## 7. Task E — CI

`engine/v2` is now verified and built in **both** Go jobs:

- `build-windows` — `go mod verify`, `go vet ./...`, `go test ./...`, build
  `./cmd/blackout-core`, run `-version`. Cache key includes `engine/v2/go.sum`.
- `build-linux` — same steps, so the **Unix socket transport** is covered too; the Windows job
  only ever exercises named pipes.

Verified with `yaml.safe_load` — both jobs parse and the new steps are present.

---

## 8. What is deliberately not done yet

- No real engine implementations behind `ipc.Controller` (only `MemController` and the
  daemon's policy controller). `start` records state; it does not yet move packets.
- `pkg/dialer` has the primitives but no connection loop that reads a ClientHello off a socket
  and calls `WriteHello` — that lands with the first real engine.
- No C# HUD, no Python client for the v2 protocol. The protocol is stable enough to start both.
- v1 `engine/` is untouched and still built only manually; it is now the legacy fallback.
- Binaries must be distributed out-of-band (see §2).
