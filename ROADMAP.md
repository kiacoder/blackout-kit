# Blackout Kit — Roadmap

This roadmap reflects the **current 1.1.1 codebase** and separates shipped work from next-step work more clearly.

Ranks in historical project language remain useful as flavor, but this roadmap now prioritizes factual status over hype.

---

## Current release line: 1.1.1 stabilization

The current line is focused on **stabilization, correctness, packaging, documentation accuracy, and boundary hardening**.

That includes work already visible in the codebase such as:

- Typer-based public CLI routing
- Windows packaged executable and Linux runtime build pipeline
- Linux managed runtime support for `xray`, `tun`, `hysteria2`, and `tuic`
- local readiness checks
- route recommendation dashboard
- targeted recovery and recovery audit history
- machine-bound vault storage for proxy URIs and supported VPN secrets
- MCP server with an explicitly constrained tool surface
- client-side VLESS REALITY handling
- experimental native GDPI backend with `legacy` kept as the default

---

## Shipped capabilities

### Core product and UX

| Item | Status | Notes |
|---|---|---|
| Typer public CLI | Done | `blackoutkit/typer_cli.py` is the current public CLI entrypoint |
| Legacy dispatcher compatibility | Done | Typer forwards into the established `cli.py` command implementations |
| Zero-flag launcher flow | Done | Launcher tries GUI first and falls back to interactive terminal menu |
| Route recommendation dashboard | Done | Local-only ranking via `blackout route` |
| Local readiness checks | Done | `blackout ready [engine]` and internal gating before connect/start paths |
| Live status view | Done | `blackout status --watch` |
| Desktop GUI | Done | Windows-only `CustomTkinter` GUI surface |
| MCP server | Done | Documented stdio tool surface in `blackoutkit/mcp_server.py` |

### Connection/runtime surface

| Item | Windows | Linux | Notes |
|---|---|---|---|
| SNI path | Done | Not supported | Windows-only native DLL-backed SNI runtime |
| XRay path | Done | Done | Linux uses the managed `blackout-engine` runner |
| TUN path | Done | Done | Linux requires root and its managed runtime path |
| Hysteria2 | Done | Done | sing-box proxy mode via native DLL or Linux runner |
| TUIC | Done | Done | sing-box proxy mode via native DLL or Linux runner |
| WARP | Done | Not supported | Current runtime is backed by `blackout_warp.dll` |
| Psiphon | Done | Not supported | Current runtime is backed by `blackout_warp.dll` |
| GoodbyeDPI legacy | Done | Not supported | Stable default backend |
| GoodbyeDPI native | Experimental | Not supported | Product keeps `legacy` as the default |
| Tor | Done | Not a primary supported path | Requires a supplied runtime |
| Windows VPN engines | Done | Not supported | IKEv2, WireGuard, OpenVPN, SoftEther |
| Apps Script relay | Done | Limited | HTTP relay path only |
| mhrv relay | Done | Limited | Embedded HTTP relay; not HTTPS MITM |

### Safety, repair, and storage

| Item | Status | Notes |
|---|---|---|
| Linux endpoint-scoped kill switch | Done | Supported kill-switch implementation |
| Windows kill switch | Retired | Legacy rules intentionally removed rather than treated as supported protection |
| Targeted crash recovery | Done | Blackout-owned routes/proxy/DNS/adapter/firewall cleanup |
| Recovery preview/history | Done | Preview and bounded redacted audit history |
| Machine-bound encrypted config vault | Done | Protects proxy URIs and supported secrets at rest |
| Defender exclusion helper | Done | Windows path via `doctor --fix-av` |
| Country profiles | Done | IR, RU, CN, IQ, GB, US, EU |

---

## Immediate documentation and maintenance priorities

These are the highest-value near-term priorities after the current documentation refresh.

### 1. Native GDPI parity decision

**Status:** Active product question

The codebase already includes an experimental native GDPI path, but the product intentionally keeps `legacy` as the default.

Near-term goal:

- verify whether the native path reaches functional parity on real Windows environments
- document exact limitations if it does not
- keep `legacy` default until parity is demonstrated, not assumed

### 2. Documentation and in-app help alignment

**Status:** Active

The markdown docs, contributor docs, and `blackout help` content should stay aligned with the actual 1.1.1 runtime surface.

Near-term goal:

- keep code, README, guides, and in-app help in lockstep
- avoid claims that outgrow the shipped code

### 3. Release/runtime provenance clarity

**Status:** Active

The project now mixes Python packaging, packaged Windows executable flows, repo-built DLL/runtime assets, and some still-external runtime dependencies.

Near-term goal:

- keep the provenance story clear for users and contributors
- make it obvious which runtimes are repo-built, release-provided, auto-downloaded, or user-supplied

---

## Next likely feature wave

These are reasonable next-step areas, but they should be treated as **candidates**, not promises.

### Advanced routing and runtime quality

| Candidate | Why it matters | Current caution |
|---|---|---|
| Persistent daemon IPC improvements | Cleaner status/control channel | Should not destabilize the existing daemon lifecycle |
| Better local health scoring | Smarter engine recommendations | Must stay clearly local-only and not imply remote validation |
| More polished GUI workflows | Better usability for Windows users | GUI should remain honest about local-vs-remote state |
| Runtime provenance reporting | Better trust/debug story | Needs careful wording and release integration |

### Transport and protocol work

| Candidate | Why it matters | Current caution |
|---|---|---|
| ShadowTLS evaluation | Useful transport option in some environments | Must be implemented and verified before being advertised |
| More sing-box-backed protocol coverage | Reuse native/runtime infrastructure | Avoid feature claims before configuration and validation are real |
| Better Linux operational ergonomics | Makes Linux support easier to use | Keep Linux scope explicit rather than growing implied support |

### Contributor and release operations

| Candidate | Why it matters | Current caution |
|---|---|---|
| Stronger release checklists | Better artifact confidence | Avoid claiming reproducibility that is not actually enforced |
| More targeted tests around docs-sensitive behavior | Prevent docs drift | Focus on user-visible commands, readiness, recovery, and config flows |
| Public maintainer docs | Easier outside contribution | Keep internal scratch notes separate from canonical docs |

---

## Explicitly deferred or intentionally limited areas

These areas are either intentionally limited today or should not be presented as active product guarantees.

| Area | Current stance |
|---|---|
| Windows kill switch | Intentionally unsupported; legacy rules removed |
| Full Linux parity with Windows engine catalog | Not a current goal |
| Claims of anonymity or detection resistance | Avoid unless independently justified |
| “Country profile means it will work there” messaging | Avoid; profiles are guidance only |
| Aggressive auto-repair of unrelated network state | Avoid; targeted recovery is the policy |
| Making native GDPI the default prematurely | Avoid until parity is proven |

---

## Version focus summary

| Version line | Focus |
|---|---|
| 1.1.x | Stabilization, packaging, boundary hardening, docs accuracy, Linux managed runtime support |
| 1.2.x | Only after stabilization: carefully selected transport/runtime improvements and contributor ergonomics |
| Later | Broader UX/runtime expansions only if they can be documented and verified honestly |

---

## Maintainer rule of thumb

A roadmap item should move from “candidate” to “shipped” only when all three are true:

1. the code path exists
2. the platform/runtime scope is explicit
3. the docs can describe it without hedging into fiction

That rule is especially important for a project like Blackout Kit, where inaccurate claims are themselves a security and trust problem.
