# Contributing to Blackout Kit

This guide is for contributors, maintainers, and anyone touching packaging, tests, docs, or engine/runtime behavior.

If you only want to use the app, read [docs/user-guide.md](docs/user-guide.md).

---

## Project philosophy

Blackout Kit is a high-trust local networking tool. That changes how contribution quality should be judged.

A good change is not just “feature complete.” It should also be:

- accurate in what it claims
- bounded in what it mutates
- explicit about platform scope
- careful about local-vs-remote guarantees
- resistant to leaving the machine in a worse state after failure

For this repo, **documentation accuracy is a security feature**.

---

## Source of truth hierarchy

When code and docs differ, prefer this order:

1. code paths that ship current behavior
2. packaging/build workflows
3. tests that validate user-visible behavior
4. public docs
5. historical notes and scratch handoff files

### Files that define current product behavior

#### Package / release metadata
- `pyproject.toml`
- `blackoutkit/__init__.py`

#### Entrypoints and command surface
- `blackout.py`
- `blackoutkit/typer_cli.py`
- `blackoutkit/cli.py`

#### Engine / platform scope
- `blackoutkit/engines/__init__.py`
- `blackoutkit/routing.py`
- `blackoutkit/engines/xray.py`
- `blackoutkit/engines/sni.py`
- `blackoutkit/engines/gdpi.py`
- `blackoutkit/engines/tun.py`
- `blackoutkit/engines/singbox_proxy.py`
- `blackoutkit/engines/warp.py`
- `blackoutkit/engines/psiphon.py`

#### Safety / storage / trust boundaries
- `blackoutkit/settings.py`
- `blackoutkit/security.py`
- `blackoutkit/vault.py`
- `blackoutkit/readiness.py`
- `blackoutkit/mcp_server.py`
- `blackoutkit/doctor.py`

#### Runtime assets / downloader behavior
- `blackoutkit/downloader.py`
- `blackoutkit/core.py`

#### CI / release pipeline
- `.github/workflows/build.yml`
- `.github/workflows/codeql.yml`

---

## Repository layout

| Path | Purpose |
|---|---|
| `blackout.py` | Source entrypoint |
| `blackoutkit/` | Main Python package |
| `blackoutkit/typer_cli.py` | Public CLI entry surface |
| `blackoutkit/cli.py` | Proven dispatcher and most command implementations |
| `blackoutkit/engines/` | Engine implementations and engine registry |
| `blackoutkit/config/` | Saved config parsing and storage |
| `blackoutkit/scanner/` | Cloudflare scan and proxy test helpers |
| `engine/` | Go sources for native runtime components |
| `docs/` | Public docs site assets and the user guide |
| `tests/` | Python test suite |
| `.github/workflows/` | CI, build, release, and CodeQL workflows |

---

## Platform model

### Windows

Windows is the broad platform target.

Current notable surfaces:

- broad engine catalog
- GUI
- system-proxy flows
- split-tunnel proxy bypass patterns
- DLL-backed native runtime components
- Windows VPN integrations

### Linux

Linux is intentionally narrower.

Current supported engine surface:

- `xray`
- `tun`
- `hysteria2`
- `tuic`

Linux uses the managed `blackout-engine` runtime path and is also where the supported endpoint-scoped kill switch lives.

### Contribution rule

Never describe a Windows-only behavior as cross-platform unless the code proves it.

---

## Runtime asset model

This repo currently uses multiple runtime classes.

### Repo-built native runtime artifacts

- `blackout_core.dll`
- `blackout_warp.dll`
- `blackout-engine-linux-amd64` (released) / `bins/blackout-engine` (local Linux runtime)

### Auto-downloadable runtime assets

Managed by `blackoutkit/downloader.py`.

Examples include:

- `xray`
- `goodbyedpi`
- `sing-box`
- `wireguard`
- `linux_engine`
- `warp_dll`
- `sni-spoofing` (as the project’s current DLL/runtime asset key, not a public user-facing promise that the historical standalone exe still defines the shipped path)

### Manual or semi-manual runtime cases

Some paths are still user-supplied or require external installers/bundles.

Contributors should verify the exact current downloader and doctor behavior before documenting them.

### Documentation rule

Use the naming and scope that the current code uses, not outdated marketing names or old installer stories.

---

## Command-surface rules

The public CLI is Typer-based, but many commands still delegate into `cli.py`.

That means a command may be documented by:

- its Typer declaration in `blackoutkit/typer_cli.py`
- its actual implementation in `blackoutkit/cli.py`

When documenting commands, verify both.

### Important nuance: `legend`

`legend` appears in two meanings:

- security mode: `blackout mode legend`
- connect/start target: `blackout connect legend`

Do not flatten those into one concept in docs or reviews.

---

## Safety boundaries contributors must preserve

### 1. Local vs remote truth

A recurring rule in this repo:

- **local readiness** is not **remote reachability**
- **open local port** is not **working internet path**
- **country profile recommendation** is not **guaranteed success**

Avoid code or docs that blur those boundaries.

### 2. Targeted recovery over destructive reset

Default recovery is intentionally narrow.

Do not turn `blackout fix` into “reset the whole machine” behavior unless the user explicitly requests the broader reset path and the code clearly separates it.

### 3. Windows kill-switch honesty

The old Windows Firewall kill-switch approach is intentionally retired.

Do not reintroduce docs or UX text that implies Windows kill-switch support exists today unless you have reimplemented and verified a safe design.

### 4. Keep `legacy` GDPI as default until parity is real

The repo already includes an experimental native GDPI backend, but the product keeps `legacy` as the default path.

Do not change the default casually, and do not write docs that imply parity before it is demonstrated.

### 5. Documentation accuracy is part of the security model

If a doc claim outgrows the code, fix the doc or the code before shipping.

---

## Tests and verification

At a minimum, after changes touching user-visible behavior, run:

```bash
python blackout.py version
```

```bash
python blackout.py --help
```

```bash
python blackout.py help quick_start
```

```bash
python blackout.py help security
```

```bash
python -m pytest --rootdir=. tests
```

### Docs-sensitive checks

When changing docs, command wording, or help text, also check for drift by grepping or reviewing references to:

- Windows kill switch claims
- native-vs-legacy GDPI claims
- platform support lists
- runtime asset names
- README / guide cross-links
- manual vs auto-download binary claims
- REALITY vs normal TLS wording

---

## CI and release pipeline

Current CI includes:

- Windows build and executable smoke test
- Linux runtime build
- Python tests on both major paths
- wheel installation smoke tests
- Linux distro package smoke tests
- CodeQL for Python and Go

### Release notes for maintainers

The release pipeline currently publishes:

- `dist/blackout.exe`
- `dist/blackout-engine-linux-amd64`

If you change runtime asset expectations, release docs and README install instructions must be checked in the same pass.

---

## Documentation surfaces to keep aligned

Canonical public docs:

- `README.md`
- `SECURITY.md`
- `ROADMAP.md`
- `docs/user-guide.md`
- `CONTRIBUTING.md`
- GitHub issue and PR templates

Shipped user-facing help surface:

- `blackoutkit/help_text.py`

Internal/local notes that should not be mistaken for canonical public docs:

- local memory files and handoff notes outside the repo

When you update one of the public command descriptions substantially, check whether `help_text.py` now drifts.

---

## Pull request expectations

Good PRs for this repo should clearly say:

- what changed
- why it changed
- which platform(s) it affects
- which engine(s) or command paths it affects
- whether it changes docs, trust boundaries, or recovery behavior
- how it was tested

If a change affects any of these, call it out explicitly:

- system-proxy behavior
- local encryption/vault behavior
- kill-switch behavior
- readiness logic
- route recommendation logic
- downloader/runtime-asset expectations
- crash recovery scope

---

## Issue reporting guidance for contributors

When reproducing or triaging issues, include:

- platform and architecture
- install method (packaged exe, source, wheel, etc.)
- command used
- engine used
- whether the daemon was involved
- whether the issue is local-only or depends on a remote server
- whether admin/root was required or granted
- whether the bug is about trust/privacy, availability, packaging, or UX

This matters because the same symptom can come from very different layers in Blackout Kit.

---

## Good contribution targets

High-value contribution areas usually include:

- docs and in-app help alignment
- tests for user-visible command behavior
- packaging and runtime provenance clarity
- targeted recovery correctness
- readiness / route recommendation correctness
- clearer contributor tooling and diagnostics
- native GDPI parity verification work

---

## Things to avoid

Avoid these unless you have strong justification and verification:

- broad destructive cleanup as a shortcut
- docs that promise privacy or success beyond the code
- platform generalization without testing
- renaming runtime assets casually without updating every affected surface
- mixing historical scratch notes with current canonical docs
- making the UI or help output imply remote validation when only local checks ran

---

## Final maintainer rule

For Blackout Kit, a change is only “done” when:

1. the runtime behavior is correct
2. the boundary claims are still true
3. the docs and help surfaces say the same thing

That is the standard for code, docs, and release work alike.
