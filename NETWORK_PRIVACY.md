# Network Privacy & Egress Disclosure

Blackout Kit is a local network tool. This document is an exhaustive disclosure of every
outbound network destination the software can contact, the exact trigger for each, and what
data leaves the machine. It exists so that an independent auditor can verify the claims against
source without trusting this file.

Every entry below cites the file and line where the behaviour lives. Where this document and the
code disagree, **the code is authoritative** — please file an issue.

---

## 1. Telemetry & Tracking

| Claim | Value |
| :--- | :--- |
| Telemetry endpoints | **0** |
| Tracking / analytics SDKs | **0** |
| Background phone-home calls | **0** |
| Crash reporting / error upload | **0** |
| Usage counters, beacons, pixels | **0** |

Blackout Kit contains **no telemetry backend, no analytics SDK, no crash reporter, and no
licensing or activation check.** There is no server that receives usage data, because no such
server exists in this project.

**How to verify:**

```bash
# No telemetry/analytics/crash-reporting client is present anywhere in the package:
grep -rniE "telemetry|analytics|sentry|posthog|mixpanel|amplitude|segment\.io|google-analytics|appcenter" \
  --include="*.py" blackoutkit/

# The GitHub update check has exactly ONE call site, inside the `update` command:
grep -rn --include="*.py" "check_for_update" blackoutkit/

# The daemon packages contain no HTTP client usage at all:
grep -rnE --include="*.py" "urlopen|httpx|requests\.|urllib" blackoutkit/daemon/
```

The third command returns **no matches**. The background daemon (`qos_monitor`,
`traffic_monitor`, `dns_interceptor`, `qos_shaper`) performs no HTTP egress of any kind; its
threads operate on local sockets, routing tables, and engine subprocesses only.

> **Note on `adblock_auto_update_interval_hours`:** `blackoutkit/settings.py:184` declares this
> setting with a 24-hour default. It is a **declared setting with no scheduler wired to it** —
> nothing reads it on a timer, so it causes **no background traffic today**. Blocklist refresh
> happens only when you run `blackout threat-feeds update`. This is flagged so that no auditor
> mistakes the setting name for an active background updater.

---

## 2. Update Checks

Update checks are **manual-only**. There is no startup check, no periodic check, and no silent
version ping.

| Property | Value |
| :--- | :--- |
| Trigger | `blackout update` (explicit user invocation only) |
| Endpoint | `https://api.github.com/repos/kiacoder/blackout-kit/releases/latest` |
| Frequency | Never automatic |
| Data sent | `User-Agent: blackout-kit/<version>` and standard HTTP headers only |

**Enforcement:** `check_for_update()` (`blackoutkit/updater.py:48`) has exactly one caller —
`cmd_update` at `blackoutkit/cli.py:3802`, which is reachable only through the `update` command
registered at `blackoutkit/typer_cli.py:3497`. No import-time or daemon-time call path exists.

The updater additionally pins its destination against a host allowlist
(`_UPDATE_TRUSTED_HOSTS`, `blackoutkit/updater.py:29`) and refuses any releases endpoint that is
not `api.github.com` (`blackoutkit/updater.py:54`).

**Nothing is transmitted except the HTTP request itself.** Your IP address is visible to GitHub
as a consequence of the TCP connection — this is unavoidable for any outbound request and is not
a telemetry payload. No machine ID, config, config-hash, hardware fingerprint, or usage history
is sent.

---

## 3. DNS Resolution (DNS-over-HTTPS)

| Property | Value |
| :--- | :--- |
| Trigger | `blackout dns proxy` (explicit), or resolution during an active bypass session |
| Default upstream | `https://1.1.1.1/dns-query` (Cloudflare) |
| User override | `--upstream <url>` |
| Listener bind | `127.0.0.1` — non-loopback bind is **refused** |
| Validation | HTTPS required, embedded credentials rejected |

The DoH listener binds to loopback and **hard-refuses** any non-loopback address
(`blackoutkit/tools.py:2085`). The upstream must be `https://` with no embedded credentials
(`_validate_doh_upstream`, `blackoutkit/tools.py:2077`).

### ⚠️ Disclosure: the DoH upstream is Cloudflare by default

The task-level summary "DoH queries target user-configured endpoints" requires an important
correction. The default is **not** user-configured — it is a hard-coded Cloudflare endpoint:

- `blackoutkit/typer_cli.py:4252` — `--upstream` defaults to `https://1.1.1.1/dns-query`
- `blackoutkit/tools.py:2068` — same default in `run_doh_proxy_server`

Unless you pass `--upstream`, **every domain you resolve is disclosed to Cloudflare (AS13335).**
Set `--upstream` to your own resolver if that is unacceptable.

### ⚠️ Disclosure: the DoH bootstrap resolver is not configurable

`_resolve_via_doh` (`blackoutkit/tools.py:647`) hard-codes
`https://1.1.1.1/dns-query?name=<domain>&type=A` with **no configuration hook at all**. It is a
fallback used when the OS resolver cannot answer. Any domain passed to it is disclosed to
Cloudflare regardless of your `--upstream` setting. This is listed as a remediation candidate in
§8.

Also note the DoH proxy is a **standalone command** — it is not confined to active bypass
sessions. It runs whenever you start it, and for as long as you leave it running.

---

## 4. GeoIP / ISP & Diagnostics

### ⚠️ Disclosure: ISP lookup uses plaintext HTTP and is not diagnostics-only

Two corrections to the summary wording, both material:

**(a) The ISP lookup leaves the machine over unencrypted HTTP.** `blackoutkit/network_switcher.py:231`
queries:

```
http://ip-api.com/json?fields=isp,org,as,city,country,countryCode
```

with an HTTPS fallback to `https://ipinfo.io/json` (`network_switcher.py:254`). The primary is
**`http://`, not `https://`** — your approximate city/country and the request itself traverse the
path unencrypted and are visible to any on-path observer. The destination is a fixed allowlist
(`_ISP_LOOKUP_HOSTS`, `network_switcher.py:16`), **not** loopback and **not** user-selected.

**(b) It is reachable outside diagnostic commands.** Carrier auto-detection is offered during
interactive `blackout connect` when you select `auto` (`blackoutkit/connection_service.py:211`).
This is a **connection-time** lookup, not a diagnostic one.

**What leaves:** nothing but the HTTP request itself — no user agent beyond the default, no
credentials, no config. The remote service infers your approximate location from your source IP,
which it sees anyway.

### Public IP detection

`blackoutkit/tools.py:791` queries `https://api.ipify.org`, `https://checkip.amazonaws.com`, and
`https://ifconfig.me/ip` in sequence to report your egress IP. Explicit command only.

### `doctor` connectivity probes

`blackout doctor` probes **public internet endpoints** to test reachability — these are **not**
loopback:

| Region | Probed URLs | Location |
| :--- | :--- | :--- |
| Default | `http://cp.cloudflare.com/`, `http://www.google.com/generate_204` | `blackoutkit/doctor.py:541` |
| China | `http://www.baidu.com`, `http://www.qq.com` | `blackoutkit/doctor.py:539` |

All are scheme-validated through `_validated_probe_url` (`doctor.py:554`). Both probe sets are
plain `http://`.

### Bandwidth benchmark

`blackout speedtest` transfers test payloads to/from `speed.cloudflare.com`
(`blackoutkit/tools.py:688`–`705`). This **uploads data to Cloudflare** by design — that is what a
speed test is. Run it only if you accept that.

---

## 5. MCP Server

| Property | Value |
| :--- | :--- |
| Transport | **Local stdio only** (JSON-RPC 2.0 over stdin/stdout) |
| Exposed network sockets | **0** |
| Listening ports | **0** |
| Remotely reachable | **No** |

The MCP server (`blackoutkit/mcp_server.py`) reads JSON-RPC messages from stdin and writes to
stdout (`mcp_server.py:688`). It **never opens a socket** — the module's only imports are `hmac`,
`json`, `logging`, `os`, `sys`, and the local `settings` module (`mcp_server.py:25`–`31`); there is
no `socket` import and no listener construction of any kind. There is no port to scan and no
network path to it.

Internal imports and log output are redirected from stdout to stderr (`mcp_server.py:72`) so that
nothing can corrupt the JSON-RPC frame stream.

Privileged tool calls are gated by `BLACKOUT_MCP_TOKEN` (fallback `BLACKOUT_MCP_SECRET`) using a
constant-time `hmac.compare_digest` comparison that **fails closed** (`mcp_server.py:334`–`390`).
See `SECURITY.md` → "MCP authorization".

---

## 6. Complete Egress Inventory

Every external destination reachable from this codebase. "Trigger" is always an explicit user
action unless noted.

| Destination | Purpose | Trigger | Transport |
| :--- | :--- | :--- | :--- |
| `api.github.com` | Release metadata | `blackout update` | HTTPS |
| `github.com`, `raw.githubusercontent.com` | Source/asset download | `blackout update --apply` | HTTPS |
| `1.1.1.1` (Cloudflare) | DoH resolution | DNS proxy / bypass session / DoH bootstrap | HTTPS |
| `cp.cloudflare.com`, `www.google.com/generate_204` | Connectivity probe | `blackout doctor` | ⚠️ HTTP |
| `www.baidu.com`, `www.qq.com` | Connectivity probe (CN region) | `blackout doctor` | ⚠️ HTTP |
| `ip-api.com` | ISP / country detection | ISP auto-detect | ⚠️ HTTP |
| `ipinfo.io` | ISP detection fallback | ISP auto-detect | HTTPS |
| `api.ipify.org`, `checkip.amazonaws.com`, `ifconfig.me` | Public IP report | Explicit IP command | HTTPS |
| `speed.cloudflare.com` | Bandwidth benchmark | `blackout speedtest` | HTTP + HTTPS |
| `sslbl.abuse.ch`, `data.phishtank.com`, `rules.emergingthreats.net` | Threat feeds | `blackout threat-feeds update` | HTTPS |
| `easylist-downloads.adblockplus.org`, `phishing.army` | Ad-block lists | `blackout adblock …` | HTTPS |
| `dist.torproject.org`, `build.openvpn.net`, `www.softether.org` | Engine binaries | `blackout bins install …` | HTTPS |
| `script.google.com` | User's own Apps Script relay | User-configured relay | HTTPS-enforced |
| `detectportal.firefox.com` | Captive-portal detection | Proxy connectivity test | HTTP |
| Your configured VPN / proxy nodes | The bypass itself | `blackout connect` | Engine-dependent |

### Third-party CDN fetch by the local report page

The HTML report served by `blackoutkit/tools.py:2412` embeds
`<script src="https://cdn.jsdelivr.net/npm/chart.js">`. When you open that report **in a
browser**, your browser — not Blackout Kit — fetches Chart.js from jsDelivr, disclosing the page
view to that CDN. The Python process never contacts it. Opened offline, the charts simply do not
render.

---

## 7. What Never Leaves This Machine

- Saved proxy/VPN/SSH configs and URIs (`configs.enc`, `ssh_vault.json`)
- Vault contents and settings secrets (`secrets.enc`)
- Machine identity / machine-bound encryption keys
- Event journal (`events.jsonl`), stability history, scan caches
- Support bundles — written **only** to the path you choose, with secrets removed rather than
  masked (`blackout support-bundle --preview` shows exactly what will be written)
- Credentials — passed directly to native engines, never written to temp files, never logged

Nothing syncs to any cloud service. There is no cloud service.

---

## 8. Remediation Candidates

These are **known, disclosed, and not yet fixed.** They are listed here rather than hidden, and
are tracked for a future change. This document describes current behaviour, not intended
behaviour.

| # | Issue | Location | Severity | Proposed fix |
| :-- | :--- | :--- | :--- | :--- |
| 1 | ISP lookup uses **plaintext HTTP** to `ip-api.com`, exposing the request to on-path observers | `blackoutkit/network_switcher.py:231` | 🟡 Medium | Switch primary to the HTTPS variant `https://ip-api.com/json/…` (the service supports it), or make `ipinfo.io` the primary |
| 2 | DoH defaults to hard-coded Cloudflare `1.1.1.1`, so "user-configured" is only true if the user overrides it | `blackoutkit/typer_cli.py:4252`, `tools.py:2068` | 🟡 Medium | Surface the upstream in settings and document the default prominently; consider a neutral default |
| 3 | `_resolve_via_doh` bootstrap has **no** configuration hook — always Cloudflare | `blackoutkit/tools.py:647` | 🟡 Medium | Honour the configured DoH upstream instead of a literal |
| 4 | `doctor` connectivity probes use plain HTTP | `blackoutkit/doctor.py:539`, `:541` | 🟢 Low | Probes only need a reachability signal; HTTPS variants exist for both |
| 5 | `adblock_auto_update_interval_hours` is declared but unwired — misleading name | `blackoutkit/settings.py:184` | 🟢 Low | Either implement it behind an explicit opt-in, or remove/rename it |
| 6 | Local HTML report pulls Chart.js from a third-party CDN | `blackoutkit/tools.py:2412` | 🟢 Low | Vendor Chart.js into package assets |

---

## 9. Auditing This Yourself

```bash
# Every external host referenced in the package:
grep -rhoE "https?://[a-zA-Z0-9._-]+" blackoutkit/ --include="*.py" \
  | sed 's|https\?://||' | sort | uniq -c | sort -rn

# Confirm no background egress in the daemon:
grep -rnE --include="*.py" "urlopen|httpx|requests\.|urllib" blackoutkit/daemon/

# Confirm the update check has a single, manual call site:
grep -rn --include="*.py" "check_for_update" blackoutkit/

# Confirm the MCP server opens no sockets:
#   (word-boundary patterns; a bare `listen` would false-positive on the word "listener"
#    in a docstring at mcp_server.py:43)
grep -nE "\bsocket\b|\.bind\(|\.listen\(|serve_forever|uvicorn|http\.server|create_server" \
  blackoutkit/mcp_server.py          # → no matches

# Stronger: the module imports no networking module at all.
grep -nE "^import |^from " blackoutkit/mcp_server.py
# → hmac, json, logging, os, sys, and . settings — no `socket`, no `http`, no `asyncio` server
```

For runtime confirmation, capture traffic with a proxy or firewall log while running
`blackout doctor`, `blackout update`, and `blackout dns proxy`, and diff the observed
destinations against the inventory in §6.

---

## Related Documents

- [`SECURITY.md`](SECURITY.md) — vulnerability reporting, assurance matrix, known advisories
- [`SBOM.json`](SBOM.json) — full software bill of materials
- [`README.md`](README.md) — MCP authorization scope, release verification
