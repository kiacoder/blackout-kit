# Network Privacy & Egress Matrix

Every outbound connection Blackout Kit can make, what triggers it, and how to stop it.
This document is written for an outside reviewer: each row names the code that performs the
contact, so a claim here is a claim you can check rather than a promise.

Blackout Kit is a local network tool. Its purpose is to carry **your** traffic to servers
**you** configure. It has no backend, no account, no analytics, and no first-party server of
its own. The only contacts it initiates on its own are the ones a feature needs to do the job
you asked for — and each of those is listed below.

**Bottom line: 0 telemetry · 0 tracking analytics · 0 background phone-home.**

---

## 1. Telemetry and analytics

| Claim | Evidence |
|---|---|
| No telemetry backend | No analytics SDK, no crash reporter, no beacon endpoint anywhere in `blackoutkit/`. Nothing is sent on startup, on exit, or on failure. |
| No tracking identifiers | There is no install ID, no machine fingerprint sent anywhere, and no cookie. `machine_identity` material is used only for the machine-bound local vault key (`blackoutkit/vault.py`). |
| No crash reporting | A daemon crash is written to local files (`daemon.out`, `crash.log`) and read back only by commands you run. |
| No auto-upload of diagnostics | `blackout support-bundle` writes a file to the path you name and refuses to overwrite it. `uploaded: false` is part of the bundle itself, and `blackout support-bundle --preview` prints what a bundle would contain before anything is written. |
| No update pings | See §2 — a release check happens only when you run `blackout update`. |
| No phones-home from the daemon | `blackoutkit/daemon/__init__.py` and `blackoutkit/daemon.py` contact nothing beyond the engine they were told to start and the OS proxy/DNS APIs. |

Verification for a reviewer:

```bash
# No analytics/tracking SDKs in the shipped package
python - <<'PY'
import pathlib, re
bad = re.compile(r"(segment|mixpanel|amplitude|appinsights|sentry|google-analytics|posthog)", re.I)
hits = [str(p) for p in pathlib.Path("blackoutkit").rglob("*.py") if bad.search(p.read_text(encoding="utf-8", errors="ignore"))]
print("matches:", hits or "none")
PY
```

## 2. Update checks

| Endpoint | Transport | When it is contacted | Data sent |
|---|---|---|---|
| `api.github.com/repos/kiacoder/blackout-kit/releases/latest` | HTTPS GET | **Only** when you run `blackout update`, or when you opt into `--apply` | Nothing identifying you. Request headers are `User-Agent: blackout-kit/<version>` and no query parameters, no token |
| `github.com/…/releases/download/<tag>/blackout-source.zip` or `blackout.exe` | HTTPS GET | Only after you confirm the update in `blackout update --apply` | — |

- No scheduled or implicit update check exists: nothing else in the codebase calls
  `updater.check_for_update()` (`blackoutkit/cli.py` → `cmd_update` is the single caller).
- An applied update is accepted only if its SHA-256 matches the digest GitHub publishes for
  that release asset (`blackoutkit/updater.py`), and only from an allow-listed HTTPS GitHub host
  (`_UPDATE_TRUSTED_HOSTS`). A digest mismatch aborts, the staged download is deleted, and the
  existing install is left untouched.
- `install.ps1` performs the same check before it installs or runs anything: no checksum asset
  means no install.
- Build provenance for those assets is signed by GitHub Sigstore; see `SECURITY.md`
  ("Security Assurance & Verification Matrix") for `gh attestation verify`.

## 3. DNS resolution and DNS-over-HTTPS

| Path | Endpoint | When |
|---|---|---|
| Encrypted DNS through the engine | `https+local://cloudflare-dns.com/dns-query`, `https+local://dns.google/dns-query`, plus `1.1.1.1` / `8.8.8.8` fallbacks written into the XRay config's `dns.servers` | While an XRay-based session is running, and only when the `xray_doh_dns` setting is on (it is the default). Queries go to the DoH resolvers named in the generated config; nothing is sent to Blackout |
| Local DoH proxy | Inbound: UDP `127.0.0.1:5300` only. Outbound: the `--upstream` URL you pass (default `https://1.1.1.1/dns-query`) | Only while `blackout tools dns-proxy` runs, i.e. an active bypass session you started |
| DoH bootstrap for a single name | By default, tries `https://1.1.1.1/dns-query`, then `https://9.9.9.9/dns-query`, then `https://8.8.8.8/dns-query`; a valid `BLACKOUT_DOH_RESOLVER` HTTPS URL for one of those three IP hostnames replaces that list with the single configured endpoint | Only when an engine or `blackout doctor` needs to resolve a hostname it must not trust the system resolver for. The hostname is URL-encoded as the `name` query parameter and the request advertises `application/dns-json`; configured query/fragment components are rejected, and redirects are not followed |
| System resolver | your ISP/system DNS | Ordinary hostname lookups during commands you run; Blackout does not change system DNS unless you run `blackout tools dns-set` / the targeted recovery flow, and those are logged locally |
| DNS benchmark | UDP 53 to the resolver IPs in `POPULAR_DNS` (`1.1.1.1`, `8.8.8.8`, `9.9.9.9`, AdGuard, OpenDNS, and the Iranian bypass resolvers) | Only when you run `blackout tools dns-bench` (or `dns-flush`/`dns-set` in the same command family) |

For bootstrap lookups, network, HTTP, invalid JSON/status, and missing or non-IPv4 A-answer failures advance to the next resolver; if all attempts fail, the lookup returns no result. DNS resolution is best-effort: answers can differ by provider and are not proof of authoritative or untampered DNS.

The local DoH proxy is deliberately un-exposable: `run_doh_proxy_server` refuses any bind
address outside `{127.0.0.1, ::1}` (`DOH_PROXY_ALLOWED_BINDS`) so it can never become an open
resolver on a LAN interface, it rejects a non-HTTPS upstream or one carrying embedded
credentials, and it re-validates every redirect target against the SSRF guard
(`_net_utils.reject_private_host`). DoH queries therefore reach only the endpoint **you**
configured, and only while a bypass session is active.

## 4. GeoIP, ISP and diagnostic lookups

| Feature | Endpoint | When | Notes |
|---|---|---|---|
| ISP / country detection | `https://ipapi.co/json/` (primary), then `https://ipinfo.io/json` (fallback) | Only while a command that needs the ASN is running: `blackout network` status panel / `blackout network isp`, `blackout country` auto-detection, `blackout doctor` when no country is pinned, interactive `blackout connect` when the carrier picker selects auto-detection, foreground `blackout emergency`, and after a successful `blackout tools dns-set` country-aware tip | Both requests use HTTPS with the standard library's default TLS certificate verification; redirects are rejected. A network, HTTP-status (including rate-limit), invalid JSON, or invalid schema failure at the primary tries the fallback; if both fail, detection returns no result. The response is used to pick a profile and is then discarded; lookup is best-effort and never gates connecting. Each provider sees the IP it is already answering for, exactly as any web request would |
| Public IP helper | `https://api.ipify.org`, `https://checkip.amazonaws.com`, `https://ifconfig.me/ip` | Not contacted by any command or by the daemon today: `blackoutkit.tools.get_public_ip()` is a library helper with no caller in the shipped CLI | Tried in order, first answer wins. Listed so a reviewer who greps for it finds an explanation instead of a surprise |
| Connectivity probes | `http://cp.cloudflare.com/`, `http://www.google.com/generate_204`, `http://detectportal.firefox.com/`, and `http://www.baidu.com` / `http://www.qq.com` on the Russia profile path | `blackout doctor`, `blackout scan`, proxy reachability tests | Hard-coded public URLs, scheme-validated by `_validated_probe_url`; used only to answer "is anything there" |
| Bandwidth benchmark | `https://speed.cloudflare.com/__up` (upload) and the paired Cloudflare download endpoint | Only `blackout tools speedtest`; `blackout tools speedtest-history` reads the local file and contacts nothing | Results are written to a local JSON history file and never reported |
| Cloudflare IP scan | TCP connect to `:443` on addresses inside the public Cloudflare IPv4 ranges (`data/cloudflare_ips.txt`, `https://www.cloudflare.com/ips/`) | Only `blackout scan` / `blackout tools scan` | Latency measurement only; no payload is sent. Cache written to `scan_cache.json` |
| WinDivert / hotspot shield | none | — | Local packet inspection on this machine; no external destination |
| Npcap / WinTUN guidance | `npcap.com`, `www.wintun.net` (text in a hint) | never contacted | `doctor` prints the URL for you to visit; Blackout does not download either driver |

Nothing in this table runs on a timer. There is no periodic geolocation or "still here" ping.

## 5. Downloads of third-party engine binaries

`blackout bins download` / `blackout bins update` fetch the engine runtimes an engine needs
(Xray-core, sing-box, GoodbyeDPI, Psiphon, WARP, Tor, OpenVPN, SoftEther, WireGuard
portable, and Blackout Kit's own releases). Sources are the upstream GitHub releases listed in
`blackoutkit/downloader.py`, restricted to `github.com`, `objects.githubusercontent.com`, and
`raw.githubusercontent.com` over HTTPS (`_trusted_download_url`), with Tor and OpenVPN fetched
from `dist.torproject.org` and `build.openvpn.net` respectively.

- Every download is staged in a temporary directory, verified against the publisher's SHA-256
  digest, structurally checked (`downloader.verify_binary`), and only then promoted into `bins/`.
- Provenance (repository, release tag, asset name, expected and actual digest) is recorded in
  `bins/.provenance.json`. `downloader.verify_provenance()` and `verify_bins_integrity()` re-check
  installed files against that record; no CLI command is wired to them today, which is stated
  rather than glossed so a reviewer does not go looking for `blackout bins verify`.
- A missing digest, an untrusted host, or a mismatch means the staged file is deleted and nothing is
  installed. These commands are user-invoked; nothing downloads while the daemon runs.

## 6. Content and blocklist feeds (all opt-in, all on demand)

| Feed | Endpoint | Enabled by default? |
|---|---|---|
| Ad-block lists | `https://easylist-downloads.adblockplus.org/easylist.txt`, `https://phishing.army/download/phishing_army_blocklist.txt`, plus any source you add | No — `adblock_enabled` is `False`; the lists are fetched only when you run `blackout tools adblock update` (bounded to 10 MB per list, HTTPS, non-private host required) |
| Threat indicators | `https://sslbl.abuse.ch/blacklist/`, `https://data.phishtank.com/data/online-valid.json`, `https://rules.emergingthreats.net/blockips/compromised-ips.txt` | Updated only when you run `blackout tools threat-feeds update`; feed URLs are validated as HTTPS with a global (non-private) host, and a failed refresh keeps the last good snapshot |
| Media download | whatever URL you pass to `blackout media …` (yt-dlp) | Only when you run it |
| Torrents | trackers/DHT peers of the torrent you added | Only while `blackout torrent …` is used |
| Apps Script relay | `https://script.google.com/macros/s/<id>/exec` | Only while the `appsscript` engine runs, and only against **your** own deployment ID; validated as HTTPS on `script.google.com` (`_validated_relay_url`). Its local listener is `127.0.0.1:<gas_proxy_port>` |

## 7. Engine traffic — user-supplied destinations

When an engine is connected, Blackout routes traffic to the endpoint you configured: your own
VLESS/Trojan/VMess/Hysteria2/TUIC server, WireGuard/IKEv2/OpenVPN/SoftEther/Psiphon/Tor/WARP
endpoints, a `vless://`-style URI you imported, or a neighbour's proxy on the LAN.

**Those upstreams are untrusted by default.** Blackout Kit cannot vouch for a server it did not
build, and a proxy operator can see the traffic it carries. Route selection is documented in
`SECURITY.md`; the trust position is stated in the matrix there.

## 8. Local listeners — nothing reachable from another machine by default

| Listener | Bind | Port (default) | Started by |
|---|---|---|---|
| SNI spoofer | `127.0.0.1` | 40443 (`sni_listen_port`) | `blackout connect sni` |
| XRay SOCKS5 / HTTP | `127.0.0.1` | 10808 / 10809 | `blackout connect xray` |
| sing-box (Hysteria2 / TUIC) SOCKS | `127.0.0.1` | 10808 (`xray_socks_port`) | `blackout connect hysteria2` / `tuic` |
| Psiphon / Tor / WARP / MHRV / Apps Script proxies | `127.0.0.1` | 1081, 9050, 1080, 8085, 8087 | the corresponding engine |
| DoH DNS proxy | `127.0.0.1` (UDP) | 5300 | `blackout tools dns-proxy` |
| Dashboard / REST | `127.0.0.1` | 8080 | `blackout api start` |
| Operator event stream (SSE) | `127.0.0.1` | 8787 | `blackout events serve` — off unless started, read-only, unauthenticated (any local process can read it) |
| Core daemon control channel | Windows named pipe `\\.\pipe\blackout_ipc`, Linux Unix socket `/tmp/blackout.sock` | — | the supervised engine daemon; local IPC only, no TCP socket |
| Neighbour share forwarder | `127.0.0.1` **unless** you set `neighbor_bind_lan` | 10809 | `blackout neighbor share` |
| Neighbour discovery beacon | UDP multicast `239.255.42.99:51820` | — | `blackout neighbor share` / `discover`; LAN-local, no internet |
| Honeypot decoy listener | `0.0.0.0` (see note) | 22, 80, 445, 3389, 8080 | **Only** `blackout tools honeypot`, and that is the point of the feature |

Two rows deserve explicit attention, because a reviewer should not have to guess:

- **Every proxy listener binds to loopback.** A wildcard bind is never a default and is never
  silent: LAN sharing requires the `neighbor_bind_lan` setting to be turned on, and the guard is
  covered by `tests/test_security_boundaries.py::test_default_binds_never_expose_lan`.
- **`blackout tools honeypot` binds all interfaces on purpose.** It opens decoy TCP listeners so
  that probes from other hosts on the network are *observed*; it accepts no data, sends no
  responses, and returns nothing to the prober. It is opt-in, runs only for the duration of that
  command, and is the only all-interface listener in the project. If you do not run the command,
  no such socket exists.

## 9. MCP server — stdio only

`blackout mcp` speaks JSON-RPC 2.0 over **standard input and standard output**. It:

- opens **no** listening socket and binds no port — there is no HTTP/SSE/UDP transport to
  expose, so nothing on your network can reach it;
- requires `auth_token` equal to the server's `BLACKOUT_MCP_TOKEN` (or `BLACKOUT_MCP_SECRET`)
  for every state-changing tool, comparing with `hmac.compare_digest` and failing closed when no
  secret is configured; denials are reported to the client as `isError` so a refused call cannot
  be read as a successful one;
- reads its secret from its own environment only — never from a request, and never echoed back;
- writes nothing anywhere except the local state the invoked tool changes.

The MCP attack surface that does exist is the agent holding the token, not the network; that
residual risk is spelled out in `SECURITY.md` → "MCP authorization".

## 10. What Blackout Kit never sends

No copy of your config, server list, subscription URL, log, event journal, speedtest history,
scan cache, or neighbour cache is ever transmitted. Files listed in the Local Data Inventory of
`SECURITY.md` stay on disk; uninstalling is deleting `~/.blackout-kit/`.

## 11. Verify it yourself

```bash
# Watch what the process actually touches while you exercise a feature
sudo tcpdump -ni any -c 200 'not port 22'          # Linux
Get-NetTCPConnection -OwningProcess (Get-Process blackout).Id   # Windows

# Or block all egress except the endpoint you configured and confirm the feature still works.
```

`blackout doctor`, `blackout snapshot`, and `blackout events recent` show what the tool knows about
its own state, and `blackout support-bundle --preview` shows exactly what a bundle would contain
before any file is written.

If you find an egress path that is not documented here, that is a bug: report it through the
process in `SECURITY.md`.

## 12. Remediation candidates and unwired settings

Known trade-offs in the current egress surface. These are **candidates for future hardening**, not
scheduled work, and none of them changes behavior today. Each row names the code so the claim can
be checked.

### 12.1 Remediation candidates

| # | Surface | Where in code | Current behavior | Trade-off | Candidate hardening |
|---|---|---|---|---|---|
| R1 | Plaintext-HTTP ISP / country lookup | `blackoutkit/network_switcher.py` — `get_isp_info()` now uses `https://ipapi.co/json/`, then `https://ipinfo.io/json` | **Resolved:** both providers are HTTPS-only; the standard library's default TLS certificate verification remains enabled. Network, HTTP-status (including rate-limit), invalid JSON, or invalid schema failures try the next provider, and both failing returns `None` | Provider services still receive the requesting IP as part of serving the lookup; HTTPS protects the request and response in transit. The answer only picks a profile and is then discarded | None for this finding; the lookup is HTTPS-only with best-effort provider fallback |
| R2 | Default upstream DoH resolver | `blackoutkit/tools.py` — `DOH_PROXY_DEFAULT_UPSTREAM`; `blackoutkit/typer_cli.py` — `--upstream` default | `https://1.1.1.1/dns-query` | The default is a well-known anycast address and only applies to the local DoH proxy. Its upstream remains user-selectable | None for this finding; the proxy endpoint can be explicitly selected |
| R3 | DoH bootstrap resolver | `blackoutkit/tools.py` — `resolve_doh()` | Uses `BLACKOUT_DOH_RESOLVER` when it is HTTPS and hosted on `1.1.1.1`, `9.9.9.9`, or `8.8.8.8`; otherwise tries Cloudflare, Quad9, then Google | Any successful provider sees the queried hostname; DNS results remain resolver-dependent and best-effort | None for this finding; the allow-listed override and ordered fallbacks are documented in §3 |
| R4 | Diagnostic HTTP probes | `blackoutkit/doctor.py` — `check_internet()` | `http://cp.cloudflare.com/` and `http://www.google.com/generate_204` over plain HTTP | Captive-portal detection depends on unencrypted HTTP, so an HTTPS probe answers a different question. A probe also reveals that a diagnostic ran | Keep plain HTTP only for the portal check and label it as such, or add an HTTPS reachability check as the primary result |
| R5 | Third-party CDN script in the local web dashboard | `blackoutkit/tools.py` — `run_web_api_dashboard()`, the `/` page | `<script src="https://cdn.jsdelivr.net/npm/chart.js">` with no `integrity=` attribute. The dashboard binds `127.0.0.1` by default | Opening the page makes the browser fetch and run code from jsDelivr. A compromised CDN release would execute in the dashboard's origin | Vendor `chart.js` into the package, or pin the version with an SRI `integrity` hash |

### 12.2 Unwired background setting: `adblock_auto_update_interval_hours`

`blackoutkit/settings.py` defines `adblock_auto_update_interval_hours` (default `24`) and lists it in
the "Ad Blocking" settings category. **No code reads it.** No daemon loop, thread, timer, or
scheduler is wired to it. The only caller of a blocklist refresh is `update_all_blocklists()`, which
runs only when you invoke `blackout tools adblock update`.

You can confirm this with `grep -rn adblock_auto_update_interval_hours blackoutkit/`. The matches
should be the definition and the category entry, and nothing else. Setting the value therefore
creates no background egress. If a scheduler is ever added, this section and §6 must be updated in
the same change.

---

Related: [`SECURITY.md`](SECURITY.md) · [`README.md`](README.md) · [`docs/privacy.html`](docs/privacy.html)
