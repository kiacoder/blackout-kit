# Blackout Kit — v1 Codebase Context for the v2 Go Core Upgrade

> Extracted 2026-10-08 from `C:\Users\kiacoder\blackout-kit` at git HEAD `50e66e5`
> ("feat: interactive carrier picker, fragment tuning, milestone test battery").
> Version: **1.1.1** (`pyproject.toml`, `blackoutkit/__init__.py`).
>
> Note on paths: the task referenced `C:\Users\D121\Documents\BCK\blackout-kit`, which
> does not exist on this machine. The working checkout is `C:\Users\kiacoder\blackout-kit`.

---

## 1. Current architecture flow

```
blackout.py  (thin shim: compat gate, PyInstaller bins extraction, error envelope)
   └─> blackoutkit.typer_cli:main          [console_scripts entry: `blackout`]
         └─> app = typer.Typer(...)  +  19 registered sub-apps
               └─> blackoutkit.cli.cmd_*   (legacy argparse-style handlers, 195 KB)
                     └─> ConnectionService (connection_service.py, 52 KB)
                           ├─> readiness / preset / ISP-profile resolution
                           ├─> cli._start_engine_stack(name)
                           └─> blackoutkit.engines.ENGINE_REGISTRY[name]()
                                 └─> Engine.start()
                                       ├─ [A] ctypes -> bins/blackout_core.dll  (in-process, Win32 only)
                                       ├─ [B] ctypes -> bins/blackout_warp.dll  (WARP / Psiphon)
                                       ├─ [C] subprocess -> bins/*.exe          (xray, sing-box, goodbyedpi…)
                                       └─ [D] subprocess -> blackout-engine <sub>  (Linux runner)
```

### 1.1 `blackout.py` — entry point (180 lines)

- Runs `_check_compat()` before importing anything heavy: Python ≥3.10, Windows ≥10, x64 only.
  Warnings are non-fatal.
- If `sys.frozen` (PyInstaller), copies `_MEIPASS/bins/*` into `BINS_DIR` (size-mismatch check only).
- Delegates everything to `blackoutkit.typer_cli:main`; installs `proxy_manager.install_console_close_handler()`.
- Error envelope: with `--json` it emits `cli_output.emit_error("internal_error", …)`;
  otherwise `theme.print_friendly_error(exc)`; always exits 1.

### 1.2 `blackoutkit/cli.py` — legacy handler layer (195 KB, ~4 550 lines)

Despite the name, this is **not** the Typer app. `cli.py:main()` is a 3-line fallback that
re-exports `typer_cli.main`. Its real role is the implementation body:

| Region | Lines | Contents |
|---|---|---|
| `_LazyModule` + lazy re-exports | 45–135 | defers heavy imports (proxy_manager, config, ip_scanner) |
| `_get_engine_classes(name)` | 141–228 | maps engine name → 1..N engine classes (a "stack") |
| Platform gating | 229–266 | `_platform_engine_error`, `_linux_default_engine`, `_linux_dependencies` |
| Preset / env override machinery | 268–381 | `_mode_overrides`, `_preset_payload`, `_temporary_env_overrides` |
| `_start_engine_stack(name)` | 382–504 | instantiates the stack, starts each engine, returns list |
| Commands | 593–4330 | `cmd_country/scan/test/start/connect/stop/emergency/status/route/theme/logs/config/settings/tools/mode/killswitch/panic/shield/neighbor/download/media/torrent/help/doctor/update/preflight/network/bins/ready/fix` |
| Interactive menu | 4335–4538 | `_interactive_menu`, `_show_launcher_menu` |
| `main()` | 4548 | → `typer_cli.main` |

Key detail: presets (`--iran`, `--russia`, ISP profiles) are applied as **transient environment
overrides** (`BLACKOUT_SETTING_<KEY>`), never by rewriting saved settings.

### 1.3 `blackoutkit/typer_cli.py` — active CLI surface (184 KB)

- `app = typer.Typer(...)` at line 566 with a custom `_JsonTyperGroup` (line 517) for `--json`.
- Top-level commands: `capabilities, demo, setup, version, fix, scan, route, theme, status,
  ready, doctor, connect, start, mode, killswitch, add-to-path, gui (hidden), mcp, test, stop,
  disconnect, emergency, logs, panic, shield, update, manual, help, preflight, _daemon_run,
  _watchdog, 0xDEADBEEF, snapshot, support-bundle`.
- 19 sub-apps: `split-tunnel, network, config, report, tools (→ threat-feeds), country/countries,
  neighbor, download, media, torrent, settings, bins, ssh, api, automation, vault, operator, events`.
- Commands reach back into `cli.py` via local imports (`from .cli import cmd_scan`, `_status_snapshot`, …),
  and `connect` builds a `ConnectionService` with injected dependencies
  (`start_engine_stack=cli._start_engine_stack`, `proxy_details=cfg.get_engine_proxy_details`, …).

### 1.4 `blackoutkit/config/manager.py` — V2Ray config schema (24 KB)

- `@dataclass ProxyConfig` — 19 fields: `protocol, address, port, password, uuid, sni, host, path,
  alpn, fp, transport, security, public_key, short_id, spider_x, flow, service_name, xhttp_mode,
  insecure, name, raw_uri`.
- Methods that are part of the contract: `is_sni_compatible()` (address in {127.0.0.1, 0.0.0.0} and
  port == 40443), `display_name()`, `is_reality()`, `reality_validation_error()`, `transport_label()`.
- Parsers: `parse_v2ray_uri` → `_parse_vless_trojan` (vless/trojan/hysteria2/tuic) and `_parse_vmess`.
  `splithttp` is normalised to `xhttp`.
- Storage: `CONFIGS_FILE = DATA_DIR/"configs.txt"` (newline-delimited URIs), optional encrypted vault
  (`blackoutkit.vault`), cross-platform mutation lock (`msvcrt.locking` / `fcntl.flock`), atomic
  temp-file + `os.replace` saves.
- Subscription import is SSRF-hardened: HTTPS only, no credentials, no localhost/`.local`,
  global-only resolved IPs, ≤3 redirects, 2 MB / 10 000 line caps.
- `SETUP_SCHEMA_VERSION = 1`; `serialize_setup()` strips credentials from exported URIs.
- `select_proxy_config(protocols)` honours `BLACKOUT_CONFIG_OFFSET` for rotation.

### 1.5 `blackoutkit/settings.py` — runtime settings schema

- `SETTINGS_FILE = ~/.blackout-kit/settings.json`, `SETTINGS_SCHEMA_VERSION = 1`,
  `_schema_version` key, env override layer (`_apply_env_overrides`), `_VALIDATORS` dict.
- ~110 keys grouped into 27 UI groups. Engine-relevant defaults:

| Key | Default | Meaning |
|---|---|---|
| `sni_listen_port` | 40443 | local SNI spoofer listener |
| `sni_connect_ip` | 104.19.229.21 | clean Cloudflare endpoint |
| `sni_connect_port` | 443 | |
| `sni_fake_sni` | www.hcaptcha.com | |
| `sni_arvancloud_sni` | www.arvancloud.ir | Iran-domestic CDN fake SNI |
| `xray_socks_port` / `xray_http_port` | 10808 / 10809 | |
| `xray_fragment` | `10-50,10-50` | TLS record fragment `length,interval` |
| `xray_fingerprint` | chrome | uTLS fingerprint |
| `gdpi_backend` | `legacy` | `legacy` = goodbyedpi.exe, `native` = Go/WinDivert DLL |
| `gdpi_flags` | `auto` | `auto` probes modesets `-1`..`-6` |
| `selected_engine` | `auto` | 18 valid values |
| `security_mode` | `speed` | speed / private / legend |
| `engine_order` | `[sni, gdpi, psiphon]` | fallback order |
| `country` | `""` | empty = auto-detect from ISP |
| `wg_config_file` / `wg_interface` | `""` / `wg0` | native WireGuard |

---

## 2. Go engine layer

Two independent Go modules, both built with `-buildmode=c-shared` and loaded via `ctypes`.

### 2.1 `engine/` → `bins/blackout_core.dll` (73 MB, tracked in git)

`go.mod`: module `blackout-engine`, **go 1.26**. Direct deps:

| Dependency | Version | Used by |
|---|---|---|
| `github.com/xtls/xray-core` | v1.260327.0 | `xray.go` |
| `github.com/sagernet/sing-box` | v1.13.14 | `singbox.go` (TUN, Hysteria2, TUIC) |
| `golang.zx2c4.com/wireguard` | 2023-12-11 (pinned via `replace`) | `wireguard.go` (userspace netstack) |
| `github.com/google/gopacket` | v1.1.19 | `gdpi_windows.go` |
| `github.com/imgk/divert-go` | v0.1.0 | `gdpi_windows.go` (WinDivert) |
| `github.com/armon/go-socks5` | 2016-09-02 | `wireguard.go` SOCKS5 bridge |

Two `replace` directives pin `gvisor.dev/gvisor` to 2023-12-02 and `golang.zx2c4.com/wireguard`
to 2023-12-11 — old pins, worth re-checking before a v2 bump.

#### Exported C ABI (`bins/blackout_core.h`, generated by cgo)

```c
GoInt  StartXrayC(char* configPath);      void StopXrayC(void);
GoInt  StartSingBoxC(char* configInput);  void StopSingBoxC(void);
int    StartGDPIC(void);                  void StopGDPIC(void);   int IsGDPIRunningC(void);
GoInt  StartSNIC(char* configPath);       void StopSNIC(void);
GoInt  StartMHRVC(int port, char* ids);   void StopMHRVC(void);
GoInt  StartNeighborC(int listenPort, int targetPort);  void StopNeighborC(void);
char*  ScanIPsC(char* ipsC, int port, int concurrency, int timeoutMs);
int    StartWireGuardC(char* configPath, int socksPort);  void StopWireGuardC(void);
```

ABI caveat: the header mixes `GoInt` (64-bit) with plain `int` (32-bit) return types, while
`blackoutkit/core.py` declares `restype = ctypes.c_int` for every single one. It works today
only because small return values survive the 32-bit read; it is a latent trap on any future
signature change. `ScanIPsC` returns a `C.CString` that nothing ever frees.

`core.get_core_dll()` caches one `ctypes.CDLL`, calls `os.add_dll_directory(BINS_DIR)`, and sets
argtypes/restypes explicitly; `get_warp_dll()` does the same for `blackout_warp.dll`.
Both return `None` on non-Win32 — **the entire DLL path is Windows-only**.

#### `engine/gdpi_windows.go` (140 lines) — WinDivert packet fragmentation

- `//go:build windows`; stub `gdpi_nonwindows.go` returns an error on other platforms.
- Filter: `outbound and tcp and (tcp.PayloadLength > 0) and (tcp.DstPort == 80 or tcp.DstPort == 443)`,
  opened at `divert.LayerNetwork`.
- `gdpiChunkSize = 10` — **hardcoded**. For any TCP payload > 10 bytes, the packet is re-serialized
  into 10-byte TCP segments: copy IPv4/IPv6 header, copy TCP header, set `Payload`, advance `Seq`
  by the cumulative offset, `SetNetworkLayerForChecksum`, then `handle.Send()` each chunk.
  Serialization uses `FixLengths + ComputeChecksums`.
- IPv4 and IPv6 branches are near-duplicates of each other.
- State: package-level `gdpiHandle *divert.Handle` + `gdpiRunning atomic.Bool`. One goroutine
  `Recv`s into a 65 535-byte buffer; any processing error sets running false and returns silently.
- **Missing vs. upstream GoodbyeDPI:** no configurable chunk size, no `Auto` mode detection,
  no TCP/UDP fake-packet injection, no TTL / hop-limit manipulation, no IPv4 MF-fragment mode,
  no host/domain blacklist, no `--dns-verb`, no HTTP/HTTPS split modes, no `--wrong-seq`,
  no `--reverse-frag`.

#### `engine/sni.go` (163 lines) — SNI relay with ClientHello fragmentation

- `SNIConfig` JSON: `LISTEN_HOST, LISTEN_PORT, CONNECT_IP, CONNECT_PORT, FAKE_SNI`.
- `startSNIInternal` opens a TCP listener, accepts, spawns `handleClient`.
- `handleClient` dials `CONNECT_IP:CONNECT_PORT` with a 10 s timeout / 30 s keepalive dialer,
  sets `NoDelay` + keepalive on both sides, then bidirectionally copies.
- On the **first** client read > 20 bytes, the whole buffer is written to the server in **10-byte
  chunks** (TLS ClientHello fragmentation), relying on TCP_NODELAY to emit separate segments.
- ⚠️ **`config.FakeSNI` is parsed but never used.** `handleClient` receives only
  `(ConnectIP, ConnectPort)`. There is no fake-ClientHello injection, no `FAKE_SNI` packet,
  no SNI rewrite — it is a plain TCP relay that chunks the first write. The Python side
  (`engines/sni.py`) writes `FAKE_SNI` into `config.json` and believes it is spoofing.
- Listener is package-global; no concurrency limit, no graceful drain, no metrics.

#### `engine/singbox.go`, `xray.go`, `wireguard.go`, `mhrv.go`, `neighbor.go`, `scanner.go`

- `singbox.go`: `startSingBoxConfig([]byte)` unmarshals `option.Options` and runs a library
  `box.Box`; `StartSingBoxC` accepts either a JSON body or a file path (prefix `{` check).
- `xray.go`: `core.LoadConfig("json", f)` → `core.New` → `Start`; blocks on SIGINT in `RunXray`.
- `wireguard.go`: parses a `.conf` into wireguard IPC format, builds a **userspace netstack TUN**,
  `IpcSet`, `Up()`, then exposes a SOCKS5 listener on `127.0.0.1:<socksPort>` via `armon/go-socks5`.
- `mhrv.go`: Google Apps Script relay; `startMHRVInternal(port, idsComma)`.
- `neighbor.go`: `startNeighborInternal(listenPort, targetPort)` LAN proxy share.
- `scanner.go`: `scanIPsInternal(ips, port, concurrency, timeoutMs)` — semaphore-bounded parallel
  TCP dial, returns a comma-joined `"IP|latency"` string sorted by latency.
- `main.go`: CLI binary with subcommands `xray`, `sing-box`, `sni`, `mhrv` — this is the **Linux
  runner** path (`blackout-engine <sub> --config …`).

### 2.2 `engine/warp/` → `bins/blackout_warp.dll` (41 MB)

Separate `go.mod`. Exports: `StartWarpC(int socksPort, char* country)`,
`StopWarpC()`, `StartPsiphonC(int socksPort, int httpPort, char* country)`, `StopPsiphonC()`.

### 2.3 Build pipeline

- `.github/workflows/build.yml` `build-windows` job: sets up Go 1.26 with
  `cache-dependency-path: engine/warp/go.sum`, then verifies/builds **only** `engine/warp`.
- **`engine/` (blackout_core.dll) is not built or tested in CI.** The only Go test in the repo is
  `engine/gdpi_nonwindows_test.go`. The DLL in `bins/` was produced by a local manual
  `go build -buildmode=c-shared`.
- `.gitignore` lists `bins/*.dll` and `bins/*.exe`, but `bins/blackout_core.dll`,
  `blackout_core.dll.bak` (57 MB), `blackout_warp.dll`, `blackout_warp.dll.bak` (31 MB) and
  `blackout-engine.exe~` (51 MB) were committed before the ignore and are still tracked —
  roughly 190 MB of binaries in git history.

---

## 3. Engine loading and execution (`blackoutkit/engines/`)

### 3.1 `base.py` — `Engine` ABC (the contract every engine must keep)

```python
class Engine(ABC):
    name: str
    description: str
    def start(self) -> bool          # abstract
    def stop(self)                   # DLL stop func, else psutil tree terminate (3 s) → kill
    def is_running(self) -> bool     # poll() or _dll_stop_func + port health probe
    def check_process_alive(self) -> bool
    @property pid -> int | None
```

Internal state every engine relies on:
- `self._process: subprocess.Popen | None`
- `self._dll_stop_func` — set to the DLL's `Stop*C` after a successful `Start*C`
- `self._health_check_addr: tuple[host, port] | None` — enables silent-crash detection
- `self._config_dir` — per-instance `tempfile.mkdtemp(prefix="bk_engine_")`, removed on stop
- `self._log = logging.getLogger("blackoutkit.engine").getChild(name)`

Helpers: `find_binary(names, system_names)`, `start_process(cmd)`, `wait_for_process(timeout=0.5)`,
`binary_command()`, `check_port_free()`, `wait_for_port()`, `check_process_alive()`.

### 3.2 `__init__.py` — `ENGINE_REGISTRY` (18 engines)

```
sni  xray  gdpi  psiphon  warp  tun  tor  mhrv  ikev2  wireguard  openvpn
softether  neighbor  appsscript  hysteria2  tuic  awg  hotspot-shield
```
Plus `get_engine(name)`, `list_engines()`, `engine_names()`,
`next_engine_candidate(current, failed, platform_filter)` (Linux allowlist = `xray, tun,
hysteria2, tuic, awg`).

### 3.3 Representative engines

| Engine | Execution | Notes |
|---|---|---|
| `sni.py` | **DLL** `StartSNIC(path)` | writes `config.json` into `_config_dir`, supports `connect_ip == "auto"` → Cloudflare scan + per-IP TLS handshake scoring, `wait_for_port(40443)` |
| `gdpi.py` | **dual backend** | `GoodbyeDPIEngine` proxies to `_LegacyGoodbyeDPIEngine` (goodbyedpi.exe subprocess, modeset `auto` probing `-1`..`-6`, UAC elevation via generated `.ps1` + PID file) or `_NativeGoodbyeDPIEngine` (`StartGDPIC`/`IsGDPIRunningC`) |
| `tun.py` | **DLL** `StartSingBoxC` | generates a sing-box TUN config (interface `BlackoutKit-TUN`, `172.19.0.1/30`, MTU 9000, `auto_route`, `strict_route`, stack `mixed`), requires admin/WinTUN; on Linux routes through `blackout-engine sing-box --config …` |
| `wireguard.py` | **DLL** `StartWireGuardC(path, port)` | userspace WG + SOCKS5 bridge |
| `xray.py` | **subprocess** `xray.exe run -c …` | 21 KB, also the source of `XRAY_BIN_NAMES` / `LINUX_RUNNER_NAMES` |

### 3.4 Packet-fragment / DPI-bypass routines currently in place

1. **WinDivert TCP segmentation** — `engine/gdpi_windows.go`, fixed 10-byte chunks on ports 80/443.
2. **ClientHello chunking in the SNI relay** — `engine/sni.go`, 10-byte writes of the first read.
3. **Legacy GoodbyeDPI subprocess** — `bins/goodbyedpi.exe` + `WinDivert.dll` / `WinDivert64.sys`,
   modeset auto-probe with connectivity verification against google.com / 1.1.1.1 / 8.8.8.8 / youtube.com.
4. **Xray `fragment` outbound** — `engines/xray.py:197-220` turns `xray_fragment` (`length,interval`)
   into a `freedom` outbound with `{"packets": "tlshello", ...}` and wires it via
   `streamSettings.sockopt.dialerProxy = "fragment-out"`.
5. **`fragment_tuner.py`** (new, 11 KB) — launches a short-lived Xray per candidate
   (`""`, `10-20,30-40`, `10-50,10-50`, `5-10,20-30`), pushes one HTTP GET through a local HTTP
   inbound pinned to the clean IP with `serverName=fake_sni`, records `ProbeOutcome(fragment, ok,
   latency_ms, detail)`, and `apply_winner()` writes `sni_connect_ip` + `xray_fragment`.
   Validation rule: empty or exactly `range,range`.
6. **ISP sub-profiles** — `isp_profiles.py`: `ir-mci` (AS197207), `ir-irancell` (AS44244),
   `ir-rightel` (AS57218), `ir-tci` (AS58224/AS48434), `ir-shatel` (AS31549). Each carries
   `engine_order`, `security_mode`, `fake_sni`, `xray_fragment`, `xray_fingerprint` as transient
   overrides. `SCHEMA_VERSION = 1`. Explicitly documented as *not* field-verified.
7. **Country profiles** — `country_profiles.py` supplies `bypass_domains_for(country)` and
   `direct_dns_for(country)`; TUN bypass defaults include `domain:ir`, aparat, digikala, snapp, divar.
8. **Split tunneling / routing** — `split_tunnel.py`, `routing.py`, `russia_whitelist.py`.

---

## 4. Bundled binaries (`bins/`)

| Category | Files |
|---|---|
| **Go c-shared DLLs** | `blackout_core.dll` (73 MB, tracked), `blackout_warp.dll` (41 MB, tracked), `.bak` copies of both, `blackout_core.h`, `blackout_warp.h` |
| **Go CLI binary** | `blackout-engine.exe` (70 MB), `blackout-engine.exe~` (51 MB), `go-gdpi.exe` (5 MB) |
| **WinDivert** | `WinDivert.dll` (46 KB), `WinDivert64.sys` (92 KB) |
| **Proxy cores** | `xray.exe` (35 MB), `sing-box.exe` (45 MB) |
| **VPN** | `wireguard.exe`, `wg.exe`, `openvpn.exe` + `openvpn-gui` + `openvpnserv` + `tapctl.exe`, `libopenvpn_plap.dll`, `softether-installer.exe` |
| **WARP / Psiphon** | `warp-plus.exe` (20 MB), `ca.psiphon.PsiphonTunnel.tunnel-core/`, `psiphon_data/` |
| **Tor / misc** | `tor.exe`, `tor-gencert.exe`, `torrc`, `goodbyedpi.exe` (75 KB), `openssl.exe` + `libssl-3-x64.dll` + `libcrypto-3-x64.dll`, `vcruntime140.dll` |

No socket/IPC bindings — Python↔Go is **in-process cgo only** on Windows, and
**argv-only subprocess** on Linux.

---

## 5. Gaps between v1 and a planned v2 Go Core

⚠️ **No v2 spec exists in the repo.** `ROADMAP.md` contains no "v2 Go Core" entry — the only "v2"
item is *REST API v2* (webhooks, WebSocket streaming). The list below is therefore derived from
what the current v1 core demonstrably lacks, not from a committed design. Confirm the intended
v2 scope before treating any of it as required.

### 5.1 Structural gaps

| # | Gap | Evidence |
|---|---|---|
| 1 | **Two divergent execution models.** Windows = in-process `ctypes` DLL; Linux = `blackout-engine <sub>` subprocess. Every feature must be implemented twice. | `core.py` returns `None` off-Win32; `tun.py` branches on `sys.platform` |
| 2 | **No version negotiation.** Python cannot ask the DLL what it is. Adding/removing an export is undetectable until `AttributeError` at runtime. | `core.py` only guards `hasattr(_dll, "IsGDPIRunningC")` |
| 3 | **No structured errors.** Every start returns `int` 0/1; the reason is printed to stdout from Go and thrown away (`stdout=DEVNULL` for subprocess engines, no capture for DLL). | `exports.go`; `base.start_process` |
| 4 | **No lifecycle beyond start/stop.** No pause, reload, hot-reconfigure, stats, per-engine health, or drain. `is_running()` is inferred from a TCP probe. | `base.py:96-119` |
| 5 | **No event/telemetry channel.** Go cannot push anything back; Python polls ports and parses logs. `ScanIPsC` returns one string; no callback, no streaming. | `scanner.go` |
| 6 | **Single global instance per subsystem.** `gdpiHandle`, `sniListener`, `xrayServer`, `singboxInstance`, `wgDevice` are package-level singletons — one of each per process, no multi-instance, no namespacing. | all `engine/*.go` |
| 7 | **A Go panic or DLL fault kills the CLI.** The core runs inside the Python process; there is no supervisor, no crash isolation, no restart. | `core.get_core_dll()` |
| 8 | **Memory-leaking ABI.** `ScanIPsC` returns `C.CString` with no free path; `GoInt`/`int` return-type mismatch against `ctypes.c_int` declarations. | `exports.go`, `core.py` |
| 9 | **No CI for the core.** Only `engine/warp` is built in CI; `engine/` has one trivial non-Windows test and no build script. | `.github/workflows/build.yml:120-131` |
| 10 | **190 MB of binaries tracked in git** despite `.gitignore` rules. | `git ls-files bins` |
| 11 | **Hardcoded tuning.** `gdpiChunkSize = 10`, SNI chunk size `10`, filter pinned to ports 80/443, WG MTU 1420, SOCKS port defaults — none configurable from Python. | `gdpi_windows.go:17`, `sni.go:124` |

### 5.2 Functional gaps in the DPI-bypass routines

| # | Gap |
|---|---|
| 12 | **`FAKE_SNI` is dead config.** `engine/sni.go` never uses it — no fake ClientHello injection, no SNI rewrite. The advertised "SNI spoofing (patterniha method)" is, in the native path, ClientHello chunking only. |
| 13 | **Native GDPI is a fragmenter, not GoodbyeDPI.** No fake packets, TTL tricks, MF fragmentation, wrong-seq, domain blacklist, or auto-strategy. `gdpi_flags` is explicitly ignored in native mode (`engines/gdpi.py:349`). |
| 14 | **No IPv6 parity in policy.** IPv6 code path exists in GDPI, but nothing above it (SNI relay, TUN bypass, profiles) is v6-aware. |
| 15 | **Fragment tuning is Xray-only.** `fragment_tuner.py` measures Xray freedom fragmentation; it cannot tune the WinDivert chunk size or the SNI relay chunk size, because neither is exposed. |
| 16 | **No QUIC / HTTP/3 handling.** The WinDivert filter is `tcp` only; sing-box covers Hysteria2/TUIC but there is no UDP/QUIC DPI strategy. |
| 17 | **No observability.** No packet counters, no per-strategy success metrics, no way to ask "did fragmentation actually help". |
| 18 | **No cross-engine coordination.** GDPI (WinDivert, L3) and the SNI relay (L4 proxy) can run simultaneously with no awareness of each other; `engine_order` is a fallback list, not a composition model. |

### 5.3 Interfaces that must survive a v2 rewrite

These are load-bearing and are referenced from many modules:

- **C ABI in `blackout_core.h`** — 15 symbols. Any rename breaks `core.py` argtype declarations,
  `engines/{sni,gdpi,tun,wireguard}.py`, and `engines/{xray,mhrv,neighbor,psiphon,warp}.py`.
- **`Engine` ABC in `engines/base.py`** — `start/stop/is_running/check_process_alive/pid` plus the
  four instance attributes `_process`, `_dll_stop_func`, `_health_check_addr`, `_config_dir`.
- **`ENGINE_REGISTRY` + `get_engine/list_engines/engine_names/next_engine_candidate`** — the single
  source of truth the CLI, daemon, GUI, MCP server and readiness checks all read.
- **`ProxyConfig` dataclass** and `parse_v2ray_uri` — consumed by config, tools, reporting, vault, GUI.
- **Settings keys** — `SETTINGS_SCHEMA_VERSION = 1` with ~110 keys; `gdpi_backend`,
  `sni_*`, `xray_*`, `selected_engine`, `engine_order`, `country` are the engine-critical ones.
- **`ConnectionService` / `ConnectionRequest` / `ConnectionResult`** — the orchestration contract
  between the Typer CLI and the engines (`connection_service.py:40-103`).
- **`ISP profile schema** (`SCHEMA_VERSION = 1`) and `SETUP_SCHEMA_VERSION = 1` for setup export.
- **`--json` output envelope** (`cli_output.emit_error`, `schema_version`, `ok`, `error.code`).

### 5.4 Suggested shape for v2 (to be confirmed, not yet specified anywhere)

A single Go process exposing a local control channel (named pipe on Windows, Unix socket on Linux)
with a versioned request/response schema, keeping the current `Engine` ABC as a thin client:

- `CoreClient.handshake() → {api_version, capabilities[]}`
- structured results `{ok: bool, code: string, message: string, context: {...}}`
- streaming events (engine state, packet stats, strategy outcomes) instead of port polling
- tunable strategy parameters (chunk size, fake-SNI injection, TTL, ports, protocol filter)
- the Python side keeps: config parsing, settings, presets/ISP profiles, UI, daemon policy

---

## 6. Open questions

1. Is the planned "v2 Go Core" a rewrite of `engine/` in place, or a new sibling module
   (`engine/v2/`)? No such entry exists in `ROADMAP.md`.
2. Should v2 keep the c-shared DLL + ctypes model, or move to a separate supervised process with
   an IPC channel? (The latter is the only way to fix gaps 1, 3, 4, 5, 7.)
3. Is fixing the unused `FAKE_SNI` in the SNI relay in scope for v2, or is the current chunking
   behavior intentional?
4. Should `blackout_core.dll` be built in CI and dropped from git (replacing the tracked 190 MB)?
