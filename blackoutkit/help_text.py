"""
Blackout Kit - In-app help documentation.
Rich-formatted detailed help for every command.

Rare upgrades:
  - 18 topics (was 8) — covers every command, engine, and use-case
  - search_help(query): fuzzy keyword search across all topics
  - get_help() shows categorised index with descriptions
"""

# ─────────────────────────────── Topics ──────────────────────────────────────
# Each topic is a Rich-markup string.  Keep lines ≤ 80 chars wide.

TOPICS: dict[str, str] = {

# ── New users ─────────────────────────────────────────────────────────────────

"quick_start": """
[bold cyan]Quick Start — 5 steps to get online[/bold cyan]

[bold]Step 1 — Verify local runtime prerequisites[/bold]
  Windows uses the binary requirements for the engine you choose. The SNI path
  needs sni-spoofing.exe and XRay; other engines have their own requirements.

  Linux x86_64 supports XRay, XRay → sing-box TUN, Hysteria2, and TUIC through
  the managed [bold]blackout-engine[/bold] runner in bins/. The Windows SNI,
  GoodbyeDPI, VPN, and desktop-GUI paths are unavailable on Linux.

[bold]Step 1b — Review or pin a country profile[/bold]
  blackout country
  A profile can inform local recommendations; an unpinned lookup uses network
  access and does not confirm that an engine or upstream proxy will work.
  Pin explicitly when needed: blackout country set CN

[bold]Step 2 — Add a V2Ray config[/bold]
  blackout config add "vless://..."
  OR import a subscription:
  blackout config import <subscription-url>

[bold]Step 3 — Inspect local readiness[/bold]
  blackout route
  This shows locally supported engine candidates without probing saved nodes.

[bold]Step 4 — Start in background[/bold]
  blackout connect --background
  Engines with an HTTP proxy can set the Windows system proxy when auto_set_proxy
  is enabled; network-level engines use their own routing path.

[bold]Step 5 — Verify local state[/bold]
  blackout status
  Check the daemon state and any local HTTP/SOCKS ports. Open local ports do not
  by themselves prove upstream reachability.

[dim]Need free configs? See: blackout help config[/dim]
[dim]Something broken? Run: blackout doctor[/dim]
""",

"faq": """
[bold cyan]Frequently Asked Questions[/bold cyan]

[bold]Q: The proxy stops working after a few hours. Why?[/bold]
  Network conditions, upstream servers, or local runtime state may have changed.
  Check [bold]blackout status[/bold] and [bold]blackout logs[/bold], then inspect
  [bold]blackout route[/bold] for locally ready alternatives. Use daemon mode or
  [bold]blackout emergency -d[/bold] only after reviewing the selected engines.
  A restart does not guarantee that an upstream service will become reachable.

[bold]Q: Cloudflare CAPTCHA keeps showing. How do I fix it?[/bold]
  CAPTCHA behavior is decided by the destination service and cannot be guaranteed
  by a local setting. Check the selected engine and upstream service, try the
  default XRay fingerprint, or choose another locally ready engine with
  [bold]blackout route[/bold].

[bold]Q: Can I share the proxy with my phone?[/bold]
  Option A — USB tethering/hotspot:
    Enable Mobile Hotspot in Windows, then run:
    blackout settings set neighbor_bind_lan true
  Option B — LAN peer sharing (another PC nearby with Blackout Kit):
    blackout neighbor discover
  See: [bold]blackout help neighbor[/bold]

[bold]Q: My browser works but Discord / Telegram doesn't.[/bold]
  Those apps often ignore the system proxy.
  Install a Proxifier (github.com/yrutschle/redsocks)
  or use a SOCKS-aware client setting in the app.
  Discord: Settings → Advanced → Proxy → SOCKS5 127.0.0.1:10808

[bold]Q: Is this legal?[/bold]
  That is a question for a lawyer in your jurisdiction.
  Blackout Kit is a tool — what you do with it is your responsibility.

[bold]Q: Will this make me anonymous?[/bold]
  No mode guarantees anonymity. The modes configure local XRay and legacy GDPI
  settings; your device, destination, network, and upstream server remain part
  of the threat model. See: [bold]blackout help security[/bold]
""",

# ── Core commands ─────────────────────────────────────────────────────────────

"start": """
[bold cyan]blackout start[/bold cyan]
Start a supported engine and configure a system proxy when that engine exposes one.

[bold]Usage:[/bold]
  blackout start                        Start the default engine path
  blackout start --engine sni           Windows SNI + XRay stack
  blackout start --engine gdpi          Windows GoodbyeDPI path
  blackout start --engine psiphon       Psiphon VPN path
  blackout start --engine warp          Cloudflare WARP path
  blackout start --engine tor           Tor proxy path
  blackout start -d                     Run in background — survives terminal close

[bold]What happens:[/bold]
  The selected engine controls its own startup sequence. The Windows SNI stack
  starts its local SNI component and XRay; XRay exposes SOCKS/HTTP ports when
  configured. Linux supports only XRay, TUN, Hysteria2, and TUIC through the
  managed runner. A Windows system proxy is set only when auto_set_proxy is
  enabled and the selected engine provides an HTTP proxy.

[bold]Tips:[/bold]
  • Use [bold]-d[/bold] so the proxy stays up if you close the terminal
  • If one engine fails, try [bold]blackout emergency[/bold]
  • Check [bold]blackout status[/bold] anytime to see connection health
  • Run [bold]blackout preflight[/bold] first to catch missing binaries early
""",

"stop": """
[bold cyan]blackout stop[/bold cyan]
Stop all running engines and clear the Windows system proxy.

[bold]Usage:[/bold]
  blackout stop

[bold]What happens:[/bold]
  1. The managed daemon and its child engines are stopped
  2. If a daemon was running and auto_set_proxy is enabled, the system proxy is cleared
  3. If the saved kill-switch setting is enabled, Blackout Kit attempts to remove
     its own platform firewall rules

[bold]Note:[/bold]
  If no daemon is running, this command reports that state and does not clear an
  independently configured system proxy. Use targeted recovery only after a crash:
    blackout fix
  On Linux, run commands that modify TUN/firewall state with sudo.
""",

"scan": """
[bold cyan]blackout scan[/bold cyan]
Measure local TCP reachability for generated Cloudflare IPs and resolve configured
fake-SNI domains. Results are local observations, not proof that a bypass path
will work.

[bold]Usage:[/bold]
  blackout scan                         Scan both IPs and SNI domains
  blackout scan --ips                   Only scan Cloudflare IPs
  blackout scan --sni                   Only resolve fake-SNI domains
  blackout scan --count 200             Scan 200 IPs (default: 100)

[bold]What it does:[/bold]
  • Generates candidates from Cloudflare CIDR ranges
  • Tests TCP connectivity to port 443 in parallel
  • Ranks responding candidates by local latency
  • Resolves configured fake-SNI domains through the current DNS path

[bold]After scanning:[/bold]
  You may set a responding IP:  blackout settings set sni_connect_ip <ip>
  Then test your supported local engine and upstream configuration.
""",

"emergency": """
[bold cyan]blackout emergency[/bold cyan]
Automatically try every engine until one successfully connects.

[bold]Usage:[/bold]
  blackout emergency                    Foreground mode
  blackout emergency -d                 Background mode (recommended)

[bold]Engine order:[/bold]
  Uses the configured engine order when set; otherwise it uses the active
  country profile. Linux tries only its supported engine subset.
  Change order: blackout settings set engine_order sni,psiphon,gdpi

[bold]When to use:[/bold]
  • A managed engine stopped working
  • You want to try locally supported alternatives

[bold]Limit:[/bold]
  Emergency mode starts candidates in sequence; it cannot confirm that an
  upstream proxy, VPN server, or filtering environment will work.
""",

"status": """
[bold cyan]blackout status[/bold cyan]
Show a read-only local snapshot of the daemon and proxy ports.

[bold]Usage:[/bold]
  blackout status
  blackout status --watch
  blackout status --watch --interval 5

[bold]Displays:[/bold]
  • Daemon PID, active engine, and reconnect state
  • System proxy status
  • Local HTTP/SOCKS port availability
  • Saved local latency/loss history when available
  • Security mode and Blackout Kit terminal palette

[bold]Privacy and safety:[/bold]
  Status never reconnects, runs repair, changes routing, or probes a remote host.
  It reads only local daemon/proxy state, local ports, and saved local history.
""",

"route": """
[bold cyan]blackout route[/bold cyan]
Rank locally ready engines without contacting remote nodes.

[bold]Usage:[/bold]
  blackout route

[bold]Evidence used:[/bold]
  • Current platform support
  • Installed local engine binaries
  • Saved proxy protocols
  • Country profile and explicit engine preference
  • Saved local latency/loss history

[bold]Safety:[/bold]
  This dashboard does not download binaries, probe configs, start engines, or
  change settings/routes. [bold]blackout connect[/bold] uses the highest ready
  recommendation when no engine is explicitly supplied.
""",

"theme": """
[bold cyan]blackout theme[/bold cyan]
Set Blackout Kit's Rich terminal palette.

[bold]Usage:[/bold]
  blackout theme
  blackout theme dark
  blackout theme light

[bold]Note:[/bold]
  This changes only colors printed by Blackout Kit. It does not alter Windows
  Terminal, PowerShell, Linux terminal settings, or the graphical application.
""",

"connect": """
[bold cyan]blackout connect[/bold cyan]
Connect using an explicit engine or the highest locally ready recommendation.

[bold]Usage:[/bold]
  blackout connect                      Use local readiness recommendation
  blackout connect --engine warp        Use a specific supported engine
  blackout connect --iran               Apply the Iran profile's local settings
  blackout connect -d                   Run in background

[bold]What it does:[/bold]
  1. Ranks engines from local platform support, installed components, saved
     config protocols, any pinned country profile, settings, and local history
  2. Lets interactive terminals accept or replace the recommendation
  3. Starts the selected engine stack and sets a system proxy when that engine
     exposes one
  4. Runs a small Cloudflare scan only for the Windows SNI path when no saved
     Cloudflare IP exists

[bold]Limits:[/bold]
  Recommendations do not probe saved proxy nodes or guarantee connectivity.
  On Linux, only XRay, TUN, Hysteria2, and TUIC are supported through the
  managed blackout-engine runner.
""",

"fix": """
[bold cyan]blackout fix[/bold cyan]
Safely repair post-crash Blackout Kit network state in one command.

[bold]Windows targeted recovery:[/bold]
  ✓ Clears stale Blackout system proxy settings
  ✓ Removes only routes owned by detected stale Blackout virtual adapters
  ✓ Restores DHCP DNS only when a connected physical adapter still uses loopback DNS
  ✓ Restarts only the deterministic BlackoutKit-TUN adapter when unhealthy
  ✓ Flushes DNS without resetting Winsock, TCP/IP, or DHCP

[bold]Linux targeted recovery:[/bold]
  ✓ Removes only the `inet blackoutkit` / `BLACKOUTKIT_*` firewall objects
  ✓ Removes only the deterministic BlackoutKit-TUN interface
  ✓ Flushes the local DNS cache when a supported cache service is active
  ✓ Never flushes system routes, changes NetworkManager, rewrites resolver config,
    or touches third-party VPN interfaces

[bold]Usage:[/bold]
  blackout fix                          Run safe targeted recovery
  blackout tools netfix                 Same safe recovery flow
  blackout fix --flush-arp              Explicitly flush ARP/neighbor cache
  blackout tools arp-flush              Same explicit ARP/neighbor repair
  blackout fix --full-route-reset       Windows emergency only: runs route -f, then renews DHCP
  blackout fix --full-stack-reset       Windows emergency only: resets Winsock, TCP/IP, autotuning, and DHCP

[bold]Safety boundary:[/bold]
  • Stop Blackout first — recovery skips all mutations while its daemon is active
  • ARP flushing may briefly interrupt LAN neighbor discovery, so it is never automatic
  • On Linux, run system recovery with sudo

[bold]Warning:[/bold]
  --full-route-reset deletes every IPv4 route, including unrelated VPN and custom LAN routes.
  --full-stack-reset can interrupt all active network connections.
  Use either only after the default targeted repair fails.
""",

# ── Settings & config ─────────────────────────────────────────────────────────

"settings": """
[bold cyan]blackout settings[/bold cyan]
Customize every aspect of Blackout Kit.

[bold]Usage:[/bold]
  blackout settings list                Show all settings and current values
  blackout settings get sni_fake_sni    Show a single value
  blackout settings set sni_connect_ip 104.19.229.21
  blackout settings reset               Reset everything to defaults

[bold]Key settings:[/bold]
  sni_connect_ip      Windows SNI target IP; scan can measure TCP reachability
  sni_fake_sni        Windows SNI component's configured fake-SNI value
  xray_fingerprint    XRay fingerprint: chrome / firefox / safari / random
  auto_set_proxy      Apply a system proxy only for engines that expose one
  engine_order        Emergency-mode priority on Windows
  psiphon_country     Requested Psiphon exit-country setting
  gdpi_backend        legacy = stable default; native = experimental Go/WinDivert
  gdpi_flags          Legacy-GDPI modeset flags only
  gdpi_always_test_all  Test every legacy-GDPI modeset before selecting one
  kill_switch         Allow compatible starts to attempt the platform kill switch
  xray_doh_dns        Route XRay DNS through configured DoH servers when enabled
  xray_split_tunnel   XRay routing rules for LAN and `.ir` traffic; separate from
                      Windows system-proxy bypass patterns

[bold]Environment overrides (advanced):[/bold]
  Every setting can be overridden without editing settings.json:
  set BLACKOUT_XRAY_HTTP_PORT=9999 && blackout start
  Useful for scripting or per-session overrides.
""",

"config": """
[bold cyan]blackout config[/bold cyan]
Manage V2Ray proxy configurations.

[bold]Usage:[/bold]
  blackout config list                  List all saved configs
  blackout config add <uri>             Add a supported proxy URI
  blackout config import <url>          Import from subscription URL
  blackout config remove <n>            Remove config #n
  blackout config encrypt               Encrypt configs.txt with AES-256-GCM
  blackout config decrypt               Decrypt configs.enc back to configs.txt

[bold]Testing configs:[/bold]
  Analyze your configs: [bold]blackout test[/bold]
  Shows local protocol, transport/security mode, SNI compatibility, and label.
  It does not probe saved endpoints and does not print URI credentials or
  REALITY key material.

[bold]SNI-compatible configs:[/bold]
  Configs must use address 127.0.0.1:40443 to route through the Windows SNI
  engine. Linux requires a direct supported proxy configuration.
  Example:
  trojan://password@127.0.0.1:40443?security=tls&sni=www.hcaptcha.com
            &type=ws&path=/ws&host=www.hcaptcha.com

[bold]VLESS REALITY configs:[/bold]
  Standard VLESS REALITY URIs work with [bold]blackout connect xray[/bold]
  and [bold]blackout connect tun[/bold]. REALITY is a VLESS security mode,
  not a separate engine command. Required fields are security=reality, sni,
  and pbk/publicKey; supported transports are tcp, ws, and grpc. Import the
  URI only from a server operator you trust. Config lists show only protocol,
  transport, and label; they never print credentials or REALITY key material.

  [bold]Free subscription sources:[/bold]
  github.com/barry-far/V2ray-Config
  github.com/Mohammadgb0078/IRV2ray
  t.me/patterniha  (Telegram — SNI-specific configs)

[bold]Config encryption:[/bold]
  Your configs contain server credentials.
  Encrypt them: [bold]blackout config encrypt[/bold]
  The file is encrypted with AES-256-GCM using a key derived from this machine.
  Keep a secure backup before moving configs to another device.
""",

"split_tunnel": """
[bold cyan]blackout split-tunnel[/bold cyan]
Manage Windows system-proxy bypass entries.

[bold]Usage:[/bold]
  blackout split-tunnel list
  blackout split-tunnel add example.com
  blackout split-tunnel add 192.168.1.*
  blackout split-tunnel remove example.com

[bold]What it changes:[/bold]
  • Saves direct-bypass patterns locally in split_tunnel.json
  • Applies them to the Windows ProxyOverride setting
  • Matching destinations bypass the Windows system proxy directly

[bold]Limits:[/bold]
  • This is not per-process routing or a general network-layer route table
  • It does not configure Linux TUN routing or firewall bypass rules
  • It affects proxy-aware traffic that uses the Windows system proxy
""",

# ── Engines ───────────────────────────────────────────────────────────────────

"engines": """
[bold cyan]Engine Reference[/bold cyan]
Windows exposes the full engine set. Linux x86_64 supports only XRay, the
XRay → sing-box TUN stack, Hysteria2, and TUIC through blackout-engine.
Availability and results depend on local prerequisites, the chosen server, and
network conditions; no engine guarantees censorship circumvention or anonymity.

[bold]DPI Bypass Engines (no VPN):[/bold]
  [bold]sni[/bold]        Windows SNI-spoofing + XRay stack
             Requires: sni-spoofing.exe + XRay + a compatible local config
             Port: 40443 (listen) → HTTP :10809 / SOCKS :10808
             Availability: Windows only; effectiveness depends on the network

  [bold]gdpi[/bold]       Windows GoodbyeDPI TCP-handling path
             Requires: goodbyedpi.exe + WinDivert.dll + Administrator
             Suitable only where its network behavior is effective; it is not a
             proxy or VPN and does not cover every protocol.
             Backend: [bold]legacy[/bold] by default; [bold]native[/bold] Go/WinDivert backend is experimental

[bold]VPN / Tunnel Engines:[/bold]
  [bold]psiphon[/bold]    Multi-protocol client using Psiphon Tunnel Core
             Requires: psiphon-tunnel-core-x86_64.exe
             Port: HTTP :8081 / SOCKS :1081
             Use when its local runtime and upstream service are available; bootstrap
             time and reachability vary by network.

  [bold]warp[/bold]       Cloudflare WARP client path
             Requires: warp-plus.exe
             Port: SOCKS :1080
             Results, exit characteristics, and destination CAPTCHA behavior vary
             by the upstream service and network.

  [bold]tor[/bold]        Local SOCKS proxy using a supplied Tor runtime
             Requires: tor.exe (Expert Bundle)
             Port: SOCKS :9050
             Use only with an appropriate Tor threat model; Blackout Kit itself
             does not establish anonymity or prevent traffic correlation

  [bold]wireguard[/bold]  Modern UDP-based VPN (your own server)
             Requires: wireguard.exe + .conf file
             Set: blackout settings set wg_config_file C:/path/wg0.conf

  [bold]openvpn[/bold]    Battle-tested TLS VPN (your own server)
             Requires: openvpn.exe + .ovpn config file
             Set: blackout settings set openvpn_config C:/path/vpn.ovpn

  [bold]softether[/bold]  Windows SoftEther VPN client
             Requires: vpnclient.exe + vpncmd.exe
             Set: softether_host / softether_hub / softether_username

[bold]Special Engines:[/bold]
  [bold]neighbor[/bold]   Share or borrow internet from a nearby device on LAN
             No internet needed — peer discovery via UDP multicast
             See: blackout help neighbor

  [bold]appsscript[/bold] HTTP relay through Google Apps Script
             Built-in, no binary needed — routes eligible HTTP traffic through
             the configured Apps Script relay; it is not a general HTTPS tunnel
             Port: HTTP :8087

  [bold]mhrv[/bold]       Embedded HTTP Google Apps Script relay via blackout_core.dll
             Port: HTTP :8085; HTTPS CONNECT is intentionally unsupported
             No CA certificate is installed and Windows trust stores are not modified

[bold]Usage:[/bold]
  blackout start --engine <name>

[bold]Country Compatibility:[/bold]
  Engine    Iran  China  Iraq  UK   USA
  sni        ✓✓    ✗      ✓✓    ✓    —
  xray       ✓✓    ✓✓✓    ✓✓    ✓    ✓
  gdpi       ✓     ✗      ✓     ✓✓   ✓
  warp       ✓     ✓      ✓     ✓    ✓✓
  psiphon    ✓     ✓      ✓     ✓    —
  tor        ✓     ✓✓     ✓     ✓    ✓

  See: [bold]blackout help countries[/bold] for detailed per-country guidance.
""",

"network": """
[bold cyan]blackout network[/bold cyan]
WiFi network management and ISP intelligence.

[bold]Usage:[/bold]
  blackout network                      Show current network status and ISP
  blackout network scan                 Show all available WiFi networks
  blackout network isp                  Detailed ISP + ASN + location info
  blackout network auto                 Auto-switch to best saved network
  blackout network switch <SSID>        Switch to a specific WiFi profile

[bold]Features:[/bold]
  • [bold]ISP Detection:[/bold] Identifies your provider and country censorship level
  • [bold]Auto-Switch:[/bold] Finds nearby saved WiFi networks and connects to the
    one with the strongest signal if your current one drops
  • [bold]Signal Bars:[/bold] Visual signal strength indicators for all nearby nets
""",

"logs": """
[bold cyan]blackout logs[/bold cyan]
View the real-time output of the background daemon and engines.

[bold]Usage:[/bold]
  blackout logs                         Show last 50 lines of logs
  blackout logs --lines 200             Show last 200 lines

[bold]What's logged:[/bold]
  • Engine startup and shutdown events
  • Process IDs (PIDs) of running binaries
  • Connection successes and failures
  • Error messages from xray, sni-spoofer, etc.
""",

"test": """
[bold cyan]blackout test[/bold cyan]
Analyze and verify your saved V2Ray configurations.

[bold]Usage:[/bold]
  blackout test

[bold]What it checks:[/bold]
  • [bold]Protocol:[/bold] Trojan, VLESS, etc.
  • [bold]SNI Compatibility:[/bold] Does the config point to 127.0.0.1:40443?
  • [bold]Transport/Security:[/bold] Local transport mode, including REALITY
  • [bold]SNI Compatibility:[/bold] Whether it targets the Windows SNI listener
  • [bold]Name:[/bold] User-friendly URI remark

[bold]Privacy:[/bold]
  The command is local-only: it does not probe endpoints and does not display
  URI credentials, endpoints, or REALITY key material.
""",

"mode": """
[bold cyan]blackout mode[/bold cyan]
Switch between local XRay and legacy GoodbyeDPI setting profiles.

[bold]Usage:[/bold]
  blackout mode                         Show current mode and descriptions
  blackout mode speed                   Compatibility-focused XRay settings
  blackout mode private                 Random XRay fingerprint + MUX
  blackout mode legend                  Strict known-bad normal-TLS handling

[bold]Detailed info:[/bold]
  See: [bold]blackout help security[/bold]
""",

"preflight": """
[bold cyan]blackout preflight[/bold cyan]
Ensure you are ready for an impending internet blackout.

[bold]What is checked:[/bold]
  ✓ Essential binaries present in bins/
  ✓ At least one working V2Ray config saved
  ✓ Cloudflare IP cache is fresh
  ✓ Settings are valid for your country
  ✓ Disk space and permissions

[bold]Usage:[/bold]
  blackout preflight

[bold]Tip:[/bold]
  Run this command while you still have internet access. If it fails,
  run [bold]blackout doctor --fix[/bold] to prepare your system.
""",

"vpn": """
[bold cyan]VPN Engine Setup (WireGuard / OpenVPN / SoftEther / IKEv2)[/bold cyan]
For users who have their own VPN server.

[bold]WireGuard (recommended — fastest):[/bold]
  1. Install WireGuard from wireguard.com
  2. Save your .conf file anywhere (e.g. C:/VPN/wg0.conf)
  3. Run:  blackout settings set wg_config_file "C:/VPN/wg0.conf"
  4. Run:  blackout start --engine wireguard
  WireGuard uses the supplied configuration through the Windows client; routing behavior is defined by that configuration.

[bold]OpenVPN:[/bold]
  1. Install OpenVPN from openvpn.net
  2. Save your .ovpn file (e.g. C:/VPN/server.ovpn)
  3. Run:  blackout settings set openvpn_config "C:/VPN/server.ovpn"
  4. Run:  blackout start --engine openvpn

[bold]SoftEther VPN:[/bold]
  1. Install SoftEther VPN Client from softether.org
  2. Set server details:
     blackout settings set softether_host vpn.yourserver.com
     blackout settings set softether_hub VPN
     blackout settings set softether_username yourusername
     blackout settings set softether_password yourpassword
  3. Run:  blackout start --engine softether

[bold]IKEv2 / L2TP (Windows built-in VPN):[/bold]
  1. Set credentials:
     blackout settings set ikev2_server vpn.yourserver.com
     blackout settings set ikev2_username yourusername
     blackout settings set ikev2_password yourpassword
     blackout settings set ikev2_tunnel_type IKEv2
  2. Run:  blackout start --engine ikev2
  Windows creates a native VPN connection — no extra software needed.
""",

# ── Security ──────────────────────────────────────────────────────────────────

"security": """
[bold cyan]Security Modes[/bold cyan]
Three local configuration presets for XRay and legacy GoodbyeDPI settings.
They do not guarantee privacy, anonymity, connectivity, or resistance to
traffic analysis.

[bold]SPEED (default)[/bold]
  • Chrome XRay fingerprint
  • XRay MUX disabled
  • Normal TLS streams use allowInsecure=True
  Run: [bold]blackout mode speed[/bold]

[bold]PRIVATE[/bold]
  • Random XRay fingerprint
  • XRay MUX enabled
  • Normal TLS streams use allowInsecure=True; certificate issues may be
    recorded after startup
  Run: [bold]blackout mode private[/bold]

[bold]LEGEND[/bold]
  • Random XRay fingerprint + MUX
  • Known-bad normal TLS certificates are refused unless explicitly allowed
  • Kill switch and config encryption remain separate opt-in commands
  Run: [bold]blackout mode legend[/bold]

[bold]REALITY note:[/bold]
  VLESS REALITY validates its configured public key inside XRay's REALITY
  handshake. It does not use the normal TLS certificate policy or cert-check.
  Import REALITY URIs only from a trusted operator; this client-side support does
  not create server keys, validate the operator, guarantee anonymity, or prevent
  detection.

[bold]Check current mode:[/bold]
  blackout mode

[bold]GDPI backend note:[/bold]
  Security modes still tune [bold]gdpi_flags[/bold], which only affect the
  [bold]legacy[/bold] GDPI backend. The [bold]native[/bold] experimental backend
  ignores those flags for now.
""",

"killswitch": """
[bold cyan]Kill Switch[/bold cyan]
Blocks non-allowlisted traffic if the managed proxy or tunnel goes down.

[bold]Linux only:[/bold]
  Uses only an owned `inet blackoutkit` nftables table, with iptables/ip6tables
  fallback. Before enabling, Blackout Kit resolves a compatible configured upstream
  proxy into literal IP:port rules. It permits loopback, LAN/DHCP, BlackoutKit-TUN,
  and that exact endpoint; it refuses activation if it cannot resolve a safe
  endpoint. This is endpoint-scoped firewall control, not a guarantee against all
  leaks or privileged local adversaries.

[bold]Windows:[/bold]
  Unavailable. Blackout Kit removes its legacy Windows Firewall rules because a
  Windows Firewall block rule overrides the required per-process allow rules.

[bold]Usage:[/bold]
  sudo blackout killswitch on           Enable Linux kill switch
  sudo blackout killswitch off          Disable Linux kill switch
  sudo blackout killswitch test         Check Linux state

[bold]Requirements:[/bold]
  sudo/root and a validated upstream endpoint allowlist on Linux.

[bold]Warning:[/bold]
  If you enable the Linux kill switch and stop the proxy, direct internet stays
  blocked until you run [bold]sudo blackout killswitch off[/bold].
""",

# ── Utilities ─────────────────────────────────────────────────────────────────

"tools": """
[bold cyan]blackout tools[/bold cyan]
Full network diagnostic and utility toolkit.

[bold]Commands:[/bold]
  ping [host]           TCP ping — more reliable than ICMP behind a proxy
  dns-bench             Benchmark all DNS servers (Cloudflare, Google, Shecan...)
  dns-flush             Clear OS DNS cache (helps when sites don't load)
  dns-set cloudflare    Set DNS to 1.1.1.1 (recommended)
  dns-set shecan        Shecan — fast Iranian filtered DNS
  dns-set electro       Electrotm — bypass-capable Iranian DNS
  dns-set 403           403.online — Iranian bypass DNS
  dns-set google        Set DNS to 8.8.8.8
  dns-set <ip>          Set DNS to any custom IP
  speedtest             Download + upload speed test via Cloudflare
  adapters              List all network adapters and their IPs
  mtu [host]            Detect path MTU (fixes slow HTTPS on some networks)
  traceroute [host]     Show network hops to destination
  cert-check <host>     Check a normal TLS certificate and current mode policy
  cert-check <host> --allow  Explicitly allow a normal-TLS host in LEGEND mode
  hotspot               Toggle Windows Mobile Hotspot on/off
  share-vpn             Inspect an eligible Windows adapter and show manual ICS steps
  netfix                Targeted post-crash recovery for Blackout-owned state
  arp-flush             Explicitly flush local ARP/neighbor cache (may briefly affect LAN discovery)

[bold]Background daemon reconnect:[/bold]
  Failed engines restart immediately, then retry with capped exponential backoff
  (default 2s → 4s → 8s, capped at 60s) until max_retries is exhausted.
  After a failed restart, daemon recovery preserves the active proxy and never
  uses a full route reset; `blackout fix --full-route-reset` stays manual.

[bold]Cloudflare captcha tips:[/bold]
  If sites show Cloudflare challenges:
  1. Check xray_fingerprint = chrome  (default)
  2. Run [bold]blackout scan[/bold] to get a fresh IP
  3. Try: [bold]blackout start --engine warp[/bold]
""",

"neighbor": """
[bold cyan]blackout neighbor[/bold cyan]
Share or borrow internet from a nearby device on your LAN.

[bold]Scenario:[/bold]
  Your laptop is bypassing censorship.
  Your friend's device on the same WiFi cannot.
  Use neighbor sharing — no config, no setup, auto-discovery.

[bold]On the sharing device (you have internet):[/bold]
  blackout neighbor share

  This broadcasts a UDP beacon on the LAN every 5 seconds.
  Other devices running Blackout Kit will find you automatically.

[bold]On the connecting device (no internet):[/bold]
  blackout neighbor discover            Find nearby devices sharing
  blackout neighbor connect <ip>        Connect to a specific IP

[bold]How it works:[/bold]
  • UDP multicast on 239.255.42.99:51820 (LAN only, TTL=3)
  • The sharer exposes their HTTP proxy on port 10809
  • The connecting device sets its system proxy to the sharer's IP
  • A heartbeat keeps the connection alive and reconnects on drop

[bold]Tip:[/bold]
  Enable LAN binding:  blackout settings set neighbor_bind_lan true
  This allows ANY device on your network to use your proxy.
""",

"doctor": """
[bold cyan]blackout doctor[/bold cyan]
Self-diagnosis and automatic repair.

[bold]Usage:[/bold]
  blackout doctor                       Run all checks (read-only)
  blackout doctor --fix                 Run checks AND auto-fix everything possible

[bold]What is checked:[/bold]
  ✓ bins/ directory exists
  ✓ ~/.blackout-kit/ data directory exists
  ✓ settings.json valid (all keys present, values in range)
  ✓ Disk space ≥ 200 MB free
  ✓ Direct internet connectivity
  ✓ Winsock catalog health (Windows)
  ✓ WinDivert DLL + sys file (needed by GoodbyeDPI and SNI)
  ✓ data/cloudflare_ips.txt, fake_snis.txt, configs.txt
  ✓ Python packages: rich, httpx, psutil, cryptography
  ✓ Binary presence: sni-spoofing.exe, xray.exe, goodbyedpi.exe...
  ✓ Binary runnability: actually launches each binary to catch DLL errors

[bold]Auto-fixable issues:[/bold]
  • Missing data files → recreated with defaults
  • Corrupted settings.json → reset to factory defaults
  • Missing Python packages → installed via pip
  • Missing bins/ or data directories → created
""",

"update": """
[bold cyan]blackout update[/bold cyan]
Check for new versions and update automatically.

[bold]Usage:[/bold]
  blackout update                       Check for an available update
  blackout update --apply               Download and apply the available update
  blackout preflight                    Check readiness without connecting

[bold]Update process:[/bold]
  1. Queries GitHub releases API for newest version
  2. Downloads the release ZIP with a progress bar
  3. Verifies SHA256 hash (rejects corrupted downloads)
  4. Backs up current blackoutkit/ folder
  5. Extracts and replaces blackoutkit/ only (bins/ and data/ are untouched)
  6. Rolls back automatically if extraction fails

[bold]Preflight checks:[/bold]
  blackout preflight  verifies:
  • Required binaries present (sni-spoofing.exe, xray.exe)
  • At least one V2Ray config is saved
  • Cloudflare IP cache is fresh (< 12 hours old)
  • Settings are valid
  • Enough disk space

[bold]Tip:[/bold]
  Run [bold]blackout preflight[/bold] before a scheduled blackout to ensure everything
  is ready before you lose internet access.
""",

"warp": """
[bold cyan]Cloudflare WARP Engine[/bold cyan]
Uses Cloudflare WARP protocol — gives you a clean Cloudflare IP.

[bold]Why WARP?[/bold]
  • Your traffic comes from a Cloudflare data center IP
  • These IPs are "clean" — websites trust them more
  • Fewer CAPTCHAs and bot challenges than standard proxies
  • Effective even during partial blackouts

[bold]Setup:[/bold]
  1. Download warp-plus: github.com/hiddify/warp-plus/releases
  2. Place warp-plus.exe in bins/
  3. Run: blackout start --engine warp

[bold]Country selection:[/bold]
  blackout settings set psiphon_country US    Use US exit node
  blackout settings set psiphon_country DE    Use Germany exit node (default)
  (WARP reuses the psiphon_country setting)

[bold]Powered by:[/bold]
  hiddify/warp-plus (Warp + optional Psiphon fallback)
""",

"troubleshoot": """
[bold cyan]Troubleshooting Guide[/bold cyan]

[bold]Nothing loads at all after starting:[/bold]
  1. blackout status       (check ports open)
  2. blackout logs         (check for errors)
  3. blackout doctor --fix (auto-repair common issues)
  4. blackout scan         (refresh Cloudflare IP)
  5. blackout stop && blackout start -d

[bold]Proxy works but is very slow:[/bold]
  • Run blackout scan → apply fastest IP
  • Try xray_fingerprint chrome (default)
  • Try a different engine: blackout start --engine warp
  • Check your configs: [bold]blackout test[/bold]

[bold]GoodbyeDPI crashes immediately:[/bold]
  Cause: WinDivert.dll missing OR not running as Administrator.
  Fix:
  1. Make sure WinDivert.dll AND WinDivert64.sys are in bins/
  2. Right-click → "Run as Administrator"
  3. Or add bins/ to Defender exclusions:
     blackout tools netfix

[bold]Psiphon never connects (stuck on "waiting for port"):[/bold]
  Psiphon can take 30-60 s to bootstrap.
  If it still fails after 60 s, the Psiphon servers may be blocked.
  Try a different country: blackout settings set psiphon_country US

[bold]WinDivert / SNI blocked by Windows Defender:[/bold]
  blackout doctor --fix   (adds bins/ to Defender exclusions automatically)
  Or manually: Windows Security → Virus & Threat Protection →
  Manage Settings → Add or Remove Exclusions → Add bins/ folder

[bold]System proxy not cleared after stop:[/bold]
  blackout stop           (clears proxy automatically)
  Or manually: Settings → Network → Proxy → turn off "Use a proxy server"

[bold]Error: 'blackout' is not recognized:[/bold]
  Run directly: python blackout.py <command>
  Or add the folder to your PATH.

[bold]Country-Specific Fixes:[/bold]
  [bold]Country profiles:[/bold]  Pin a profile to influence local engine and DNS
  recommendations. Profiles do not establish that an engine or proxy will work.

            blackout country set IR
            blackout country set CN
            blackout route

  Windows includes SNI, GoodbyeDPI, and VPN engine options. Linux supports only
  XRay, TUN, Hysteria2, and TUIC through blackout-engine. Review local readiness
  with [bold]blackout route[/bold] before choosing an engine.
""",


"cert": """
[bold cyan]TLS Certificate Bypass — blackout tools cert-check[/bold cyan]
Proactively check any server's TLS certificate and apply per-mode policy.

[bold]Usage:[/bold]
  blackout tools cert-check google.com          Check port 443 (default)
  blackout tools cert-check myproxy.com:8443    Check custom port
  blackout tools cert-check myproxy.com --allow  Allow in LEGEND mode too

[bold]What it checks:[/bold]
  • Subject + Issuer CN
  • Expiry date and days remaining
  • Self-signed detection (subject == issuer)
  • Strict TLS validation for normal TLS configurations in LEGEND mode
  • Per-mode policy: what allowInsecure would be for your current mode

[bold]Per-mode policy:[/bold]
  SPEED   → allowInsecure = True for normal TLS streams
  PRIVATE → allowInsecure = True; a certificate issue may be recorded after start
  LEGEND  → rejects a known-bad normal TLS certificate unless explicitly allowed

[bold]REALITY note:[/bold]
  This command applies only to normal TLS configurations. VLESS REALITY uses
  XRay's REALITY handshake and configured public key instead, so it does not
  run a TLS certificate probe or use this certificate policy.

[bold]Auto-detection:[/bold]
  For normal TLS configs, XRay uses the policy below when it starts:
    • LEGEND mode: sync probe — blocks start if cert is bad
    • PRIVATE mode: background probe — warns but connects
    • SPEED mode:   no probe — connects immediately

[bold]LEGEND mode override:[/bold]
  If you have a self-signed cert on your proxy server and trust it:
  blackout tools cert-check myproxy.com --allow
  This marks the host as manually allowed, so LEGEND mode will permit it.
  The cert details are still displayed — trust is explicit, not blind.

[bold]Cert record store:[/bold]
  All checked hosts are cached in ~/.blackout-kit/cert_records.json
  Records are reused on subsequent xray starts (no re-probe unless you run cert-check).
""",

"bins": """
[bold cyan]blackout bins[/bold cyan]
Auto-download all engine binaries directly from their official GitHub releases.
No manual steps, no copy-pasting — one command installs everything.

[bold]Usage:[/bold]
  blackout bins                     Show status of all binaries (installed / missing)
  blackout bins download            Download all missing auto-downloadable binaries
  blackout bins download xray       Download a specific binary by key
  blackout bins update              Re-download all installed binaries to get latest versions

[bold]Binary keys:[/bold]
  xray          Xray-core V2Ray engine — required for sni and configs
  goodbyedpi    GoodbyeDPI + WinDivert driver — required for gdpi engine
  sing-box      TUN mode engine (sing-box)
  warp-plus     Cloudflare WARP engine

[bold]Manual-only binaries:[/bold]
  sni-spoofing  patterniha/SNI-Spoofing — release is .rar format, extract manually
                Download: github.com/patterniha/SNI-Spoofing/releases
                Place sni-spoofing.exe in the bins/ folder

  psiphon       Psiphon Tunnel Core — no pre-built Windows binary in releases
                Build from source (Go): github.com/Psiphon-Labs/psiphon-tunnel-core

[bold]How it works:[/bold]
  1. Hits GitHub releases API to find the latest version
  2. Downloads the Windows x64 ZIP with a live progress bar
  3. Extracts the right .exe (and DLLs where needed) into bins/
  4. You can start using the engine immediately — no restart needed

[bold]Tip:[/bold]
  Run [bold]blackout bins download[/bold] right after a fresh install — gets you
  xray, goodbyedpi, sing-box, and warp-plus in one shot.
  Then [bold]blackout doctor[/bold] to verify everything is ready.
""",

"countries": """
[bold cyan]Country Profiles — Multi-Country Support[/bold cyan]
Blackout Kit includes country profiles that inform local engine and DNS recommendations.

[bold]Country Reference:[/bold]
  Country          Level    Local first candidate   DNS
  Iran (IR)        HIGH     sni                     Shecan / Electro / 403online
  China (CN)       EXTREME  xray                    Alibaba / Tencent / 114 DNS
  Iraq (IQ)        MEDIUM   sni                     Cloudflare / Google
  UK   (GB)        LOW      gdpi                    Cloudflare / Google
  USA  (US)        MINIMAL  warp                    Cloudflare / Quad9

  These are local profile inputs, not remote availability tests or a guarantee
  that an upstream server will work.

[bold]Usage:[/bold]
  blackout country                      Show active profile & detection
  blackout country set <CODE>           Pin to a specific country (IR/CN/US...)
  blackout country reset                Return to auto-detection

[bold]Auto-detect your country:[/bold]
  blackout country
  (Reads ISP info from ip-api.com — requires internet)

[bold]Manually set your country:[/bold]
  blackout country set IR        Set to Iran
  blackout country set CN        Set to China (recommended for GFW users)
  blackout country set GB        Set to UK
  blackout country set US        Set to USA
  blackout country set IQ        Set to Iraq
  blackout country reset         Back to auto-detect

[bold]Review local state:[/bold]
  blackout country            Show the active profile and its test URLs
  blackout network isp        Show ISP and country context when the lookup works
  blackout route              Rank locally ready engines without probing nodes

[bold]Important:[/bold]
  Country profiles are guidance, not connectivity tests. Filtering behavior,
  DNS availability, upstream server reachability, and engine support vary by
  platform and network. Pin a profile only when it reflects your own context.
""",

}

# ─────────────────────────── Topic categories ────────────────────────────────
# Used by the help index to group topics for readability.

_CATEGORIES: dict[str, list[str]] = {
    "Getting Started":  ["quick_start", "faq", "countries", "bins", "network"],
    "Core Commands":    ["start", "stop", "scan", "connect", "fix", "status", "route", "theme", "emergency", "mode"],
    "Configuration":    ["settings", "config", "split_tunnel"],
    "Engines":          ["engines", "vpn", "warp", "neighbor"],
    "Security":         ["security", "killswitch"],
    "Maintenance":      ["tools", "cert", "doctor", "update", "preflight", "logs"],
    "Help":             ["troubleshoot", "test"],
}

# One-liner description for each topic (shown in the index)
_SUMMARIES: dict[str, str] = {
    "quick_start":   "New here? Start here — 5 steps to get online",
    "faq":           "Answers to the most common questions",
    "start":         "Start a bypass engine and set the system proxy",
    "stop":          "Stop all engines and clear the system proxy",
    "scan":          "Probe Cloudflare IPs and fake-SNI domains for the Windows SNI path",
    "connect":       "Connect with an explicit engine or local recommendation",
    "fix":           "Auto-diagnose and repair common issues",
    "status":        "Read local daemon, proxy-port, and reconnect status (or watch it live)",
    "route":         "Rank locally ready engines without probing remote nodes",
    "theme":         "Set Blackout Kit's terminal-only dark/light Rich palette",
    "emergency":     "Try every engine until one connects",
    "settings":      "View and change all configuration settings",
    "config":        "Add, import, and manage V2Ray configs",
    "split_tunnel":  "Manage Windows system-proxy bypass patterns",
    "engines":       "All bypass engines explained — which to use when",
    "vpn":           "Set up WireGuard / OpenVPN / SoftEther / IKEv2",
    "warp":          "Cloudflare WARP — clean IP, fewer captchas",
    "neighbor":      "Share or borrow internet from a nearby device",
    "security":      "Speed / Private / Legend security modes",
    "killswitch":    "Linux endpoint-scoped firewall protection",
    "tools":         "Ping, DNS benchmark, speedtest, MTU, netfix...",
    "doctor":        "Self-diagnosis and automatic repair",
    "update":        "Update Blackout Kit + preflight readiness check",
    "preflight":     "Offline-first readiness check for blackouts",
    "logs":          "View background daemon and engine output",
    "test":          "Analyze saved V2Ray configurations",
    "mode":          "Switch between Speed / Private / Legend security modes",
    "network":       "WiFi switcher and ISP provider intelligence",
    "troubleshoot":  "Common problems and how to fix them",
    "countries":     "Country profiles: censorship levels, best engines, DNS per country",
    "bins":          "Auto-download engine binaries from GitHub releases in one command",
    "cert":          "TLS cert check + SPEED/PRIVATE/LEGEND bypass policy",
}


# ─────────────────────────── Public API ──────────────────────────────────────

def get_help(topic: str | None) -> str:
    """
    Return Rich-formatted help for a topic, or a categorised index if topic is None.
    Falls back to search results for unknown topic names.
    """
    if topic:
        if topic in TOPICS:
            return TOPICS[topic]
        # Unknown topic — try a search
        results = search_help(topic)
        if results:
            lines = [
                f"[yellow]No exact topic '{topic}' — did you mean one of these?[/yellow]\n"
            ]
            for name, _ in results[:5]:
                lines.append(
                    f"  [cyan]blackout help {name:<16}[/cyan] {_SUMMARIES.get(name, '')}"
                )
            return "\n".join(lines)
        return f"[red]Unknown help topic: '{topic}'[/red]  Run [bold]blackout help[/bold] to see all topics."

    # ── Full index ──
    lines = [
        "[bold]Blackout Kit — Help Index[/bold]\n",
        "[dim]Run [bold]blackout help <topic>[/bold] for detailed help on any topic.[/dim]\n",
    ]
    for category, names in _CATEGORIES.items():
        lines.append(f"\n[bold white]{category}[/bold white]")
        for name in names:
            summary = _SUMMARIES.get(name, "")
            lines.append(f"  [cyan]blackout help {name:<16}[/cyan] [dim]{summary}[/dim]")

    return "\n".join(lines)


def search_help(query: str) -> list[tuple[str, str]]:
    """
    Search all help topics for a keyword (case-insensitive).

    Returns a list of (topic_name, matched_line) sorted by relevance.
    Matches in summaries score higher than matches in body text.
    """
    query_lower = query.lower()
    matches: list[tuple[int, str, str]] = []   # (score, name, snippet)

    for name, body in TOPICS.items():
        score = 0
        snippet = ""

        # Summary match scores highest
        summary = _SUMMARIES.get(name, "")
        if query_lower in summary.lower():
            score += 10
            snippet = snippet or summary

        # Topic name match
        if query_lower in name.lower():
            score += 8
            snippet = snippet or f"Topic: {name}"

        # Body text match — find first matching line
        if query_lower in body.lower():
            score += 3
            for line in body.splitlines():
                clean = line.strip()
                if query_lower in clean.lower() and len(clean) > 5:
                    # Strip Rich markup for snippet display
                    import re
                    snippet = snippet or re.sub(r"\[.*?\]", "", clean).strip()
                    break

        if score > 0:
            matches.append((score, name, snippet or _SUMMARIES.get(name, "")))

    matches.sort(key=lambda x: x[0], reverse=True)
    return [(name, snippet) for _, name, snippet in matches]
