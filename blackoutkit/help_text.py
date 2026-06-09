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

[bold]Step 1 — Put binaries in bins/[/bold]
  At minimum you need TWO files in the [bold]bins/[/bold] folder:
    sni-spoofing.exe    (from t.me/patterniha or the project GitHub)
    xray.exe            (from github.com/XTLS/Xray-core/releases)

  Optional but recommended:
    goodbyedpi.exe      (github.com/ValdikSS/goodbyedpi/releases)
    warp-plus.exe       (github.com/hiddify/warp-plus/releases)

[bold]Step 1b — Verify your country profile[/bold]
  blackout country
  Auto-detects your country and shows the best engine for your location.
  For China: blackout country set CN  (manual pin recommended)

[bold]Step 2 — Add a V2Ray config[/bold]
  blackout config add "vless://...@127.0.0.1:40443?..."
  OR import a subscription:
  blackout config import https://your-subscription-url

[bold]Step 3 — Run a scan[/bold]
  blackout scan
  This finds the fastest Cloudflare IP for your location.

[bold]Step 4 — Start in background[/bold]
  blackout start -d
  Your Windows system proxy is set automatically.

[bold]Step 5 — Verify it works[/bold]
  blackout status
  You should see HTTP/SOCKS ports open and latency shown.

[dim]Need free configs? See: blackout help config[/dim]
[dim]Something broken? Run: blackout doctor[/dim]
""",

"faq": """
[bold cyan]Frequently Asked Questions[/bold cyan]

[bold]Q: The proxy stops working after a few hours. Why?[/bold]
  The censorship infrastructure changes IP blocks frequently.
  Run [bold]blackout scan[/bold] then [bold]blackout stop && blackout start -d[/bold]
  Or use daemon mode: [bold]blackout emergency -d[/bold]
  The daemon automatically switches engines if one fails.

[bold]Q: Cloudflare CAPTCHA keeps showing. How do I fix it?[/bold]
  1. Make sure xray_fingerprint = chrome  (default)
  2. Run [bold]blackout scan[/bold] to get a fresh Cloudflare IP
  3. Try: [bold]blackout start --engine warp[/bold]
     WARP gives you a "clean" Cloudflare IP with no captchas.

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
  Standard mode (SPEED) is NOT anonymous — it just bypasses censorship.
  For anonymity use: [bold]blackout mode legend[/bold]
  That enables Tor multi-hop routing. It is SLOW.
  See: [bold]blackout help security[/bold]
""",

# ── Core commands ─────────────────────────────────────────────────────────────

"start": """
[bold cyan]blackout start[/bold cyan]
Start a bypass engine and set Windows system proxy automatically.

[bold]Usage:[/bold]
  blackout start                        Auto-select best engine (sni by default)
  blackout start --engine sni           SNI + XRay stack (most effective)
  blackout start --engine gdpi          GoodbyeDPI only (no proxy port needed)
  blackout start --engine psiphon       Psiphon VPN (heaviest blackouts)
  blackout start --engine warp          Cloudflare WARP (clean IPs, no captchas)
  blackout start --engine tor           Tor onion network (max anonymity)
  blackout start -d                     Run in background — survives terminal close

[bold]What happens:[/bold]
  1. SNI engine starts on port 40443 (intercepts and fakes TLS headers)
  2. XRay core starts on SOCKS :10808 / HTTP :10809
  3. Windows system proxy is automatically set to 127.0.0.1:10809
  4. Your browser and most apps now go through the bypass

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
  1. Daemon process (and all child engines) are terminated
  2. Windows system proxy is cleared (direct connection restored)
  3. Kill switch is disabled if it was active

[bold]Note:[/bold]
  If the daemon is not responding, kill it manually:
    taskkill /F /IM python.exe
  Then run: blackout stop  (to clear the proxy even without the daemon)
""",

"scan": """
[bold cyan]blackout scan[/bold cyan]
Find the best Cloudflare IP and working fake SNI domains.

[bold]Usage:[/bold]
  blackout scan                         Scan both IPs and SNI domains
  blackout scan --ips                   Only scan Cloudflare IPs
  blackout scan --sni                   Only test fake SNI domain resolution
  blackout scan --count 200             Scan 200 IPs (default: 100)

[bold]What it does:[/bold]
  • Generates IPs from all official Cloudflare CIDR ranges
  • Tests TCP connectivity to port 443 on all IPs in parallel
  • Ranks results by latency (lower = faster)
  • Tests which fake SNI domains resolve correctly

[bold]After scanning:[/bold]
  Apply the best IP:  blackout settings set sni_connect_ip <ip>
  Then restart:       blackout stop && blackout start -d
""",

"emergency": """
[bold cyan]blackout emergency[/bold cyan]
Automatically try every engine until one successfully connects.

[bold]Usage:[/bold]
  blackout emergency                    Foreground mode
  blackout emergency -d                 Background mode (recommended)

[bold]Engine order:[/bold]
  sni → gdpi → psiphon  (configurable via settings engine_order)
  Change order: blackout settings set engine_order sni,psiphon,gdpi

[bold]When to use:[/bold]
  • You cannot access the internet at all
  • Your normal engine stopped working mid-session
  • You just woke up and found out there is a blackout
""",

"status": """
[bold cyan]blackout status[/bold cyan]
Show what's running and whether the proxy is actually working.

[bold]Displays:[/bold]
  • Daemon PID and active engine name
  • Windows system proxy status (enabled / what address)
  • Direct internet connectivity test
  • HTTP proxy port (10809) — open or closed
  • SOCKS5 proxy port (10808) — open or closed
  • End-to-end HTTP proxy latency through the bypass
  • SOCKS5 proxy latency

[bold]Tip:[/bold]
  Run [bold]blackout status[/bold] after starting — latency shown means it works.
  If ports show "closed", the engine crashed. Check logs:
  blackout logs
""",

"connect": """
[bold cyan]blackout connect[/bold cyan]
Smart one-command connect: scan → pick best engine → start in background.

[bold]Usage:[/bold]
  blackout connect                      Full auto (scan + start best engine)
  blackout connect --engine warp        Skip scan, use specific engine
  blackout connect --iran               🔥 Apply Iran bypass profile
                                        (Firefox fingerprint + private mode)
  blackout connect -d                   Run in background

[bold]What it does:[/bold]
  1. Runs a Cloudflare IP scan (unless --engine is specified)
  2. Applies the fastest IP to settings
  3. Starts the best available engine in background mode
  4. Sets system proxy automatically
  5. Shows status when done

[bold]Tip:[/bold]
  This is the command to use every morning. It handles everything.
""",

"fix": """
[bold cyan]blackout fix[/bold cyan]
Diagnose and auto-repair common issues in one command.

[bold]What it checks and fixes (Live Checklist):[/bold]
  ✓ System proxy not set → sets it
  ✓ DNS cache stale → flushes it
  ✓ Winsock corrupted → resets it
  ✓ Engine not running → restarts it
  ✓ TCP/IP stack issues → resets stack
  ✓ Cloudflare IP outdated → rescans

[bold]Usage:[/bold]
  blackout fix                          Run all auto-repairs with live status
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
  sni_connect_ip      Cloudflare IP to route through (run scan to find best)
  sni_fake_sni        Domain DPI sees — must be a whitelisted domain
  xray_fingerprint    TLS fingerprint: chrome / firefox / safari / random
                      [yellow]chrome gives fewest Cloudflare captchas[/yellow]
  auto_set_proxy      true = system proxy is set automatically
  engine_order        sni,gdpi,psiphon — emergency mode priority
  psiphon_country     Exit country for Psiphon (DE/US/CA/NL...)
  gdpi_flags          -9 = maximum bypass, -5 = balanced, -1 = minimal
  kill_switch         true = block ALL internet if proxy drops (safe mode)

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
  blackout config add <uri>             Add a vless:// or trojan:// URI
  blackout config import <url>          Import from subscription URL
  blackout config remove <n>            Remove config #n
  blackout config encrypt               Encrypt configs.txt with AES-256-GCM
  blackout config decrypt               Decrypt configs.enc back to configs.txt

[bold]Testing configs:[/bold]
  Analyze your configs: [bold]blackout test[/bold]
  Shows which configs are SNI-compatible and their basic details.

[bold]SNI-compatible configs:[/bold]
  Configs must use address 127.0.0.1:40443 to route through the SNI engine.
  Example:
  trojan://password@127.0.0.1:40443?security=tls&sni=www.hcaptcha.com
            &type=ws&path=/ws&host=www.hcaptcha.com

[bold]Free subscription sources:[/bold]
  github.com/barry-far/V2ray-Config
  github.com/Mohammadgb0078/IRV2ray
  t.me/patterniha  (Telegram — SNI-specific configs)

[bold]Config encryption:[/bold]
  Your configs contain server credentials.
  Encrypt them: [bold]blackout config encrypt[/bold]
  The file is locked with AES-256-GCM tied to this machine.
""",

# ── Engines ───────────────────────────────────────────────────────────────────

"engines": """
[bold cyan]Engine Reference[/bold cyan]
All bypass engines in Blackout Kit and when to use each.

[bold]DPI Bypass Engines (no VPN):[/bold]
  [bold]sni[/bold]        SNI packet injection — most effective for Cloudflare-fronted servers
             Requires: sni-spoofing.exe + xray.exe + a config
             Port: 40443 (listen) → HTTP :10809 / SOCKS :10808
             Best for: normal day-to-day use

  [bold]gdpi[/bold]       GoodbyeDPI TCP fragmentation — lightweight, no proxy port
             Requires: goodbyedpi.exe + WinDivert.dll + Administrator
             Best for: sites that don't need a proxy (Telegram, etc.)

[bold]VPN / Tunnel Engines:[/bold]
  [bold]psiphon[/bold]    Multi-protocol VPN — works even during heavy blackouts
             Requires: psiphon-tunnel-core-x86_64.exe
             Port: HTTP :8081 / SOCKS :1081
             Best for: last-resort when SNI fails, slow bootstrap

  [bold]warp[/bold]       Cloudflare WARP — clean residential IP, very few captchas
             Requires: warp-plus.exe
             Port: SOCKS :1080
             Best for: CAPTCHA issues, partial blackouts

  [bold]tor[/bold]        Tor onion network — maximum anonymity
             Requires: tor.exe (Expert Bundle)
             Port: SOCKS :9050
             Best for: high-privacy needs, slow

  [bold]wireguard[/bold]  Modern UDP-based VPN (your own server)
             Requires: wireguard.exe + .conf file
             Set: blackout settings set wg_config_file C:/path/wg0.conf

  [bold]openvpn[/bold]    Battle-tested TLS VPN (your own server)
             Requires: openvpn.exe + .ovpn config file
             Set: blackout settings set openvpn_config C:/path/vpn.ovpn

  [bold]softether[/bold]  SSL-VPN (looks like HTTPS on port 443)
             Requires: vpnclient.exe + vpncmd.exe
             Set: softether_host / softether_hub / softether_username

[bold]Special Engines:[/bold]
  [bold]neighbor[/bold]   Share or borrow internet from a nearby device on LAN
             No internet needed — peer discovery via UDP multicast
             See: blackout help neighbor

  [bold]appsscript[/bold] HTTP relay through Google Apps Script (domain fronting)
             Built-in, no binary needed — Google servers relay your traffic
             Port: HTTP :8087

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
  • [bold]Address/Port:[/bold] Valid server coordinates
  • [bold]Name:[/bold] User-friendly name from the URI remark

[dim]Coming soon: Real-time latency testing for every saved config.[/dim]
""",

"mode": """
[bold cyan]blackout mode[/bold cyan]
Switch between pre-configured security and performance profiles.

[bold]Usage:[/bold]
  blackout mode                         Show current mode and descriptions
  blackout mode speed                   Max speed, minimal overhead
  blackout mode private                 Random fingerprint + DoH
  blackout mode legend                  Multi-hop + timing obfuscation

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
  WireGuard installs as a Windows service and routes all traffic.

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
Three privacy levels — choose based on your threat model.

[bold]SPEED (default)[/bold]
  Goal: bypass censorship as fast as possible
  • Chrome TLS fingerprint (most compatible)
  • No mux overhead
  • No logging
  Run: [bold]blackout mode speed[/bold]

[bold]PRIVATE[/bold]
  Goal: harder to fingerprint your traffic
  • Random TLS fingerprint (chrome/firefox/safari rotates)
  • Mux enabled (multiple requests share one connection)
  • Slightly slower
  Run: [bold]blackout mode private[/bold]

[bold]LEGEND 🔥[/bold]
  Goal: near-untraceable
  • Random fingerprint + mux
  • SNI → XRay → Tor multi-hop (3 layers!)
  • Randomized packet timing
  • Config encryption enabled automatically
  • Kill switch enabled automatically
  • Very slow — expect 3-10× slower than SPEED
  Run: [bold]blackout mode legend[/bold]

[bold]Check current mode:[/bold]
  blackout mode

[bold]Note:[/bold]
  SPEED and PRIVATE still bypass censorship well.
  LEGEND adds anonymity on top — use it only if you need it.
""",

"killswitch": """
[bold cyan]Kill Switch[/bold cyan]
Blocks ALL internet if the proxy goes down.

[bold]Purpose:[/bold]
  Without a kill switch, if your proxy crashes, your traffic goes
  out unfiltered — the ISP sees everything. The kill switch prevents this
  by blocking all outbound traffic except through the proxy ports.

[bold]Usage:[/bold]
  blackout killswitch on                Enable kill switch
  blackout killswitch off               Disable kill switch
  blackout killswitch status            Check if active (queries Windows Firewall)

[bold]What it blocks:[/bold]
  • All outbound traffic  (except proxy ports 10808, 10809, 40443, 9050)
  • LAN traffic is allowed (192.168.*, 10.*, 172.16.*)
  • Port 853 TCP+UDP is blocked  → prevents DoH/DoT DNS leaks

[bold]Requirements:[/bold]
  Administrator privileges required.

[bold]Auto-enable in LEGEND mode:[/bold]
  [bold]blackout mode legend[/bold] enables the kill switch automatically.

[bold]Warning:[/bold]
  If you enable kill switch and the proxy is stopped, you lose internet.
  Run [bold]blackout killswitch off[/bold] to restore direct access.
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
  cert-check <host>     Check TLS certificate validity + per-mode policy
  cert-check <host> --allow  Allow host in LEGEND mode (self-signed bypass)
  hotspot               Toggle Windows Mobile Hotspot on/off
  share-vpn             Share your VPN via ICS (Internet Connection Sharing)
  netfix                Auto-repair: DNS flush + Winsock reset + TCP/IP reset

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
  blackout update                       Check and apply latest update
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
  [bold]Iran:[/bold]   SNI engine works best. Use Shecan/Electro DNS.
            blackout tools dns-set shecan
            blackout start --engine sni

  [bold]China:[/bold]  SNI does NOT work against GFW. Use Xray with a proper config.
            blackout country set CN
            blackout tools dns-set alibaba
            blackout start --engine xray

  [bold]Iraq:[/bold]   Similar to Iran. SNI + WARP both effective.
            blackout start --engine sni
            If SNI fails: blackout start --engine warp

  [bold]UK:[/bold]     GoodbyeDPI bypasses Ofcom ISP content filters.
            blackout start --engine gdpi

  [bold]USA:[/bold]    Usually just WARP for privacy/throttling bypass.
            blackout start --engine warp
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
  • Strict TLS validation (same as what xray does in LEGEND mode)
  • Per-mode policy: what allowInsecure would be for your current mode

[bold]Per-mode policy:[/bold]
  SPEED   → allowInsecure = True  always — silent, zero friction
  PRIVATE → allowInsecure = True  always — but logs a warning if cert is bad
  LEGEND  → allowInsecure = False when cert is KNOWN bad — hard refuses connection

[bold]Auto-detection:[/bold]
  When xray starts, the cert is probed automatically (3s timeout):
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
Blackout Kit natively supports 5 countries with tailored engine + DNS recommendations.

[bold]Country Reference:[/bold]
  Country          Level    Best Engine   DNS
  Iran (IR)        HIGH     sni           Shecan / Electro / 403online
  China (CN)       EXTREME  xray          Alibaba / Tencent / 114 DNS
  Iraq (IQ)        MEDIUM   sni           Cloudflare / Google
  UK   (GB)        LOW      gdpi          Cloudflare / Google
  USA  (US)        MINIMAL  warp          Cloudflare / Quad9

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

[bold]Verify your bypass works:[/bold]
  blackout country            See test URLs for your country
  blackout network isp        Full ISP + country context panel

[bold]China notes (EXTREME censorship):[/bold]
  The Great Firewall blocks by IP, SNI, and deep packet inspection.
  • SNI spoofing does NOT bypass the GFW
  • Use xray engine with a non-Chinese server config
  • Use Alibaba DNS (223.5.5.5) inside China for reliable resolution
  • Psiphon and WARP work as fallbacks but can be slow

[bold]Iran notes (HIGH censorship):[/bold]
  ISP-level DPI — SNI spoofing is very effective.
  • Shecan / Electro DNS resolve filtered domains
  • WARP is a good backup when SNI is blocked
  • Emergency mode: sni → warp → psiphon → gdpi
""",

}

# ─────────────────────────── Topic categories ────────────────────────────────
# Used by the help index to group topics for readability.

_CATEGORIES: dict[str, list[str]] = {
    "Getting Started":  ["quick_start", "faq", "countries", "bins", "network"],
    "Core Commands":    ["start", "stop", "scan", "connect", "fix", "status", "emergency", "mode"],
    "Configuration":    ["settings", "config"],
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
    "scan":          "Find the fastest Cloudflare IP for your location",
    "connect":       "One command: scan + pick best engine + start",
    "fix":           "Auto-diagnose and repair common issues",
    "status":        "Check what's running and whether the proxy works",
    "emergency":     "Try every engine until one connects",
    "settings":      "View and change all configuration settings",
    "config":        "Add, import, and manage V2Ray configs",
    "engines":       "All bypass engines explained — which to use when",
    "vpn":           "Set up WireGuard / OpenVPN / SoftEther / IKEv2",
    "warp":          "Cloudflare WARP — clean IP, fewer captchas",
    "neighbor":      "Share or borrow internet from a nearby device",
    "security":      "Speed / Private / Legend security modes",
    "killswitch":    "Block all traffic if the proxy drops",
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
