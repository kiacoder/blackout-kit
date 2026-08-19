"""
Blackout Kit - In-app help documentation.
Rich-formatted detailed help for every command.
"""

TOPICS: dict[str, str] = {

"quick_start": """
[bold cyan]Quick Start[/bold cyan]

[bold]1. Inspect local prerequisites[/bold]
  blackout doctor

[bold]2. Check runtime status[/bold]
  blackout bins

[bold]3. Download what Blackout Kit can install automatically[/bold]
  blackout bins download

[bold]4. Add or import configs if your chosen engine needs them[/bold]
  blackout config add <uri>
  blackout config import <url>

[bold]5. See what is locally ready[/bold]
  blackout route
  blackout ready xray

[bold]6. Connect[/bold]
  blackout connect

[bold]7. Inspect local state[/bold]
  blackout status

[dim]Important: route, ready, and status describe local state. They do not prove
remote reachability or guarantee bypass success.[/dim]
""",

"faq": """
[bold cyan]Frequently Asked Questions[/bold cyan]

[bold]Q: Does Blackout Kit guarantee privacy or anonymity?[/bold]
  No. It is a local coordinator for bypass engines and upstream configurations.
  Your actual privacy depends on the selected engine, the upstream server, the
  network, and the device you are using.

[bold]Q: Does blackout ready mean the tunnel will work?[/bold]
  No. It validates local prerequisites only: settings, files, ports, platform
  support, and related local state.

[bold]Q: Why does Linux support fewer engines?[/bold]
  Linux intentionally supports only xray, tun, hysteria2, and tuic through the
  managed blackout-engine runtime path.

[bold]Q: Is there a Windows kill switch?[/bold]
  No supported one. The old Windows Firewall approach is intentionally retired.
  The supported kill switch is Linux-only.

[bold]Q: Why does GoodbyeDPI sometimes load the site shell but not video?[/bold]
  Browser media can prefer QUIC/UDP while GoodbyeDPI is TCP-oriented. Disable
  QUIC in the browser to test whether that is the issue.
""",

"start": """
[bold cyan]blackout start[/bold cyan]
Start a specific engine path.

Examples:
  blackout start xray
  blackout start gdpi
  blackout start warp
  blackout start tun
  blackout start legend

[dim]Use 'blackout connect' if you want a locally recommended engine instead of an
explicit one.[/dim]
""",

"stop": """
[bold cyan]blackout stop[/bold cyan]
Stop the managed daemon and clear Blackout-managed local proxy state.

Notes:
  • If auto_set_proxy is enabled and the active proxy is Blackout-managed, it is cleared.
  • If Linux kill switch state is active, Blackout tries to remove only its own firewall state.
  • If no daemon is running, stop reports that and does not clear unrelated external proxy settings.
""",

"scan": """
[bold cyan]blackout scan[/bold cyan]
Measure local TCP reachability for generated Cloudflare candidates and resolve
configured fake-SNI domains.

Examples:
  blackout scan
  blackout scan --ips
  blackout scan --sni
  blackout scan --count 200

[dim]Scan results are local observations, not proof that a bypass path or remote
proxy server will work.[/dim]
""",

"connect": """
[bold cyan]blackout connect[/bold cyan]
Connect using an explicit engine or the highest locally ready recommendation.

Examples:
  blackout connect
  blackout connect xray
  blackout connect --background
  blackout connect --iran
  blackout connect --russia

Preset notes:
  • --iran applies temporary Iran-specific local overrides and uses the legend stack
  • --russia applies temporary Russia transport overrides for mixed XRay and QUIC-style paths
  • presets do not rewrite your saved settings; background mode forwards the temporary overrides into the daemon

What it uses:
  • platform support
  • installed local runtimes
  • saved protocols
  • pinned country profile
  • settings
  • local health history

[dim]This recommendation logic is local-only. It does not probe remote nodes as proof
of success.[/dim]
""",

"fix": """
[bold cyan]blackout fix[/bold cyan]
Run targeted post-crash recovery for Blackout-owned network state.

Examples:
  blackout fix
  blackout fix --preview
  blackout fix --history
  blackout fix --flush-arp
  blackout fix --full-route-reset
  blackout fix --full-stack-reset

Policy:
  • default recovery is intentionally narrow
  • preview shows planned actions without changing state
  • broader Windows resets remain explicit opt-in actions
  • Linux recovery removes only Blackout-owned firewall/tunnel/routing state
""",

"status": """
[bold cyan]blackout status[/bold cyan]
Show a read-only local snapshot of daemon, proxy, port, and saved health state.

Examples:
  blackout status
  blackout status --watch
  blackout status --watch --interval 5

[dim]Status does not reconnect, repair, or validate remote reachability.[/dim]
""",

"route": """
[bold cyan]blackout route[/bold cyan]
Rank engines from local readiness and saved local health history.

Evidence used:
  • platform support
  • installed runtimes
  • saved proxy protocols
  • pinned country profile
  • local settings
  • local stability history

[dim]No remote nodes are contacted during route ranking.[/dim]
""",

"theme": """
[bold cyan]blackout theme[/bold cyan]
Set or inspect Blackout Kit's terminal-only Rich palette.

Examples:
  blackout theme
  blackout theme dark
  blackout theme light

[dim]This affects only Blackout Kit output, not the host terminal application.[/dim]
""",

"settings": """
[bold cyan]blackout settings[/bold cyan]
View and change saved settings.

Examples:
  blackout settings list
  blackout settings get security_mode
  blackout settings set gdpi_backend legacy
  blackout settings set kill_switch false

Important settings to know:
  • gdpi_backend
  • security_mode
  • auto_set_proxy
  • engine_order
  • selected_engine
  • terminal_theme
  • country
  • xray_doh_dns
  • xray_split_tunnel
  • reconnect_initial_delay
  • reconnect_max_delay

[dim]kill_switch is supported only on Linux.[/dim]
""",

"config": """
[bold cyan]blackout config[/bold cyan]
Manage saved proxy URIs and encrypted local storage.

Examples:
  blackout config list
  blackout config add <uri>
  blackout config import <url>
  blackout config remove <n>
  blackout config encrypt
  blackout config decrypt

Important notes:
  • encryption is machine-bound
  • decrypt is a same-machine recovery action that restores plaintext files
  • test/list views should not be treated as remote reachability checks
""",

"split_tunnel": """
[bold cyan]blackout split-tunnel[/bold cyan]
Manage Windows system-proxy bypass patterns.

Examples:
  blackout split-tunnel list
  blackout split-tunnel add example.com
  blackout split-tunnel remove example.com

[dim]This is not per-process routing and not Linux route-table management.[/dim]
""",

"engines": """
[bold cyan]Engine Reference[/bold cyan]

[bold]Windows supports:[/bold]
  sni, xray, gdpi, psiphon, warp, tun, tor, mhrv, ikev2,
  wireguard, openvpn, softether, appsscript, hysteria2, tuic, legend

[bold]XRay transports:[/bold]
  ws, tcp, grpc, xhttp (also accepts legacy type=splithttp)

[bold]Linux supports:[/bold]
  xray, tun, hysteria2, tuic

[bold]Important notes:[/bold]
  • gdpi uses legacy as the stable default backend; native is experimental
  • warp and psiphon currently rely on blackout_warp.dll runtime paths
  • several native Windows paths rely on blackout_core.dll
  • legend is both a security-mode name and a composite connect/start target

[dim]Engine availability does not guarantee that a network or upstream server will work.[/dim]
""",

"network": """
[bold cyan]blackout network[/bold cyan]
WiFi and ISP-oriented helper commands.

Examples:
  blackout network
  blackout network scan
  blackout network isp
  blackout network auto
  blackout network switch <ssid>

[dim]Country and ISP context can inform recommendations, but they do not prove that a
specific engine or server path will work.[/dim]
""",

"logs": """
[bold cyan]blackout logs[/bold cyan]
Read recent daemon log output.

Examples:
  blackout logs
  blackout logs --lines 200
""",

"test": """
[bold cyan]blackout test[/bold cyan]
Analyze saved configuration entries locally.

It helps inspect:
  • protocol
  • transport/security mode
  • naming/labels
  • local compatibility shape

[dim]This command is local-only and does not prove endpoint reachability.[/dim]
""",

"mode": """
[bold cyan]blackout mode[/bold cyan]
View or set the local security mode.

Examples:
  blackout mode
  blackout mode speed
  blackout mode private
  blackout mode legend

[dim]Mode changes are local configuration changes, not privacy guarantees.[/dim]
""",

"preflight": """
[bold cyan]blackout preflight[/bold cyan]
Run an offline-first readiness summary before a potential outage.

Helpful companions:
  blackout doctor
  blackout route
  blackout ready [engine]
""",

"vpn": """
[bold cyan]VPN Engine Setup[/bold cyan]
Blackout Kit supports several VPN-style paths, but setup details vary by engine.

Examples:
  • wireguard requires a supplied .conf file
  • openvpn requires a supplied .ovpn file
  • ikev2 uses saved built-in Windows VPN settings
  • softether depends on the relevant client components

[dim]These paths still depend on your upstream VPN server or runtime setup.[/dim]
""",

"security": """
[bold cyan]Security Modes[/bold cyan]
Blackout Kit exposes three local security presets:

[bold]SPEED[/bold]
  Compatibility-focused local settings.

[bold]PRIVATE[/bold]
  Randomized XRay fingerprint plus MUX.

[bold]LEGEND[/bold]
  Stricter handling for known-bad normal TLS certificates.

Important boundaries:
  • these are local settings bundles
  • they do not guarantee anonymity or bypass success
  • REALITY uses XRay's REALITY handshake, not the normal TLS cert-check path
""",

"killswitch": """
[bold cyan]Kill Switch[/bold cyan]
The supported kill switch is Linux-only.

Examples:
  sudo blackout killswitch on
  sudo blackout killswitch off
  sudo blackout killswitch test

Important facts:
  • Linux kill switch is endpoint-scoped and Blackout-owned
  • it refuses activation without a safe upstream endpoint allowlist
  • Windows legacy rules are intentionally unsupported and removed
""",

"tools": """
[bold cyan]blackout tools[/bold cyan]
Network diagnostics and support commands.

Examples:
  blackout tools ping 1.1.1.1
  blackout tools dns-bench
  blackout tools dns-set cloudflare
  blackout tools dns-flush
  blackout tools speedtest
  blackout tools adapters
  blackout tools traceroute google.com
  blackout tools cert-check example.com
  blackout tools netfix
  blackout tools arp-flush

[dim]Some tools change local network state; read the command output carefully.[/dim]
""",

"neighbor": """
[bold cyan]blackout neighbor[/bold cyan]
Share or consume a nearby LAN-based proxy path.

Examples:
  blackout neighbor discover
  blackout neighbor connect <ip>
  blackout neighbor share

[dim]This is a local-LAN feature, not a privacy guarantee or an internet reachability proof.[/dim]
""",

"doctor": """
[bold cyan]blackout doctor[/bold cyan]
Run environment checks and optionally auto-fix fixable local issues.

Examples:
  blackout doctor
  blackout doctor --fix
  blackout doctor --fix-av

Doctor can inspect:
  • settings validity
  • runtime presence
  • binary integrity/runnability
  • stale proxy state
  • stale Blackout adapter state
  • config encryption status
  • platform compatibility

[dim]doctor is about local machine state, not proof that an upstream connection will work.[/dim]
""",

"update": """
[bold cyan]blackout update[/bold cyan]
Check for a newer project release and optionally apply it.

Examples:
  blackout update
  blackout update --apply

Related checks:
  blackout preflight
  blackout ready [engine]
  blackout fix --preview
""",

"warp": """
[bold cyan]WARP and Psiphon Runtime Notes[/bold cyan]
Current code uses blackout_warp.dll for the active WARP and Psiphon runtime paths.

Important notes:
  • user-facing workflow stays 'warp' or 'psiphon'
  • runtime asset naming is implementation detail, but docs should stay accurate
  • actual behavior still depends on local runtime state and upstream availability
""",

"troubleshoot": """
[bold cyan]Troubleshooting[/bold cyan]

If a connection path fails:
  1. blackout doctor
  2. blackout ready <engine>
  3. blackout route
  4. blackout logs
  5. blackout status

If crash leftovers break networking:
  1. blackout stop
  2. blackout fix
  3. use the broader Windows-only reset flags only if targeted recovery fails

If a binary is missing:
  1. blackout bins
  2. blackout bins download

If GoodbyeDPI loads a site shell but media fails:
  browser-side QUIC/UDP may be bypassing the TCP-oriented path.
""",

"cert": """
[bold cyan]blackout tools cert-check[/bold cyan]
Check a normal TLS certificate and see current mode policy implications.

Examples:
  blackout tools cert-check example.com
  blackout tools cert-check example.com:8443
  blackout tools cert-check example.com --allow

Important note:
  This applies to normal TLS handling. REALITY does not use this path.
""",

"bins": """
[bold cyan]blackout bins[/bold cyan]
Inspect, download, or update Blackout Kit runtime assets and related binaries.

Examples:
  blackout bins
  blackout bins download
  blackout bins download xray
  blackout bins update

Important notes:
  • some items are auto-downloadable
  • some remain manual or semi-manual depending on engine/runtime path
  • current runtime naming includes assets like blackout_core.dll, blackout_warp.dll,
    and blackout-engine for Linux

[dim]Check the current downloader behavior rather than assuming every historical engine
name still maps 1:1 to a standalone executable path.[/dim]
""",

"countries": """
[bold cyan]Country Profiles[/bold cyan]
Built-in profiles currently exist for:
  IR, RU, CN, IQ, GB, US, EU

Examples:
  blackout country
  blackout country set IR
  blackout country set RU
  blackout country set CN
  blackout country reset

[dim]Country profiles inform local recommendations. They are not guarantees.[/dim]
[dim]Russia is currently a first-pass profile that favors XRay and QUIC-capable paths before lighter DPI bypass options.[/dim]
""",

"russia": """
[bold cyan]Russia Support[/bold cyan]
Blackout Kit ships first-class Russia support through the RU country profile and the
[bold]--russia[/bold] transport preset.

[bold]Phase 1 — RU country profile[/bold]
  blackout country set RU

Recommends engines in this order on both Windows and Linux:
  xray → hysteria2 → tuic → (Windows: warp, gdpi; Linux: tun)

[bold]Phase 2 — Russia transport preset[/bold]
  blackout connect --russia
  blackout start xray --russia
  blackout start hysteria2 --russia
  blackout start tuic --russia

The preset applies temporary local overrides for one launch only:
  • pins the RU country profile
  • uses PRIVATE security mode (random TLS fingerprint)
  • keeps DNS-over-HTTPS enabled
  • disables Iran-only split-tunnel domain shortcuts
  • disables Iran-specific TLS fragmentation overrides
  • does NOT rewrite your saved settings, even in background mode

[bold]What works in Russia (field-verified)[/bold]
  • VLESS + REALITY over TCP — fastest and most reliable path
  • Hysteria2 — works on cellular but slower than REALITY
  • Both XHTTP and plain REALITY transports work well
  • XHTTP is now supported: add configs with type=xhttp or type=splithttp

[bold]Known Russian filtering behavior[/bold]
  • Cellular whitelist mode: only whitelisted IP ranges pass
    (Yandex, VK, Ozon, and other Russian tech giants)
  • Blocked IPs die instantly — all connections to that IP stop working
  • A successful TCP handshake does NOT mean the tunnel works:
    connections often pass the handshake, then drop when real data flows

[bold]Practical guidance[/bold]
  • Prefer a server whose IP sits on or behind a whitelisted range
  • If a working endpoint suddenly fails completely, the IP was likely
    just blocked — rotate to the next saved config instead of retrying
  • REALITY does not use the normal TLS cert-check path; use
    [bold]blackout tools cert-check[/bold] only for normal TLS hosts

[dim]Russia support is a first-pass profile and preset, not a guarantee of bypass
success. Effectiveness depends on the network, server IP, and current filtering.[/dim]
""",
}

_CATEGORIES: dict[str, list[str]] = {
    "Getting Started": ["quick_start", "faq", "countries", "russia", "bins", "network"],
    "Core Commands": ["start", "stop", "scan", "connect", "fix", "status", "route", "theme", "emergency", "mode"],
    "Configuration": ["settings", "config", "split_tunnel"],
    "Engines": ["engines", "vpn", "warp", "neighbor"],
    "Security": ["security", "killswitch"],
    "Maintenance": ["tools", "cert", "doctor", "update", "preflight", "logs"],
    "Help": ["troubleshoot", "test"],
}

_SUMMARIES: dict[str, str] = {
    "quick_start": "First-run order: doctor, bins, route, ready, connect, status",
    "faq": "Common questions and product-boundary answers",
    "start": "Start an explicit engine path",
    "stop": "Stop the daemon and clear Blackout-managed local proxy state",
    "scan": "Measure local TCP reachability for Cloudflare and fake-SNI inputs",
    "connect": "Connect with a local recommendation or explicit engine",
    "fix": "Targeted recovery for Blackout-owned crash leftovers",
    "status": "Read local daemon, proxy, and port state",
    "route": "Rank locally ready engines without probing remote nodes",
    "theme": "Set Blackout Kit's terminal-only palette",
    "emergency": "Try locally supported engine candidates in sequence",
    "settings": "View and change saved settings",
    "config": "Manage saved config URIs and local encrypted storage",
    "split_tunnel": "Manage Windows system-proxy bypass patterns",
    "engines": "Current engine and platform support overview",
    "vpn": "VPN-path setup notes",
    "warp": "Current WARP and Psiphon runtime notes",
    "neighbor": "LAN sharing and nearby-proxy flow",
    "security": "Explain speed/private/legend mode boundaries",
    "killswitch": "Linux-only supported kill switch",
    "tools": "Diagnostics and local network tools",
    "doctor": "Inspect and auto-fix local environment issues",
    "update": "Check and apply project updates",
    "preflight": "Offline-first readiness summary",
    "logs": "Read daemon log output",
    "test": "Analyze saved configs locally",
    "mode": "View or set the security mode",
    "network": "WiFi and ISP helper commands",
    "troubleshoot": "Common failure paths and what to check next",
    "countries": "Country profiles are guidance, not guarantees",
    "russia": "Russia profile and --russia transport preset notes",
    "bins": "Manage runtime assets and downloadable binaries",
    "cert": "Check normal TLS certs and policy impact",
}


def get_help(topic: str | None) -> str:
    if topic:
        if topic in TOPICS:
            return TOPICS[topic]
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
    query_lower = query.lower()
    matches: list[tuple[int, str, str]] = []

    for name, body in TOPICS.items():
        score = 0
        snippet = ""

        summary = _SUMMARIES.get(name, "")
        if query_lower in summary.lower():
            score += 10
            snippet = snippet or summary

        if query_lower in name.lower():
            score += 8
            snippet = snippet or f"Topic: {name}"

        if query_lower in body.lower():
            score += 3
            for line in body.splitlines():
                clean = line.strip()
                if query_lower in clean.lower() and len(clean) > 5:
                    import re
                    snippet = snippet or re.sub(r"\[.*?\]", "", clean).strip()
                    break

        if score > 0:
            matches.append((score, name, snippet or _SUMMARIES.get(name, "")))

    matches.sort(key=lambda x: x[0], reverse=True)
    return [(name, snippet) for _, name, snippet in matches]
