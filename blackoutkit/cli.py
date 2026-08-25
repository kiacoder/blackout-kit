"""
Blackout Kit - Main CLI.
All user-facing commands live here.
"""
import argparse
import asyncio
from collections import deque
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import json
import os
import sys
import threading
import time
from pathlib import Path

from rich.panel import Panel
from rich.progress import (
    Progress, SpinnerColumn, BarColumn,
    TextColumn, TimeElapsedColumn, TaskProgressColumn,
)
from rich.table import Table
from rich.live import Live
from rich import box

from . import __version__
from .theme import console, print_banner, make_table, latency_color, refresh_console_theme, is_interactive, ask_choice, confirm
from . import settings as cfg
from . import daemon

import importlib

class _LazyModule:
    def __init__(self, name, package):
        self._name = name
        self._package = package
        self._mod = None
    def __getattr__(self, item):
        if self._mod is None:
            self._mod = importlib.import_module(self._name, self._package)
        return getattr(self._mod, item)

net_tools = _LazyModule(".tools", "blackoutkit")
doc = _LazyModule(".doctor", "blackoutkit")
updater = _LazyModule(".updater", "blackoutkit")
sec = _LazyModule(".security", "blackoutkit")
cp = _LazyModule(".country_profiles", "blackoutkit")

def set_system_proxy(*args, **kwargs):
    from .proxy_manager import set_system_proxy as _func
    return _func(*args, **kwargs)

def clear_system_proxy(*args, **kwargs):
    from .proxy_manager import clear_system_proxy as _func
    return _func(*args, **kwargs)

def get_proxy_status(*args, **kwargs):
    from .proxy_manager import get_proxy_status as _func
    return _func(*args, **kwargs)

def generate_cloudflare_ips(*args, **kwargs):
    from .scanner.ip_scanner import generate_cloudflare_ips as _func
    return _func(*args, **kwargs)

def scan_ips(*args, **kwargs):
    from .scanner.ip_scanner import scan_ips as _func
    return _func(*args, **kwargs)

def save_cache(*args, **kwargs):
    from .scanner.ip_scanner import save_cache as _func
    return _func(*args, **kwargs)

def load_configs(*args, **kwargs):
    from .config.manager import load_configs as _func
    return _func(*args, **kwargs)

def add_config(*args, **kwargs):
    from .config.manager import add_config as _func
    return _func(*args, **kwargs)

def remove_config(*args, **kwargs):
    from .config.manager import remove_config as _func
    return _func(*args, **kwargs)

def import_and_merge(*args, **kwargs):
    from .config.manager import import_and_merge as _func
    return _func(*args, **kwargs)

def get_help(*args, **kwargs):
    from .help_text import get_help as _func
    return _func(*args, **kwargs)


def test_tcp_port(*args, **kwargs):
    from .scanner.proxy_tester import test_tcp_port as _func
    return _func(*args, **kwargs)


def test_direct(*args, **kwargs):
    from .scanner.proxy_tester import test_direct as _func
    return _func(*args, **kwargs)

# ──────────────────────────── Engine map ─────────────────────────

ALL_ENGINE_CHOICES = ["auto", "sni", "xray", "gdpi", "psiphon", "warp", "tun", "tor", "mhrv", "ikev2", "wireguard", "openvpn", "softether", "appsscript", "hysteria2", "tuic", "awg", "legend"]

def _get_engine_classes(name: str) -> tuple:
    if sys.platform.startswith("linux") and name == "tun":
        from .engines.xray import XRayEngine
        from .engines.tun import TUNEngine
        return (XRayEngine, TUNEngine)
    if name == "sni":
        from .engines.sni import SNIEngine
        from .engines.xray import XRayEngine
        return (SNIEngine, XRayEngine)
    elif name == "xray":
        from .engines.xray import XRayEngine
        return (XRayEngine,)
    elif name == "gdpi":
        from .engines.gdpi import GoodbyeDPIEngine
        return (GoodbyeDPIEngine,)
    elif name == "psiphon":
        from .engines.psiphon import PsiphonEngine
        return (PsiphonEngine,)
    elif name == "warp":
        from .engines.warp import WARPEngine
        return (WARPEngine,)
    elif name == "tun":
        from .engines.tun import TUNEngine
        return (TUNEngine,)
    elif name == "tor":
        from .engines.tor import TorEngine
        return (TorEngine,)
    elif name == "mhrv":
        from .engines.mhrv import MhrvEngine
        return (MhrvEngine,)
    elif name == "ikev2":
        from .engines.ikev2 import IKEv2Engine
        return (IKEv2Engine,)
    elif name == "wireguard":
        from .engines.wireguard import WireGuardEngine
        return (WireGuardEngine,)
    elif name == "openvpn":
        from .engines.openvpn import OpenVPNEngine
        return (OpenVPNEngine,)
    elif name == "softether":
        from .engines.softether import SoftEtherEngine
        return (SoftEtherEngine,)
    elif name == "appsscript":
        from .engines.appsscript import AppsScriptEngine
        return (AppsScriptEngine,)
    elif name == "hysteria2":
        from .engines.singbox_proxy import Hysteria2Engine
        return (Hysteria2Engine,)
    elif name == "tuic":
        from .engines.singbox_proxy import TuicEngine
        return (TuicEngine,)
    elif name == "awg":
        from .engines.amneziawg import AmneziaWGEngine
        return (AmneziaWGEngine(),)
    elif name == "legend":
        from .engines.tor import TorEngine
        from .engines.sni import SNIEngine
        from .engines.xray import XRayEngine
        return (TorEngine, SNIEngine, XRayEngine)
    return ()
VALID_COUNTRY_CODES = tuple(sorted(cp._BY_CODE.keys()))
EXTRA_ADMIN_ENGINES = {"gdpi", "warp", "tun"}
AUTO_SCAN_ENGINES = {"sni"}
AUTO_DOWNLOAD_DEPENDENCIES = {
    "sni": ["xray", "sni-spoofing"],
    "xray": ["xray"],
    "gdpi": ["goodbyedpi"],
    "mhrv": ["mhrv"],
    "legend": ["xray", "sni-spoofing"],
    "wireguard": ["wireguard"],
    "softether": ["softether"],
    "tor": ["tor"],
    "openvpn": ["openvpn"],
    "warp": ["warp_dll"],
    "psiphon": ["warp_dll"],
    "tun": ["sing-box"],
    "hysteria2": [],
    "tuic": [],
    "awg": [],
    "ikev2": [],
    "appsscript": [],
}

_LINUX_SUPPORTED_ENGINES = frozenset({"xray", "tun", "hysteria2", "tuic", "awg"})


def _platform_engine_error(name: str) -> str | None:
    if not sys.platform.startswith("linux"):
        return None
    if name in _LINUX_SUPPORTED_ENGINES:
        return None
    return (
        f"{name} is currently Windows-only. Linux currently supports XRay, "
        "TUN, Hysteria2, and TUIC through the managed blackout-engine runner."
    )


def _linux_default_engine(name: str) -> str:
    if sys.platform.startswith("linux") and name in {"auto", "sni", "gdpi", "psiphon", "warp", "legend"}:
        return "tun"
    return name


def _linux_dependencies(name: str) -> list[str]:
    if sys.platform.startswith("linux") and name in {"xray", "tun", "hysteria2", "tuic"}:
        return ["linux_engine"]
    return AUTO_DOWNLOAD_DEPENDENCIES.get(name, [])


def _linux_runner_available() -> bool:
    from . import BINS_DIR

    return (BINS_DIR / "blackout-engine").is_file()


def _linux_missing_dependencies(name: str) -> list[str]:
    if _linux_dependencies(name) == ["linux_engine"] and not _linux_runner_available():
        return ["linux_engine"]
    return []


def _linux_dependency_hint() -> str:
    return "Install the Linux x86_64 Blackout Kit release asset so bins/blackout-engine is available."


def _setting_env_name(key: str) -> str:
    return f"BLACKOUT_{key.upper()}"


def _setting_env_value(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return ",".join(str(item) for item in value)
    return str(value)


def _env_overrides_from_settings(overrides: dict[str, object]) -> dict[str, str]:
    return {
        _setting_env_name(key): _setting_env_value(value)
        for key, value in overrides.items()
    }


@contextmanager
def _temporary_env_overrides(env_overrides: dict[str, str] | None):
    previous: dict[str, str | None] = {}
    env_overrides = env_overrides or {}
    for key, value in env_overrides.items():
        previous[key] = os.environ.get(key)
        os.environ[key] = value
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _mode_overrides(mode_name: str) -> dict[str, object]:
    mode = sec.MODES.get(mode_name, {})
    overrides = {
        key: value
        for key, value in mode.items()
        if key != "description" and key in cfg.DEFAULTS
    }
    overrides["security_mode"] = mode_name
    return overrides


def _preset_payload(preset_name: str | None, settings: dict, *, direct_start: bool = False) -> tuple[str | None, dict[str, str], list[str], str | None]:
    if not preset_name:
        return None, {}, [], None

    if preset_name == "iran":
        overrides = _mode_overrides("legend" if direct_start else "private")
        overrides["country"] = "IR"
        if direct_start:
            overrides["sni_fake_sni"] = "www.snapp.ir"
            overrides["xray_fragment"] = "10-20,30-40"
        else:
            overrides["xray_fingerprint"] = "firefox"
            current_sni = settings.get("sni_fake_sni", "")
            arvancloud_sni = settings.get("sni_arvancloud_sni", "www.arvancloud.ir")
            if current_sni in ("www.hcaptcha.com", ""):
                overrides["sni_fake_sni"] = arvancloud_sni
            if not settings.get("xray_fragment"):
                overrides["xray_fragment"] = "10-50,10-50"

        changes = [
            "Country profile: Iran",
            f"Security mode: {str(overrides['security_mode']).upper()}",
            f"TLS fingerprint: {overrides['xray_fingerprint']}",
        ]
        if "sni_fake_sni" in overrides:
            changes.append(f"Fake SNI → {overrides['sni_fake_sni']}")
        if overrides.get("xray_fragment"):
            changes.append("TLS fragmentation enabled")
        footer = "[dim]This preset applies temporary local overrides for Iran-specific routing assumptions and does not rewrite your saved settings.[/dim]"
        return "Iran 2026 — TIC Evasion", _env_overrides_from_settings(overrides), changes, footer

    if preset_name == "russia":
        overrides = _mode_overrides("private")
        overrides.update({
            "country": "RU",
            "xray_doh_dns": True,
            "xray_split_tunnel": False,
            "xray_fragment": "",
        })
        current_sni = settings.get("sni_fake_sni", "")
        if current_sni in (settings.get("sni_arvancloud_sni", "www.arvancloud.ir"), ""):
            overrides["sni_fake_sni"] = "www.hcaptcha.com"
        changes = [
            "Country profile: Russia",
            "Security mode: PRIVATE",
            "DNS-over-HTTPS enabled",
            "Iran-specific split-tunnel rules disabled",
            "Iran-specific TLS fragmentation disabled",
        ]
        if "sni_fake_sni" in overrides:
            changes.append(f"Fake SNI → {overrides['sni_fake_sni']}")
        footer = "[dim]This preset temporarily pins RU guidance for mixed VLESS, Trojan, Hysteria2, and TUIC paths without changing your saved defaults.[/dim]"
        return "Russia — Transport Preset", _env_overrides_from_settings(overrides), changes, footer

    raise ValueError(f"Unknown preset: {preset_name}")


def _print_preset_panel(title: str, changes: list[str], footer: str | None) -> None:
    from .theme import success_panel

    body = "[bold]Preset Active[/bold]\n\n" + "\n".join(f"  • {change}" for change in changes)
    if footer:
        body += f"\n\n{footer}"
    console.print()
    console.print(success_panel(body, title=title))


def _start_engine_stack(name: str):
    """Instantiate and start all engines in a stack. Returns running list."""
    from . import downloader as dl

    platform_error = _platform_engine_error(name)
    if platform_error:
        console.print(f"[error]{platform_error}[/error]")
        return []

    missing_linux = _linux_missing_dependencies(name)
    if missing_linux:
        console.print(f"[error]✗ {_linux_dependency_hint()}[/error]")
        return []

    deps = _linux_dependencies(name)
    if deps and not sys.platform.startswith("linux"):
        installed = dl.check_installed()
        missing = [k for k in deps if not installed.get(k, False)]
        if missing:
            auto_downloadable = []
            manual_only = []
            for k in missing:
                info = dl.BIN_REGISTRY.get(k)
                if info:
                    if info.github_repo:
                        auto_downloadable.append((k, info))
                    else:
                        manual_only.append(info)

            if manual_only:
                console.print(f"\n[error]✗ Missing manual-install binaries required for [bold]{name}[/bold]:[/error]")
                for info in manual_only:
                    console.print(
                        f"\n  [bold yellow]{info.display_name}[/bold yellow]\n"
                        f"  Please download from: [cyan]{info.manual_url}[/cyan]\n"
                        f"  Note: {info.manual_note or 'Extract to bins/ folder'}\n"
                    )
                return []

            if auto_downloadable:
                console.print(f"\n[warning]⚠️ Required binaries for [bold]{name}[/bold] are missing.[/warning]")
                for k, info in auto_downloadable:
                    console.print(f"  • {info.display_name}")
                try:
                    ans = console.input("\n[bold cyan]Would you like to download and install them now? (y/n):[/bold cyan] ").strip().lower()
                except (KeyboardInterrupt, EOFError):
                    return []
                if ans in ("y", "yes"):
                    console.print()
                    for k, info in auto_downloadable:
                        _download_single(dl, k, info)
                    # Recheck
                    installed = dl.check_installed()
                    still_missing = [k for k in deps if not installed.get(k, False)]
                    if still_missing:
                        console.print("[error]Some binaries are still missing. Aborting connection.[/error]")
                        return []
                else:
                    console.print("[warning]Aborted. Engine cannot start without binaries.[/warning]")
                    return []

    classes = _get_engine_classes(name)
    running = []

    import logging
    from rich.status import Status

    class EngineStatusHandler(logging.Handler):
        def __init__(self, status_obj, eng_name):
            super().__init__()
            self.status_obj = status_obj
            self.eng_name = eng_name
            self.setLevel(logging.DEBUG)
            # Use basic formatting so we just get the message
            self.setFormatter(logging.Formatter("%(message)s"))

        def emit(self, record):
            if record.levelno <= logging.INFO:
                msg = self.format(record)
                self.status_obj.update(
                    f"[bold cyan]Starting {self.eng_name}...[/bold cyan]\n  [dim]→ {msg}[/dim]"
                )

    with console.status(f"[bold cyan]Starting stack: {name}...[/bold cyan]") as status:
        for cls in classes:
            eng = cls()
            
            # Attach handler to this specific engine's logger
            handler = EngineStatusHandler(status, eng.name)
            eng._log.addHandler(handler)
            # Ensure the logger passes DEBUG messages to our handler
            old_level = eng._log.level
            eng._log.setLevel(logging.DEBUG)
            
            try:
                success = eng.start()
            finally:
                eng._log.removeHandler(handler)
                eng._log.setLevel(old_level)
                
            if success:
                running.append(eng)
            else:
                console.print(f"  [warning]⚠ {eng.name} failed to start (check logs for details)[/warning]")
                # Rollback: stop all already started engines in this stack
                for r in running:
                    try:
                        r.stop()
                    except Exception:
                        pass
                return []
                
    return running



# ──────────────────────────── Country profile helper ─────────────

def _get_active_profile():
    """Return CountryProfile from settings pin or auto-detect from ISP (4s timeout)."""
    from .network_switcher import get_isp_info
    code = cfg.load().get("country", "")
    if code:
        return cp.get_profile(code)
    return cp.detect_country(get_isp_info(timeout=4.0))


# ──────────────────────────── Commands ───────────────────────────

def cmd_country(args):
    """Show, set, or reset the active country profile."""
    subcmd = getattr(args, "country_command", None)

    if subcmd == "set":
        code = args.code.upper()
        profile = cp.get_profile(code)
        if not profile:
            console.print(
                f"[error]Unknown country code: {code}[/error]  "
                f"Valid codes: {', '.join(VALID_COUNTRY_CODES)}"
            )
            return
        cfg.set_value("country", code)
        console.print(f"[success]✓ Country pinned to:[/success] [bold]{profile.name}[/bold] ({code})")
        console.print("  [muted]Run [bold]blackout country[/bold] to see the full profile.[/muted]")
        return

    if subcmd == "reset":
        cfg.set_value("country", "")
        console.print("[success]✓ Country pin cleared.[/success]  Back to auto-detect from ISP.")
        return

    # ── No subcommand: detect + show panel ──
    pinned = cfg.load().get("country", "")
    with console.status("[bold]Detecting country...[/bold]", spinner="dots"):
        profile = _get_active_profile()

    if not profile:
        console.print(Panel(
            "  [warning]Could not detect country.[/warning]\n\n"
            "  [dim]Set manually with [bold]blackout country set <code>[/bold][/dim]\n"
            f"  [dim]Valid codes: {'  '.join(VALID_COUNTRY_CODES)}[/dim]",
            title="[bold]Country Profile[/bold]",
            border_style="yellow",
            width=56,
        ))
        return

    detect_label  = "pinned" if pinned else "auto-detected"
    level_upper   = profile.censorship_level.upper()
    engine_str    = " → ".join(profile.engine_order)
    dns_str       = " / ".join(label for label, _ in profile.bypass_dns)
    test_str      = "  ".join(profile.test_urls) if profile.test_urls else "(none)"

    console.print(Panel(
        f"  [muted]Country:[/muted]    [bold]{profile.name}[/bold]  ({detect_label})\n"
        f"  [muted]Code:[/muted]       {profile.code}\n"
        f"  [muted]Level:[/muted]      [bold]{level_upper}[/bold] censorship\n\n"
        f"  [muted]Engine order:[/muted]  {engine_str}\n"
        f"  [muted]Bypass DNS:[/muted]    {dns_str}\n"
        f"  [muted]Test URLs:[/muted]     {test_str}\n\n"
        f"  [dim]\"{profile.notes}\"[/dim]",
        title="[bold]Country Profile[/bold]",
        border_style="cyan",
        width=60,
    ))


def cmd_scan(args):
    s = cfg.load()
    do_ips = args.ips or not args.sni
    do_sni = args.sni or not args.ips

    console.print()

    if do_sni:
        _scan_fake_snis()

    if do_ips:
        count = getattr(args, "count", None) or s["scan_ip_count"]
        _scan_cloudflare_ips(count, s["scan_concurrency"], s["scan_timeout"])


def _scan_fake_snis():
    sni_file = Path(__file__).parent.parent / "data" / "fake_snis.txt"
    if not sni_file.exists():
        console.print("[warning]data/fake_snis.txt not found[/warning]")
        return

    try:
        domains = [
            d.strip() for d in sni_file.read_text(encoding="utf-8", errors="replace").splitlines()
            if d.strip() and not d.startswith("#")
        ]
    except (OSError, IOError, MemoryError) as e:
        console.print(f"[error]Failed to read fake SNIs file: {e}[/error]")
        return

    table = make_table(
        "Fake SNI Domains",
        [("Domain", "cyan"), ("Resolves?", ""), ("Notes", "dim")],
        [],
    )

    import socket as _sock
    _old_timeout = _sock.getdefaulttimeout()
    _sock.setdefaulttimeout(3)
    try:
        for domain in domains:
            try:
                _sock.getaddrinfo(domain, 443)
                table.add_row(domain, "[success]✓ Yes[/success]", "Safe to use")
            except Exception:
                table.add_row(domain, "[error]✗ No[/error]", "DNS blocked")
    finally:
        _sock.setdefaulttimeout(_old_timeout)

    console.print(table)
    console.print()


def _scan_cloudflare_ips(count: int, concurrency: int, timeout: float):
    console.print("[info]Testing pre-tested known-good IPs first...[/info]")
    from .scanner.ip_scanner import KNOWN_GOOD_IPS, scan_ips, generate_cloudflare_ips
    from . import settings as cfg
    custom_ips = cfg.load().get("sni_custom_ips") or []
    pre_tested = list(set(custom_ips + KNOWN_GOOD_IPS))
    
    results = asyncio.run(
        scan_ips(pre_tested, concurrency=concurrency, timeout=timeout)
    )
    
    if results:
        # Found good IPs, no need to do a full scan
        ips = pre_tested
        console.print(f"[success]Found {len(results)} working IPs from known-good list. Skipping full scan.[/success]")
    else:
        console.print(f"[warning]Known-good IPs failed. Generating {count} random Cloudflare IPs to scan...[/warning]")
        ips = generate_cloudflare_ips(count)
        scanned = {"done": 0}
        with Progress(
            SpinnerColumn(style="bold red"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40, style="red", complete_style="green"),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(f"Scanning {len(ips)} IPs on :443 ...", total=len(ips))
            def on_done():
                scanned["done"] += 1
                progress.advance(task)
            results = asyncio.run(
                scan_ips(ips, concurrency=concurrency, timeout=timeout, progress_callback=on_done)
            )

    if results:
        save_cache(results)

    if not results:
        console.print("[error]No reachable Cloudflare IPs found. Your internet may be fully blocked.[/error]")
        return

    table = make_table(
        f"Reachable Cloudflare IPs  ({len(results)} / {len(ips)} responded)",
        [("IP Address", "cyan"), ("Latency", ""), ("Tier", "")],
        [],
    )
    for ip, ms in results[:20]:
        if ms < 40:
            tier = "[bold magenta]Celestial[/bold magenta]"
        elif ms < 70:
            tier = "[bold red]Legendary[/bold red]"
        elif ms < 100:
            tier = "[bold orange3]Epic[/bold orange3]"
        elif ms < 150:
            tier = "[bold blue]Rare[/bold blue]"
        elif ms < 250:
            tier = "[bold green]Uncommon[/bold green]"
        else:
            tier = "[dim]Common[/dim]"
        table.add_row(ip, latency_color(ms), tier)

    console.print(table)

    best_ip = results[0][0]
    console.print(
        f"\n[success]Best IP:[/success] [bold]{best_ip}[/bold]  "
        f"({results[0][1]:.0f}ms)\n"
        f"Apply it: [bold]blackout settings set sni_connect_ip {best_ip}[/bold]"
    )


def cmd_test(args):
    configs = load_configs()
    if not configs:
        console.print("[warning]No configs in data/configs.txt[/warning]")
        console.print("Add one: [bold]blackout config add <uri>[/bold]")
        console.print("Or import: [bold]blackout config import <url>[/bold]")
        return

    sni_ok  = sum(1 for c in configs if c.is_sni_compatible())
    direct  = len(configs) - sni_ok

    console.print(
        f"\n[info]Loaded {len(configs)} configs[/info]  "
        f"([success]{sni_ok} SNI-compatible[/success]  "
        f"[muted]{direct} direct[/muted])\n"
    )

    table = make_table(
        "Config List",
        [("#", "dim"), ("Proto", "cyan"), ("Transport", "yellow"),
         ("Type", ""), ("Name", "white")],
        [],
    )
    for i, c in enumerate(configs, 1):
        ctype = "[success]SNI spoofer[/success]" if c.is_sni_compatible() else "[muted]direct[/muted]"
        table.add_row(str(i), c.protocol, c.transport_label(), ctype, c.name or "-")

    console.print(table)


def _resolve_engine_name(args, default: str = "sni") -> str:
    pos_engine = getattr(args, "pos_engine", None)
    flag_engine = getattr(args, "engine", None)
    selected = pos_engine or flag_engine or default
    return default if selected == "auto" else selected


def _health_check_target(proxy_info):
    if not proxy_info:
        return None
    host, port = proxy_info
    if host.startswith("socks="):
        host = host.split("=", 1)[1]
    return (host, port)


def cmd_start(args):
    requested_engine = _resolve_engine_name(args)
    engine_name = _linux_default_engine(requested_engine)
    background = getattr(args, "background", False)
    iran = getattr(args, "iran", False)
    russia = getattr(args, "russia", False)

    if iran and russia:
        console.print("[error]Choose only one preset: --iran or --russia.[/error]")
        return

    preset_name = "iran" if iran else "russia" if russia else None
    preset_title = None
    preset_changes: list[str] = []
    preset_footer = None
    env_overrides: dict[str, str] = {}
    base_settings = cfg.load()

    if preset_name:
        if preset_name == "iran":
            engine_name = "legend"
            if requested_engine not in {"auto", "sni", "xray", "legend", "tor"}:
                console.print("[yellow]Iran preset is tuned for the Tor + SNI + XRay stack and related local settings.[/yellow]")
        preset_title, env_overrides, preset_changes, preset_footer = _preset_payload(
            preset_name,
            base_settings,
            direct_start=True,
        )

    effective_engine_name = engine_name
    with _temporary_env_overrides(env_overrides):
        platform_error = _platform_engine_error(effective_engine_name)
        if platform_error:
            console.print(f"[error]{platform_error}[/error]")
            return
        if not _ensure_ready(effective_engine_name):
            return

        if preset_title:
            _print_preset_panel(preset_title, preset_changes, preset_footer)

        s = cfg.load()
        proxy_info = None
        health_target = None

        import ctypes
        is_admin = False
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            pass

        if background:
            try:
                pid = daemon.start(effective_engine_name, env_overrides=env_overrides)
                console.print(Panel(
                    f"[success]Engine:[/success]  [bold]{effective_engine_name}[/bold]\n"
                    f"[success]PID:[/success]     [bold]{pid}[/bold]\n"
                    f"[success]Log:[/success]     [dim]{daemon.LOG_FILE}[/dim]\n\n"
                    f"[muted]Run [bold]blackout status[/bold] to monitor.[/muted]\n"
                    f"[muted]Run [bold]blackout stop[/bold] to stop.[/muted]",
                    title="[bold green]✓ Blackout Kit — Background[/bold green]",
                    border_style="green",
                ))
            except RuntimeError as e:
                console.print(f"[error]{e}[/error]")
            return

        if sys.platform == "win32" and not is_admin and effective_engine_name in EXTRA_ADMIN_ENGINES:
            console.print("[warning]Elevating to Administrator... Please accept the UAC prompt.[/warning]")
            try:
                pid = daemon.start(effective_engine_name, env_overrides=env_overrides)
                if not pid:
                    console.print("[error]Failed to start daemon (UAC prompt declined or timed out).[/error]")
                    return
                console.print(f"  [success]✓ {effective_engine_name}[/success] running in background (PID {pid})")
                console.print("\n[muted]Press Ctrl+C to stop.[/muted]\n")
                try:
                    # Wait for log file to be created (daemon might not have created it yet)
                    for _ in range(100):  # Wait up to 10 seconds
                        if daemon.LOG_FILE.exists():
                            break
                        time.sleep(0.1)
                    if not daemon.LOG_FILE.exists():
                        console.print("[warning]⚠ Daemon log file not created (may be disabled). Stopping...[/warning]")
                        daemon.stop()
                        return
                    with open(daemon.LOG_FILE, "r", encoding="utf-8") as f:
                        f.seek(0, 2)
                        try:
                            while daemon.get_pid() is not None:
                                line = f.readline()
                                if not line:
                                    time.sleep(0.1)
                                    continue
                                if "[ERROR]" in line:
                                    console.print(f"[red]{line.strip()}[/red]")
                                elif "[WARNING]" in line:
                                    console.print(f"[yellow]{line.strip()}[/yellow]")
                                elif "[success]" in line:
                                    console.print(f"[green]{line.strip()}[/green]")
                                else:
                                    console.print(f"[dim]{line.strip()}[/dim]")
                        except KeyboardInterrupt:
                            pass
                        finally:
                            console.print("\n[warning]Stopping...[/warning]")
                            daemon.stop()
                except FileNotFoundError:
                    console.print("[warning]⚠ Failed to open daemon log file. Stopping...[/warning]")
                    daemon.stop()
                return
            except RuntimeError as e:
                console.print(f"[error]{e}[/error]")
                return

        kill_switch_enabled = False
        if sys.platform.startswith("linux") and s.get("kill_switch", False):
            if not sec.prepare_linux_kill_switch(effective_engine_name):
                console.print("[error]Could not resolve a safe Linux kill-switch endpoint; refusing to start.[/error]")
                return
            if not sec.enable_kill_switch(effective_engine_name):
                console.print("[error]Linux kill switch could not be enabled; refusing to start the system tunnel.[/error]")
                return
            kill_switch_enabled = True

        engines = _start_engine_stack(effective_engine_name)
        if not engines:
            if kill_switch_enabled:
                sec.disable_kill_switch()
                sec.clear_linux_kill_switch_endpoint(effective_engine_name)
            console.print("[error]No engines could start. Make sure binaries are in bins/.[/error]")
            return

        for eng in engines:
            console.print(f"  [success]✓ {eng.name}[/success] running (PID {eng.pid})")

        if s.get("auto_set_proxy"):
            proxy_info = cfg.get_engine_proxy_details(effective_engine_name, s)
            if proxy_info:
                p_host, p_port = proxy_info
                if set_system_proxy(p_host, p_port):
                    console.print(f"  [success]✓ System proxy set[/success] → {p_host}:{p_port}")
                health_target = _health_check_target(proxy_info)
            else:
                console.print("  [info]Network-level engine — no system proxy needed[/info]")

        console.print("\n[muted]Press Ctrl+C to stop.[/muted]\n")
        try:
            last_check = time.monotonic()
            while all(e.is_running() for e in engines):
                time.sleep(1)
                now = time.monotonic()
                if now - last_check > 10.0:
                    last_check = now
                    if s.get("auto_set_proxy") and health_target:
                        import socket
                        try:
                            with socket.create_connection(health_target, timeout=2.0):
                                pass
                        except Exception:
                            console.print("\n[warning]⚠ Proxy port stopped responding. Check your internet connection.[/warning]")
        except KeyboardInterrupt:
            pass
        finally:
            console.print("\n[warning]Stopping...[/warning]")
            for eng in engines:
                eng.stop()
            if s.get("auto_set_proxy"):
                clear_system_proxy()
            if kill_switch_enabled:
                sec.disable_kill_switch()
                sec.clear_linux_kill_switch_endpoint(effective_engine_name)
            console.print("[success]Stopped. System proxy cleared.[/success]")


def cmd_stop(args):
    if daemon.stop():
        s = cfg.load()
        if s.get("auto_set_proxy"):
            clear_system_proxy()
        if s.get("kill_switch", False):
            try:
                sec.disable_kill_switch()
            except Exception:
                pass
        console.print("[success]✓ Daemon stopped. System proxy cleared.[/success]")
    else:
        console.print("[warning]No daemon is running.[/warning]")


def cmd_emergency(args):
    background = getattr(args, "background", False)

    if background:
        try:
            pid = daemon.start("emergency")
            console.print(Panel(
                "[bold red]🚨 EMERGENCY MODE — Background[/bold red]\n\n"
                f"[muted]Trying engines in order: {' → '.join(cfg.get('engine_order'))}[/muted]\n\n"
                f"[success]PID:[/success] [bold]{pid}[/bold]\n"
                f"[success]Log:[/success] [dim]{daemon.LOG_FILE}[/dim]",
                border_style="red",
            ))
        except RuntimeError as e:
            console.print(f"[error]{e}[/error]")
        return

    # ── Foreground emergency ──
    console.print(Panel(
        "[bold red]🚨 EMERGENCY MODE[/bold red]\n"
        "Trying locally supported engine candidates in sequence.",
        border_style="red",
    ))

    s             = cfg.load()
    em_profile    = _get_active_profile()
    default_order = em_profile.engine_order if em_profile else ["sni", "gdpi", "psiphon"]
    order = s.get("engine_order") or default_order
    if sys.platform.startswith("linux"):
        order = ["tun", "xray", "hysteria2", "tuic"]
    active        = []
    health_target = None
    proxy_info = None

    for ename in order:
        engines = _start_engine_stack(ename)
        if not engines:
            console.print(f"  [error]✗ {ename} — no binaries found[/error]")
            continue

        time.sleep(3)

        ok = all(e.is_running() for e in engines)
        if ok:
            console.print(f"  [success]✓ {ename} is running![/success]")
            active = engines
            break
        else:
            for eng in engines:
                eng.stop()
            console.print(f"  [error]✗ {ename} crashed[/error]")

    if not active:
        console.print("\n[error]All engines failed. Check bins/ folder.[/error]")
        return

    if s.get("auto_set_proxy"):
        proxy_info = cfg.get_engine_proxy_details(ename, s)
        if proxy_info:
            p_host, p_port = proxy_info
            if set_system_proxy(p_host, p_port):
                console.print(f"[success]✓ System proxy set[/success] → {p_host}:{p_port}")
            health_target = _health_check_target(proxy_info)
        else:
            console.print("  [info]Network-level engine — no system proxy needed[/info]")

    console.print("\n[muted]Press Ctrl+C to stop.[/muted]")
    try:
        last_check = time.monotonic()
        while all(e.is_running() for e in active):
            time.sleep(1)
            
            # Every 10 seconds, check if the proxy is actually routing traffic
            now = time.monotonic()
            if now - last_check > 10.0:
                last_check = now
                if s.get("auto_set_proxy") and health_target:
                    import socket
                    try:
                        with socket.create_connection(health_target, timeout=2.0):
                            pass
                    except Exception:
                        console.print("\n[warning]⚠ Proxy port stopped responding. Check your internet connection.[/warning]")
    except KeyboardInterrupt:
        pass
    finally:
        for eng in active:
            eng.stop()
        if s.get("auto_set_proxy"):
            clear_system_proxy()
        console.print("[success]Stopped.[/success]")


def _status_snapshot() -> dict:
    """Collect only local daemon, proxy, port, and stability state."""
    settings = cfg.load()
    pid = daemon.get_pid()
    state = daemon.get_state()
    proxy = get_proxy_status()
    active_engine = state.get("engine", "unknown") if state else "unknown"
    proxy_target = cfg.get_engine_proxy_details(active_engine, settings) if pid else None
    http_port = None
    socks_port = None
    if proxy_target:
        host, port = proxy_target
        if isinstance(host, str) and host.startswith("socks="):
            socks_port = port
        else:
            http_port = port
            if active_engine in ("sni", "xray", "legend"):
                socks_port = settings.get("xray_socks_port", 10808)
    return {
        "settings": settings,
        "pid": pid,
        "state": state,
        "proxy": proxy,
        "active_engine": active_engine,
        "http_port": http_port,
        "socks_port": socks_port,
        "http_open": test_tcp_port("127.0.0.1", http_port) is not None if http_port else None,
        "socks_open": test_tcp_port("127.0.0.1", socks_port) is not None if socks_port else None,
        "stability": sec.get_stability_score(active_engine) if state else None,
        "latencies": sec.get_recent_latencies(active_engine) if state else [],
        "events": daemon.get_recent_events(3) if pid else [],
    }


def _sparkline(data: list[float | None], width: int = 15, higher_is_better: bool = False) -> str:
    """
    Generate a Unicode sparkline from numeric data.

    higher_is_better=False (default): latency-style coloring — low values are green.
    higher_is_better=True: throughput-style coloring — high values are green.
    """
    valid = [v for v in data if v is not None]
    if not valid:
        return "[muted]" + " " * width + "[/muted]"

    # Pad to width
    data = data[-width:]
    if len(data) < width:
        data = [None] * (width - len(data)) + data

    min_val, max_val = min(valid), max(valid)
    bars = " ▂▃▄▅▆▇█"

    res = ""
    for v in data:
        if v is None:
            res += "[error]x[/error]"
        else:
            if min_val == max_val:
                idx = 3
            else:
                idx = int((v - min_val) / (max_val - min_val) * 7)
            if higher_is_better:
                # Higher throughput = better = green; relative to this sample's own range
                ratio = 0.5 if min_val == max_val else (v - min_val) / (max_val - min_val)
                color = "success" if ratio >= 0.66 else ("warning" if ratio >= 0.33 else "error")
            else:
                # Higher latency = worse = red, lower = better = green
                if v < 300:
                    color = "success"
                elif v < 800:
                    color = "warning"
                else:
                    color = "error"
            res += f"[{color}]{bars[idx]}[/{color}]"
    return res


def _format_bps(bps: float) -> str:
    for unit in ("B/s", "KB/s", "MB/s", "GB/s"):
        if bps < 1024.0:
            return f"{bps:.1f} {unit}"
        bps /= 1024.0
    return f"{bps:.1f} TB/s"


MAX_BANDWIDTH_HISTORY = 300
MAX_BANDWIDTH_INTERFACES = 32


def _record_bandwidth_history(history: dict[str, list[float]], rates: dict[str, dict]) -> None:
    """Record bounded download-rate samples for the most recently observed interfaces."""
    for name, rate in rates.items():
        samples = history.pop(name, None)
        if samples is None:
            if len(history) >= MAX_BANDWIDTH_INTERFACES:
                del history[next(iter(history))]
            samples = []
        history[name] = samples
        samples.append(rate["rx_bps"])
        if len(samples) > MAX_BANDWIDTH_HISTORY:
            samples.pop(0)


def _latency_monitor_panel(host: str, history: list[float | None], window: int = 60) -> Panel:
    display = history[-window:]
    stats = net_tools.ping_stats(display) if display else {"avg": None, "min": None, "max": None, "jitter": None, "loss_pct": 0.0}
    graph = _sparkline(display, width=max(1, min(40, len(display))))

    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    table.add_column(style="muted", width=16)
    table.add_column()
    table.add_row("Target", host)
    table.add_row("Samples", str(len(display)))
    table.add_row("History", graph if display else "[dim]collecting...[/dim]")
    if stats["avg"] is not None:
        jitter_str = f"{stats['jitter']:.1f}ms" if stats["jitter"] is not None else "-"
        table.add_row("Avg / Min / Max", f"{stats['avg']:.1f}ms / {stats['min']:.1f}ms / {stats['max']:.1f}ms")
        table.add_row("Jitter", jitter_str)
        table.add_row("Loss", f"{stats['loss_pct']:.0f}%")
    latest = display[-1] if display else None
    latest_disp = latency_color(latest) if latest is not None else ("[error]timeout[/error]" if display else "[dim]-[/dim]")
    table.add_row("Latest", latest_disp)
    return Panel(table, title=f"[heading]Latency Monitor — {host}[/heading]  [muted](Ctrl+C to stop)[/muted]", border_style="panel.border")


def _bandwidth_panel(rates: dict[str, dict], history: dict[str, list[float]]) -> Panel:
    table = Table(box=box.SIMPLE, header_style="table.header")
    table.add_column("Interface", style="cyan")
    table.add_column("Download", style="white")
    table.add_column("Upload", style="white")
    table.add_column("Trend (down)")

    active = {name: r for name, r in rates.items() if r["rx_bps"] > 0 or r["tx_bps"] > 0}
    shown = active if active else rates
    for name in sorted(shown, key=lambda n: shown[n]["rx_bps"], reverse=True)[:8]:
        r = shown[name]
        graph = _sparkline(history.get(name, []), width=max(1, min(20, len(history.get(name, [])))), higher_is_better=True)
        table.add_row(name, _format_bps(r["rx_bps"]), _format_bps(r["tx_bps"]), graph)

    if not shown:
        table.add_row("[dim]no interfaces found[/dim]", "-", "-", "")

    return Panel(table, title="[heading]Bandwidth Monitor[/heading]  [muted](Ctrl+C to stop)[/muted]", border_style="panel.border")


_CAPTURE_PROTO_STYLES = {"TCP": "cyan", "UDP": "yellow", "ICMP": "magenta", "ARP": "blue", "IP": "white"}


def _capture_panel(packets: deque, stats: dict, iface: str) -> Panel:
    table = Table(box=box.SIMPLE, header_style="table.header")
    table.add_column("Time", style="muted", no_wrap=True)
    table.add_column("Proto", width=6)
    table.add_column("Source", style="white")
    table.add_column("Destination", style="white")
    table.add_column("Len", justify="right", style="dim")

    for pkt in list(packets)[-15:]:
        style = _CAPTURE_PROTO_STYLES.get(pkt["proto"], "dim")
        src = f"{pkt['src']}:{pkt['sport']}" if pkt["sport"] else pkt["src"]
        dst = f"{pkt['dst']}:{pkt['dport']}" if pkt["dport"] else pkt["dst"]
        table.add_row(
            time.strftime("%H:%M:%S", time.localtime(pkt["ts"])),
            f"[{style}]{pkt['proto']}[/{style}]",
            src,
            dst,
            str(pkt["length"]),
        )

    if not packets:
        table.add_row("", "", "[dim]waiting for traffic...[/dim]", "", "")

    proto_counts = stats.get("protocol_counts", {})
    footer = "  ".join(f"{proto}: {n}" for proto, n in sorted(proto_counts.items(), key=lambda kv: -kv[1]))
    subtitle = f"[muted]{footer}[/muted]" if footer else None

    return Panel(
        table,
        title=f"[heading]Packet Capture — {iface or 'auto'}[/heading]  [muted]({stats.get('total_packets', 0)} captured, Ctrl+C to stop)[/muted]",
        subtitle=subtitle,
        border_style="panel.border",
    )


def _capture_summary_table(summary: dict) -> Table:
    table = make_table(
        f"Capture Summary  ({summary['total_packets']} packets, {summary['total_bytes']:,} bytes, {summary['duration']:.1f}s)",
        [("Protocol", "cyan"), ("Packets", "bold white")],
        [],
    )
    for proto, n in sorted(summary["protocol_counts"].items(), key=lambda kv: -kv[1]):
        table.add_row(proto, str(n))

    if summary["top_talkers"]:
        table.add_row("", "")
        table.add_row("[bold]Top talkers[/bold]", "")
        for addr, n in summary["top_talkers"]:
            table.add_row(addr, str(n))

    return table


def _status_panel(snapshot: dict) -> Panel:
    state = snapshot["state"]
    pid = snapshot["pid"]
    if not pid:
        daemon_info = "[muted]○ Not running[/muted]"
    else:
        status = state.get("status", "connected") if state else "unknown"
        status_info = "[success]● Connected[/success]" if status == "connected" else f"[warning]● {status.title()}[/warning]"
        if status == "failed":
            status_info = "[error]● Reconnect attempts exhausted[/error]"
        retry = ""
        if status == "reconnecting":
            retry = f"\n  [muted]Next retry:[/muted] {state.get('next_retry_delay', '?')}s"
        daemon_info = (
            f"{status_info}  (PID {pid})\n"
            f"  [muted]Engine:[/muted]  [bold]{snapshot['active_engine']}[/bold]\n"
            f"  [muted]Started:[/muted] {state.get('started', '-')}"
            f"{retry}"
        )
    stability = snapshot["stability"]
    stability_info = "[muted]No local health history[/muted]"
    if stability and stability.get("avg_ms") is not None:
        graph = _sparkline(snapshot.get("latencies", []))
        stability_info = (
            f"avg {stability['avg_ms']:.0f}ms · loss {stability['loss_pct']:.0f}% · "
            f"{stability['trend']}  {graph}"
        )
    proxy = snapshot["proxy"]
    proxy_info = f"[success]● Active[/success]  {proxy['server']}" if proxy["enabled"] else "[muted]○ Off[/muted]"
    
    io_info = ""
    if state and "io_bytes" in state and state["io_bytes"]:
        rx, tx = state["io_bytes"]
        def fmt_bytes(b):
            for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
                if b < 1024.0:
                    return f"{b:.1f}{unit}"
                b /= 1024.0
            return f"{b:.1f}PB"
        io_info = f"[cyan]↓[/cyan] {fmt_bytes(rx)}   [magenta]↑[/magenta] {fmt_bytes(tx)}"

    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    table.add_column(style="muted", width=18)
    table.add_column()
    table.add_row("Daemon", daemon_info)
    if io_info:
        table.add_row("Data transferred", io_info)
    
    events = snapshot.get("events", [])
    if events:
        table.add_row("Recent events", "\n".join(events))

    table.add_row("System proxy", proxy_info)
    table.add_row("HTTP local port", "[success]Open[/success]" if snapshot["http_open"] else "[muted]n/a[/muted]" if snapshot["http_open"] is None else "[error]Closed[/error]")
    table.add_row("SOCKS local port", "[success]Open[/success]" if snapshot["socks_open"] else "[muted]n/a[/muted]" if snapshot["socks_open"] is None else "[error]Closed[/error]")
    table.add_row("Local stability", stability_info)
    table.add_row("Security mode", snapshot["settings"].get("security_mode", "speed").upper())
    table.add_row("Terminal palette", snapshot["settings"].get("terminal_theme", "dark").upper())
    return Panel(table, title="[heading]Blackout Kit Status[/heading]", border_style="panel.border")


def cmd_status(args):
    """Show a read-only local status snapshot, optionally refreshing it live."""
    watch = getattr(args, "watch", False)
    interval = getattr(args, "interval", 2.0)
    if not watch:
        console.print(_status_panel(_status_snapshot()))
        return
    try:
        with Live(_status_panel(_status_snapshot()), console=console, refresh_per_second=4) as live:
            while True:
                time.sleep(interval)
                live.update(_status_panel(_status_snapshot()))
    except KeyboardInterrupt:
        console.print("\n[muted]Status watch stopped.[/muted]")


def _local_country_profile(settings: dict):
    code = settings.get("country", "")
    return cp.get_profile(code) if code else None


def _routing_candidates():
    from . import downloader
    from .config.manager import load_configs
    from .routing import recommend_routes

    settings = cfg.load()
    profile = _local_country_profile(settings)
    return recommend_routes(
        settings,
        country_profile=profile,
        installed=downloader.check_installed(),
        protocols={config.protocol for config in load_configs()},
        stability_scores=sec.all_stability_scores(),
    )


def cmd_route(args):
    """Display local engine recommendations without probing remote nodes."""
    candidates = _routing_candidates()
    if not candidates:
        console.print(Panel("[warning]No engine is supported on this platform.[/warning]", title="Smart Routing", border_style="yellow"))
        return None
    table = Table(box=box.ROUNDED, header_style="table.header")
    table.add_column("Engine", style="engine")
    table.add_column("Ready")
    table.add_column("Local evidence", style="muted")
    table.add_column("Blockers", style="warning")
    for candidate in candidates:
        table.add_row(
            candidate.engine,
            "[success]Ready[/success]" if candidate.ready else "[error]Blocked[/error]",
            candidate.evidence,
            ", ".join(candidate.blockers) or "—",
        )
    recommended = next((candidate for candidate in candidates if candidate.ready), candidates[0])
    console.print(Panel(table, title=f"[heading]Smart Routing · recommends {recommended.engine}[/heading]", border_style="panel.border"))
    console.print("[muted]Recommendations use local settings, a pinned country profile when set, installed components, and saved health history only. They do not probe nodes or change connectivity.[/muted]")
    return recommended


def _recommended_engine_name() -> str:
    candidates = _routing_candidates()
    candidate = next((candidate for candidate in candidates if candidate.ready), None)
    return candidate.engine if candidate else "xray"


def cmd_theme(args):
    """Show or set Blackout Kit's terminal-only Rich palette."""
    palette = getattr(args, "palette", None)
    if not palette:
        palette = cfg.load().get("terminal_theme", "dark")
        console.print(f"[info]Terminal palette:[/info] [bold]{palette}[/bold] (Blackout Kit only)")
        return
    cfg.set_value("terminal_theme", palette)
    refresh_console_theme()
    console.print(f"[success]✓ Terminal palette set to {palette}.[/success] This does not change your terminal application.")


def cmd_logs(args):
    lines = getattr(args, "lines", 50)
    content = daemon.read_logs(lines)
    console.print(Panel(
        f"[dim]{content}[/dim]",
        title=f"[bold]Daemon Logs[/bold]  [dim]{daemon.LOG_FILE}[/dim]",
        border_style="dim",
    ))


def cmd_config(args):
    if not hasattr(args, "config_command") or not args.config_command:
        console.print("[warning]Usage: blackout config [list | add <uri> | import <url> | remove <n> | export | import-setup <string>][/warning]")
        return

    if args.config_command == "list":
        configs = load_configs()
        if not configs:
            console.print("[warning]No configs saved. Use 'blackout config add' or 'blackout config import'.[/warning]")
            return
        table = make_table(
            f"Saved Configs  ({len(configs)})",
            [("#", "dim"), ("Protocol", "cyan"), ("Transport", "yellow"),
             ("Compatible", ""), ("Name", "white")],
            [],
        )
        for i, c in enumerate(configs, 1):
            compat = "[success]✓ SNI[/success]" if c.is_sni_compatible() else "[dim]direct[/dim]"
            table.add_row(str(i), c.protocol, c.transport_label(), compat, c.name or "-")
        console.print(table)

    elif args.config_command == "add":
        try:
            c = add_config(args.uri)
            name = f" [{c.name}]" if c.name else ""
            console.print(f"[success]✓ Added:[/success] {c.protocol.upper()} · {c.transport_label()}{name}")
        except ValueError as e:
            console.print(f"[error]{e}[/error]")

    elif args.config_command == "remove":
        try:
            remove_config(args.index - 1)
            console.print(f"[success]✓ Removed config #{args.index}[/success]")
        except IndexError as e:
            console.print(f"[error]{e}[/error]")

    elif args.config_command == "import":
        console.print("[info]Importing from subscription URL...[/info]")
        try:
            added, total = import_and_merge(args.url)
            console.print(f"[success]✓ Imported {added} new configs. Total: {total}[/success]")
        except Exception as e:
            console.print(f"[error]Import failed: {e}[/error]")

    elif args.config_command == "encrypt":
        if sec.configs_are_obfuscated():
            console.print("[warning]Encrypted local vault storage is already active.[/warning]")
            return
        try:
            sec.obfuscate_configs()
        except Exception:
            console.print("[error]Encryption failed. Plaintext files were preserved.[/error]")
            return
        console.print("[success]✓ Proxy configs and supported VPN secrets are encrypted at rest.[/success]")
        console.print("[muted]Plaintext proxy configs and password/PSK settings were removed only after encrypted records were written.[/muted]")
        console.print("[muted]Use [bold]blackout config decrypt[/bold] only for same-machine recovery; it restores plaintext files.[/muted]")

    elif args.config_command == "decrypt":
        if not sec.configs_are_obfuscated():
            console.print("[warning]No encrypted local vault data was found.[/warning]")
            return
        if sec.deobfuscate_configs():
            console.print("[success]✓ Encrypted proxy configs and supported VPN secrets restored to plaintext files.[/success]")
            console.print("[warning]Run blackout config encrypt again when recovery is complete to protect them at rest.[/warning]")
        else:
            console.print("[error]Decryption failed. Encrypted files were preserved; they may be corrupted or from a different machine.[/error]")

    elif args.config_command == "export":
        from .config.manager import serialize_setup
        import base64

        try:
            setup_data = serialize_setup()
            blob = json.dumps(setup_data, sort_keys=True).encode("utf-8")
            b64_string = base64.b64encode(blob).decode("ascii")

            if hasattr(args, "output") and args.output:
                from pathlib import Path
                output_path = Path(args.output).resolve()
                if not output_path.parent.exists():
                    output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(b64_string, encoding="utf-8")
                console.print(f"[success]✓ Setup exported to:[/success] {output_path}")
            else:
                console.print("[success]Setup string (base64):[/success]")
                console.print(b64_string)
                console.print(f"[muted]({len(b64_string)} chars)[/muted]")
        except Exception as e:
            console.print(f"[error]Export failed: {e}[/error]")

    elif args.config_command == "import-setup":
        from .config.manager import deserialize_setup, save_configs
        import base64

        try:
            setup_string = args.setup_string
            if not setup_string:
                console.print("[error]No setup string provided.[/error]")
                return

            blob = base64.b64decode(setup_string.encode("ascii"))
            setup_data = json.loads(blob.decode("utf-8"))
            configs, settings_data = deserialize_setup(setup_data)

            console.print(f"[info]Setup contains {len(configs)} config(s) + {len(settings_data)} setting(s)[/info]")

            if not getattr(args, "force", False):
                resp = console.input("[warning]Import will overwrite existing configs and settings. Continue? [y/N]:[/warning] ")
                if resp.lower() != "y":
                    console.print("[muted]Import cancelled.[/muted]")
                    return

            save_configs(configs)
            current = cfg.load()
            current.update(settings_data)
            cfg.save(current)
            console.print("[success]✓ Setup imported successfully[/success]")
        except (base64.binascii.Error, json.JSONDecodeError, ValueError) as e:
            console.print(f"[error]Invalid setup string: {e}[/error]")
        except Exception as e:
            console.print(f"[error]Import failed: {e}[/error]")


def cmd_settings(args):
    refresh_console_theme()
    s = cfg.load()

    if not hasattr(args, "settings_command") or not args.settings_command:
        _settings_list(s)
        return

    if args.settings_command == "list":
        _settings_list(s)

    elif args.settings_command == "get":
        if args.key not in cfg.DEFAULTS:
            console.print(f"[error]Unknown key: {args.key}[/error]")
            return
        value = cfg.display_value(args.key, s[args.key])
        console.print(f"  [bold]{args.key}[/bold] = [cyan]{value}[/cyan]")
        console.print(f"  [muted]{cfg.describe(args.key)}[/muted]")

    elif args.settings_command == "set":
        try:
            value = cfg.coerce_value(args.key, args.value)
            cfg.set_value(args.key, value)
            if args.key == "color_theme":
                refresh_console_theme()
            display = cfg.display_value(args.key, value)
            console.print(f"[success]✓ {args.key} = {display}[/success]")
        except ValueError as e:
            console.print(f"[error]{e}[/error]")

    elif args.settings_command == "reset":
        cfg.reset()
        console.print("[success]✓ All settings reset to defaults.[/success]")


def _settings_list(s: dict):
    table = make_table(
        "Settings",
        [("Key", "cyan"), ("Value", "bold white"), ("Description", "dim")],
        [],
    )
    for key, default in cfg.DEFAULTS.items():
        val = str(cfg.display_value(key, s.get(key, default)))
        table.add_row(key, val, cfg.describe(key))
    console.print(table)


def cmd_tools(args):


    if not hasattr(args, "tools_command") or not args.tools_command:
        console.print(Panel(
            "[bold]Available tools:[/bold]\n\n"
            "  [cyan]ping <host>[/cyan]              — TCP ping test\n"
            "  [cyan]dns-bench[/cyan]                — Benchmark DNS servers\n"
            "  [cyan]dns-flush[/cyan]                — Flush DNS cache\n"
            "  [cyan]speedtest[/cyan]                — Download speed test\n"
            "  [cyan]speedtest-history[/cyan]        — Show speedtest trend over time\n"
            "  [cyan]mtu [host][/cyan]               — Detect path MTU\n"
            "  [cyan]adapters[/cyan]                 — List network adapters\n"
            "  [cyan]traceroute <host>[/cyan]        — Traceroute\n"
            "  [cyan]subnet <ip/cidr>[/cyan]         — Calculate subnet details\n"
            "  [cyan]connections[/cyan]              — Live TCP/UDP connection table\n"
            "  [cyan]scan-ports <host>[/cyan]        — Scan common TCP ports\n"
            "  [cyan]discover[/cyan]                 — Discover devices on your LAN\n"
            "  [cyan]dns-inspect[/cyan]              — Check for DNS interference/poisoning\n"
            "  [cyan]latency-monitor [host][/cyan]   — Live ping graph with jitter/loss\n"
            "  [cyan]bandwidth[/cyan]                — Live per-interface throughput\n"
            "  [cyan]bandwidth-cap[/cyan]            — Set and monitor bandwidth limits\n"
            "  [cyan]traffic-log[/cyan]              — Query network traffic audit trail\n"
            "  [cyan]adblock[/cyan]                  — Manage ad/tracker blocklists\n"
            "  [cyan]qos[/cyan]                      — Quality of Service (QoS) traffic shaping\n"
            "  [cyan]scan-file <path>[/cyan]          — Scan one local file with Windows Defender
"
            "  [cyan]file-hash <path>[/cyan]          — Calculate a local SHA-256 fingerprint
"
            "  [cyan]cert-check <host[:port]>[/cyan] — TLS certificate check\n"
            "  [cyan]netfix[/cyan]                   — Targeted Blackout network recovery\n"
            "  [cyan]arp-flush[/cyan]                — Explicitly flush local ARP/neighbor cache\n",
            title="[bold]Network Toolkit[/bold]", border_style="cyan",
        ))
        return

    if args.tools_command == "ping":
        host = getattr(args, "host", "8.8.8.8")
        console.print(f"\n[info]Pinging {host} (4 times via TCP :80)...[/info]\n")
        times = net_tools.ping(host, 4)
        stats = net_tools.ping_stats(times)
        table = make_table(
            f"Ping — {host}",
            [("Packet", "dim"), ("Result", "")],
            [],
        )
        for i, t in enumerate(times, 1):
            table.add_row(f"#{i}", latency_color(t) if t else "[error]timeout[/error]")
        console.print(table)
        if stats["avg"] is not None:
            jitter_str = (f"  jitter=[bold]{stats['jitter']:.1f}ms[/bold]"
                          if stats["jitter"] is not None else "")
            console.print(
                f"\n  avg=[bold]{stats['avg']:.1f}ms[/bold]  "
                f"min={stats['min']:.1f}ms  max={stats['max']:.1f}ms"
                f"{jitter_str}  loss=[bold]{stats['loss_pct']:.0f}%[/bold]"
            )

    elif args.tools_command == "dns-bench":
        console.print("\n[info]Benchmarking DNS servers (3 queries each)...[/info]\n")
        with console.status("[bold]Testing...[/bold]", spinner="dots"):
            results = net_tools.benchmark_dns()
        table = make_table(
            "DNS Benchmark",
            [("Server", "cyan"), ("IP", "dim"), ("Avg Latency", "")],
            [],
        )
        for name, ip, ms in results:
            table.add_row(name, ip, latency_color(ms))
        console.print(table)
        if results:
            best = results[0]
            console.print(f"\n[success]Best DNS:[/success] {best[0]} — {best[1]}  ({best[2]:.0f}ms)")
            console.print(f"Set it: [bold]blackout tools dns-set {best[1]}[/bold]")

    elif args.tools_command == "dns-flush":
        console.print("[info]Flushing DNS cache...[/info]")
        if net_tools.flush_dns():
            console.print("[success]✓ DNS cache flushed.[/success]")
        else:
            console.print("[error]Failed — try running as administrator.[/error]")

    elif args.tools_command == "speedtest":
        console.print("\n[info]Running speed test via Cloudflare (download + upload)...[/info]\n")
        with console.status("[bold]Testing...[/bold]", spinner="dots"):
            result = net_tools.simple_speed_test()
        net_tools.record_speedtest_result(result)
        lat         = result["latency_ms"]
        mbps        = result["download_mbps"]
        upload_mbps = result.get("upload_mbps")
        up_str = f"[bold]{'%.2f' % upload_mbps} Mbps[/bold]" if upload_mbps is not None else "[dim]—[/dim]"
        console.print(Panel(
            f"  [muted]Latency:[/muted]   {latency_color(lat) if lat is not None else '[error]timeout[/error]'}\n"
            f"  [muted]Download:[/muted]  [bold]{'%.2f' % mbps if mbps is not None else '?'} Mbps[/bold]\n"
            f"  [muted]Upload:[/muted]    {up_str}\n"
            f"  [muted]Test:[/muted]      {result.get('test_size', '-')}",
            title="[bold]Speed Test — Cloudflare[/bold]",
            border_style="cyan",
        ))
        console.print("[muted]Saved to history — run [bold]blackout tools speedtest-history[/bold] to see the trend.[/muted]\n")

    elif args.tools_command == "speedtest-history":
        history = net_tools.get_speedtest_history(limit=30)
        if not history:
            console.print("[warning]No speedtest history yet. Run [bold]blackout tools speedtest[/bold] a few times first.[/warning]\n")
            return

        download_values = [entry.get("download_mbps") for entry in history]
        graph = _sparkline(download_values, width=min(30, len(download_values)), higher_is_better=True)

        valid = [v for v in download_values if v is not None]
        avg = sum(valid) / len(valid) if valid else 0
        best = max(valid) if valid else 0
        worst = min(valid) if valid else 0

        console.print()
        console.print(Panel(
            f"  [muted]Samples:[/muted]  {len(history)}\n"
            f"  [muted]Download trend:[/muted]  {graph}\n"
            f"  [muted]Average:[/muted]  {avg:.1f} Mbps    [muted]Best:[/muted]  {best:.1f} Mbps    [muted]Worst:[/muted]  {worst:.1f} Mbps",
            title="[bold]Speedtest History (last 30 runs)[/bold]",
            border_style="cyan",
        ))

        table = make_table(
            "Recent Runs",
            [("When", "dim"), ("Latency", ""), ("Download", "white"), ("Upload", "white")],
            [],
        )
        for entry in history[-10:]:
            when = time.strftime("%m-%d %H:%M", time.localtime(entry.get("ts", 0)))
            lat_disp = f"{entry['latency_ms']:.0f}ms" if entry.get("latency_ms") is not None else "-"
            dl_disp = f"{entry['download_mbps']:.1f} Mbps" if entry.get("download_mbps") is not None else "-"
            ul_disp = f"{entry['upload_mbps']:.1f} Mbps" if entry.get("upload_mbps") is not None else "-"
            table.add_row(when, lat_disp, dl_disp, ul_disp)
        console.print(table)
        console.print()

    elif args.tools_command == "mtu":
        host = getattr(args, "host", "8.8.8.8")
        console.print(f"[info]Detecting MTU to {host}...[/info]")
        with console.status("[bold]Probing...[/bold]"):
            mtu = net_tools.detect_mtu(host)
        if mtu:
            console.print(f"[success]Detected MTU: {mtu}[/success]")
            console.print("Optimal is usually 1500. If lower, try: [bold]blackout tools netfix[/bold]")
        else:
            console.print("[warning]MTU detection requires Windows and admin privileges.[/warning]")

    elif args.tools_command == "adapters":
        adapters = net_tools.list_adapters()
        table = make_table(
            "Network Adapters",
            [("Adapter", "cyan"), ("Status", ""), ("IPv4", "white"), ("IPv6", "dim")],
            [],
        )
        for a in adapters:
            if a.get("ipv4") or a.get("ipv6"):
                raw_status = a.get("status", "Unknown")
                if raw_status == "Connected":
                    status_markup = "[green]● Connected[/green]"
                elif raw_status == "Disconnected":
                    status_markup = "[dim]○ Disconnected[/dim]"
                else:
                    status_markup = f"[dim]{raw_status}[/dim]"
                table.add_row(a["name"], status_markup, a.get("ipv4", "-"), a.get("ipv6", "-"))
        console.print(table)

    elif args.tools_command == "traceroute":
        host = getattr(args, "host", "8.8.8.8")
        console.print(f"\n[info]Traceroute to {host}...[/info]\n")
        with console.status("[bold]Tracing...[/bold]"):
            hops = net_tools.traceroute(host)
        for hop, line in hops:
            console.print(f"  [dim]{hop:>2}[/dim]  {line}")
        console.print()

    elif args.tools_command == "connections":
        established_only = getattr(args, "established", False)
        with console.status("[bold]Reading connection table...[/bold]", spinner="dots"):
            conns = net_tools.get_active_connections(established_only=established_only)

        if not conns:
            console.print("[warning]No connections found (or permission denied — try running as administrator).[/warning]")
            return

        table = make_table(
            f"Active Connections  ({len(conns)})",
            [("Process", "cyan"), ("PID", "dim"), ("Proto", "yellow"),
             ("Local", "white"), ("Remote", "white"), ("State", "")],
            [],
        )
        for c in conns:
            local = f"{c['local_addr']}:{c['local_port']}"
            remote = f"{c['remote_addr']}:{c['remote_port']}" if c["remote_addr"] else "-"
            status = c["status"]
            if status == "ESTABLISHED":
                status_disp = "[success]ESTABLISHED[/success]"
            elif status == "LISTEN":
                status_disp = "[cyan]LISTEN[/cyan]"
            else:
                status_disp = f"[dim]{status}[/dim]"
            table.add_row(c["process"], str(c["pid"]) if c["pid"] else "-", c["protocol"], local, remote, status_disp)

        console.print()
        console.print(table)
        console.print("[muted]Tip: use [bold]blackout tools connections --established[/bold] to hide listening sockets.[/muted]")
        console.print()

    elif args.tools_command == "dns-inspect":
        with console.status("[bold]Comparing system DNS against a trusted resolver...[/bold]", spinner="dots"):
            report = net_tools.inspect_dns()

        servers = report["servers"]
        console.print()
        console.print(Panel(
            f"[muted]Configured DNS servers:[/muted] {', '.join(servers) if servers else '[dim]unknown[/dim]'}",
            title="[bold]System DNS[/bold]",
            border_style="cyan",
        ))

        if not report["trusted_resolver_reachable"]:
            console.print(
                "\n[warning]Could not reach the trusted DoH resolver (1.1.1.1) — DNS comparison is unavailable.[/warning]\n"
                "[muted]This can mean outbound HTTPS to 1.1.1.1 is blocked, or you have no internet access right now.[/muted]\n"
            )
            return

        table = make_table(
            "Resolution Comparison (system vs. trusted DoH)",
            [("Domain", "cyan"), ("System DNS", "white"), ("Trusted DoH", "white"), ("Status", "")],
            [],
        )
        suspect_count = 0
        for check in report["checks"]:
            if check["suspect"]:
                suspect_count += 1
                status = "[error]⚠ BLOCKED?[/error]"
            else:
                status = "[success]✓ OK[/success]"
            table.add_row(check["domain"], check["system_ip"], check["trusted_ip"], status)
        console.print(table)

        if suspect_count:
            console.print(
                f"\n[warning]{suspect_count} domain(s) resolved via the trusted resolver but NOT via your system "
                "DNS.[/warning] This can indicate DNS blocking or poisoning — it is a local heuristic signal, "
                "not proof of tampering.\n"
            )
        else:
            console.print("\n[success]No DNS interference detected against the test domain set.[/success]\n")

    elif args.tools_command == "discover":
        console.print("\n[info]Sweeping the local subnet — this can take a few seconds...[/info]\n")
        with Progress(
            SpinnerColumn(style="bold red"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40, style="red", complete_style="green"),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("Discovering LAN devices...", total=254)
            hosts = net_tools.discover_lan_hosts(progress_callback=lambda: progress.advance(task))

        if not hosts:
            console.print("[warning]Could not determine local subnet — check your network connection.[/warning]\n")
            return

        table = make_table(
            f"LAN Devices  ({len(hosts)} found)",
            [("IP Address", "cyan"), ("MAC Address", "dim"), ("Hostname", "white")],
            [],
        )
        for h in hosts:
            ip_disp = f"[bold]{h['ip']}[/bold] [success](you)[/success]" if h["is_self"] else h["ip"]
            table.add_row(ip_disp, h["mac"], h["hostname"])
        console.print(table)
        console.print("[muted]Devices with no OS-visible MAC entry may not respond to the probe ports used.[/muted]\n")

    elif args.tools_command == "scan-ports":
        host = getattr(args, "host", None)
        if not host:
            return
        port_range = getattr(args, "ports", None)
        target_ports = None
        if port_range:
            try:
                if "-" in port_range:
                    lo, hi = port_range.split("-", 1)
                    target_ports = list(range(int(lo), int(hi) + 1))
                else:
                    target_ports = [int(p.strip()) for p in port_range.split(",") if p.strip()]
            except ValueError:
                console.print(f"[error]Invalid port range: {port_range}[/error]")
                return

        total = len(target_ports) if target_ports else len(net_tools.COMMON_PORTS)
        console.print(f"\n[info]Scanning {host} — {total} port(s)...[/info]\n")

        with Progress(
            SpinnerColumn(style="bold red"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40, style="red", complete_style="green"),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(f"Scanning {host}...", total=total)
            results = net_tools.scan_ports(
                host,
                ports=target_ports,
                progress_callback=lambda: progress.advance(task),
            )

        if not results:
            console.print(f"[warning]No open ports found on {host} (or host unreachable).[/warning]\n")
            return

        table = make_table(
            f"Open Ports on {host}  ({len(results)} found)",
            [("Port", "cyan"), ("Service", "bold white"), ("Status", "")],
            [],
        )
        for r in results:
            table.add_row(str(r["port"]), r["service"], "[success]● OPEN[/success]")
        console.print(table)
        console.print()

    elif args.tools_command == "subnet":
        cidr = getattr(args, "cidr", None)
        if not cidr:
            return
        details = net_tools.calculate_subnet(cidr)
        if not details:
            console.print(f"[error]Invalid IP/CIDR format: {cidr}[/error]")
            return

        table = make_table(
            f"Subnet Calculator: {cidr}",
            [("Property", "cyan"), ("Value", "bold white")],
            [],
        )
        table.add_row("Network ID", details["network"])
        table.add_row("Broadcast IP", details["broadcast"])
        table.add_row("Subnet Mask", f"{details['netmask']} (/{details['cidr']})")
        table.add_row("Usable IPs", f"{details['first_ip']} - {details['last_ip']}")
        table.add_row("Total Hosts", str(details["total_hosts"]))
        table.add_row("Usable Hosts", str(details["usable_hosts"]))

        console.print()
        console.print(table)
        console.print()

    elif args.tools_command == "latency-monitor":
        host = getattr(args, "host", "8.8.8.8")
        interval = getattr(args, "interval", 1.0)
        history: list[float | None] = []
        console.print()
        try:
            with Live(_latency_monitor_panel(host, history), console=console, refresh_per_second=4) as live:
                while True:
                    history.append(net_tools.ping_once(host))
        MAX_HISTORY = 300  # ~5 minutes at 1Hz sampling
                    live.update(_latency_monitor_panel(host, history))
                    time.sleep(interval)
        except KeyboardInterrupt:
            console.print("\n[muted]Latency monitor stopped.[/muted]")

                    if len(history) > MAX_HISTORY:
                        history.pop(0)
    elif args.tools_command == "bandwidth":
        interval = getattr(args, "interval", 1.0)
        history: dict[str, list[float]] = {}
        prev = net_tools.get_interface_io_counters()
        console.print()
        try:
            with Live(_bandwidth_panel({}, history), console=console, refresh_per_second=4) as live:
                while True:
                    time.sleep(interval)
                    curr = net_tools.get_interface_io_counters()
                    rates = net_tools.compute_bandwidth_rates(prev, curr, interval)
                    prev = curr
                    _record_bandwidth_history(history, rates)
                    live.update(_bandwidth_panel(rates, history))
        except KeyboardInterrupt:
            console.print("\n[muted]Bandwidth monitor stopped.[/muted]")

    elif args.tools_command == "bandwidth-cap":
        from .tools.bandwidth_caps import (
            load_caps, set_cap, remove_cap, get_current_usage, get_cap, check_cap_exceeded,
            load_bandwidth_history, list_all_caps
        )

        subcmd = getattr(args, "bandwidth_cap_subcmd", "list")

        if subcmd == "set":
            interface = getattr(args, "interface", None)
            daily_mb = getattr(args, "daily_mb", None)
            monthly_mb = getattr(args, "monthly_mb", None)

            if not interface:
                console.print("[error]Error: interface required[/error]")
                return

            set_cap(interface, daily_mb, monthly_mb)
            console.print(f"[success]✓ Bandwidth cap set for {interface}[/success]")
            if daily_mb:
                console.print(f"  Daily limit: {daily_mb} MB")
            if monthly_mb:
                console.print(f"  Monthly limit: {monthly_mb} MB")

        elif subcmd == "list":
            caps = list_all_caps()
            if not caps:
                console.print("[muted]No bandwidth caps configured.[/muted]")
                return

            from rich.table import Table
            table = Table(title="Bandwidth Caps")
            table.add_column("Interface", style="cyan")
            table.add_column("Daily Limit", style="yellow")
            table.add_column("Monthly Limit", style="yellow")

            for iface, cap_data in caps.items():
                daily = cap_data.get("daily_mb", "—")
                monthly = cap_data.get("monthly_mb", "—")
                table.add_row(iface, str(daily) + " MB" if daily else "—", str(monthly) + " MB" if monthly else "—")

            console.print(table)

        elif subcmd == "stats":
            interface = getattr(args, "interface", None)
            if not interface:
                console.print("[error]Error: interface required[/error]")
                return

            daily_limit, monthly_limit = get_cap(interface)
            today_rx, today_tx, month_rx, month_tx = get_current_usage(interface)

            console.print(f"\n[bold cyan]Bandwidth Stats for {interface}[/bold cyan]")
            console.print(f"  Today:  {today_rx / 1024 / 1024:.1f} MB ↓ + {today_tx / 1024 / 1024:.1f} MB ↑ = {(today_rx + today_tx) / 1024 / 1024:.1f} MB total")
            console.print(f"  Month:  {month_rx / 1024 / 1024:.1f} MB ↓ + {month_tx / 1024 / 1024:.1f} MB ↑ = {(month_rx + month_tx) / 1024 / 1024:.1f} MB total")

            if daily_limit or monthly_limit:
                exceeded, pct, status = check_cap_exceeded(interface, daily_limit, monthly_limit)
                console.print(f"\n  Status: [{('red' if exceeded else 'yellow' if pct >= 50 else 'green')}]{status}[/]")
                console.print(f"  Usage:  {pct:.1f}%")

        elif subcmd == "remove":
            interface = getattr(args, "interface", None)
            if not interface:
                console.print("[error]Error: interface required[/error]")
                return

            remove_cap(interface)
            console.print(f"[success]✓ Bandwidth cap removed for {interface}[/success]")

    elif args.tools_command == "traffic-log":
        from .tools.traffic_log import (
            load_traffic_log, get_traffic_stats, get_traffic_by_hour, get_top_apps,
            prune_old_logs, clear_traffic_log, get_log_entry_count, get_log_size_mb
        )

        subcmd = getattr(args, "traffic_log_subcmd", "list")
        app_filter = getattr(args, "app", None)
        protocol_filter = getattr(args, "protocol", None)
        hours_filter = getattr(args, "hours", 24)

        if subcmd == "list":
            limit = getattr(args, "limit", 50)
            since_hours = getattr(args, "hours", 24)
            since_ts = (datetime.now(timezone.utc) - timedelta(hours=since_hours)).timestamp() if since_hours else None
            entries = load_traffic_log(since_ts=since_ts, limit=limit)

            if not entries:
                console.print(f"[muted]No traffic entries in last {since_hours} hours.[/muted]")
                return

            table = Table(title=f"Network Traffic (last {since_hours}h, showing {len(entries)})")
            table.add_column("Time", style="dim")
            table.add_column("Process", style="cyan")
            table.add_column("Protocol", style="yellow")
            table.add_column("Remote", style="white")
            table.add_column("↓ RX", style="blue")
            table.add_column("↑ TX", style="green")
            table.add_column("Status", style="white")

            for entry in entries[:20]:
                ts = datetime.fromtimestamp(entry['ts'], tz=timezone.utc).strftime("%H:%M:%S")
                proc = entry.get('process', '?')[:20]
                prot = entry.get('protocol', '?')
                remote = entry.get('remote', '?')[:20]
                rx_mb = entry.get('bytes_recv', 0) / 1024 / 1024
                tx_mb = entry.get('bytes_sent', 0) / 1024 / 1024
                status = entry.get('status', '?')
                rx_str = f"{rx_mb:.2f} MB" if rx_mb > 0 else "—"
                tx_str = f"{tx_mb:.2f} MB" if tx_mb > 0 else "—"
                table.add_row(ts, proc, prot, remote, rx_str, tx_str, status)

            console.print(table)

        elif subcmd == "stats":
            stats = get_traffic_stats(app=app_filter, protocol=protocol_filter)

            console.print(f"\n[bold cyan]Traffic Statistics[/bold cyan]")
            if app_filter:
                console.print(f"[muted]Filter: app={app_filter}[/muted]")
            if protocol_filter:
                console.print(f"[muted]Filter: protocol={protocol_filter}[/muted]")

            console.print(f"\n[bold]Overall[/bold]")
            console.print(f"  Total connections: {stats['total_connections']}")
            console.print(f"  Total downloaded: {stats['total_recv_bytes'] / 1024 / 1024:.1f} MB")
            console.print(f"  Total uploaded: {stats['total_sent_bytes'] / 1024 / 1024:.1f} MB")

            if stats['by_app']:
                console.print(f"\n[bold]By App[/bold]")
                for app_name, app_stats in sorted(stats['by_app'].items(), key=lambda x: x[1]['recv_bytes'] + x[1]['sent_bytes'], reverse=True)[:10]:
                    rx = app_stats['recv_bytes'] / 1024 / 1024
                    tx = app_stats['sent_bytes'] / 1024 / 1024
                    conn = app_stats['conn_count']
                    console.print(f"  {app_name[:30]:30} — ↓{rx:7.1f} MB  ↑{tx:7.1f} MB  ({conn} conns)")

            if stats['by_protocol']:
                console.print(f"\n[bold]By Protocol[/bold]")
                for prot, prot_stats in sorted(stats['by_protocol'].items(), key=lambda x: x[1]['recv_bytes'] + x[1]['sent_bytes'], reverse=True):
                    rx = prot_stats['recv_bytes'] / 1024 / 1024
                    tx = prot_stats['sent_bytes'] / 1024 / 1024
                    conn = prot_stats['conn_count']
                    console.print(f"  {prot:10} — ↓{rx:7.1f} MB  ↑{tx:7.1f} MB  ({conn} conns)")

        elif subcmd == "hourly":
            since_hours = getattr(args, "hours", 24)
            by_hour = get_traffic_by_hour(since_hours=since_hours)

            console.print(f"\n[bold cyan]Traffic by Hour (last {since_hours}h)[/bold cyan]")
            table = Table()
            table.add_column("Hour", style="dim")
            table.add_column("↓ Downloaded", style="blue")
            table.add_column("↑ Uploaded", style="green")
            table.add_column("Conns", style="yellow")

            for hour_key in sorted(by_hour.keys()):
                data = by_hour[hour_key]
                rx_mb = data['recv_bytes'] / 1024 / 1024
                tx_mb = data['sent_bytes'] / 1024 / 1024
                table.add_row(hour_key, f"{rx_mb:.1f} MB", f"{tx_mb:.1f} MB", str(data['conn_count']))

            console.print(table)

        elif subcmd == "clear":
            if confirm("Clear all traffic logs? This cannot be undone."):
                clear_traffic_log()
                console.print("[success]✓ Traffic log cleared.[/success]")
            else:
                console.print("[muted]Cancelled.[/muted]")

        elif subcmd == "prune":
            days = getattr(args, "older_than", 30)
            removed = prune_old_logs(retention_days=days)
            console.print(f"[success]✓ Removed {removed} old entries (older than {days} days).[/success]")

        elif subcmd == "info":
            entry_count = get_log_entry_count()
            size_mb = get_log_size_mb()
            console.print(f"\n[bold cyan]Traffic Log Info[/bold cyan]")
            console.print(f"  Entries: {entry_count:,}")
            console.print(f"  Size: {size_mb:.1f} MB")

    elif args.tools_command == "adblock":
        from .tools.adblock import (
            add_blocklist_source, remove_blocklist_source, get_blocklist_sources,
            download_blocklist, update_all_blocklists, add_custom_block, remove_custom_block,
            add_whitelist, remove_whitelist, check_domain_blocked, get_adblock_stats,
            get_dns_query_log, get_adblock_status
        )

        subcmd = getattr(args, "adblock_subcmd", "status")

        if subcmd == "sources":
            sources = get_blocklist_sources()
            if not sources:
                console.print("[muted]No blocklist sources configured.[/muted]")
                return

            table = Table(title="Ad Blocklists")
            table.add_column("Name", style="cyan")
            table.add_column("Rules", style="yellow")
            table.add_column("Last Updated", style="dim")
            table.add_column("Status", style="white")

            for source in sources:
                last_update = source.get('last_update', 'Never')
                if last_update:
                    try:
                        dt = datetime.fromisoformat(last_update)
                        last_update = dt.strftime("%Y-%m-%d %H:%M")
                    except Exception:
                        pass
                rule_count = source.get('rule_count', 0)
                status = "[green]enabled[/green]" if source.get('enabled', True) else "[dim]disabled[/dim]"
                table.add_row(source['name'], str(rule_count), last_update, status)

            console.print(table)

        elif subcmd == "sources-add":
            name = getattr(args, "name", None)
            url = getattr(args, "url", None)

            if not name or not url:
                console.print("[error]Error: name and url required[/error]")
                return

            if add_blocklist_source(name, url):
                console.print(f"[success]✓ Added blocklist: {name}[/success]")
            else:
                console.print(f"[warning]Blocklist '{name}' already exists[/warning]")

        elif subcmd == "sources-remove":
            name = getattr(args, "name", None)
            if not name:
                console.print("[error]Error: name required[/error]")
                return

            if remove_blocklist_source(name):
                console.print(f"[success]✓ Removed blocklist: {name}[/success]")
            else:
                console.print(f"[warning]Blocklist '{name}' not found[/warning]")

        elif subcmd == "custom-add":
            domain = getattr(args, "domain", None)
            if not domain:
                console.print("[error]Error: domain required[/error]")
                return

            if add_custom_block(domain):
                console.print(f"[success]✓ Added custom block: {domain}[/success]")
            else:
                console.print(f"[warning]Domain '{domain}' already blocked[/warning]")

        elif subcmd == "custom-remove":
            domain = getattr(args, "domain", None)
            if not domain:
                console.print("[error]Error: domain required[/error]")
                return

            if remove_custom_block(domain):
                console.print(f"[success]✓ Removed custom block: {domain}[/success]")
            else:
                console.print(f"[warning]Domain '{domain}' not found[/warning]")

        elif subcmd == "whitelist-add":
            domain = getattr(args, "domain", None)
            if not domain:
                console.print("[error]Error: domain required[/error]")
                return

            if add_whitelist(domain):
                console.print(f"[success]✓ Whitelisted: {domain}[/success]")
            else:
                console.print(f"[warning]Domain '{domain}' already whitelisted[/warning]")

        elif subcmd == "whitelist-remove":
            domain = getattr(args, "domain", None)
            if not domain:
                console.print("[error]Error: domain required[/error]")
                return

            if remove_whitelist(domain):
                console.print(f"[success]✓ Removed from whitelist: {domain}[/success]")
            else:
                console.print(f"[warning]Domain '{domain}' not whitelisted[/warning]")

        elif subcmd == "status":
            status = get_adblock_status()
            console.print(f"\n[bold cyan]Ad Blocker Status[/bold cyan]")
            console.print(f"  Sources: {status['enabled_sources']}/{status['total_sources']} enabled")
            console.print(f"  Total rules: {status['total_rules']:,}")
            console.print(f"  Custom blocks: {status['custom_blocks']}")
            console.print(f"  Whitelisted: {status['whitelisted']}")
            console.print(f"  Blocked today: {status['queries_blocked_today']}")

        elif subcmd == "stats":
            stats = get_adblock_stats()
            console.print(f"\n[bold cyan]Ad Blocking Statistics[/bold cyan]")
            console.print(f"  Total rules: {stats['total_rules']:,}")
            console.print(f"  Blocked today: {stats['queries_blocked_today']}")
            console.print(f"  Sources: {stats['sources_enabled']}/{stats['sources_total']} enabled")

            if stats['top_blocked_domains']:
                console.print(f"\n[bold]Top Blocked Domains[/bold]")
                for item in stats['top_blocked_domains']:
                    console.print(f"  {item['domain']}: {item['count']} queries")

        elif subcmd == "log":
            blocked_only = getattr(args, "blocked_only", False)
            hours = getattr(args, "hours", 24)
            limit = getattr(args, "limit", 100)

            entries = get_dns_query_log(blocked_only=blocked_only, hours=hours, limit=limit)

            if not entries:
                console.print(f"[muted]No DNS queries in last {hours} hours.[/muted]")
                return

            title = "Blocked DNS Queries" if blocked_only else "DNS Query Log"
            table = Table(title=title)
            table.add_column("Time", style="dim")
            table.add_column("Domain", style="white")
            table.add_column("Status", style="")

            for entry in entries[:50]:
                ts = datetime.fromtimestamp(entry['ts'], tz=timezone.utc).strftime("%H:%M:%S")
                domain = entry.get('domain', '?')[:50]
                status = "[red]BLOCKED[/red]" if entry.get('blocked') else "[green]allowed[/green]"
                table.add_row(ts, domain, status)

            console.print(table)

        elif subcmd == "update":
            console.print("[info]Updating blocklists...[/info]")
            with console.status("[bold]Downloading...[/bold]", spinner="dots"):
                results = update_all_blocklists()

            console.print()
            for name, (success, rule_count, error) in results.items():
                if success:
                    console.print(f"[success]✓ {name}[/success] — {rule_count:,} rules")
                else:
                    console.print(f"[error]✗ {name}[/error] — {error}")

    elif args.tools_command == "qos":
        from .tools.qos import (
            load_qos_rules, add_rule, remove_rule, enable_rule, disable_rule,
            list_rules, get_qos_stats, set_enforcement_mode, get_enforcement_mode,
            compile_qos_rules_for_shaper, get_violations
        )
        from rich.table import Table

        subcmd = getattr(args, "qos_subcmd", "rules")

        if subcmd == "rules":
            show_cmd = getattr(args, "qos_show_cmd", "list")

            if show_cmd == "list":
                rules = list_rules()
                if not rules:
                    console.print("[muted]No QoS rules configured.[/muted]")
                    return

                table = Table(title="QoS Rules")
                table.add_column("ID", style="cyan")
                table.add_column("Name", style="white")
                table.add_column("Type", style="yellow")
                table.add_column("Target", style="green")
                table.add_column("Priority", style="magenta")
                table.add_column("Rate (kbps)", style="blue")
                table.add_column("Status", style="")

                for rule in rules:
                    enabled = "[green]●[/green]" if rule.get("enabled", True) else "[dim]○[/dim]"
                    rate = f"{rule.get('rate_limit_kbps', 0)}" if rule.get("rate_limit_kbps", 0) > 0 else "unlimited"
                    table.add_row(
                        rule["id"][:8],
                        rule["name"],
                        rule["type"],
                        rule["target"],
                        str(rule.get("priority", 50)),
                        rate,
                        enabled
                    )

                console.print(table)

            elif show_cmd == "add":
                name = getattr(args, "name", None)
                rule_type = getattr(args, "rule_type", None)
                target = getattr(args, "target", None)
                priority = getattr(args, "priority", 50)
                rate_limit = getattr(args, "rate_limit", 0)

                if not all([rule_type, target]):
                    console.print("[error]Error: type and target required[/error]")
                    return

                # Auto-generate name if not provided
                if not name:
                    name = f"{rule_type}_{target.replace('.', '_').replace(':', '_')}"[:64]

                rule_id = add_rule(name, rule_type, target, priority, rate_limit)
                console.print(f"[success]✓ Created rule: {rule_id}[/success]")

            elif show_cmd == "remove":
                rule_id = getattr(args, "rule_id", None)
                if not rule_id:
                    console.print("[error]Error: rule_id required[/error]")
                    return

                if remove_rule(rule_id):
                    console.print(f"[success]✓ Removed rule: {rule_id}[/success]")
                else:
                    console.print(f"[warning]Rule not found: {rule_id}[/warning]")

            elif show_cmd == "enable":
                rule_id = getattr(args, "rule_id", None)
                if not rule_id:
                    console.print("[error]Error: rule_id required[/error]")
                    return

                if enable_rule(rule_id):
                    console.print(f"[success]✓ Enabled rule: {rule_id}[/success]")
                else:
                    console.print(f"[warning]Rule not found: {rule_id}[/warning]")

            elif show_cmd == "disable":
                rule_id = getattr(args, "rule_id", None)
                if not rule_id:
                    console.print("[error]Error: rule_id required[/error]")
                    return

                if disable_rule(rule_id):
                    console.print(f"[success]✓ Disabled rule: {rule_id}[/success]")
                else:
                    console.print(f"[warning]Rule not found: {rule_id}[/warning]")

        elif subcmd == "stats":
            rule_id = getattr(args, "rule_id", None)

            stats = get_qos_stats(rule_id)

            if rule_id:
                console.print(f"\n[bold cyan]QoS Rule Stats: {stats.get('name')}[/bold cyan]")
                console.print(f"  Type: {stats.get('type')}")
                console.print(f"  Priority: {stats.get('priority')}/100")
                console.print(f"  Rate Limit: {stats.get('rate_limit_kbps', 0)} kbps")
                console.print(f"  Status: {'[green]enabled[/green]' if stats.get('enabled') else '[dim]disabled[/dim]'}")
                console.print(f"  Current RX: {stats.get('current_rx_kbps', 0):.1f} kbps")
                console.print(f"  Current TX: {stats.get('current_tx_kbps', 0):.1f} kbps")
                console.print(f"  Over limit: {'[warning]Yes[/warning]' if stats.get('over_limit') else '[green]No[/green]'}")
            else:
                console.print(f"\n[bold cyan]QoS Statistics[/bold cyan]")
                console.print(f"  Total rules: {stats.get('total_rules')}")
                console.print(f"  Enabled: {stats.get('enabled_rules')}")
                console.print(f"  Mode: {stats.get('enforcement_mode').upper()}")

                per_rule = stats.get('per_rule_stats', [])
                if per_rule:
                    table = Table(title="Per-Rule Stats")
                    table.add_column("Rule", style="cyan")
                    table.add_column("Priority", style="magenta")
                    table.add_column("RX (kbps)", style="blue")
                    table.add_column("TX (kbps)", style="blue")
                    table.add_column("Over Limit", style="")

                    for item in per_rule:
                        over = "[warning]●[/warning]" if item.get('over_limit') else "[green]–[/green]"
                        table.add_row(
                            item['name'],
                            str(item['priority']),
                            f"{item.get('rx_kbps', 0):.1f}",
                            f"{item.get('tx_kbps', 0):.1f}",
                            over
                        )

                    console.print(table)

        elif subcmd == "mode":
            new_mode = getattr(args, "mode", None)

            if not new_mode:
                current = get_enforcement_mode()
                console.print(f"\n[bold cyan]QoS Enforcement Mode[/bold cyan]")
                console.print(f"  Current: [bold]{current.upper()}[/bold]")
                console.print(f"  Options: off, monitor, enforce")
                return

            if set_enforcement_mode(new_mode):
                console.print(f"[success]✓ QoS mode set to: {new_mode.upper()}[/success]")
            else:
                console.print(f"[error]Invalid mode: {new_mode}[/error]")

        elif subcmd == "violations":
            hours = getattr(args, "hours", 24)
            limit = getattr(args, "limit", 50)

            since_ts = time.time() - (hours * 3600)
            violations = get_violations(since_ts=since_ts, limit=limit)

            if not violations:
                console.print(f"[muted]No violations in last {hours} hours.[/muted]")
                return

            table = Table(title="QoS Violations")
            table.add_column("Time", style="dim")
            table.add_column("Rule", style="cyan")
            table.add_column("Type", style="yellow")
            table.add_column("Details", style="white")

            for v in violations[:limit]:
                ts = datetime.fromtimestamp(v['ts'], tz=timezone.utc).strftime("%H:%M:%S")
                table.add_row(
                    ts,
                    v.get('rule_id', '?')[:8],
                    v.get('violation_type'),
                    v.get('details', '')[: 60]
                )

            console.print(table)

    elif args.tools_command == "capture":
        from .proxy_manager import is_admin

        iface = getattr(args, "iface", None)
        count = getattr(args, "count", 0) or 0
        bpf_filter = getattr(args, "filter", None)
        host_filter = getattr(args, "host", None)
        if host_filter:
            bpf_filter = f"host {host_filter}" if not bpf_filter else f"({bpf_filter}) and host {host_filter}"

        if not is_admin():
            console.print(
                "[warning]Not running elevated — packet capture usually requires Administrator/root "
                "privileges. Continuing anyway; it may fail below.[/warning]\n"
            )

        max_packets = cfg.get("capture_max_packets", 2000)
        packets: deque = deque(maxlen=max_packets)
        stop_event = threading.Event()
        capture_error: list[Exception] = []

        def _on_packet(pkt: dict):
            packets.append(pkt)

        def _run_capture():
            try:
                net_tools.capture_packets(
                    iface=iface,
                    bpf_filter=bpf_filter,
                    count=count,
                    stop_event=stop_event,
                    on_packet=_on_packet,
                )
            except Exception as exc:
                capture_error.append(exc)
            finally:
                stop_event.set()

        console.print()
        thread = threading.Thread(target=_run_capture, daemon=True)
        thread.start()
        try:
            with Live(_capture_panel(packets, {}, iface), console=console, refresh_per_second=4) as live:
                while not stop_event.is_set():
                    stats = net_tools.summarize_capture_packets(list(packets))
                    live.update(_capture_panel(packets, stats, iface))
                    time.sleep(0.25)
                    if count and len(packets) >= count:
                        break
        except KeyboardInterrupt:
            stop_event.set()
        thread.join(timeout=2.0)

        if capture_error:
            exc = capture_error[0]
            console.print(f"\n[error]Packet capture unavailable: {exc}[/error]")
            console.print(
                "[muted]Install scapy (`pip install scapy`) and, on Windows, Npcap from "
                "https://npcap.com (check \"WinPcap API-compatible Mode\" during install). "
                "Run `blackout doctor` to check prerequisites.[/muted]\n"
            )
            return

        console.print("\n[muted]Capture stopped.[/muted]\n")
        summary = net_tools.summarize_capture_packets(list(packets))
        console.print(_capture_summary_table(summary))
        console.print()

    elif args.tools_command == "dns-set":
        presets = {
            # Global public DNS
            "cloudflare":  "1.1.1.1",
            "cloudflare2": "1.0.0.1",
            "google":      "8.8.8.8",
            "google2":     "8.8.4.4",
            "quad9":       "9.9.9.9",
            "opendns":     "208.67.222.222",
            "adguard":     "94.140.14.14",
            # Iranian bypass/filtered DNS
            "shecan":      "185.51.200.2",
            "shecan2":     "178.22.122.100",
            "electro":     "78.157.42.100",
            "electro2":    "78.157.42.101",
            "403":         "10.202.10.202",
            "begzar":      "185.55.226.26",
            # Chinese domestic DNS (trusted inside GFW)
            "alibaba":     "223.5.5.5",
            "tencent":     "119.29.29.29",
            "114dns":      "114.114.114.114",
        }
        dns_ip = presets.get(args.server.lower(), args.server)
        console.print(f"[info]Setting DNS to {dns_ip}...[/info]")
        ok = net_tools.set_dns(dns_ip)
        if ok:
            console.print(f"[success]✓ DNS set to {dns_ip}[/success]")
            console.print("[muted]Run 'blackout tools dns-flush' to apply immediately.[/muted]")
            # Country-aware tip
            dns_profile = _get_active_profile()
            if dns_profile:
                rec_dns = dns_profile.bypass_dns[0][1] if dns_profile.bypass_dns else None
                if rec_dns and dns_ip != rec_dns:
                    console.print(
                        f"  [dim]Tip for {dns_profile.name}: "
                        f"recommended DNS is {dns_profile.bypass_dns[0][0]} "
                        f"({rec_dns})[/dim]"
                    )
        else:
            console.print("[error]Failed — run as administrator.[/error]")

    elif args.tools_command == "scan-file":
        from .tools.file_scanner import scan_file

        result = scan_file(getattr(args, "path", ""))
        status = result["status"]
        target = result["target"] or "the supplied path"
        detail = result.get("detail")
        if status == "clean":
            console.print(f"[success]✓ No threats reported for {target}.[/success]")
        elif status == "detected":
            console.print(f"[warning]⚠ Windows Defender reported a threat in {target}.[/warning]")
        elif status == "indeterminate":
            console.print(f"[warning]Scan result for {target} is indeterminate.[/warning]")
        else:
            console.print(f"[error]File scan could not complete for {target}: {detail}[/error]")
        if detail and status in {"detected", "indeterminate", "scanner-error"}:
            console.print(f"[muted]{detail}[/muted]")

    elif args.tools_command == "file-hash":
        from .tools.file_fingerprint import fingerprint_file

        result = fingerprint_file(getattr(args, "path", ""))
        status = result["status"]
        target = result["target"] or "the supplied path"
        if status == "fingerprinted":
            console.print(f"[success]SHA-256 for {target}:[/success]")
            console.print(f"  [bold]{result['sha256']}[/bold]")
            console.print(f"  [muted]{result['bytes']:,} bytes[/muted]")
        elif status == "changed-during-read":
            console.print(
                f"[warning]File changed while it was being read; no stable SHA-256 was produced for {target}.[/warning]"
            )
            console.print(f"[muted]{result['detail']}[/muted]")
        else:
            detail = result.get("detail") or "Unknown file hashing error."
            console.print(f"[error]File hash could not complete for {target}: {detail}[/error]")

    elif args.tools_command == "cert-check":
        from . import cert_bypass as cb
        from . import security as sec

        raw = args.host
        if ":" in raw:
            parts = raw.rsplit(":", 1)
            try:
                host, port = parts[0], int(parts[1])
            except ValueError:
                console.print("[error]Invalid format — use: cert-check host[:port][/error]")
                return
        else:
            host, port = raw, 443

        # Handle --allow flag (mark as manually allowed for LEGEND mode)
        if getattr(args, "allow", False):
            cb.allow_host(host, port)
            console.print(
                f"[success]✓ {host}:{port} marked as manually allowed.[/success]  "
                "LEGEND mode will now permit this connection."
            )

        with console.status(f"[bold]Probing {host}:{port}...[/bold]", spinner="dots"):
            record = cb.check_host_cert(host, port, timeout=8.0)

        # ── Status line ───────────────────────────────────────────
        if record.cert_ok:
            status_line = "[success]✓ VALID[/success]"
        elif record.error and "Connection" in record.error:
            status_line = f"[warning]⚠ UNREACHABLE[/warning]  ({record.error})"
        else:
            status_line = f"[error]✗ INVALID[/error]  ({record.error})"

        # ── Expiry display ────────────────────────────────────────
        if record.expires:
            if record.days_left < 0:
                expiry_str = f"{record.expires}  [error](EXPIRED {abs(record.days_left)} days ago)[/error]"
            elif record.days_left < 14:
                expiry_str = f"{record.expires}  [warning]({record.days_left} days left — expiring soon!)[/warning]"
            else:
                expiry_str = f"{record.expires}  [dim]({record.days_left} days left)[/dim]"
        else:
            expiry_str = "[dim]Unknown[/dim]"

        self_signed_str = "[error]YES[/error]" if record.self_signed else "[success]No[/success]"

        # ── Mode policy table ────────────────────────────────────
        current_mode = sec.get_current_mode()
        policy_lines = []
        for m in ("speed", "private", "legend"):
            allow, warn = cb.should_allow_insecure(host, port, m)
            icon   = "✓" if allow else "✗"
            colour = "success" if allow else "error"
            marker = "  ◄ active" if m == current_mode else ""
            policy_lines.append(
                f"  [{colour}]{icon}[/{colour}]  {m.upper():<8}  allowInsecure = {'True' if allow else 'False'}{marker}"
            )

        console.print(Panel(
            f"  [muted]Host:[/muted]        [bold]{host}:{port}[/bold]\n"
            f"  [muted]Status:[/muted]      {status_line}\n"
            f"  [muted]Subject:[/muted]     [dim]{record.subject or 'N/A'}[/dim]\n"
            f"  [muted]Issuer:[/muted]      [dim]{record.issuer or 'N/A'}[/dim]\n"
            f"  [muted]Expires:[/muted]     {expiry_str}\n"
            f"  [muted]Self-signed:[/muted] {self_signed_str}\n\n"
            "[bold]Mode Policy (allowInsecure):[/bold]\n" +
            "\n".join(policy_lines) +
            (f"\n\n[dim]To allow in LEGEND mode: [bold]blackout tools cert-check {host} --allow[/bold][/dim]"
             if not record.cert_ok and not record.manually_allowed else ""),
            title="[bold]TLS Certificate[/bold]",
            border_style="cyan" if record.cert_ok else "yellow",
            width=64,
        ))

    elif args.tools_command == "hotspot":
        console.print("[info]Toggling Windows Mobile Hotspot...[/info]")
        result = net_tools.toggle_hotspot()
        console.print(result)

    elif args.tools_command == "share-vpn":
        console.print(Panel(
            "[bold]VPN Connection Sharing[/bold]\n\n"
            "This enables Windows Internet Connection Sharing (ICS)\n"
            "so other devices on your hotspot get the VPN too.\n\n"
            "[dim]Requires: admin rights + hotspot active[/dim]",
            border_style="yellow",
        ))
        result = net_tools.enable_ics()
        console.print(result)

    elif args.tools_command == "arp-flush":
        console.print("[yellow]Flushing the local ARP/neighbor cache may briefly interrupt LAN discovery...[/yellow]")
        ok, detail = net_tools.flush_arp_cache()
        if ok:
            console.print(f"[success]✓ {detail}[/success]")
        else:
            console.print(f"[error]✗ {detail}[/error]")

    elif args.tools_command == "netfix":
        preview = getattr(args, "preview", False)
        plan = net_tools.plan_network_recovery()
        console.print(_recovery_table(plan, preview=True))
        if preview:
            console.print("[muted]Preview only: no system state or audit log was changed.[/muted]")
            return
        console.print(Panel(
            "[bold yellow]Running targeted crash recovery. Admin rights may be requested.[/bold yellow]\n"
            "[dim]Repairs only Blackout-owned routes, loopback DNS, and unhealthy BlackoutKit-TUN state.[/dim]",
            border_style="yellow",
        ))
        for step in net_tools.run_network_recovery(audit_source="tools"):
            status = "[success]✓ Done[/success]" if step["ok"] else "[error]✗ Failed[/error]"
            console.print(f"  {status}  {step['name']} [dim]— {step['detail']}[/dim]")
        console.print("\n[success]Done. Restart may be needed for full effect.[/success]")



def cmd_mode(args):
    """Set or display the security mode (speed / private / legend)."""
    mode_name = getattr(args, "mode_name", None)

    if not mode_name:
        # Just display current mode and all options
        current = sec.get_current_mode()
        table = make_table(
            "Security Modes",
            [("Mode", "cyan"), ("Active", ""), ("Description", "dim")],
            [],
        )
        for name, info in sec.MODES.items():
            active = "[success]● YES[/success]" if name == current else "[muted]  —[/muted]"
            table.add_row(name.upper(), active, info["description"])
        console.print()
        console.print(table)
        console.print(
            f"\n[muted]Current mode: [bold]{current.upper()}[/bold]  "
            f"Change: [bold]blackout mode speed|private|legend[/bold][/muted]\n"
        )
        return

    try:
        sec.apply_mode(mode_name)
        console.print(f"\n[success]✓ Security mode set to:[/success] [bold]{mode_name.upper()}[/bold]")
        console.print(f"  [muted]{sec.mode_description(mode_name)}[/muted]")

        # Auto-enable kill switch in LEGEND mode
        if mode_name == "legend":
            s = cfg.load()
            if not s.get("kill_switch", False):
                console.print(
                    "\n[yellow]Tip:[/yellow] LEGEND mode works best with the kill switch enabled.\n"
                    "Run: [bold]blackout killswitch on[/bold]"
                )
    except ValueError as e:
        console.print(f"[error]{e}[/error]")
    console.print()


def cmd_killswitch(args):
    """Manage the verified Linux endpoint-scoped kill switch."""
    action = getattr(args, "action", None)

    if not action:
        s = cfg.load()
        enabled = s.get("kill_switch", False)
        status = "[success]● ENABLED[/success]" if enabled else "[muted]○ Disabled[/muted]"
        console.print(Panel(
            f"Kill Switch: {status}\n\n"
            "[dim]Available only on Linux with a validated upstream endpoint allowlist.[/dim]\n"
            "[dim]Windows legacy rules are removed because Windows Firewall cannot safely combine its block and per-process allow rules.[/dim]\n\n"
            "[muted]Commands: [bold]blackout killswitch on[/bold]  /  [bold]blackout killswitch off[/bold][/muted]",
            title="[bold]Kill Switch[/bold]", border_style="red",
        ))
        return

    if action == "on":
        if not sys.platform.startswith("linux"):
            console.print(
                "[error]Kill switch is unavailable on Windows: legacy rules were removed because "
                "Windows Firewall block rules override per-process allow rules.[/error]"
            )
            return
        console.print("[info]Enabling kill switch (nftables/iptables)...[/info]")
        ok = sec.enable_kill_switch()
        if ok:
            cfg.set_value("kill_switch", True)
            console.print("[success]✓ Kill switch ENABLED.[/success]  All non-allowlisted traffic is blocked.")
        else:
            console.print("[error]Failed — requires sudo and a validated upstream endpoint allowlist.[/error]")

    elif action == "off":
        console.print("[info]Disabling kill switch...[/info]")
        ok = sec.disable_kill_switch()
        if ok:
            cfg.set_value("kill_switch", False)
            console.print("[success]✓ Kill switch DISABLED.[/success]  Normal routing restored.")
        else:
            console.print("[error]Failed — try running as administrator.[/error]")

    elif action == "test":
        console.print("[info]Testing kill switch effectiveness...[/info]\n")
        passed, details = sec.test_kill_switch()
        if passed:
            console.print(Panel(
                f"[success]✓ KILL SWITCH WORKS![/success]\n\n{details}",
                title="[bold green]Kill Switch Test Passed[/bold green]",
                border_style="green",
            ))
        else:
            console.print(Panel(
                f"[error]✗ KILL SWITCH TEST FAILED![/error]\n\n{details}",
                title="[bold red]Kill Switch Test Failed[/bold red]",
                border_style="red",
            ))


def cmd_panic(args):
    """Instantly kills all connections, flushes DNS, clears proxies, and resets killswitch."""
    console.print("[bold red]🚨 PANIC BUTTON ACTIVATED 🚨[/bold red]")
    console.print("[muted]Executing emergency disconnect and trace flush...[/muted]\n")
    
    # 1. Stop daemon
    console.print("[dim]→ Stopping daemon & all engines...[/dim]")
    from . import daemon
    daemon.stop()
    
    # 2. Clear System Proxy
    console.print("[dim]→ Clearing Windows system proxy...[/dim]")
    from .proxy_manager import clear_system_proxy
    clear_system_proxy()
    
    # 3. Disable Kill Switch
    console.print("[dim]→ Disabling kill switch firewall rules...[/dim]")
    from . import security as sec
    sec.disable_kill_switch()
    cfg.set_value("kill_switch", False)
    
    # 4. Flush DNS
    console.print("[dim]→ Flushing DNS cache...[/dim]")
    from .tools import flush_dns
    flush_dns()
    
    console.print("\n[bold green]✓ SYSTEM SECURED. YOU ARE OFFLINE.[/bold green]")


def cmd_shield(args):
    """Apply DNS blocking and Linux-only firewall protection when available."""
    console.print("[bold cyan]🛡️  SHIELD MODE ACTIVATED[/bold cyan]")

    if sys.platform.startswith("linux"):
        console.print("[dim]→ Enabling endpoint-scoped Linux kill switch...[/dim]")
        ok = sec.enable_kill_switch()
        if ok:
            cfg.set_value("kill_switch", True)
            console.print("[success]✓ Linux kill switch enabled.[/success]")
        else:
            console.print("[warning]Linux kill switch was not enabled; it requires sudo and a validated upstream endpoint.[/warning]")
    else:
        console.print("[dim]→ Kill switch unavailable on Windows; legacy firewall rules remain removed.[/dim]")

    # Set DNS to AdGuard/Mullvad
    console.print("[dim]→ Setting system DNS to Ad-blocking servers (AdGuard)...[/dim]")
    from .tools import set_dns
    if set_dns("94.140.14.14"):
        console.print("[success]✓ Tracker & Ad Blocker enabled at network level.[/success]")
    else:
        console.print("[warning]⚠ Could not auto-set DNS. Try running as admin.[/warning]")
    
def cmd_neighbor(args):
    """Neighbor internet — share or connect via a nearby Blackout Kit device."""
    from .engines.neighbor import NeighborConnectEngine, NeighborShareEngine
    subcmd = getattr(args, "neighbor_command", None)

    if not subcmd or subcmd == "help":
        console.print(Panel(
            "[bold]Neighbor Internet[/bold] — connect via a nearby device that has internet.\n\n"
            "  [cyan]discover[/cyan]           — Scan LAN for nearby sharers (8s timeout)\n"
            "  [cyan]connect[/cyan]            — Auto-discover + route through a neighbor\n"
            "  [cyan]connect --host IP[/cyan]  — Connect to a specific neighbor by IP\n"
            "  [cyan]share[/cyan]              — Broadcast your proxy so others can find you\n\n"
            "[dim]HOW IT WORKS:\n"
            "  Sharer: Has internet + runs Blackout Kit → enables 'share' mode\n"
            "          Creates a hotspot → guests connect to it\n"
            "  Guest:  Joins sharer's hotspot → runs 'neighbor connect'\n"
            "          Traffic routes: Guest → [LAN] → Sharer → [SNI/VPN] → Internet[/dim]",
            title="[bold]Neighbor Internet[/bold]", border_style="cyan",
        ))
        return

    if subcmd == "discover":
        console.print("[info]Scanning LAN for nearby Blackout Kit devices (8 seconds)...[/info]")
        result = NeighborConnectEngine.discover(timeout=8.0)
        if result:
            host, port = result
            console.print(Panel(
                f"[success]✓ Found a sharer![/success]\n\n"
                f"  IP:    [bold]{host}[/bold]\n"
                f"  Port:  [bold]{port}[/bold]  (HTTP proxy)\n\n"
                f"Connect: [bold]blackout neighbor connect --host {host}[/bold]",
                title="[bold green]Neighbor Found[/bold green]", border_style="green",
            ))
        else:
            console.print("[warning]No sharers found on LAN. Ask your neighbor to run:[/warning]")
            console.print("  [bold]blackout neighbor share[/bold]")

    elif subcmd == "connect":
        host = getattr(args, "host", None)
        port = getattr(args, "port", 0)

        if not host:
            console.print("[info]Discovering nearby sharer (8s)...[/info]")
            result = NeighborConnectEngine.discover(timeout=8.0)
            if not result:
                console.print("[error]No sharer found. Try: blackout neighbor discover[/error]")
                return
            host, port = result
            console.print(f"[success]✓ Found sharer at {host}:{port}[/success]")

        port = port or 10809
        console.print(f"[info]Connecting to neighbor proxy at {host}:{port}...[/info]")

        engine = NeighborConnectEngine(peer_host=host, peer_port=port)
        if not engine.start():
            console.print(f"[error]Cannot reach {host}:{port} — is the neighbor's proxy running?[/error]")
            return

        # Set system proxy to point at the neighbor
        s = cfg.load()
        if s.get("auto_set_proxy"):
            set_system_proxy(host, port)
            console.print(f"[success]✓ System proxy → {host}:{port}[/success]")

        console.print(Panel(
            f"[success]Connected via neighbor[/success]\n\n"
            f"  Routing through: [bold]{host}:{port}[/bold]\n\n"
            "[dim]Your traffic: You → [LAN] → Neighbor → Internet[/dim]\n\n"
            "[muted]Press Ctrl+C to disconnect.[/muted]",
            title="[bold green]Neighbor Connected[/bold green]", border_style="green",
        ))

        try:
            while engine.is_running():
                time.sleep(2)
            console.print("[warning]⚠ Neighbor proxy went offline![/warning]")
        except KeyboardInterrupt:
            pass
        finally:
            engine.stop()
            if s.get("auto_set_proxy"):
                clear_system_proxy()
            console.print("[success]Disconnected.[/success]")

    elif subcmd == "share":
        s = cfg.load()
        port = s.get("neighbor_proxy_port", s.get("xray_http_port", 10809))

        # Get local LAN IP
        local_ip = _get_local_ip()

        console.print(Panel(
            f"[bold]Sharing proxy on LAN[/bold]\n\n"
            f"  Announcing port [bold]{port}[/bold] via UDP multicast\n"
            f"  Your LAN IP: [bold]{local_ip}[/bold]\n\n"
            "[yellow]IMPORTANT:[/yellow] You must have a bypass engine running first!\n"
            "[dim]Run:[/dim] [bold]blackout start -d[/bold] [dim](in another terminal)[/dim]\n\n"
            "[yellow]Also:[/yellow] Create a hotspot so neighbors can connect to your WiFi.\n"
            "[dim]Run:[/dim] [bold]blackout tools hotspot[/bold]\n\n"
            "[muted]Press Ctrl+C to stop sharing.[/muted]",
            title="[bold yellow]Neighbor Share Mode[/bold yellow]", border_style="yellow",
        ))

        engine = NeighborShareEngine(proxy_port=port)
        engine.start()

        try:
            while engine.is_running():
                time.sleep(2)
        except KeyboardInterrupt:
            pass
        finally:
            engine.stop()
            console.print("[success]Stopped sharing.[/success]")

    elif subcmd == "cache-list":
        from .scanner import neighbor_cache
        neighbors = neighbor_cache.load_neighbor_cache(max_age_minutes=1440)
        if not neighbors:
            console.print("[muted]No cached neighbors found.[/muted]")
            return

        table = make_table(
            f"Cached LAN Neighbors ({len(neighbors)})",
            [("IP", "cyan"), ("Port", "yellow"), ("MAC", "dim"), ("Hostname", "white"), ("Last Seen", "")],
            [],
        )
        for n in neighbors:
            ip = n.get("ip", "?")
            port = str(n.get("port", "?"))
            mac = n.get("mac", "?")
            hostname = n.get("hostname", "-")
            last_seen = n.get("last_seen", "?")
            # Parse ISO timestamp to readable format
            try:
                from datetime import datetime
                ts = datetime.fromisoformat(last_seen)
                last_seen_str = ts.strftime("%H:%M:%S")
            except Exception:
                last_seen_str = last_seen[:19]
            table.add_row(ip, port, mac, hostname, last_seen_str)

        console.print(table)
        age = neighbor_cache.cache_age_minutes()
        if age >= 0:
            console.print(f"[muted]Cache age: {age:.1f} minutes (TTL: 10 minutes)[/muted]")

    elif subcmd == "cache-refresh":
        console.print("[info]Discovering neighbors and refreshing cache (8s)...[/info]")
        result = NeighborConnectEngine.discover(timeout=8.0)
        if result:
            host, port = result
            from .scanner import neighbor_cache
            neighbor_cache.add_neighbor(host, port)
            console.print(f"[success]✓ Found and cached: {host}:{port}[/success]")
        else:
            console.print("[warning]No neighbors found on LAN.[/warning]")

    elif subcmd == "cache-clear":
        from .scanner import neighbor_cache
        force = getattr(args, "force", False)

        if not force:
            resp = console.input("[warning]Clear all cached neighbors? [y/N]: [/warning]")
            if resp.lower() != "y":
                console.print("[muted]Cancelled.[/muted]")
                return

        neighbor_cache.clear_neighbor_cache()
        console.print("[success]✓ Neighbor cache cleared[/success]")


def _get_local_ip() -> str:
    """Get the LAN IP of this machine."""
    try:
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "unknown"


def cmd_download(args):
    """Download manager — multi-threaded HTTP(S) downloads with queue, resume, and speed limiting."""
    from .tools import download_manager
    from . import settings as cfg
    from rich.progress import Progress, SpinnerColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
    from rich.table import Table

    subcmd = getattr(args, "download_command", None)

    if not subcmd or subcmd == "help":
        console.print(Panel(
            "[bold]Download Manager[/bold] — Multi-threaded downloads with resume & speed limiting.\n\n"
            "  [cyan]add <url>[/cyan]           — Queue a download\n"
            "  [cyan]list[/cyan]                — Show queue and progress\n"
            "  [cyan]start [ID...]​[/cyan]      — Start queued downloads\n"
            "  [cyan]cancel [ID...]​[/cyan]     — Pause downloads (keep partial files)\n"
            "  [cyan]clear[/cyan]               — Clear completed downloads\n"
            "  [cyan]watch[/cyan]               — Live progress for active downloads\n\n"
            "[dim]Examples:[/dim]\n"
            "  blackout download add https://example.com/file.zip\n"
            "  blackout download list\n"
            "  blackout download start --all\n"
            "  blackout download watch",
            title="Blackout Download", border_style="cyan"
        ))
        return

    # ── add: Queue a download ──────────────────────────────────────
    if subcmd == "add":
        url = getattr(args, "url", None)
        output = getattr(args, "output", None)
        speed_limit = getattr(args, "speed_limit", 0)

        if not url:
            console.print("[error]Usage: blackout download add <url> [--output FILE] [--speed-limit KBPS][/error]")
            return

        try:
            speed_limit = int(speed_limit) if speed_limit else 0
        except ValueError:
            console.print(f"[error]Invalid speed limit: {speed_limit}[/error]")
            return

        download_id = download_manager.queue_download(url, destination=output, speed_limit_kbps=speed_limit)
        console.print(f"[success]✓ Added to queue[/success] ([dim]ID: {download_id}[/dim])")

    # ── list: Show queue and progress ──────────────────────────────
    elif subcmd == "list":
        status_filter = getattr(args, "status", None)

        downloads = download_manager.list_downloads()
        if not downloads:
            console.print("[muted]No downloads in queue.[/muted]")
            return

        # Build display table
        table = make_table("Download Queue", [
            ("ID", "cyan"),
            ("Status", "white"),
            ("Progress", "white"),
            ("Speed", "white"),
            ("Filename", "dim"),
        ], [])

        for d in downloads:
            status_str = d.status.value
            if d.status == download_manager.DownloadStatus.DOWNLOADING:
                status_str = f"[bold green]{status_str}[/bold green]"
            elif d.status == download_manager.DownloadStatus.COMPLETED:
                status_str = f"[bold green]{status_str}[/bold green]"
            elif d.status == download_manager.DownloadStatus.FAILED:
                status_str = f"[bold red]{status_str}[/bold red]"
            elif d.status == download_manager.DownloadStatus.PAUSED:
                status_str = f"[yellow]{status_str}[/yellow]"

            if d.total_size > 0:
                pct = int((d.downloaded / d.total_size) * 100)
                progress_str = f"{pct}% ({d.downloaded//1024//1024}MB / {d.total_size//1024//1024}MB)"
            else:
                progress_str = f"{d.downloaded//1024//1024}MB / ?"

            speed_str = ""
            if d.speed_limit_kbps > 0:
                speed_str = f"{d.speed_limit_kbps} KBps"

            filename = d.destination.name

            table.add_row(d.id, status_str, progress_str, speed_str, filename)

        console.print(table)

    # ── start: Begin queued downloads ──────────────────────────────
    elif subcmd == "start":
        ids = getattr(args, "ids", None) or []
        start_all = getattr(args, "all", False)

        if not ids and not start_all:
            # Start all pending by default
            start_all = True

        if start_all:
            downloads = download_manager.list_downloads(download_manager.DownloadStatus.PENDING)
            ids = [d.id for d in downloads]

        if not ids:
            console.print("[warning]No downloads to start.[/warning]")
            return

        for download_id in ids:
            if download_manager.start_download(download_id):
                console.print(f"[success]✓ Started[/success] {download_id}")
            else:
                console.print(f"[warning]⚠ Already running or not found: {download_id}[/warning]")

    # ── cancel: Pause downloads ────────────────────────────────────
    elif subcmd == "cancel":
        ids = getattr(args, "ids", None) or []
        cancel_all = getattr(args, "all", False)

        if cancel_all:
            downloads = download_manager.list_downloads(download_manager.DownloadStatus.DOWNLOADING)
            ids = [d.id for d in downloads]

        if not ids:
            console.print("[warning]No downloads to cancel.[/warning]")
            return

        for download_id in ids:
            if download_manager.cancel_download(download_id):
                console.print(f"[yellow]⊘ Paused[/yellow] {download_id}")
            else:
                console.print(f"[warning]⚠ Not running: {download_id}[/warning]")

    # ── clear: Remove completed/failed downloads ───────────────────
    elif subcmd == "clear":
        scope = getattr(args, "scope", "completed")  # completed | failed | all

        if scope == "all":
            if is_interactive():
                resp = Prompt.ask("[yellow]Clear entire queue?[/yellow]", choices=["y", "n"], default="n")
                if resp.lower() != "y":
                    return
            queue = []
        else:
            try:
                status = download_manager.DownloadStatus(scope)
            except ValueError:
                console.print(f"[error]Invalid scope: {scope}[/error]")
                return

            queue = download_manager.list_downloads()
            queue = [d for d in queue if d.status != status]

        download_manager.save_queue(queue)
        console.print(f"[success]✓ Cleared {scope} downloads[/success]")

    # ── watch: Live progress display ───────────────────────────────
    elif subcmd == "watch":
        download_id = getattr(args, "id", None)

        console.print("\n[info]Watching downloads (Ctrl+C to stop)...[/info]\n")

        try:
            with Progress(
                SpinnerColumn(style="bold red"),
                TaskProgressColumn(),
                BarColumn(bar_width=40, style="red", complete_style="green"),
                TimeElapsedColumn(),
                console=console,
                transient=False,
            ) as progress:
                # Add task for each active download
                task_map = {}
                if download_id:
                    downloads = [download_manager.get_download(download_id)] if download_manager.get_download(download_id) else []
                else:
                    downloads = download_manager.list_downloads(download_manager.DownloadStatus.DOWNLOADING)

                for d in downloads:
                    task = progress.add_task(f"[cyan]{d.destination.name}[/cyan]", total=d.total_size or 1)
                    task_map[d.id] = task

                # Live update loop
                if not task_map:
                    console.print("[warning]No active downloads to watch.[/warning]")
                    return

                while task_map:
                    for download_id, task in list(task_map.items()):
                        d = download_manager.get_download(download_id)
                        if not d:
                            del task_map[download_id]
                            continue

                        progress.update(task, completed=d.downloaded, total=d.total_size or d.downloaded)

                        if d.status != download_manager.DownloadStatus.DOWNLOADING:
                            del task_map[download_id]

                    if not task_map:
                        break

                    time.sleep(0.5)

                console.print("\n[success]✓ Watching complete[/success]")

        except KeyboardInterrupt:
            console.print("\n[muted]Stopped watching (downloads continue in background)[/muted]\n")


def cmd_media(args):
    """Media downloader — Queue YouTube and similar video downloads with yt-dlp."""
    from .tools import media_downloader
    from rich.table import Table

    subcmd = getattr(args, "media_command", None)

    if not subcmd or subcmd == "help":
        console.print(Panel(
            "[bold]Media Downloader[/bold] — Download videos from YouTube, TikTok, etc.\n\n"
            "  [cyan]add <url>[/cyan]               — Queue a video download\n"
            "  [cyan]list[/cyan]                    — Show download queue\n"
            "  [cyan]watch [ID][/cyan]              — Live progress (all or specific)\n"
            "  [cyan]cancel <id>[/cyan]             — Stop a download\n"
            "  [cyan]clear[/cyan]                   — Remove completed downloads\n\n"
            "[dim]Format options:[/dim]\n"
            "  [cyan]--format FORMAT[/cyan]         — yt-dlp format (e.g., best[ext=mp4])\n"
            "  [cyan]--best-audio-video[/cyan]      — Download best audio + video\n"
            "  [cyan]--output DIR[/cyan]            — Save location (default: ~/Downloads/blackout-media)\n\n"
            "[dim]Examples:[/dim]\n"
            "  blackout media add https://www.youtube.com/watch?v=... --format best[ext=mp4]\n"
            "  blackout media list\n"
            "  blackout media watch",
            title="Blackout Media Downloader", border_style="cyan"
        ))
        return

    manager = media_downloader.get_media_manager()

    # ── add: Queue a media download ────────────────────────────────
    if subcmd == "add":
        url = getattr(args, "url", None)
        format_spec = getattr(args, "format", "")
        best_audio_video = getattr(args, "best_audio_video", False)
        output = getattr(args, "output", None)

        if not url:
            console.print("[error]Usage: blackout media add <url> [--format FORMAT | --best-audio-video] [--output DIR][/error]")
            return

        if best_audio_video:
            format_spec = "best"
        elif not format_spec:
            console.print("[error]Must specify --format or --best-audio-video[/error]")
            return

        media_id = manager.add_download(url, format_spec=format_spec, output_dir=output)
        console.print(f"[success]✓ Queued media download[/success] ([dim]ID: {media_id}[/dim])")

    # ── list: Show queue ───────────────────────────────────────────
    elif subcmd == "list":
        with manager.lock:
            downloads = manager.downloads

        if not downloads:
            console.print("[muted]No media downloads in queue.[/muted]")
            return

        table = make_table("Media Downloads", [
            ("ID", "cyan"),
            ("Status", "white"),
            ("Title", "dim"),
            ("Progress", "white"),
        ], [])

        for d in downloads:
            status_str = d.status.value
            if d.status == media_downloader.MediaDownloadStatus.DOWNLOADING:
                status_str = f"[bold green]{status_str}[/bold green]"
            elif d.status == media_downloader.MediaDownloadStatus.COMPLETED:
                status_str = f"[bold green]{status_str}[/bold green]"
            elif d.status == media_downloader.MediaDownloadStatus.FAILED:
                status_str = f"[bold red]{status_str}[/bold red]"

            title = d.title or "(extracting...)"
            progress = f"{d.speed_kbps} KB/s" if d.speed_kbps > 0 else "waiting"

            table.add_row(d.id[:8], status_str, title, progress)

        console.print(table)

    # ── watch: Live progress ───────────────────────────────────────
    elif subcmd == "watch":
        watch_id = getattr(args, "id", None)

        try:
            while True:
                with manager.lock:
                    downloads = manager.downloads

                if watch_id:
                    downloads = [d for d in downloads if d.id.startswith(watch_id)]

                if not downloads:
                    console.print("[muted]No media downloads to watch.[/muted]")
                    break

                console.clear()
                console.print("[bold cyan]Media Downloads — Live[/bold cyan]\n")

                table = make_table("Status", [
                    ("ID", "cyan"),
                    ("Status", "white"),
                    ("Progress", "white"),
                    ("Speed", "white"),
                ], [])

                for d in downloads:
                    status_str = d.status.value
                    if d.status == media_downloader.MediaDownloadStatus.DOWNLOADING:
                        status_str = f"[bold green]{status_str}[/bold green]"
                    elif d.status == media_downloader.MediaDownloadStatus.COMPLETED:
                        status_str = f"[bold green]{status_str}[/bold green]"
                    elif d.status == media_downloader.MediaDownloadStatus.FAILED:
                        status_str = f"[bold red]{status_str}[/bold red]"

                    progress = f"{d.speed_kbps} KB/s"
                    table.add_row(d.id[:8], status_str, d.title or "(extracting...)", progress)

                console.print(table)
                time.sleep(1)

        except KeyboardInterrupt:
            console.print("\n[muted]Stopped watching (downloads continue in background)[/muted]\n")

    # ── cancel: Stop a download ────────────────────────────────────
    elif subcmd == "cancel":
        dl_id = getattr(args, "id", None)
        if not dl_id:
            console.print("[error]Usage: blackout media cancel <id>[/error]")
            return

        if manager.cancel_download(dl_id):
            console.print(f"[success]✓ Cancelled media download[/success] ([dim]{dl_id}[/dim])")
        else:
            console.print(f"[error]✗ Media download not found: {dl_id}[/error]")

    # ── clear: Remove completed ────────────────────────────────────
    elif subcmd == "clear":
        count = manager.clear_completed()
        console.print(f"[success]✓ Removed {count} completed downloads[/success]")


def cmd_torrent(args):
    """Torrent downloader — Queue magnet and .torrent downloads with libtorrent."""
    from .tools import torrent_manager
    from rich.table import Table

    subcmd = getattr(args, "torrent_command", None)

    if not subcmd or subcmd == "help":
        console.print(Panel(
            "[bold]Torrent Manager[/bold] — Download torrents and magnets.\n\n"
            "  [cyan]add <magnet|file>[/cyan]      — Queue a torrent download\n"
            "  [cyan]list[/cyan]                   — Show torrent queue\n"
            "  [cyan]watch [ID][/cyan]             — Live progress\n"
            "  [cyan]cancel <id>[/cyan]            — Stop a torrent\n"
            "  [cyan]seed <id> [--ratio R][/cyan]  — Set seed ratio (default: 1.0)\n"
            "  [cyan]clear[/cyan]                  — Remove completed torrents\n\n"
            "[dim]Options:[/dim]\n"
            "  [cyan]--output DIR[/cyan]           — Save location (default: ~/Downloads/blackout-torrents)\n"
            "  [cyan]--ratio R[/cyan]              — Seed ratio (1.0 = 1:1, default)\n\n"
            "[dim]Examples:[/dim]\n"
            "  blackout torrent add magnet:?xt=urn:btih:...\n"
            "  blackout torrent list\n"
            "  blackout torrent seed <id> --ratio 1.5",
            title="Blackout Torrent Manager", border_style="cyan"
        ))
        return

    manager = torrent_manager.get_torrent_manager()

    # ── add: Queue a torrent ───────────────────────────────────────
    if subcmd == "add":
        magnet_or_file = getattr(args, "magnet_or_file", None)
        output = getattr(args, "output", None)
        seed_ratio = getattr(args, "ratio", 1.0)

        if not magnet_or_file:
            console.print("[error]Usage: blackout torrent add <magnet|.torrent-file> [--output DIR] [--ratio N][/error]")
            return

        try:
            seed_ratio = float(seed_ratio)
        except (ValueError, TypeError):
            seed_ratio = 1.0

        torrent_id = manager.add_torrent(magnet_or_file, output_dir=output, seed_ratio=seed_ratio)
        console.print(f"[success]✓ Queued torrent[/success] ([dim]ID: {torrent_id}[/dim])")

    # ── list: Show queue ───────────────────────────────────────────
    elif subcmd == "list":
        with manager.lock:
            downloads = manager.downloads

        if not downloads:
            console.print("[muted]No torrents in queue.[/muted]")
            return

        table = make_table("Torrents", [
            ("ID", "cyan"),
            ("Status", "white"),
            ("Progress", "white"),
            ("Peers/Seeds", "white"),
            ("Speed", "white"),
        ], [])

        for d in downloads:
            status_str = d.status.value
            if d.status == torrent_manager.TorrentStatus.DOWNLOADING:
                status_str = f"[bold green]{status_str}[/bold green]"
            elif d.status == torrent_manager.TorrentStatus.SEEDING:
                status_str = f"[yellow]{status_str}[/yellow]"
            elif d.status == torrent_manager.TorrentStatus.COMPLETED:
                status_str = f"[bold green]{status_str}[/bold green]"
            elif d.status == torrent_manager.TorrentStatus.FAILED:
                status_str = f"[bold red]{status_str}[/bold red]"

            if d.total_size > 0:
                pct = int((d.downloaded / d.total_size) * 100)
                progress = f"{pct}%"
            else:
                progress = "waiting"

            peers_seeds = f"{d.peers}p/{d.seeds}s" if d.peers > 0 else "—"
            speed = f"↓{d.download_rate_kbps}KB ↑{d.upload_rate_kbps}KB" if d.download_rate_kbps > 0 else "waiting"

            table.add_row(d.id[:8], status_str, progress, peers_seeds, speed)

        console.print(table)

    # ── watch: Live progress ───────────────────────────────────────
    elif subcmd == "watch":
        watch_id = getattr(args, "id", None)

        try:
            while True:
                with manager.lock:
                    downloads = manager.downloads

                if watch_id:
                    downloads = [d for d in downloads if d.id.startswith(watch_id)]

                if not downloads:
                    console.print("[muted]No torrents to watch.[/muted]")
                    break

                console.clear()
                console.print("[bold cyan]Torrents — Live[/bold cyan]\n")

                table = make_table("Status", [
                    ("ID", "cyan"),
                    ("Status", "white"),
                    ("Progress", "white"),
                    ("Peers", "white"),
                    ("Download", "white"),
                    ("Upload", "white"),
                ], [])

                for d in downloads:
                    status_str = d.status.value
                    if d.status == torrent_manager.TorrentStatus.SEEDING:
                        status_str = f"[yellow]{status_str}[/yellow]"

                    if d.total_size > 0:
                        pct = int((d.downloaded / d.total_size) * 100)
                        progress = f"{pct}%"
                    else:
                        progress = "—"

                    peers = f"{d.peers}p/{d.seeds}s" if d.peers > 0 else "—"
                    dl_speed = f"{d.download_rate_kbps}KB/s"
                    ul_speed = f"{d.upload_rate_kbps}KB/s"

                    table.add_row(d.id[:8], status_str, progress, peers, dl_speed, ul_speed)

                console.print(table)
                time.sleep(1)

        except KeyboardInterrupt:
            console.print("\n[muted]Stopped watching (torrents continue in background)[/muted]\n")

    # ── cancel: Stop a torrent ─────────────────────────────────────
    elif subcmd == "cancel":
        torrent_id = getattr(args, "id", None)
        if not torrent_id:
            console.print("[error]Usage: blackout torrent cancel <id>[/error]")
            return

        if manager.cancel_download(torrent_id):
            console.print(f"[success]✓ Cancelled torrent[/success] ([dim]{torrent_id}[/dim])")
        else:
            console.print(f"[error]✗ Torrent not found: {torrent_id}[/error]")

    # ── seed: Set seed ratio ───────────────────────────────────────
    elif subcmd == "seed":
        torrent_id = getattr(args, "id", None)
        seed_ratio = getattr(args, "ratio", 1.0)

        if not torrent_id:
            console.print("[error]Usage: blackout torrent seed <id> [--ratio R][/error]")
            return

        try:
            seed_ratio = float(seed_ratio)
        except (ValueError, TypeError):
            seed_ratio = 1.0

        if manager.set_seed_ratio(torrent_id, seed_ratio):
            console.print(f"[success]✓ Set seed ratio to {seed_ratio}[/success]")
        else:
            console.print(f"[error]✗ Torrent not found: {torrent_id}[/error]")

    # ── clear: Remove completed ────────────────────────────────────
    elif subcmd == "clear":
        count = manager.clear_completed()
        console.print(f"[success]✓ Removed {count} completed torrents[/success]")


def cmd_help(args):
    topic = getattr(args, "topic", None)
    content = get_help(topic)
    console.print(Panel(content, title="[bold]Blackout Kit — Help[/bold]", border_style="cyan"))


def cmd_doctor(args):
    auto_fix = getattr(args, "fix", False)
    fix_av   = getattr(args, "fix_av", False)

    if fix_av:
        console.print("[info]Adding bins/ folder to Windows Defender exclusions...[/info]")
        ok = sec.add_defender_exclusion()
        if ok:
            console.print("[success]✓ Exclusion added! Defender will no longer flag binaries in bins/.[/success]")
        else:
            console.print("[error]Failed — run as administrator and try again.[/error]")
        return

    if auto_fix:
        console.print("[yellow]Running checks and auto-fixing where possible...[/yellow]")
    else:
        console.print("[info]Running diagnostic checks...[/info]")
    results = doc.run_all_checks(auto_fix=auto_fix)
    doc.print_report(results, auto_fixed=auto_fix)


def cmd_update(args):
    """Check for updates and optionally apply them."""
    force = getattr(args, "force", False)

    console.print(f"\n[info]Current version: {__version__}[/info]")
    console.print("[muted]Checking GitHub for updates...[/muted]")

    with console.status("[bold]Checking...[/bold]", spinner="dots"):
        release = updater.check_for_update()

    if not release:
        console.print(f"\n[success]✓ You are up to date! ({__version__})[/success]\n")
        return

    console.print(Panel(
        f"[bold yellow]New version available![/bold yellow]\n\n"
        f"  Current:  [muted]{__version__}[/muted]\n"
        f"  Latest:   [bold green]{release['version']}[/bold green]\n\n"
        f"[dim]{(release.get('body') or '')[:300]}{'...' if len(release.get('body') or '') > 300 else ''}[/dim]",
        title="[bold]Update Available[/bold]", border_style="yellow",
    ))

    if not force:
        console.print("\nRun [bold]blackout update --apply[/bold] to install the update.")
        return

    console.print("\n[info]Downloading and applying update...[/info]")
    with console.status("[bold]Updating...[/bold]", spinner="dots"):
        ok = updater.download_and_apply(release)

    if ok:
        console.print(f"[success]✓ Updated to {release['version']}! Restart blackout to use it.[/success]\n")
    else:
        console.print("[error]Update failed. Check your internet connection and try again.[/error]\n")


def cmd_preflight(args):
    """Run offline-first readiness check — are you ready for a blackout?"""
    console.print()
    console.print(Panel(
        "[bold]Pre-Blackout Readiness Check[/bold]\n"
        "[dim]Verifying that Blackout Kit can work with zero internet access.[/dim]",
        border_style="yellow",
    ))
    console.print()

    with console.status("[bold]Checking...[/bold]", spinner="dots"):
        results = updater.run_preflight()

    ready, crit_fails, total_fails = updater.preflight_summary(results)

    table = make_table(
        "Preflight Report",
        [("Check", "white"), ("Status", ""), ("Details", "dim")],
        [],
    )
    for r in results:
        if r.ok:
            status = "[success]✓ READY[/success]"
        elif r.critical:
            status = "[error]✗ CRITICAL[/error]"
        else:
            status = "[yellow]⚠ WARN[/yellow]"
        table.add_row(r.name, status, r.message)

    console.print(table)

    if ready:
        console.print(Panel(
            "[bold green]✓ READY FOR BLACKOUT![/bold green]\n\n"
            "All critical checks passed. When the blackout hits:\n"
            "  → [bold]blackout start -d[/bold]   (or 'blackout emergency -d' if SNI fails)\n\n"
            "[dim]Tip: Run 'blackout scan' periodically to keep the IP cache fresh.[/dim]",
            border_style="green",
        ))
    else:
        console.print(Panel(
            f"[bold red]✗ NOT READY  ({crit_fails} critical issue(s))[/bold red]\n\n"
            "Fix the CRITICAL items above before the blackout hits!\n\n"
            "Quick checklist:\n"
            "  1. Download binaries → [bold]blackout doctor[/bold] shows where\n"
            "  2. Add configs   → [bold]blackout config import <subscription-url>[/bold]\n"
            "  3. Scan IPs      → [bold]blackout scan[/bold]\n"
            "  4. Test it now   → [bold]blackout start[/bold]",
            border_style="red",
        ))
    console.print()


def cmd_network(args):
    """WiFi network switcher and ISP detection."""
    from . import network_switcher as ns

    subcmd = getattr(args, "network_command", None)

    if not subcmd:
        # ── Status panel ──
        with console.status("[bold]Detecting network info...[/bold]", spinner="dots"):
            ssid     = ns.get_current_ssid()
            signal   = ns.get_wifi_signal()
            isp_info = ns.get_isp_info()
            switchable = ns.get_switchable_networks()

        ssid_disp   = f"[bold]{ssid}[/bold]" if ssid else "[dim]Not connected[/dim]"
        isp_disp    = isp_info.isp_short if isp_info else "[dim]Unknown[/dim]"
        sw_count    = len(switchable)

        if signal is not None:
            bar = ns._signal_bar(signal)
            signal_disp = f"{bar}  {signal}%"
        else:
            signal_disp = "[dim]N/A (ethernet or no WiFi)[/dim]"

        sw_disp = (
            f"[success]{sw_count} available[/success]"
            if sw_count > 0
            else "[muted]None[/muted]"
        )

        # Country line
        net_profile = cp.detect_country(isp_info)
        if net_profile:
            country_disp = (
                f"[bold]{net_profile.name}[/bold]  "
                f"[dim][{net_profile.censorship_level.upper()} censorship][/dim]"
            )
        else:
            country_disp = "[dim]Unknown[/dim]"

        console.print(Panel(
            f"  [muted]SSID:[/muted]     {ssid_disp}\n"
            f"  [muted]ISP:[/muted]      [bold]{isp_disp}[/bold]\n"
            f"  [muted]Country:[/muted]  {country_disp}\n"
            f"  [muted]Signal:[/muted]   {signal_disp}\n"
            f"  [muted]Switchable networks:[/muted] {sw_disp}\n\n"
            f"  [dim]Run: [bold]blackout network scan[/bold][/dim]",
            title="[bold]Network Status[/bold]",
            border_style="cyan",
            width=60,
        ))
        return

    if subcmd == "scan":
        with console.status("[bold]Scanning WiFi networks...[/bold]", spinner="dots"):
            available = ns.list_available_networks()
            saved_set = set(ns.list_saved_profiles())

        for net in available:
            net.saved = net.ssid in saved_set

        available.sort(key=lambda n: n.signal, reverse=True)

        if not available:
            console.print("[warning]No WiFi networks found. Make sure you're on WiFi.[/warning]")
            return

        table = make_table(
            "Available WiFi Networks",
            [("SSID", "cyan"), ("Signal", ""), ("Auth", "dim"), ("Switchable", "")],
            [],
        )
        for net in available:
            bar = ns._signal_bar(net.signal, width=4)
            signal_str = f"{bar} {net.signal}%"
            sw_str = "[success]✓ YES[/success]" if net.saved else "[dim](no pass)[/dim]"
            table.add_row(net.ssid, signal_str, net.auth, sw_str)

        console.print(table)

    elif subcmd == "isp":
        with console.status("[bold]Looking up ISP...[/bold]", spinner="dots"):
            isp_info = ns.get_isp_info()

        if not isp_info:
            console.print("[error]Could not reach ISP lookup API. Check your internet connection.[/error]")
            return

        console.print(Panel(
            f"  [muted]ISP:[/muted]         [bold]{isp_info.isp}[/bold]\n"
            f"  [muted]Short name:[/muted]  [bold cyan]{isp_info.isp_short}[/bold cyan]\n"
            f"  [muted]ASN:[/muted]         [dim]{isp_info.asn or 'N/A'}[/dim]\n"
            f"  [muted]City:[/muted]        {isp_info.city or 'N/A'}\n"
            f"  [muted]Country:[/muted]     {isp_info.country or 'N/A'}",
            title="[bold]ISP Information[/bold]",
            border_style="cyan",
        ))

        # Country context panel
        isp_profile = cp.detect_country(isp_info)
        if isp_profile:
            best_engine = isp_profile.engine_order[0] if isp_profile.engine_order else "sni"
            console.print(Panel(
                f"  [dim]\"{isp_profile.notes}\"[/dim]\n"
                f"  [muted]Best engine:[/muted] [bold]{best_engine}[/bold]",
                title="[bold]Country Context[/bold]",
                border_style="dim",
                width=50,
            ))

    elif subcmd == "switch":
        ssid = args.ssid
        saved = ns.list_saved_profiles()

        if ssid not in saved:
            console.print(f"[error]No saved profile for '{ssid}'.[/error]")
            console.print("[muted]You can only switch to networks you've connected to before.[/muted]")
            if saved:
                console.print(f"[muted]Saved profiles: {', '.join(saved)}[/muted]")
            else:
                console.print("[muted]No saved profiles found.[/muted]")
            return

        console.print(f"\n[info]Switching to [bold]{ssid}[/bold]...[/info]")
        with console.status(f"[bold]Connecting to {ssid}...[/bold]", spinner="dots"):
            ok = ns.switch_to_network(ssid)

        if ok:
            console.print(Panel(
                f"[success]✓ Connected to [bold]{ssid}[/bold]![/success]\n\n"
                "[dim]ISP may have changed. Check it: [bold]blackout network isp[/bold][/dim]",
                border_style="green",
            ))
        else:
            console.print(
                f"[error]Failed to connect to '{ssid}'.[/error]\n"
                "[muted]Make sure the network is in range and your saved password is correct.[/muted]"
            )

    elif subcmd == "auto":
        current = ns.get_current_ssid()
        switchable = ns.get_switchable_networks()

        if not switchable:
            console.print(Panel(
                "[warning]No switchable networks found.[/warning]\n\n"
                "  Possible reasons:\n"
                "  [dim]• You're on ethernet (no WiFi in use)[/dim]\n"
                "  [dim]• No other saved networks are in range[/dim]\n"
                "  [dim]• All nearby networks require a new password[/dim]\n\n"
                "[dim]Run [bold]blackout network scan[/bold] to see all nearby networks.[/dim]",
                title="[bold]Auto-Switch[/bold]",
                border_style="yellow",
            ))
            return

        console.print(
            f"\n[info]Found [bold]{len(switchable)}[/bold] candidate network(s). "
            "Trying best signal first...[/info]\n"
        )
        for net in switchable:
            bar = ns._signal_bar(net.signal, width=4)
            console.print(f"  [dim]→[/dim] [bold]{net.ssid}[/bold]  {bar} {net.signal}%")
        console.print()

        with console.status("[bold]Auto-switching...[/bold]", spinner="dots"):
            new_ssid = ns.auto_switch(exclude_ssid=current)

        if new_ssid:
            console.print(Panel(
                f"[success]✓ Auto-switched to [bold]{new_ssid}[/bold]![/success]\n\n"
                "[dim]ISP may have changed. Check it: [bold]blackout network isp[/bold][/dim]",
                title="[bold green]Connected[/bold green]",
                border_style="green",
            ))
        else:
            console.print(
                "[error]Auto-switch failed — could not connect to any available network.[/error]\n"
                "[muted]Try manually: [bold]blackout network switch <ssid>[/bold][/muted]"
            )


def cmd_bins(args):
    """Manage engine binaries — show status, download missing, update all."""
    from . import downloader as dl
    from rich.panel import Panel as _Panel

    subcmd = getattr(args, "bins_command", None)

    # ── No subcommand: status table ───────────────────────────────
    if not subcmd:
        installed   = dl.check_installed()
        all_bins    = dl.list_available()
        inst_count  = sum(1 for k, v in installed.items() if v)

        table = make_table(
            f"Engine Binaries  ({inst_count}/{len(all_bins)} installed)",
            [("Binary", "cyan"), ("Status", ""), ("Auto?", "dim"), ("Description", "dim")],
            [],
        )
        for b in all_bins:
            is_inst = installed.get(b.key, False)
            status  = "[success]✓ Installed[/success]" if is_inst else (
                "[error]✗ Missing[/error]" if b.required else "[yellow]○ Optional[/yellow]"
            )
            auto    = "[green]✓ auto[/green]" if b.github_repo else "[dim]manual[/dim]"
            table.add_row(b.display_name, status, auto, b.description)

        console.print()
        console.print(table)

        missing_required = [b for b in all_bins if b.required and not installed.get(b.key)]
        missing_auto     = [b for b in all_bins if b.github_repo and not installed.get(b.key)]
        missing_manual   = [b for b in all_bins if not b.github_repo and not installed.get(b.key)]

        if missing_required:
            names = ", ".join(b.display_name for b in missing_required)
            console.print(f"\n[error]Required binaries missing: {names}[/error]")

        if missing_auto:
            console.print(
                f"\n[dim]{len(missing_auto)} binary/ies can be auto-downloaded:[/dim]  "
                "[bold]blackout bins download[/bold]"
            )
        if missing_manual:
            console.print(f"[dim]{len(missing_manual)} require manual download — run [bold]blackout bins download[/bold] for links.[/dim]")
        console.print()
        return

    # ── download ──────────────────────────────────────────────────
    if subcmd == "download":
        target_key = getattr(args, "binary", None)

        if target_key:
            # Download one specific binary
            info = dl.BIN_REGISTRY.get(target_key)
            if not info:
                valid = ", ".join(dl.BIN_REGISTRY.keys())
                console.print(f"[error]Unknown binary: '{target_key}'[/error]  Valid: {valid}")
                return

            if not info.github_repo and target_key not in ("tor", "openvpn"):
                console.print(_Panel(
                    f"[yellow]{info.display_name}[/yellow] requires manual download.\n\n"
                    f"  [dim]{info.manual_note}[/dim]\n\n"
                    f"  Download from: [bold]{info.manual_url}[/bold]\n"
                    f"  Then place the .exe in: [bold]{dl.BINS_DIR}[/bold]",
                    title="[bold]Manual Download Required[/bold]",
                    border_style="yellow",
                ))
                return

            _download_single(dl, target_key, info)

        else:
            # Download ALL missing auto-downloadable binaries
            all_bins  = dl.list_available()
            installed = dl.check_installed()
            to_dl     = [b for b in all_bins if (b.github_repo or b.key in ("tor", "openvpn")) and not installed.get(b.key)]
            manual    = [b for b in all_bins if not b.github_repo and b.key not in ("tor", "openvpn") and not installed.get(b.key)]

            if not to_dl and not manual:
                console.print("[success]✓ All binaries are already installed![/success]")
                return

            if to_dl:
                console.print(f"\n[info]Downloading {len(to_dl)} binary/ies...[/info]\n")
                for b in to_dl:
                    _download_single(dl, b.key, b)

            if manual:
                console.print()
                console.print(_Panel(
                    "[bold]The following require manual download:[/bold]\n\n" +
                    "\n".join(
                        f"  [yellow]{b.display_name}[/yellow]\n"
                        f"    {b.manual_note}\n"
                        f"    Download: [dim]{b.manual_url}[/dim]\n"
                        f"    Place in: [dim]{dl.BINS_DIR}[/dim]"
                        for b in manual
                    ),
                    title="[bold]Manual Downloads[/bold]",
                    border_style="yellow",
                ))

    # ── update ────────────────────────────────────────────────────
    elif subcmd == "update":
        installed = dl.check_installed()
        to_update = [
            b for b in dl.list_available()
            if (b.github_repo or b.key in ("tor", "openvpn")) and installed.get(b.key)
        ]

        if not to_update:
            console.print("[warning]No auto-downloadable binaries are currently installed.[/warning]")
            return

        console.print(f"\n[info]Re-downloading {len(to_update)} installed binary/ies to get latest versions...[/info]\n")
        for b in to_update:
            _download_single(dl, b.key, b, force=True)


def _download_single(dl, key: str, info, force: bool = False):
    """Download one binary with a Rich progress bar. Used by cmd_bins."""
    from rich.progress import (
        Progress, SpinnerColumn, BarColumn,
        TextColumn, DownloadColumn, TransferSpeedColumn, TimeRemainingColumn,
    )

    label = f"Downloading [bold]{info.display_name}[/bold]..."
    repo_disp = info.github_repo or (
        "dist.torproject.org" if key == "tor" else
        "build.openvpn.net" if key == "openvpn" else
        "manual"
    )
    console.print(f"  [dim]→[/dim] {info.display_name}  [dim]{repo_disp}[/dim]")

    task_ref: dict = {"id": None, "progress": None}

    def _cb(done: int, total: int) -> None:
        p = task_ref["progress"]
        t = task_ref["id"]
        if p is None or t is None:
            return
        if total and p.tasks[t].total is None:
            p.update(t, total=total)
        p.update(t, completed=done)

    from .theme import create_download_progress
    with create_download_progress() as progress:
        task_ref["progress"] = progress
        task_ref["id"] = progress.add_task(label, total=None)

        ok, msg = dl.download_binary(key, progress_callback=_cb)

    if ok:
        console.print(f"  [success]✓ {msg}[/success]")
    else:
        console.print(f"  [error]✗ {msg}[/error]")


def cmd_easteregg(args):
    console.print(Panel(
        "[bold yellow]🥚 OH WOW! YOU FOUND THE EASTER EGG! 🥚[/bold yellow]\n\n"
        "Congrats — you're officially the kind of person who reads docs\n"
        "or tries random commands for fun. Respect. 🫡\n\n"
        "[bold red]🖕[/bold red] to every firewall that ever got in your way.\n\n"
        "[dim]Now go tell everyone. Or don't. Your choice.[/dim]",
        title="[bold]SECRET COMMAND[/bold]",
        border_style="yellow",
    ))


def _render_ready_checks(engine_name: str, checks: list) -> None:
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan", padding=(0, 2))
    table.add_column("Check", style="white")
    table.add_column("Status", width=14)
    table.add_column("Details", style="dim")
    for check in checks:
        status = "[green]Ready[/green]" if check.ok else ("[yellow]Warning[/yellow]" if not check.blocking else "[red]Blocked[/red]")
        table.add_row(check.name, status, check.detail)
    console.print(Panel(table, title=f"[heading]Local Readiness · {engine_name}[/heading]", border_style="panel.border"))
    console.print("[muted]This check reads local settings, files, process state, and loopback ports only. It does not start engines, probe remote hosts, download files, or change networking.[/muted]")


def cmd_ready(args):
    """Show strict local readiness for a selected engine."""
    from . import readiness

    requested = getattr(args, "engine", None) or getattr(args, "pos_engine", None) or "auto"
    engine_name = _recommended_engine_name() if requested == "auto" else requested
    checks = readiness.evaluate(engine_name)
    _render_ready_checks(engine_name, checks)
    return all(check.ok or not check.blocking for check in checks)


def _ensure_ready(engine_name: str) -> bool:
    from . import readiness

    checks = readiness.evaluate(engine_name)
    if all(check.ok or not check.blocking for check in checks):
        return True
    _render_ready_checks(engine_name, checks)
    console.print("[error]Connection was not started because local readiness checks found blockers.[/error]")
    return False


def cmd_connect(args):
    """Smart connect — auto-preps and starts the best locally-ready engine."""
    requested_engine = getattr(args, "pos_engine", None) or getattr(args, "engine", None)
    background = getattr(args, "background", False)
    iran_mode = getattr(args, "iran", False)
    russia_mode = getattr(args, "russia", False)

    if iran_mode and russia_mode:
        console.print("[error]Choose only one preset: --iran or --russia.[/error]")
        return

    preset_name = "iran" if iran_mode else "russia" if russia_mode else None
    env_overrides: dict[str, str] = {}
    connect_profile = None
    base_settings = cfg.load()

    if preset_name:
        _title, env_overrides, _changes, _footer = _preset_payload(preset_name, base_settings, direct_start=False)

    with _temporary_env_overrides(env_overrides):
        recommended = _recommended_engine_name()
        connect_profile = _get_active_profile()

    engine_name = recommended if requested_engine in (None, "auto") else requested_engine

    if requested_engine is None and is_interactive() and not background:
        choice = ask_choice(
            f"Recommended engine: {recommended}. Continue or choose manually?",
            ["recommended", "manual", "cancel"],
            default="recommended",
        )
        if choice == "cancel":
            console.print("[muted]Connection cancelled.[/muted]")
            return
        if choice == "manual":
            with _temporary_env_overrides(env_overrides):
                cmd_route(args)
                choices = [candidate.engine for candidate in _routing_candidates()]
            engine_name = ask_choice("Choose an engine", choices, default=recommended)
            if not engine_name:
                console.print("[muted]Connection cancelled.[/muted]")
                return

    if connect_profile:
        rec = connect_profile.engine_order[0] if connect_profile.engine_order else engine_name
        console.print(
            f"  [dim]Detected: {connect_profile.name} "
            f"({connect_profile.censorship_level}) — {rec} recommended[/dim]"
        )
        if connect_profile.code == "CN" and engine_name in ("sni",):
            console.print(
                "[yellow]Note:[/yellow] SNI spoofing is largely ineffective against "
                "China's Great Firewall (GFW blocks IPs + SNI).\n"
                "  Suggested engine: [bold]blackout connect --engine xray[/bold]"
            )
        if connect_profile.code == "RU" and engine_name in ("sni", "gdpi"):
            console.print(
                "[yellow]Note:[/yellow] Russia's preset currently favors XRay and QUIC-capable paths first.\n"
                "  Suggested engines: [bold]blackout connect --engine xray[/bold], "
                "[bold]blackout connect --engine hysteria2[/bold], or [bold]blackout connect --engine tuic[/bold]"
            )

    s = cfg.load()
    if not sys.platform.startswith("linux") and engine_name in ("sni", "auto") and not s.get("sni_connect_ip"):
        console.print("[yellow]No saved Cloudflare IP — running quick scan (10 IPs)...[/yellow]")
        ips = generate_cloudflare_ips(10)
        with Progress(
            SpinnerColumn(style="bold red"),
            TextColumn("[progress.description]{task.description}"),
            console=console, transient=True,
        ) as p:
            p.add_task("Scanning Cloudflare IPs...")
            results = asyncio.run(scan_ips(ips, concurrency=10, timeout=3.0))

        if results:
            best_ip = results[0][0]
            cfg.set_value("sni_connect_ip", best_ip)
            console.print(f"[success]✓ Best IP found: {best_ip} ({results[0][1]:.0f}ms)[/success]")
        else:
            console.print("[warning]No reachable Cloudflare IPs. Proceeding anyway...[/warning]")

    class _FakeArgs:
        pass

    fake = _FakeArgs()
    fake.engine = engine_name if engine_name != "auto" else "sni"
    fake.background = background
    fake.iran = iran_mode
    fake.russia = russia_mode
    cmd_start(fake)


def _recovery_table(steps: list[dict], *, preview: bool = False):
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan", padding=(0, 2))
    table.add_column("Step", style="white", width=30)
    table.add_column("Status", width=18)
    table.add_column("Details", style="dim")
    for step in steps:
        status = "[cyan]Planned[/cyan]" if preview else ("[green]✓ Done[/green]" if step["ok"] else "[red]✗ Failed[/red]")
        table.add_row(step["name"], status, step["detail"])
    return table


def cmd_fix(args):
    """Run targeted post-crash network recovery with a live Rich checklist."""
    full_route_reset = getattr(args, "full_route_reset", False)
    full_stack_reset = getattr(args, "full_stack_reset", False)
    flush_arp = getattr(args, "flush_arp", False)
    preview = getattr(args, "preview", False)
    history = getattr(args, "history", False)
    history_lines = getattr(args, "history_lines", 20)
    if history:
        from . import recovery_audit
        records = recovery_audit.history(history_lines)
        console.print(Panel(json.dumps(records, indent=2), title="[heading]Recovery Audit History[/heading]", border_style="panel.border"))
        return
    if not (sys.platform == "win32" or sys.platform.startswith("linux")):
        console.print("[yellow]`blackout fix` is supported only on Windows and Linux.[/yellow]")
        return

    if sys.platform.startswith("linux") and (full_route_reset or full_stack_reset):
        console.print("[yellow]Full route and stack resets are Windows-only. Linux recovery remains targeted.[/yellow]")
        full_route_reset = False
        full_stack_reset = False

    if flush_arp:
        console.print("[yellow]ARP flushing is explicit and may briefly interrupt local-network discovery.[/yellow]")

    if sys.platform == "win32" and (full_route_reset or full_stack_reset):
        warnings = []
        if full_route_reset:
            warnings.append("`route -f` removes every IPv4 route before DHCP renewal")
        if full_stack_reset:
            warnings.append("Winsock, TCP/IP, autotuning, and DHCP will be reset")
        console.print(Panel(
            "[bold red]Emergency network reset enabled.[/bold red]\n"
            f"[dim]{'; '.join(warnings)}. Use only if targeted recovery did not restore connectivity.[/dim]",
            border_style="red",
        ))

    plan = net_tools.plan_network_recovery(
        full_route_reset=full_route_reset,
        full_stack_reset=full_stack_reset,
        flush_arp=flush_arp,
    )
    console.print(_recovery_table(plan, preview=True))
    if preview:
        console.print("[muted]Preview only: no system proxy, route, DNS, adapter, firewall, or audit-log change was made.[/muted]")
        return

    results: list[dict] = []

    def _make_table():
        return _recovery_table(results)

    console.print()
    recovery_details = (
        "[dim]Removes only Blackout Kit-owned firewall objects and the deterministic BlackoutKit-TUN interface; it never resets system networking.[/dim]\n"
        "[dim]Run with sudo. Full route and stack reset options are Windows-only.[/dim]"
        if sys.platform.startswith("linux") else
        "[dim]Clears stale Blackout routes, restores DHCP DNS only from loopback, and restarts only unhealthy virtual adapters.[/dim]\n"
        "[dim]Run as Administrator for full effect. Full route reset is opt-in only.[/dim]"
    )
    console.print(Panel(
        "[bold yellow]Targeted Network Recovery[/bold yellow]\n" + recovery_details,
        border_style="yellow",
    ))
    console.print()

    with Live(_make_table(), console=console, refresh_per_second=10) as live:
        results.extend(net_tools.run_network_recovery(
            full_route_reset=full_route_reset,
            full_stack_reset=full_stack_reset,
            flush_arp=flush_arp,
            audit_source="cli",
        ))
        live.update(_make_table())

    done = sum(1 for step in results if step["ok"])
    console.print()
    console.print(f"[success]✓ {done}/{len(results)} recovery steps completed.[/success]")
    console.print("[muted]A system restart may be needed for Winsock or TCP/IP changes to fully take effect.[/muted]")
    console.print()


# ──────────────────── Interactive Zero-Flag menu ─────────────────

def _make_fake_args(**kwargs):
    """Build a fake argparse Namespace for calling cmd_ functions from the menu."""
    class _Fake:
        pass
    obj = _Fake()
    for k, v in kwargs.items():
        setattr(obj, k, v)
    return obj


def cmd_menu_select_engine():
    s = cfg.load()
    current = s.get("selected_engine", "auto")

    t = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
    t.add_column("#", style="dim", width=4)
    t.add_column("Key", style="bold white", width=14)
    t.add_column("Description", style="dim")

    options = [
        ("auto",       "Smart Auto-Select (recommended, uses country profile)"),
        ("sni",        "SNI Packet Injection + XRay (best for Iran)"),
        ("xray",       "XRay proxy core only (best manual option for China)"),
        ("gdpi",       "GoodbyeDPI (Windows-only passive DPI bypass)"),
        ("psiphon",    "Psiphon VPN (multi-protocol VPN fallback)"),
        ("warp",       "Cloudflare WARP (clean residential IP)"),
        ("hysteria2",  "Hysteria2 QUIC proxy via sing-box"),
        ("tuic",       "TUIC QUIC proxy via sing-box"),
        ("awg",        "AmneziaWG — obfuscated WireGuard via sing-box (experimental)"),
        ("legend",     "Legend Mode (Tor + SNI + XRay chained)"),
        ("appsscript", "Google Apps Script HTTP Relay (ultimate fallback)"),
        ("mhrv",       "Embedded HTTP Google Apps Script relay"),
        ("tor",        "Tor Proxy Only"),
        ("wireguard",  "WireGuard VPN"),
        ("openvpn",    "OpenVPN"),
        ("softether",  "SoftEther SSL-VPN"),
    ]

    # Start interactive menu instead of prompt
    selected_idx = 0

    def generate_menu(idx):
        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        t.add_column("Marker", style="bold cyan", width=2)
        t.add_column("Engine", style="bold white", width=14)
        t.add_column("Description", style="dim")
        for i, (key, desc) in enumerate(options):
            active_marker = "[success]● active[/success]" if key == current else ""
            if i == idx:
                t.add_row(">", f"[cyan]{key}[/cyan]", f"[cyan]{desc}[/cyan] {active_marker}")
            else:
                t.add_row(" ", key, f"{desc} {active_marker}")
        
        t.add_row(" ", "", "")
        if idx == len(options):
            t.add_row(">", "[red]Cancel[/red]", "[dim]Return to main menu[/dim]")
        else:
            t.add_row(" ", "[red]Cancel[/red]", "[dim]Return to main menu[/dim]")
            
        return Panel(t, title="[bold]Select Bypass Strategy (Manual Engine Selection)[/bold]", border_style="cyan")

    if sys.platform != "win32":
        console.print(generate_menu(-1))
        try:
            choice = console.input("\n[bold cyan]Choose option [0-12]:[/bold cyan] ").strip()
        except (KeyboardInterrupt, EOFError):
            return
        if not choice or choice == "0": return
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(options):
                selected_key = options[idx][0]
                cfg.set_value("selected_engine", selected_key)
                console.print(f"\n[success]✓ Preferred engine set to [bold]{selected_key}[/bold]![/success]")
                console.print("[info]Engine selected. You can now use the 'Connect' option from the main menu.[/info]\n")
        except ValueError:
            pass
        return

    while True:
        with Live(generate_menu(selected_idx), console=console, auto_refresh=False, transient=True) as live:
            while True:
                live.update(generate_menu(selected_idx), refresh=True)
                ch = msvcrt.getch()
                if ch in (b'\x00', b'\xe0'):
                    arrow = msvcrt.getch()
                    if arrow == b'H': # UP
                        selected_idx = (selected_idx - 1) % (len(options) + 1)
                    elif arrow == b'P': # DOWN
                        selected_idx = (selected_idx + 1) % (len(options) + 1)
                elif ch == b'\r':
                    break
                elif ch == b'\x03': # Ctrl+C
                    return
                else:
                    decoded = ch.decode('utf-8', 'ignore')
                    if decoded == '0':
                        selected_idx = len(options)
                        break

        if selected_idx == len(options):
            return
            
        selected_key = options[selected_idx][0]
        cfg.set_value("selected_engine", selected_key)
        console.print(f"\n[success]✓ Preferred engine set to [bold]{selected_key}[/bold]![/success]")
        console.print("[info]Engine selected. You can now use the 'Connect' option from the main menu.[/info]\n")
        break



def _interactive_menu():
    """Display an interactive menu navigable with arrow keys when blackout is run with no arguments."""
    menu_items = [
        ("🚀 Connect",   "Start bypass — smart/preferred engine", "1"),
        ("⚡ Emergency",  "Try locally supported candidates", "2"),
        ("🔌 Engine",     "Select manual bypass engine (sni/psiphon/warp...)", "3"),
        ("🌍 Country",    "Show or set country profile (IR/RU/CN/…)", "4"),
        ("📊 Status",    "Check daemon + connection health", "5"),
        ("📡 Live Status", "Watch local connection state", "W"),
        ("🧭 Routing",   "Rank local engine readiness", "R"),
        ("🎨 Theme",     "Set Blackout Kit terminal palette", "T"),
        ("🔍 Scan",      "Scan Cloudflare IPs + SNI domains", "6"),
        ("🏥 Doctor",    "Self-diagnose and auto-repair", "7"),
        ("🔧 Fix",       "Auto-fix DNS / Winsock / TCP/IP", "8"),
        ("🌐 Tools",     "Network toolkit (ping, speedtest…)", "9"),
        ("⚙  Settings",  "View and change settings", "S"),
        ("❌ Exit",      "", "0"),
    ]

    _EXIT = object()
    _dispatch = {
        "1": lambda: cmd_connect(_make_fake_args(engine=None, background=False, iran=False)),
        "2": lambda: cmd_emergency(_make_fake_args(background=False)),
        "3": cmd_menu_select_engine,
        "4": lambda: cmd_country(_make_fake_args(country_command=None)),
        "5": lambda: cmd_status(_make_fake_args(watch=False, interval=2.0)),
        "W": lambda: cmd_status(_make_fake_args(watch=True, interval=2.0)),
        "w": lambda: cmd_status(_make_fake_args(watch=True, interval=2.0)),
        "R": lambda: cmd_route(_make_fake_args()),
        "r": lambda: cmd_route(_make_fake_args()),
        "T": lambda: cmd_theme(_make_fake_args(palette=ask_choice("Choose terminal palette", ["dark", "light"], default=cfg.load().get("terminal_theme", "dark")))),
        "t": lambda: cmd_theme(_make_fake_args(palette=ask_choice("Choose terminal palette", ["dark", "light"], default=cfg.load().get("terminal_theme", "dark")))),
        "6": lambda: cmd_scan(_make_fake_args(ips=False, sni=False, count=None)),
        "7": lambda: cmd_doctor(_make_fake_args(fix=False, fix_av=False)),
        "8": lambda: cmd_fix(_make_fake_args()),
        "9": lambda: cmd_tools(_make_fake_args(tools_command=None)),
        "S": lambda: cmd_settings(_make_fake_args(settings_command=None)),
        "s": lambda: cmd_settings(_make_fake_args(settings_command=None)),
        "0": _EXIT,
    }

    selected_idx = 0

    def generate_menu(idx):
        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        t.add_column("Marker", style="bold cyan", width=2)
        t.add_column("Action", style="bold white", width=18)
        t.add_column("Description", style="dim")
        for i, (action, desc, key) in enumerate(menu_items):
            if i == idx:
                t.add_row(">", f"[cyan]{action}[/cyan]", f"[cyan]{desc}[/cyan]")
            else:
                t.add_row(" ", action, desc)
        return Panel(t, title="[bold]Use Arrow Keys to Navigate[/bold]", border_style="cyan")

    if sys.platform != "win32":
        # Fallback to simple input for non-Windows (or write a proper Unix getch)
        console.print(generate_menu(-1))
        try:
            choice = console.input("\n[bold cyan]Enter choice [0-9, S]:[/bold cyan] ").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[muted]Bye![/muted]")
            return
        handler = _dispatch.get(choice.upper())
        if handler is _EXIT: return
        if handler: handler()
        return

    import msvcrt

    while True:
        with Live(generate_menu(selected_idx), console=console, auto_refresh=False, transient=True) as live:
            while True:
                live.update(generate_menu(selected_idx), refresh=True)
                ch = msvcrt.getch()
                if ch in (b'\x00', b'\xe0'):
                    arrow = msvcrt.getch()
                    if arrow == b'H': # UP
                        selected_idx = (selected_idx - 1) % len(menu_items)
                    elif arrow == b'P': # DOWN
                        selected_idx = (selected_idx + 1) % len(menu_items)
                elif ch == b'\r':
                    break
                elif ch == b'\x03': # Ctrl+C
                    console.print("\n[muted]Bye![/muted]")
                    return
                else:
                    # Allow quick select via numbers
                    decoded = ch.decode('utf-8', 'ignore').upper()
                    for i, (_, _, key) in enumerate(menu_items):
                        if key.upper() == decoded:
                            selected_idx = i
                            break

        action_key = menu_items[selected_idx][2]
        handler = _dispatch.get(action_key.upper())
        if handler is _EXIT:
            console.print("[muted]Bye![/muted]")
            return
        elif handler:
            console.print()
            handler()
            console.print()
            
            # Don't pause if the user just started the engine (foreground), 
            # because they already hit Ctrl+C to stop it.
            if action_key not in ("1", "2", "W"):
                console.print("[dim]Press any key to return to menu...[/dim]")
                msvcrt.getch()
                console.print()
        else:
            return


def cmd_daemon_run(args):
    """Hidden command — runs inside the background daemon process."""
    daemon.run_daemon_loop(args.engine, getattr(args, "env_overrides_json", None))


def main():
    """Fallback entry point to route to typer_cli."""
    from .typer_cli import main as typer_main
    typer_main()

# End of file
