"""
Blackout Kit - DNS engine.

A resolver-switching engine, separate from the tunnel engines in
``blackoutkit/engines/``: it does not carry traffic, it decides who answers
name lookups. That distinction matters because a tunnel can be perfectly
healthy and still leak every domain you visit to the carrier's resolver.

The catalogue below is the *default* set. Two of its three categories are
copied verbatim from XDNS (a single-file Windows client): the exact
primary/secondary pairs it switches between when you pick "Sanctions" or
"Speed". They are reproduced here because they are known-good pairs for the
networks this project targets - in particular the Iranian resolvers, where
using only the primary address loses the redundancy the operator intended.

Design notes
------------
* A provider is a *pair*, not an address. ``apply()`` writes both, in order,
  so the OS falls back to the secondary instead of to the DHCP server.
* ``apply()`` snapshots the resolvers it replaced into
  ``~/.blackout-kit/dns_state.json`` before touching anything, so
  ``restore()`` can put the machine back the way it was found.
* Every platform call is a plain subprocess with a timeout. Nothing here
  raises out of ``apply()``: a DNS change that half-succeeded must report
  what happened, not crash the caller mid-tunnel.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

_log = logging.getLogger("blackoutkit.dns")

APP_DATA_DIR = Path.home() / ".blackout-kit"
STATE_FILE = APP_DATA_DIR / "dns_state.json"

# ──────────────────────────── Catalogue ──────────────────────────────────────

CATEGORY_SANCTIONS = "sanctions"
CATEGORY_SPEED = "speed"
CATEGORY_EXTRA = "extra"

CATEGORY_ORDER = (CATEGORY_SANCTIONS, CATEGORY_SPEED, CATEGORY_EXTRA)

CATEGORY_LABELS = {
    CATEGORY_SANCTIONS: "Sanctions - resolvers chosen to survive national filtering",
    CATEGORY_SPEED: "Speed - high-performance public resolvers",
    CATEGORY_EXTRA: "Extra - filtering, privacy and domestic resolvers",
}

CATEGORY_SHORT = {
    CATEGORY_SANCTIONS: "sanctions",
    CATEGORY_SPEED: "speed",
    CATEGORY_EXTRA: "extra",
}


@dataclass(frozen=True)
class DNSProvider:
    """One selectable resolver pair."""

    key: str
    name: str
    primary: str
    category: str
    secondary: str | None = None
    note: str = ""

    @property
    def servers(self) -> tuple[str, ...]:
        """Primary first, then secondary - the order the OS should try them."""
        return (self.primary, self.secondary) if self.secondary else (self.primary,)

    def describe(self) -> str:
        return f"{self.name} ({', '.join(self.servers)})"

    def as_dict(self) -> dict:
        return {
            "key": self.key,
            "name": self.name,
            "primary": self.primary,
            "secondary": self.secondary,
            "category": self.category,
            "note": self.note,
        }


# The first two groups start with XDNS's own lists, verbatim, then continue
# with well-known resolvers that answer from the same places. Keeping the
# operator's pairs first matters: they are the ones known to survive on the
# networks this project targets.
DNS_CATALOG: tuple[DNSProvider, ...] = (
    # -- Sanctions: survive filtering ------------------------------------
    DNSProvider("shecan", "Shecan", "178.22.122.100", CATEGORY_SANCTIONS, "185.51.200.2",
                note="Iranian filtered-but-fast resolver"),
    DNSProvider("electro", "Electro", "78.157.42.100", CATEGORY_SANCTIONS, "78.157.42.101",
                note="Iranian bypass resolver"),
    DNSProvider("begzar", "Begzar", "185.55.226.26", CATEGORY_SANCTIONS, "185.55.226.25",
                note="Iranian unfiltered resolver"),
    DNSProvider("radar", "Radar", "10.202.10.10", CATEGORY_SANCTIONS, "10.202.10.11",
                note="Iranian game/anti-sanction resolver"),
    DNSProvider("403", "403.online", "10.202.10.202", CATEGORY_SANCTIONS, "10.202.10.102",
                note="Iranian anti-sanction resolver (403.online)"),
    DNSProvider("opendns", "OpenDNS", "208.67.222.222", CATEGORY_SANCTIONS, "208.67.220.220",
                note="Cisco OpenDNS; the fallback in XDNS's list"),
    # -- Speed: public resolvers -----------------------------------------
    DNSProvider("yandex", "Yandex", "77.88.8.8", CATEGORY_SPEED, "77.88.8.1",
                note="Low latency from Iran and the CIS"),
    DNSProvider("cloudflare", "Cloudflare", "1.1.1.1", CATEGORY_SPEED, "1.0.0.1",
                note="Fastest global anycast resolver"),
    DNSProvider("cloudflare-security", "Cloudflare Security", "1.1.1.2", CATEGORY_SPEED, "1.0.0.2",
                note="Cloudflare with malware blocking"),
    DNSProvider("cloudflare-family", "Cloudflare Family", "1.1.1.3", CATEGORY_SPEED, "1.0.0.3",
                note="Cloudflare with malware and adult-content blocking"),
    DNSProvider("google", "Google", "8.8.8.8", CATEGORY_SPEED, "8.8.4.4",
                note="Widely reachable, heavily logged"),
    DNSProvider("dnssb", "DNS.SB", "185.222.222.222", CATEGORY_SPEED, "45.11.45.11",
                note="No-log resolver with DoH/DoT/DoQ"),
    DNSProvider("controld", "Control D", "76.76.2.0", CATEGORY_SPEED, "76.76.10.0",
                note="Free tier of Control D's filtering resolver"),
    DNSProvider("level3", "Level3", "4.2.2.1", CATEGORY_SPEED, "4.2.2.2",
                note="Long-lived public resolver, good reachability"),
    DNSProvider("vercara", "Vercara (Neustar)", "64.6.64.6", CATEGORY_SPEED, "64.6.65.6",
                note="Formerly Verisign/Neustar; operated by Vercara"),
    DNSProvider("comodo", "Comodo", "8.26.56.26", CATEGORY_SPEED, "8.20.247.20",
                note="SecureDNS; older infrastructure, widely reachable"),
    DNSProvider("gcore", "Gcore", "95.85.95.85", CATEGORY_SPEED, "2.56.220.2",
                note="Gcore public DNS; low latency in Europe and the CIS"),
    DNSProvider("oracle", "Oracle Dyn", "216.146.35.35", CATEGORY_SPEED, "216.146.36.36",
                note="Oracle's long-running Dyn resolver"),
    DNSProvider("wikimedia", "Wikimedia", "185.71.138.138", CATEGORY_SPEED, None,
                note="Non-profit resolver run by the Wikimedia Foundation"),
    DNSProvider("dns4eu", "DNS4EU", "86.54.11.100", CATEGORY_SPEED, "86.54.11.200",
                note="EU-backed unfiltered resolver"),
    # -- Extra: filtering, privacy, domestic -----------------------------
    DNSProvider("quad9", "Quad9", "9.9.9.9", CATEGORY_EXTRA, "149.112.112.112",
                note="Blocks known-malicious domains"),
    DNSProvider("quad9-unsecured", "Quad9 Unfiltered", "9.9.9.10", CATEGORY_EXTRA,
                "149.112.112.10", note="Quad9 with the blocklist removed"),
    DNSProvider("adguard", "AdGuard", "94.140.14.14", CATEGORY_EXTRA, "94.140.15.15",
                note="Ad and tracker filtering"),
    DNSProvider("adguard-family", "AdGuard Family", "94.140.14.15", CATEGORY_EXTRA, "94.140.15.16",
                note="Ad filtering plus safe search and adult-content blocking"),
    DNSProvider("adguard-nonfiltering", "AdGuard Unfiltered", "94.140.14.140", CATEGORY_EXTRA,
                "94.140.14.141", note="AdGuard with no filtering at all"),
    DNSProvider("cleanbrowsing", "CleanBrowsing", "185.228.168.9", CATEGORY_EXTRA, "185.228.169.9",
                note="Blocks malware and phishing"),
    DNSProvider("cleanbrowsing-family", "CleanBrowsing Family", "185.228.168.168", CATEGORY_EXTRA,
                "185.228.169.168", note="Family filter: adult content, proxies and VPNs"),
    DNSProvider("nextdns", "NextDNS", "45.90.28.0", CATEGORY_EXTRA, "45.90.30.0",
                note="Configurable filtering; a profile id is needed for custom rules"),
    DNSProvider("mullvad", "Mullvad", "194.242.2.2", CATEGORY_EXTRA, "194.242.2.4",
                note="No-log, no-filter resolver (default + base endpoints)"),
    DNSProvider("opendns-family", "OpenDNS FamilyShield", "208.67.222.123", CATEGORY_EXTRA,
                "208.67.220.123", note="OpenDNS with adult content blocked"),
    DNSProvider("yandex-safe", "Yandex Safe", "77.88.8.88", CATEGORY_EXTRA, "77.88.8.2",
                note="Yandex with fraud and infected-site blocking"),
    DNSProvider("yandex-family", "Yandex Family", "77.88.8.7", CATEGORY_EXTRA, "77.88.8.3",
                note="Yandex with adult content blocked"),
    DNSProvider("alibaba", "Alibaba", "223.5.5.5", CATEGORY_EXTRA, "223.6.6.6",
                note="Domestic resolver inside the GFW"),
    DNSProvider("tencent", "Tencent", "119.29.29.29", CATEGORY_EXTRA, "182.254.116.116",
                note="Domestic resolver inside the GFW"),
    DNSProvider("114dns", "114DNS", "114.114.114.114", CATEGORY_EXTRA, "114.114.115.115",
                note="Domestic resolver inside the GFW"),
)

_BY_KEY = {p.key: p for p in DNS_CATALOG}
_BY_IP: dict[str, DNSProvider] = {}
for _p in DNS_CATALOG:
    for _ip in _p.servers:
        _BY_IP.setdefault(_ip, _p)


def providers(category: str | None = None) -> list[DNSProvider]:
    """Return the catalogue, optionally filtered to one category."""
    if category is None:
        return list(DNS_CATALOG)
    wanted = category.strip().lower()
    return [p for p in DNS_CATALOG if p.category == wanted]


def provider_keys() -> list[str]:
    return [p.key for p in DNS_CATALOG]


def find(query: str) -> DNSProvider | None:
    """Look a provider up by key, display name, or either of its addresses."""
    if not query:
        return None
    needle = query.strip().lower()
    if needle in _BY_KEY:
        return _BY_KEY[needle]
    for prov in DNS_CATALOG:
        if prov.name.lower() == needle:
            return prov
    if needle in _BY_IP:
        return _BY_IP[needle]
    return None


def is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def active_provider(servers: list[str] | None = None) -> DNSProvider | None:
    """Which catalogue entry, if any, the system is currently using."""
    current = servers if servers is not None else current_servers()
    for server in current:
        prov = _BY_IP.get(server)
        if prov is not None:
            return prov
    return None


# ──────────────────────────── Results ────────────────────────────────────────


@dataclass
class DNSApplyResult:
    """Outcome of an apply/restore. Never raises - reports."""

    ok: bool
    detail: str = ""
    provider: str = ""
    applied: tuple[str, ...] = ()
    previous: tuple[str, ...] = ()
    adapter: str | None = None

    def __bool__(self) -> bool:  # lets `if engine.apply(...)` read naturally
        return self.ok


# ──────────────────────────── Platform backends ──────────────────────────────


def _run(command: list[str], timeout: float = 12.0) -> tuple[int, str]:
    """Run a command, returning (returncode, combined output)."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors="ignore",
            timeout=timeout,
        )
        return result.returncode, (result.stdout or "") + (result.stderr or "")
    except FileNotFoundError:
        return 127, f"{command[0]} not found"
    except subprocess.TimeoutExpired:
        return 124, f"{command[0]} timed out"
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, str(exc)


def _is_admin() -> bool:
    try:
        from .proxy_manager import is_admin

        return bool(is_admin())
    except Exception:
        return False


def active_adapters() -> list[str]:
    """Names of adapters that are up, excluding loopback/virtual filters."""
    if sys.platform == "win32":
        code, out = _run([
            "powershell", "-NoProfile", "-Command",
            "(Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and "
            "$_.Name -notlike '*Loopback*' }).Name",
        ])
        if code == 0:
            return [line.strip() for line in out.splitlines() if line.strip()]
        return []
    if sys.platform == "darwin":
        code, out = _run(["networksetup", "-listallnetworkservices"])
        if code == 0:
            lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
            # First line is a header; a disabled service is prefixed with '*'.
            return [ln for ln in lines[1:] if not ln.startswith("*")]
        return []
    return ["system"]


def current_servers() -> list[str]:
    """The resolvers the OS is using right now."""
    try:
        from .tools import get_system_dns_servers

        return list(get_system_dns_servers())
    except Exception:
        return []


# -- Windows -----------------------------------------------------------------


def _apply_windows(servers: list[str], adapter: str | None) -> DNSApplyResult:
    targets = [adapter] if adapter else active_adapters()
    if not targets:
        return DNSApplyResult(False, "No active network adapter found.")
    if not _is_admin():
        return DNSApplyResult(
            False,
            "Changing DNS needs administrator rights. Re-run the terminal as "
            "Administrator (or use the elevated prompt) and try again.",
        )

    for name in targets:
        # `static` replaces the whole list, so the primary is written first and
        # the rest are appended by index. validate=no stops netsh from asking
        # "the configured DNS server is incorrect, continue?" on a terminal
        # that has no stdin.
        code, out = _run([
            "netsh", "interface", "ip", "set", "dns",
            f"name={name}", "static", servers[0], "validate=no",
        ])
        if code != 0:
            return DNSApplyResult(False, f"netsh failed on {name}: {out.strip()}", adapter=name)
        for index, server in enumerate(servers[1:], start=2):
            _run([
                "netsh", "interface", "ip", "add", "dns",
                f"name={name}", server, f"index={index}", "validate=no",
            ])
    return DNSApplyResult(True, f"Applied to {', '.join(targets)}.", adapter=adapter)


def _restore_windows(adapters: list[str]) -> DNSApplyResult:
    if not _is_admin():
        return DNSApplyResult(False, "Restoring DNS needs administrator rights.")
    targets = adapters or active_adapters()
    failures = []
    for name in targets:
        code, out = _run(["netsh", "interface", "ip", "set", "dns", f"name={name}", "dhcp"])
        if code != 0:
            failures.append(f"{name}: {out.strip()}")
    if failures:
        return DNSApplyResult(False, "; ".join(failures))
    return DNSApplyResult(True, f"Reset {len(targets)} adapter(s) to DHCP DNS.")


# -- Linux -------------------------------------------------------------------


def _linux_resolv_conf() -> Path:
    return Path("/etc/resolv.conf")


def _apply_linux(servers: list[str], adapter: str | None) -> DNSApplyResult:
    if not _is_admin():
        return DNSApplyResult(False, "Writing /etc/resolv.conf needs root (try sudo).")
    path = _linux_resolv_conf()
    try:
        backup = path.read_bytes()
    except OSError as exc:
        return DNSApplyResult(False, f"Could not read {path}: {exc}")

    # systemd-resolved owns resolv.conf as a symlink; writing through it is
    # overwritten within seconds, so talk to resolvectl when it is present.
    code, _ = _run(["systemctl", "is-active", "--quiet", "systemd-resolved"], timeout=5)
    if code == 0:
        for iface in ("", adapter or ""):
            args = ["resolvectl", "dns"] + ([iface] if iface else []) + list(servers)
            code, out = _run(args)
            if code == 0:
                return DNSApplyResult(True, "Applied via systemd-resolved (resolvectl).", adapter=adapter)
        _log.debug("resolvectl failed; falling back to resolv.conf")

    body = ["# Written by Blackout Kit dns engine", "# original saved to ~/.blackout-kit/dns_state.json"]
    body += [f"nameserver {server}" for server in servers]
    body.append("options timeout:2 attempts:2")
    try:
        path.write_text("\n".join(body) + "\n", encoding="utf-8")
    except OSError as exc:
        return DNSApplyResult(False, f"Could not write {path}: {exc}")

    _save_backup_bytes(backup)
    return DNSApplyResult(True, f"Wrote {path} with {len(servers)} nameserver(s).", adapter=adapter)


def _restore_linux(adapters: list[str]) -> DNSApplyResult:
    if not _is_admin():
        return DNSApplyResult(False, "Restoring DNS needs root.")
    code, _ = _run(["systemctl", "is-active", "--quiet", "systemd-resolved"], timeout=5)
    if code == 0:
        code, out = _run(["resolvectl", "revert"])
        if code == 0:
            return DNSApplyResult(True, "Reverted systemd-resolved DNS.")
        _log.debug("resolvectl revert failed: %s", out)
    original = _load_backup_bytes()
    if original is None:
        return DNSApplyResult(False, "No saved resolv.conf backup to restore.")
    try:
        _linux_resolv_conf().write_bytes(original)
    except OSError as exc:
        return DNSApplyResult(False, f"Could not restore {_linux_resolv_conf()}: {exc}")
    return DNSApplyResult(True, "Restored the previous /etc/resolv.conf.")


# -- macOS -------------------------------------------------------------------


def _apply_macos(servers: list[str], adapter: str | None) -> DNSApplyResult:
    targets = [adapter] if adapter else active_adapters()
    if not targets:
        return DNSApplyResult(False, "No network service found.")
    if not _is_admin():
        return DNSApplyResult(False, "Changing DNS needs sudo on macOS.")
    for service in targets:
        code, out = _run(["networksetup", "-setdnsservers", service, *servers])
        if code != 0:
            return DNSApplyResult(False, f"networksetup failed on {service}: {out.strip()}", adapter=service)
    return DNSApplyResult(True, f"Applied to {', '.join(targets)}.", adapter=adapter)


def _restore_macos(adapters: list[str]) -> DNSApplyResult:
    if not _is_admin():
        return DNSApplyResult(False, "Restoring DNS needs sudo on macOS.")
    targets = adapters or active_adapters()
    for service in targets:
        _run(["networksetup", "-setdnsservers", service, "Empty"])
    return DNSApplyResult(True, f"Cleared DNS on {len(targets)} service(s).")


# ──────────────────────────── State (for restore) ────────────────────────────


def _state_path() -> Path:
    return STATE_FILE


def _save_state(payload: dict) -> None:
    try:
        APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
        tmp = STATE_FILE.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp.replace(STATE_FILE)
    except OSError as exc:
        _log.warning("Could not persist DNS state: %s", exc)


def load_state() -> dict:
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _backup_path() -> Path:
    return APP_DATA_DIR / "resolv.conf.bak"


def _save_backup_bytes(data: bytes) -> None:
    try:
        APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
        _backup_path().write_bytes(data)
    except OSError as exc:
        _log.warning("Could not save resolv.conf backup: %s", exc)


def _load_backup_bytes() -> bytes | None:
    try:
        return _backup_path().read_bytes()
    except OSError:
        return None


# ──────────────────────────── The engine ─────────────────────────────────────


class DNSEngine:
    """Apply a resolver pair to the system, and put it back afterwards.

    Usage::

        engine = DNSEngine()
        engine.apply("shecan")        # both Shecan addresses, in order
        engine.current_servers()      # ['178.22.122.100', '185.51.200.2']
        engine.restore()              # back to DHCP / the saved resolv.conf
    """

    name = "dns"
    description = "Switch the system resolver to a curated pair, and restore it"

    # ── catalogue ────────────────────────────────────────────────────
    def providers(self, category: str | None = None) -> list[DNSProvider]:
        return providers(category)

    def find(self, query: str) -> DNSProvider | None:
        return find(query)

    def categories(self) -> list[tuple[str, str, list[DNSProvider]]]:
        """[(category, label, providers)] in display order."""
        return [
            (cat, CATEGORY_LABELS[cat], providers(cat))
            for cat in CATEGORY_ORDER
            if providers(cat)
        ]

    # ── state ────────────────────────────────────────────────────────
    def current_servers(self) -> list[str]:
        return current_servers()

    def active(self) -> DNSProvider | None:
        return active_provider(self.current_servers())

    def state(self) -> dict:
        return load_state()

    # ── actions ──────────────────────────────────────────────────────
    def apply(self, query: str, adapter: str | None = None) -> DNSApplyResult:
        """Apply a catalogue provider (by key/name/IP) or a raw IP list.

        ``query`` may be a catalogue key, a display name, a single IP
        (secondary left untouched), or "ip1,ip2".
        """
        servers, label = self._resolve_target(query)
        if not servers:
            return DNSApplyResult(
                False,
                f"Unknown DNS provider '{query}'. Try one of: {', '.join(provider_keys())}",
            )

        previous = self.current_servers()
        if previous == servers:
            return DNSApplyResult(
                True,
                "Already using these resolvers - nothing to change.",
                provider=label,
                applied=tuple(servers),
                previous=tuple(previous),
                adapter=adapter,
            )

        _save_state({
            "previous": previous,
            "applied": servers,
            "provider": label,
            "adapters": [adapter] if adapter else active_adapters(),
            "timestamp": time.time(),
            "platform": sys.platform,
        })

        result = self._dispatch_apply(servers, adapter)
        result.provider = label
        result.applied = tuple(servers)
        result.previous = tuple(previous)
        if result.ok:
            _log.info("DNS set to %s (%s)", label, ", ".join(servers))
        else:
            _log.warning("DNS apply failed: %s", result.detail)
        return result

    def restore(self) -> DNSApplyResult:
        """Undo the last apply: DHCP on Windows, the saved file elsewhere."""
        state = load_state()
        adapters = [a for a in state.get("adapters", []) if isinstance(a, str)]
        result = self._dispatch_restore(adapters)
        if result.ok:
            _save_state({})
            _log.info("DNS restored.")
        return result

    def flush(self) -> bool:
        try:
            from .tools import flush_dns

            return bool(flush_dns())
        except Exception as exc:
            _log.warning("DNS flush failed: %s", exc)
            return False

    def benchmark(self, domain: str = "www.google.com", repeat: int = 2):
        """Latency for every catalogue entry. Returns [(name, ip, ms)]."""
        try:
            from .tools import _dns_query

            rows = []
            for prov in DNS_CATALOG:
                samples = []
                for _ in range(max(1, repeat)):
                    start = time.monotonic()
                    if _dns_query(prov.primary, domain) is not None:
                        samples.append((time.monotonic() - start) * 1000.0)
                if samples:
                    rows.append((prov.name, prov.primary, round(sum(samples) / len(samples), 1)))
            rows.sort(key=lambda row: row[2])
            return rows
        except Exception as exc:
            _log.warning("DNS benchmark failed: %s", exc)
            return []

    # ── internals ────────────────────────────────────────────────────
    def _resolve_target(self, query: str) -> tuple[list[str], str]:
        raw = (query or "").strip()
        if not raw:
            return [], ""

        prov = find(raw)
        if prov is not None:
            return list(prov.servers), prov.describe()

        if "," in raw or " " in raw:
            parts = [p for p in raw.replace(",", " ").split() if p]
            if all(is_ip_literal(p) for p in parts):
                return parts, ", ".join(parts)
            return [], ""

        if is_ip_literal(raw):
            return [raw], raw
        return [], ""

    def _dispatch_apply(self, servers: list[str], adapter: str | None) -> DNSApplyResult:
        if sys.platform == "win32":
            return _apply_windows(servers, adapter)
        if sys.platform == "darwin":
            return _apply_macos(servers, adapter)
        return _apply_linux(servers, adapter)

    def _dispatch_restore(self, adapters: list[str]) -> DNSApplyResult:
        if sys.platform == "win32":
            return _restore_windows(adapters)
        if sys.platform == "darwin":
            return _restore_macos(adapters)
        return _restore_linux(adapters)


# ──────────────────────────── Convenience ────────────────────────────────────


def apply_provider(query: str, adapter: str | None = None) -> DNSApplyResult:
    return DNSEngine().apply(query, adapter=adapter)


def restore_system_dns() -> DNSApplyResult:
    return DNSEngine().restore()


__all__ = [
    "CATEGORY_EXTRA",
    "CATEGORY_LABELS",
    "CATEGORY_ORDER",
    "CATEGORY_SANCTIONS",
    "CATEGORY_SPEED",
    "DNSApplyResult",
    "DNS_CATALOG",
    "DNSEngine",
    "DNSProvider",
    "active_provider",
    "active_adapters",
    "apply_provider",
    "current_servers",
    "find",
    "is_ip_literal",
    "load_state",
    "provider_keys",
    "providers",
    "restore_system_dns",
]
