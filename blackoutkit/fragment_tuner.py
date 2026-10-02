"""
Blackout Kit - TLS fragment tuning paired with clean-IP scanning.

Picks the TLS record fragmentation that actually completes a handshake against
a specific clean Cloudflare endpoint: for each candidate `xray_fragment` value
a short-lived Xray instance is launched with a minimal probe config (HTTP
inbound → freedom outbound pinned to the target IP with a fake-SNI TLS
stream), one HTTP request is pushed through it, and success/latency is
recorded. The winning (IP, fragment) pair can then be applied to settings so
the normal connect pipeline picks both up.

Honesty boundary: a probe measures whether one HTTP request over one TLS
handshake succeeded and how long it took, at one moment, from one network.
It is not a guarantee of bypass success or sustained throughput; carriers
may throttle patterns differently over time.
"""
from __future__ import annotations

import json
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from . import settings as cfg
from .engines.base import BINS_DIR
from .engines.xray import XRAY_BIN_NAMES

DEFAULT_CANDIDATES: tuple[str, ...] = ("", "10-20,30-40", "10-50,10-50", "5-10,20-30")

DEFAULT_PROBE_TIMEOUT = 8.0
_DEFAULT_HTTP_PORT = 18443
_STARTUP_WAIT_SECONDS = 6.0


@dataclass(frozen=True)
class ProbeOutcome:
    """One fragment candidate measured against one target IP."""

    fragment: str
    ok: bool
    latency_ms: float | None
    detail: str


@dataclass(frozen=True)
class TuneResult:
    target_ip: str
    fake_sni: str
    outcomes: tuple[ProbeOutcome, ...]

    @property
    def winner(self) -> ProbeOutcome | None:
        successful = [outcome for outcome in self.outcomes if outcome.ok]
        if not successful:
            return None
        # Stable tiebreak: candidate order (simplest configuration first).
        return min(successful, key=lambda outcome: outcome.latency_ms or 0.0)


def find_xray_binary() -> Path | None:
    for name in XRAY_BIN_NAMES:
        candidate = BINS_DIR / name
        if candidate.is_file():
            return candidate
    return None


def validate_fragment(value: str) -> str | None:
    """Mirror the settings validator: empty or exactly 'range,range'."""
    if value == "":
        return None
    if value.count(",") != 1:
        return "fragment must be empty or 'range,range' (e.g. 10-20,30-40)"
    for part in value.split(","):
        part = part.strip()
        if not part or "-" not in part:
            return f"fragment range part '{part}' must look like '10-20'"
        low_high = part.split("-", 1)
        if not all(side.strip().isdigit() for side in low_high):
            return f"fragment range '{part}' must use numbers"
    return None


def build_probe_config(target_ip: str, fake_sni: str, http_port: int, fragment: str) -> dict[str, Any]:
    """Minimal Xray config: one HTTP inbound → pinned TLS freedom outbound.

    The TLS handshake originates inside Xray so the candidate fragmentation
    actually applies to the ClientHello, mirroring the live engine path.
    """
    if validate_fragment(fragment):
        raise ValueError(f"invalid fragment setting: {fragment!r}")
    direct_outbound: dict[str, Any] = {
        "tag": "probe-direct",
        "protocol": "freedom",
        "settings": {"address": target_ip, "port": 443},
        "streamSettings": {
            "network": "tcp",
            "security": "tls",
            "tlsSettings": {
                "serverName": fake_sni,
                # Certificate verification stays ON: recent Xray removed
                # allowInsecure outright, and a Cloudflare-fronted fake SNI
                # serves a valid certificate for that name anyway. SNIs whose
                # certificates cannot verify fail the probe honestly.
            },
        },
    }
    outbounds: list[dict[str, Any]] = []
    if fragment:
        length, interval = (part.strip() for part in fragment.split(","))
        outbounds.append({
            "tag": "fragment-out",
            "protocol": "freedom",
            "settings": {
                "fragment": {"packets": "tlshello", "length": length, "interval": interval},
            },
        })
        direct_outbound["streamSettings"]["sockopt"] = {"dialerProxy": "fragment-out"}
    outbounds.append(direct_outbound)
    return {
        "log": {"loglevel": "error", "access": "none", "error": "none"},
        "inbounds": [{
            "tag": "probe-in",
            "port": http_port,
            "listen": "127.0.0.1",
            "protocol": "http",
            "settings": {},
        }],
        "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs"},
    }


def _wait_for_port(port: int, *, deadline_seconds: float) -> bool:
    deadline = time.monotonic() + deadline_seconds
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.25)
            try:
                sock.connect(("127.0.0.1", port))
                return True
            except OSError:
                time.sleep(0.1)
    return False


def probe_fragment(
    xray_bin: Path,
    config: dict[str, Any],
    fragment: str,
    *,
    timeout: float = DEFAULT_PROBE_TIMEOUT,
    request_via_proxy: Callable[[int, str, float], tuple[bool, float]] | None = None,
) -> ProbeOutcome:
    """Launch one short-lived Xray with `config` and push one request through.

    `request_via_proxy(http_port, host, timeout)` returns (ok, latency_ms) and
    is injectable for tests; the default performs an HTTP GET to the fake SNI
    through the local probe inbound.
    """
    import os

    http_port = int(config["inbounds"][0]["port"])
    direct = next(
        (outbound for outbound in config.get("outbounds", []) if outbound.get("tag") == "probe-direct"),
        {},
    )
    probe_host = direct.get("streamSettings", {}).get("tlsSettings", {}).get("serverName", "")

    config_file = None
    process = None
    try:
        handle = tempfile.NamedTemporaryFile(
            prefix="blackout-fragment-probe-", suffix=".json", delete=False
        )
        config_file = Path(handle.name)
        handle.write(json.dumps(config).encode("utf-8"))
        handle.close()

        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        try:
            process = subprocess.Popen(
                [str(xray_bin), "run", "-c", str(config_file)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=creationflags,
            )
        except OSError as exc:
            return ProbeOutcome(fragment, False, None, f"Xray could not start: {exc}")

        if not _wait_for_port(http_port, deadline_seconds=_STARTUP_WAIT_SECONDS):
            return ProbeOutcome(fragment, False, None, "Xray probe inbound did not open")

        getter = request_via_proxy or _default_request_via_proxy
        started = time.monotonic()
        try:
            ok, _latency = getter(http_port, probe_host, timeout)
        except Exception as exc:
            return ProbeOutcome(fragment, False, None, f"probe request failed: {exc}")
        latency = (time.monotonic() - started) * 1000
        label = fragment or "no fragmentation"
        if ok:
            return ProbeOutcome(fragment, True, round(latency, 1), f"handshake+request ok ({label})")
        return ProbeOutcome(fragment, False, None, f"request did not complete ({label})")
    finally:
        if process is not None:
            try:
                process.terminate()
                process.wait(timeout=3)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass
        if config_file is not None:
            try:
                config_file.unlink(missing_ok=True)
            except OSError:
                pass


def _default_request_via_proxy(http_port: int, host: str, timeout: float) -> tuple[bool, float]:
    import httpx

    proxy_url = f"http://127.0.0.1:{http_port}"
    with httpx.Client(proxy=proxy_url, timeout=timeout) as client:
        response = client.get(f"http://{host}/", headers={"Host": host, "User-Agent": "blackout-kit/fragment-probe"})
        return response.status_code < 500, response.elapsed.total_seconds() * 1000 if hasattr(response, "elapsed") else 0.0


def tune(
    target_ip: str,
    *,
    fake_sni: str | None = None,
    candidates: tuple[str, ...] | list[str] = DEFAULT_CANDIDATES,
    xray_bin: Path | None = None,
    request_via_proxy: Callable[[int, str, float], tuple[bool, float]] | None = None,
    prober: Callable[[str, dict[str, Any]], ProbeOutcome] | None = None,
) -> TuneResult:
    """Measure every candidate fragment against one clean IP; rank results.

    `prober(fragment, config)` is injectable for tests; by default a
    short-lived Xray process is launched per candidate.
    """
    resolved_sni = fake_sni or str(cfg.load().get("sni_fake_sni") or "www.hcaptcha.com")
    if prober is None:
        binary = xray_bin or find_xray_binary()
        if binary is None:
            raise FileNotFoundError("Xray core binary not found in bins/ — run: blackout bins download")

        def prober(fragment: str, config: dict[str, Any]) -> ProbeOutcome:
            return probe_fragment(binary, config, fragment, request_via_proxy=request_via_proxy)

    outcomes: list[ProbeOutcome] = []
    for index, candidate in enumerate(candidates):
        error = validate_fragment(candidate)
        if error:
            outcomes.append(ProbeOutcome(candidate, False, None, error))
            continue
        port = _DEFAULT_HTTP_PORT + index
        config = build_probe_config(target_ip, resolved_sni, port, candidate)
        outcomes.append(prober(candidate, config))
    return TuneResult(target_ip=target_ip, fake_sni=resolved_sni, outcomes=tuple(outcomes))


def resolve_target_ip(
    explicit: str | None = None,
    *,
    count: int = 20,
    scanner: Callable[[str | None, int], str | None] | None = None,
) -> str | None:
    """Explicit argument → cached best clean IP → fresh quick scan."""
    if explicit:
        return explicit
    if scanner is not None:
        return scanner(None, count)

    from .scanner import ip_scanner

    cached = ip_scanner.load_cache(max_age_hours=24)
    if cached:
        return cached[0][0]
    try:
        import asyncio

        ips = ip_scanner.generate_cloudflare_ips(count)
        results = asyncio.run(ip_scanner.scan_ips(ips, concurrency=20, timeout=2.0))
        return results[0][0] if results else None
    except Exception:
        return None


def apply_winner(target_ip: str, fragment: str, *, settings_set: Callable[[str, Any], Any] | None = None) -> None:
    """Bind the winning pair into settings so connect picks both up."""
    setter = settings_set or cfg.set_value
    setter("sni_connect_ip", target_ip)
    setter("xray_fragment", fragment)


__all__ = [
    "DEFAULT_CANDIDATES",
    "ProbeOutcome",
    "TuneResult",
    "apply_winner",
    "build_probe_config",
    "find_xray_binary",
    "probe_fragment",
    "resolve_target_ip",
    "tune",
    "validate_fragment",
]
