"""Live security observer (Roadmap Phase 6).

Bridges the daemon's traffic sampler to the two Phase 6 security engines so
they actually run against live connections instead of only being queryable:

* :class:`~blackoutkit.anomaly_detector.AnomalyDetector` — unusual connection
  patterns, exfiltration, C2-ish behaviour.
* :class:`~blackoutkit.threat_feeds.ThreatFeedsManager` — malicious IP/domain
  blocklists.

The observer is deliberately small and side-effect-scoped: for each sampled
connection it (a) feeds the anomaly detector and (b) checks the remote
endpoint against the blocklists, returning a list of *hits* and (optionally)
invoking an ``on_hit`` callback. It never blocks or drops traffic itself — it
records and reports; enforcement stays with the routing/firewall layer.

It is injectable (detector, feeds, clock, callback) so it can be unit-tested
without the daemon, the filesystem, or the network.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Callable, Optional

_log = logging.getLogger(__name__)


def split_endpoint(endpoint: object) -> tuple[str, Optional[int]]:
    """Split ``host``/``host:port``/``[v6]:port`` into ``(host, port|None)``."""
    text = str(endpoint or "").strip()
    if not text:
        return "", None
    if text.startswith("["):  # bracketed IPv6: [::1]:443
        host, _, rest = text[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else ""
        try:
            return host, int(port)
        except (TypeError, ValueError):
            return host, None
    if text.count(":") == 1:  # host:port (IPv4 / hostname)
        host, _, port = text.partition(":")
        try:
            return host, int(port)
        except (TypeError, ValueError):
            return text, None
    # Bare host, or a bare IPv6 literal with no port.
    return text, None


class SecurityObserver:
    """Feed live connection samples to the anomaly detector and threat feeds."""

    def __init__(
        self,
        *,
        detector: Any = None,
        threat_feeds: Any = None,
        on_hit: Optional[Callable[[dict[str, Any]], None]] = None,
        clock: Optional[Callable[[], float]] = None,
    ):
        if detector is None:
            from .anomaly_detector import AnomalyDetector

            detector = AnomalyDetector()
        if threat_feeds is None:
            from .threat_feeds import ThreatFeedsManager

            threat_feeds = ThreatFeedsManager()
        self._detector = detector
        self._threat_feeds = threat_feeds
        self._on_hit = on_hit
        self._clock = clock or time.time

    # ── public ──────────────────────────────────────────────────────────────

    def observe(self, entry: dict[str, Any]) -> list[dict[str, Any]]:
        """Process one traffic-log entry; return any anomaly/threat hits."""
        if not isinstance(entry, dict):
            return []
        hits: list[dict[str, Any]] = []
        hits.extend(self._check_anomaly(entry))
        hits.extend(self._check_threat(entry))
        for hit in hits:
            if self._on_hit is not None:
                try:
                    self._on_hit(hit)
                except Exception:  # a bad callback must not break monitoring
                    _log.debug("security observer on_hit callback failed", exc_info=True)
        return hits

    # ── internals ───────────────────────────────────────────────────────────

    def _check_anomaly(self, entry: dict[str, Any]) -> list[dict[str, Any]]:
        try:
            from .anomaly_detector import ConnectionEvent

            remote_host, remote_port = split_endpoint(entry.get("remote"))
            local_host, _ = split_endpoint(entry.get("local"))
            ts_value = entry.get("ts")
            event = ConnectionEvent(
                timestamp=float(ts_value if ts_value is not None else self._clock()),
                src_ip=local_host,
                dst_ip=remote_host,
                dst_port=remote_port or 0,
                protocol=str(entry.get("protocol", "tcp")),
                bytes_sent=int(entry.get("bytes_sent") or 0),
                bytes_received=int(entry.get("bytes_recv") or 0),
                state=str(entry.get("status", "established")).casefold(),
                process_name=entry.get("process"),
                bytes_available=bool(entry.get("bytes_available", True)),
            )
            anomaly = self._detector.detect(event)
        except Exception:
            _log.debug("anomaly detection failed for sample", exc_info=True)
            return []
        if anomaly is None:
            return []
        return [{
            "kind": "anomaly",
            "severity": getattr(anomaly, "severity", "unknown"),
            "type": getattr(anomaly, "anomaly_type", "unknown"),
            "detail": getattr(anomaly, "description", ""),
            "remote": entry.get("remote", ""),
            "process": entry.get("process", ""),
        }]

    def _check_threat(self, entry: dict[str, Any]) -> list[dict[str, Any]]:
        remote_host, _ = split_endpoint(entry.get("remote"))
        if not remote_host:
            return []
        try:
            blocked_ip = bool(self._threat_feeds.is_ip_blocked(remote_host))
            blocked_domain = False
            if not blocked_ip:
                blocked_domain = bool(self._threat_feeds.is_domain_blocked(remote_host))
        except Exception:
            _log.debug("threat-feed check failed for sample", exc_info=True)
            return []
        if not (blocked_ip or blocked_domain):
            return []
        return [{
            "kind": "threat",
            "severity": "high",
            "type": "blocked_ip" if blocked_ip else "blocked_domain",
            "detail": f"Connection to blocklisted {'IP' if blocked_ip else 'domain'} {remote_host}",
            "remote": entry.get("remote", ""),
            "process": entry.get("process", ""),
        }]
