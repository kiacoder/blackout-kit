"""Threat intelligence feed management and safe local indicator storage."""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import tempfile
import threading
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Set
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)
_STATE_LOCK = threading.Lock()
_MAX_FEED_BYTES = 10 * 1024 * 1024
_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _normalize_domain(value: object) -> Optional[str]:
    if not isinstance(value, str):
        return None
    domain = value.strip().casefold().rstrip(".")
    if not domain or len(domain) > 253 or "/" in domain or ":" in domain:
        return None
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        return None
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if not _validate_domain_text(domain):
        return None
    return domain


def _validate_domain_text(domain: str) -> bool:
    if not domain or len(domain) > 253 or domain.startswith(".") or domain.endswith("."):
        return False
    labels = domain.split(".")
    return len(labels) >= 2 and all(_DOMAIN_LABEL.fullmatch(label) for label in labels)


def _indicator_path(config_dir: Optional[Path] = None) -> Path:
    directory = config_dir or Path.home() / ".blackout-kit" / "threat-feeds"
    return Path(directory) / "blocked_domains.json"


def load_domain_indicators(config_dir: Optional[Path] = None) -> Set[str]:
    """Load normalized domain indicators; malformed state fails closed for this source."""
    path = _indicator_path(config_dir)
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return set()
    if not isinstance(data, list):
        return set()
    return {
        normalized
        for value in data
        if (normalized := _normalize_domain(value)) is not None
    }


@dataclass
class ThreatFeed:
    """Configuration for an HTTP(S) threat feed source."""

    name: str
    url: str
    feed_type: str
    enabled: bool = True
    last_updated: Optional[str] = None
    entry_count: int = 0


class ThreatFeedsManager:
    """Manage threat intelligence feeds and local indicator snapshots."""

    DEFAULT_FEEDS = [
        ThreatFeed(
            name="abuse.ch-ips",
            url="https://sslbl.abuse.ch/blacklist/",
            feed_type="ip",
        ),
        ThreatFeed(
            name="phishtank-domains",
            url="https://data.phishtank.com/data/online-valid.json",
            feed_type="domain",
        ),
        ThreatFeed(
            name="emergingthreats-ips",
            url="https://rules.emergingthreats.net/blockips/compromised-ips.txt",
            feed_type="ip",
        ),
    ]

    def __init__(self, config_dir: Optional[Path] = None):
        self.config_dir = Path(
            config_dir or Path.home() / ".blackout-kit" / "threat-feeds"
        )
        self.config_dir.mkdir(parents=True, exist_ok=True)

        self.feeds_config = self.config_dir / "feeds.json"
        self.blocked_ips = self.config_dir / "blocked_ips.json"
        self.blocked_domains = self.config_dir / "blocked_domains.json"
        self.feed_indicators = self.config_dir / "feed_indicators.json"
        self.custom_ips_file = self.config_dir / "custom_ips.json"
        self.custom_domains_file = self.config_dir / "custom_domains.json"

        self.feeds: dict[str, ThreatFeed] = {}
        self.ip_set: Set[str] = set()
        self.domain_set: Set[str] = set()
        self.custom_ips: Set[str] = set()
        self.custom_domains: Set[str] = set()
        self._feed_indicators: dict[str, dict[str, Set[str]]] = {}

        self._load_feeds()
        self._load_blocked()
        self._rebuild_indicator_sets()

    @staticmethod
    def _read_json(path: Path) -> object:
        try:
            return json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError):
            return None

    @staticmethod
    def _atomic_json_write(path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{path.name}-", suffix=".tmp", dir=path.parent
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(value, handle, indent=2, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        except OSError:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise

    def add_feed(self, feed: ThreatFeed) -> bool:
        """Add a validated threat feed."""
        if not isinstance(feed, ThreatFeed):
            return False
        feed.name = str(feed.name).strip()
        feed.feed_type = str(feed.feed_type).casefold().strip()
        feed.url = str(feed.url).strip()
        if not self._validate_feed(feed) or feed.name in self.feeds:
            logger.warning("Invalid or duplicate threat feed configuration: %s", feed.name)
            return False
        self.feeds[feed.name] = feed
        self._save_feeds()
        return True

    def remove_feed(self, feed_name: str) -> bool:
        """Remove a feed and its owned indicators."""
        if feed_name not in self.feeds:
            return False
        del self.feeds[feed_name]
        self._feed_indicators.pop(feed_name, None)
        self._rebuild_indicator_sets()
        self._save_feeds()
        self._save_blocked()
        return True

    def list_feeds(self) -> list[ThreatFeed]:
        return list(self.feeds.values())

    def update_feeds(self) -> dict[str, bool]:
        """Update enabled feeds while preserving the last good snapshot on failure."""
        results: dict[str, bool] = {}
        for name, feed in list(self.feeds.items()):
            if not feed.enabled:
                self._feed_indicators.pop(name, None)
                results[name] = False
                continue
            try:
                results[name] = self._fetch_feed(feed)
            except Exception as exc:
                logger.error("Failed to update feed %s: %s", name, exc)
                results[name] = False
        self._rebuild_indicator_sets()
        self._save_blocked()
        return results

    def is_ip_blocked(self, ip: str) -> bool:
        """Check whether an exact normalized IP indicator is present."""
        try:
            normalized = str(ip).strip()
            return str(ipaddress.ip_address(normalized)) in self.ip_set
        except ValueError:
            return False

    def is_domain_blocked(self, domain: str) -> bool:
        """Check whether an exact normalized domain indicator is present."""
        normalized = _normalize_domain(domain)
        return normalized in self.domain_set if normalized else False

    def add_custom_ip(self, ip: str) -> bool:
        """Add a custom IP indicator."""
        normalized = self._normalize_ip(ip)
        if normalized is None or normalized in self.custom_ips:
            return False
        self.custom_ips.add(normalized)
        self._rebuild_indicator_sets()
        self._save_blocked()
        return True

    def add_custom_domain(self, domain: str) -> bool:
        """Add a custom domain indicator."""
        normalized = _normalize_domain(domain)
        if normalized is None or normalized in self.custom_domains:
            return False
        self.custom_domains.add(normalized)
        self._rebuild_indicator_sets()
        self._save_blocked()
        return True

    def get_stats(self) -> dict:
        return {
            "total_feeds": len(self.feeds),
            "enabled_feeds": sum(1 for feed in self.feeds.values() if feed.enabled),
            "blocked_ips": len(self.ip_set),
            "blocked_domains": len(self.domain_set),
            "last_update": max(
                (feed.last_updated for feed in self.feeds.values() if feed.last_updated),
                default="never",
            ),
        }

    def _fetch_feed(self, feed: ThreatFeed) -> bool:
        """Fetch and atomically replace one feed's indicator snapshot."""
        logger.info("Updating feed: %s", feed.name)
        try:
            response = httpx.get(feed.url, timeout=30)
            response.raise_for_status()
            content = response.text
            if len(content.encode("utf-8", errors="replace")) > _MAX_FEED_BYTES:
                logger.error("Feed %s exceeded the response size limit", feed.name)
                return False
            if feed.feed_type == "ip":
                indicators = self._parse_ip_values(content)
            else:
                indicators = self._parse_domain_values(content)
            if not indicators:
                logger.warning("Feed %s contained no valid indicators", feed.name)
                return False
            self._feed_indicators[feed.name] = {
                "ips": indicators if feed.feed_type == "ip" else set(),
                "domains": indicators if feed.feed_type == "domain" else set(),
            }
            feed.last_updated = datetime.now(timezone.utc).isoformat()
            feed.entry_count = len(indicators)
            self._save_feeds()
            self._rebuild_indicator_sets()
            self._save_blocked()
            logger.info("Feed %s updated: %d entries", feed.name, len(indicators))
            return True
        except (httpx.RequestError, httpx.HTTPStatusError) as exc:
            logger.error("Failed to fetch feed %s: %s", feed.name, exc)
            return False

    def _parse_ip_values(self, content: str) -> Set[str]:
        values: Set[str] = set()
        for raw_line in content.lstrip("﻿").splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            tokens = [token.strip() for token in re.split(r"[,\s]+", line) if token.strip()]
            candidate = tokens[0] if tokens else ""
            normalized = self._normalize_ip(candidate)
            if normalized is not None:
                values.add(normalized)
        return values

    def _parse_domain_values(self, content: str) -> Set[str]:
        values: Set[str] = set()
        text = content.lstrip("﻿").strip()
        if text.startswith("["):
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                data = None
            if isinstance(data, list):
                for entry in data:
                    candidate = entry.get("url") if isinstance(entry, dict) else entry
                    domain = self._extract_domain(candidate)
                    if domain:
                        values.add(domain)
                return values

        for raw_line in content.lstrip("﻿").splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            tokens = line.split()
            if len(tokens) > 1 and self._normalize_ip(tokens[0]) is not None:
                candidates = tokens[1:]
            else:
                candidates = [tokens[0]] if tokens else []
            for candidate in candidates:
                domain = self._extract_domain(candidate)
                if domain:
                    values.add(domain)
        return values

    def _parse_ip_feed(self, content: str, feed_name: str) -> int:
        """Parse an IP feed and merge its valid indicators into the current set."""
        values = self._parse_ip_values(content)
        self.ip_set.update(values)
        return len(values)

    def _parse_domain_feed(self, content: str, feed_name: str) -> int:
        """Parse a JSON, hosts-format, or one-domain-per-line feed."""
        values = self._parse_domain_values(content)
        self.domain_set.update(values)
        return len(values)

    def _extract_domain(self, url_or_domain: object) -> Optional[str]:
        """Return a normalized hostname without credentials, ports, or paths."""
        if not isinstance(url_or_domain, str):
            return None
        value = url_or_domain.strip()
        if not value:
            return None
        if value.casefold().startswith(("http://", "https://")):
            try:
                parsed = urlparse(value)
                if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname:
                    return None
                return _normalize_domain(parsed.hostname)
            except ValueError:
                return None
        return _normalize_domain(value)

    def _validate_feed(self, feed: ThreatFeed) -> bool:
        if not feed.name or feed.feed_type not in {"ip", "domain"}:
            return False
        parsed = urlparse(feed.url)
        return (
            parsed.scheme.casefold() == "https"
            and bool(parsed.hostname)
            and parsed.username is None
            and parsed.password is None
        )

    @staticmethod
    def _normalize_ip(ip: object) -> Optional[str]:
        if not isinstance(ip, str):
            return None
        candidate = ip.strip()
        try:
            if "/" in candidate:
                network = ipaddress.ip_network(candidate, strict=False)
                return str(network.network_address)
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            return None

    def _validate_ip(self, ip: str) -> bool:
        return self._normalize_ip(ip) is not None

    def _validate_domain(self, domain: str) -> bool:
        return _normalize_domain(domain) is not None

    def _load_feeds(self) -> None:
        data = self._read_json(self.feeds_config) if self.feeds_config.exists() else None
        if isinstance(data, list):
            for raw_feed in data:
                if not isinstance(raw_feed, dict):
                    continue
                try:
                    feed = ThreatFeed(
                        name=str(raw_feed.get("name", "")).strip(),
                        url=str(raw_feed.get("url", "")).strip(),
                        feed_type=str(raw_feed.get("feed_type", "")).casefold().strip(),
                        enabled=bool(raw_feed.get("enabled", True)),
                        last_updated=(
                            str(raw_feed["last_updated"])
                            if raw_feed.get("last_updated") is not None
                            else None
                        ),
                        entry_count=max(0, int(raw_feed.get("entry_count", 0))),
                    )
                except (TypeError, ValueError):
                    continue
                if self._validate_feed(feed) and feed.name not in self.feeds:
                    self.feeds[feed.name] = feed
        if not self.feeds:
            self.feeds = {feed.name: replace(feed) for feed in self.DEFAULT_FEEDS}
            self._save_feeds()

    @staticmethod
    def _normalized_set(data: object, normalizer) -> Set[str]:
        if not isinstance(data, list):
            return set()
        return {
            normalized
            for value in data
            if (normalized := normalizer(value)) is not None
        }

    def _load_blocked(self) -> None:
        raw_ips = self._normalized_set(self._read_json(self.blocked_ips), self._normalize_ip)
        raw_domains = self._normalized_set(
            self._read_json(self.blocked_domains), _normalize_domain
        )
        loaded_custom_ips = self._normalized_set(
            self._read_json(self.custom_ips_file), self._normalize_ip
        )
        loaded_custom_domains = self._normalized_set(
            self._read_json(self.custom_domains_file), _normalize_domain
        )
        if self.custom_ips_file.exists():
            self.custom_ips = loaded_custom_ips
        elif self.feed_indicators.exists():
            self.custom_ips = set()
        else:
            self.custom_ips = raw_ips
        if self.custom_domains_file.exists():
            self.custom_domains = loaded_custom_domains
        elif self.feed_indicators.exists():
            self.custom_domains = set()
        else:
            self.custom_domains = raw_domains

        data = self._read_json(self.feed_indicators)
        if isinstance(data, dict):
            for name, indicators in data.items():
                if not isinstance(indicators, dict):
                    continue
                self._feed_indicators[str(name)] = {
                    "ips": self._normalized_set(indicators.get("ips"), self._normalize_ip),
                    "domains": self._normalized_set(
                        indicators.get("domains"), _normalize_domain
                    ),
                }

    def _rebuild_indicator_sets(self) -> None:
        self.ip_set = set(self.custom_ips)
        self.domain_set = set(self.custom_domains)
        for name, indicators in self._feed_indicators.items():
            feed = self.feeds.get(name)
            if feed is None or not feed.enabled:
                continue
            self.ip_set.update(indicators.get("ips", set()))
            self.domain_set.update(indicators.get("domains", set()))

    def _save_feeds(self) -> None:
        with _STATE_LOCK:
            self._atomic_json_write(
                self.feeds_config, [asdict(feed) for feed in self.feeds.values()]
            )

    def _save_blocked(self) -> None:
        with _STATE_LOCK:
            self._atomic_json_write(self.blocked_ips, sorted(self.ip_set))
            self._atomic_json_write(self.blocked_domains, sorted(self.domain_set))
            self._atomic_json_write(self.custom_ips_file, sorted(self.custom_ips))
            self._atomic_json_write(self.custom_domains_file, sorted(self.custom_domains))
            self._atomic_json_write(
                self.feed_indicators,
                {
                    name: {
                        "ips": sorted(indicators.get("ips", set())),
                        "domains": sorted(indicators.get("domains", set())),
                    }
                    for name, indicators in self._feed_indicators.items()
                    if name in self.feeds
                },
            )

    def clear_all(self) -> None:
        """Clear all threat data and configured feeds."""
        self.ip_set.clear()
        self.domain_set.clear()
        self.custom_ips.clear()
        self.custom_domains.clear()
        self._feed_indicators.clear()
        self.feeds.clear()
        self._save_blocked()
        self._save_feeds()
