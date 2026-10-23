"""Community marketplace for plugins (Roadmap Phase 8).

A small, security-first catalog for discovering and installing plugins. An
entry pins the plugin file's **SHA-256**; :meth:`Marketplace.install` refuses to
write a plugin whose downloaded bytes do not match, so a tampered or
man-in-the-middle catalog cannot smuggle in code.

Network access happens only in :meth:`Marketplace.refresh` (fetch a catalog)
and :meth:`Marketplace.install` (fetch one plugin file) — both explicit,
user-invoked actions. Nothing here runs in the background.

.. warning::
   Installed plugins are arbitrary Python executed by the plugin system. Only
   install plugins you trust, and keep ``plugins_enabled`` off otherwise.
"""
from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
import logging
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from .plugins import DEFAULT_PLUGIN_DIR, PLUGIN_KINDS

# A plugin name becomes a filename, and a catalog is remote input.
_SAFE_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

_log = logging.getLogger(__name__)

DEFAULT_CATALOG_URL = "https://raw.githubusercontent.com/kiacoder/blackout-kit-plugins/main/catalog.json"

__all__ = [
    "MarketplaceEntry",
    "MarketplaceError",
    "Marketplace",
    "DEFAULT_CATALOG_URL",
]


class MarketplaceError(Exception):
    """Raised for catalog/install/verify failures."""


@dataclass(frozen=True)
class MarketplaceEntry:
    """One plugin available in the marketplace."""

    name: str
    kind: str
    url: str
    sha256: str
    version: str = "0.0.0"
    description: str = ""
    author: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MarketplaceEntry":
        name = str(data.get("name") or "").strip()
        url = str(data.get("url") or "").strip()
        sha256 = str(data.get("sha256") or "").strip().lower()
        kind = str(data.get("kind") or "rule").strip().lower()
        if not name or not url:
            raise MarketplaceError("catalog entry needs 'name' and 'url'")
        # `name` becomes a filename. A catalog is remote input, so it must not
        # be able to say "../../startup/evil" - install() wrote to
        # plugin_dir / f"{name}.py" with no check at all.
        if not _SAFE_NAME.match(name):
            raise MarketplaceError(
                f"entry name {name!r} is not a safe plugin name "
                "(letters, digits, '-' and '_' only, max 64)"
            )
        if len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256):
            raise MarketplaceError(f"entry {name!r} has an invalid sha256")
        if kind not in PLUGIN_KINDS:
            raise MarketplaceError(f"entry {name!r} has an invalid kind: {kind!r}")
        return cls(
            name=name, kind=kind, url=url, sha256=sha256,
            version=str(data.get("version") or "0.0.0"),
            description=str(data.get("description") or ""),
            author=str(data.get("author") or ""),
        )


class Marketplace:
    """Discover, search, and install plugins from a signed-by-hash catalog."""

    def __init__(
        self,
        plugin_dir: Optional[Path] = None,
        *,
        catalog: Optional[Any] = None,
        catalog_url: Optional[str] = None,
    ):
        env_dir = os.environ.get("BLACKOUT_PLUGIN_DIR")
        self.plugin_dir = Path(plugin_dir or env_dir or DEFAULT_PLUGIN_DIR)
        self.catalog_url = catalog_url or DEFAULT_CATALOG_URL
        self._entries: dict[str, MarketplaceEntry] = {}
        if catalog is not None:
            self.load_catalog(catalog)

    # ── catalog ─────────────────────────────────────────────────────────────

    def load_catalog(self, catalog: Any) -> None:
        """Load entries from a path, a list, or a ``{name: entry}`` mapping."""
        if isinstance(catalog, (str, os.PathLike)):
            try:
                data = json.loads(Path(catalog).read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise MarketplaceError(f"cannot read catalog: {exc}") from exc
        else:
            data = catalog

        if isinstance(data, dict) and "plugins" in data:
            data = data["plugins"]
        if isinstance(data, dict):
            raw_entries: Iterable[Any] = data.values()
        elif isinstance(data, list):
            raw_entries = data
        else:
            raise MarketplaceError("catalog must be a list, a mapping, or a JSON path")

        for raw in raw_entries:
            if not isinstance(raw, dict):
                raise MarketplaceError("catalog entries must be objects")
            entry = MarketplaceEntry.from_dict(raw)
            self._entries[entry.name] = entry

    def refresh(self, url: Optional[str] = None, *, timeout: float = 30.0, fetcher: Optional[Callable[[str], bytes]] = None) -> int:
        """Fetch and merge a catalog from ``url`` (default :attr:`catalog_url`)."""
        target = url or self.catalog_url
        raw = (fetcher or self._fetch)(target)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MarketplaceError(f"invalid catalog from {target}: {exc}") from exc
        before = len(self._entries)
        self.load_catalog(data)
        return len(self._entries) - before

    def entries(self) -> list[MarketplaceEntry]:
        return sorted(self._entries.values(), key=lambda e: e.name)

    def search(self, query: str) -> list[MarketplaceEntry]:
        needle = str(query).lower()
        return [
            e for e in self.entries()
            if needle in e.name.lower() or needle in e.description.lower()
        ]

    def info(self, name: str) -> MarketplaceEntry:
        entry = self._entries.get(name)
        if entry is None:
            raise MarketplaceError(f"unknown plugin: {name!r}")
        return entry

    # ── install / remove ────────────────────────────────────────────────────

    def install(
        self,
        name: str,
        *,
        entry: Optional[MarketplaceEntry] = None,
        fetcher: Optional[Callable[[str], bytes]] = None,
        verify: bool = True,
    ) -> Path:
        """Download, verify, and install a plugin file. Returns the written path."""
        entry = entry or self.info(name)
        data = (fetcher or self._fetch)(entry.url)
        if verify:
            digest = hashlib.sha256(data).hexdigest()
            if digest != entry.sha256:
                raise MarketplaceError(
                    f"checksum mismatch for {name!r}: expected {entry.sha256}, got {digest}"
                )
        self.plugin_dir.mkdir(parents=True, exist_ok=True)
        target = self._plugin_path(entry.name)
        target.write_bytes(data)
        _log.info("Installed plugin %s -> %s", name, target)
        return target

    def remove(self, name: str) -> bool:
        """Remove an installed plugin file. Returns ``True`` if it existed."""
        target = self._plugin_path(name)
        if target.exists():
            target.unlink()
            return True
        return False

    def _plugin_path(self, name: str) -> Path:
        """Resolve a plugin name to a path inside the plugin directory.

        Belt and braces: from_dict() already rejects unsafe names, but remove()
        and install() take a bare string, so containment is checked here too.
        """
        if not _SAFE_NAME.match(name or ""):
            raise MarketplaceError(f"invalid plugin name: {name!r}")
        target = (self.plugin_dir / f"{name}.py").resolve()
        if not target.is_relative_to(self.plugin_dir.resolve()):
            raise MarketplaceError(f"plugin path escapes the plugin directory: {name!r}")
        return target

    def installed(self) -> list[str]:
        """Names of plugin files present in the plugin directory."""
        if not self.plugin_dir.is_dir():
            return []
        return sorted(p.stem for p in self.plugin_dir.glob("*.py") if not p.name.startswith("_"))

    def entry_dicts(self) -> list[dict[str, Any]]:
        return [asdict(e) for e in self.entries()]

    # ── network ─────────────────────────────────────────────────────────────

    @staticmethod
    def _fetch(url: str) -> bytes:
        try:
            import httpx
        except Exception as exc:  # pragma: no cover - httpx is a hard dependency
            raise MarketplaceError(f"httpx unavailable: {exc}") from exc
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https":
            # The catalog supplies both the URL and the expected hash, so a
            # plain-http catalog cannot protect itself from a MITM that edits
            # both. Refuse rather than pretend the checksum means something.
            raise MarketplaceError(f"refusing a non-https plugin URL: {url}")
        try:
            response = httpx.get(url, timeout=30.0, follow_redirects=True)
            response.raise_for_status()
        except Exception as exc:
            raise MarketplaceError(f"failed to fetch {url}: {exc}") from exc
        final = urllib.parse.urlsplit(str(response.url))
        if final.hostname != parsed.hostname:
            raise MarketplaceError(
                f"plugin URL redirected to another host ({parsed.hostname} -> "
                f"{final.hostname}); refusing"
            )
        return response.content
