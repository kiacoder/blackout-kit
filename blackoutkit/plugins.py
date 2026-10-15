"""Plugin system (Roadmap Phase 8).

Load user-supplied plugins that extend Blackout Kit with **custom rules**,
**analyzers**, and **exporters**. A plugin is a single ``.py`` file in the
plugin directory (``~/.blackout-kit/plugins`` or ``$BLACKOUT_PLUGIN_DIR``) that
defines one or more subclasses of the base classes below.

.. warning::
   **Plugins are arbitrary Python and run with this process's full privileges.**
   Importing a plugin executes its top-level code. Loading is therefore gated
   behind the ``plugins_enabled`` setting (default **off**) and only ever reads
   from the plugin directory. Only install plugins you trust.

A minimal rule plugin::

    from blackoutkit.plugins import PluginMetadata, RulePlugin

    class BigUpload(RulePlugin):
        metadata = PluginMetadata(
            name="big-upload", kind="rule", version="1.0",
            description="Flag uploads over 100 MB",
        )

        def evaluate(self, context):
            total = context.get("bytes_sent", 0)
            if total > 100_000_000:
                return [{"id": "big-upload", "severity": "medium",
                         "message": f"upload of {total} bytes"}]
            return []
"""
from __future__ import annotations

import importlib.util
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

_log = logging.getLogger(__name__)

DEFAULT_PLUGIN_DIR = Path.home() / ".blackout-kit" / "plugins"
PLUGIN_KINDS = ("rule", "analyzer", "exporter")

__all__ = [
    "PluginMetadata",
    "Plugin",
    "RulePlugin",
    "AnalyzerPlugin",
    "ExporterPlugin",
    "PluginError",
    "PluginManager",
    "DEFAULT_PLUGIN_DIR",
    "PLUGIN_KINDS",
]


class PluginError(Exception):
    """Raised for an unknown, disabled, or broken plugin."""


@dataclass(frozen=True)
class PluginMetadata:
    """Describes a plugin."""

    name: str
    kind: str
    version: str = "0.0.0"
    description: str = ""
    author: str = ""


class Plugin:
    """Base class for every plugin. Subclasses must set ``metadata``."""

    metadata: PluginMetadata


class RulePlugin(Plugin):
    """Evaluates a context dict and returns zero or more findings."""

    def evaluate(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        raise NotImplementedError


class AnalyzerPlugin(Plugin):
    """Analyzes a list of records and returns a result dict."""

    def analyze(self, records: list[dict[str, Any]]) -> dict[str, Any]:
        raise NotImplementedError


class ExporterPlugin(Plugin):
    """Writes a report dict to ``output`` and returns the path written."""

    def export(self, report: dict[str, Any], output: Path) -> Path:
        raise NotImplementedError


_BASES = (RulePlugin, AnalyzerPlugin, ExporterPlugin)


class PluginManager:
    """Discovers, loads, and runs plugins from a directory."""

    def __init__(
        self,
        plugin_dir: Optional[Path] = None,
        *,
        enabled: Optional[bool] = None,
    ):
        env_dir = os.environ.get("BLACKOUT_PLUGIN_DIR")
        self.plugin_dir = Path(plugin_dir or env_dir or DEFAULT_PLUGIN_DIR)
        # ``enabled=None`` defers to the plugins_enabled setting at call time.
        self._enabled_override = enabled
        self._plugins: dict[str, Plugin] = {}
        self._errors: dict[str, str] = {}
        self._discovered = False

    # ── gating ──────────────────────────────────────────────────────────────

    @property
    def enabled(self) -> bool:
        if self._enabled_override is not None:
            return self._enabled_override
        try:
            from . import settings as cfg

            return bool(cfg.load().get("plugins_enabled", False))
        except Exception:
            return False

    @property
    def errors(self) -> dict[str, str]:
        """Map of ``filename -> error`` for plugins that failed to load."""
        self._ensure_discovered()
        return dict(self._errors)

    # ── discovery ───────────────────────────────────────────────────────────

    def _ensure_discovered(self) -> None:
        if self._discovered:
            return
        self._discovered = True
        if not self.enabled:
            return
        if not self.plugin_dir.is_dir():
            return
        for path in sorted(self.plugin_dir.glob("*.py")):
            if path.name.startswith("_"):
                continue
            try:
                for plugin in self._load_file(path):
                    name = plugin.metadata.name
                    if name in self._plugins:
                        _log.warning("Duplicate plugin name %r (%s) — keeping the first", name, path.name)
                        continue
                    self._plugins[name] = plugin
            except Exception as exc:  # a broken plugin must not stop discovery
                _log.warning("Plugin %s failed to load: %s", path.name, exc)
                self._errors[path.name] = str(exc)

    def _load_file(self, path: Path) -> list[Plugin]:
        module_name = f"blackoutkit_plugin_{path.stem}"
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            raise PluginError(f"cannot load {path.name}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return self._plugins_from_module(module)

    @staticmethod
    def _plugins_from_module(module: Any) -> list[Plugin]:
        found: list[Plugin] = []
        explicit = getattr(module, "PLUGIN", None)
        if isinstance(explicit, Plugin):
            found.append(explicit)
        for value in vars(module).values():
            if (
                isinstance(value, type)
                and issubclass(value, _BASES)
                and value not in _BASES
            ):
                instance = value()
                if not isinstance(getattr(instance, "metadata", None), PluginMetadata):
                    raise PluginError(
                        f"{value.__name__} must set a PluginMetadata 'metadata' attribute"
                    )
                found.append(instance)
        if not found:
            raise PluginError("no Plugin subclass or PLUGIN instance found")
        return found

    # ── accessors ───────────────────────────────────────────────────────────

    def list(self) -> list[PluginMetadata]:
        """All discovered plugins' metadata, sorted by name."""
        self._ensure_discovered()
        return sorted((p.metadata for p in self._plugins.values()), key=lambda m: m.name)

    def by_kind(self, kind: str) -> list[PluginMetadata]:
        """Metadata for plugins of one kind (rule/analyzer/exporter)."""
        return [m for m in self.list() if m.kind == kind]

    def get(self, name: str) -> Plugin:
        """Return a loaded plugin by name, or raise :class:`PluginError`."""
        self._ensure_discovered()
        plugin = self._plugins.get(name)
        if plugin is None:
            if not self.enabled:
                raise PluginError("plugins are disabled (enable the 'plugins_enabled' setting)")
            raise PluginError(f"unknown plugin: {name!r}")
        return plugin

    # ── runners ─────────────────────────────────────────────────────────────

    def run_rule(self, name: str, context: dict[str, Any]) -> list[dict[str, Any]]:
        plugin = self.get(name)
        if not isinstance(plugin, RulePlugin):
            raise PluginError(f"{name!r} is not a rule plugin")
        findings = plugin.evaluate(context)
        return list(findings or [])

    def run_analyzer(self, name: str, records: list[dict[str, Any]]) -> dict[str, Any]:
        plugin = self.get(name)
        if not isinstance(plugin, AnalyzerPlugin):
            raise PluginError(f"{name!r} is not an analyzer plugin")
        return dict(plugin.analyze(records) or {})

    def run_exporter(self, name: str, report: dict[str, Any], output: Path) -> Path:
        plugin = self.get(name)
        if not isinstance(plugin, ExporterPlugin):
            raise PluginError(f"{name!r} is not an exporter plugin")
        return Path(plugin.export(report, Path(output)))

    def run_rules(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Run every rule plugin and aggregate their findings (each tagged)."""
        results: list[dict[str, Any]] = []
        for meta in self.by_kind("rule"):
            try:
                for finding in self.run_rule(meta.name, context):
                    results.append({"plugin": meta.name, **finding})
            except Exception as exc:
                _log.warning("Rule plugin %s failed: %s", meta.name, exc)
        return results
