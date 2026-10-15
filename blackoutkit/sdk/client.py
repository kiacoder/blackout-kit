"""High-level Python SDK for Blackout Kit (Roadmap Phase 8).

Embed and drive Blackout Kit programmatically instead of shelling out to the
CLI. This is a **thin, stable facade** over the same internals the CLI uses — it
delegates rather than re-implements, so the SDK and the CLI can never disagree
about behaviour.

Example::

    from blackoutkit.sdk import Blackout

    bk = Blackout()
    bk.version                          # "1.7.0"
    bk.set_setting("country", "IR")
    bk.engines()                        # ["auto", "xray", "sni", ...]
    bk.readiness("xray")                # {"engine": ..., "ready": bool, "checks": [...]}
    bk.metrics()                        # system + daemon metrics
    bk.connections(process="chrome")    # active connections
    bk.connect()                        # start the daemon with the selected engine
    bk.status()
    bk.disconnect()

Nothing here starts a network engine except :meth:`Blackout.connect`, and
nothing requires the optional ``[api]`` extra.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from .exceptions import BlackoutError, EngineError, SettingsError

__all__ = ["Blackout"]


class Blackout:
    """A programmatic client for Blackout Kit.

    Every method is a thin wrapper over an existing internal module. The class
    holds no state of its own: it always reflects the current on-disk settings
    and live daemon state.
    """

    # ── metadata ────────────────────────────────────────────────────────────

    @property
    def version(self) -> str:
        """The installed Blackout Kit version."""
        from .. import __version__

        return __version__

    # ── settings ────────────────────────────────────────────────────────────

    def get_setting(self, key: str) -> Any:
        """Return one setting value (falling back to its default)."""
        from .. import settings as cfg

        if key not in cfg.DEFAULTS:
            raise SettingsError(f"Unknown setting: {key!r}")
        return cfg.load().get(key, cfg.DEFAULTS[key])

    def set_setting(self, key: str, value: Any) -> None:
        """Validate and persist one setting. Raises :class:`SettingsError`."""
        from .. import settings as cfg

        try:
            cfg.set_value(key, value)
        except ValueError as exc:
            raise SettingsError(str(exc)) from exc

    def all_settings(self) -> dict[str, Any]:
        """Return every persisted setting."""
        from .. import settings as cfg

        return cfg.load()

    # ── engines & capabilities ──────────────────────────────────────────────

    def engines(self) -> list[str]:
        """Sorted list of engine names supported on this platform."""
        from .. import capabilities

        return sorted(capabilities.supported_engine_names())

    def capabilities(self, engine: Optional[str] = None) -> Any:
        """Capability dict for one engine, or a list for all engines."""
        from .. import capabilities

        if engine is None:
            return [
                capabilities.serialize_capability(cap)
                for cap in capabilities.all_capabilities()
            ]
        cap = capabilities.get_capability(engine)
        if cap is None:
            raise BlackoutError(f"Unknown engine: {engine!r}")
        return capabilities.serialize_capability(cap)

    # ── readiness & diagnostics ─────────────────────────────────────────────

    def readiness(self, engine: str) -> dict[str, Any]:
        """Readiness report for an engine: ``{engine, ready, checks}``."""
        from .. import readiness

        return {
            "engine": engine,
            "ready": readiness.ready(engine),
            "checks": readiness.as_dicts(engine),
        }

    def is_ready(self, engine: str) -> bool:
        """Whether an engine is ready to start."""
        from .. import readiness

        return readiness.ready(engine)

    def doctor(self, *, include_optional: bool = False, auto_fix: bool = False) -> list[dict[str, Any]]:
        """Run the local diagnostic checks and return them as dicts."""
        from .. import doctor

        results = doctor.run_all_checks(
            auto_fix=auto_fix, include_optional=include_optional
        )
        return [
            {
                "name": r.name,
                "ok": r.ok,
                "message": r.message,
                "fixable": r.fixable,
                "issue_type": r.issue_type,
            }
            for r in results
        ]

    # ── daemon / connection control ─────────────────────────────────────────

    def status(self) -> dict[str, Any]:
        """Daemon status: ``{running, pid, state}``."""
        from .. import daemon

        pid = daemon.get_pid()
        return {"running": pid is not None, "pid": pid, "state": daemon.get_state()}

    @property
    def connected(self) -> bool:
        """Whether a daemon is currently running."""
        from .. import daemon

        return daemon.get_pid() is not None

    def connect(
        self,
        engine: Optional[str] = None,
        *,
        env_overrides: Optional[dict[str, str]] = None,
    ) -> dict[str, Any]:
        """Start the daemon with ``engine`` (defaults to ``selected_engine``).

        Raises :class:`EngineError` if a daemon is already running or the engine
        cannot start.
        """
        from .. import daemon

        if engine is None:
            engine = self.get_setting("selected_engine")
        try:
            pid = daemon.start(engine, env_overrides)
        except RuntimeError as exc:
            raise EngineError(str(exc)) from exc
        return {"engine": engine, "pid": pid}

    def disconnect(self) -> bool:
        """Stop the running daemon. Returns ``True`` if a stop was issued."""
        from .. import daemon

        return bool(daemon.stop())

    def recent_events(self, limit: int = 5) -> list[str]:
        """Recent daemon lifecycle log lines."""
        from .. import daemon

        return daemon.get_recent_events(limit)

    def read_logs(self, lines: int = 50) -> str:
        """Tail of the daemon log."""
        from .. import daemon

        return daemon.read_logs(lines)

    def events(self, limit: int = 50, *, type_prefix: Optional[str] = None) -> list[dict[str, Any]]:
        """Structured recent events (in-process bus + persisted journal)."""
        from .. import events as events_mod

        return events_mod.merged_recent_events(limit=limit, type_prefix=type_prefix)

    # ── observability ───────────────────────────────────────────────────────

    def metrics(self) -> dict[str, Any]:
        """System + daemon metrics (CPU, memory, daemon RSS)."""
        from .. import api

        return api.collect_metrics()

    def connections(
        self,
        *,
        process: Optional[str] = None,
        port: Optional[int] = None,
        established_only: bool = False,
    ) -> dict[str, Any]:
        """Active connections, optionally filtered by process name / port."""
        from .. import api

        return api.collect_connections(
            established_only=established_only, process=process, port=port
        )

    def bandwidth(self) -> dict[str, Any]:
        """Aggregate and per-NIC byte counters."""
        from .. import api

        return api.collect_bandwidth()

    def anomalies(self, *, hours: int = 24, severity: Optional[str] = None) -> list[dict[str, Any]]:
        """Persisted anomalies from the last ``hours`` (0 = no time filter)."""
        from dataclasses import asdict
        from datetime import datetime, timedelta, timezone

        from ..anomaly_detector import AnomalyDetector

        since = (
            datetime.now(timezone.utc) - timedelta(hours=hours) if hours else None
        )
        items = AnomalyDetector(persist=False).get_anomalies(
            since=since, severity=severity
        )
        return [asdict(a) for a in items]

    def threat_stats(self) -> dict[str, Any]:
        """Threat-feed counts (feeds, blocked IPs/domains, last update)."""
        from ..threat_feeds import ThreatFeedsManager

        return ThreatFeedsManager().get_stats()

    def recommendations(self) -> list[dict[str, Any]]:
        """Predictive optimization recommendations from usage history."""
        from dataclasses import asdict

        from ..predictor import Predictor

        return [asdict(r) for r in Predictor().get_all_recommendations()]

    def benchmark(self, samples: int = 10) -> dict[str, Any]:
        """Run the local performance benchmarks (daemon RSS, IPC latency)."""
        from ..benchmarks import run_benchmarks

        return run_benchmarks(samples=samples)

    def report(
        self,
        output: Path,
        *,
        format: str = "csv",
        compliance_mode: Optional[str] = None,
        since_hours: int = 24,
    ) -> Path:
        """Generate a report (``csv``/``pdf``) and return the written path."""
        from ..reporting import ReportGenerator

        try:
            return ReportGenerator().export(
                Path(output),
                format=format,
                compliance_mode=compliance_mode,
                since_hours=since_hours,
            )
        except ValueError as exc:
            raise BlackoutError(str(exc)) from exc
