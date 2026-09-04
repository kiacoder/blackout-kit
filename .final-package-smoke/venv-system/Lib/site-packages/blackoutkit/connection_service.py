"""Shared connection lifecycle used by Typer and legacy command adapters."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import asyncio
import ctypes
import os
import socket
import sys
import time
from typing import Any, Callable


_WINDOWS_ELEVATED_ENGINES = frozenset({"gdpi", "warp", "tun"})
_LINUX_ENGINES = frozenset({"xray", "tun", "hysteria2", "tuic", "awg"})
_LINUX_DEFAULTABLE_ENGINES = frozenset({"auto", "sni", "gdpi", "psiphon", "warp", "legend"})


class ConnectionServiceError(RuntimeError):
    """Raised only for invalid service integration boundaries."""



def _invoke_start_stack(factory: Callable[..., list], engine_name: str, emit: bool) -> list:
    try:
        return factory(engine_name, emit=emit)
    except TypeError as exc:
        if "emit" not in str(exc):
            raise
        return factory(engine_name)



def _invoke_daemon_start(factory: Callable[..., int], engine_name: str, env_overrides: dict[str, str]) -> int:
    return factory(engine_name, env_overrides=env_overrides)


@dataclass(frozen=True)
class ConnectionRequest:
    """Typed input for a connect or start transaction."""

    operation: str
    pos_engine: str | None = None
    engine: str | None = None
    background: bool = False
    iran: bool = False
    russia: bool = False


@dataclass
class ConnectionResult:
    """Safe, serializable outcome of one connection transaction."""

    operation: str
    ok: bool
    status: str
    engine: str | None = None
    pid: int | None = None
    background: bool = False
    code: str | None = None
    message: str | None = None
    cancelled: bool = False
    preset: dict[str, Any] | None = None
    profile: dict[str, Any] | None = None
    readiness: list[dict[str, Any]] = field(default_factory=list)
    sni_scan_attempted: bool = False
    sni_ip_saved: bool = False
    proxy_configured: bool = False
    warnings: list[str] = field(default_factory=list)

    def payload(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "operation": self.operation,
            "status": self.status,
            "engine": self.engine,
            "background": self.background,
            "proxy_configured": self.proxy_configured,
        }
        if self.pid is not None:
            data["pid"] = self.pid
        if self.preset is not None:
            data["preset"] = {
                "name": self.preset.get("name"),
                "title": self.preset.get("title"),
                "changes": list(self.preset.get("changes", [])),
            }
        if self.profile is not None:
            data["profile"] = dict(self.profile)
        if self.readiness:
            data["readiness"] = list(self.readiness)
        if self.sni_scan_attempted:
            data["sni_scan"] = {"attempted": True, "ip_saved": self.sni_ip_saved}
        if self.warnings:
            data["warnings"] = list(self.warnings)
        if self.cancelled:
            data["cancelled"] = True
        return data


class ConnectionService:
    """Run connect/start as one transaction with injectable local boundaries."""

    def __init__(
        self,
        *,
        settings_load: Callable[[], dict] | None = None,
        settings_set: Callable[[str, Any], Any] | None = None,
        readiness_evaluate: Callable[[str], list] | None = None,
        readiness_gate: Callable[[str], bool] | None = None,
        resolve_engine: Callable[..., str] | None = None,
        linux_default_engine: Callable[[str], str] | None = None,
        platform_engine_error: Callable[[str], str | None] | None = None,
        preset_payload: Callable[..., tuple[str | None, dict[str, str], list[str], str | None]] | None = None,
        recommended_engine: Callable[[], str] | None = None,
        active_profile: Callable[[], Any] | None = None,
        route_candidates: Callable[[], list] | None = None,
        choose_engine: Callable[[str], str | None] | None = None,
        choose_connection: Callable[[str, list[str], str], str | None] | None = None,
        is_interactive: Callable[[], bool] | None = None,
        scan_sni_ip: Callable[[dict], tuple[str, float] | None] | None = None,
        start_engine_stack: Callable[..., list] | None = None,
        daemon_start: Callable[..., int] | None = None,
        daemon_stop: Callable[[], bool] | None = None,
        daemon_get_pid: Callable[[], int | None] | None = None,
        daemon_log_file: Any = None,
        set_proxy: Callable[[str, int], bool] | None = None,
        clear_proxy: Callable[[], bool] | None = None,
        get_proxy_status: Callable[[], dict] | None = None,
        restore_proxy: Callable[[dict], bool] | None = None,
        cleanup_proxy: Callable[[], bool] | None = None,
        proxy_details: Callable[[str, dict], tuple[str, int] | None] | None = None,
        kill_switch_prepare: Callable[[str], bool] | None = None,
        kill_switch_enable: Callable[[str], bool] | None = None,
        kill_switch_disable: Callable[[], bool] | None = None,
        kill_switch_clear_endpoint: Callable[[str | None], Any] | None = None,
        is_admin: Callable[[], bool] | None = None,
        emit: Callable[[dict[str, Any]], None] | None = None,
        emit_output: bool = True,
        sleep: Callable[[float], Any] | None = None,
        monotonic: Callable[[], float] | None = None,
        platform: Callable[[], str] | None = None,
    ) -> None:
        self.settings_load = settings_load or _load_settings
        self.settings_set = settings_set or _set_setting
        self.readiness_evaluate = readiness_evaluate or _evaluate_readiness
        self.readiness_gate = readiness_gate
        self.resolve_engine = resolve_engine or resolve_engine_name
        self.linux_default_engine = linux_default_engine or linux_default
        self.platform_engine_error = platform_engine_error or platform_error
        self.preset_payload = preset_payload or build_preset_payload
        self.recommended_engine = recommended_engine or recommended_engine_name
        self.active_profile = active_profile or active_country_profile
        self.route_candidates = route_candidates or routing_candidates
        self.choose_engine = choose_engine or choose_engine_default
        self.choose_connection = choose_connection or choose_connection_default
        self.is_interactive = is_interactive or interactive_default
        self.scan_sni_ip = scan_sni_ip or scan_missing_sni_ip
        self.start_engine_stack = start_engine_stack or start_stack_default
        self.daemon_start = daemon_start or daemon_start_default
        self.daemon_stop = daemon_stop or daemon_stop_default
        self.daemon_get_pid = daemon_get_pid or daemon_pid_default
        self.daemon_log_file = daemon_log_file if daemon_log_file is not None else daemon_log_default()
        self.set_proxy = set_proxy or set_proxy_default
        self.clear_proxy = clear_proxy or clear_proxy_default
        self._track_proxy_ownership = get_proxy_status is not None
        self.get_proxy_status = get_proxy_status or get_proxy_status_default
        self.restore_proxy = restore_proxy or restore_proxy_default
        self.cleanup_proxy = cleanup_proxy or cleanup_proxy_default
        self.proxy_details = proxy_details or proxy_details_default
        self.kill_switch_prepare = kill_switch_prepare or kill_switch_prepare_default
        self.kill_switch_enable = kill_switch_enable or kill_switch_enable_default
        self.kill_switch_disable = kill_switch_disable or kill_switch_disable_default
        self.kill_switch_clear_endpoint = kill_switch_clear_endpoint or kill_switch_clear_default
        self.is_admin = is_admin or admin_default
        self.emit = emit
        self.emit_output = bool(emit_output)
        self.sleep = sleep or time.sleep
        self.monotonic = monotonic or time.monotonic
        self.platform = platform or (lambda: sys.platform)

    def connect(self, request: ConnectionRequest) -> ConnectionResult:
        request = _normalized_request(request, "connect")
        if request.iran and request.russia:
            return self._failure(request, "invalid_preset", "Choose only one preset: --iran or --russia.", status="invalid")

        requested = request.pos_engine or request.engine
        preset_name = _preset_name(request)
        base_settings = self.settings_load()
        connect_overrides: dict[str, str] = {}
        if preset_name:
            _title, connect_overrides, _changes, _footer = self.preset_payload(
                preset_name,
                base_settings,
                direct_start=False,
            )

        with temporary_env_overrides(connect_overrides):
            recommended = self.recommended_engine()
            profile = self.active_profile()
            engine_before_preset = recommended if requested in (None, "auto") else requested
            if requested is None and self.is_interactive() and not request.background:
                choice = self.choose_connection(
                    f"Recommended engine: {recommended}. Continue or choose manually?",
                    ["recommended", "manual", "cancel"],
                    "recommended",
                )
                if choice == "cancel" or choice is None:
                    return self._cancelled(request, engine_before_preset)
                if choice == "manual":
                    candidates = self.route_candidates()
                    choices = [str(candidate.engine) for candidate in candidates]
                    selected = self.choose_connection("Choose an engine", choices, recommended) if choices else None
                    if not selected:
                        return self._cancelled(request, engine_before_preset)
                    engine_before_preset = selected

        engine_name, env_overrides, preset = self._start_preset(
            engine_before_preset,
            preset_name,
            base_settings,
            request,
        )
        profile_payload = _profile_payload(profile)
        warnings = self._profile_warnings(profile, engine_before_preset)
        for warning in warnings:
            self._event("warning", message=warning)
        if profile_payload:
            self._event("profile", profile=profile_payload)

        with temporary_env_overrides(env_overrides):
            platform_message = self.platform_engine_error(engine_name)
            if platform_message:
                return self._failure(
                    request,
                    "unsupported_engine",
                    platform_message,
                    engine=engine_name,
                    preset=preset,
                    profile=profile_payload,
                    warnings=warnings,
                )
            ready, checks = self._ready(engine_name)
            if not ready:
                return self._failure(
                    request,
                    "not_ready",
                    "Connection was not started because local readiness checks found blockers.",
                    engine=engine_name,
                    readiness=checks,
                    preset=preset,
                    profile=profile_payload,
                    warnings=warnings,
                )

            scan_attempted = False
            ip_saved = False
            if (
                self.platform() == "win32"
                and engine_before_preset in {"sni", "auto"}
                and not self.settings_load().get("sni_connect_ip")
            ):
                scan_attempted = True
                self._event("sni_scan_started")
                result = self.scan_sni_ip(self.settings_load())
                if result:
                    best_ip, latency = result
                    self.settings_set("sni_connect_ip", best_ip)
                    ip_saved = True
                    self._event("sni_scan_result", ip=best_ip, latency=latency)
                else:
                    self._event("sni_scan_empty")

            result = self._start_resolved(
                request,
                engine_name,
                env_overrides,
                preset=preset,
                profile=profile_payload,
                readiness=checks,
                readiness_already_checked=True,
                warnings=warnings,
            )
            result.sni_scan_attempted = scan_attempted
            result.sni_ip_saved = ip_saved
            return result

    def start(self, request: ConnectionRequest) -> ConnectionResult:
        request = _normalized_request(request, "start")
        if request.iran and request.russia:
            return self._failure(request, "invalid_preset", "Choose only one preset: --iran or --russia.", status="invalid")

        requested = request.pos_engine or request.engine
        if requested is None:
            requested = self.choose_engine("Choose an engine to start")
            if not requested:
                return self._cancelled(request)
        requested = self.resolve_engine(
            type("EngineArgs", (), {"pos_engine": requested, "engine": None})()
        )
        preset_name = _preset_name(request)
        base_settings = self.settings_load()
        engine_name, env_overrides, preset = self._start_preset(
            requested,
            preset_name,
            base_settings,
            request,
        )
        return self._start_resolved(
            request,
            engine_name,
            env_overrides,
            preset=preset,
            readiness_already_checked=False,
        )

    def _start_resolved(
        self,
        request: ConnectionRequest,
        engine_name: str,
        env_overrides: dict[str, str],
        *,
        preset: dict[str, Any] | None = None,
        profile: dict[str, Any] | None = None,
        readiness: list[dict[str, Any]] | None = None,
        readiness_already_checked: bool,
        warnings: list[str] | None = None,
    ) -> ConnectionResult:
        warnings = list(warnings or [])
        with temporary_env_overrides(env_overrides):
            error = self.platform_engine_error(engine_name)
            if error:
                return self._failure(
                    request,
                    "unsupported_engine",
                    error,
                    engine=engine_name,
                    preset=preset,
                    profile=profile,
                    warnings=warnings,
                )

            checks = list(readiness or [])
            if not readiness_already_checked:
                ready, checks = self._ready(engine_name)
                if not ready:
                    return self._failure(
                        request,
                        "not_ready",
                        "Connection was not started because local readiness checks found blockers.",
                        engine=engine_name,
                        readiness=checks,
                        preset=preset,
                        profile=profile,
                        warnings=warnings,
                    )

            if preset:
                self._event("preset", preset=preset)

            if request.background:
                return self._start_background(
                    request,
                    engine_name,
                    env_overrides,
                    preset=preset,
                    profile=profile,
                    readiness=checks,
                    warnings=warnings,
                )

            return self._start_foreground(
                request,
                engine_name,
                env_overrides=env_overrides,
                preset=preset,
                profile=profile,
                readiness=checks,
                warnings=warnings,
            )

    def _start_background(
        self,
        request: ConnectionRequest,
        engine_name: str,
        env_overrides: dict[str, str],
        *,
        preset: dict[str, Any] | None,
        profile: dict[str, Any] | None,
        readiness: list[dict[str, Any]],
        warnings: list[str],
    ) -> ConnectionResult:
        try:
            pid = _invoke_daemon_start(self.daemon_start, engine_name, env_overrides)
        except RuntimeError as exc:
            return self._failure(
                request,
                "daemon_start_failed",
                str(exc),
                engine=engine_name,
                preset=preset,
                profile=profile,
                readiness=readiness,
                warnings=warnings,
            )
        self._event("background", engine=engine_name, pid=pid)
        return ConnectionResult(
            operation=request.operation,
            ok=bool(pid),
            status="background" if pid else "failed",
            engine=engine_name,
            pid=pid or None,
            background=True,
            code=None if pid else "daemon_start_failed",
            message=None if pid else "Daemon did not start.",
            preset=preset,
            profile=profile,
            readiness=readiness,
            warnings=warnings,
        )

    def _start_foreground(
        self,
        request: ConnectionRequest,
        engine_name: str,
        env_overrides: dict[str, str],
        *,
        preset: dict[str, Any] | None,
        profile: dict[str, Any] | None,
        readiness: list[dict[str, Any]],
        warnings: list[str],
    ) -> ConnectionResult:
        if self.platform() == "win32" and not self.is_admin() and engine_name in _WINDOWS_ELEVATED_ENGINES:
            return self._start_elevated(
                request,
                engine_name,
                env_overrides=env_overrides,
                preset=preset,
                profile=profile,
                readiness=readiness,
                warnings=warnings,
            )

        kill_switch_prepared = False
        kill_switch_enabled = False
        engines: list[Any] = []
        proxy_configured = False
        proxy_changed = False
        settings = self.settings_load()
        proxy_before = (
            self.get_proxy_status()
            if self._track_proxy_ownership and settings.get("auto_set_proxy")
            else None
        )
        try:
            if self.platform().startswith("linux") and settings.get("kill_switch", False):
                if not self.kill_switch_prepare(engine_name):
                    return self._failure(
                        request,
                        "kill_switch_unavailable",
                        "Could not resolve a safe Linux kill-switch endpoint; refusing to start.",
                        engine=engine_name,
                        preset=preset,
                        profile=profile,
                        readiness=readiness,
                        warnings=warnings,
                    )
                kill_switch_prepared = True
                if not self.kill_switch_enable(engine_name):
                    return self._failure(
                        request,
                        "kill_switch_failed",
                        "Linux kill switch could not be enabled; refusing to start the system tunnel.",
                        engine=engine_name,
                        preset=preset,
                        profile=profile,
                        readiness=readiness,
                        warnings=warnings,
                    )
                kill_switch_enabled = True

            engines = _invoke_start_stack(self.start_engine_stack, engine_name, self.emit_output)
            if not engines:
                return self._failure(
                    request,
                    "engine_start_failed",
                    "No engines could start. Make sure binaries are in bins/.",
                    engine=engine_name,
                    preset=preset,
                    profile=profile,
                    readiness=readiness,
                    warnings=warnings,
                )

            for engine in engines:
                self._event("engine_started", name=getattr(engine, "name", engine_name), pid=getattr(engine, "pid", None))

            health_target = None
            if settings.get("auto_set_proxy"):
                proxy_info = self.proxy_details(engine_name, settings)
                if proxy_info:
                    host, port = proxy_info
                    proxy_configured = bool(self.set_proxy(host, port))
                    proxy_changed = proxy_configured
                    health_target = health_check_target(proxy_info)
                    self._event("proxy", configured=proxy_configured, host=host, port=port)
                else:
                    self._event("network_engine", engine=engine_name)

            self._event("monitoring", engine=engine_name)
            interrupted = False
            try:
                self._monitor(engines, settings, health_target)
            except KeyboardInterrupt:
                interrupted = True
                self._event("cancelled")
            return ConnectionResult(
                operation=request.operation,
                ok=True,
                status="stopped",
                engine=engine_name,
                background=False,
                preset=preset,
                profile=profile,
                readiness=readiness,
                proxy_configured=proxy_configured,
                warnings=warnings,
                cancelled=interrupted,
            )
        finally:
            if engines:
                self._event("stopping", engine=engine_name)
                for engine in engines:
                    try:
                        engine.stop()
                    except Exception as exc:
                        self._event("cleanup_error", detail=str(exc))
            if self._track_proxy_ownership and settings.get("auto_set_proxy"):
                try:
                    self.cleanup_proxy()
                except Exception as exc:
                    self._event("cleanup_error", detail=str(exc))
            elif proxy_changed and settings.get("auto_set_proxy"):
                try:
                    if proxy_before and proxy_before.get("enabled") and proxy_before.get("server"):
                        self.restore_proxy(proxy_before)
                    else:
                        self.clear_proxy()
                except Exception as exc:
                    self._event("cleanup_error", detail=str(exc))
            if kill_switch_enabled:
                try:
                    self.kill_switch_disable()
                except Exception as exc:
                    self._event("cleanup_error", detail=str(exc))
            if kill_switch_prepared:
                try:
                    self.kill_switch_clear_endpoint(engine_name)
                except Exception as exc:
                    self._event("cleanup_error", detail=str(exc))
            if engines:
                self._event("stopped", engine=engine_name)

    def _start_elevated(
        self,
        request: ConnectionRequest,
        engine_name: str,
        *,
        env_overrides: dict[str, str],
        preset: dict[str, Any] | None,
        profile: dict[str, Any] | None,
        readiness: list[dict[str, Any]],
        warnings: list[str],
    ) -> ConnectionResult:
        self._event("elevating", engine=engine_name)
        try:
            pid = _invoke_daemon_start(self.daemon_start, engine_name, env_overrides)
        except RuntimeError as exc:
            return self._failure(request, "daemon_start_failed", str(exc), engine=engine_name, preset=preset, profile=profile, readiness=readiness, warnings=warnings)
        if not pid:
            return self._failure(request, "daemon_start_failed", "Failed to start daemon (UAC prompt declined or timed out).", engine=engine_name, preset=preset, profile=profile, readiness=readiness, warnings=warnings)

        interrupted = False
        try:
            log_path = self.daemon_log_file
            for _ in range(100):
                if log_path.exists():
                    break
                self.sleep(0.1)
            if not log_path.exists():
                self._event("warning", message="Daemon log file was not created; stopping elevated startup.")
                return self._failure(request, "daemon_start_failed", "Failed to open daemon log file.", engine=engine_name, preset=preset, profile=profile, readiness=readiness, warnings=warnings)
            with log_path.open("r", encoding="utf-8") as stream:
                stream.seek(0, 2)
                while self.daemon_get_pid() is not None:
                    line = stream.readline()
                    if line:
                        self._event("daemon_log", line=line.rstrip())
                    else:
                        self.sleep(0.1)
        except KeyboardInterrupt:
            interrupted = True
        finally:
            self._event("stopping", engine=engine_name)
            self.daemon_stop()
        return ConnectionResult(
            operation=request.operation,
            ok=True,
            status="background_stopped" if interrupted else "background",
            engine=engine_name,
            pid=pid,
            background=True,
            preset=preset,
            profile=profile,
            readiness=readiness,
            warnings=warnings,
        )

    def _monitor(self, engines: list[Any], settings: dict, health_target: tuple[str, int] | None) -> None:
        last_check = self.monotonic()
        while all(engine.is_running() for engine in engines):
            self.sleep(1)
            now = self.monotonic()
            if now - last_check <= 10.0:
                continue
            last_check = now
            if not settings.get("auto_set_proxy") or not health_target:
                continue
            try:
                with socket.create_connection(health_target, timeout=2.0):
                    pass
            except Exception:
                self._event("proxy_warning", message="Proxy port stopped responding. Check your internet connection.")

    def _ready(self, engine_name: str) -> tuple[bool, list[dict[str, Any]]]:
        if self.readiness_gate is not None:
            return bool(self.readiness_gate(engine_name)), []
        checks = list(self.readiness_evaluate(engine_name))
        ready = all(bool(getattr(check, "ok", False)) or not bool(getattr(check, "blocking", True)) for check in checks)
        payload = [
            {
                "name": str(getattr(check, "name", "check")),
                "ok": bool(getattr(check, "ok", False)),
                "blocking": bool(getattr(check, "blocking", True)),
                "detail": str(getattr(check, "detail", "")),
            }
            for check in checks
        ]
        return ready, payload

    def _start_preset(
        self,
        engine_name: str,
        preset_name: str | None,
        settings: dict,
        request: ConnectionRequest,
    ) -> tuple[str, dict[str, str], dict[str, Any] | None]:
        effective = self.linux_default_engine(engine_name)
        if preset_name == "iran":
            effective = "legend"
            if engine_name not in {"auto", "sni", "xray", "legend", "tor"}:
                self._event("warning", message="Iran preset is tuned for the Tor + SNI + XRay stack and related local settings.")
        title, overrides, changes, footer = self.preset_payload(
            preset_name,
            settings,
            direct_start=True,
        ) if preset_name else (None, {}, [], None)
        preset = None
        if preset_name:
            preset = {
                "name": preset_name,
                "title": title,
                "changes": changes,
                "footer": footer,
                "overrides": overrides,
            }
        return effective, overrides, preset

    def _profile_warnings(self, profile: Any, engine_name: str) -> list[str]:
        if not profile:
            return []
        warnings = []
        if getattr(profile, "code", None) == "CN" and engine_name == "sni":
            warnings.append("SNI spoofing is largely ineffective against China's Great Firewall (GFW blocks IPs + SNI).")
        if getattr(profile, "code", None) == "RU" and engine_name in {"sni", "gdpi"}:
            warnings.append("Russia's profile currently favors XRay and QUIC-capable paths first.")
        return warnings

    def _cancelled(self, request: ConnectionRequest, engine: str | None = None) -> ConnectionResult:
        self._event("cancelled")
        return ConnectionResult(
            operation=request.operation,
            ok=False,
            status="cancelled",
            engine=engine,
            background=request.background,
            cancelled=True,
            code="cancelled",
            message="Connection cancelled.",
        )

    def _failure(self, request: ConnectionRequest, code: str, message: str, *, status: str = "failed", **kwargs) -> ConnectionResult:
        self._event("error", code=code, message=message)
        return ConnectionResult(
            operation=request.operation,
            ok=False,
            status=status,
            background=request.background,
            code=code,
            message=message,
            **kwargs,
        )

    def _event(self, event_type: str, **payload: Any) -> None:
        if self.emit is not None:
            self.emit({"type": event_type, **payload})


def _normalized_request(request: ConnectionRequest, operation: str) -> ConnectionRequest:
    return ConnectionRequest(
        operation=operation,
        pos_engine=request.pos_engine,
        engine=request.engine,
        background=bool(request.background),
        iran=bool(request.iran),
        russia=bool(request.russia),
    )


def _preset_name(request: ConnectionRequest) -> str | None:
    return "iran" if request.iran else "russia" if request.russia else None


def _profile_payload(profile: Any) -> dict[str, Any] | None:
    if not profile:
        return None
    return {
        "code": getattr(profile, "code", None),
        "name": getattr(profile, "name", None),
        "censorship_level": getattr(profile, "censorship_level", None),
        "recommended_engine": (getattr(profile, "engine_order", None) or [None])[0],
    }


def temporary_env_overrides(env_overrides: dict[str, str] | None):
    previous: dict[str, str | None] = {}
    for key, value in (env_overrides or {}).items():
        previous[key] = os.environ.get(key)
        os.environ[key] = str(value)
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


# Keep the helper usable as a context manager without imposing a public dependency.
temporary_env_overrides = contextmanager(temporary_env_overrides)


def resolve_engine_name(args: Any, default: str = "sni") -> str:
    selected = getattr(args, "pos_engine", None) or getattr(args, "engine", None) or default
    return default if selected == "auto" else selected


def linux_default(name: str) -> str:
    if sys.platform.startswith("linux") and name in {"auto", "sni", "gdpi", "psiphon", "warp", "legend"}:
        return "tun"
    return name


def platform_error(name: str) -> str | None:
    if not sys.platform.startswith("linux"):
        return None
    if name in {"xray", "tun", "hysteria2", "tuic", "awg"}:
        return None
    return (
        f"{name} is currently Windows-only. Linux currently supports XRay, TUN, Hysteria2, "
        "and TUIC through the managed blackout-engine runner."
    )


def _setting_env_name(key: str) -> str:
    return f"BLACKOUT_{key.upper()}"


def _setting_env_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return ",".join(str(item) for item in value)
    return str(value)


def _env_overrides_from_settings(overrides: dict[str, Any]) -> dict[str, str]:
    return {_setting_env_name(key): _setting_env_value(value) for key, value in overrides.items()}


def build_preset_payload(
    preset_name: str | None,
    settings: dict,
    *,
    direct_start: bool = False,
) -> tuple[str | None, dict[str, str], list[str], str | None]:
    if not preset_name:
        return None, {}, [], None
    from . import security as sec
    from . import settings as cfg

    def mode_overrides(mode_name: str) -> dict[str, Any]:
        mode = sec.MODES.get(mode_name, {})
        overrides = {key: value for key, value in mode.items() if key != "description" and key in cfg.DEFAULTS}
        overrides["security_mode"] = mode_name
        return overrides

    if preset_name == "iran":
        overrides = mode_overrides("legend" if direct_start else "private")
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
        overrides = mode_overrides("private")
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


def choose_engine_default(prompt: str) -> str | None:
    from .cli import _ask_engine

    return _ask_engine(prompt)


def choose_connection_default(prompt: str, choices: list[str], default: str) -> str | None:
    from .theme import ask_choice

    return ask_choice(prompt, choices, default=default)


def interactive_default() -> bool:
    from .theme import is_interactive

    return is_interactive()


def _load_settings() -> dict:
    from . import settings as cfg

    return cfg.load()


def _set_setting(key: str, value: Any) -> Any:
    from . import settings as cfg

    return cfg.set_value(key, value)


def _evaluate_readiness(engine: str) -> list:
    from . import readiness

    return readiness.evaluate(engine)


def recommended_engine_name() -> str:
    from .cli import _recommended_engine_name

    return _recommended_engine_name()


def active_country_profile() -> Any:
    from .cli import _get_active_profile

    return _get_active_profile()


def routing_candidates() -> list:
    from .cli import _routing_candidates

    return _routing_candidates()


def scan_missing_sni_ip(
    settings: dict,
    *,
    generate: Callable[[int], list[str]] | None = None,
    scan: Callable[..., Any] | None = None,
) -> tuple[str, float] | None:
    if generate is None:
        from .scanner.ip_scanner import generate_cloudflare_ips as generate
    if scan is None:
        from .scanner.ip_scanner import scan_ips as scan
    results = asyncio.run(scan(generate(10), concurrency=10, timeout=3.0))
    return results[0] if results else None


def start_stack_default(name: str, *, emit: bool = True) -> list:
    from .cli import _start_engine_stack

    return _start_engine_stack(name, emit=emit)


def daemon_start_default(engine_name: str, **kwargs) -> int:
    from . import daemon

    return daemon.start(engine_name, **kwargs)


def daemon_stop_default() -> bool:
    from . import daemon

    return daemon.stop()


def daemon_pid_default() -> int | None:
    from . import daemon

    return daemon.get_pid()


def daemon_log_default():
    from . import daemon

    return daemon.LOG_FILE


def set_proxy_default(host: str, port: int) -> bool:
    from .proxy_manager import set_system_proxy

    return set_system_proxy(host, port)


def clear_proxy_default() -> bool:
    from .proxy_manager import clear_system_proxy

    return clear_system_proxy()


def cleanup_proxy_default() -> bool:
    from .proxy_manager import cleanup_owned_system_proxy

    return cleanup_owned_system_proxy()


def get_proxy_status_default() -> dict:
    from .proxy_manager import get_proxy_status

    return get_proxy_status()


def restore_proxy_default(status: dict) -> bool:
    from .proxy_manager import set_system_proxy

    server = str(status.get("server", ""))
    if not server:
        return clear_proxy_default()
    if server.startswith("socks="):
        host, port = server[6:].rsplit(":", 1)
        return set_system_proxy(host, int(port), protocol="socks")
    host, port = server.rsplit(":", 1)
    return set_system_proxy(host, int(port))


def proxy_details_default(engine_name: str, settings: dict) -> tuple[str, int] | None:
    from . import settings as cfg

    return cfg.get_engine_proxy_details(engine_name, settings)


def kill_switch_prepare_default(engine_name: str) -> bool:
    from . import security

    return security.prepare_linux_kill_switch(engine_name)


def kill_switch_enable_default(engine_name: str) -> bool:
    from . import security

    return security.enable_kill_switch(engine_name)


def kill_switch_disable_default() -> bool:
    from . import security

    return security.disable_kill_switch()


def kill_switch_clear_default(engine_name: str | None) -> Any:
    from . import security

    return security.clear_linux_kill_switch_endpoint(engine_name)


def admin_default() -> bool:
    if sys.platform != "win32":
        return False
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def health_check_target(proxy_info: tuple[str, int] | None) -> tuple[str, int] | None:
    if not proxy_info:
        return None
    host, port = proxy_info
    if isinstance(host, str) and host.startswith("socks="):
        host = host.split("=", 1)[1]
    return host, port


__all__ = [
    "ConnectionRequest",
    "ConnectionResult",
    "ConnectionService",
    "build_preset_payload",
    "health_check_target",
    "platform_error",
    "resolve_engine_name",
    "temporary_env_overrides",
]
