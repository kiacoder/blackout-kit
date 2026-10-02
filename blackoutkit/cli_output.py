"""Shared output, error, and sensitive-input helpers for the CLI."""
from __future__ import annotations

import getpass
import json
import sys
import time
from dataclasses import dataclass
from typing import Any, TextIO

from rich.console import Console
from rich.table import Table

OUTPUT_SCHEMA_VERSION = 1
DEFAULT_INPUT_LIMIT = 2 * 1024 * 1024
_SAFE_SOURCE_LABELS = frozenset({
    "settings",
    "saved-configs",
    "local-readiness",
    "binary-registry",
    "platform",
    "legacy-dispatcher",
    "typer-adapter",
})


class OptionalDependencyError(RuntimeError):
    """Raised when a feature is used without its optional installation extra."""

    def __init__(self, feature: str, dependency: str, prerequisite: str | None = None):
        self.feature = feature
        self.dependency = dependency
        self.prerequisite = prerequisite
        message = f"{feature} support is unavailable; install blackout-kit[{feature}] ({dependency})"
        if prerequisite:
            message += f". {prerequisite}"
        super().__init__(message)


def require_import(
    feature: str,
    module: str,
    dependency: str | None = None,
    prerequisite: str | None = None,
):
    """Import an optional module or raise a stable feature-specific error."""
    try:
        return __import__(module, fromlist=["*"])
    except (ImportError, ModuleNotFoundError) as exc:
        raise OptionalDependencyError(feature, dependency or module, prerequisite) from exc


def require_executable(feature: str, executable: str, dependency: str | None = None) -> str:
    """Return an optional executable path or raise a stable feature-specific error."""
    import shutil

    path = shutil.which(executable)
    if not path:
        raise OptionalDependencyError(feature, dependency or executable)
    return path


@dataclass(frozen=True)
class OutputOptions:
    """Output preferences propagated from the root Typer context."""

    json_output: bool = False
    quiet: bool = False
    verbose: bool = False
    no_color: bool = False
    json_lines: bool = False


def success_payload(data: Any) -> dict[str, Any]:
    return {"schema_version": OUTPUT_SCHEMA_VERSION, "ok": True, "data": data}


def error_payload(code: str, message: str, details: Any = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if details is not None:
        error["details"] = details
    return {
        "schema_version": OUTPUT_SCHEMA_VERSION,
        "ok": False,
        "error": error,
    }


def emit_json(
    data: Any,
    *,
    console: Console,
    envelope: bool = True,
) -> None:
    payload = success_payload(data) if envelope else data
    console.print(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        markup=False,
        highlight=False,
        soft_wrap=True,
    )


def emit_jsonl(
    data: Any,
    *,
    console: Console,
    envelope: bool = True,
) -> None:
    emit_json(data, console=console, envelope=envelope)


def emit_error(
    code: str,
    message: str,
    *,
    console: Console,
    exit_code: int = 1,
    details: Any = None,
    json_output: bool = False,
) -> int:
    if json_output:
        emit_json(error_payload(code, message, details), console=console, envelope=False)
    else:
        console.print(f"[error]{message}[/error]")
    return exit_code


def read_stdin(*, stream: TextIO | None = None, limit: int = DEFAULT_INPUT_LIMIT) -> str:
    """Read one bounded value from stdin without printing it."""
    source = stream or sys.stdin
    value = source.read(limit + 1)
    if len(value) > limit:
        raise ValueError(f"input exceeds the {limit} byte limit")
    return value.rstrip("\r\n")


def read_secret(
    prompt: str,
    *,
    prompt_input: bool = False,
    stdin_input: bool = False,
    stream: TextIO | None = None,
    input_limit: int = DEFAULT_INPUT_LIMIT,
) -> str:
    """Read a secret without echoing it or placing it in routine output."""
    if prompt_input and stdin_input:
        raise ValueError("choose only one secret input mode")
    if stdin_input:
        return read_stdin(stream=stream, limit=input_limit)
    if prompt_input:
        return getpass.getpass(prompt)
    raise ValueError("secret input requires --prompt or --stdin")


def is_quiet(options: OutputOptions) -> bool:
    return options.quiet and not options.json_output


def print_success(message: str, *, console: Console, options: OutputOptions) -> None:
    if not is_quiet(options):
        console.print(message)


def print_warning(message: str, *, console: Console, options: OutputOptions) -> None:
    if not is_quiet(options):
        console.print(message)


def emit_verbose(
    *,
    options: OutputOptions,
    command: str,
    started: float,
    sources: tuple[str, ...] = (),
    stream: TextIO | None = None,
) -> None:
    """Write allowlisted local timing metadata to stderr only."""
    if not options.verbose:
        return
    safe_sources = tuple(label for label in sources if label in _SAFE_SOURCE_LABELS)
    target = stream or sys.stderr
    elapsed_ms = max(0.0, (time.perf_counter() - started) * 1000)
    target.write(
        f"verbose command={command} elapsed_ms={elapsed_ms:.2f} "
        f"sources={','.join(safe_sources) or 'none'}\n"
    )
    target.flush()


def sanitize_diagnostic_detail(message: object) -> str:
    """Return a bounded diagnostic category without paths or exception data."""
    text = str(message or "").casefold()
    if "not installed" in text or "missing" in text:
        return "dependency or local resource unavailable"
    if "permission" in text or "administrator" in text or "sudo" in text:
        return "additional permissions required"
    if "timeout" in text or "connection" in text or "internet" in text:
        return "local connectivity check did not complete"
    if "unsupported" in text or "unavailable" in text:
        return "feature unavailable on this platform"
    if text in {"ok", "installed", "n/a", "connected"}:
        return str(message)
    return "check completed with additional details available in human output"


def safe_doctor_check(result: object) -> dict[str, object]:
    """Serialize a doctor result without forwarding user-controlled detail."""
    return {
        "name": str(getattr(result, "name", "unknown"))[:80],
        "ok": bool(getattr(result, "ok", False)),
        "detail": sanitize_diagnostic_detail(getattr(result, "message", "")),
        "fixable": bool(getattr(result, "fixable", False)),
    }


SAFE_SOURCE_LABELS = _SAFE_SOURCE_LABELS


# ───────────────────── Blackout Operator renderers ─────────────────────
# Human presentation for the structured snapshot / recommendation / event
# layers. All data arrives already sanitized; renderers never compute state.

_SEVERITY_STYLES = {
    "debug": "dim",
    "info": "cyan",
    "warning": "yellow",
    "error": "red",
    "critical": "bold red",
}


def _kv_table(title: str) -> "Table":
    table = Table(show_header=False, padding=(0, 2), title=title)
    table.add_column("Field", style="bold cyan", no_wrap=True)
    table.add_column("Value")
    return table


def render_snapshot(snapshot: dict[str, Any], *, console: Console) -> None:
    """Render the canonical local snapshot."""
    from rich.panel import Panel

    engines = snapshot.get("engines") or {}
    ready = engines.get("ready") or []
    recommended = (engines.get("recommended") or {}).get("engine")
    daemon_info = snapshot.get("daemon") or {}
    proxy = snapshot.get("system_proxy") or {}
    vault_info = snapshot.get("vault") or {}

    overview = _kv_table("Local Snapshot")
    overview.add_row("Generated", str(snapshot.get("generated_at", "")))
    overview.add_row("Platform", f"{snapshot.get('platform', {}).get('system')} · "
                                 f"admin={snapshot.get('privileges', {}).get('admin')}")
    overview.add_row("Daemon", "running" if daemon_info.get("running") else "not running")
    overview.add_row("Active engine", str(daemon_info.get("engine", "none")))
    overview.add_row("System proxy", f"enabled={proxy.get('enabled')}"
                                     f"{' (' + str(proxy.get('server')) + ')' if proxy.get('enabled') else ''}")
    overview.add_row("Vault", str(vault_info.get("detail", "unknown")))
    overview.add_row("Ready engines", ", ".join(ready) if ready else "none")
    overview.add_row("Recommendation", str(recommended or "none"))
    console.print(Panel(overview, border_style="panel.border"))
    events_info = snapshot.get("events") or {}
    render_events((events_info.get("recent") or [])[-5:], console=console)
    console.print(f"[muted]{(snapshot.get('scope') or {}).get('note', '')}[/muted]")


def render_recommendations(payload: dict[str, Any], *, console: Console) -> None:
    """Render deterministic recommendations."""
    from rich.panel import Panel
    from rich.table import Table as RichTable

    recs = payload.get("recommendations") or []
    table = RichTable(show_header=True, header_style="bold cyan", padding=(0, 2),
                      title="Deterministic Recommendations (local evidence only)")
    table.add_column("Problem")
    table.add_column("Action")
    table.add_column("Safety")
    table.add_column("Risk")
    table.add_column("Conf.")
    table.add_column("Reason")
    for rec in recs:
        table.add_row(
            str(rec.get("problem", "")),
            str(rec.get("recommended_action", "")),
            str(rec.get("safety", "")),
            str(rec.get("risk", "")),
            f"{rec.get('confidence', 0):.2f}",
            str(rec.get("reason", "")),
        )
    console.print(Panel(table, border_style="panel.border"))
    console.print(f"[muted]{payload.get('note', '')}[/muted]")


def render_operator_status(payload: dict[str, Any], *, console: Console) -> None:
    """Render the live operator view: snapshot + top recommendation."""
    render_snapshot(payload.get("snapshot") or {}, console=console)
    recs = payload.get("recommendations") or []
    if recs:
        top = recs[0]
        approval = ""
        if top.get("requires_confirmation"):
            approval = " · needs your confirmation before anyone applies it"
        console.print(
            f"[bold]Next:[/bold] {top.get('recommended_action')} "
            f"[dim]({top.get('problem')}, risk={top.get('risk')}{approval})[/dim]"
        )
    pending = [
        event for event in ((payload.get("snapshot") or {}).get("events") or {}).get("recent", [])
        if event.get("type") == "user.approval_required"
    ]
    if pending:
        console.print("[warning]⚠ Human input required (user.approval_required events pending)[/warning]")


def render_action_catalog(payload: dict[str, Any], *, console: Console) -> None:
    from rich.table import Table as RichTable

    table = RichTable(show_header=True, header_style="bold cyan", padding=(0, 2),
                      title="Action Catalog (safety classes)")
    table.add_column("Action")
    table.add_column("Safety")
    table.add_column("Admin")
    table.add_column("Confirmation")
    table.add_column("Description")
    for action in payload.get("actions", []):
        table.add_row(
            str(action.get("name", "")),
            str(action.get("safety", "")),
            "yes" if action.get("requires_admin") else "no",
            "required" if action.get("requires_confirmation") else "not required",
            str(action.get("description", "")),
        )
    console.print(table)


def render_events(events: list[dict[str, Any]], *, console: Console) -> None:
    from rich.table import Table as RichTable

    if not events:
        console.print("[muted]No local events recorded yet.[/muted]")
        return
    table = RichTable(show_header=True, header_style="bold cyan", padding=(0, 2),
                      title="Recent Local Events")
    table.add_column("Time")
    table.add_column("Type")
    table.add_column("Sev.")
    table.add_column("Engine")
    table.add_column("Summary")
    for event in events:
        style = _SEVERITY_STYLES.get(str(event.get("severity")), "white")
        table.add_row(
            str(event.get("timestamp", ""))[:19],
            str(event.get("type", "")),
            f"[{style}]{event.get('severity', 'info')}[/{style}]",
            str(event.get("engine") or "—"),
            str(event.get("summary") or ""),
        )
    console.print(table)


def render_support_preview(payload: dict[str, Any], *, console: Console) -> None:
    from rich.panel import Panel

    snapshot_info = payload.get("snapshot") or {}
    body = (
        f"[bold]Support bundle preview[/bold] — nothing is written or uploaded by a preview.\n\n"
        f"system: {payload.get('system', {}).get('platform')} · python {payload.get('system', {}).get('python')}\n"
        f"install: {(payload.get('install') or {}).get('method')}\n"
        f"versions: {len(payload.get('versions') or {})} entries\n"
        f"snapshot: {snapshot_info.get('section_count')} sections "
        f"({', '.join(snapshot_info.get('fields', [])[:8])}…)\n"
        f"daemon_errors: {(payload.get('daemon_errors') or {}).get('line_count')} lines\n"
        f"logs: daemon tail {(payload.get('logs') or {}).get('daemon_tail_chars')} chars\n"
        f"recovery_history: {(payload.get('recovery_history') or {}).get('record_count')} records\n"
        f"settings: {(payload.get('settings') or {}).get('key_count')} keys (sensitive values redacted)\n\n"
        f"[bold]Redaction:[/bold] {payload.get('redaction_policy', {}).get('strategy')}\n"
        f"[bold]Never included:[/bold]\n"
        + "\n".join(f"  • {item}" for item in payload.get("excluded", []))
    )
    console.print(Panel(body, border_style="panel.border"))


def render_support_summary(path: "Any", *, console: Console) -> None:
    from rich.panel import Panel

    console.print(Panel(
        f"[success]✓ Support bundle written[/success]\n\n"
        f"[bold]{path}[/bold]\n\n"
        "Credentials, proxy/VPN/SSH URIs, and vault contents were removed.\n"
        "Review the file before sharing it. Blackout Kit does not upload it anywhere.",
        border_style="green",
    ))


__all__ = [
    "DEFAULT_INPUT_LIMIT",
    "OUTPUT_SCHEMA_VERSION",
    "SAFE_SOURCE_LABELS",
    "OptionalDependencyError",
    "OutputOptions",
    "emit_error",
    "emit_json",
    "emit_jsonl",
    "emit_verbose",
    "error_payload",
    "is_quiet",
    "print_success",
    "print_warning",
    "read_secret",
    "read_stdin",
    "render_action_catalog",
    "render_events",
    "render_operator_status",
    "render_recommendations",
    "render_snapshot",
    "render_support_preview",
    "render_support_summary",
    "require_executable",
    "require_import",
    "safe_doctor_check",
    "sanitize_diagnostic_detail",
    "success_payload",
]
