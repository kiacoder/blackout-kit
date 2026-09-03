"""
Blackout Kit - Modern Typer CLI (Migration in Progress).
This will eventually replace cli.py.
"""
from __future__ import annotations

from dataclasses import dataclass
import base64
import json
import sys
import time
from pathlib import Path

import click
import typer
import typer._click.exceptions as typer_exceptions
from typer.core import TyperGroup

if not sys.stdout.isatty():
    import typer.rich_utils as _typer_rich_utils

    _typer_rich_utils.FORCE_TERMINAL = False

from . import __version__
from .cli_output import (
    OptionalDependencyError,
    OutputOptions,
    emit_error,
    emit_json,
    emit_jsonl,
    emit_verbose,
    error_payload,
    is_quiet,
    read_secret,
    require_import,
    safe_doctor_check,
)
from .theme import (
    ask_choice,
    ask_int,
    ask_text,
    confirm,
    console,
    is_interactive,
    make_table,
    print_friendly_error,
    refresh_console_theme,
)


_DEFAULT_NO_COLOR = console.no_color


@dataclass(frozen=True)
class StatusArgs:
    watch: bool = False
    interval: float = 2.0


@dataclass(frozen=True)
class RouteArgs:
    pass


@dataclass(frozen=True)
class ConnectArgs:
    pos_engine: str | None = None
    engine: str | None = None
    background: bool = False
    iran: bool = False
    russia: bool = False


@dataclass(frozen=True)
class DoctorArgs:
    fix: bool = False
    fix_av: bool = False
    include_optional: bool = False
    local_only: bool = False


def _option_value(value, default=None):
    if value.__class__.__name__ in {"OptionInfo", "ArgumentInfo"}:
        value = value.default
    return default if value is None and default is not None else value


def _args(**values):
    """Build the legacy dispatcher namespace at a typed command boundary."""
    from argparse import Namespace

    return Namespace(**values)


def _output_options(ctx: typer.Context | None = None) -> OutputOptions:
    current = ctx
    while current is not None:
        obj = getattr(current, "obj", None)
        if isinstance(obj, dict) and isinstance(obj.get("output"), OutputOptions):
            return obj["output"]
        current = getattr(current, "parent", None)
    return OutputOptions()


def _print_json(payload) -> None:
    emit_json(payload, console=console, envelope=False)


def _print_json_enveloped(data) -> None:
    emit_json(data, console=console, envelope=True)


def _print_json_lines(data) -> None:
    emit_jsonl(data, console=console, envelope=True)


def _print_cli_error(code: str, message: str, *, options: OutputOptions, exit_code: int = 1) -> None:
    emit_error(
        code,
        message,
        console=console,
        exit_code=exit_code,
        json_output=options.json_output,
    )
    raise typer.Exit(code=exit_code)


def _optional_dependency_error(exc: OptionalDependencyError, *, options: OutputOptions) -> None:
    _print_cli_error("optional_dependency_missing", str(exc), options=options, exit_code=1)


def _fail_parameter(message: str, *, options: OutputOptions) -> None:
    if options.json_output:
        _print_cli_error("invalid_input", message, options=options, exit_code=2)
    raise typer.BadParameter(message)


def _read_cli_secret(
    prompt: str,
    *,
    prompt_input: bool,
    stdin_input: bool,
) -> str:
    try:
        return read_secret(
            prompt,
            prompt_input=prompt_input,
            stdin_input=stdin_input,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc


def _is_quiet(options: OutputOptions) -> bool:
    return is_quiet(options)


def _print_success(message: str, options: OutputOptions) -> None:
    if not _is_quiet(options):
        console.print(message)


def _print_warning(message: str, options: OutputOptions) -> None:
    if not _is_quiet(options):
        console.print(message)


def _safe_settings(settings: dict) -> dict:
    from . import settings as cfg

    return {
        key: cfg.display_value(key, settings.get(key, default))
        for key, default in cfg.DEFAULTS.items()
    }


def _envelope(data: dict) -> dict:
    return {"schema_version": 1, "ok": True, "data": data}


def _config_payload(configs: list) -> dict:
    return {
        "configs": [
            {
                "index": index,
                "protocol": config.protocol,
                "transport": config.transport_label(),
                "sni_compatible": config.is_sni_compatible(),
                "name": config.name or None,
            }
            for index, config in enumerate(configs, 1)
        ]
    }


def _settings_payload(settings: dict) -> dict:
    from . import settings as cfg

    return {
        "settings": _safe_settings(settings),
        "groups": [{"name": name, "keys": keys} for name, keys in cfg.iter_setting_groups()],
    }


def _status_payload(snapshot: dict) -> dict:
    payload = dict(snapshot)
    payload["settings"] = _safe_settings(snapshot.get("settings", {}))
    proxy = snapshot.get("proxy")
    if isinstance(proxy, dict):
        payload["proxy"] = {
            "enabled": bool(proxy.get("enabled")),
            "configured": bool(proxy.get("server")),
        }
    return payload


def _output_from_context(ctx: typer.Context | None) -> OutputOptions:
    return _output_options(ctx)


def _route_payload(candidates: list) -> dict:
    recommended = next((item for item in candidates if item.ready), candidates[0] if candidates else None)
    return {
        "recommended": recommended.engine if recommended else None,
        "candidates": [
            {
                "engine": item.engine,
                "score": item.score,
                "ready": item.ready,
                "evidence": item.evidence,
                "blockers": list(item.blockers),
                "stability": item.stability,
            }
            for item in candidates
        ],
    }


def _one_based_index(number: int) -> int:
    number = _option_value(number)
    if number is None or number < 1:
        raise typer.BadParameter("config number must be at least 1")
    return number - 1


def _render_settings(settings: dict) -> None:
    from rich.markup import escape
    from . import settings as cfg

    table = make_table(
        "Settings",
        [("Key", "cyan"), ("Value", "bold white"), ("Description", "dim")],
        [],
    )
    for key, default in cfg.DEFAULTS.items():
        value = cfg.display_value(key, settings.get(key, default))
        if isinstance(value, list):
            value = ", ".join(str(item) for item in value)
        table.add_row(
            escape(key),
            escape(str(value)),
            escape(cfg.describe(key)),
        )
    console.print(table)


def _render_config_list(configs: list, options: OutputOptions | None = None) -> None:
    from rich.markup import escape

    options = options or OutputOptions()
    if _is_quiet(options):
        return
    if not configs:
        console.print("[warning]No configs saved. Use 'blackout config add' or 'blackout config import'.[/warning]")
        return
    table = make_table(
        f"Saved Configs  ({len(configs)})",
        [("#", "dim"), ("Protocol", "cyan"), ("Transport", "yellow"),
         ("Compatible", ""), ("Name", "white")],
        [],
    )
    for index, config in enumerate(configs, 1):
        compatibility = "SNI" if config.is_sni_compatible() else "direct"
        table.add_row(
            str(index),
            escape(config.protocol),
            escape(config.transport_label()),
            escape(compatibility),
            escape(config.name or "-"),
        )
    console.print(table)


def _setup_blob() -> str:
    from .config.manager import serialize_setup

    return base64.b64encode(
        json.dumps(serialize_setup(), sort_keys=True).encode("utf-8")
    ).decode("ascii")


def _validate_setup_data(setup_data: dict) -> tuple[list, dict]:
    from . import settings as cfg
    from .config.manager import deserialize_setup

    try:
        configs, settings_data = deserialize_setup(setup_data)
    except ValueError as exc:
        raise typer.BadParameter(f"Invalid setup data: {exc}") from exc

    seen_uris = set()
    for config in configs:
        if not config.raw_uri:
            raise typer.BadParameter("Setup contains a config without a URI")
        if config.raw_uri in seen_uris:
            raise typer.BadParameter("Setup contains duplicate config URIs")
        seen_uris.add(config.raw_uri)
    try:
        settings_data = cfg.validate_updates(settings_data)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    return configs, settings_data


def _decode_setup(setup_string: str) -> tuple[list, dict]:
    try:
        blob = base64.b64decode(
            "".join(setup_string.split()).encode("ascii"),
            validate=True,
        )
        setup_data = json.loads(blob.decode("utf-8"))
    except (base64.binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise typer.BadParameter(f"Invalid setup string: {exc}") from exc
    return _validate_setup_data(setup_data)


def _read_profile_passphrase(*, prompt: bool, stdin_input: bool) -> str:
    return _read_cli_secret(
        "Profile passphrase: ",
        prompt_input=prompt,
        stdin_input=stdin_input,
    )


def _read_profile_file(path: Path) -> bytes:
    from . import vault

    profile_path = path.expanduser().resolve()
    try:
        if profile_path.stat().st_size > vault.PROFILE_MAX_BYTES:
            raise ValueError("encrypted profile exceeds the size limit")
        return profile_path.read_bytes()
    except OSError as exc:
        raise ValueError("encrypted profile could not be read") from exc


def _apply_setup(configs: list, settings_data: dict) -> None:
    from .config.manager import load_configs, save_configs
    from . import settings as cfg

    old_configs = load_configs()
    old_settings = cfg.load()
    try:
        save_configs(configs)
        updated = dict(old_settings)
        updated.update(settings_data)
        cfg.save(updated)
    except Exception:
        try:
            save_configs(old_configs)
        except Exception:
            pass
        raise


def _compatibility_payload(configs: list) -> dict:
    from . import settings as cfg
    from . import downloader
    from .capabilities import build_capability_matrix
    from .routing import recommend_routes

    settings = cfg.load()
    installed = downloader.check_installed()
    protocols = sorted({str(config.protocol).lower() for config in configs})
    candidates = recommend_routes(
        settings,
        installed=installed,
        protocols=set(protocols),
        configs=configs,
        stability_scores={},
    )
    by_engine = {candidate.engine: candidate for candidate in candidates}
    rows = build_capability_matrix(
        settings=settings,
        installed=installed,
        configs=configs,
    )
    engines = []
    for row in rows:
        candidate = by_engine.get(row["name"])
        if candidate is None:
            continue
        engines.append({
            "engine": candidate.engine,
            "score": candidate.score,
            "ready": candidate.ready,
            "evidence": candidate.evidence,
            "blockers": list(candidate.blockers),
            "stability": candidate.stability,
            "compatible_protocols": row["compatible_protocols"],
            "required_components": row["runtime_requirements"],
            "required_settings": [
                {
                    "key": key,
                    "configured": key not in row["blockers"] and not any(
                        blocker == f"{key} not configured" for blocker in row["blockers"]
                    ),
                }
                for key in row["required_settings"]
            ],
        })
    return {
        "configs": _config_payload(configs)["configs"],
        "saved_protocols": protocols,
        "installed_components": {
            key: bool(value) for key, value in sorted(installed.items())
        },
        "engines": engines,
    }


def _config_diff_payload(current: list, incoming: list, current_settings: dict, incoming_settings: dict) -> dict:
    from . import settings as cfg

    records = []
    for index in range(max(len(current), len(incoming))):
        old = current[index] if index < len(current) else None
        new = incoming[index] if index < len(incoming) else None
        if old is None:
            status = "added"
        elif new is None:
            status = "removed"
        elif old.raw_uri != new.raw_uri:
            status = "changed"
        else:
            status = "unchanged"
        current_record = _config_payload([old])["configs"][0] if old else None
        incoming_record = _config_payload([new])["configs"][0] if new else None
        if current_record is not None:
            current_record["index"] = index + 1
        if incoming_record is not None:
            incoming_record["index"] = index + 1
        records.append({
            "index": index + 1,
            "status": status,
            "current": current_record,
            "incoming": incoming_record,
        })

    setting_changes = []
    for key in sorted(incoming_settings):
        old_value = current_settings.get(key, cfg.DEFAULTS.get(key))
        new_value = incoming_settings[key]
        if old_value != new_value:
            setting_changes.append({
                "key": key,
                "current": cfg.display_value(key, old_value),
                "incoming": cfg.display_value(key, new_value),
            })
    return {
        "configs": records,
        "config_changes": sum(item["status"] != "unchanged" for item in records),
        "settings": setting_changes,
        "setting_changes": len(setting_changes),
    }


def _json_requested(argv: list[str] | None = None, ctx: click.Context | None = None) -> bool:
    current = ctx
    while current is not None:
        if current.params.get("json_output"):
            return True
        current = current.parent
    return "--json" in (sys.argv[1:] if argv is None else argv)


def _parser_error_message(error: BaseException) -> str:
    missing_parameter = (
        click.exceptions.MissingParameter,
        typer_exceptions.MissingParameter,
    )
    no_such_option = (
        click.exceptions.NoSuchOption,
        typer_exceptions.NoSuchOption,
    )
    bad_parameter = (
        click.exceptions.BadParameter,
        typer_exceptions.BadParameter,
    )
    if isinstance(error, missing_parameter):
        return "a required command input is missing"
    if isinstance(error, no_such_option):
        return "an unsupported command option was provided"
    if isinstance(error, bad_parameter):
        return "a command input has an invalid value"
    if isinstance(error, (click.UsageError, typer_exceptions.UsageError)):
        return "invalid command usage"
    return "invalid command usage"


class _JsonTyperGroup(TyperGroup):
    """Keep parser failures machine-readable only for explicit JSON requests."""

    _usage_error_types = (click.UsageError, typer_exceptions.UsageError)
    _exit_type = click.exceptions.Exit

    def _emit_parser_error(
        self,
        error: BaseException,
        ctx: click.Context | None = None,
        argv: list[str] | None = None,
    ) -> None:
        if not _json_requested(argv=argv, ctx=ctx):
            raise error
        emit_error(
            "invalid_input",
            _parser_error_message(error),
            console=console,
            exit_code=2,
            json_output=True,
        )
        raise SystemExit(2) from error

    def parse_args(self, ctx: click.Context, args: list[str]) -> list[str]:
        original_args = list(args)
        try:
            return super().parse_args(ctx, args)
        except self._usage_error_types as exc:
            self._emit_parser_error(exc, ctx, original_args)
            raise AssertionError("unreachable")

    def invoke(self, ctx: click.Context):
        try:
            return super().invoke(ctx)
        except self._usage_error_types as exc:
            self._emit_parser_error(exc, ctx)
            raise AssertionError("unreachable")

    def main(self, args=None, **kwargs):
        argv = list(sys.argv[1:] if args is None else args)
        try:
            return super().main(args=argv, **kwargs)
        except self._exit_type:
            raise
        except self._usage_error_types as exc:
            self._emit_parser_error(exc, argv=argv)
            raise AssertionError("unreachable")


app = typer.Typer(
    cls=_JsonTyperGroup,
    name="blackout",
    help="Blackout Kit — Network Security & Bypass Toolkit",
    add_completion=True,
    no_args_is_help=False,
    rich_markup_mode="rich"
)

# We will gradually port commands from cli.py into here.


def _capability_payload(engine: str | None = None) -> dict:
    from .capabilities import build_capability_matrix
    from . import settings as cfg
    from .config.manager import load_configs
    from .downloader import check_installed

    rows = build_capability_matrix(
        settings=cfg.load(),
        installed=check_installed(),
        configs=load_configs(),
    )
    if engine:
        normalized = engine.strip().lower()
        rows = [row for row in rows if row["name"] == normalized]
    return {"engine_count": len(rows), "engines": rows}


def _render_capabilities(payload: dict) -> None:
    table = make_table(
        "Capability Matrix",
        [("Engine", "cyan"), ("Platform", ""), ("State", ""),
         ("Upstream", "yellow"), ("Runtime", "dim"), ("Privilege", "dim")],
        [],
    )
    for row in payload["engines"]:
        state = row["state"]
        state_text = "[success]ready[/success]" if state == "ready" else (
            "[muted]unsupported[/muted]" if state == "unsupported" else "[warning]blocked[/warning]"
        )
        table.add_row(
            row["name"],
            ", ".join(row["platforms"]),
            state_text,
            row["upstream_requirement"],
            ", ".join(row["runtime_requirements"]) or "-",
            row["privilege"],
        )
    console.print(table)
    console.print(
        "[muted]Cataloged engines remain visible even when unavailable here. "
        "Ready means local prerequisites only; it does not prove upstream reachability.[/muted]"
    )


@app.command()
def capabilities(
    engine: str = typer.Argument(None, help="Show one capability (omit to show the full catalog)"),
    ctx: typer.Context = None,
):
    """Show the full engine capability matrix without starting anything."""
    engine = _option_value(engine)
    options = _output_options(ctx)
    payload = _capability_payload(engine)
    if engine and not payload["engines"]:
        _fail_parameter(f"Unknown capability: '{engine}'", options=options)
    if options.json_output:
        _print_json_enveloped(payload)
        return
    if not _is_quiet(options):
        _render_capabilities(payload)


@app.command()
def demo(ctx: typer.Context = None):
    """Show a read-only simulation of the local Blackout Kit workflow."""
    from .demo import build_demo_report

    options = _output_options(ctx)
    report = build_demo_report()
    if options.json_output:
        _print_json_enveloped(report)
        return
    if not _is_quiet(options):
        from rich.panel import Panel
        console.print(Panel(
            "[bold]SIMULATION ONLY[/bold]\n\n"
            "This demonstration starts no engines, contacts no remote hosts, downloads nothing, "
            "changes no system or network state, and terminates no processes.",
            title="Blackout Kit Demo",
            border_style="cyan",
        ))
        _render_capabilities({"engines": report["capabilities"]})
        console.print("[bold]Golden path:[/bold] " + " → ".join(report["golden_path"]))
        console.print("[muted]Use `blackout setup` for the guided path. A local green check is not remote reachability.[/muted]")


@app.command()
def setup(
    connect: bool = typer.Option(False, "--connect", help="Ask for confirmation, then run the selected connection"),
    ctx: typer.Context = None,
):
    """Run the beginner-friendly local setup checklist before connecting."""
    from .onboarding import build_current_setup_plan, render_setup_plan, run_setup

    options = _output_options(ctx)
    connect = bool(_option_value(connect, False))
    if connect and (options.json_output or _is_quiet(options) or not is_interactive()):
        _print_cli_error(
            "invalid_input",
            "setup --connect requires an interactive terminal; the noninteractive checklist is read-only",
            options=options,
            exit_code=2,
        )
    if options.json_output or _is_quiet(options) or not is_interactive():
        plan = build_current_setup_plan(read_only=True)
        if options.json_output:
            _print_json_enveloped(plan.payload())
            if plan.blockers:
                raise typer.Exit(code=1)
            return
        if not _is_quiet(options):
            render_setup_plan(plan, console)
        if plan.blockers:
            raise typer.Exit(code=1)
        if not connect:
            if not _is_quiet(options):
                console.print("[muted]Checklist complete. Run `blackout setup --connect` only when you are ready to start networking.[/muted]")
            return
    else:
        plan = run_setup(console=console)
        if plan.blockers:
            console.print(
                "[warning]Nothing was changed. Follow the blocker guidance, then run `blackout setup` again.[/warning]"
            )
            raise typer.Exit(code=1)
        if not connect:
            console.print("[muted]Checklist complete. Run `blackout setup --connect` only when you are ready to start networking.[/muted]")
            return

    if not confirm(
        f"Start {plan.recommended_engine or 'the selected engine'} and allow its documented local network changes?",
        default=False,
    ):
        console.print("[muted]Connection not started.[/muted]")
        return
    from .connection_service import ConnectionRequest
    result = _connection_service(options).connect(ConnectionRequest(
        operation="connect",
        pos_engine=plan.recommended_engine,
    ))
    _render_connection_result(result, options)
    if not result.ok:
        raise typer.Exit(code=1)




@app.command()
def version(ctx: typer.Context = None):
    """Show the Blackout Kit version."""
    options = _output_from_context(ctx)
    if options.json_output:
        _print_json_enveloped({"name": "blackout-kit", "version": __version__})
        return
    if not _is_quiet(options):
        console.print(f"blackout-kit [bold green]{__version__}[/bold green]")

def _recovery_flags(
    full_route_reset: bool,
    full_stack_reset: bool,
    flush_arp: bool,
) -> tuple[dict[str, bool], list[str]]:
    flags = {
        "full_route_reset": bool(full_route_reset),
        "full_stack_reset": bool(full_stack_reset),
        "flush_arp": bool(flush_arp),
    }
    warnings = []
    if sys.platform.startswith("linux") and (flags["full_route_reset"] or flags["full_stack_reset"]):
        warnings.append("Full route and stack resets are Windows-only. Linux recovery remains targeted.")
        flags["full_route_reset"] = False
        flags["full_stack_reset"] = False
    if flags["flush_arp"]:
        warnings.append("ARP flushing is explicit and may briefly interrupt local-network discovery.")
    return flags, warnings


def _recovery_platform_supported() -> bool:
    return sys.platform == "win32" or sys.platform.startswith("linux")


def _recovery_success(steps: list[dict]) -> bool:
    return all(bool(step.get("ok")) for step in steps)




def _recovery_steps_payload(steps: list[dict]) -> list[dict[str, object]]:
    from . import recovery_audit

    return [
        {
            "name": recovery_audit.redact(step.get("name", ""))[:120],
            "ok": bool(step.get("ok")),
            "detail": recovery_audit.redact(step.get("detail", ""))[:240],
        }
        for step in steps
        if isinstance(step, dict)
    ]


def _recovery_history_payload(records: list[dict]) -> list[dict[str, object]]:
    from . import recovery_audit

    payload = []
    for record in records:
        if not isinstance(record, dict):
            continue
        flags = record.get("flags") if isinstance(record.get("flags"), dict) else {}
        actions = record.get("actions") if isinstance(record.get("actions"), list) else []
        payload.append({
            "timestamp": recovery_audit.redact(record.get("timestamp", ""))[:40],
            "source": recovery_audit.redact(record.get("source", ""))[:40],
            "platform": recovery_audit.redact(record.get("platform", ""))[:20],
            "flags": {
                key: bool(flags.get(key))
                for key in ("full_route_reset", "full_stack_reset", "flush_arp")
            },
            "actions": [
                {
                    "name": recovery_audit.redact(action.get("name", ""))[:120],
                    "ok": bool(action.get("ok")),
                    "detail": recovery_audit.redact(action.get("detail", ""))[:240],
                }
                for action in actions
                if isinstance(action, dict)
            ],
        })
    return payload


def _render_recovery_steps(steps: list[dict], *, preview: bool) -> None:
    from rich.markup import escape

    table = make_table(
        "Recovery Plan" if preview else "Recovery Results",
        [("Step", "white"), ("Status", ""), ("Details", "dim")],
        [],
    )
    for step in _recovery_steps_payload(steps):
        if preview:
            status = "[cyan]Planned[/cyan]"
        else:
            status = "[green]Done[/green]" if step["ok"] else "[red]Failed[/red]"
        table.add_row(
            escape(step["name"]),
            status,
            escape(step["detail"]),
        )
    console.print(table)


def _render_recovery_history(records: list[dict]) -> None:
    from rich.panel import Panel

    console.print(Panel(
        json.dumps(_recovery_history_payload(records), indent=2, ensure_ascii=False),
        title="[heading]Recovery Audit History[/heading]",
        border_style="panel.border",
    ))


def _run_recovery_flow(
    *,
    flags: dict[str, bool],
    preview: bool,
    options: OutputOptions,
    audit_source: str,
    warnings: list[str] | None = None,
    command_label: str = "fix",
) -> None:
    if not _recovery_platform_supported():
        _print_cli_error(
            "unsupported_platform",
            f"`blackout {command_label}` is supported only on Windows and Linux",
            options=options,
        )

    warnings = list(warnings or [])
    from . import tools as recovery_tools

    try:
        plan = recovery_tools.plan_network_recovery(**flags)
    except Exception:
        _print_cli_error(
            "recovery_plan_failed",
            "Blackout Kit could not prepare the local recovery plan",
            options=options,
        )

    if preview:
        payload = {
            "operation": "preview",
            "flags": flags,
            "warnings": warnings,
            "steps": _recovery_steps_payload(plan),
            "success": True,
        }
        if options.json_output:
            _print_json_enveloped(payload)
        elif not _is_quiet(options):
            _render_recovery_steps(plan, preview=True)
            console.print("[muted]Preview only: no system state or audit log was changed.[/muted]")
        return

    try:
        results = recovery_tools.run_network_recovery(
            **flags,
            audit_source=audit_source,
        )
    except Exception:
        _print_cli_error(
            "recovery_failed",
            "Blackout Kit could not complete local network recovery",
            options=options,
        )

    success = _recovery_success(results)
    payload = {
        "operation": "execute",
        "flags": flags,
        "warnings": warnings,
        "steps": _recovery_steps_payload(results),
        "success": success,
    }
    if options.json_output:
        _print_json_enveloped(payload)
    elif not _is_quiet(options):
        _render_recovery_steps(results, preview=False)
        message = "[success]Recovery completed.[/success]" if success else "[error]Recovery completed with failures.[/error]"
        console.print(message)
    if not success:
        raise typer.Exit(code=1)


@app.command()
def fix(
    full_route_reset: bool = typer.Option(
        False,
        "--full-route-reset",
        help="Emergency only: flush every IPv4 route before renewing DHCP",
    ),
    full_stack_reset: bool = typer.Option(
        False,
        "--full-stack-reset",
        help="Emergency only: reset Winsock, TCP/IP, autotuning, and DHCP",
    ),
    flush_arp: bool = typer.Option(
        False,
        "--flush-arp",
        help="Explicitly flush the local ARP/neighbor cache",
    ),
    preview: bool = typer.Option(False, "--preview", help="Show Blackout-owned recovery actions without changing anything"),
    history: bool = typer.Option(False, "--history", help="Show redacted local recovery audit history"),
    history_lines: int = typer.Option(20, "--history-lines", min=1, max=100, help="Audit records to show with --history"),
    ctx: typer.Context = None,
):
    """Repair targeted post-crash Blackout network state."""
    from . import recovery_audit

    options = _output_options(ctx)
    full_route_reset = bool(_option_value(full_route_reset, False))
    full_stack_reset = bool(_option_value(full_stack_reset, False))
    flush_arp = bool(_option_value(flush_arp, False))
    preview = bool(_option_value(preview, False))
    history = bool(_option_value(history, False))
    history_lines = int(_option_value(history_lines, 20))

    if history:
        records = recovery_audit.history(history_lines)
        payload = {"history": _recovery_history_payload(records), "lines": history_lines}
        if options.json_output:
            _print_json_enveloped(payload)
        elif not _is_quiet(options):
            _render_recovery_history(records)
        return

    flags, warnings = _recovery_flags(full_route_reset, full_stack_reset, flush_arp)
    human_warnings = warnings
    if not options.json_output and not _is_quiet(options):
        for warning in human_warnings:
            console.print(f"[warning]{warning}[/warning]")
        if sys.platform == "win32" and (flags["full_route_reset"] or flags["full_stack_reset"]):
            from rich.panel import Panel

            reset_warnings = []
            if flags["full_route_reset"]:
                reset_warnings.append("`route -f` removes every IPv4 route before DHCP renewal")
            if flags["full_stack_reset"]:
                reset_warnings.append("Winsock, TCP/IP, autotuning, and DHCP will be reset")
            console.print(Panel(
                "[bold red]Emergency network reset enabled.[/bold red]\n"
                f"[dim]{'; '.join(reset_warnings)}. Use only if targeted recovery did not restore connectivity.[/dim]",
                border_style="red",
            ))

    _run_recovery_flow(
        flags=flags,
        preview=preview,
        options=options,
        audit_source="cli",
        warnings=human_warnings,
        command_label="fix",
    )



@app.command()
def scan(
    ips: bool = typer.Option(False, "--ips", help="Scan Cloudflare IPs"),
    sni: bool = typer.Option(False, "--sni", help="Scan fake SNI domains"),
    count: int = typer.Option(None, "--count", "-c", help="Number of IPs to generate")
):
    """Scan Cloudflare IPs and fake SNI domains"""
    from .cli import cmd_scan
    cmd_scan(_args(
        ips=bool(_option_value(ips, False)),
        sni=bool(_option_value(sni, False)),
        count=_option_value(count),
    ))

def _ask_engine(prompt_text: str = "Choose an engine") -> str | None:
    from rich.columns import Columns
    from rich.panel import Panel
    from rich.align import Align
    from .cli import ALL_ENGINE_CHOICES

    if not is_interactive():
        return None
    engine_panels = [Panel(f"[engine]{engine}[/engine]", border_style="panel.border", expand=True) for engine in ALL_ENGINE_CHOICES]
    console.print(Panel(
        Align.center(Columns(engine_panels, align="center", expand=True, equal=True)),
        title="[heading]Available engines[/heading]",
        border_style="panel.border",
        padding=(1, 2),
    ))
    return ask_choice(prompt_text, ALL_ENGINE_CHOICES, default="auto")


def _forward_status(command: StatusArgs, options: OutputOptions) -> None:
    from .cli import _status_snapshot, cmd_status

    if options.json_output:
        if not command.watch:
            _print_json_enveloped(_status_payload(_status_snapshot()))
            return
        try:
            while True:
                _print_json_enveloped(_status_payload(_status_snapshot()))
                time.sleep(command.interval)
        except KeyboardInterrupt:
            return

    cmd_status(command)


@app.command()
def route(ctx: typer.Context = None):
    """Show local, read-only engine recommendations."""
    from .cli import _routing_candidates, cmd_route

    options = _output_from_context(ctx)
    candidates = _routing_candidates()
    if options.json_output:
        _print_json_enveloped(_route_payload(candidates))
        return
    if not _is_quiet(options):
        cmd_route(RouteArgs())


@app.command()
def theme(
    palette: str = typer.Argument(None, help="dark | light (omit to show/select)"),
):
    """Show or set Blackout Kit's terminal-only palette."""
    from .cli import cmd_theme

    palette = _option_value(palette)
    if palette is None and is_interactive():
        from . import settings as cfg
        palette = ask_choice(
            "Choose terminal palette",
            ["dark", "light"],
            default=cfg.load().get("terminal_theme", "dark"),
        )
    if palette is not None and palette not in ("dark", "light"):
        raise typer.BadParameter("must be dark or light")

    args = _args()
    args.palette = palette
    cmd_theme(args)


@app.command()
def status(
    watch: bool = typer.Option(False, "--watch", "-w", help="Refresh local status until Ctrl+C"),
    interval: float = typer.Option(2.0, "--interval", min=0.5, max=60.0, help="Refresh interval in seconds"),
    ctx: typer.Context = None,
):
    """Show daemon status and local connection health."""
    watch = bool(_option_value(watch, False))
    interval = float(_option_value(interval, 2.0))
    options = _output_from_context(ctx)
    if _is_quiet(options):
        return
    _forward_status(StatusArgs(watch=watch, interval=interval), options)


@app.command()
def ready(
    engine: str = typer.Argument("auto", help="Engine to validate locally (or auto)"),
    ctx: typer.Context = None,
):
    """Check local engine readiness without changing anything."""
    from . import readiness
    from .cli import _recommended_engine_name

    engine = _option_value(engine, "auto")
    options = _output_options(ctx)
    engine_name = _recommended_engine_name() if engine == "auto" else engine
    checks = readiness.evaluate(engine_name)
    ready_now = all(check.ok or not check.blocking for check in checks)
    if options.json_output:
        _print_json_enveloped({
            "engine": engine_name,
            "ready": ready_now,
            "checks": [
                {
                    "name": check.name,
                    "ok": check.ok,
                    "blocking": check.blocking,
                    "detail": check.detail,
                }
                for check in checks
            ],
        })
        if not ready_now:
            raise typer.Exit(code=1)
        return
    if _is_quiet(options):
        if not ready_now:
            raise typer.Exit(code=1)
        return
    from .cli import _render_ready_checks
    _render_ready_checks(engine_name, checks)
    if not ready_now:
        raise typer.Exit(code=1)


def _doctor_payload(results: list) -> dict:
    return {
        "ok": all(getattr(result, "ok", False) for result in results),
        "checks": [safe_doctor_check(result) for result in results],
    }


def _country_payload(profile, *, pinned: bool, auto_detected: bool = False) -> dict:
    if profile is None:
        return {
            "code": None,
            "name": None,
            "censorship_level": None,
            "engine_order": [],
            "pinned": pinned,
            "auto_detected": auto_detected,
        }
    return {
        "code": profile.code,
        "name": profile.name,
        "censorship_level": profile.censorship_level,
        "engine_order": list(profile.engine_order),
        "bypass_dns": [label for label, _address in profile.bypass_dns],
        "test_url_count": len(profile.test_urls),
        "pinned": pinned,
        "auto_detected": auto_detected,
    }


def _bins_payload() -> dict:
    from . import downloader

    installed = downloader.check_installed()
    binaries = [
        {
            "key": info.key,
            "name": info.display_name,
            "installed": bool(installed.get(info.key, False)),
            "required": bool(info.required),
            "auto_download": bool(info.github_repo),
        }
        for info in downloader.list_available()
    ]
    return {
        "installed_count": sum(item["installed"] for item in binaries),
        "total_count": len(binaries),
        "required_missing": [
            item["key"] for item in binaries
            if item["required"] and not item["installed"]
        ],
        "binaries": binaries,
    }


@app.command()
def doctor(
    fix: bool = typer.Option(False, "--fix", help="Auto-fix every repairable issue"),
    fix_av: bool = typer.Option(False, "--fix-av", help="Add Windows Defender exclusions"),
    local_only: bool = typer.Option(False, "--local-only", help="Inspect local state only; never probe the internet or execute engines"),
    include_optional: bool = typer.Option(
        False,
        "--include-optional",
        help="Include packet-capture checks for Scapy/Npcap/libpcap",
    ),
    ctx: typer.Context = None,
):
    """Diagnose and fix environment issues."""
    from . import doctor as doctor_module

    options = _output_options(ctx)
    fix = bool(_option_value(fix, False))
    fix_av = bool(_option_value(fix_av, False))
    local_only = bool(_option_value(local_only, False))
    include_optional = bool(_option_value(include_optional, False))
    if local_only and (fix or fix_av):
        _print_cli_error(
            "invalid_input",
            "--local-only cannot be combined with mutating doctor flags",
            options=options,
            exit_code=2,
        )
    if options.json_output and (fix or fix_av):
        _print_cli_error(
            "invalid_input",
            "--json doctor is read-only; omit --fix and --fix-av",
            options=options,
            exit_code=2,
        )
    if options.json_output:
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            if local_only:
                results = doctor_module.run_local_checks(include_optional=include_optional)
            else:
                results = (
                    doctor_module.run_all_checks(include_optional=True)
                    if include_optional
                    else doctor_module.run_all_checks()
                )
        payload = _doctor_payload(results)
        _print_json_enveloped(payload)
        if not payload["ok"]:
            raise typer.Exit(code=1)
        return
    if _is_quiet(options):
        return
    from .cli import cmd_doctor
    args = DoctorArgs(
        fix=fix,
        fix_av=fix_av,
        include_optional=include_optional,
        local_only=local_only,
    )
    cmd_doctor(args)


def _connection_service(options: OutputOptions):
    from . import readiness
    from . import security
    from . import settings as cfg
    from . import daemon
    from . import proxy_manager
    from . import cli
    from .connection_service import ConnectionService

    def emit(event: dict[str, object]) -> None:
        if not _is_quiet(options):
            _render_connection_event(event)

    return ConnectionService(
        settings_load=cfg.load,
        settings_set=cfg.set_value,
        readiness_evaluate=readiness.evaluate,
        resolve_engine=cli._resolve_engine_name,
        linux_default_engine=cli._linux_default_engine,
        platform_engine_error=cli._platform_engine_error,
        preset_payload=cli._preset_payload,
        recommended_engine=cli._recommended_engine_name,
        active_profile=cli._get_active_profile,
        route_candidates=cli._routing_candidates,
        choose_engine=_ask_engine,
        choose_connection=ask_choice,
        is_interactive=is_interactive,
        start_engine_stack=cli._start_engine_stack,
        daemon_start=daemon.start,
        daemon_stop=daemon.stop,
        daemon_get_pid=daemon.get_pid,
        daemon_log_file=daemon.LOG_FILE,
        set_proxy=proxy_manager.set_system_proxy,
        clear_proxy=proxy_manager.clear_system_proxy,
        get_proxy_status=proxy_manager.get_proxy_status,
        restore_proxy=proxy_manager.restore_system_proxy,
        cleanup_proxy=proxy_manager.cleanup_owned_system_proxy,
        proxy_details=cfg.get_engine_proxy_details,
        kill_switch_prepare=security.prepare_linux_kill_switch,
        kill_switch_enable=security.enable_kill_switch,
        kill_switch_disable=security.disable_kill_switch,
        kill_switch_clear_endpoint=security.clear_linux_kill_switch_endpoint,
        emit=emit,
        emit_output=not _is_quiet(options),
    )


def _render_connection_event(event: dict[str, object]) -> None:
    event_type = event.get("type")
    if event_type == "profile":
        profile = event.get("profile") or {}
        console.print(
            f"  [dim]Detected: {profile.get('name')} ({profile.get('censorship_level')}) — "
            f"{profile.get('recommended_engine')} recommended[/dim]"
        )
    elif event_type == "warning":
        console.print(f"[warning]{event.get('message', '')}[/warning]")
    elif event_type == "preset":
        preset = event.get("preset") or {}
        from .theme import success_panel
        body = "[bold]Preset Active[/bold]\n\n" + "\n".join(
            f"  • {change}" for change in preset.get("changes", [])
        )
        if preset.get("footer"):
            body += f"\n\n{preset['footer']}"
        console.print(success_panel(body, title=preset.get("title", "Preset")))
    elif event_type == "engine_started":
        console.print(
            f"  [success]✓ {event.get('name')}[/success] running "
            f"(PID {event.get('pid')})"
        )
    elif event_type == "proxy" and event.get("configured"):
        host = event.get("host")
        port = event.get("port")
        console.print(f"  [success]✓ System proxy set[/success] → {host}:{port}")
    elif event_type == "network_engine":
        console.print("  [info]Network-level engine — no system proxy needed[/info]")
    elif event_type == "proxy_warning":
        console.print(f"\n[warning]⚠ {event.get('message')}[/warning]")
    elif event_type == "stopping":
        console.print("\n[warning]Stopping...[/warning]")
    elif event_type == "sni_scan_started":
        console.print("[yellow]No saved Cloudflare IP — running quick scan (10 IPs)...[/yellow]")
    elif event_type == "sni_scan_result":
        console.print(
            f"[success]✓ Best IP found: {event.get('ip')} "
            f"({float(event.get('latency', 0)):.0f}ms)[/success]"
        )
    elif event_type == "sni_scan_empty":
        console.print("[warning]No reachable Cloudflare IPs. Proceeding anyway...[/warning]")


def _render_connection_result(result, options: OutputOptions) -> None:
    from rich.panel import Panel

    if result.ok:
        if result.background and result.pid is not None and not _is_quiet(options):
            from . import daemon
            console.print(Panel(
                f"[success]Engine:[/success]  [bold]{result.engine}[/bold]\n"
                f"[success]PID:[/success]     [bold]{result.pid}[/bold]\n"
                f"[success]Log:[/success]     [dim]{daemon.LOG_FILE}[/dim]\n\n"
                "[muted]Run [bold]blackout status[/bold] to monitor.[/muted]\n"
                "[muted]Run [bold]blackout stop[/bold] to stop.[/muted]",
                title="[bold green]✓ Blackout Kit — Background[/bold green]",
                border_style="green",
            ))
        elif result.cancelled and not _is_quiet(options):
            console.print("[muted]Connection cancelled.[/muted]")
        return
    if result.readiness:
        from rich.table import Table
        table = Table(show_header=True, header_style="bold cyan", padding=(0, 2))
        table.add_column("Check")
        table.add_column("Status")
        table.add_column("Details")
        for check in result.readiness:
            status = "Ready" if check["ok"] else ("Warning" if not check["blocking"] else "Blocked")
            table.add_row(check["name"], status, check["detail"])
        console.print(Panel(table, title=f"[heading]Local Readiness · {result.engine or 'unknown'}[/heading]", border_style="panel.border"))
        console.print("[muted]This check reads local settings, files, process state, and loopback ports only. It does not start engines, probe remote hosts, download files, or change networking.[/muted]")
    if result.code == "invalid_preset":
        _print_cli_error("invalid_input", result.message or "invalid preset", options=options, exit_code=2)
        return
    if result.code == "not_ready":
        return
    if result.message:
        console.print(f"[error]{result.message}[/error]")


@app.command()
def connect(
    pos_engine: str = typer.Argument(None, help="Engine to use (e.g. sni, psiphon, auto)"),
    engine: str = typer.Option(None, "--engine", help="Engine to use"),
    background: bool = typer.Option(False, "--background", "-d", help="Run as background daemon"),
    iran: bool = typer.Option(False, "--iran", help="TIC 2026 evasion profile"),
    russia: bool = typer.Option(False, "--russia", help="Russia transport preset"),
    ctx: typer.Context = None,
):
    """Smart connect — uses a recommendation when no engine is specified."""
    from .connection_service import ConnectionRequest

    options = _output_options(ctx)
    request = ConnectionRequest(
        operation="connect",
        pos_engine=_option_value(pos_engine),
        engine=_option_value(engine),
        background=bool(_option_value(background, False)),
        iran=bool(_option_value(iran, False)),
        russia=bool(_option_value(russia, False)),
    )
    result = _connection_service(options).connect(request)
    _render_connection_result(result, options)
    if not result.ok:
        raise typer.Exit(code=2 if result.code == "invalid_preset" else 1)
    return result


@app.command()
def start(
    pos_engine: str = typer.Argument(None, help="Engine to use"),
    engine: str = typer.Option(None, "--engine", help="Engine to use"),
    background: bool = typer.Option(False, "--background", "-d", help="Run as daemon"),
    iran: bool = typer.Option(False, "--iran", help="TIC 2026 profile"),
    russia: bool = typer.Option(False, "--russia", help="Russia transport preset"),
    ctx: typer.Context = None,
):
    """Start a selected bypass engine."""
    from .connection_service import ConnectionRequest

    options = _output_options(ctx)
    request = ConnectionRequest(
        operation="start",
        pos_engine=_option_value(pos_engine),
        engine=_option_value(engine),
        background=bool(_option_value(background, False)),
        iran=bool(_option_value(iran, False)),
        russia=bool(_option_value(russia, False)),
    )
    result = _connection_service(options).start(request)
    _render_connection_result(result, options)
    if not result.ok:
        raise typer.Exit(code=2 if result.code == "invalid_preset" else 1)
    return result




@app.command()
def mode(
    mode_name: str = typer.Argument(None, help="speed | private | legend (omit to interactively select)"),
):
    """View or set security mode."""
    from .cli import cmd_mode

    if not mode_name:
        mode_name = ask_choice("Select a security mode", ["speed", "private", "legend"])
        if mode_name is None:
            return

    args = _args()
    args.mode_name = mode_name
    cmd_mode(args)


@app.command()
def killswitch(
    action: str = typer.Argument(None, help="on | off | test (omit to interactively select)"),
):
    """Manage the Linux-only endpoint-scoped kill switch."""
    from .cli import cmd_killswitch

    if not action:
        action = ask_choice("Select kill-switch action", ["on", "off", "test"])
        if action is None:
            return

    args = _args()
    args.action = action
    cmd_killswitch(args)


# Existing command implementations continue below.
def _add_to_user_path(directory: str) -> bool:
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment", 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
            try:
                current_path, _ = winreg.QueryValueEx(key, "PATH")
            except OSError:
                current_path = ""
            
            if directory.lower() not in current_path.lower():
                new_path = current_path
                if new_path and not new_path.endswith(";"):
                    new_path += ";"
                new_path += directory
                winreg.SetValueEx(key, "PATH", 0, winreg.REG_EXPAND_SZ, new_path)
                return True
            return False
    except Exception as e:
        console.print(f"[error]Failed to update PATH: {e}[/error]")
        return False

@app.command("add-to-path")
def add_to_path():
    """Add Blackout Kit to the system PATH so you can run it anywhere."""
    import sys
    from pathlib import Path
    
    if getattr(sys, 'frozen', False):
        target_dir = str(Path(sys.executable).parent.resolve())
    else:
        target_dir = str(Path(__file__).parent.parent.resolve())
        
    if _add_to_user_path(target_dir):
        console.print(f"[success]✓ Added {target_dir} to your system PATH![/success]")
        console.print("[info]You will need to restart your terminal for this to take effect.[/info]")
    else:
        console.print(f"[info]Blackout Kit ({target_dir}) is already in your PATH.[/info]")

@app.command(hidden=True)
def gui(ctx: typer.Context = None):
    """Start the native desktop app (install blackout-kit[gui])."""
    options = _output_options(ctx)
    try:
        from .gui_app import run_gui
    except (ImportError, ModuleNotFoundError):
        _optional_dependency_error(
            OptionalDependencyError("gui", "customtkinter"),
            options=options,
        )
    run_gui()


_JSON_NATIVE_COMMANDS = frozenset({
    "version", "status", "route", "ready", "doctor", "fix", "tools", "settings", "config",
    "country", "bins", "capabilities", "demo", "setup",
})
_CONFIG_JSON_COMMANDS = frozenset({
    "list", "validate", "check-duplicates", "compatibility", "diff",
    "add", "import", "replace", "remove", "encrypt", "decrypt", "export",
    "profile-export", "profile-import", "import-setup",
})
_SETTINGS_JSON_COMMANDS = frozenset({"list", "get", "set", "reset"})
_COUNTRY_JSON_COMMANDS = frozenset({"set", "reset", "show", "list"})
_BINS_JSON_COMMANDS = frozenset({"list"})
_TOOLS_JSON_COMMANDS = frozenset({"netfix"})


def _reject_unsupported_json(command: str | None, options: OutputOptions) -> None:
    if options.json_output and command not in _JSON_NATIVE_COMMANDS:
        _print_cli_error(
            "unsupported_output_mode",
            f"--json is not supported for '{command or 'this command'}'",
            options=options,
            exit_code=2,
        )



def _reject_group_json(command: str | None, options: OutputOptions, supported: set[str]) -> None:
    if options.json_output and command not in supported:
        _print_cli_error(
            "unsupported_output_mode",
            f"--json is not supported for '{command or 'this command'}'",
            options=options,
            exit_code=2,
        )



def _safe_command_name(command: str | None) -> str:
    return command or "root"


def _json_command_supported(ctx: typer.Context | None) -> bool:
    if ctx is None:
        return True
    command = getattr(ctx, "invoked_subcommand", None)
    return command in _JSON_NATIVE_COMMANDS


def _register_verbose_close(ctx: typer.Context, options: OutputOptions) -> None:
    if not options.verbose:
        return
    started = time.perf_counter()
    command = getattr(ctx, "invoked_subcommand", None) or "root"
    register = getattr(ctx, "call_on_close", None)
    if register is None:
        return
    register(
        lambda: emit_verbose(
            options=options,
            command=command,
            started=started,
            sources=("typer-adapter",),
        )
    )


@app.command()
def mcp():
    """Start the AI Agent MCP (Model Context Protocol) stdio server."""
    from .mcp_server import run_mcp_server
    run_mcp_server()

# ── SPLIT TUNNEL GROUP ──
split_app = typer.Typer(help="Split Tunneling & Direct Proxy Bypass", no_args_is_help=True)
app.add_typer(split_app, name="split-tunnel")

@split_app.command("list")
def split_list():
    """List all direct proxy bypass rules"""
    from .split_tunnel import load_split_rules
    rules = load_split_rules()
    console.print("\n[bold cyan]Direct Bypass Rules (Split Tunnel):[/bold cyan]")
    for r in rules:
        console.print(f"  • {r}")
    console.print()

@split_app.command("add")
def split_add(target: str = typer.Argument(..., help="Domain, IP, or CIDR to bypass proxy")):
    """Add a domain or IP to bypass system proxy directly"""
    from .split_tunnel import add_direct_route
    if add_direct_route(target):
        console.print(f"[success]✓ Added '{target}' to split-tunnel direct bypass list![/success]")

@split_app.command("remove")
def split_remove(target: str = typer.Argument(..., help="Domain, IP, or CIDR to remove")):
    """Remove a domain or IP from direct proxy bypass list"""
    from .split_tunnel import remove_direct_route
    if remove_direct_route(target):
        console.print(f"[success]✓ Removed '{target}' from split-tunnel direct bypass list![/success]")

# ── NETWORK GROUP ──
network_app = typer.Typer(help="WiFi network switcher + ISP detection", no_args_is_help=True)
app.add_typer(network_app, name="network")

@network_app.command("scan")
def net_scan():
    """Show all available WiFi networks"""
    from .cli import cmd_network
    args = _args()
    args.network_command = "scan"
    cmd_network(args)

@network_app.command("isp")
def net_isp():
    """Show current ISP provider info"""
    from .cli import cmd_network
    args = _args()
    args.network_command = "isp"
    cmd_network(args)

@network_app.command("auto")
def net_auto():
    """Auto-switch to best available saved network"""
    from .cli import cmd_network
    args = _args()
    args.network_command = "auto"
    cmd_network(args)

@network_app.command("switch")
def net_switch(
    ssid: str = typer.Argument(None, help="SSID of the network to switch to")
):
    """Switch to a specific WiFi network."""
    from .cli import cmd_network

    ssid = ssid or ask_text("Enter the SSID of the network to switch to")
    if not ssid:
        return
    args = _args()
    args.network_command = "switch"
    args.ssid = ssid
    cmd_network(args)

# ── CONFIG GROUP ──
config_app = typer.Typer(help="Manage V2Ray proxy configs", no_args_is_help=False)
app.add_typer(config_app, name="config")


@config_app.callback(invoke_without_command=True)
def config_status(ctx: typer.Context):
    """Open the keyboard config manager when no subcommand is given."""
    options = _output_options(ctx)
    if ctx.invoked_subcommand is not None:
        _reject_group_json(ctx.invoked_subcommand, options, _CONFIG_JSON_COMMANDS)
        return
    if options.json_output:
        _print_cli_error(
            "missing_command",
            "a config subcommand is required",
            options=options,
            exit_code=2,
        )
    if not is_interactive():
        console.print("[warning]Usage: blackout config (list | add <uri> | import <url> | replace <n> <uri> | remove <n>)[/warning]")
        return
    from .interactive import run_config_menu
    run_config_menu()

@config_app.command("list")
def cfg_list(ctx: typer.Context = None):
    """List saved configs without exposing credentials."""
    from .config.manager import load_configs

    configs = load_configs()
    options = _output_options(ctx)
    if options.json_output:
        _print_json_enveloped(_config_payload(configs))
        return
    _render_config_list(configs, options)


@config_app.command("validate")
def cfg_validate(ctx: typer.Context = None):
    """Validate saved proxy records using local parser checks only."""
    from .config.manager import load_configs, validate_configs

    options = _output_options(ctx)
    findings = validate_configs(load_configs())
    payload = {
        "valid": all(item["ok"] for item in findings),
        "configs": findings,
    }
    if options.json_output:
        _print_json_enveloped(payload)
        return
    if _is_quiet(options):
        return
    if not findings:
        console.print("[muted]No saved proxy configs.[/muted]")
        return
    table = make_table(
        "Config Validation",
        [("#", "dim"), ("Status", ""), ("Protocol", "cyan"), ("Transport", "yellow"), ("Finding", "dim")],
        [],
    )
    for item in findings:
        table.add_row(
            str(item["index"]),
            "[success]valid[/success]" if item["ok"] else "[error]invalid[/error]",
            item.get("protocol", "-"),
            item.get("transport", "-"),
            item.get("error", "-") if not item["ok"] else "-",
        )
    console.print(table)


@config_app.command("check-duplicates")
def cfg_check_duplicates(ctx: typer.Context = None):
    """Find duplicate saved proxy records without printing their URIs."""
    from .config.manager import duplicate_config_indexes, load_configs

    options = _output_options(ctx)
    duplicates = duplicate_config_indexes(load_configs())
    payload = {
        "has_duplicates": bool(duplicates),
        "duplicate_groups": duplicates,
        "duplicate_count": sum(len(group) for group in duplicates),
    }
    if options.json_output:
        _print_json_enveloped(payload)
        return
    if _is_quiet(options):
        return
    if not duplicates:
        console.print("[success]No duplicate proxy records found.[/success]")
        return
    console.print(f"[warning]Found {len(duplicates)} duplicate group(s).[/warning]")
    for group in duplicates:
        console.print(f"  Config indexes: {', '.join(str(index) for index in group)}")


@config_app.command("compatibility")
def cfg_compatibility(ctx: typer.Context = None):
    """Report local engine and saved-proxy compatibility without network probes."""
    from .config.manager import load_configs

    options = _output_options(ctx)
    payload = _compatibility_payload(load_configs())
    if options.json_output:
        _print_json_enveloped(payload)
        return
    if _is_quiet(options):
        return
    console.print(f"[bold]Saved protocols:[/bold] {', '.join(payload['saved_protocols']) or 'none'}")
    table = make_table(
        "Local Engine Compatibility",
        [("Engine", "cyan"), ("Ready", ""), ("Protocols", "yellow"), ("Blockers", "dim")],
        [],
    )
    for item in payload["engines"]:
        table.add_row(
            item["engine"],
            "[success]ready[/success]" if item["ready"] else "[error]blocked[/error]",
            ", ".join(item["compatible_protocols"]) or "-",
            ", ".join(item["blockers"]) or "-",
        )
    console.print(table)


@config_app.command("diff")
def cfg_diff(
    setup: str = typer.Argument(..., help="Base64-encoded setup to compare locally"),
    ctx: typer.Context = None,
):
    """Compare a setup against local config and settings without applying it."""
    from . import settings as cfg
    from .config.manager import load_configs

    options = _output_options(ctx)
    try:
        incoming_configs, incoming_settings = _decode_setup(_option_value(setup))
    except typer.BadParameter as exc:
        _fail_parameter(str(exc), options=options)
    payload = _config_diff_payload(
        load_configs(),
        incoming_configs,
        cfg.load(),
        incoming_settings,
    )
    if options.json_output:
        _print_json_enveloped(payload)
        return
    if _is_quiet(options):
        return
    console.print(
        f"Config changes: {payload['config_changes']} · "
        f"Setting changes: {payload['setting_changes']}"
    )
    for item in payload["configs"]:
        if item["status"] != "unchanged":
            console.print(f"  Config #{item['index']}: {item['status']}")
    for item in payload["settings"]:
        console.print(f"  Setting {item['key']}: changed")


@config_app.command("add")
def cfg_add(
    uri: str = typer.Argument(None, help="V2Ray URI to add (vmess://, vless://, etc)"),
    prompt: bool = typer.Option(False, "--prompt", help="Read the URI without echoing it"),
    stdin_input: bool = typer.Option(False, "--stdin", help="Read the URI from stdin without echoing it"),
    ctx: typer.Context = None,
):
    """Add a V2Ray URI without echoing credential-bearing input."""
    from .config.manager import add_config, load_configs, parse_v2ray_uri

    options = _output_options(ctx)
    uri = _option_value(uri)
    prompt = bool(_option_value(prompt, False))
    stdin_input = bool(_option_value(stdin_input, False))
    if prompt or stdin_input:
        if uri:
            _fail_parameter("do not provide a URI with --prompt or --stdin", options=options)
        uri = _read_cli_secret("V2Ray URI: ", prompt_input=prompt, stdin_input=stdin_input)
    else:
        uri = uri or ask_text("Enter the V2Ray URI")
    if not uri:
        return
    parsed = parse_v2ray_uri(uri)
    if parsed is None:
        _fail_parameter("Invalid V2Ray URI", options=options)
    if any(config.raw_uri == parsed.raw_uri for config in load_configs()):
        _fail_parameter("A config with this URI is already saved", options=options)
    try:
        config = add_config(uri)
    except ValueError as exc:
        _fail_parameter(str(exc), options=options)
    if options.json_output:
        _print_json_enveloped({
            "added": True,
            "protocol": config.protocol,
            "transport": config.transport_label(),
        })
    elif not _is_quiet(options):
        console.print(
            f"[success]✓ Added {config.protocol.upper()} · "
            f"{config.transport_label()}[/success]"
        )


@config_app.command("import")
def cfg_import(url: str = typer.Argument(None, help="Subscription URL to import"), ctx: typer.Context = None):
    """Import and merge configs from a subscription URL."""
    from .config.manager import import_and_merge

    options = _output_options(ctx)
    url = _option_value(url)
    url = url or ask_text("Enter the subscription URL")
    if not url:
        return
    try:
        added, total = import_and_merge(url)
    except ValueError as exc:
        _fail_parameter(str(exc), options=options)
    except OSError as exc:
        _print_cli_error("subscription_unavailable", str(exc), options=options)
    if options.json_output:
        _print_json_enveloped({"added": added, "total": total})
    elif not _is_quiet(options):
        console.print(f"[success]✓ Imported {added} new configs. Total: {total}.[/success]")


@config_app.command("replace")
def cfg_replace(
    num: int = typer.Argument(..., help="Config number to replace"),
    uri: str = typer.Argument(..., help="Replacement V2Ray URI"),
    ctx: typer.Context = None,
):
    """Replace one saved V2Ray URI."""
    from .config.manager import replace_config

    try:
        config = replace_config(_one_based_index(num), uri)
    except (IndexError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    options = _output_options(ctx)
    if options.json_output:
        safe_config = _config_payload([config])["configs"][0]
        safe_config["index"] = _option_value(num)
        _print_json_enveloped({"replaced": True, "config": safe_config})
        return
    if _is_quiet(options):
        return
    console.print(
        f"[success]✓ Replaced config #{num} with "
        f"{config.protocol.upper()} · {config.transport_label()}[/success]"
    )


@config_app.command("remove")
def cfg_remove(num: int = typer.Argument(None, help="Config number to remove"), ctx: typer.Context = None):
    """Remove a config by number."""
    from .config.manager import remove_config

    options = _output_options(ctx)
    num = _option_value(num)
    num = num if num is not None else ask_int("Enter the config number to remove")
    if num is None:
        return
    try:
        remove_config(_one_based_index(num))
    except IndexError as exc:
        if options.json_output:
            _print_cli_error("invalid_input", str(exc), options=options, exit_code=2)
        raise typer.BadParameter(str(exc)) from exc
    if options.json_output:
        _print_json_enveloped({"removed": True, "index": num})
    elif not _is_quiet(options):
        console.print(f"[success]✓ Removed config #{num}[/success]")


@config_app.command("encrypt")
def cfg_encrypt(ctx: typer.Context = None):
    """Encrypt saved proxy configs and supported secrets at rest."""
    from . import security as sec

    options = _output_options(ctx)
    if sec.configs_are_obfuscated():
        if options.json_output:
            _print_json_enveloped({"encrypted": True, "already_active": True})
        elif not _is_quiet(options):
            console.print("[warning]Encrypted local vault storage is already active.[/warning]")
        return
    try:
        sec.obfuscate_configs()
    except Exception:
        _print_cli_error("encryption_failed", "encryption failed; plaintext files were preserved", options=options)
    if options.json_output:
        _print_json_enveloped({"encrypted": True, "already_active": False})
    elif not _is_quiet(options):
        console.print("[success]✓ Proxy configs and supported VPN secrets are encrypted at rest.[/success]")


@config_app.command("decrypt")
def cfg_decrypt(ctx: typer.Context = None):
    """Restore encrypted configs and supported secrets for recovery."""
    from . import security as sec

    options = _output_options(ctx)
    if not sec.configs_are_obfuscated():
        if options.json_output:
            _print_json_enveloped({"decrypted": False, "encrypted_data": False})
        elif not _is_quiet(options):
            console.print("[warning]No encrypted local vault data was found.[/warning]")
        return
    if not sec.deobfuscate_configs():
        _print_cli_error("decryption_failed", "decryption failed; encrypted files were preserved", options=options)
    if options.json_output:
        _print_json_enveloped({"decrypted": True, "encrypted_data": True})
    elif not _is_quiet(options):
        console.print("[success]✓ Encrypted proxy configs and supported VPN secrets restored.[/success]")


@config_app.command("export")
def cfg_export(
    output: str = typer.Option(None, "--output", "-o", help="Save to file (required for machine-readable output)"),
    force: bool = typer.Option(False, "--force", "-f", help="Explicitly allow plaintext setup export"),
    ctx: typer.Context = None,
):
    """Export a plaintext setup only after an explicit safety confirmation."""
    output = _option_value(output)
    force = bool(_option_value(force, False))
    options = _output_options(ctx)
    if options.json_output and not output:
        _print_cli_error(
            "unsafe_output",
            "JSON mode requires --output for plaintext setup export",
            options=options,
            exit_code=2,
        )
    if not force:
        if not is_interactive():
            _print_cli_error(
                "confirmation_required",
                "plaintext setup export requires --force in non-interactive mode",
                options=options,
                exit_code=2,
            )
        if not confirm(
            "Export a plaintext setup containing credential-bearing proxy URIs?",
            default=False,
        ):
            return

    setup_string = _setup_blob()
    if output:
        output_path = Path(output).expanduser().resolve()
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(setup_string, encoding="utf-8")
        except OSError:
            _print_cli_error(
                "export_failed",
                "setup could not be written",
                options=options,
            )
        if options.json_output:
            _print_json_enveloped({"exported": True, "format": "plaintext-setup"})
            return
        if not _is_quiet(options):
            console.print(f"[success]✓ Setup exported to:[/success] {output_path}")
        return

    console.print("[warning]Plaintext setup string; handle it like a password.[/warning]")
    console.print(setup_string)


@config_app.command("profile-export")
def cfg_profile_export(
    output: str = typer.Option(..., "--output", "-o", help="Destination for the encrypted profile"),
    prompt: bool = typer.Option(False, "--prompt", help="Read the passphrase without echoing it"),
    stdin_input: bool = typer.Option(False, "--stdin", help="Read the passphrase from stdin without echoing it"),
    ctx: typer.Context = None,
):
    """Export an authenticated portable profile without printing its contents."""
    from . import vault
    from .config.manager import serialize_setup

    options = _output_options(ctx)
    prompt = bool(_option_value(prompt, False))
    stdin_input = bool(_option_value(stdin_input, False))
    try:
        passphrase = _read_profile_passphrase(prompt=prompt, stdin_input=stdin_input)
        payload = vault.encrypt_profile(serialize_setup(), passphrase)
        output_path = Path(_option_value(output)).expanduser().resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        vault.atomic_write(output_path, payload)
    except (OSError, ValueError, vault.VaultError, typer.BadParameter) as exc:
        _print_cli_error("profile_export_failed", str(exc), options=options)
    if options.json_output:
        _print_json_enveloped({"exported": True, "format": "encrypted-profile"})
    elif not _is_quiet(options):
        console.print(f"[success]✓ Encrypted profile written to:[/success] {output_path}")


@config_app.command("profile-import")
def cfg_profile_import(
    profile: str = typer.Argument(..., help="Encrypted profile file to import"),
    prompt: bool = typer.Option(False, "--prompt", help="Read the passphrase without echoing it"),
    stdin_input: bool = typer.Option(False, "--stdin", help="Read the passphrase from stdin without echoing it"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip the overwrite confirmation"),
    ctx: typer.Context = None,
):
    """Authenticate and import a portable profile after complete validation."""
    from . import vault

    options = _output_options(ctx)
    prompt = bool(_option_value(prompt, False))
    stdin_input = bool(_option_value(stdin_input, False))
    force = bool(_option_value(force, False))
    try:
        passphrase = _read_profile_passphrase(prompt=prompt, stdin_input=stdin_input)
        profile_data = vault.decrypt_profile(_read_profile_file(Path(_option_value(profile))), passphrase)
        configs, settings_data = _validate_setup_data(profile_data)
    except (OSError, ValueError, vault.VaultError, typer.BadParameter) as exc:
        _print_cli_error("profile_import_failed", str(exc), options=options)

    if not force:
        if not is_interactive():
            _print_cli_error(
                "confirmation_required",
                "profile import requires --force in non-interactive mode",
                options=options,
                exit_code=2,
            )
        if not confirm("Import this profile and overwrite current configs/settings?", default=False):
            return
    try:
        _apply_setup(configs, settings_data)
    except Exception:
        _print_cli_error("profile_import_failed", "profile could not be applied", options=options)
    payload = {
        "imported": True,
        "format": "encrypted-profile",
        "config_count": len(configs),
        "setting_count": len(settings_data),
    }
    if options.json_output:
        _print_json_enveloped(payload)
    elif not _is_quiet(options):
        console.print(
            f"[success]✓ Encrypted profile imported ({len(configs)} configs, "
            f"{len(settings_data)} settings).[/success]"
        )


@config_app.command("import-setup")
def cfg_import_setup(
    setup_string: str = typer.Argument(None, help="Base64-encoded setup string"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation prompt"),
    ctx: typer.Context = None,
):
    """Validate and import configs and selected settings from a setup string."""
    setup_string = _option_value(setup_string)
    force = bool(_option_value(force, False))
    options = _output_options(ctx)
    setup_string = setup_string or ask_text("Enter the setup string")
    if not setup_string:
        return
    try:
        configs, settings_data = _decode_setup(setup_string)
    except typer.BadParameter as exc:
        _fail_parameter(str(exc), options=options)
    if not force:
        if not is_interactive():
            _print_cli_error(
                "confirmation_required",
                "setup import requires --force in non-interactive mode",
                options=options,
                exit_code=2,
            )
        if not confirm("Import setup and overwrite current configs/settings?", default=False):
            return
    try:
        _apply_setup(configs, settings_data)
    except Exception:
        _print_cli_error("setup_import_failed", "setup could not be applied", options=options)
    if options.json_output:
        _print_json_enveloped({
            "imported": True,
            "format": "plaintext-setup",
            "config_count": len(configs),
            "setting_count": len(settings_data),
        })
    elif not _is_quiet(options):
        console.print("[success]✓ Setup imported successfully.[/success]")

# ── TOOLS GROUP ──
tools_app = typer.Typer(help="Network diagnostics, DNS, hotspot, and more", no_args_is_help=False)
app.add_typer(tools_app, name="tools")


@tools_app.callback(invoke_without_command=True)
def tools_status(ctx: typer.Context):
    """Validate JSON support before delegated tool commands run."""
    options = _output_options(ctx)
    if ctx.invoked_subcommand is not None:
        _reject_group_json(ctx.invoked_subcommand, options, _TOOLS_JSON_COMMANDS)
        return
    if options.json_output:
        _print_cli_error(
            "missing_command",
            "a tools subcommand is required",
            options=options,
            exit_code=2,
        )
    typer.echo(ctx.get_help())
    raise typer.Exit(code=2)


@tools_app.command("dns-bench")
def tools_dns_bench():
    """Benchmark DNS servers"""
    from .cli import cmd_tools
    args = _args()
    args.tools_command = "dns-bench"
    cmd_tools(args)

@tools_app.command("dns-flush")
def tools_dns_flush():
    """Flush DNS cache"""
    from .cli import cmd_tools
    args = _args()
    args.tools_command = "dns_flush".replace("_", "-")
    cmd_tools(args)

@tools_app.command("dns-set")
def tools_dns_set(
    ip: str = typer.Argument(None, help="DNS IP (e.g. 1.1.1.1)"),
    adapter: str = typer.Option(None, "--adapter", "-a", help="Specific adapter name")
):
    """Set system DNS server."""
    from .cli import cmd_tools

    ip = ip or ask_text("Enter the DNS IP to set")
    if not ip:
        return
    args = _args()
    args.tools_command = "dns-set"
    args.server = ip
    args.adapter = adapter
    cmd_tools(args)

@tools_app.command("speedtest")
def tools_speedtest():
    """Run download speed test"""
    from .cli import cmd_tools
    args = _args()
    args.tools_command = "speedtest".replace("_", "-")
    cmd_tools(args)

@tools_app.command("speedtest-history")
def tools_speedtest_history():
    """Show a trend graph of your last 30 recorded speedtests."""
    from .cli import cmd_tools
    args = _args()
    args.tools_command = "speedtest-history"
    cmd_tools(args)

@tools_app.command("adapters")
def tools_adapters():
    """List network adapters and IPs"""
    from .cli import cmd_tools
    args = _args()
    args.tools_command = "adapters".replace("_", "-")
    cmd_tools(args)


@tools_app.command("mac")
def tools_mac(
    action: str = typer.Argument("status", help="status | randomize | restore"),
    adapter: str = typer.Option(None, "--adapter", "-a", help="Active physical Wi-Fi adapter name"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip the interactive Wi-Fi interruption confirmation"),
):
    """Inspect, randomize, or restore the active physical Wi-Fi MAC."""
    from .cli import cmd_tools

    args = _args()
    args.tools_command = "mac"
    args.mac_action = action.lower()
    args.adapter = adapter
    args.force = force
    cmd_tools(args)


@tools_app.command("netfix")
def tools_netfix(
    preview: bool = typer.Option(False, "--preview", help="Show Blackout-owned recovery actions without changing anything"),
    ctx: typer.Context = None,
):
    """Safely repair post-crash network state (admin may be requested)."""
    options = _output_options(ctx)
    preview = bool(_option_value(preview, False))
    flags, warnings = _recovery_flags(False, False, False)
    _run_recovery_flow(
        flags=flags,
        preview=preview,
        options=options,
        audit_source="tools",
        warnings=warnings,
        command_label="tools netfix",
    )


@tools_app.command("arp-flush")
def tools_arp_flush():
    """Explicitly flush the local ARP/neighbor cache"""
    from .cli import cmd_tools
    args = _args()
    args.tools_command = "arp-flush"
    cmd_tools(args)

@tools_app.command("hotspot")
def tools_hotspot(
    action: str = typer.Argument(None, help="on | off")
):
    """Start or stop Windows Mobile Hotspot."""
    from .cli import cmd_tools

    action = action or ask_choice("Select hotspot action", ["on", "off"])
    if not action:
        return
    args = _args()
    args.tools_command = "hotspot"
    args.action = action
    cmd_tools(args)

@tools_app.command("share-vpn")
def tools_share_vpn(
    action: str = typer.Argument(None, help="on | off")
):
    """Share VPN connection via hotspot (ICS)."""
    from .cli import cmd_tools

    action = action or ask_choice("Select ICS VPN sharing action", ["on", "off"])
    if not action:
        return
    args = _args()
    args.tools_command = "share-vpn"
    args.action = action
    cmd_tools(args)

@tools_app.command("ping")
def tools_ping(host: str = typer.Argument(None, help="Host to ping")):
    """TCP ping test."""
    from .cli import cmd_tools

    host = host or ask_text("Enter host or IP to ping")
    if not host:
        return
    args = _args()
    args.tools_command = "ping"
    args.host = host
    cmd_tools(args)
    
@tools_app.command("mtu")
def tools_mtu(
    host: str = typer.Argument("8.8.8.8", help="Host to ping"),
    set_mtu: bool = typer.Option(False, "--set", help="Auto-set the best MTU")
):
    """Detect and optionally set MTU"""
    from .cli import cmd_tools
    args = _args()
    args.tools_command = "mtu"
    args.host = host
    args.set = set_mtu
    cmd_tools(args)

@tools_app.command("traceroute")
def tools_traceroute(host: str = typer.Argument(None, help="Host to trace")):
    """Traceroute to a host."""
    from .cli import cmd_tools

    host = host or ask_text("Enter host or IP to trace")
    if not host:
        return
    args = _args()
    args.tools_command = "traceroute"
    args.host = host
    cmd_tools(args)

@tools_app.command("subnet")
def tools_subnet(cidr: str = typer.Argument(..., help="IP with CIDR mask (e.g. 192.168.1.0/24)")):
    """Calculate subnet range, broadcast, and mask."""
    from .cli import cmd_tools
    args = _args()
    args.tools_command = "subnet"
    args.cidr = cidr
    cmd_tools(args)

@tools_app.command("connections")
def tools_connections(
    established: bool = typer.Option(False, "--established", help="Show only ESTABLISHED connections (hide listeners)"),
):
    """Show a live table of active TCP/UDP connections with process names."""
    from .cli import cmd_tools
    args = _args()
    args.tools_command = "connections"
    args.established = established
    cmd_tools(args)

@tools_app.command("dns-inspect")
def tools_dns_inspect():
    """Compare system DNS resolution against a trusted resolver to spot interference."""
    from .cli import cmd_tools
    args = _args()
    args.tools_command = "dns-inspect"
    cmd_tools(args)

@tools_app.command("discover")
def tools_discover():
    """Discover live devices on your local subnet (ARP-based LAN scan)."""
    from .cli import cmd_tools
    args = _args()
    args.tools_command = "discover"
    cmd_tools(args)

@tools_app.command("scan-ports")
def tools_scan_ports(
    host: str = typer.Argument(None, help="Host or IP to scan"),
    ports: str = typer.Option(None, "--ports", "-p", help="Port range (e.g. 1-1000) or comma list (e.g. 22,80,443). Omit to scan common ports."),
):
    """Scan a host for open TCP ports (common ports by default)."""
    from .cli import cmd_tools

    host = host or ask_text("Enter host or IP to scan")
    if not host:
        return
    args = _args()
    args.tools_command = "scan-ports"
    args.host = host
    args.ports = ports
    cmd_tools(args)

@tools_app.command("latency-monitor")
def tools_latency_monitor(
    host: str = typer.Argument("8.8.8.8", help="Host to ping continuously"),
    interval: float = typer.Option(1.0, "--interval", "-i", help="Seconds between samples"),
):
    """Live-updating ping graph with rolling avg/jitter/loss. Ctrl+C to stop."""
    from .cli import cmd_tools
    args = _args()
    args.tools_command = "latency-monitor"
    args.host = host
    args.interval = interval
    cmd_tools(args)

@tools_app.command("bandwidth")
def tools_bandwidth(
    interval: float = typer.Option(1.0, "--interval", "-i", help="Seconds between samples"),
):
    """Live-updating per-interface upload/download throughput. Ctrl+C to stop."""
    from .cli import cmd_tools
    args = _args()
    args.tools_command = "bandwidth"
    args.interval = interval
    cmd_tools(args)

@tools_app.command("bandwidth-cap")
def tools_bandwidth_cap(
    subcmd: str = typer.Argument("list", help="set|list|stats|remove"),
    interface: str = typer.Option(None, "--interface", "-i", help="Interface name (e.g. eth0, wlan0)"),
    daily_mb: int = typer.Option(None, "--daily", "-d", help="Daily limit in MB"),
    monthly_mb: int = typer.Option(None, "--monthly", "-m", help="Monthly limit in MB"),
):
    """Set and monitor daily/monthly bandwidth limits per interface."""
    from .cli import cmd_tools
    args = _args()
    args.tools_command = "bandwidth-cap"
    args.bandwidth_cap_subcmd = subcmd
    args.interface = interface
    args.daily_mb = daily_mb
    args.monthly_mb = monthly_mb
    cmd_tools(args)

@tools_app.command("traffic-log")
def tools_traffic_log(
    subcmd: str = typer.Argument("list", help="list|stats|hourly|clear|prune|info"),
    app: str = typer.Option(None, "--app", "-a", help="Filter by process name"),
    protocol: str = typer.Option(None, "--protocol", "-p", help="Filter by protocol (TCP/UDP)"),
    hours: int = typer.Option(24, "--hours", "-h", help="Last N hours to query"),
    limit: int = typer.Option(50, "--limit", "-l", help="Max entries to show in list"),
    older_than: int = typer.Option(30, "--older-than", help="Prune entries older than N days"),
):
    """Query network traffic audit trail, aggregate stats, and manage logs."""
    from .cli import cmd_tools
    args = _args()
    args.tools_command = "traffic-log"
    args.traffic_log_subcmd = subcmd
    args.app = app
    args.protocol = protocol
    args.hours = hours
    args.limit = limit
    args.older_than = older_than
    cmd_tools(args)

@tools_app.command("adblock")
def tools_adblock(
    subcmd: str = typer.Argument("status", help="sources|sources-add|sources-remove|custom-add|custom-remove|whitelist-add|whitelist-remove|status|stats|log|update"),
    name: str = typer.Option(None, "--name", "-n", help="Blocklist name (for sources-add/remove)"),
    url: str = typer.Option(None, "--url", "-u", help="Blocklist URL (for sources-add)"),
    domain: str = typer.Option(None, "--domain", "-d", help="Domain (for custom-add/remove/whitelist commands)"),
    blocked_only: bool = typer.Option(False, "--blocked-only", help="Show only blocked queries in log"),
    hours: int = typer.Option(24, "--hours", "-h", help="Last N hours to query"),
    limit: int = typer.Option(100, "--limit", "-l", help="Max log entries to show"),
):
    """Manage ad and tracker blocking via blocklists, custom rules, and whitelist."""
    from .cli import cmd_tools
    args = _args()
    args.tools_command = "adblock"
    args.adblock_subcmd = subcmd
    args.name = name
    args.url = url
    args.domain = domain
    args.blocked_only = blocked_only
    args.hours = hours
    args.limit = limit
    cmd_tools(args)

@tools_app.command("qos")
def tools_qos(
    subcmd: str = typer.Argument("rules", help="rules|stats|mode|violations"),
    action: str = typer.Argument(None, help="For 'rules': list|add|remove|enable|disable"),
    name: str = typer.Option(None, "--name", "-n", help="Rule name (for add)"),
    rule_type: str = typer.Option(None, "--type", "-t", help="Rule type: app|protocol|port|interface"),
    target: str = typer.Option(None, "--target", help="Target: process name, protocol, port, or interface"),
    priority: int = typer.Option(50, "--priority", "-p", help="Stored priority metadata 0-100 (default 50)"),
    rate_limit: int = typer.Option(0, "--rate-limit", "-r", help="Stored rate-limit metadata in kbps (0=unset)"),
    rule_id: str = typer.Option(None, "--id", help="Rule ID (for remove/enable/disable)"),
    mode: str = typer.Option(None, help="For 'mode': off|monitor"),
    hours: int = typer.Option(24, "--hours", "-h", help="Last N hours to query"),
    limit: int = typer.Option(50, "--limit", "-l", help="Max entries to show"),
):
    """Manage monitor-only QoS rule metadata and stored inspection records.

    Rules persist app, protocol, port, and interface metadata. Priority and
    rate-limit fields are stored configuration only; they do not control live
    traffic. Statistics intentionally report zero-value placeholders because
    this command does not measure or control throughput.

    Subcommands:
      rules [list|add|remove|enable|disable]  - Manage stored QoS rules
      stats                                   - Inspect stored rules and placeholders
      mode [off|monitor]                      - Set monitoring mode
      violations                              - View stored violation records

    Examples:
      blackout tools qos rules list
      blackout tools qos rules add --type app --target chrome.exe --name chrome_metadata
      blackout tools qos rules remove --id rule_001
      blackout tools qos stats
      blackout tools qos mode monitor
      blackout tools qos violations --hours 24
    """
    from .cli import cmd_tools
    args = _args()
    args.tools_command = "qos"
    args.qos_subcmd = subcmd
    args.qos_show_cmd = action or "list"  # Default to "list" if action is None
    args.name = name
    args.rule_type = rule_type
    args.target = target
    args.priority = priority
    args.rate_limit = rate_limit
    args.rule_id = rule_id
    args.mode = mode
    args.hours = hours
    args.limit = limit
    cmd_tools(args)

@tools_app.command("capture")
def tools_capture(
    iface: str = typer.Argument(None, help="Interface name to capture on (see `tools adapters`); omit for auto"),
    count: int = typer.Option(0, "--count", "-c", help="Stop after N packets (0 = unbounded, Ctrl+C to stop)"),
    filter: str = typer.Option(None, "--filter", "-f", help="Raw BPF filter expression (e.g. 'tcp port 443')"),
    host: str = typer.Option(None, "--host", help="Shorthand filter for traffic to/from this host"),
    pcap: str = typer.Option(None, "--pcap", "-p", help="Export packet trace to standard .pcap binary file for Wireshark"),
    ctx: typer.Context = None,
):
    """Capture packets locally; install `blackout-kit[capture]` and Npcap/libpcap first."""
    options = _output_options(ctx)
    try:
        require_import("capture", "scapy.all", "scapy", "Windows also requires Npcap; Linux requires libpcap")
    except OptionalDependencyError as exc:
        _optional_dependency_error(exc, options=options)
    from .cli import cmd_tools
    cmd_tools(_args(
        tools_command="capture",
        iface=_option_value(iface),
        count=int(_option_value(count, 0)),
        filter=_option_value(filter),
        host=_option_value(host),
        pcap=_option_value(pcap),
    ))

@tools_app.command("scan-file")
def tools_scan_file(
    path: str = typer.Argument(..., help="Existing local file to scan"),
):
    """Scan one local file with installed Windows Defender."""
    from .cli import cmd_tools

    args = _args()
    args.tools_command = "scan-file"
    args.path = path
    cmd_tools(args)


@tools_app.command("file-hash")
def tools_file_hash(
    path: str = typer.Argument(..., help="Existing local file to fingerprint"),
):
    """Calculate a local SHA-256 fingerprint for one file."""
    from .cli import cmd_tools

    args = _args()
    args.tools_command = "file-hash"
    args.path = path
    cmd_tools(args)


@tools_app.command("cert-check")
def tools_cert_check(
    host: str = typer.Argument(None, help="Host to check"),
    allow: bool = typer.Option(False, "--allow", help="Trust this host in LEGEND mode"),
):
    """Check TLS certificate for a host[:port]."""
    from .cli import cmd_tools

    host = host or ask_text("Enter host or IP to check TLS certificate")
    if not host:
        return
    cmd_tools(_args(
        tools_command="cert-check",
        host=host,
        allow=allow,
    ))

@app.command()
def test():
    """Analyze saved V2Ray configs"""
    from .cli import cmd_test
    cmd_test(_args())

@app.command()
def stop():
    """Stop background daemon"""
    from .cli import cmd_stop
    cmd_stop(_args())

@app.command()
def disconnect():
    """Stop background daemon (alias for stop)"""
    from .cli import cmd_stop
    cmd_stop(_args())

@app.command()
def emergency(
    background: bool = typer.Option(False, "--background", "-d", help="Run as background daemon"),
):
    """Try locally supported engine candidates in sequence."""
    from .cli import cmd_emergency
    cmd_emergency(_args(background=background))


@app.command()
def logs(
    lines: int = typer.Option(50, "--lines", "-n", min=1, help="Number of log lines to show"),
):
    """View daemon log output"""
    from .cli import cmd_logs
    cmd_logs(_args(lines=lines))

@app.command()
def panic():
    """🚨 Instantly kill all connections, flush DNS, clear proxies, and restore normal state"""
    from .cli import cmd_panic
    cmd_panic(_args())

@app.command()
def shield():
    """Apply DNS blocking and request Linux-only firewall protection"""
    from .cli import cmd_shield
    cmd_shield(_args())

@app.command()
def update(
    apply: bool = typer.Option(False, "--apply", help="Download and apply the available update"),
):
    """Update Blackout Kit to latest version"""
    from .cli import cmd_update
    cmd_update(_args(force=apply))


def _show_help(topic):
    from .cli import cmd_help

    args = _args()
    args.topic = topic
    cmd_help(args)


@app.command(name="manual")
def manual_help(topic: str = typer.Argument(None, help="Help topic (e.g., 'iran', 'engines', 'configs')")):
    """Show detailed manual/help for a specific topic"""
    _show_help(topic)


@app.command(name="help")
def help_command(topic: str = typer.Argument(None, help="Help topic (e.g., 'iran', 'engines', 'configs')")):
    """Show detailed manual/help for a specific topic"""
    _show_help(topic)
country_app = typer.Typer(help="View or pin the active censorship country profile", no_args_is_help=False)
app.add_typer(country_app, name="country")

@country_app.callback(invoke_without_command=True)
def country_status(ctx: typer.Context):
    """Show the active country profile."""
    options = _output_options(ctx)
    if ctx.invoked_subcommand is not None:
        _reject_group_json(ctx.invoked_subcommand, options, _COUNTRY_JSON_COMMANDS)
        return
    from . import settings as cfg

    options = _output_options(ctx)
    values = cfg.load()
    pinned_code = values.get("country", "")
    if options.json_output:
        from . import country_profiles as profiles

        profile = profiles.get_profile(pinned_code) if pinned_code else None
        _print_json_enveloped(_country_payload(profile, pinned=bool(pinned_code)))
        return
    from .cli import cmd_country
    cmd_country(_args(country_command=None))


@country_app.command("set")
def country_set(
    code: str = typer.Argument(..., help="Country code: IR, RU, CN, IQ, GB, US, or EU"),
    ctx: typer.Context = None,
):
    """Pin the active country profile."""
    from . import country_profiles as profiles
    from . import settings as cfg

    code = _option_value(code)
    if ctx is None:
        from .cli import cmd_country

        cmd_country(_args(country_command="set", code=code))
        return
    options = _output_options(ctx)
    profile = profiles.get_profile(code)
    if profile is None:
        _fail_parameter(f"Unknown country code: {code}", options=options)
    cfg.set_value("country", profile.code)
    if options.json_output:
        _print_json_enveloped(_country_payload(profile, pinned=True))
    elif not _is_quiet(options):
        console.print(f"[success]✓ Country pinned to:[/success] {profile.name} ({profile.code})")


@country_app.command("reset")
def country_reset(ctx: typer.Context = None):
    """Return to ISP-based country auto-detection."""
    from . import settings as cfg

    options = _output_options(ctx)
    cfg.set_value("country", "")
    if options.json_output:
        _print_json_enveloped({"reset": True, "pinned": False})
    elif not _is_quiet(options):
        console.print("[success]✓ Country pin cleared.[/success]  Back to auto-detect from ISP.")


@country_app.command("show", hidden=True)
def country_show(ctx: typer.Context = None):
    """Show the active country profile."""
    country_status(ctx)


@country_app.command("list")
def country_list(ctx: typer.Context = None):
    """List built-in country profiles without network detection."""
    from . import country_profiles as profiles

    options = _output_options(ctx)
    records = [
        {
            "code": profile.code,
            "name": profile.name,
            "censorship_level": profile.censorship_level,
            "engine_order": list(profile.engine_order),
        }
        for profile in profiles.get_all_profiles()
    ]
    if options.json_output:
        _print_json_enveloped({"profiles": records})
    elif not _is_quiet(options):
        for record in records:
            console.print(f"{record['code']}: {record['name']} ({record['censorship_level']})")

# ── NEIGHBOR GROUP ──
neighbor_app = typer.Typer(help="Connect via a nearby Blackout Kit device", no_args_is_help=True)
app.add_typer(neighbor_app, name="neighbor")

@neighbor_app.command("discover")
def neighbor_discover():
    """Scan LAN for nearby sharers"""
    from .cli import cmd_neighbor
    args = _args()
    args.neighbor_command = "discover"
    cmd_neighbor(args)

@neighbor_app.command("connect")
def neighbor_connect(
    ip: str = typer.Argument(None, help="Neighbor IP address (e.g. 192.168.1.5)")
):
    """Use a neighbor's proxy."""
    from .cli import cmd_neighbor

    ip = ip or ask_text("Enter neighbor IP to connect to")
    if not ip:
        return
    args = _args()
    args.neighbor_command = "connect"
    args.host = ip
    cmd_neighbor(args)

@neighbor_app.command("share")
def neighbor_share():
    """Broadcast your proxy so neighbors can connect"""
    from .cli import cmd_neighbor
    args = _args()
    args.neighbor_command = "share"
    cmd_neighbor(args)

@neighbor_app.command("cache-list")
def neighbor_cache_list():
    """List cached LAN neighbors"""
    from .cli import cmd_neighbor
    args = _args()
    args.neighbor_command = "cache-list"
    cmd_neighbor(args)

@neighbor_app.command("cache-refresh")
def neighbor_cache_refresh():
    """Force neighbor discovery and refresh cache"""
    from .cli import cmd_neighbor
    args = _args()
    args.neighbor_command = "cache-refresh"
    cmd_neighbor(args)

@neighbor_app.command("cache-clear")
def neighbor_cache_clear(force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation prompt")):
    """Clear all cached neighbors"""
    from .cli import cmd_neighbor
    args = _args()
    args.neighbor_command = "cache-clear"
    args.force = force
    cmd_neighbor(args)

# ── DOWNLOAD GROUP ──
download_app = typer.Typer(help="Download manager with queue, resume, and speed limiting", no_args_is_help=True)
app.add_typer(download_app, name="download")

@download_app.command("add")
def download_add(url: str = typer.Argument(..., help="HTTP(S) URL to download"), output: str = typer.Option(None, "--output", "-o", help="Save to file"), speed_limit: int = typer.Option(0, "--speed-limit", "-s", help="Max speed in KBps (0=unlimited)")):
    """Queue a download"""
    from .cli import cmd_download
    args = _args()
    args.download_command = "add"
    args.url = url
    args.output = output
    args.speed_limit = speed_limit
    cmd_download(args)

@download_app.command("list")
def download_list(status: str = typer.Option(None, "--status", "-s", help="Filter by status (pending|downloading|completed|failed)")):
    """Show download queue and progress"""
    from .cli import cmd_download
    args = _args()
    args.download_command = "list"
    args.status = status
    cmd_download(args)

@download_app.command("start")
def download_start(ids: list[str] = typer.Argument(None, help="Download IDs to start"), all: bool = typer.Option(False, "--all", "-a", help="Start all pending downloads")):
    """Start queued downloads"""
    from .cli import cmd_download
    args = _args()
    args.download_command = "start"
    args.ids = ids or []
    args.all = all
    cmd_download(args)

@download_app.command("cancel")
def download_cancel(ids: list[str] = typer.Argument(None, help="Download IDs to cancel"), all: bool = typer.Option(False, "--all", "-a", help="Cancel all active downloads")):
    """Pause downloads (keep partial files for resume)"""
    from .cli import cmd_download
    args = _args()
    args.download_command = "cancel"
    args.ids = ids or []
    args.all = all
    cmd_download(args)

@download_app.command("clear")
def download_clear(scope: str = typer.Option("completed", "--scope", "-s", help="Clear completed|failed|all")):
    """Remove downloads from queue"""
    from .cli import cmd_download
    args = _args()
    args.download_command = "clear"
    args.scope = scope
    cmd_download(args)

@download_app.command("watch")
def download_watch(id: str = typer.Option(None, "--id", "-i", help="Watch specific download (default: all active)")):
    """Live progress for active downloads"""
    from .cli import cmd_download
    args = _args()
    args.download_command = "watch"
    args.id = id
    cmd_download(args)

# ── MEDIA GROUP ──
media_app = typer.Typer(help="Download videos from YouTube and similar platforms", no_args_is_help=True)
app.add_typer(media_app, name="media")

@media_app.command("add")
def media_add(url: str = typer.Argument(..., help="YouTube or similar video URL"), format: str = typer.Option(None, "--format", "-f", help="yt-dlp format (e.g., best[ext=mp4])"), best_audio_video: bool = typer.Option(False, "--best-audio-video", "-b", help="Download best audio + video"), output: str = typer.Option(None, "--output", "-o", help="Save to directory")):
    """Queue a media download; start it with `media start`."""
    from .cli import cmd_media
    cmd_media(_args(
        media_command="add",
        url=_option_value(url),
        format=_option_value(format),
        best_audio_video=bool(_option_value(best_audio_video, False)),
        output=_option_value(output),
    ))


@media_app.command("start")
def media_start():
    """Start queued media downloads (requires blackout-kit[media])."""
    from .cli import cmd_media
    cmd_media(_args(media_command="start"))


@media_app.command("list")
def media_list():
    """Show media download queue"""
    from .cli import cmd_media
    cmd_media(_args(media_command="list"))


@media_app.command("watch")
def media_watch(id: str = typer.Option(None, "--id", "-i", help="Watch specific download (default: all active)")):
    """Live progress for active downloads"""
    from .cli import cmd_media
    cmd_media(_args(media_command="watch", id=_option_value(id)))


@media_app.command("cancel")
def media_cancel(id: str = typer.Argument(..., help="Download ID to cancel")):
    """Stop a media download"""
    from .cli import cmd_media
    cmd_media(_args(media_command="cancel", id=_option_value(id)))


@media_app.command("clear")
def media_clear():
    """Remove completed downloads"""
    from .cli import cmd_media
    cmd_media(_args(media_command="clear"))


# ── TORRENT GROUP ──
torrent_app = typer.Typer(help="Download torrents and magnets with libtorrent", no_args_is_help=True)
app.add_typer(torrent_app, name="torrent")

@torrent_app.command("add")
def torrent_add(magnet_or_file: str = typer.Argument(..., help="Magnet link or .torrent file path"), output: str = typer.Option(None, "--output", "-o", help="Save to directory"), ratio: float = typer.Option(1.0, "--ratio", "-r", help="Seed ratio (1.0 = 1:1, default)")):
    """Queue a torrent download."""
    from .cli import cmd_torrent
    cmd_torrent(_args(torrent_command="add", magnet_or_file=_option_value(magnet_or_file), output=_option_value(output), ratio=float(_option_value(ratio, 1.0))))


@torrent_app.command("start")
def torrent_start():
    """Start queued torrents (requires blackout-kit[torrent])."""
    from .cli import cmd_torrent
    cmd_torrent(_args(torrent_command="start"))


@torrent_app.command("list")
def torrent_list():
    """Show torrent queue"""
    from .cli import cmd_torrent
    cmd_torrent(_args(torrent_command="list"))


@torrent_app.command("watch")
def torrent_watch(id: str = typer.Option(None, "--id", "-i", help="Watch specific torrent (default: all active)")):
    """Live progress for active torrents"""
    from .cli import cmd_torrent
    cmd_torrent(_args(torrent_command="watch", id=_option_value(id)))


@torrent_app.command("cancel")
def torrent_cancel(id: str = typer.Argument(..., help="Torrent ID to cancel")):
    """Stop a torrent"""
    from .cli import cmd_torrent
    cmd_torrent(_args(torrent_command="cancel", id=_option_value(id)))


@torrent_app.command("seed")
def torrent_seed(id: str = typer.Argument(..., help="Torrent ID"), ratio: float = typer.Option(1.0, "--ratio", "-r", help="Seed ratio")):
    """Set seed ratio for a torrent"""
    from .cli import cmd_torrent
    cmd_torrent(_args(torrent_command="seed", id=_option_value(id), ratio=float(_option_value(ratio, 1.0))))


@torrent_app.command("clear")
def torrent_clear():
    """Remove completed torrents"""
    from .cli import cmd_torrent
    cmd_torrent(_args(torrent_command="clear"))

# ── SETTINGS GROUP ──
settings_app = typer.Typer(help="View and change all settings", no_args_is_help=False)
app.add_typer(settings_app, name="settings")


@settings_app.callback(invoke_without_command=True)
def settings_status(ctx: typer.Context):
    """Open the keyboard settings editor when no subcommand is given."""
    options = _output_options(ctx)
    if ctx.invoked_subcommand is not None:
        _reject_group_json(ctx.invoked_subcommand, options, _SETTINGS_JSON_COMMANDS)
        return
    if options.json_output:
        _print_cli_error(
            "missing_command",
            "a settings subcommand is required",
            options=options,
            exit_code=2,
        )
    if not is_interactive():
        console.print("[warning]Usage: blackout settings (list | get <key> | set <key> <value> | reset)[/warning]")
        return
    from .interactive import run_settings_menu
    run_settings_menu()


@settings_app.command("edit")
def settings_edit():
    """Open the keyboard settings editor explicitly."""
    from .interactive import run_settings_menu
    run_settings_menu()


@config_app.command("edit")
def config_edit():
    """Open the keyboard config manager explicitly."""
    from .interactive import run_config_menu
    run_config_menu()


@settings_app.command("list")
def settings_list(ctx: typer.Context = None):
    """List all settings with sensitive values masked."""
    from . import settings as cfg
    from rich.markup import escape

    values = cfg.load()
    options = _output_options(ctx)
    if options.json_output:
        _print_json_enveloped(_settings_payload(values))
        return
    if _is_quiet(options):
        return
    _render_settings(values)


@settings_app.command("get")
def settings_get(
    key: str = typer.Argument(..., help="Setting key"),
    ctx: typer.Context = None,
):
    """Get one setting with its description."""
    from . import settings as cfg
    from rich.markup import escape

    key = _option_value(key)
    if key not in cfg.DEFAULTS:
        raise typer.BadParameter(f"Unknown setting: '{key}'")
    values = cfg.load()
    value = cfg.display_value(key, values.get(key, cfg.DEFAULTS[key]))
    options = _output_options(ctx)
    if options.json_output:
        _print_json_enveloped({
            "key": key,
            "value": value,
            "description": cfg.describe(key),
        })
        return
    if _is_quiet(options):
        return
    display_value = ", ".join(str(item) for item in value) if isinstance(value, list) else str(value)
    console.print(f"  [bold]{escape(key)}[/bold] = [cyan]{escape(display_value)}[/cyan]")
    console.print(f"  [muted]{escape(cfg.describe(key))}[/muted]")


@settings_app.command("set")
def settings_set(
    key: str = typer.Argument(..., help="Setting key"),
    value: str = typer.Argument(None, help="New value (omit with --prompt or --stdin)"),
    prompt: bool = typer.Option(False, "--prompt", help="Read a sensitive value without echoing it"),
    stdin_input: bool = typer.Option(False, "--stdin", help="Read a value from stdin without echoing it"),
    ctx: typer.Context = None,
):
    """Change one setting after type and bounds validation."""
    from . import settings as cfg

    key = _option_value(key)
    value = _option_value(value)
    prompt = bool(_option_value(prompt, False))
    stdin_input = bool(_option_value(stdin_input, False))
    options = _output_options(ctx)
    if key not in cfg.DEFAULTS:
        _fail_parameter(f"Unknown setting: '{key}'", options=options)
    if prompt or stdin_input:
        if key not in cfg.SENSITIVE_KEYS:
            _fail_parameter("--prompt and --stdin are only available for sensitive settings", options=options)
        if value is not None:
            _fail_parameter("do not provide a value with --prompt or --stdin", options=options)
        value = _read_cli_secret(
            f"{key}: ",
            prompt_input=prompt,
            stdin_input=stdin_input,
        )
    elif key in cfg.SENSITIVE_KEYS:
        _fail_parameter("secret input requires --prompt or --stdin", options=options)
    if value is None:
        _fail_parameter("a value is required", options=options)
    try:
        typed_value = cfg.coerce_value(key, value)
        cfg.set_value(key, typed_value)
    except ValueError as exc:
        _fail_parameter(str(exc), options=options)
    if key in {"color_theme", "terminal_theme"}:
        refresh_console_theme()
    if options.json_output:
        _print_json_enveloped({
            "updated": True,
            "key": key,
            "value": cfg.display_value(key, typed_value),
        })
    elif not _is_quiet(options):
        display = cfg.display_value(key, typed_value)
        console.print(f"[success]✓ {key} = {display}[/success]")


@settings_app.command("reset")
def settings_reset(ctx: typer.Context = None):
    """Reset all settings to defaults."""
    from . import settings as cfg

    options = _output_options(ctx)
    cfg.reset()
    if options.json_output:
        _print_json_enveloped({"reset": True})
    elif not _is_quiet(options):
        console.print("[success]✓ All settings reset to defaults.[/success]")


# ── BINS GROUP ──
bins_app = typer.Typer(help="Download and manage engine binaries", no_args_is_help=False)
app.add_typer(bins_app, name="bins")

@bins_app.callback(invoke_without_command=True)
def bins_status(ctx: typer.Context):
    """Show installed and missing engine binaries."""
    options = _output_options(ctx)
    if ctx.invoked_subcommand is not None:
        _reject_group_json(ctx.invoked_subcommand, options, _BINS_JSON_COMMANDS)
        return
    payload = _bins_payload()
    if options.json_output:
        _print_json_enveloped(payload)
        return
    if _is_quiet(options):
        return
    from .cli import cmd_bins
    cmd_bins(_args(bins_command=None))


@bins_app.command("list")
def bins_list(ctx: typer.Context = None):
    """List local binary status without downloads or system changes."""
    options = _output_options(ctx)
    payload = _bins_payload()
    if options.json_output:
        _print_json_enveloped(payload)
        return
    if _is_quiet(options):
        return
    for item in payload["binaries"]:
        status = "installed" if item["installed"] else "missing"
        required = "required" if item["required"] else "optional"
        console.print(f"{item['key']}: {status} ({required})")

@bins_app.command("download")
def bins_download(
    engine: str = typer.Argument(None, help="Specific engine (or omit for all missing)")
):
    """Download missing binaries"""
    from .cli import cmd_bins
    args = _args()
    args.bins_command = "download"
    args.binary = engine
    cmd_bins(args)

@bins_app.command("update")
def bins_update():
    """Re-download installed binaries to update them."""
    from .cli import cmd_bins
    cmd_bins(_args(bins_command="update"))

@app.command(name="_daemon_run", hidden=True)
def daemon_run(
    engine: str = typer.Option(..., "--engine"),
    generation: str = typer.Option(..., "--generation", hidden=True),
    env_overrides_json: str = typer.Option(None, "--env-overrides-json", hidden=True),
):
    from .cli import cmd_daemon_run
    args = _args()
    args.engine = engine
    args.generation = generation
    args.env_overrides_json = env_overrides_json
    cmd_daemon_run(args)


@app.command(name="_watchdog", hidden=True)
def watchdog(
    pid: int = typer.Argument(...),
    generation: str = typer.Argument(...),
):
    from .watchdog import monitor
    monitor(pid, generation)


@app.command()
def preflight():
    """Check readiness for an internet blackout"""
    from .cli import cmd_preflight
    cmd_preflight(_args())

@app.command(name="0xDEADBEEF", hidden=True)
def deadbeef():
    from .cli import cmd_easteregg
    cmd_easteregg(_args())

@app.callback(invoke_without_command=True)
def app_callback(
    ctx: typer.Context,
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit machine-readable JSON for read-only commands",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Suppress routine human-readable output",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose command output",
    ),
    no_color: bool = typer.Option(
        False,
        "--no-color",
        help="Disable terminal styling",
    ),
):
    console.no_color = _DEFAULT_NO_COLOR
    json_output = bool(_option_value(json_output, False))
    quiet = bool(_option_value(quiet, False))
    verbose = bool(_option_value(verbose, False))
    no_color = bool(_option_value(no_color, False))
    options = OutputOptions(
        json_output=json_output,
        quiet=quiet,
        verbose=verbose,
        no_color=no_color,
    )
    ctx.obj = {"output": options}
    _register_verbose_close(ctx, options)
    if ctx.invoked_subcommand is not None:
        _reject_unsupported_json(ctx.invoked_subcommand, options)
    if no_color:
        console.no_color = True
    if ctx.invoked_subcommand is None:
        if json_output:
            _print_cli_error(
                "missing_command",
                "a command is required",
                options=ctx.obj["output"],
                exit_code=2,
            )
        if not quiet and is_interactive():
            from .onboarding import render_first_run_welcome
            render_first_run_welcome(console)
        from . import settings as cfg
        from .cli import print_banner, _show_launcher_menu
        s = cfg.load()
        if s.get("show_banner", True) and not quiet:
            print_banner()
        _show_launcher_menu()


def main():
    """Global entry point for the Typer CLI."""
    from . import proxy_manager

    proxy_manager.install_console_close_handler()
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n[muted]Operation cancelled by user.[/muted]")
        sys.exit(130)
    except Exception as exc:
        if _json_requested():
            emit_error(
                "internal_error",
                "Blackout Kit could not complete that action",
                console=console,
                json_output=True,
            )
        else:
            print_friendly_error(exc)
        sys.exit(1)


if __name__ == "__main__":
    main()


@tools_app.command("audit")
def tools_audit():
    """🛡️ Run a security hardening audit (scans open ports, DNS, cleartext services, killswitch)."""
    from .tools import run_network_audit

    console.print("[bold cyan]🛡️ Running Network Hardening Audit...[/bold cyan]\n")
    report = run_network_audit()

    score = report["score"]
    grade = report["grade"]
    score_color = "green" if score >= 80 else "yellow" if score >= 60 else "red"

    console.print(f"Overall Security Posture Score: [{score_color}][bold]{score}/100 ({grade})[/bold][/{score_color}]\n")

    table = make_table(
        "Security Audit Findings",
        [("Category", "cyan"), ("Status", ""), ("Summary", "bold white"), ("Recommendation", "dim")],
        [],
    )

    for f in report["findings"]:
        status = "[success]✓ PASS[/success]" if f["ok"] else f"[error]⚠ {f['severity']}[/error]"
        table.add_row(f["category"], status, f["summary"], f["recommendation"])

    console.print(table)


@tools_app.command("process-monitor")
def tools_process_monitor():
    """👁️ Live Process Network Monitor (attributes active sockets to local processes)."""
    from .tools import monitor_process_network

    console.print("[bold cyan]👁️ Process Network Connection Summary...[/bold cyan]\n")
    procs = monitor_process_network()

    table = make_table(
        "Process Network Summary",
        [("PID", "dim"), ("Process Name", "bold white"), ("Total Sockets", "cyan"), ("Established", "green"), ("Protocols", "yellow"), ("Sample Remote Endpoint", "dim")],
        [],
    )

    for p in procs[:30]:  # Top 30 process talkers
        table.add_row(
            str(p["pid"]),
            p["process"],
            str(p["socket_count"]),
            str(p["established_count"]),
            p["protocols"],
            p["remote_sample"]
        )

    console.print(table)


@tools_app.command("honeypot")
def tools_honeypot(
    duration: int = typer.Option(60, "--duration", "-d", help="Duration in seconds to run honeypot listener"),
    ports: str = typer.Option("22,80,445,3389,8080", "--ports", "-p", help="Comma-separated decoy ports"),
):
    """🐝 Public Wi-Fi Honeypot & Scan Detector (alerts when local network IPs probe decoy ports)."""
    from .tools import run_honeypot_listener

    port_list = [int(p.strip()) for p in ports.split(",") if p.strip().isdigit()]
    console.print(f"[bold cyan]🐝 Public Wi-Fi Honeypot Active[/bold cyan] (listening on ports {port_list} for {duration}s)...\n")

    def _alert(probe):
        console.print(f"[bold red]⚠️ ALERT: Port probe detected from {probe['remote_ip']}:{probe['remote_port']} -> Decoy Port {probe['target_port']}![/bold red]")

    probes = run_honeypot_listener(ports=port_list, duration=float(duration), callback=_alert)

    if probes:
        console.print(f"\n[bold red]Detected {len(probes)} suspicious scan attempts during honeypot session.[/bold red]")
    else:
        console.print("[success]✓ Honeypot session finished. No suspicious network scans detected on local LAN.[/success]")


@tools_app.command("dns-proxy")
def tools_dns_proxy(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Local IP to bind DNS proxy listener"),
    port: int = typer.Option(5300, "--port", "-p", help="Local UDP port to bind DNS proxy listener"),
    upstream: str = typer.Option("https://1.1.1.1/dns-query", "--upstream", "-u", help="Upstream DoH endpoint URL"),
):
    """🌐 Secure DoH DNS Proxy Engine (local UDP listener that forwards queries over encrypted DNS-over-HTTPS)."""
    from .tools import run_doh_proxy_server

    console.print(f"[bold cyan]🌐 Secure DoH DNS Proxy Engine Active[/bold cyan]")
    console.print(f"[muted]Listening on UDP {host}:{port} -> Forwarding over encrypted DoH to {upstream}[/muted]")
    console.print("[dim]Press Ctrl+C to stop local DNS proxy...[/dim]\n")

    try:
        run_doh_proxy_server(host=host, port=port, upstream_doh=upstream)
    except KeyboardInterrupt:
        console.print("\n[muted]DoH DNS Proxy server stopped.[/muted]")


@tools_app.command("explain")
def tools_explain():
    """🤖 AI Network Explainer (reads live network state and summarizes anomalies)."""
    from .tools import explain_network_state

    console.print("[bold cyan]🤖 AI Network State Analysis...[/bold cyan]\n")
    report = explain_network_state()

    console.print(f"Overall Security Score: [bold green]{report['security_score']}/100 ({report['grade']})[/bold green]")
    console.print(f"Active Process Connections: {report['active_processes_count']}")
    console.print(f"Anomalies Detected: [bold red]{report['total_anomalies_detected']}[/bold red]\n")

    if report["anomalies"]:
        console.print("[bold yellow]Detected Anomalies / Warnings:[/bold yellow]")
        for a in report["anomalies"]:
            console.print(f"  • {a}")
    else:
        console.print("[bold green]✓ No suspicious network anomalies detected.[/bold green]")


# ── SSH GROUP ──
ssh_app = typer.Typer(help="SSH Vault & Manager (manage and connect to SSH servers)", no_args_is_help=False)
app.add_typer(ssh_app, name="ssh")

@ssh_app.command("add")
def ssh_add(
    name: str = typer.Argument(..., help="Profile alias name (e.g. prod-server)"),
    host: str = typer.Option(..., "--host", "-h", help="Hostname or IP address"),
    user: str = typer.Option("root", "--user", "-u", help="SSH username (default: root)"),
    port: int = typer.Option(22, "--port", "-p", help="SSH port (default: 22)"),
    key: str = typer.Option("", "--key", "-k", help="Optional private key file path"),
):
    """Add or update an SSH connection profile in the vault."""
    from .tools import save_ssh_profile
    if save_ssh_profile(name, host, user, port, key):
        console.print(f"[success]✓ SSH profile '{name}' saved to vault![/success]")
    else:
        console.print(f"[error]Failed to save SSH profile '{name}'[/error]")

@ssh_app.command("list")
def ssh_list():
    """List all saved SSH profiles."""
    from .tools import list_ssh_profiles
    profiles = list_ssh_profiles()
    if not profiles:
        console.print("[muted]No SSH profiles saved in vault. Use `blackout ssh add` to add one.[/muted]")
        return
    table = make_table(
        "Saved SSH Vault Profiles",
        [("Name", "bold cyan"), ("User@Host", "bold white"), ("Port", "yellow"), ("Key Path", "dim")],
        [],
    )
    for p in profiles:
        table.add_row(p["name"], f"{p['user']}@{p['host']}", str(p["port"]), p.get("key_path") or "default")
    console.print(table)

@ssh_app.command("connect")
def ssh_connect(
    name: str = typer.Argument(..., help="SSH profile name to connect to"),
):
    """Connect to a saved SSH profile using system ssh client."""
    import subprocess
    from .tools import list_ssh_profiles
    profiles = {p["name"]: p for p in list_ssh_profiles()}
    if name not in profiles:
        console.print(f"[error]SSH profile '{name}' not found in vault.[/error]")
        return
    p = profiles[name]
    cmd = ["ssh", f"{p['user']}@{p['host']}", "-p", str(p["port"])]
    if p.get("key_path"):
        cmd.extend(["-i", p["key_path"]])
    console.print(f"[info]Connecting to {p['name']} ({p['user']}@{p['host']}:{p['port']})...[/info]")
    try:
        subprocess.run(cmd)
    except Exception as exc:
        console.print(f"[error]Failed to launch SSH client: {exc}[/error]")

@ssh_app.command("remove")
def ssh_remove(
    name: str = typer.Argument(..., help="SSH profile name to remove"),
):
    """Remove a saved SSH profile from vault."""
    from .tools import remove_ssh_profile
    if remove_ssh_profile(name):
        console.print(f"[success]✓ Removed SSH profile '{name}' from vault.[/success]")
    else:
        console.print(f"[error]SSH profile '{name}' not found in vault.[/error]")


# ── REST API / DASHBOARD GROUP ──
api_app = typer.Typer(help="Local REST API & Web Dashboard", no_args_is_help=False)
app.add_typer(api_app, name="api")

@api_app.command("start")
def api_start(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Host IP to bind web server"),
    port: int = typer.Option(8080, "--port", "-p", help="Port to bind web server"),
):
    """Start local REST API and browser-based Web Dashboard."""
    from .tools import run_web_api_dashboard
    console.print(f"[bold cyan]🌐 Starting Blackout Kit Web Dashboard & REST API...[/bold cyan]")
    console.print(f"[success]✓ Open dashboard in your browser:[/success] [bold white]http://{host}:{port}/[/bold white]")
    console.print("[dim]Press Ctrl+C to stop the REST API server...[/dim]\n")
    run_web_api_dashboard(host=host, port=port)


# ── AUTOMATION GROUP ──
automation_app = typer.Typer(help="Scriptable Event Automation (rules for network events)", no_args_is_help=False)
app.add_typer(automation_app, name="automation")

@automation_app.command("add")
def auto_add(
    name: str = typer.Argument(..., help="Automation rule name"),
    event: str = typer.Option(..., "--event", "-e", help="Event trigger name (e.g. on_network_disconnect, on_dns_tamper)"),
    action: str = typer.Option(..., "--action", "-a", help="Action to run: panic | flush_dns | flush_arp | audit | recovery"),
):
    """Add a scriptable event automation rule."""
    from .tools import save_automation_rule
    if save_automation_rule(name, event, action):
        console.print(f"[success]✓ Automation rule '{name}' saved![/success]")
    else:
        console.print(f"[error]Failed to save automation rule '{name}'[/error]")

@automation_app.command("list")
def auto_list():
    """List configured event automation rules."""
    from .tools import list_automation_rules
    rules = list_automation_rules()
    if not rules:
        console.print("[muted]No automation rules saved. Use `blackout automation add` to create one.[/muted]")
        return
    table = make_table(
        "Event Automation Rules",
        [("Rule Name", "bold cyan"), ("Event Trigger", "bold white"), ("Action", "yellow"), ("Status", "green")],
        [],
    )
    for r in rules:
        status = "Active" if r.get("enabled", True) else "Disabled"
        table.add_row(r["name"], r["event"], r["action"], status)
    console.print(table)

@automation_app.command("trigger")
def auto_trigger(
    event: str = typer.Argument(..., help="Event name to trigger (e.g. on_network_disconnect)"),
):
    """Manually trigger an event to run matching automation actions."""
    from .tools import trigger_automation_event
    results = trigger_automation_event(event)
    if not results:
        console.print(f"[muted]No active automation rules matched event '{event}'.[/muted]")
        return
    for res in results:
        status_str = "[success]✓ OK[/success]" if res["ok"] else "[error]✗ Failed[/error]"
        console.print(f"Rule [bold]{res['rule']}[/bold]: {status_str} -> {res['detail']}")

@automation_app.command("remove")
def auto_remove(
    name: str = typer.Argument(..., help="Automation rule name to remove"),
):
    """Remove an automation rule."""
    from .tools import remove_automation_rule
    if remove_automation_rule(name):
        console.print(f"[success]✓ Removed automation rule '{name}'.[/success]")
    else:
        console.print(f"[error]Automation rule '{name}' not found.[/error]")


@tools_app.command("scan-yara")
def tools_scan_yara(
    path: str = typer.Argument(..., help="Path to local file to scan with YARA rules engine"),
):
    """🔒 YARA Rules Engine (scan file against malware & webshell byte signatures)."""
    from .tools import scan_file_yara
    res = scan_file_yara(path)
    if not res["ok"]:
        console.print(f"[error]YARA scan error: {res.get('error')}[/error]")
        return
    if res["clean"]:
        console.print(f"[success]✓ YARA Scan Clean: No signature threats found in {path}[/success]")
    else:
        console.print(f"[bold red]⚠️ YARA THREAT MATCHES DETECTED in {path}:[/bold red]")
        for m in res["matches"]:
            console.print(f"  • Matched Rule: [bold]{m['rule']}[/bold]")


@tools_app.command("simulate")
def tools_simulate(
    host: str = typer.Argument("8.8.8.8", help="Target host to probe"),
    latency: float = typer.Option(100.0, "--latency", "-l", help="Added latency in ms"),
    loss: float = typer.Option(10.0, "--loss", help="Simulated packet loss percentage (0-100)"),
):
    """⚡ Network Simulation (simulate high latency and packet loss for DevOps/QA testing)."""
    from .tools import simulate_network_conditions
    res = simulate_network_conditions(host=host, added_latency_ms=latency, simulated_loss_pct=loss)
    st = res["stats"]
    console.print(f"[bold cyan]⚡ Network Simulation to {host}[/bold cyan] (+{latency}ms latency, {loss}% loss):\n")
    console.print(f"Avg Latency: {st['avg']:.1f}ms | Loss Rate: {st['loss_pct']:.1f}%")


@tools_app.command("phishing-check")
def tools_phishing_check(
    domain: str = typer.Argument(..., help="Domain name to check for phishing / typosquatting risks"),
):
    """🛡️ Phishing Domain Check (scans domain for typosquatting & phishing heuristics)."""
    from .tools import check_phishing_domain
    res = check_phishing_domain(domain)
    if res["safe"]:
        console.print(f"[success]✓ Domain '{domain}' ({res['ip']}) appears clean from common phishing keywords.[/success]")
    else:
        console.print(f"[bold red]⚠️ PHISHING / TYPOSQUATTING RISK DETECTED for '{domain}':[/bold red]")
        for r in res["reasons"]:
            console.print(f"  • {r}")


@tools_app.command("traffic-graph")
def tools_traffic_graph(
    samples: int = typer.Option(5, "--samples", "-s", help="Number of samples to record"),
    interval: float = typer.Option(1.0, "--interval", "-i", help="Interval between samples in seconds"),
):
    """📊 Live Visual Traffic Graph (displays real-time bandwidth bars)."""
    from .tools import get_interface_io_counters, compute_bandwidth_rates, generate_ascii_bandwidth_chart
    console.print(f"[bold cyan]📊 Live Traffic Visual Bar Graph ({samples} samples)...[/bold cyan]\n")

    prev = get_interface_io_counters()
    for _ in range(samples):
        time.sleep(interval)
        curr = get_interface_io_counters()
        rates = compute_bandwidth_rates(prev, curr, interval)
        prev = curr

        tot_rx = sum(r["rx_bps"] for r in rates.values())
        tot_tx = sum(r["tx_bps"] for r in rates.values())

        chart = generate_ascii_bandwidth_chart(tot_rx, tot_tx)
        console.print(chart + "\n")


@tools_app.command("arp-guard")
def tools_arp_guard():
    """🌐 Subnet ARP Guard (detects duplicate MAC addresses indicating ARP poisoning / MITM)."""
    from .tools import detect_arp_spoofing
    res = detect_arp_spoofing()
    if res["ok"]:
        console.print(f"[success]✓ ARP Guard Clean: Checked {res['total_hosts']} hosts on local ARP table. No ARP spoofing detected.[/success]")
    else:
        console.print(f"[bold red]⚠️ SUSPECTED ARP POISONING / MITM ATTACK DETECTED:[/bold red]")
        for s in res["spoof_suspects"]:
            console.print(f"  • MAC [bold]{s['mac']}[/bold] is shared by multiple IPs: {', '.join(s['ips'])}")


# ── VAULT MANAGEMENT GROUP ──
vault_app = typer.Typer(help="Encrypted Vault Backup & Key Utility", no_args_is_help=False)
app.add_typer(vault_app, name="vault")

@vault_app.command("backup")
def vault_backup(
    output: str = typer.Option("blackout_vault_backup.json", "--output", "-o", help="Backup output path"),
):
    """Create an encrypted backup of the saved configs & settings vault."""
    from . import settings as cfg
    from .config.manager import load_configs, serialize_setup
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
    out_path = Path(output).expanduser().resolve()
    try:
        setup_data = serialize_setup()
        out_path.write_text(json.dumps(setup_data, indent=2), encoding="utf-8")
        console.print(f"[success]✓ Vault backup written to: {out_path}[/success]")
    except Exception as exc:
        console.print(f"[error]Failed to write vault backup: {exc}[/error]")

@vault_app.command("restore")
def vault_restore(
    path: str = typer.Argument(..., help="Path to backup file to restore"),
):
    """Restore vault configs & settings from a backup file."""
    from .typer_cli import _decode_setup, _apply_setup
    p = Path(path).expanduser().resolve()
    if not p.exists():
        console.print(f"[error]Backup file not found: {p}[/error]")
        return
    try:
        content = p.read_text(encoding="utf-8")
        setup_data = json.loads(content)
        from .typer_cli import _validate_setup_data
        configs, settings_data = _validate_setup_data(setup_data)
        _apply_setup(configs, settings_data)
        console.print(f"[success]✓ Vault restored successfully from {p} ({len(configs)} configs)![/success]")
    except Exception as exc:
        console.print(f"[error]Failed to restore vault backup: {exc}[/error]")


@config_app.command("benchmark")
def cfg_benchmark():
    """📜 Interactive Proxy Config Benchmark (test all saved proxy records concurrently)."""
    from .config.manager import load_configs
    from .scanner.proxy_tester import test_tcp_port
    configs = load_configs()
    if not configs:
        console.print("[muted]No saved configs to benchmark.[/muted]")
        return
    console.print(f"[bold cyan]📜 Benchmarking {len(configs)} saved proxy configs...[/bold cyan]\n")
    table = make_table(
        "Config Benchmark Results",
        [("#", "dim"), ("Protocol", "cyan"), ("Transport", "yellow"), ("Server Endpoint", "bold white"), ("Latency", "green")],
        [],
    )
    for idx, cfg in enumerate(configs, 1):
        parsed = cfg.parsed_dict if hasattr(cfg, "parsed_dict") else {}
        server = parsed.get("add") or parsed.get("host") or "unknown"
        port = int(parsed.get("port") or 443)
        lat = test_tcp_port(server, port)
        lat_str = f"{int(lat)} ms" if lat is not None else "[red]Timeout[/red]"
        table.add_row(str(idx), cfg.protocol, cfg.transport_label(), f"{server}:{port}", lat_str)
    console.print(table)


@ssh_app.command("sftp")
def ssh_sftp(
    name: str = typer.Argument(..., help="SSH profile name"),
    action: str = typer.Option("ls", "--action", "-a", help="ls | get | put"),
    remote: str = typer.Option(".", "--remote", "-r", help="Remote path"),
    local: str = typer.Option("", "--local", "-l", help="Local path for get/put"),
):
    """📂 SFTP Remote File Manager (browse, upload, or download remote files)."""
    import subprocess
    from .tools import run_sftp_client
    res = run_sftp_client(name, action=action, remote_path=remote, local_path=local)
    if not res["ok"]:
        console.print(f"[error]{res['error']}[/error]")
        return
    console.print(f"[info]Connecting to SFTP for {res['user_host']}...[/info]")
    try:
        subprocess.run(res["command_args"])
    except Exception as exc:
        console.print(f"[error]Failed to launch SFTP client: {exc}[/error]")
