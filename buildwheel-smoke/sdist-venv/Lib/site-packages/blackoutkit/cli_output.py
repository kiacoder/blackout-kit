"""Shared output, error, and sensitive-input helpers for the CLI."""
from __future__ import annotations

from dataclasses import dataclass
import getpass
import json
import sys
import time
from typing import Any, TextIO

from rich.console import Console


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


__all__ = [
    "DEFAULT_INPUT_LIMIT",
    "OUTPUT_SCHEMA_VERSION",
    "OptionalDependencyError",
    "OutputOptions",
    "SAFE_SOURCE_LABELS",
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
    "require_executable",
    "require_import",
    "safe_doctor_check",
    "sanitize_diagnostic_detail",
    "success_payload",
]
