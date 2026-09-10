"""Validation helpers with helpful error messages."""
from __future__ import annotations

import typer
from pathlib import Path
from typing import Any, Optional

from .theme import console


class ValidationError(typer.BadParameter):
    """Validation error with helpful context."""

    def __init__(
        self,
        message: str,
        *,
        hint: Optional[str] = None,
        examples: Optional[list[str]] = None,
        param_hint: Optional[str] = None,
    ):
        """
        Create a validation error with helpful guidance.

        Args:
            message: The main error message
            hint: Optional hint about what went wrong
            examples: Optional list of correct usage examples
            param_hint: Optional info about which parameter failed
        """
        self.message = message
        self.hint = hint
        self.examples = examples
        self.param_hint = param_hint
        super().__init__(message)

    def display(self) -> None:
        """Display the error in a user-friendly format."""
        console.print(f"[red]✗ {self.message}[/red]")
        if self.hint:
            console.print(f"[yellow]💡 {self.hint}[/yellow]")
        if self.examples:
            console.print("[cyan]Examples:[/cyan]")
            for example in self.examples:
                console.print(f"  [dim]$[/dim] {example}")


def validate_file_exists(path: str, param_name: str = "file") -> Path:
    """Validate that a file exists."""
    p = Path(path)
    if not p.exists():
        raise ValidationError(
            f"{param_name} not found: {path}",
            hint=f"Check the path and try again. Make sure the file exists.",
            examples=[f"blackout config import /path/to/{param_name}"],
        )
    if not p.is_file():
        raise ValidationError(
            f"{param_name} is not a file: {path}",
            hint=f"Expected a file, not a directory.",
        )
    return p


def validate_integer(value: Any, param_name: str, *, min_val: int = None, max_val: int = None) -> int:
    """Validate that a value is an integer within bounds."""
    try:
        num = int(value)
    except (ValueError, TypeError):
        raise ValidationError(
            f"{param_name} must be a number, got: {value!r}",
            hint=f"Use only digits (0-9)",
            examples=[f"blackout config remove 1"],
        )

    if min_val is not None and num < min_val:
        raise ValidationError(
            f"{param_name} must be at least {min_val}, got: {num}",
            hint=f"Provide a larger number",
        )

    if max_val is not None and num > max_val:
        raise ValidationError(
            f"{param_name} must be at most {max_val}, got: {num}",
            hint=f"Provide a smaller number",
        )

    return num


def validate_choice(value: str, choices: list[str], param_name: str = "option") -> str:
    """Validate that a value is one of the allowed choices."""
    if value not in choices:
        raise ValidationError(
            f"Invalid {param_name}: {value!r}",
            hint=f"Must be one of: {', '.join(choices)}",
            examples=[f"blackout theme {choices[0]}"],
        )
    return value


def validate_url(url: str, param_name: str = "URL", *, require_https: bool = False) -> str:
    """
    Validate that a URL has a valid scheme.

    Args:
        url: The URL to validate
        param_name: The parameter name for error messages
        require_https: If True, only allow https:// (not http://)

    Returns:
        The validated URL string
    """
    if require_https:
        allowed_schemes = ("https://", "vmess://", "vless://", "trojan://", "hysteria2://")
        hint = "URL must start with https:// or a proxy protocol (vmess, vless, trojan, hysteria2)"
    else:
        allowed_schemes = ("http://", "https://", "vmess://", "vless://", "trojan://", "hysteria2://")
        hint = "URL must start with http://, https://, or a proxy protocol (vmess, vless, trojan, hysteria2)"

    if not url.startswith(allowed_schemes):
        raise ValidationError(
            f"Invalid {param_name}: {url[:50]}...",
            hint=hint,
            examples=[
                "blackout config add https://example.com/sub",
                "blackout config add vmess://...",
            ],
        )
    return url


def validate_not_empty(value: str, param_name: str = "value") -> str:
    """Validate that a value is not empty."""
    if not value or not value.strip():
        raise ValidationError(
            f"{param_name} cannot be empty",
            hint=f"Provide a non-empty {param_name}",
            examples=[f"blackout config add vless://..."],
        )
    return value.strip()


def validate_port(port: Any, param_name: str = "port") -> int:
    """Validate that a value is a valid port number."""
    num = validate_integer(port, param_name, min_val=1, max_val=65535)
    return num


def validate_config_number(num: Any) -> int:
    """Validate that a config number is valid (1-indexed)."""
    n = validate_integer(num, "config number", min_val=1)
    return n


def handle_validation_error(exc: ValidationError) -> None:
    """Display a validation error and exit gracefully."""
    exc.display()
    raise typer.Exit(code=1)
