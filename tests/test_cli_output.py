import io
import json

import pytest
from rich.console import Console

from blackoutkit.cli_output import (
    OutputOptions,
    emit_error,
    emit_json,
    error_payload,
    read_secret,
    read_stdin,
    success_payload,
)


def test_success_payload_has_versioned_envelope():
    assert success_payload({"ready": True}) == {
        "schema_version": 1,
        "ok": True,
        "data": {"ready": True},
    }


def test_error_payload_omits_optional_details():
    assert error_payload("invalid_input", "Bad value") == {
        "schema_version": 1,
        "ok": False,
        "error": {"code": "invalid_input", "message": "Bad value"},
    }


def test_emit_json_is_one_line_and_parseable():
    console = Console(file=io.StringIO(), color_system=None, force_terminal=False)
    emit_json({"text": "a\nb", "number": 2}, console=console)

    output = console.file.getvalue()
    assert "\n" not in output.rstrip("\n")
    assert json.loads(output) == {
        "schema_version": 1,
        "ok": True,
        "data": {"number": 2, "text": "a\nb"},
    }


def test_emit_error_returns_exit_code_and_json():
    console = Console(file=io.StringIO(), color_system=None, force_terminal=False)

    assert emit_error(
        "invalid_input",
        "Bad value",
        console=console,
        exit_code=2,
        json_output=True,
    ) == 2
    assert json.loads(console.file.getvalue()) == {
        "schema_version": 1,
        "ok": False,
        "error": {"code": "invalid_input", "message": "Bad value"},
    }


def test_read_stdin_is_bounded_and_removes_one_line_ending():
    assert read_stdin(stream=io.StringIO("secret\r\n")) == "secret"
    with pytest.raises(ValueError, match="byte limit"):
        read_stdin(stream=io.StringIO("abcd"), limit=3)


def test_read_secret_requires_an_explicit_mode():
    with pytest.raises(ValueError, match="requires"):
        read_secret("Secret: ")
    with pytest.raises(ValueError, match="only one"):
        read_secret("Secret: ", prompt_input=True, stdin_input=True)


def test_read_secret_supports_bounded_stdin():
    assert read_secret("Secret: ", stdin_input=True, stream=io.StringIO("value\n")) == "value"


def test_output_options_defaults_are_safe():
    options = OutputOptions()
    assert options.json_output is False
    assert options.quiet is False
    assert options.verbose is False
    assert options.no_color is False
    assert options.json_lines is False
