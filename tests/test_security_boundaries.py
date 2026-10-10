"""Negative security-boundary tests — the controls must fail closed.

Feature modules cover the happy path. This file covers the opposite direction:
the credential that must be refused, the secret that must never be written, the
listener that must not reach the LAN, the download that must be deleted when its
hash does not match, and the workflow that must attest what it built.

Every boundary test carries a control case beside it: if a defence is removed or
widened by accident, something here fails instead of passing silently.

The fixtures fabricate credential-shaped *keys* (that is what redaction is
supposed to react to) but never a credential-shaped value in a real format, and
no test in this file opens a routable socket — the listener checks intercept
`bind()`.
"""
import inspect
import io
import json
import logging
import os
import re
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from blackoutkit import log_redaction, mcp_server as mcp, recovery_audit, settings
from blackoutkit import support_bundle
from blackoutkit import tools as net_tools
from blackoutkit.events import _SECRET_URI_SCHEMES

ROOT = Path(__file__).resolve().parents[1]
INSTALL_PS1 = ROOT / "install.ps1"
BUILD_YML = ROOT / ".github" / "workflows" / "build.yml"

# Fixture material, not credentials. Values are assembled at runtime so this file
# carries nothing a secret scanner can match.
_FIXTURE_ALPHA = "fixture-" + "alpha-1f4b"
_FIXTURE_BETA = "fixture-" + "beta-9c27"
_FIXTURE_GAMMA = "fixture-" + "gamma-77e0"
_FIXTURE_DELTA = "fixture-" + "delta-31aa"
_REDACTION_MARKER = log_redaction.REDACTED  # "[redacted]"; upper() is "[REDACTED]"


# ══════════════════════════ 1. MCP authorization ══════════════════════════

_FAKE_MCP_SECRET = "boundary-" + "mcp-fixture-secret"

# (label, tool, arguments, subroutine that must never run)
_MCP_PRIVILEGED_CALLS = [
    ("tun-connect", "blackout_connect", {"engine": "tun"}, "blackoutkit.daemon.start"),
    ("emergency", "blackout_emergency", {}, "blackoutkit.daemon.start"),
    ("disconnect", "blackout_disconnect", {}, "blackoutkit.daemon.stop"),
    ("dns-set", "blackout_net_tools", {"tool": "dns-set", "arg": "1.1.1.1"}, "blackoutkit.tools.set_dns"),
    ("dns-flush", "blackout_net_tools", {"tool": "dns-flush"}, "blackoutkit.tools.flush_dns"),
    ("hotspot", "blackout_net_tools", {"tool": "hotspot", "arg": "on"}, "blackoutkit.tools.toggle_hotspot"),
    ("netfix", "blackout_net_tools", {"tool": "netfix"}, "blackoutkit.tools.run_network_recovery"),
    ("settings-set", "blackout_settings", {"action": "set", "key": "kill_switch", "value": "false"}, "blackoutkit.settings.set_value"),
    ("settings-reset", "blackout_settings", {"action": "reset"}, "blackoutkit.settings.reset"),
    ("config-add", "blackout_config", {"action": "add", "uri": "vless://fixture@host:443"}, "blackoutkit.config.manager.add_config"),
    ("config-import", "blackout_config", {"action": "import", "url": "https://example.invalid/sub"}, "blackoutkit.config.manager.import_and_merge"),
    ("config-remove", "blackout_config", {"action": "remove", "index": 1}, "blackoutkit.config.manager.remove_config"),
    ("split-tunnel-add", "blackout_split_tunnel", {"action": "add", "target": "10.0.0.0/8"}, "blackoutkit.split_tunnel.add_direct_route"),
    ("security-mode", "blackout_security_mode", {"mode": "private"}, "blackoutkit.security.apply_mode"),
]

# The three shapes an unauthorized caller actually presents: a wrong value, an
# empty value, and no value at all (`None` == the argument is absent).
_INVALID_TOKENS = [
    ("wrong-token", "wrong-" + "token-value"),
    ("empty-token", ""),
    ("absent-token", None),
]


@pytest.fixture
def mcp_gate_enabled(monkeypatch):
    """The production gate: enabled, with a secret configured on the server."""
    monkeypatch.setattr(mcp, "_MCP_AUTH_ENABLED", True)
    monkeypatch.setenv("BLACKOUT_MCP_TOKEN", _FAKE_MCP_SECRET)
    monkeypatch.delenv("BLACKOUT_MCP_SECRET", raising=False)


def _dispatch(tool: str, args: dict, target: str, *, returned: object = "dispatched"):
    """Run one MCP tool call with its privileged subroutine mocked.

    Returns the tool's text result and the subroutine mock, so a test can assert
    both the denial and the absence of any side effect. The stub returns a plain
    string: a fail-open regression then surfaces as text that does not start with
    the denial prefix, instead of a MagicMock absorbing the assertion.
    """
    with patch(target, return_value=returned) as subroutine, \
         patch("blackoutkit.readiness.evaluate", return_value=[]), \
         patch("blackoutkit.readiness.as_dicts", return_value=[]):
        result = mcp.handle_tool_call(tool, dict(args))
    return result, subroutine


@pytest.mark.parametrize("label, tool, args, target", _MCP_PRIVILEGED_CALLS,
                         ids=[case[0] for case in _MCP_PRIVILEGED_CALLS])
def test_mcp_unauthorized_token_rejected(mcp_gate_enabled, label, tool, args, target):
    """A privileged MCP call without the server's token is refused and runs nothing."""
    for token_label, token in _INVALID_TOKENS:
        call_args = dict(args)
        if token is not None:
            call_args["auth_token"] = token

        result, subroutine = _dispatch(tool, call_args, target)

        assert subroutine.call_count == 0, (
            f"{label}/{token_label}: {tool} executed a privileged subroutine with an "
            "unauthorized token — the authorization gate failed open"
        )
        assert result.startswith("Error: Access denied."), (
            f"{label}/{token_label}: expected an authorization denial, got {result!r}"
        )
        # The denial is a failure to clients that read structure, not prose.
        assert mcp.call_failed(result) is True
        # A denial must neither confirm nor deny a guess about the real secret.
        assert _FAKE_MCP_SECRET not in result
        if token:
            assert token not in result, "the denial echoed the presented token"


def test_mcp_authorized_token_runs_exactly_once(mcp_gate_enabled):
    """Control case: the correct token runs the subroutine once, and only once."""
    result, subroutine = _dispatch(
        "blackout_net_tools",
        {"tool": "hotspot", "arg": "on", "auth_token": _FAKE_MCP_SECRET},
        "blackoutkit.tools.toggle_hotspot",
    )
    # Exactly one privileged subroutine, no more: the gate lets the call through,
    # it does not fan it out.
    subroutine.assert_called_once()
    assert not result.startswith("Error: Access denied")


def test_mcp_read_only_operations_stay_open(mcp_gate_enabled):
    """The gate is scoped to state change; reads need no token."""
    for tool, args, target, returned in (
        ("blackout_settings", {"action": "list"}, "blackoutkit.settings.load", {}),
        ("blackout_config", {"action": "list"}, "blackoutkit.config.manager.load_configs", []),
        ("blackout_net_tools", {"tool": "dns-bench"}, "blackoutkit.tools.benchmark_dns", {}),
    ):
        with patch(target, return_value=returned) as subroutine:
            result = mcp.handle_tool_call(tool, dict(args))
        subroutine.assert_called_once()
        assert not result.startswith("Error: Access denied")


def test_mcp_fails_closed_with_no_server_secret(monkeypatch):
    """An unconfigured secret denies even the right-shaped token."""
    monkeypatch.setattr(mcp, "_MCP_AUTH_ENABLED", True)
    monkeypatch.delenv("BLACKOUT_MCP_TOKEN", raising=False)
    monkeypatch.delenv("BLACKOUT_MCP_SECRET", raising=False)
    result, subroutine = _dispatch(
        "blackout_net_tools",
        {"tool": "dns-set", "arg": "1.1.1.1", "auth_token": _FAKE_MCP_SECRET},
        "blackoutkit.tools.set_dns",
    )
    subroutine.assert_not_called()
    assert result.startswith("Error: Access denied.")
    assert "BLACKOUT_MCP_TOKEN" in result


def _stdio_call(arguments: dict) -> tuple[dict, object]:
    """Drive one `tools/call` through the real stdio loop, return (response, mock)."""
    request = {
        "jsonrpc": "2.0", "id": 11, "method": "tools/call",
        "params": {"name": "blackout_net_tools", "arguments": arguments},
    }
    stdout = io.StringIO()
    with patch.object(mcp, "real_stdin", io.StringIO(json.dumps(request) + "\n")), \
         patch.object(mcp, "real_stdout", stdout), \
         patch("blackoutkit.tools.toggle_hotspot", return_value="Hotspot on") as hotspot:
        mcp.run_mcp_server()
        response = json.loads(stdout.getvalue())
    return response, hotspot


@pytest.mark.parametrize("token_label, token", _INVALID_TOKENS,
                         ids=[case[0] for case in _INVALID_TOKENS])
def test_mcp_denial_is_a_failure_in_the_jsonrpc_envelope(mcp_gate_enabled, token_label, token):
    """The stdio layer marks a denial `isError` — the envelope's `ok: false`."""
    arguments = {"tool": "hotspot", "arg": "on"}
    if token is not None:
        arguments["auth_token"] = token

    response, hotspot = _stdio_call(arguments)

    hotspot.assert_not_called()
    assert response["id"] == 11
    assert response["result"]["isError"] is True, (
        f"{token_label}: a denial reached the client as a successful text result, "
        "so an agent could read a refused call as an executed one"
    )
    assert response["result"]["content"][0]["text"].startswith("Error: Access denied.")


def test_mcp_success_carries_no_error_flag(mcp_gate_enabled):
    """Control case: an authorized call is not reported as an error."""
    response, hotspot = _stdio_call(
        {"tool": "hotspot", "arg": "on", "auth_token": _FAKE_MCP_SECRET}
    )
    hotspot.assert_called_once()
    assert "isError" not in response["result"]
    assert response["result"]["content"][0]["text"] == "Hotspot on"


# ═══════════════════ 2. Credential redaction in logs and bundles ══════════

def _samples():
    """Log lines an engine might really write, each carrying one fixture secret."""
    bearer = "eyJhbGciOiJIUzI1" + "NiJ9.eyJzdWIiOiJmaXh0dXJlIn0.signature"
    return [
        ("dsn-userinfo", f"connecting postgres://svc:{_FIXTURE_ALPHA}@db.internal:5432/analytics", _FIXTURE_ALPHA),
        ("socks-userinfo", f"peer chain socks5://bob:{_FIXTURE_BETA}@10.0.0.5:1080 ready", _FIXTURE_BETA),
        ("bearer-header", f"2026-10-09 10:11:12 [ERROR] relay rejected Authorization: Bearer {bearer} after 3 retries", bearer),
        ("key-value-tail", f"startup ok  passphrase = {_FIXTURE_GAMMA}; continuing boot", _FIXTURE_GAMMA),
        ("api-key", f"GET https://api.example.invalid/v1 api_key={_FIXTURE_DELTA} returned 401", _FIXTURE_DELTA),
        ("uri-scheme-line", f"added config: vless://{_FIXTURE_ALPHA}@host.example:443?security=tls", _FIXTURE_ALPHA),
    ]


def _through_real_logging(record_message: str) -> str:
    """Format a record exactly as the daemon writes it, formatter included."""
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(log_redaction.RedactingFormatter(
        "%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"
    ))
    logger = logging.getLogger("blackout-test-redaction")
    handlers, propagate = logger.handlers, logger.propagate
    logger.handlers, logger.propagate = [handler], False
    logger.setLevel(logging.DEBUG)
    try:
        logger.info(record_message)
    finally:
        logger.handlers, logger.propagate = handlers, propagate
        handler.close()
    return stream.getvalue()


@pytest.mark.parametrize("label, line, secret", _samples(),
                         ids=[case[0] for case in _samples()])
def test_credential_redaction_in_logs_and_bundles(label, line, secret):
    """Plaintext credentials never survive into a log line or a support bundle."""
    assert secret in line, "broken fixture: the sample must contain the secret"

    # 1. the shared scrubber every log consumer reads through
    scrubbed = log_redaction.scrub_line(line)
    if scrubbed is None:
        # Removed whole rather than trimmed: this line carries a proxy/VPN URI,
        # whose embedded credential is the secret and whose host is infrastructure.
        assert any(scheme in line.lower() for scheme in _SECRET_URI_SCHEMES), (
            f"{label}: a line without a secret URI was dropped instead of redacted"
        )
    else:
        assert secret not in scrubbed, f"{label}: the secret survived log_redaction.scrub_line"
        assert _REDACTION_MARKER.upper() in scrubbed.upper(), (
            f"{label}: redacted output must carry the {_REDACTION_MARKER} marker"
        )

    # 2. the daemon's own formatter, at write time
    logged = _through_real_logging(line)
    assert secret not in logged, f"{label}: the secret reached the daemon log stream"
    if scrubbed is None:
        assert "://" not in logged, f"{label}: a dropped URI still reached the log stream"

    # 3. the exported support bundle
    with patch("blackoutkit.daemon.read_logs", return_value=line + "\nnormal line"):
        encoded = json.dumps(support_bundle.collect(), ensure_ascii=False)
    assert secret not in encoded, f"{label}: the secret reached the support bundle"

    # 4. the recovery audit trail, written from the same kind of step detail
    assert secret not in recovery_audit.redact(line), f"{label}: the secret reached recovery audit"

    # 5. and none of this is achieved by dropping the whole log tail
    assert "normal line" in encoded


def test_support_bundle_export_file_contains_no_plaintext_secret(tmp_path):
    """The file a user attaches to a bug report is as clean as the dict."""
    target = tmp_path / "bundle.json"
    leaked = "\n".join(line for _label, line, _secret in _samples())
    with patch("blackoutkit.daemon.read_logs", return_value=leaked), \
         patch("blackoutkit.settings.load", return_value={
             "security_mode": "SPEED",
             "ikev2_" + "password": _FIXTURE_ALPHA,
             "selected_engine": "sni",
         }):
        support_bundle.export_bundle(target)

    written = target.read_text(encoding="utf-8")
    for _label, _line, secret in _samples():
        assert secret not in written, "a fixture secret leaked into the exported bundle"
    assert _FIXTURE_ALPHA not in written
    assert "SPEED" in written, "non-sensitive settings must survive redaction"
    # The bundle documents the marker it applied and that nothing was uploaded.
    payload = json.loads(written)
    assert payload["redaction_policy"]["marker"] == _REDACTION_MARKER
    assert payload["uploaded"] is False


def test_redaction_marker_is_one_value_across_surfaces():
    """Events, logs, and bundles must not disagree about the marker string."""
    from blackoutkit import events

    assert events.REDACTED == log_redaction.REDACTED == support_bundle.REDACTED
    assert events.REDACTED.upper() == "[REDACTED]"


def test_redaction_keeps_ordinary_log_lines_intact():
    """Control case: scrubbing must not be a sledgehammer."""
    benign = "Daemon starting (PID 1234). Engine: warp on port 40000"
    assert log_redaction.scrub_line(benign) == benign
    assert benign in _through_real_logging(benign)


def test_daemon_writes_redacted_logs_at_write_time():
    """Both daemon entrypoints install the redacting formatter, not a plain one."""
    for relative in ("blackoutkit/daemon.py", "blackoutkit/daemon/__init__.py"):
        source = (ROOT / relative).read_text(encoding="utf-8")
        assert "RedactingFormatter" in source, f"{relative} lost its redacting formatter"


# ═══════════════════════ 3. Default binds never expose the LAN ═════════════

LOOPBACK = "127.0.0.1"
WILDCARD = "0.0.0.0"


@pytest.fixture
def default_settings(monkeypatch):
    """Settings as a fresh install sees them; call with overrides to opt in."""
    def _apply(**overrides):
        values = dict(settings.DEFAULTS)
        values.update(overrides)
        monkeypatch.setattr(settings, "load", lambda: dict(values))
        return values
    return _apply


def test_default_binds_never_expose_lan(default_settings, tmp_path):
    """Every local listener Blackout starts by itself is loopback-only."""
    from blackoutkit.engines.neighbor import NeighborShareEngine
    from blackoutkit.engines.singbox_proxy import SingBoxProxyEngine
    from blackoutkit.engines.sni import SNIEngine
    from blackoutkit.engines.xray import XRayEngine

    default_settings()

    # Neighbor sharing: loopback until the operator opts into LAN exposure.
    neighbor = NeighborShareEngine()
    assert neighbor.bind_lan is False
    assert neighbor.bind_address == LOOPBACK
    assert neighbor.bind_address != WILDCARD

    # SNI spoofer: the config file handed to the native binary.
    sni = SNIEngine()
    sni._config_dir = tmp_path
    sni_config = json.loads(sni._write_config().read_text(encoding="utf-8"))
    assert sni_config["LISTEN_HOST"] == LOOPBACK
    assert sni._health_check_addr[0] == LOOPBACK

    # XRay inbound SOCKS/HTTP listeners.
    xray = XRayEngine(proxy_config=SimpleNamespace(
        protocol="vless", address="endpoint.example.invalid", port=443,
        sni="endpoint.example.invalid", name="fixture",
    ))
    with patch.object(xray, "_build_outbound", return_value={"tag": "proxy", "protocol": "vless"}):
        xray_inbounds = xray.generate_config()["inbounds"]
    assert xray_inbounds, "XRay must define its local listeners"
    assert {item["listen"] for item in xray_inbounds} == {LOOPBACK}

    # sing-box (Hysteria2 / TUIC) inbound SOCKS listener.
    singbox = SingBoxProxyEngine(proxy_config=SimpleNamespace(
        protocol="hysteria2", address="proxy.example.invalid", port=443,
        **{"pass" + "word": "fixture-" + "value"},
        uuid="", sni="proxy.example.invalid", insecure=False, alpn="",
    ))
    assert {item["listen"] for item in singbox._generate_config()["inbounds"]} == {LOOPBACK}
    assert singbox._health_check_addr[0] == LOOPBACK


def test_doh_proxy_defaults_to_loopback_and_refuses_wildcards(default_settings):
    """The DoH listener binds loopback, and a wildcard bind is refused outright."""
    default_settings()
    signature = inspect.signature(net_tools.run_doh_proxy_server)
    assert signature.parameters["host"].default == LOOPBACK
    assert net_tools.DOH_PROXY_DEFAULT_HOST == LOOPBACK
    assert net_tools.DOH_PROXY_ALLOWED_BINDS == frozenset({LOOPBACK, "::1"})

    binds: list[tuple[str, int]] = []

    class _RecordingSocket:
        def __init__(self, *_args, **_kwargs):
            pass

        def setsockopt(self, *_args, **_kwargs):
            return None

        def settimeout(self, *_args, **_kwargs):
            return None

        def bind(self, address):
            binds.append(tuple(address))

        def recvfrom(self, _size):
            raise TimeoutError

        def close(self):
            return None

    with patch.object(net_tools.socket, "socket", _RecordingSocket):
        net_tools.run_doh_proxy_server(duration=0.001)
        assert binds == [(LOOPBACK, net_tools.DOH_PROXY_DEFAULT_PORT)], binds
        binds.clear()
        for attempted in (WILDCARD, "::", "localhost", f"{WILDCARD}:5300", "10.1.2.3", ""):
            net_tools.run_doh_proxy_server(host=attempted, duration=0.001)
        assert binds == [], f"the DoH proxy bound a non-loopback address: {binds}"


def test_neighbor_lan_exposure_requires_explicit_opt_in(default_settings):
    """`0.0.0.0` appears only when the user turns LAN sharing on, and the native
    forwarder receives the same flag that the property reports, so the log line,
    the setting, and the listener cannot drift apart."""
    from blackoutkit.engines.neighbor import NeighborShareEngine

    default_settings(neighbor_bind_lan=True)
    opted_in = NeighborShareEngine()
    assert opted_in.bind_lan is True
    assert opted_in.bind_address == WILDCARD

    default_settings()
    assert NeighborShareEngine().bind_address == LOOPBACK


def test_local_http_surfaces_are_loopback_only():
    from blackoutkit import event_bridge

    assert event_bridge.DEFAULT_HOST == LOOPBACK
    assert inspect.signature(net_tools.run_web_api_dashboard).parameters["host"].default == LOOPBACK
    assert settings.DEFAULTS["proxy_host"] == LOOPBACK

    for refused in (WILDCARD, "0.0.0.0", "::"):
        with pytest.raises(ValueError):
            event_bridge.start_bridge(host=refused)


def test_settings_defaults_never_widen_a_bind():
    """No default setting points a listener at every interface.

    `adblock_sinkhole_ip` is the one DEFAULTS entry that names `0.0.0.0`: it is
    the address *returned* for a blocked domain (a null route for the resolver's
    answer), never an address Blackout binds. The carve-out is asserted rather
    than assumed, so a new bind widening still fails this test.
    """
    host_settings = {
        key: value for key, value in settings.DEFAULTS.items()
        if key.endswith(("_host", "_bind_host", "_listen_host"))
    }
    assert host_settings, "expected local host settings to exist"
    for key, value in host_settings.items():
        assert value in {LOOPBACK, "::1", ""}, f"{key} defaults to {value!r}"

    wildcards = {
        key: value for key, value in settings.DEFAULTS.items()
        if isinstance(value, str) and value.strip() == WILDCARD
    }
    assert set(wildcards) == {"adblock_sinkhole_ip"}, wildcards
    assert bool(settings.DEFAULTS["neighbor_bind_lan"]) is False


# ═══════════════════════ 4. Installer checksum abort logic ═════════════════

def _install_text() -> str:
    return INSTALL_PS1.read_text(encoding="utf-8")


def test_installer_checksum_abort_logic():
    """A SHA-256 mismatch deletes the staged download before anything can run it."""
    text = _install_text()

    # The abort helper is the single failure path, and it does both required
    # things: unlink the staged bytes, then exit non-zero.
    stop = re.search(r"function Stop-Install \{(.*?)\n\}", text, re.S)
    assert stop is not None, "install.ps1 lost its Stop-Install failure path"
    body = stop.group(1)
    assert "Remove-Item -LiteralPath $StagedPath -Force" in body
    assert "Remove-Item -LiteralPath $ChecksumPath -Force" in body
    assert re.search(r"^\s*exit 1\s*$", body, re.M), "Stop-Install must exit non-zero"

    # Order of operations: hash the staged bytes, detect the mismatch, delete the
    # staging area, and only then move anything into place — the verified file is
    # the only thing that can reach the install target.
    verify = text.index("Get-FileHash -LiteralPath $StagedPath")
    mismatch = text.index("SHA-256 mismatch")
    remove = text.index("Remove-Item -LiteralPath $ChecksumPath", verify)
    move = text.index("Move-Item -LiteralPath $StagedPath")
    run_doctor = text.index("& $ExePath doctor")
    assert verify < mismatch < remove < move < run_doctor

    # Every way the checksum can be wrong ends in the same abort: a missing
    # checksum asset, an unparseable entry, and an actual mismatch.
    for guard in ("publishes no SHA-256 checksum", "missing, ambiguous, or malformed",
                  "SHA-256 mismatch"):
        assert guard in text, f"{guard!r} guard is gone from install.ps1"
        window = text[text.index(guard):text.index(guard) + 400]
        assert "Stop-Install" in window, f"{guard!r} no longer aborts the install"


def test_python_updater_rejects_a_digest_mismatch_and_removes_the_staged_file(tmp_path, monkeypatch):
    """The in-app updater holds the same contract as install.ps1: abort, unlink,
    and never replace a working install."""

    class _StagedFile:
        """NamedTemporaryFile stand-in that records the path it vouches for."""

        def __init__(self, path: Path):
            self.path = path

        def __enter__(self):
            self.path.write_bytes(b"")
            return self

        def __exit__(self, *_exc):
            return False

        @property
        def name(self) -> str:
            return str(self.path)

    staged_paths: list[Path] = []

    def _fake_tempfile(suffix: str = "", delete: bool = False, **_kwargs):
        path = tmp_path / f"staged{suffix}"
        staged_paths.append(path)
        return _StagedFile(path)

    body = b"payload-that-does-not-match-the-published-digest"
    asset = {
        "name": "blackout-source.zip",
        "browser_download_url": "https://github.com/kiacoder/blackout-kit/releases/download/v2.0.0/blackout-source.zip",
        "size": len(body),
        "digest": "sha256:" + "0" * 64,  # well formed, deliberately the wrong digest
    }
    release = {
        "tag_name": "v2.0.0", "assets": [asset], "source_asset": asset,
        "zipball_url": asset["browser_download_url"],
    }

    package = tmp_path / "blackoutkit"
    package.mkdir()
    marker = package / "marker.py"
    marker.write_text("old\n", encoding="utf-8")
    monkeypatch.setattr("blackoutkit.updater.PROJECT_ROOT", tmp_path)
    monkeypatch.setattr("blackoutkit.updater.APP_DATA_DIR", tmp_path / "app")
    monkeypatch.setattr("blackoutkit.updater.tempfile.NamedTemporaryFile", _fake_tempfile)

    class _Response(io.BytesIO):
        headers = {"Content-Length": str(len(body))}

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            self.close()

    monkeypatch.setattr(
        "blackoutkit.updater.urllib.request.urlopen",
        lambda *_args, **_kwargs: _Response(body),
    )

    from blackoutkit import downloader, updater

    assert updater.download_and_apply(release) is False, "a mismatched digest must abort"
    assert staged_paths, "the updater never staged a download; this test proves nothing"
    assert not staged_paths[-1].exists(), "the rejected download was left on disk"
    assert marker.read_text(encoding="utf-8") == "old\n", "a failed download reached the package"

    # The binary downloader returns the same verdict, so both install paths agree.
    staged = tmp_path / "staged.bin"
    staged.write_bytes(body)
    ok, message = downloader._verify_download_digest(staged, asset)
    assert ok is False
    assert "SHA-256" in message


_PWSH_HARNESS = r'''
$ErrorActionPreference = 'Stop'
$Mode = $args[0]
$Script = $args[1]
$Work = $args[2]

$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Script, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw 'install.ps1 does not parse' }

# Run the installer's own functions, extracted by the PowerShell parser, so this
# exercises shipped code rather than a paraphrase of it.
foreach ($name in @('Stop-Install', 'Get-ExpectedSha256')) {
    $found = $ast.FindAll({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true) | Select-Object -First 1
    if (-not $found) { throw "$name not found in install.ps1" }
    Invoke-Expression $found.Extent.Text
}

$StagedPath = Join-Path $Work 'blackout.exe.download'
$ChecksumPath = Join-Path $Work 'release-checksums.download'
Set-Content -LiteralPath $StagedPath -Value 'payload' -NoNewline
$actual = (Get-FileHash -LiteralPath $StagedPath -Algorithm SHA256).Hash

if ($Mode -eq 'mismatch') {
    Set-Content -LiteralPath $ChecksumPath -Value ("{0}  blackout.exe`n" -f ('f' * 64)) -NoNewline
} else {
    Set-Content -LiteralPath $ChecksumPath -Value ("{0}  blackout.exe`n" -f $actual.Trim().ToLowerInvariant()) -NoNewline
}

$text = Get-Content -LiteralPath $ChecksumPath -Raw
$expected = Get-ExpectedSha256 -Text $text -FileName 'blackout.exe'
if (-not $expected) {
    Stop-Install 'The release checksum for blackout.exe is missing, ambiguous, or malformed. The download was deleted.'
}
if (-not ($actual.Trim() -ieq $expected.Trim())) {
    Stop-Install ("SHA-256 mismatch for blackout.exe (expected {0}, got {1}). The download was deleted." -f $expected, $actual)
}
Write-Output ("VERIFIED " + $actual)
'''


@pytest.mark.skipif(
    shutil.which("pwsh") is None and not os.environ.get("CI"),
    reason="pwsh is not installed",
)
def test_installer_abort_unlinks_staged_download_and_exits_nonzero(tmp_path):
    """Behavioural proof of the same contract under PowerShell: mismatch →
    staged download removed, exit status 1."""
    if shutil.which("pwsh") is None:
        pytest.fail("pwsh must be installed on CI runners so install.ps1 is exercised")

    harness = tmp_path / "harness.ps1"
    harness.write_text(_PWSH_HARNESS, encoding="utf-8")
    env = {**os.environ, "POWERSHELL_TELEMETRY_OPTOUT": "1"}

    mismatch_dir = tmp_path / "mismatch"
    mismatch_dir.mkdir()
    aborted = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(harness), "mismatch",
         str(INSTALL_PS1), str(mismatch_dir)],
        capture_output=True, text=True, timeout=180, env=env,
    )
    assert aborted.returncode == 1, (
        "a checksum mismatch must abort with a non-zero exit code, got "
        f"{aborted.returncode}: {aborted.stdout}{aborted.stderr}"
    )
    assert "[ERROR] SHA-256 mismatch" in aborted.stdout
    assert not (mismatch_dir / "blackout.exe.download").exists(), \
        "the staged download survived the abort"
    assert not (mismatch_dir / "release-checksums.download").exists(), \
        "the staged checksum file survived the abort"

    # Control case: a matching digest keeps the staged file and exits 0, so the
    # assertions above are watching the mismatch path and not a broken harness.
    match_dir = tmp_path / "match"
    match_dir.mkdir()
    verified = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(harness), "match",
         str(INSTALL_PS1), str(match_dir)],
        capture_output=True, text=True, timeout=180, env=env,
    )
    assert verified.returncode == 0, verified.stdout + verified.stderr
    assert verified.stdout.startswith("VERIFIED")
    assert (match_dir / "blackout.exe.download").exists()


# ═══════════════════════ 5. Release provenance (CI) ════════════════════════

def _workflow():
    yaml = pytest.importorskip("yaml")
    return yaml.safe_load(BUILD_YML.read_text(encoding="utf-8"))


def _attest_steps(job: dict) -> list[dict]:
    return [step for step in job["steps"]
            if str(step.get("uses", "")).startswith("actions/attest-build-provenance@")]


@pytest.mark.parametrize("job_name", ["package-smoke", "build-windows", "build-linux", "release"])
def test_release_provenance_permissions_and_attestations(job_name):
    workflow = _workflow()
    job = workflow["jobs"][job_name]
    permissions = job.get("permissions", {})
    assert permissions.get("id-token") == "write", f"{job_name}: no OIDC token to sign with"
    assert permissions.get("attestations") == "write", f"{job_name}: cannot persist attestations"
    assert permissions.get("contents") in {"read", "write"}, f"{job_name}: unexpected contents scope"

    steps = _attest_steps(job)
    assert steps, f"{job_name}: built artifacts without attesting their provenance"
    for step in steps:
        # A fork pull request cannot mint an OIDC token, so the step is skipped
        # there — it must never be downgraded to "unsigned but green".
        assert "pull_request" in str(step.get("if", "")), (
            f"{job_name}: the attestation step is not gated off pull_request events"
        )
        assert str(step["with"]["subject-path"]).count("dist/") >= 1, (
            f"{job_name}: attestation names no dist/ subject"
        )


def test_release_job_attests_every_published_asset():
    workflow = _workflow()
    job = workflow["jobs"]["release"]
    assert job["permissions"]["contents"] == "write", "the release job cannot publish its assets"
    names = [step.get("name", "") for step in job["steps"]]
    attests = [step for step in job["steps"] if "Attest Build Provenance" in str(step.get("name", ""))]
    assert attests, "the release job publishes binaries with no provenance"

    subjects = str(attests[0]["with"]["subject-path"])
    for asset in ("dist/blackout.exe", "dist/checksums.txt",
                  "dist/blackout-engine-linux-amd64", "dist/blackout-source.zip",
                  "dist/blackout.exe.sha256"):
        assert asset in subjects, f"{asset} is published but never attested"

    # Provenance binds the exact bytes that get published: attest once the
    # checksums exist, before the release goes out.
    assert names.index("Generate and verify SHA-256 checksums") < names.index("Attest Build Provenance (Sigstore)")
    assert names.index("Attest Build Provenance (Sigstore)") < names.index("Create Release")

    publish = next(step for step in job["steps"] if step.get("name") == "Create Release")
    files = str(publish["with"]["files"])
    assert "dist/checksums.txt" in files
    assert "dist/blackout.exe.sha256" in files


# ═════════════════ 6. Packaging & dependency hygiene ══════════════════════

CHOCO_INSTALL = ROOT / "choco" / "tools" / "chocolateyinstall.ps1"

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib


def test_release_version_metadata_matches_package_version():
    from blackoutkit import __version__

    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert metadata["project"]["version"] == "1.3.0"
    assert __version__ == "1.3.0"


def test_choco_installer_checksum_is_parser_safe_and_fails_closed():
    """The Chocolatey digest is a well-formed SHA-256 literal (so linters and
    `choco pack` parse it) and it cannot install anything until it is real."""
    text = CHOCO_INSTALL.read_text(encoding="utf-8")
    # Windows PowerShell 5.1 reads BOM-less UTF-8 as Windows-1252.
    assert all(ord(char) < 128 for char in text), "chocolateyinstall.ps1 must stay ASCII"

    match = re.search(r"^\$checksum64\s*=\s*(.+)$", text, re.M)
    assert match, "chocolateyinstall.ps1 lost its checksum declaration"
    literal = match.group(1).strip()
    assert re.fullmatch(r"'0' \* 64|'[0-9a-f]{64}'", literal), (
        f"checksum64 must be 64 hexadecimal characters, got {literal!r}"
    )
    assert not re.search(r"\$checksum64\s*=\s*'[^']*[^0-9a-f'\s][^']*'", text), \
        "a non-hexadecimal digest slipped back into the choco script"

    # An operator-supplied digest is validated, not trusted, and the placeholder
    # aborts before any download happens.
    assert "^[0-9a-f]{64}$" in text
    guard = text.index("Refusing to install an unverified binary")
    assert guard < text.index("Get-ChocolateyWebFile"), \
        "the placeholder must abort before the download, not after"
    assert "-ChecksumType 'sha256'" in text


def test_declared_dependency_floors_match_the_sbom():
    """The published SBOM must record the same security floors an installer
    resolves, so the bill of materials cannot drift from the package metadata."""
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    sbom = json.loads((ROOT / "SBOM.json").read_text(encoding="utf-8"))
    recorded = {str(item["name"]).lower(): item["versionInfo"] for item in sbom["packages"]}
    pattern = re.compile(r"^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?>=(?P<floor>[0-9][0-9a-zA-Z.]*)")

    def floors(requirements):
        found = {}
        for item in requirements:
            match = pattern.match(item)
            assert match, f"dependency {item!r} is not a '>=' floor"
            found[match.group(1).lower()] = match.group("floor")
        return found

    runtime = floors(metadata["project"]["dependencies"])
    assert set(runtime) <= set(recorded), f"SBOM is missing {sorted(set(runtime) - set(recorded))}"
    for name, floor in runtime.items():
        assert recorded[name] == floor, f"SBOM records {name} {recorded[name]}, pyproject declares >={floor}"

    for name, floor in floors(metadata["build-system"]["requires"]).items():
        assert recorded.get(name) == floor, f"SBOM does not record the build floor for {name}"

    # Advisory-backed floors: these are the ones an external reviewer checks first.
    assert runtime["cryptography"] >= "50.0.0"
    assert runtime["certifi"] >= "2024.7.4"
    assert runtime["pyyaml"] >= "6.0.1"
    extras = metadata["project"]["optional-dependencies"]
    assert floors(extras["gui"])["pillow"] >= "12.3.0"
    assert floors(extras["media"])["yt-dlp"] >= "2026.7.4"
    # requests/urllib3 are not dependencies; the SBOM says so explicitly rather
    # than leaving a reviewer to wonder why their CVE floors are missing.
    assert "requests" not in runtime and "urllib3" not in runtime
    assert "requests" in sbom["creationInfo"]["comment"].lower()


def test_ci_parses_both_powershell_entry_points():
    """The Windows job must parse every PowerShell script that ships, not just the
    one that had the audited bug."""
    text = BUILD_YML.read_text(encoding="utf-8")
    assert "[System.Management.Automation.Language.Parser]::ParseFile" in text
    assert "choco/tools/chocolateyinstall.ps1" in text
