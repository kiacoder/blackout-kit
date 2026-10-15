"""Phase 8 — plugin system (blackoutkit.plugins)."""
from __future__ import annotations

from pathlib import Path

import pytest

from blackoutkit.plugins import (
    AnalyzerPlugin,
    ExporterPlugin,
    PluginError,
    PluginManager,
    PluginMetadata,
    RulePlugin,
)

RULE_SRC = '''
from blackoutkit.plugins import PluginMetadata, RulePlugin

class BigUpload(RulePlugin):
    metadata = PluginMetadata(name="big-upload", kind="rule", version="1.0",
                              description="flag big uploads")
    def evaluate(self, context):
        n = context.get("bytes_sent", 0)
        return [{"id": "big-upload", "severity": "medium", "message": str(n)}] if n > 100 else []
'''

ANALYZER_SRC = '''
from blackoutkit.plugins import PluginMetadata, AnalyzerPlugin

class Counter(AnalyzerPlugin):
    metadata = PluginMetadata(name="counter", kind="analyzer")
    def analyze(self, records):
        return {"count": len(records)}
'''

EXPORTER_SRC = '''
from blackoutkit.plugins import PluginMetadata, ExporterPlugin

class Txt(ExporterPlugin):
    metadata = PluginMetadata(name="txt", kind="exporter")
    def export(self, report, output):
        from pathlib import Path
        output = Path(output)
        output.write_text(str(report), encoding="utf-8")
        return output
'''

BROKEN_SRC = "raise RuntimeError('boom at import')\n"

EXPLICIT_SRC = '''
from blackoutkit.plugins import PluginMetadata, RulePlugin

class R(RulePlugin):
    metadata = PluginMetadata(name="explicit", kind="rule")
    def evaluate(self, context):
        return []

PLUGIN = R()
'''

NOMETA_SRC = '''
from blackoutkit.plugins import RulePlugin

class Bad(RulePlugin):
    def evaluate(self, context):
        return []
'''


def _write(tmp_path: Path, name: str, src: str) -> None:
    (tmp_path / name).write_text(src, encoding="utf-8")


def _manager(tmp_path: Path) -> PluginManager:
    return PluginManager(tmp_path, enabled=True)


# ── gating ───────────────────────────────────────────────────────────────────

def test_disabled_by_default(tmp_path):
    _write(tmp_path, "rule.py", RULE_SRC)
    mgr = PluginManager(tmp_path)  # no override -> reads plugins_enabled (default off)
    assert mgr.list() == []
    with pytest.raises(PluginError):
        mgr.get("big-upload")


def test_enabled_via_setting(tmp_path, monkeypatch):
    import blackoutkit.settings as cfg

    _write(tmp_path, "rule.py", RULE_SRC)
    monkeypatch.setattr(cfg, "load", lambda: {"plugins_enabled": True})
    mgr = PluginManager(tmp_path)
    assert [m.name for m in mgr.list()] == ["big-upload"]


# ── discovery ────────────────────────────────────────────────────────────────

def test_discovers_rule_plugin(tmp_path):
    _write(tmp_path, "rule.py", RULE_SRC)
    metas = _manager(tmp_path).list()
    assert len(metas) == 1
    assert metas[0].name == "big-upload"
    assert metas[0].kind == "rule"


def test_discovers_all_kinds(tmp_path):
    _write(tmp_path, "r.py", RULE_SRC)
    _write(tmp_path, "a.py", ANALYZER_SRC)
    _write(tmp_path, "e.py", EXPORTER_SRC)
    mgr = _manager(tmp_path)
    assert {m.kind for m in mgr.list()} == {"rule", "analyzer", "exporter"}
    assert [m.name for m in mgr.by_kind("analyzer")] == ["counter"]


def test_explicit_plugin_instance(tmp_path):
    _write(tmp_path, "x.py", EXPLICIT_SRC)
    assert [m.name for m in _manager(tmp_path).list()] == ["explicit"]


def test_broken_plugin_is_isolated(tmp_path):
    _write(tmp_path, "broken.py", BROKEN_SRC)
    _write(tmp_path, "rule.py", RULE_SRC)
    mgr = _manager(tmp_path)
    assert [m.name for m in mgr.list()] == ["big-upload"]  # good one still loads
    assert "broken.py" in mgr.errors
    assert "boom" in mgr.errors["broken.py"]


def test_missing_metadata_is_an_error(tmp_path):
    _write(tmp_path, "nometa.py", NOMETA_SRC)
    mgr = _manager(tmp_path)
    assert mgr.list() == []
    assert "nometa.py" in mgr.errors


def test_duplicate_name_keeps_first(tmp_path):
    _write(tmp_path, "a_first.py", RULE_SRC)
    _write(tmp_path, "b_second.py", RULE_SRC)
    mgr = _manager(tmp_path)
    assert [m.name for m in mgr.list()] == ["big-upload"]
    # both parsed but only one kept
    assert len(mgr._plugins) == 1


# ── runners ──────────────────────────────────────────────────────────────────

def test_run_rule(tmp_path):
    _write(tmp_path, "rule.py", RULE_SRC)
    mgr = _manager(tmp_path)
    assert mgr.run_rule("big-upload", {"bytes_sent": 500})[0]["id"] == "big-upload"
    assert mgr.run_rule("big-upload", {"bytes_sent": 1}) == []


def test_run_rules_tags_findings(tmp_path):
    _write(tmp_path, "rule.py", RULE_SRC)
    out = _manager(tmp_path).run_rules({"bytes_sent": 500})
    assert out[0]["plugin"] == "big-upload"


def test_run_analyzer(tmp_path):
    _write(tmp_path, "a.py", ANALYZER_SRC)
    assert _manager(tmp_path).run_analyzer("counter", [1, 2, 3]) == {"count": 3}


def test_run_exporter(tmp_path):
    _write(tmp_path, "e.py", EXPORTER_SRC)
    out = _manager(tmp_path).run_exporter("txt", {"a": 1}, tmp_path / "out.txt")
    assert out.read_text(encoding="utf-8") == "{'a': 1}"


def test_run_wrong_kind_raises(tmp_path):
    _write(tmp_path, "a.py", ANALYZER_SRC)
    with pytest.raises(PluginError):
        _manager(tmp_path).run_rule("counter", {})


def test_get_unknown_raises(tmp_path):
    with pytest.raises(PluginError):
        _manager(tmp_path).get("nope")


def test_metadata_is_frozen():
    m = PluginMetadata(name="x", kind="rule")
    with pytest.raises(Exception):
        m.name = "y"  # type: ignore[misc]
