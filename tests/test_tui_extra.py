"""The [tui] extra must exist and pin textual with a security floor."""
import tomllib
from pathlib import Path


def test_tui_extra_declares_textual_floor():
    data = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    extras = data["project"]["optional-dependencies"]
    assert "tui" in extras, "missing [tui] optional extra"
    assert any(d.startswith("textual>=") for d in extras["tui"]), extras["tui"]


def test_tui_extra_included_in_all():
    data = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    extras = data["project"]["optional-dependencies"]
    assert any(d.startswith("textual>=") for d in extras["all"]), "textual missing from [all]"


def test_security_md_documents_textual():
    text = Path("SECURITY.md").read_text(encoding="utf-8")
    assert "textual" in text.lower(), "SECURITY.md dependency table must document textual"
