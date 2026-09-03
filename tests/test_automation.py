import pytest
from blackoutkit.tools import (
    save_automation_rule,
    list_automation_rules,
    remove_automation_rule,
    trigger_automation_event,
)

def test_automation_rules():
    assert save_automation_rule("rule_test", "on_disconnect", "flush_dns")
    rules = list_automation_rules()
    assert any(r["name"] == "rule_test" for r in rules)
    r = next(r for r in rules if r["name"] == "rule_test")
    assert r["event"] == "on_disconnect"
    assert r["action"] == "flush_dns"

    results = trigger_automation_event("on_disconnect")
    assert len(results) >= 1
    matched = next(res for res in results if res["rule"] == "rule_test")
    assert matched["ok"] is True

    assert remove_automation_rule("rule_test")
    assert not any(r["name"] == "rule_test" for r in list_automation_rules())
