from blackoutkit.policy_engine import (
    PolicyEngine,
    publish_policy_version,
    get_active_policy_config,
    lock_policy_settings,
    apply_locked_policy_overrides,
    create_automation_rule,
)

def test_config_versioning_and_rollback(tmp_path):
    engine = PolicyEngine(policy_dir=tmp_path)

    # Publish v1
    v1 = engine.publish_config_version("v1.0", {"dns": "1.1.1.1", "split": False})
    assert v1["version"] == "v1.0"

    # Publish v2
    v2 = engine.publish_config_version("v2.0", {"dns": "8.8.8.8", "split": True})
    latest = engine.get_latest_config()
    assert latest["version"] == "v2.0"
    assert latest["config"]["dns"] == "8.8.8.8"

    # Rollback to v1
    rb = engine.rollback_config("v1.0")
    assert rb is not None
    assert "v1.0-rollback" in rb["version"]
    assert engine.get_latest_config()["config"]["dns"] == "1.1.1.1"

def test_locked_settings_enforcement(tmp_path):
    engine = PolicyEngine(policy_dir=tmp_path)
    engine.set_locked_settings({"force_encryption": True, "blocked_protocols": ["P2P"]})

    user_cfg = {"dns": "1.1.1.1", "force_encryption": False, "custom_setting": "hello"}
    enforced = engine.enforce_locked_settings(user_cfg)

    assert enforced["force_encryption"] is True  # Admin override
    assert enforced["dns"] == "1.1.1.1"
    assert enforced["custom_setting"] == "hello"

def test_automation_rules(tmp_path):
    engine = PolicyEngine(policy_dir=tmp_path)
    rule = engine.add_automation_rule(
        rule_id="rule-01",
        trigger="BANDWIDTH_EXCEEDED_1GB",
        action="ALERT_ADMIN",
    )
    assert rule["rule_id"] == "rule-01"

    rules = engine.list_automation_rules()
    assert len(rules) == 1

def test_policy_engine_helpers():
    pub = publish_policy_version("v1.1-helper", {"mode": "auto"})
    assert pub["version"] == "v1.1-helper"

    active = get_active_policy_config()
    assert active is not None

    locked = lock_policy_settings({"admin_lock": True})
    assert locked["admin_lock"] is True

    overridden = apply_locked_policy_overrides({"admin_lock": False, "user_opt": 1})
    assert overridden["admin_lock"] is True

    rule = create_automation_rule("rule-helper", "THREAT_DETECTED", "AUTO_BLOCK")
    assert rule["rule_id"] == "rule-helper"
