from blackoutkit.rbac import (
    RBACManager,
    create_org,
    create_team_member,
    authenticate_token,
    check_role_permission,
)

def test_rbac_org_and_users(tmp_path):
    db_url = f"sqlite:///{tmp_path / 'test_rbac.db'}"
    rbac = RBACManager(db_url=db_url)

    org = rbac.create_organization("org-acme", "Acme Cyber Security")
    assert org["org_id"] == "org-acme"

    user = rbac.create_user("usr-alice", "alice@acme.com", "org-acme", role="Owner")
    assert user["role"] == "Owner"

    # Token issuance and verification
    token = rbac.issue_jwt_token("usr-alice")
    assert isinstance(token, str)

    payload = rbac.verify_jwt_token(token)
    assert payload is not None
    assert payload["sub"] == "usr-alice"
    assert payload["role"] == "Owner"

def test_role_permissions_matrix():
    assert check_role_permission("Owner", "anything") is True
    assert check_role_permission("Admin", "manage_users") is True
    assert check_role_permission("Admin", "delete_organization") is False
    assert check_role_permission("Member", "view_reports") is True
    assert check_role_permission("Member", "update_policies") is False

def test_rbac_helpers(tmp_path):
    org = create_org("org-default", "Default Org")
    assert org["org_id"] == "org-default"

    mem = create_team_member("usr-bob", "bob@default.com", "org-default", role="Admin")
    assert mem["role"] == "Admin"
