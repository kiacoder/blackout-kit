with open("blackoutkit/tools.py", "r") as f:
    code = f.read()

ssh_code = '''

# ─────────────────────────── SSH Vault & Manager ───────────────────

SSH_VAULT_FILE = APP_DATA_DIR / "ssh_vault.json"

def save_ssh_profile(name: str, host: str, user: str, port: int = 22, key_path: str = "") -> bool:
    """Save or update an SSH connection profile in local storage."""
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        profiles = json.loads(SSH_VAULT_FILE.read_text()) if SSH_VAULT_FILE.exists() else {}
    except Exception:
        profiles = {}

    profiles[name] = {
        "name": name,
        "host": host,
        "user": user,
        "port": port,
        "key_path": key_path,
        "created_at": time.time()
    }

    try:
        SSH_VAULT_FILE.write_text(json.dumps(profiles, indent=2))
        return True
    except Exception as exc:
        _log.error("Failed to save SSH profile %s: %s", name, exc)
        return False

def list_ssh_profiles() -> list[dict]:
    """List all saved SSH connection profiles."""
    try:
        if not SSH_VAULT_FILE.exists():
            return []
        profiles = json.loads(SSH_VAULT_FILE.read_text())
        return sorted(list(profiles.values()), key=lambda p: p["name"])
    except Exception:
        return []

def remove_ssh_profile(name: str) -> bool:
    """Remove a saved SSH profile by name."""
    try:
        if not SSH_VAULT_FILE.exists():
            return False
        profiles = json.loads(SSH_VAULT_FILE.read_text())
        if name in profiles:
            del profiles[name]
            SSH_VAULT_FILE.write_text(json.dumps(profiles, indent=2))
            return True
        return False
    except Exception:
        return False
'''

if "def save_ssh_profile" not in code:
    code += ssh_code
    with open("blackoutkit/tools.py", "w") as f:
        f.write(code)
    print("Added SSH Vault & Manager to blackoutkit/tools.py")
