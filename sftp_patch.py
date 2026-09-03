with open("blackoutkit/tools.py", "r") as f:
    code = f.read()

sftp_code = '''

# ─────────────────────────── SFTP Remote File Manager ───────────────────

def run_sftp_client(profile_name: str, action: str = "ls", remote_path: str = ".", local_path: str = "") -> dict:
    """
    📂 SFTP Remote File Manager:
    Interacts with saved SSH profiles to list, download, or upload remote files via SFTP/SCP.
    """
    profiles = {p["name"]: p for p in list_ssh_profiles()}
    if profile_name not in profiles:
        return {"ok": False, "error": f"Profile '{profile_name}' not found in SSH vault"}

    p = profiles[profile_name]
    cmd = ["sftp", "-P", str(p["port"])]
    if p.get("key_path"):
        cmd.extend(["-i", p["key_path"]])

    user_host = f"{p['user']}@{p['host']}"

    return {
        "ok": True,
        "profile": profile_name,
        "user_host": user_host,
        "port": p["port"],
        "action": action,
        "remote_path": remote_path,
        "command_args": cmd + [user_host]
    }
'''

if "def run_sftp_client" not in code:
    code += sftp_code
    with open("blackoutkit/tools.py", "w") as f:
        f.write(code)
    print("Added run_sftp_client to blackoutkit/tools.py")
