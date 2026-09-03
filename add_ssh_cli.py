with open("blackoutkit/typer_cli.py", "r") as f:
    code = f.read()

ssh_cli_code = '''
# ── SSH GROUP ──
ssh_app = typer.Typer(help="SSH Vault & Manager (manage and connect to SSH servers)", no_args_is_help=False)
app.add_typer(ssh_app, name="ssh")

@ssh_app.command("add")
def ssh_add(
    name: str = typer.Argument(..., help="Profile alias name (e.g. prod-server)"),
    host: str = typer.Option(..., "--host", "-h", help="Hostname or IP address"),
    user: str = typer.Option("root", "--user", "-u", help="SSH username (default: root)"),
    port: int = typer.Option(22, "--port", "-p", help="SSH port (default: 22)"),
    key: str = typer.Option("", "--key", "-k", help="Optional private key file path"),
):
    """Add or update an SSH connection profile in the vault."""
    from .tools import save_ssh_profile
    if save_ssh_profile(name, host, user, port, key):
        console.print(f"[success]✓ SSH profile '{name}' saved to vault![/success]")
    else:
        console.print(f"[error]Failed to save SSH profile '{name}'[/error]")

@ssh_app.command("list")
def ssh_list():
    """List all saved SSH profiles."""
    from .tools import list_ssh_profiles
    profiles = list_ssh_profiles()
    if not profiles:
        console.print("[muted]No SSH profiles saved in vault. Use `blackout ssh add` to add one.[/muted]")
        return
    table = make_table(
        "Saved SSH Vault Profiles",
        [("Name", "bold cyan"), ("User@Host", "bold white"), ("Port", "yellow"), ("Key Path", "dim")],
        [],
    )
    for p in profiles:
        table.add_row(p["name"], f"{p['user']}@{p['host']}", str(p["port"]), p.get("key_path") or "default")
    console.print(table)

@ssh_app.command("connect")
def ssh_connect(
    name: str = typer.Argument(..., help="SSH profile name to connect to"),
):
    """Connect to a saved SSH profile using system ssh client."""
    import subprocess
    from .tools import list_ssh_profiles
    profiles = {p["name"]: p for p in list_ssh_profiles()}
    if name not in profiles:
        console.print(f"[error]SSH profile '{name}' not found in vault.[/error]")
        return
    p = profiles[name]
    cmd = ["ssh", f"{p['user']}@{p['host']}", "-p", str(p["port"])]
    if p.get("key_path"):
        cmd.extend(["-i", p["key_path"]])
    console.print(f"[info]Connecting to {p['name']} ({p['user']}@{p['host']}:{p['port']})...[/info]")
    try:
        subprocess.run(cmd)
    except Exception as exc:
        console.print(f"[error]Failed to launch SSH client: {exc}[/error]")

@ssh_app.command("remove")
def ssh_remove(
    name: str = typer.Argument(..., help="SSH profile name to remove"),
):
    """Remove a saved SSH profile from vault."""
    from .tools import remove_ssh_profile
    if remove_ssh_profile(name):
        console.print(f"[success]✓ Removed SSH profile '{name}' from vault.[/success]")
    else:
        console.print(f"[error]SSH profile '{name}' not found in vault.[/error]")
'''

if 'ssh_app = typer.Typer' not in code:
    code += "\n" + ssh_cli_code
    with open("blackoutkit/typer_cli.py", "w") as f:
        f.write(code)
    print("Added ssh_app to blackoutkit/typer_cli.py")
