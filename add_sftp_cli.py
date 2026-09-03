with open("blackoutkit/typer_cli.py", "r") as f:
    code = f.read()

sftp_cmd = '''
@ssh_app.command("sftp")
def ssh_sftp(
    name: str = typer.Argument(..., help="SSH profile name"),
    action: str = typer.Option("ls", "--action", "-a", help="ls | get | put"),
    remote: str = typer.Option(".", "--remote", "-r", help="Remote path"),
    local: str = typer.Option("", "--local", "-l", help="Local path for get/put"),
):
    """📂 SFTP Remote File Manager (browse, upload, or download remote files)."""
    import subprocess
    from .tools import run_sftp_client
    res = run_sftp_client(name, action=action, remote_path=remote, local_path=local)
    if not res["ok"]:
        console.print(f"[error]{res['error']}[/error]")
        return
    console.print(f"[info]Connecting to SFTP for {res['user_host']}...[/info]")
    try:
        subprocess.run(res["command_args"])
    except Exception as exc:
        console.print(f"[error]Failed to launch SFTP client: {exc}[/error]")
'''

if 'def ssh_sftp(' not in code:
    code += "\n" + sftp_cmd
    with open("blackoutkit/typer_cli.py", "w") as f:
        f.write(code)
    print("Added ssh_sftp to blackoutkit/typer_cli.py")
