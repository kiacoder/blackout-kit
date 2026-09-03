with open("blackoutkit/typer_cli.py", "r") as f:
    code = f.read()

yara_cmd = '''
@tools_app.command("scan-yara")
def tools_scan_yara(
    path: str = typer.Argument(..., help="Path to local file to scan with YARA rules engine"),
):
    """🔒 YARA Rules Engine (scan file against malware & webshell byte signatures)."""
    from .tools import scan_file_yara
    res = scan_file_yara(path)
    if not res["ok"]:
        console.print(f"[error]YARA scan error: {res.get('error')}[/error]")
        return
    if res["clean"]:
        console.print(f"[success]✓ YARA Scan Clean: No signature threats found in {path}[/success]")
    else:
        console.print(f"[bold red]⚠️ YARA THREAT MATCHES DETECTED in {path}:[/bold red]")
        for m in res["matches"]:
            console.print(f"  • Matched Rule: [bold]{m['rule']}[/bold]")
'''

if 'def tools_scan_yara(' not in code:
    code += "\n" + yara_cmd
    with open("blackoutkit/typer_cli.py", "w") as f:
        f.write(code)
    print("Added tools_scan_yara to blackoutkit/typer_cli.py")
