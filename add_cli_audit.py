with open("blackoutkit/typer_cli.py", "r") as f:
    code = f.read()

audit_cmd = '''
@tools_app.command("audit")
def tools_audit():
    """🛡️ Run a security hardening audit (scans open ports, DNS, cleartext services, killswitch)."""
    from .tools import run_network_audit

    console.print("[bold cyan]🛡️ Running Network Hardening Audit...[/bold cyan]\\n")
    report = run_network_audit()

    score = report["score"]
    grade = report["grade"]
    score_color = "green" if score >= 80 else "yellow" if score >= 60 else "red"

    console.print(f"Overall Security Posture Score: [{score_color}][bold]{score}/100 ({grade})[/bold][/{score_color}]\\n")

    table = make_table(
        "Security Audit Findings",
        [("Category", "cyan"), ("Status", ""), ("Summary", "bold white"), ("Recommendation", "dim")],
        [],
    )

    for f in report["findings"]:
        status = "[success]✓ PASS[/success]" if f["ok"] else f"[error]⚠ {f['severity']}[/error]"
        table.add_row(f["category"], status, f["summary"], f["recommendation"])

    console.print(table)
'''

if 'def tools_audit():' not in code:
    code += "\n" + audit_cmd
    with open("blackoutkit/typer_cli.py", "w") as f:
        f.write(code)
    print("Added tools_audit to blackoutkit/typer_cli.py")
