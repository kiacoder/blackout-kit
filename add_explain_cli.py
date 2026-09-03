with open("blackoutkit/typer_cli.py", "r") as f:
    code = f.read()

explain_cmd = '''
@tools_app.command("explain")
def tools_explain():
    """🤖 AI Network Explainer (reads live network state and summarizes anomalies)."""
    from .tools import explain_network_state

    console.print("[bold cyan]🤖 AI Network State Analysis...[/bold cyan]\\n")
    report = explain_network_state()

    console.print(f"Overall Security Score: [bold green]{report['security_score']}/100 ({report['grade']})[/bold green]")
    console.print(f"Active Process Connections: {report['active_processes_count']}")
    console.print(f"Anomalies Detected: [bold red]{report['total_anomalies_detected']}[/bold red]\\n")

    if report["anomalies"]:
        console.print("[bold yellow]Detected Anomalies / Warnings:[/bold yellow]")
        for a in report["anomalies"]:
            console.print(f"  • {a}")
    else:
        console.print("[bold green]✓ No suspicious network anomalies detected.[/bold green]")
'''

if 'def tools_explain():' not in code:
    code += "\n" + explain_cmd
    with open("blackoutkit/typer_cli.py", "w") as f:
        f.write(code)
    print("Added tools_explain to blackoutkit/typer_cli.py")
