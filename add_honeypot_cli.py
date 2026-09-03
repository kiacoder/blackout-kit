with open("blackoutkit/typer_cli.py", "r") as f:
    code = f.read()

honeypot_cmd = '''
@tools_app.command("honeypot")
def tools_honeypot(
    duration: int = typer.Option(60, "--duration", "-d", help="Duration in seconds to run honeypot listener"),
    ports: str = typer.Option("22,80,445,3389,8080", "--ports", "-p", help="Comma-separated decoy ports"),
):
    """🐝 Public Wi-Fi Honeypot & Scan Detector (alerts when local network IPs probe decoy ports)."""
    from .tools import run_honeypot_listener

    port_list = [int(p.strip()) for p in ports.split(",") if p.strip().isdigit()]
    console.print(f"[bold cyan]🐝 Public Wi-Fi Honeypot Active[/bold cyan] (listening on ports {port_list} for {duration}s)...\\n")

    def _alert(probe):
        console.print(f"[bold red]⚠️ ALERT: Port probe detected from {probe['remote_ip']}:{probe['remote_port']} -> Decoy Port {probe['target_port']}![/bold red]")

    probes = run_honeypot_listener(ports=port_list, duration=float(duration), callback=_alert)

    if probes:
        console.print(f"\\n[bold red]Detected {len(probes)} suspicious scan attempts during honeypot session.[/bold red]")
    else:
        console.print("[success]✓ Honeypot session finished. No suspicious network scans detected on local LAN.[/success]")
'''

if 'def tools_honeypot(' not in code:
    code += "\n" + honeypot_cmd
    with open("blackoutkit/typer_cli.py", "w") as f:
        f.write(code)
    print("Added tools_honeypot to blackoutkit/typer_cli.py")
