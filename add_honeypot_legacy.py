with open("blackoutkit/cli.py", "r") as f:
    code = f.read()

hp_legacy = '''
    elif cmd == "honeypot":
        from .tools import run_honeypot_listener
        duration = getattr(args, "duration", 60) or 60
        ports_str = getattr(args, "ports", "22,80,445,3389,8080") or "22,80,445,3389,8080"
        port_list = [int(p.strip()) for p in ports_str.split(",") if p.strip().isdigit()]
        console.print(f"[bold cyan]🐝 Public Wi-Fi Honeypot Active[/bold cyan] (listening on ports {port_list} for {duration}s)...\\n")
        def _alert(probe):
            console.print(f"[bold red]⚠️ ALERT: Port probe detected from {probe['remote_ip']}:{probe['remote_port']} -> Decoy Port {probe['target_port']}![/bold red]")
        probes = run_honeypot_listener(ports=port_list, duration=float(duration), callback=_alert)
        if probes:
            console.print(f"\\n[bold red]Detected {len(probes)} suspicious scan attempts during honeypot session.[/bold red]")
        else:
            console.print("[success]✓ Honeypot session finished. No suspicious network scans detected on local LAN.[/success]")
'''

if 'elif cmd == "honeypot":' not in code:
    code = code.replace('    elif cmd == "process-monitor":', hp_legacy + '\n    elif cmd == "process-monitor":')
    with open("blackoutkit/cli.py", "w") as f:
        f.write(code)
    print("Updated cmd_tools in blackoutkit/cli.py with honeypot")
