with open("blackoutkit/typer_cli.py", "r") as f:
    code = f.read()

arpguard_cmd = '''
@tools_app.command("arp-guard")
def tools_arp_guard():
    """🌐 Subnet ARP Guard (detects duplicate MAC addresses indicating ARP poisoning / MITM)."""
    from .tools import detect_arp_spoofing
    res = detect_arp_spoofing()
    if res["ok"]:
        console.print(f"[success]✓ ARP Guard Clean: Checked {res['total_hosts']} hosts on local ARP table. No ARP spoofing detected.[/success]")
    else:
        console.print(f"[bold red]⚠️ SUSPECTED ARP POISONING / MITM ATTACK DETECTED:[/bold red]")
        for s in res["spoof_suspects"]:
            console.print(f"  • MAC [bold]{s['mac']}[/bold] is shared by multiple IPs: {', '.join(s['ips'])}")
'''

if 'def tools_arp_guard(' not in code:
    code += "\n" + arpguard_cmd
    with open("blackoutkit/typer_cli.py", "w") as f:
        f.write(code)
    print("Added tools_arp_guard to blackoutkit/typer_cli.py")
