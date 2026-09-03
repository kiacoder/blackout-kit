with open("blackoutkit/typer_cli.py", "r") as f:
    code = f.read()

phish_cmd = '''
@tools_app.command("phishing-check")
def tools_phishing_check(
    domain: str = typer.Argument(..., help="Domain name to check for phishing / typosquatting risks"),
):
    """🛡️ Phishing Domain Check (scans domain for typosquatting & phishing heuristics)."""
    from .tools import check_phishing_domain
    res = check_phishing_domain(domain)
    if res["safe"]:
        console.print(f"[success]✓ Domain '{domain}' ({res['ip']}) appears clean from common phishing keywords.[/success]")
    else:
        console.print(f"[bold red]⚠️ PHISHING / TYPOSQUATTING RISK DETECTED for '{domain}':[/bold red]")
        for r in res["reasons"]:
            console.print(f"  • {r}")
'''

if 'def tools_phishing_check(' not in code:
    code += "\n" + phish_cmd
    with open("blackoutkit/typer_cli.py", "w") as f:
        f.write(code)
    print("Added tools_phishing_check to blackoutkit/typer_cli.py")
