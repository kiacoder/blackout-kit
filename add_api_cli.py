with open("blackoutkit/typer_cli.py", "r") as f:
    code = f.read()

api_cli_code = '''
# ── REST API / DASHBOARD GROUP ──
api_app = typer.Typer(help="Local REST API & Web Dashboard", no_args_is_help=False)
app.add_typer(api_app, name="api")

@api_app.command("start")
def api_start(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Host IP to bind web server"),
    port: int = typer.Option(8080, "--port", "-p", help="Port to bind web server"),
):
    """Start local REST API and browser-based Web Dashboard."""
    from .tools import run_web_api_dashboard
    console.print(f"[bold cyan]🌐 Starting Blackout Kit Web Dashboard & REST API...[/bold cyan]")
    console.print(f"[success]✓ Open dashboard in your browser:[/success] [bold white]http://{host}:{port}/[/bold white]")
    console.print("[dim]Press Ctrl+C to stop the REST API server...[/dim]\\n")
    run_web_api_dashboard(host=host, port=port)
'''

if 'api_app = typer.Typer' not in code:
    code += "\n" + api_cli_code
    with open("blackoutkit/typer_cli.py", "w") as f:
        f.write(code)
    print("Added api_app to blackoutkit/typer_cli.py")
