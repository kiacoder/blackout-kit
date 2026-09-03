with open("blackoutkit/cli.py", "r") as f:
    code = f.read()

dnsproxy_legacy = '''
    elif cmd == "dns-proxy":
        from .tools import run_doh_proxy_server
        host = getattr(args, "host", "127.0.0.1") or "127.0.0.1"
        port = getattr(args, "port", 5300) or 5300
        upstream = getattr(args, "upstream", "https://1.1.1.1/dns-query") or "https://1.1.1.1/dns-query"
        console.print(f"[bold cyan]🌐 Secure DoH DNS Proxy Engine Active[/bold cyan]")
        console.print(f"[muted]Listening on UDP {host}:{port} -> Forwarding over encrypted DoH to {upstream}[/muted]")
        console.print("[dim]Press Ctrl+C to stop local DNS proxy...[/dim]\\n")
        try:
            run_doh_proxy_server(host=host, port=port, upstream_doh=upstream)
        except KeyboardInterrupt:
            console.print("\\n[muted]DoH DNS Proxy server stopped.[/muted]")
'''

if 'elif cmd == "dns-proxy":' not in code:
    code = code.replace('    elif cmd == "honeypot":', dnsproxy_legacy + '\n    elif cmd == "honeypot":')
    with open("blackoutkit/cli.py", "w") as f:
        f.write(code)
    print("Updated cmd_tools in blackoutkit/cli.py with dns-proxy")
