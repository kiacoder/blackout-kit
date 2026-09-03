with open("blackoutkit/tools.py", "r") as f:
    code = f.read()

api_code = '''

# ─────────────────────────── Local REST API & Web Dashboard ───────────────────

def run_web_api_dashboard(host: str = "127.0.0.1", port: int = 8080) -> None:
    """
    🌐 Local REST API & Web Dashboard Server.
    Exposes endpoints: /api/status, /api/connections, /api/audit, and serves HTML dashboard on /.
    """
    from http.server import HTTPServer, BaseHTTPRequestHandler

    class APIHandler(BaseHTTPRequestHandler):
        def _send_json(self, data: dict):
            body = json.dumps(data).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_html(self, html: str):
            body = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/api/status":
                from . import __version__
                self._send_json({"ok": True, "app": "blackout-kit", "version": __version__})
            elif self.path == "/api/connections":
                conns = get_active_connections(established_only=True)
                self._send_json({"connections": conns[:50], "total": len(conns)})
            elif self.path == "/api/audit":
                self._send_json(run_network_audit())
            elif self.path == "/":
                html_dashboard = """<!DOCTYPE html>
<html>
<head>
    <title>Blackout Kit Dashboard</title>
    <style>
        body { font-family: -apple-system, monospace; background: #0f172a; color: #f8fafc; padding: 2rem; }
        .card { background: #1e293b; padding: 1.5rem; border-radius: 8px; margin-bottom: 1rem; border: 1px solid #334155; }
        h1 { color: #38bdf8; }
        .badge { background: #22c55e; color: #022c22; padding: 0.2rem 0.5rem; border-radius: 4px; font-weight: bold; }
    </style>
</head>
<body>
    <h1>Blackout Kit — Network Dashboard</h1>
    <div class="card">
        <h2>System Status <span class="badge">ONLINE</span></h2>
        <p>Local REST API is active and servicing metrics.</p>
    </div>
    <div class="card">
        <h2>Quick REST Endpoints</h2>
        <ul>
            <li><a href="/api/status" style="color:#38bdf8">GET /api/status</a></li>
            <li><a href="/api/connections" style="color:#38bdf8">GET /api/connections</a></li>
            <li><a href="/api/audit" style="color:#38bdf8">GET /api/audit</a></li>
        </ul>
    </div>
</body>
</html>"""
                self._send_html(html_dashboard)
            else:
                self.send_error(404, "Endpoint Not Found")

        def log_message(self, format, *args):
            return  # Suppress routine log output

    server = HTTPServer((host, port), APIHandler)
    _log.info("Started Blackout Kit REST API & Dashboard on http://%s:%d", host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
'''

if "def run_web_api_dashboard" not in code:
    code += api_code
    with open("blackoutkit/tools.py", "w") as f:
        f.write(code)
    print("Added run_web_api_dashboard to blackoutkit/tools.py")
