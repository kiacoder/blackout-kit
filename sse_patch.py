with open("blackoutkit/tools.py", "r") as f:
    code = f.read()

old_api = '''        def do_GET(self):
            if self.path == "/api/status":
                from . import __version__
                self._send_json({"ok": True, "app": "blackout-kit", "version": __version__})
            elif self.path == "/api/connections":
                conns = get_active_connections(established_only=True)
                self._send_json({"connections": conns[:50], "total": len(conns)})
            elif self.path == "/api/audit":
                self._send_json(run_network_audit())'''

new_api = '''        def do_GET(self):
            if self.path == "/api/status":
                from . import __version__
                self._send_json({"ok": True, "app": "blackout-kit", "version": __version__})
            elif self.path == "/api/connections":
                conns = get_active_connections(established_only=True)
                self._send_json({"connections": conns[:50], "total": len(conns)})
            elif self.path == "/api/audit":
                self._send_json(run_network_audit())
            elif self.path == "/api/live-stream":
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                try:
                    for _ in range(5):
                        payload = json.dumps({"timestamp": time.time(), "connections": len(get_active_connections(True))})
                        self.wfile.write(f"data: {payload}\\n\\n".encode("utf-8"))
                        self.wfile.flush()
                        time.sleep(0.5)
                except Exception:
                    pass'''

if old_api in code:
    code = code.replace(old_api, new_api)
    with open("blackoutkit/tools.py", "w") as f:
        f.write(code)
    print("Successfully added /api/live-stream SSE endpoint to blackoutkit/tools.py")
else:
    print("Could not match old_api in blackoutkit/tools.py")
