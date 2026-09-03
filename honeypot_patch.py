with open("blackoutkit/tools.py", "r") as f:
    code = f.read()

honeypot_code = '''

# ─────────────────────────── Public Wi-Fi Honeypot ───────────────────

def run_honeypot_listener(ports: list[int] | None = None, duration: float = 60.0, callback=None) -> list[dict]:
    """
    🐝 Public Wi-Fi Honeypot & Port Scan Detector:
    Binds decoy TCP sockets to specified ports (e.g. 80, 22, 445, 3389).
    When an external IP attempts to connect, logs the probe event and invokes optional callback.
    """
    if ports is None:
        ports = [22, 80, 445, 3389, 8080]

    detected_probes = []
    active_sockets = []

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(1.0)
            sock.bind(("0.0.0.0", port))
            sock.listen(5)
            active_sockets.append((port, sock))
        except Exception as exc:
            _log.debug("Honeypot could not bind port %d: %s", port, exc)

    if not active_sockets:
        return detected_probes

    start_time = time.time()
    while time.time() - start_time < duration:
        for port, sock in active_sockets:
            try:
                conn, addr = sock.accept()
                ip, src_port = addr[0], addr[1]
                conn.close()

                # Ignore local connections
                if ip in ("127.0.0.1", "::1"):
                    continue

                probe = {
                    "timestamp": time.time(),
                    "remote_ip": ip,
                    "remote_port": src_port,
                    "target_port": port
                }
                detected_probes.append(probe)
                if callback:
                    callback(probe)
            except socket.timeout:
                continue
            except Exception:
                continue

    for _, sock in active_sockets:
        try:
            sock.close()
        except Exception:
            pass

    return detected_probes
'''

if "def run_honeypot_listener" not in code:
    code += honeypot_code
    with open("blackoutkit/tools.py", "w") as f:
        f.write(code)
    print("Added run_honeypot_listener to blackoutkit/tools.py")
