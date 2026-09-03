with open("blackoutkit/tools.py", "r") as f:
    code = f.read()

dnsproxy_code = '''

# ─────────────────────────── Secure DoH DNS Proxy Engine ───────────────────

def run_doh_proxy_server(host: str = "127.0.0.1", port: int = 5300, upstream_doh: str = "https://1.1.1.1/dns-query", duration: float = 0.0, stop_event=None) -> None:
    """
    🌐 Secure DoH DNS Proxy Engine:
    Runs a local UDP DNS proxy server on 127.0.0.1:5300 (or custom port).
    Intercepts standard DNS queries and forwards them securely via DNS-over-HTTPS (DoH).
    """
    import struct
    import urllib.request

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    try:
        sock.bind((host, port))
        _log.info("Started DoH DNS Proxy Server on %s:%d forwarding to %s", host, port, upstream_doh)
    except Exception as exc:
        _log.error("Could not bind DNS Proxy to %s:%d: %s", host, port, exc)
        return

    start_time = time.time()
    while True:
        if stop_event and stop_event.is_set():
            break
        if duration > 0 and (time.time() - start_time) >= duration:
            break

        try:
            data, client_addr = sock.recvfrom(512)
            if not data or len(data) < 12:
                continue

            # Forward query via HTTP wire format (application/dns-message)
            req = urllib.request.Request(
                upstream_doh,
                data=data,
                headers={"Content-Type": "application/dns-message", "Accept": "application/dns-message"},
                method="POST"
            )
            try:
                with urllib.request.urlopen(req, timeout=3.0) as resp:
                    answer = resp.read()
                    if answer:
                        sock.sendto(answer, client_addr)
            except Exception as e:
                _log.debug("DoH proxy forward error: %s", e)
        except socket.timeout:
            continue
        except Exception:
            continue

    try:
        sock.close()
    except Exception:
        pass
'''

if "def run_doh_proxy_server" not in code:
    code += dnsproxy_code
    with open("blackoutkit/tools.py", "w") as f:
        f.write(code)
    print("Added run_doh_proxy_server to blackoutkit/tools.py")
