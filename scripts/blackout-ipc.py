#!/usr/bin/env python3
"""blackout-ipc: minimal control client for the blackout-core v2 daemon.

Speaks the BKV2 framed JSON protocol (engine/v2/pkg/ipc) over a Unix socket.
Commands: ping | handshake | start | stop | status | shutdown
"""
import json
import socket
import struct
import sys
import time

API_VERSION = "2.0.0"
MAGIC = b"BKV2"
MAX_FRAME = 4 * 1024 * 1024


def read_exact(sock, count):
    chunks = []
    remaining = count
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("connection closed mid-frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def call(sock, method, params=None):
    request_id = "cli-1"
    env = {"v": API_VERSION, "kind": "request", "id": request_id, "method": method}
    if params is not None:
        env["params"] = params
    body = json.dumps(env, separators=(",", ":")).encode()
    sock.sendall(MAGIC + struct.pack(">I", len(body)) + body)
    while True:
        header = read_exact(sock, 8)
        if header[:4] != MAGIC:
            raise ValueError("bad frame magic from daemon")
        length = struct.unpack(">I", header[4:8])[0]
        if length > MAX_FRAME:
            raise ValueError("frame too large")
        reply = json.loads(read_exact(sock, length).decode())
        if reply.get("kind") == "event":
            continue
        if reply.get("id") != request_id:
            continue
        break
    if reply.get("error"):
        err = reply["error"]
        raise RuntimeError(f"{err.get('code')}: {err.get('message')}")
    return reply.get("payload") or {}


def main():
    endpoint = sys.argv[1] if len(sys.argv) > 1 else "/run/blackout-core/blackout.ipc"
    method = sys.argv[2] if len(sys.argv) > 2 else "status"
    params = json.loads(sys.argv[3]) if len(sys.argv) > 3 else None

    # The daemon creates its socket asynchronously; retry while it boots.
    deadline = time.time() + 15
    last = None
    while True:
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect(endpoint)
            break
        except OSError as exc:
            last = exc
            if time.time() > deadline:
                raise SystemExit(f"cannot reach daemon at {endpoint}: {last}")
            time.sleep(0.3)

    if method in ("start", "tunnel"):
        call(sock, "handshake", {"api_version": API_VERSION, "client_name": "blackout-ipc"})
    if method == "tunnel":
        # Convenience: start the loopback socks-tunnel with daemon defaults
        # (127.0.0.1:18080) without needing JSON on a systemd command line.
        method = "start"
        params = {"engine": "socks-tunnel"}
    result = call(sock, method, params)
    print(json.dumps(result, indent=2))
    sock.close()


if __name__ == "__main__":
    main()
