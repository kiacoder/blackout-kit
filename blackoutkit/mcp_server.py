"""
Blackout Kit - Omni Model Context Protocol (MCP) Stdio Server for AI Agents.

Exposes a documented subset of Blackout Kit operations to compatible AI clients
through stdio JSON-RPC 2.0 tools.

Features exposed to AI Agents:
  - blackout_connect (engine, iran)
  - blackout_disconnect ()
  - blackout_emergency ()
  - blackout_status ()
  - blackout_read_logs (lines)
  - blackout_config (action, uri, url, index)
  - blackout_settings (action, key, value)
  - blackout_split_tunnel (action, target)
  - blackout_net_tools (tool, arg)
  - blackout_scan (count)
  - blackout_doctor ()
  - blackout_security_mode (mode)

Scope note: tool calls can start/stop local engines, import remote subscriptions,
or modify local proxy/network settings. The MCP server exposes only the subset
implemented below; descriptions must not imply unimplemented network operations.
"""
import sys
import json
import os
from pathlib import Path

# Redirect stdout to stderr for any internal imports/logs to preserve stdio JSON-RPC protocol hygiene!
real_stdout = sys.stdout
real_stdin = sys.stdin
sys.stdout = sys.stderr

def send_response(response: dict):
    """Write JSON-RPC 2.0 message to real stdout."""
    payload = json.dumps(response, ensure_ascii=False)
    real_stdout.write(payload + "\n")
    real_stdout.flush()

TOOLS_MANIFEST = [
    {
        "name": "blackout_connect",
        "description": "Start a Blackout Kit engine. `auto` uses the daemon's configured startup path; supported engines depend on the platform, installed runtime, and saved configuration.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "engine": {
                    "type": "string",
                    "description": "Engine choice: auto, sni, xray, gdpi, psiphon, warp, tun, tor, mhrv, ikev2, wireguard, openvpn, softether, hysteria2, tuic, legend. Linux supports only xray, tun, hysteria2, and tuic.",
                    "default": "auto"
                },
                "iran": {
                    "type": "boolean",
                    "description": "Enable the MCP server's LEGEND-engine Iran profile behavior",
                    "default": False
                }
            }
        }
    },
    {
        "name": "blackout_disconnect",
        "description": "Stop the active Blackout Kit daemon. This legacy MCP call bypasses the terminal command's system-proxy cleanup and does not reset external proxy settings.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "blackout_emergency",
        "description": "Start emergency mode, which tries the configured local engine candidates in sequence; Linux uses its supported subset.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "blackout_status",
        "description": "Get local daemon state, PID, active engine, saved reconnect state, and current system-proxy state. It does not test remote reachability or report public IP.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "blackout_read_logs",
        "description": "Read recent operational logs from the background daemon.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "lines": {
                    "type": "integer",
                    "description": "Number of log lines to read",
                    "default": 50
                }
            }
        }
    },
    {
        "name": "blackout_config",
        "description": "Manage V2Ray and proxy configuration URIs and subscriptions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["list", "add", "import", "remove"],
                    "description": "Action: list configs, add URI, import subscription URL, or remove by index"
                },
                "uri": {
                    "type": "string",
                    "description": "V2Ray URI (vless://, trojan://, vmess://) for add action"
                },
                "url": {
                    "type": "string",
                    "description": "Subscription URL for import action"
                },
                "index": {
                    "type": "integer",
                    "description": "1-based index number of config to remove"
                }
            },
            "required": ["action"]
        }
    },
    {
        "name": "blackout_settings",
        "description": "Read or write saved Blackout Kit settings. The legacy setter forwards raw strings without the terminal CLI's type coercion, and its reset action is not implemented; use the terminal CLI for booleans, lists, and full reset.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["get", "set", "list", "reset"],
                    "description": "Action: get, set, list, or reset settings"
                },
                "key": {
                    "type": "string",
                    "description": "Setting key name (e.g. kill_switch, xray_fingerprint, auto_set_proxy)"
                },
                "value": {
                    "type": "string",
                    "description": "Value to set"
                }
            },
            "required": ["action"]
        }
    },
    {
        "name": "blackout_split_tunnel",
        "description": "Manage saved Windows system-proxy bypass patterns. On Windows they update ProxyOverride; they are not per-process or network-layer routes, and on Linux they remain local saved data.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["add", "remove", "list"],
                    "description": "Action to perform: add, remove, or list direct bypass routes"
                },
                "target": {
                    "type": "string",
                    "description": "IP, CIDR, or domain target (e.g. 185.110.191.188 or *.local)"
                }
            },
            "required": ["action"]
        }
    },
    {
        "name": "blackout_net_tools",
        "description": "Run legacy network-tool dispatch. dns-bench, dns-flush, and dns-set are the operational MCP subset; netfix, hotspot, and ping remain schema entries but do not map to the current tool APIs. Use the terminal CLI for them.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "tool": {
                    "type": "string",
                    "enum": ["dns-bench", "dns-flush", "dns-set", "netfix", "hotspot", "ping"],
                    "description": "Diagnostic tool to execute"
                },
                "arg": {
                    "type": "string",
                    "description": "Argument for tool (e.g. DNS IP for dns-set, host for ping, 'on'/'off' for hotspot)"
                }
            },
            "required": ["tool"]
        }
    },
    {
        "name": "blackout_scan",
        "description": "Generate Cloudflare IP candidates and measure TCP reachability. This MCP tool does not scan a local network, arbitrary ports, or fake-SNI domains.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "count": {
                    "type": "integer",
                    "description": "Number of Cloudflare IPs to scan",
                    "default": 50
                }
            }
        }
    },
    {
        "name": "blackout_doctor",
        "description": "Run environment and binary diagnostic checks. The MCP implementation is read-only and does not forward the fix parameter.",
        "inputSchema": {
            "type": "object",
            "properties": {
            }
        }
    },
    {
        "name": "blackout_security_mode",
        "description": "Get or write the saved security_mode label. This legacy MCP call does not apply the terminal command's full mode preset, enable a kill switch, encrypt configurations, create multi-hop routing, or guarantee privacy.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "mode": {
                    "type": "string",
                    "enum": ["speed", "private", "legend"],
                    "description": "Security tier mode"
                }
            }
        }
    }
]

def handle_tool_call(tool_name: str, args: dict) -> str:
    """Execute tool calls and return JSON or formatted string results for AI agents."""
    try:
        if tool_name == "blackout_connect":
            engine = args.get("engine", "auto")
            iran = args.get("iran", False)
            from . import daemon, settings as cfg
            if iran:
                cfg.set_value("security_mode", "legend")
                engine = "legend"
            pid = daemon.start(engine)
            if pid:
                return f"✓ Blackout Kit connected successfully using engine '{engine}' (PID {pid}). System proxy set."
            return "✗ Failed to start daemon."

        elif tool_name == "blackout_disconnect":
            from . import daemon
            if daemon.stop():
                return "✓ Blackout Kit daemon stopped; its configured system proxy cleanup ran."
            return "✓ No active Blackout Kit daemon was running; external proxy settings were left unchanged."

        elif tool_name == "blackout_emergency":
            from . import daemon
            pid = daemon.start("emergency")
            if pid:
                return f"✓ Emergency mode initiated (PID {pid}). Sequential engine failover active."
            return "✗ Failed to start emergency mode daemon."

        elif tool_name == "blackout_status":
            from . import daemon, proxy_manager
            pid = daemon.get_pid()
            state = daemon.get_state() or {}
            proxy = proxy_manager.get_proxy_status()
            res = {
                "daemon_running": bool(pid),
                "pid": pid,
                "engine": state.get("engine", "none"),
                "status": state.get("status", "unknown"),
                "restarts": state.get("restarts", 0),
                "last_failure": state.get("last_failure"),
                "next_retry_delay": state.get("next_retry_delay"),
                "system_proxy": proxy
            }
            return json.dumps(res, indent=2)

        elif tool_name == "blackout_read_logs":
            lines = args.get("lines", 50)
            from . import daemon
            return daemon.read_logs(lines=lines)

        elif tool_name == "blackout_config":
            action = args.get("action")
            from .config import manager as cfg_mgr
            if action == "list":
                cfgs = cfg_mgr.load_configs()
                items = [{"index": i+1, "protocol": c.protocol, "sni": c.sni, "name": c.name} for i, c in enumerate(cfgs)]
                return json.dumps({"count": len(cfgs), "configs": items}, indent=2)
            elif action == "add":
                uri = args.get("uri")
                if not uri: return "Error: 'uri' parameter required"
                cfg_mgr.add_config(uri)
                return f"✓ Added V2Ray config: {uri[:30]}..."
            elif action == "import":
                url = args.get("url")
                if not url: return "Error: 'url' parameter required"
                added = cfg_mgr.import_and_merge(url)
                return f"✓ Imported {added} configs from subscription."
            elif action == "remove":
                idx = args.get("index")
                if not idx: return "Error: 'index' parameter required"
                cfg_mgr.remove_config(idx - 1)
                return f"✓ Removed config #{idx}."

        elif tool_name == "blackout_settings":
            action = args.get("action")
            key = args.get("key")
            val = args.get("value")
            from . import settings as cfg
            if action == "list":
                return json.dumps(cfg.load(), indent=2)
            elif action == "get":
                if not key: return "Error: 'key' parameter required"
                return json.dumps({key: cfg.get(key)})
            elif action == "set":
                if not key or val is None: return "Error: 'key' and 'value' required"
                cfg.set_value(key, val)
                return f"✓ Setting '{key}' updated to '{val}'."
            elif action == "reset":
                cfg.reset_all()
                return "✓ All settings reset to defaults."

        elif tool_name == "blackout_split_tunnel":
            action = args.get("action")
            target = args.get("target")
            from . import split_tunnel
            if action == "list":
                rules = split_tunnel.load_split_rules()
                return json.dumps({"direct_bypass_rules": rules}, indent=2)
            elif action == "add":
                if not target: return "Error: target is required"
                split_tunnel.add_direct_route(target)
                return f"✓ Added '{target}' to split-tunnel direct bypass list."
            elif action == "remove":
                if not target: return "Error: target is required"
                split_tunnel.remove_direct_route(target)
                return f"✓ Removed '{target}' from split-tunnel direct bypass list."

        elif tool_name == "blackout_net_tools":
            tool = args.get("tool")
            arg = args.get("arg", "")
            from . import tools as net_tools
            if tool == "dns-flush":
                net_tools.flush_dns()
                return "✓ DNS cache flushed."
            elif tool == "netfix":
                net_tools.fix_network()
                return "✓ Network repair executed."
            elif tool == "dns-bench":
                res = net_tools.benchmark_dns()
                return json.dumps(res, indent=2)
            elif tool == "dns-set":
                if not arg: return "Error: 'arg' (DNS IP) required"
                net_tools.set_dns(arg)
                return f"✓ DNS server set to {arg}."
            elif tool == "hotspot":
                action_str = arg if arg in ("on", "off") else "on"
                net_tools.toggle_hotspot(action_str)
                return f"✓ Mobile hotspot set to {action_str}."
            elif tool == "ping":
                host = arg or "8.8.8.8"
                ms = net_tools.tcp_ping(host)
                return f"Ping to {host}: {ms:.1f}ms" if ms else f"Ping to {host}: Unreachable"
            return f"Tool '{tool}' executed."

        elif tool_name == "blackout_scan":
            count = args.get("count", 50)
            from .scanner.ip_scanner import generate_cloudflare_ips, scan_ips
            import asyncio
            ips = generate_cloudflare_ips(count)
            results = asyncio.run(scan_ips(ips, concurrency=20, timeout=2.0))
            top_results = [{"ip": ip, "latency_ms": ms} for ip, ms in results[:10]]
            return json.dumps({"scanned_total": len(ips), "top_reachable": top_results}, indent=2)

        elif tool_name == "blackout_doctor":
            from . import doctor
            res = doctor.run_all_checks()
            return f"Doctor Diagnostic Results:\n{res}"

        elif tool_name == "blackout_security_mode":
            mode = args.get("mode")
            from . import settings as cfg, security
            if mode:
                cfg.set_value("security_mode", mode)
                return f"✓ Security mode updated to: {mode}"
            return f"Current Security Mode: {security.get_current_mode()}"

        return f"Unknown tool: {tool_name}"
    except Exception as exc:
        return f"Error executing {tool_name}: {exc}"

def run_mcp_server():
    """Main stdio loop reading JSON-RPC 2.0 messages from AI agents."""
    while True:
        line = real_stdin.readline()
        if not line:
            break
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except Exception:
            continue

        msg_id = msg.get("id")
        method = msg.get("method")
        params = msg.get("params", {})

        if method == "initialize":
            send_response({
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "blackout-kit-omni-mcp", "version": "1.1.1"}
                }
            })
        elif method == "notifications/initialized":
            pass
        elif method == "tools/list":
            send_response({
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"tools": TOOLS_MANIFEST}
            })
        elif method == "tools/call":
            tool_name = params.get("name")
            tool_args = params.get("arguments", {})
            output_text = handle_tool_call(tool_name, tool_args)
            send_response({
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [{"type": "text", "text": output_text}]
                }
            })
        else:
            if msg_id is not None:
                send_response({
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32601, "message": "Method not found"}
                })

if __name__ == "__main__":
    run_mcp_server()
