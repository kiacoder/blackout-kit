with open("blackoutkit/mcp_server.py", "r") as f:
    code = f.read()

mcp_tool_def = '''        types.Tool(
            name="blackout_explain_network",
            description="AI Network Explainer: Reads live network connections, sockets, DNS integrity, and security posture to detect anomalies.",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),'''

mcp_tool_handler = '''    elif name == "blackout_explain_network":
        from .tools import explain_network_state
        res = explain_network_state()
        return [types.TextContent(type="text", text=json.dumps(res, indent=2))]'''

if 'name="blackout_explain_network"' not in code:
    code = code.replace('        types.Tool(\n            name="blackout_security_mode"', mcp_tool_def + '\n        types.Tool(\n            name="blackout_security_mode"')
    code = code.replace('    elif name == "blackout_security_mode":', mcp_tool_handler + '\n    elif name == "blackout_security_mode":')
    with open("blackoutkit/mcp_server.py", "w") as f:
        f.write(code)
    print("Updated blackoutkit/mcp_server.py with blackout_explain_network tool")
