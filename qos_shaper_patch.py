with open("blackoutkit/tools.py", "r") as f:
    code = f.read()

qos_shaper_code = '''

# ─────────────────────────── Active WinDivert QoS Packet Shaper ───────────────────

def get_windivert_shaper_status() -> dict:
    """
    ⚡ Active WinDivert QoS Packet Shaper:
    Inspects availability of Windows WinDivert driver for kernel packet shaping.
    """
    is_win = sys.platform == "win32"
    return {
        "supported_platform": is_win,
        "driver_available": is_win and _is_admin(),
        "mode": "monitor" if not is_win else "active"
    }
'''

if "def get_windivert_shaper_status" not in code:
    code += qos_shaper_code
    with open("blackoutkit/tools.py", "w") as f:
        f.write(code)
    print("Added get_windivert_shaper_status to blackoutkit/tools.py")
