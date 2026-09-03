with open("blackoutkit/tools.py", "r") as f:
    code = f.read()

yara_code = '''

# ─────────────────────────── YARA Signature Rules Engine ───────────────────

BUILTIN_YARA_SIGNATURES = {
    "Webshell_Payload": [b"eval(base64_decode(", b"system($_POST[", b"shell_exec("],
    "Suspicious_Executable": [b"MZ", b"PE\\x00\\x00"],
    "EICAR_Test_File": [b"X5O!P%@AP[4\\\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"],
}

def scan_file_yara(filepath: str) -> dict:
    """
    🔒 YARA Rules Engine:
    Scans a local file against built-in byte signatures for web shells, test viruses, and suspicious payloads.
    """
    if not os.path.exists(filepath):
        return {"ok": False, "error": f"File not found: {filepath}", "matches": []}

    matches = []
    try:
        with open(filepath, "rb") as f:
            content = f.read()

        for rule_name, sigs in BUILTIN_YARA_SIGNATURES.items():
            for sig in sigs:
                if sig in content:
                    matches.append({"rule": rule_name, "pattern": str(sig)})
                    break

        return {
            "ok": True,
            "filepath": filepath,
            "matches_count": len(matches),
            "matches": matches,
            "clean": len(matches) == 0
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc), "matches": []}
'''

if "def scan_file_yara" not in code:
    code += yara_code
    with open("blackoutkit/tools.py", "w") as f:
        f.write(code)
    print("Added scan_file_yara to blackoutkit/tools.py")
