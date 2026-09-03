with open("blackoutkit/tools.py", "r") as f:
    code = f.read()

old_yara = '''def scan_file_yara(filepath: str) -> dict:'''

new_yara = '''def load_custom_yara_rule_file(rule_filepath: str) -> dict:
    """Load user-supplied YARA-like custom byte patterns from disk."""
    if not os.path.exists(rule_filepath):
        return {"ok": False, "error": f"Rule file not found: {rule_filepath}"}
    try:
        patterns = []
        with open(rule_filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    patterns.append(line.encode("utf-8"))
        return {"ok": True, "patterns": patterns}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}

def scan_file_yara(filepath: str) -> dict:'''

if old_yara in code:
    code = code.replace(old_yara, new_yara)
    with open("blackoutkit/tools.py", "w") as f:
        f.write(code)
    print("Added load_custom_yara_rule_file to blackoutkit/tools.py")
