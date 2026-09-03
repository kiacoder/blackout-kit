with open("blackoutkit/cli.py", "r") as f:
    code = f.read()

audit_legacy = '''
    elif cmd == "audit":
        from .tools import run_network_audit
        report = run_network_audit()
        score = report["score"]
        grade = report["grade"]
        score_color = "green" if score >= 80 else "yellow" if score >= 60 else "red"
        console.print(f"Overall Security Posture Score: [{score_color}][bold]{score}/100 ({grade})[/bold][/{score_color}]\\n")
        table = make_table(
            "Security Audit Findings",
            [("Category", "cyan"), ("Status", ""), ("Summary", "bold white"), ("Recommendation", "dim")],
            [],
        )
        for finding in report["findings"]:
            status = "[success]✓ PASS[/success]" if finding["ok"] else f"[error]⚠ {finding['severity']}[/error]"
            table.add_row(finding["category"], status, finding["summary"], finding["recommendation"])
        console.print(table)
'''

if 'elif cmd == "audit":' not in code:
    code = code.replace('    elif cmd == "scan-file":', audit_legacy + '\n    elif cmd == "scan-file":')
    with open("blackoutkit/cli.py", "w") as f:
        f.write(code)
    print("Updated cmd_tools in blackoutkit/cli.py with audit")
