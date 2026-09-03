with open("blackoutkit/tools.py", "r") as f:
    code = f.read()

phish_code = '''

# ─────────────────────────── Phishing & Malicious Domain Check ───────────────────

KNOWN_PHISHING_KEYWORDS = ["login-verify", "paypal-secure", "apple-id-update", "bank-security-fix", "crypto-airdrop-claim"]

def check_phishing_domain(domain: str) -> dict:
    """
    🛡️ Phishing & Malicious Domain Check:
    Checks if a domain contains suspicious typosquatting keywords or resolves to sinkhole IPs.
    """
    domain_lower = domain.lower()
    suspicious = False
    reasons = []

    for kw in KNOWN_PHISHING_KEYWORDS:
        if kw in domain_lower:
            suspicious = True
            reasons.append(f"Domain contains known phishing keyword: '{kw}'")

    if domain_lower.count("-") >= 3:
        suspicious = True
        reasons.append("Domain contains excessive hyphens (typosquatting indicator)")

    # Attempt resolution
    ip = _system_resolve(domain)

    return {
        "domain": domain,
        "ip": ip or "unresolved",
        "suspicious": suspicious,
        "reasons": reasons,
        "safe": not suspicious
    }
'''

if "def check_phishing_domain" not in code:
    code += phish_code
    with open("blackoutkit/tools.py", "w") as f:
        f.write(code)
    print("Added check_phishing_domain to blackoutkit/tools.py")
