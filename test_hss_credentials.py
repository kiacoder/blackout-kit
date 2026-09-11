#!/usr/bin/env python3
"""
Test Hotspot Shield VPN credentials by trying common patterns.
Attempts to create a test VPN connection and dial with different credentials.
"""
import subprocess
import sys
import time
from pathlib import Path

# Common credential patterns for enterprise/consumer VPNs
CREDENTIAL_PATTERNS = [
    ("vpn", "vpn"),
    ("user", "password"),
    ("admin", "admin"),
    ("hss", "hss"),
    ("hotspot", "shield"),
    ("client", "client"),
    ("vpnuser", "vpnpass"),
    ("hss_default", "hss_default"),
    ("HSS", "HSS"),
    ("default", "default"),
    ("test", "test"),
    ("", ""),  # Empty credentials (device/cert-based)
]

# Also try device-ID based patterns
DEVICE_PATTERNS = [
    "hotspot-shield-windows-store-na5iu8t7r",  # Found in binary
    "na5iu8t7r",
]

def test_ras_connection(profile_name, username, password):
    """Test RAS connection with given credentials."""
    try:
        # Use rasdial to test connection
        cmd = ["rasdial", profile_name, username, password]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15
        )

        # Check for success indicators
        success_keywords = ["successfully", "connected", "established"]
        output = result.stdout.lower() + result.stderr.lower()

        is_success = any(keyword in output for keyword in success_keywords)

        return {
            "username": username,
            "password": password,
            "returncode": result.returncode,
            "success": is_success,
            "stdout": result.stdout[:200],
            "stderr": result.stderr[:200],
        }
    except subprocess.TimeoutExpired:
        return {
            "username": username,
            "password": password,
            "timeout": True,
        }
    except Exception as e:
        return {
            "username": username,
            "password": password,
            "error": str(e),
        }


def create_test_profile(profile_name, server):
    """Create a test VPN profile using PowerShell."""
    ps_cmd = f"""
$name = '{profile_name}'
$server = '{server}'
try {{
    # Remove if exists
    Get-VpnS2SUserInstallation -Name $name -ErrorAction SilentlyContinue | Remove-VpnS2SUserInstallation -Force

    # Create new profile (minimal, for testing)
    Add-VpnS2SUserInstallation -Protocol IKEv2 `
        -EncryptionType IKEv2Only `
        -EncryptionLevel Required `
        -AuthenticationMethod EAP `
        -PassThru -Force 2>$null | Out-Null

    Write-Output "SUCCESS"
}} catch {{
    Write-Output "FAILED: $_"
}}
"""

    result = subprocess.run(
        ["powershell", "-Command", ps_cmd],
        capture_output=True,
        text=True,
        timeout=30
    )

    return "SUCCESS" in result.stdout


def main():
    profile_name = "Test-HSS-Credentials"
    server = "mh-cr-us-nyc-pr-p-9.topenginefactory.com"

    print("=" * 80)
    print("HOTSPOT SHIELD CREDENTIAL TESTING")
    print("=" * 80)
    print(f"\nTest Server: {server}")
    print(f"Profile Name: {profile_name}\n")

    # Note: Actually creating and testing VPN connections requires:
    # 1. Admin privileges
    # 2. The VPN profile to be properly configured
    # 3. Network connectivity to the server

    print("Credential patterns to test:")
    print("-" * 80)
    print(f"{'Username':<25} {'Password':<25} {'Result'}")
    print("-" * 80)

    results = []
    for username, password in CREDENTIAL_PATTERNS:
        print(f"{username:<25} {password:<25} Testing...", end="\r")

        # Try to test (would need proper VPN profile setup)
        # For now, just document the patterns
        results.append({
            "username": username,
            "password": password,
            "status": "UNTESTED - needs active VPN profile",
        })

        print(f"{username:<25} {password:<25} {results[-1]['status']}")

    print("\n" + "=" * 80)
    print("DEVICE-BASED PATTERNS TO TRY:")
    print("=" * 80)
    for device in DEVICE_PATTERNS:
        print(f"  Username: {device}")
        print(f"  Password: (various)")
        print()

    print("=" * 80)
    print("NEXT STEPS:")
    print("=" * 80)
    print("""
1. Manually create a test VPN profile in Windows:
   Settings > Network & Internet > VPN > Add VPN

2. Use Wireshark to monitor IKEv2 authentication when connecting with Hotspot Shield

3. Check if the app stores credentials in:
   - Credential Manager (Windows)
   - App's encrypted settings.dat
   - System DPAPI protected keys

4. Try these common patterns first:
   - Username: "vpn" / Password: "vpn"
   - Username: "hss" / Password: "hss"
   - Username: (empty) / Password: (empty) - cert/key based

5. Monitor with Wireshark:
   - Filter: isakmp or ikev2
   - Look for EAP-MSCHAPv2 authentication
   - Extract username from auth packets
""")


if __name__ == "__main__":
    main()
