"""
Blackout Kit - WiFi Network Switcher + ISP Detection.
Scans available WiFi networks, auto-switches ISPs, shows current ISP info.
All WiFi operations use netsh wlan (Windows only).
Non-Windows platforms return None/empty gracefully.
"""
import json
import logging
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass

_log = logging.getLogger(__name__)


# ─────────────────────────── Data classes ────────────────────────

@dataclass
class WifiNetwork:
    ssid: str
    signal: int     # 0–100
    auth: str       # "WPA2", "Open", etc.
    saved: bool     # True = we have a saved profile (can auto-connect)


@dataclass
class IspInfo:
    isp: str        # "Mobile Communication Company of Iran PLC"
    isp_short: str  # "Mokhaberat (MCI)" — friendly display name
    asn: str        # "AS197207"
    city: str
    country: str


# ──────────────────── Iranian ISP ASN → friendly name ────────────

_ISP_SHORT = {
    # ── Iran ──────────────────────────────────────────────────────
    "AS197207": "Mokhaberat (MCI)",
    "AS44244":  "Irancell (MTN)",
    "AS57218":  "Rightel",
    "AS31549":  "Shatel",
    "AS12880":  "Afranet",
    "AS48309":  "Pars Online",
    "AS58224":  "TCI",
    "AS48434":  "TCI",
    "AS6736":   "Asiatech",
    "AS48147":  "Respina",
    "AS49100":  "DATAK",
    "AS44565":  "Sabanet",
    "AS43754":  "Fanava",
    "AS39501":  "Iranserver",
    "AS25184":  "Afranet",
    "AS47262":  "Iranet",
    "AS34918":  "Pishgaman",
    "AS56402":  "Kadir",

    # ── USA ───────────────────────────────────────────────────────
    "AS7922":   "Comcast (Xfinity)",
    "AS7018":   "AT&T",
    "AS701":    "Verizon",
    "AS22773":  "Cox Communications",
    "AS11426":  "Charter (Spectrum)",
    "AS20115":  "Charter (Spectrum)",
    "AS11351":  "Charter (Spectrum)",
    "AS10796":  "Charter (Spectrum)",
    "AS6128":   "Altice USA (Optimum)",
    "AS26093":  "Mediacom",
    "AS16591":  "Google Fiber",
    "AS46887":  "Lightpath",
    "AS33651":  "Comcast Business",
    "AS21508":  "CenturyLink (Lumen)",
    "AS209":    "Lumen/CenturyLink",

    # ── UK ────────────────────────────────────────────────────────
    "AS2856":   "BT",
    "AS5089":   "Virgin Media",
    "AS5607":   "Sky Broadband",
    "AS13285":  "TalkTalk",
    "AS6871":   "Plusnet",
    "AS12576":  "EE",
    "AS1273":   "Vodafone UK",
    "AS35228":  "O2 UK",
    "AS8190":   "COLT UK",
    "AS2529":   "BT (Demon)",
    "AS25180":  "Zen Internet",
    "AS20712":  "Andrews & Arnold",
    "AS9105":   "Toob",

    # ── China ─────────────────────────────────────────────────────
    "AS4134":   "China Telecom",
    "AS4837":   "China Unicom",
    "AS9808":   "China Mobile",
    "AS9929":   "China Unicom (A2)",
    "AS4816":   "China Telecom",
    "AS17816":  "China Mobile",
    "AS17621":  "China Unicom Shanghai",
    "AS58461":  "China Telecom Jiangsu",
    "AS24445":  "China Mobile",
    "AS9812":   "China Telecom",
    "AS38019":  "China Telecom Zhejiang",
    "AS4812":   "China Telecom Shanghai",
    "AS23724":  "China Telecom IDC",

    # ── Iraq ──────────────────────────────────────────────────────
    "AS51684":  "Earthlink Iraq",
    "AS48682":  "Newroz Telecom",
    "AS56914":  "Asiacell",
    "AS59588":  "Zain Iraq",
    "AS200244": "Korek Telecom",
    "AS21277":  "IQnet",
    "AS50710":  "Cetel",
    "AS206124": "ScopeSky",
    "AS199607": "Iraqi Telecom",
    "AS60557":  "Alink Iraq",
    "AS203214": "Earthlink Business",
    "AS42915":  "Internet Service Centre",
}


# ─────────────────────────── Helpers ─────────────────────────────

def _signal_bar(pct: int, width: int = 10) -> str:
    """Return a unicode block-character signal bar like ████████░░ 82%."""
    filled = round(pct / 100 * width)
    return "█" * filled + "░" * (width - filled)


def _run_netsh(*args: str, timeout: int = 10) -> str | None:
    """
    Run a netsh command and return stdout text.
    Returns None on non-Windows or any subprocess failure.
    """
    if sys.platform != "win32":
        _log.debug("netsh unavailable on %s", sys.platform)
        return None
    try:
        result = subprocess.run(
            ["netsh"] + list(args),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=timeout,
        )
        return result.stdout
    except Exception as e:
        _log.debug("netsh %s error: %s", " ".join(args), e)
        return None


# ─────────────────────────── WiFi info ───────────────────────────

def get_current_ssid() -> str | None:
    """Return the SSID of the currently connected WiFi network, or None."""
    out = _run_netsh("wlan", "show", "interfaces")
    if not out:
        return None
    for line in out.splitlines():
        stripped = line.strip()
        # Match "SSID                   : MyNetwork" but not "BSSID ..."
        if stripped.startswith("SSID") and not stripped.startswith("BSSID"):
            parts = stripped.split(":", 1)
            if len(parts) == 2:
                ssid = parts[1].strip()
                if ssid:
                    _log.debug("Current SSID: %s", ssid)
                    return ssid
    return None


def get_wifi_signal() -> int | None:
    """Return current WiFi signal strength 0–100, or None if not on WiFi."""
    out = _run_netsh("wlan", "show", "interfaces")
    if not out:
        return None
    for line in out.splitlines():
        stripped = line.strip()
        if stripped.startswith("Signal") and ":" in stripped:
            parts = stripped.split(":", 1)
            try:
                return int(parts[1].strip().rstrip("%"))
            except ValueError:
                pass
    return None


# ─────────────────────────── ISP lookup ──────────────────────────

def get_isp_info(timeout: float = 6.0) -> IspInfo | None:
    """
    Look up current ISP via ip-api.com (fallback: ipinfo.io).
    Both APIs auto-detect the requesting IP — no key needed.
    Returns IspInfo or None if all APIs fail.
    """
    # ── Primary: ip-api.com ──
    try:
        req = urllib.request.Request(
            "http://ip-api.com/json?fields=isp,org,as,city,country",
            headers={"User-Agent": "blackout-kit/1.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())

        raw_as = data.get("as", "")            # e.g. "AS197207 Mobile ..."
        asn = raw_as.split()[0] if raw_as else ""
        isp_name = data.get("isp", "Unknown")
        return IspInfo(
            isp=isp_name,
            isp_short=_ISP_SHORT.get(asn, isp_name),
            asn=asn,
            city=data.get("city", ""),
            country=data.get("country", ""),
        )
    except Exception as e:
        _log.debug("ip-api.com lookup failed: %s", e)

    # ── Fallback: ipinfo.io ──
    try:
        req = urllib.request.Request(
            "https://ipinfo.io/json",
            headers={"User-Agent": "blackout-kit/1.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())

        org = data.get("org", "")              # e.g. "AS44244 MTN Irancell"
        asn = org.split()[0] if org else ""
        isp_name = " ".join(org.split()[1:]) if " " in org else org
        return IspInfo(
            isp=isp_name or "Unknown",
            isp_short=_ISP_SHORT.get(asn, isp_name or "Unknown"),
            asn=asn,
            city=data.get("city", ""),
            country=data.get("country", ""),
        )
    except Exception as e:
        _log.debug("ipinfo.io lookup failed: %s", e)

    _log.warning("All ISP lookup APIs failed — no internet or both endpoints unreachable.")
    return None


# ─────────────────────── Network scanning ────────────────────────

def list_available_networks() -> list[WifiNetwork]:
    """
    Scan for all visible WiFi networks using netsh wlan show networks.
    Returns list of WifiNetwork (saved=False — call list_saved_profiles to fill in).
    """
    out = _run_netsh("wlan", "show", "networks", "mode=bssid")
    if not out:
        return []

    networks: list[WifiNetwork] = []
    current_ssid: str | None = None
    current_signal = 0
    current_auth = "Unknown"

    for line in out.splitlines():
        stripped = line.strip()

        # "SSID 1 : MyNetwork" — new network block begins
        if stripped.startswith("SSID") and not stripped.startswith("BSSID") and ":" in stripped:
            # Save the previous block
            if current_ssid:
                networks.append(WifiNetwork(
                    ssid=current_ssid,
                    signal=current_signal,
                    auth=current_auth,
                    saved=False,
                ))
            parts = stripped.split(":", 1)
            current_ssid = parts[1].strip() if len(parts) == 2 else None
            current_signal = 0
            current_auth = "Unknown"

        elif stripped.startswith("Authentication") and ":" in stripped:
            parts = stripped.split(":", 1)
            auth_raw = parts[1].strip()
            # Normalize: "WPA2-Personal" → "WPA2", "Open" → "Open"
            current_auth = auth_raw.split("-")[0] if "-" in auth_raw else auth_raw

        elif stripped.startswith("Signal") and ":" in stripped:
            parts = stripped.split(":", 1)
            try:
                current_signal = int(parts[1].strip().rstrip("%"))
            except ValueError:
                pass

    # Flush the last network block
    if current_ssid:
        networks.append(WifiNetwork(
            ssid=current_ssid,
            signal=current_signal,
            auth=current_auth,
            saved=False,
        ))

    _log.debug("Found %d available WiFi networks.", len(networks))
    return networks


def list_saved_profiles() -> list[str]:
    """Return list of SSIDs for which we have saved profiles (can auto-connect)."""
    out = _run_netsh("wlan", "show", "profiles")
    if not out:
        return []
    profiles: list[str] = []
    for line in out.splitlines():
        stripped = line.strip()
        if "All User Profile" in stripped and ":" in stripped:
            parts = stripped.split(":", 1)
            ssid = parts[1].strip()
            if ssid:
                profiles.append(ssid)
    _log.debug("Saved WiFi profiles: %s", profiles)
    return profiles


def get_switchable_networks() -> list[WifiNetwork]:
    """
    Return available networks we have saved passwords for,
    excluding the current SSID, sorted by signal strength (best first).
    """
    current = get_current_ssid()
    available = list_available_networks()
    saved_set = set(list_saved_profiles())

    for net in available:
        net.saved = net.ssid in saved_set

    switchable = [
        net for net in available
        if net.saved and net.ssid != current
    ]
    switchable.sort(key=lambda n: n.signal, reverse=True)
    _log.debug(
        "Switchable networks (current=%s): %s",
        current,
        [n.ssid for n in switchable],
    )
    return switchable


# ─────────────────────── Network switching ───────────────────────

def switch_to_network(ssid: str, timeout: int = 15) -> bool:
    """
    Connect to a WiFi network by SSID (must have a saved profile).
    Returns True if successfully connected within timeout seconds.
    """
    _log.info("Requesting connection to WiFi: %s", ssid)
    out = _run_netsh("wlan", "connect", f"name={ssid}", timeout=timeout)
    if out is None:
        _log.warning("netsh wlan connect returned None for: %s", ssid)
        return False

    _log.debug("netsh connect output: %s", out.strip())
    # netsh outputs "Connection request was completed successfully." on success
    # or a brief message — either way, poll for actual connection state
    return wait_for_connection(timeout=timeout)


def wait_for_connection(timeout: int = 10) -> bool:
    """
    Poll netsh wlan show interfaces until State=connected or timeout elapses.
    Returns True if connected before timeout.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        out = _run_netsh("wlan", "show", "interfaces")
        if out:
            for line in out.splitlines():
                stripped = line.strip().lower()
                if stripped.startswith("state") and ":" in stripped:
                    state = stripped.split(":", 1)[1].strip()
                    if state == "connected":
                        _log.info("WiFi state confirmed: connected.")
                        return True
        time.sleep(1)
    _log.warning("wait_for_connection timed out after %ds.", timeout)
    return False


def auto_switch(exclude_ssid: str | None = None) -> str | None:
    """
    Try each switchable network in signal-strength order.
    Optionally exclude an additional SSID (e.g. a previously failed one).
    Returns the new SSID on success, or None if all attempts fail.
    """
    networks = get_switchable_networks()
    if exclude_ssid:
        networks = [n for n in networks if n.ssid != exclude_ssid]

    if not networks:
        _log.info("auto_switch: no candidates after exclusions.")
        return None

    for net in networks:
        _log.info("auto_switch: trying %s (signal %d%%)", net.ssid, net.signal)
        if switch_to_network(net.ssid):
            _log.info("auto_switch: successfully connected to %s.", net.ssid)
            return net.ssid
        _log.warning("auto_switch: %s failed, trying next...", net.ssid)

    _log.warning("auto_switch: all %d candidate(s) failed.", len(networks))
    return None
