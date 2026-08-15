"""
Blackout Kit - Binary Downloader.
Auto-downloads engine binaries from their official GitHub releases.

Epic features:
  - BIN_REGISTRY: declarative per-binary download spec (repo, asset pattern, extract map)
  - fnmatch-based asset + zip member matching — handles version numbers in filenames
  - In-process API response cache — avoids repeat GitHub API calls in one session
  - progress_callback pattern — CLI layer owns the Rich progress bar, this module stays UI-free
  - check_installed() / get_latest_version() for status reporting
  - Graceful handling: rate limits, 404s, bad zips, missing members — all surfaced as (False, msg)
"""
import fnmatch
import json
import tempfile
import threading
import urllib.error
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import __version__

from . import PROJECT_ROOT, BINS_DIR

_GITHUB_RELEASES_API = "https://api.github.com/repos/{repo}/releases/latest"
_API_TIMEOUT         = 10    # seconds — GitHub API lookup
_DL_TIMEOUT          = 300   # seconds — binary download (5 min for large files)

# Per-session cache: repo → release dict — avoids hammering the 60 req/hr rate limit
_release_cache: dict[str, dict] = {}
_cache_lock = threading.Lock()


# ──────────────────────────── Data model ─────────────────────────

@dataclass
class BinInfo:
    key:           str                # short internal key: "xray"
    display_name:  str                # "Xray-core (V2Ray/VLESS/Trojan)"
    description:   str                # one-liner shown in status table
    github_repo:   str | None         # "XTLS/Xray-core" — None = manual only
    asset_pattern: str | None         # fnmatch pattern against release asset names
    asset_exclude: str | None         # skip assets containing this string (e.g. "legacy")
    extract_map:   dict[str, str]     # {fnmatch_in_zip → output_filename_in_bins/}
    output_bins:   list[str]          # expected filenames in bins/ after install
    required:      bool               # True = needed for core sni/xray stack
    manual_url:    str                # human-readable download page
    manual_note:   str                # brief note explaining WHY it's manual


# ──────────────────────────── Registry ───────────────────────────

BIN_REGISTRY: dict[str, BinInfo] = {

    "goodbyedpi": BinInfo(
        key           = "goodbyedpi",
        display_name  = "GoodbyeDPI + WinDivert",
        description   = "TCP fragmentation bypass — includes WinDivert kernel driver",
        github_repo   = "ValdikSS/GoodbyeDPI",
        asset_pattern = "goodbyedpi-*.zip",
        asset_exclude = None,
        extract_map   = {
            "*/goodbyedpi.exe":  "goodbyedpi.exe",
            "*/WinDivert.dll":   "WinDivert.dll",
            "*/WinDivert64.sys": "WinDivert64.sys",
        },
        output_bins   = ["goodbyedpi.exe", "WinDivert.dll", "WinDivert64.sys"],
        required      = False,
        manual_url    = "https://github.com/ValdikSS/GoodbyeDPI/releases",
        manual_note   = "",
    ),

    "softether": BinInfo(
        key           = "softether",
        display_name  = "SoftEther VPN Client",
        description   = "SoftEther VPN — powerful SSL-VPN protocol",
        github_repo   = "SoftEtherVPN/SoftEtherVPN_Stable",
        asset_pattern = None,
        asset_exclude = None,
        extract_map   = {"softether-vpnclient-*.exe": "softether-installer.exe"},
        output_bins   = ["softether-installer.exe"],
        required      = False,
        manual_url    = "https://github.com/SoftEtherVPN/SoftEtherVPN_Stable/releases",
        manual_note   = "Downloads installer — run bins/softether-installer.exe, then copy vpnclient.exe to bins/",
    ),

    "wireguard": BinInfo(
        key           = "wireguard",
        display_name  = "WireGuard (Portable)",
        description   = "WireGuard VPN — high-speed UDP-based tunnel",
        github_repo   = "DrEm-s/wireguard-windows-portable",
        asset_pattern = "wireguard-*.zip",
        asset_exclude = None,
        extract_map   = {"*/wireguard.exe": "wireguard.exe", "*/wg.exe": "wg.exe"},
        output_bins   = ["wireguard.exe", "wg.exe"],
        required      = False,
        manual_url    = "https://github.com/DrEm-s/wireguard-windows-portable/releases",
        manual_note   = "",
    ),

    "psiphon": BinInfo(
        key           = "psiphon",
        display_name  = "Psiphon Tunnel Core",
        description   = "Psiphon multi-protocol tunnel core",
        github_repo   = None,
        asset_pattern = None,
        asset_exclude = None,
        extract_map   = {},
        output_bins   = ["psiphon-tunnel-core.exe"],
        required      = False,
        manual_url    = "https://github.com/Psiphon-Inc/psiphon-tunnel-core",
        manual_note   = "",
    ),

    "warp": BinInfo(
        key           = "warp",
        display_name  = "Cloudflare WARP Plus Engine",
        description   = "WARP+ / MASQUE tunnel binary",
        github_repo   = "bepass-org/warp-plus",
        asset_pattern = "*windows*amd64*.zip",
        asset_exclude = None,
        extract_map   = {"*warp-plus.exe": "warp-plus.exe"},
        output_bins   = ["warp-plus.exe"],
        required      = False,
        manual_url    = "https://github.com/bepass-org/warp-plus/releases",
        manual_note   = "",
    ),

    "tor": BinInfo(
        key           = "tor",
        display_name  = "Tor (Expert Bundle)",
        description   = "Tor onion network router",
        github_repo   = None,
        asset_pattern = None,
        asset_exclude = None,
        extract_map   = {},
        output_bins   = ["tor.exe"],
        required      = False,
        manual_url    = "https://www.torproject.org/download/tor/",
        manual_note   = "Download Tor Expert Bundle, extract tor.exe into bins/",
    ),

    "openvpn": BinInfo(
        key           = "openvpn",
        display_name  = "OpenVPN",
        description   = "OpenVPN executable",
        github_repo   = None,
        asset_pattern = None,
        asset_exclude = None,
        extract_map   = {},
        output_bins   = ["openvpn.exe"],
        required      = False,
        manual_url    = "https://openvpn.net/community-downloads/",
        manual_note   = "Download OpenVPN, install, and copy openvpn.exe to bins/",
    ),

    "warp_dll": BinInfo(
        key           = "warp_dll",
        display_name  = "Blackout WARP DLL (64-bit)",
        description   = "Native DLL required for WARP and Psiphon",
        github_repo   = "kiacoder/blackout-kit",
        asset_pattern = None,
        asset_exclude = None,
        extract_map   = {"blackout_warp.dll": "blackout_warp.dll"},
        output_bins   = ["blackout_warp.dll"],
        required      = False,
        manual_url    = "https://github.com/kiacoder/blackout-kit",
        manual_note   = "",
    ),

    "sing-box": BinInfo(
        key           = "sing-box",
        display_name  = "Sing-Box",
        description   = "Universal proxy platform",
        github_repo   = "SagerNet/sing-box",
        asset_pattern = "sing-box-*-windows-amd64.zip",
        asset_exclude = "beta",
        extract_map   = {"*/sing-box.exe": "sing-box.exe"},
        output_bins   = ["sing-box.exe"],
        required      = False,
        manual_url    = "https://github.com/SagerNet/sing-box/releases",
        manual_note   = "",
    ),

    "xray": BinInfo(
        key           = "xray",
        display_name  = "Xray Core",
        description   = "Xray-core proxy engine",
        github_repo   = "XTLS/Xray-core",
        asset_pattern = "Xray-windows-64.zip",
        asset_exclude = None,
        extract_map   = {"xray.exe": "xray.exe"},
        output_bins   = ["xray.exe"],
        required      = True,
        manual_url    = "https://github.com/XTLS/Xray-core/releases",
        manual_note   = "",
    ),

    "mhrv": BinInfo(
        key           = "mhrv",
        display_name  = "mhrv (in blackout_core.dll)",
        description   = "Embedded HTTP Google Apps Script relay (requires blackout_core.dll)",
        github_repo   = None,
        asset_pattern = None,
        asset_exclude = None,
        extract_map   = {},
        output_bins   = ["blackout_core.dll"],
        required      = False,
        manual_url    = "https://github.com/kiacoder/blackout-kit",
        manual_note   = "Run blackout bins download sni-spoofing to get the DLL",
    ),

    "sni-spoofing": BinInfo(
        key           = "sni-spoofing",
        display_name  = "Blackout Core DLL (64-bit)",
        description   = "Native DLL required for SNI spoofing and Xray",
        github_repo   = "kiacoder/blackout-kit",
        asset_pattern = None,
        asset_exclude = None,
        extract_map   = {"blackout_core.dll": "blackout_core.dll"},
        output_bins   = ["blackout_core.dll"],
        required      = True,
        manual_url    = "https://github.com/kiacoder/blackout-kit",
        manual_note   = "",
    ),

}


# ──────────────────────────── GitHub API ─────────────────────────

def _fetch_release(repo: str) -> dict | None:
    """
    Fetch latest release from GitHub API.
    Uses in-process cache — safe to call multiple times per session.
    Returns None on network error, 404, or rate limit.
    """
    with _cache_lock:
        if repo in _release_cache:
            return _release_cache[repo]

    url = _GITHUB_RELEASES_API.format(repo=repo)
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": f"blackout-kit/{__version__}"},
        )
        with urllib.request.urlopen(req, timeout=_API_TIMEOUT) as resp:
            data = json.loads(resp.read())
    except Exception:
        return None

    # GitHub returns a JSON with "message" key on errors (404, rate limit)
    if "message" in data and "tag_name" not in data:
        return None

    with _cache_lock:
        _release_cache[repo] = data
    return data


def _find_asset(assets: list[dict], pattern: str, exclude: str | None) -> dict | None:
    """Return the first asset matching the fnmatch pattern, skipping excluded ones."""
    for asset in assets:
        name = asset.get("name", "")
        if not fnmatch.fnmatch(name, pattern):
            continue
        if exclude and exclude in name:
            continue
        return asset
    return None


def _extract_from_zip(zip_path: Path, extract_map: dict[str, str]) -> tuple[bool, str]:
    """
    Extract files from zip_path according to extract_map.
    extract_map: {fnmatch_pattern_for_zip_member: output_filename_in_bins/}

    Tries case-sensitive match first, then case-insensitive fallback.
    Returns (True, "") on success or (False, missing_pattern) on first missing file.
    """
    BINS_DIR.mkdir(parents=True, exist_ok=True)

    try:
        with zipfile.ZipFile(zip_path) as zf:
            members = zf.namelist()
            for pattern, out_name in extract_map.items():
                # Case-sensitive match first
                matched = next(
                    (m for m in members if fnmatch.fnmatch(m, pattern)),
                    None,
                )
                # Case-insensitive fallback
                if matched is None:
                    matched = next(
                        (m for m in members if fnmatch.fnmatch(m.lower(), pattern.lower())),
                        None,
                    )
                if matched is None:
                    return False, pattern

                dest = BINS_DIR / out_name
                dest.write_bytes(zf.read(matched))
    except zipfile.BadZipFile:
        return False, "corrupt_zip"

    return True, ""


# ──────────────────────────── Integrity verification ──────────────

_PE_MAGIC = b"MZ"
_PE_SIGNATURE = b"PE\x00\x00"


def verify_binary(path: Path) -> tuple[bool, str]:
    """
    Verify that a downloaded binary is structurally valid.
    Checks:
      - .exe / .dll files: valid PE header (MZ + PE signature)
      - .sys files: valid PE header (kernel driver)
      - Other files: exists and non-empty

    Returns (True, "") or (False, reason).
    """
    if not path.exists():
        return False, "File not found"

    size = path.stat().st_size
    if size == 0:
        return False, "File is empty (0 bytes)"

    ext = path.suffix.lower()

    if ext in (".exe", ".dll", ".sys"):
        try:
            raw = path.read_bytes()
            if not raw.startswith(_PE_MAGIC):
                return False, "Missing MZ DOS header — not a valid PE executable"
            # PE signature is at offset 0x3C (pointer to PE header)
            pe_offset = int.from_bytes(raw[0x3C:0x40], "little")
            if pe_offset + 4 > len(raw) or raw[pe_offset:pe_offset + 4] != _PE_SIGNATURE:
                return False, (
                    f"PE signature not found (offset {pe_offset:#x}) — "
                    "file is corrupted or not a valid Windows binary"
                )
        except (OSError, MemoryError) as e:
            return False, f"Verification read error: {e}"

    return True, ""


def verify_bins_integrity() -> dict[str, str]:
    """
    Verify ALL binary files in the bins/ directory.
    Returns {filename: "OK" or error_reason}.
    """
    if not BINS_DIR.exists():
        return {}
    results = {}
    for f in BINS_DIR.iterdir():
        if f.is_file() and not f.name.endswith(".json"):
            ok, msg = verify_binary(f)
            results[f.name] = "OK" if ok else msg
    return results


# ──────────────────────────── Public API ─────────────────────────

def check_installed() -> dict[str, bool]:
    """Return {key: True/False} — True when all expected output_bins files exist in bins/."""
    status = {}
    for key, info in BIN_REGISTRY.items():
        status[key] = all((BINS_DIR / b).exists() for b in info.output_bins)
    return status


def get_latest_version(key: str) -> str | None:
    """Return latest GitHub tag for a binary (e.g. 'v26.3.27'), or None."""
    info = BIN_REGISTRY.get(key)
    if not info or not info.github_repo:
        return None
    release = _fetch_release(info.github_repo)
    return release.get("tag_name") if release else None


def list_available() -> list[BinInfo]:
    """Return all registered BinInfo objects."""
    return list(BIN_REGISTRY.values())


def download_binary(
    key: str,
    progress_callback: Callable[[int, int], None] | None = None,
) -> tuple[bool, str]:
    """
    Download and install a single binary by registry key.

    progress_callback(bytes_downloaded, total_bytes):
        Called during streaming download. total_bytes may be 0 if Content-Length is absent.

    Returns (True, success_message) or (False, error_message).
    """
    info = BIN_REGISTRY.get(key)
    if not info:
        return False, f"Unknown binary key: '{key}'. Valid keys: {', '.join(BIN_REGISTRY)}"

    if not info.github_repo:
        if key == "tor":
            return _download_tor_binary(progress_callback)
        elif key == "openvpn":
            return _download_openvpn_binary(progress_callback)
        elif key == "psiphon":
            return _download_psiphon_binary(progress_callback)
        note = f"  Note: {info.manual_note}" if info.manual_note else ""
        return False, f"Manual download required.\n  Visit: {info.manual_url}{note}"

    # ── Fetch release metadata ────────────────────────────────────
    release = _fetch_release(info.github_repo)
    if not release:
        return False, (
            "GitHub API unavailable — check your internet connection.\n"
            f"  Manual fallback: {info.manual_url}"
        )

    # GitHub rate-limit check
    if release.get("message"):
        msg = release["message"]
        if "rate limit" in msg.lower():
            return False, "GitHub API rate limit hit (60 req/hr unauthenticated) — retry in a few minutes."
        return False, f"GitHub API error: {msg}"

    tag    = release.get("tag_name", "unknown")
    assets = release.get("assets", [])

    asset = _find_asset(assets, info.asset_pattern, info.asset_exclude) if info.asset_pattern else None
    asset_name = asset.get("name", "") if asset else ""
    is_zip_mode = asset_name.lower().endswith(".zip") or (info.asset_pattern and info.asset_pattern.lower().endswith(".zip"))

    if is_zip_mode:
        asset = _find_asset(assets, info.asset_pattern, info.asset_exclude)
        if not asset:
            return False, (
                f"No asset matching '{info.asset_pattern}' in release {tag}.\n"
                f"  This may be a repo rename or restructure — check: {info.manual_url}"
            )
        assets_to_download = [(asset, None)]
    else:
        assets_to_download = []
        for pattern, out_name in info.extract_map.items():
            asset = _find_asset(assets, pattern, info.asset_exclude)
            if not asset:
                return False, (
                    f"No asset matching '{pattern}' in release {tag}.\n"
                    f"  This may be a repo rename or restructure — check: {info.manual_url}"
                )
            assets_to_download.append((asset, out_name))

    total_size = sum(a.get("size", 0) for a, _ in assets_to_download)
    downloaded_so_far = 0

    BINS_DIR.mkdir(parents=True, exist_ok=True)

    try:
        if is_zip_mode:
            asset, _ = assets_to_download[0]
            download_url = asset["browser_download_url"]
            tmp_path = None
            try:
                with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
                    tmp_path = Path(tmp.name)

                req = urllib.request.Request(
                    download_url,
                    headers={"User-Agent": f"blackout-kit/{__version__}"},
                )

                asset_downloaded = 0
                with urllib.request.urlopen(req, timeout=_DL_TIMEOUT) as resp:
                    cl = resp.headers.get("Content-Length")
                    if cl:
                        try:
                            asset_size = int(cl)
                            if total_size == 0 or total_size < asset_size:
                                total_size = asset_size
                        except ValueError:
                            pass

                    with open(tmp_path, "wb") as f:
                        while True:
                            chunk = resp.read(65536)
                            if not chunk:
                                break
                            f.write(chunk)
                            asset_downloaded += len(chunk)
                            if progress_callback:
                                progress_callback(asset_downloaded, total_size)

                if not zipfile.is_zipfile(tmp_path):
                    return False, f"Downloaded file is not a valid ZIP (asset: {asset['name']})."

                ok, missing = _extract_from_zip(tmp_path, info.extract_map)
                if not ok:
                    if missing == "corrupt_zip":
                        return False, "ZIP archive is corrupted — try again."
                    return False, (
                        f"Expected file not found in archive: '{missing}'\n"
                        f"  The zip structure may have changed in {tag}. Report at github.com/kiacoder/blackout-kit/issues"
                    )

                # Verify extracted binaries have valid PE headers
                for out_name in info.output_bins:
                    dest = BINS_DIR / out_name
                    ok_verify, msg = verify_binary(dest)
                    if not ok_verify:
                        try:
                            dest.unlink(missing_ok=True)
                        except Exception:
                            pass
                        return False, (
                            f"Integrity check FAILED for {out_name}: {msg}\n"
                            f"  The downloaded file may be corrupted or tampered with.\n"
                            f"  Try again or download manually: {info.manual_url}"
                        )
            finally:
                if tmp_path:
                    try:
                        tmp_path.unlink(missing_ok=True)
                    except Exception:
                        pass
        else:
            for asset, out_name in assets_to_download:
                download_url = asset["browser_download_url"]
                dest_path = BINS_DIR / out_name
                temp_dest = dest_path.with_suffix(".tmp")
                expected_size = asset.get("size", 0)
                try:
                    req = urllib.request.Request(
                        download_url,
                        headers={"User-Agent": f"blackout-kit/{__version__}"},
                    )
                    with urllib.request.urlopen(req, timeout=_DL_TIMEOUT) as resp:
                        with open(temp_dest, "wb") as f:
                            while True:
                                chunk = resp.read(65536)
                                if not chunk:
                                    break
                                f.write(chunk)
                                downloaded_so_far += len(chunk)
                                if progress_callback:
                                    progress_callback(downloaded_so_far, total_size)
                    
                    if expected_size > 0 and temp_dest.stat().st_size != expected_size:
                        raise Exception("Downloaded file size mismatch (truncated or corrupted)")

                    # Verify PE header validity before finalizing
                    ok_verify, msg = verify_binary(temp_dest)
                    if not ok_verify:
                        try:
                            temp_dest.unlink(missing_ok=True)
                        except Exception:
                            pass
                        return False, (
                            f"Integrity check FAILED for {out_name}: {msg}\n"
                            f"  The downloaded file may be corrupted or tampered with.\n"
                            f"  Try again or download manually: {info.manual_url}"
                        )

                    if dest_path.exists():
                        dest_path.unlink()
                    temp_dest.rename(dest_path)
                finally:
                    if temp_dest.exists():
                        try:
                            temp_dest.unlink()
                        except Exception:
                            pass

        return True, f"Installed {info.display_name} ({tag})"

    except urllib.error.URLError as e:
        return False, f"Download failed: {e.reason}"
    except OSError as e:
        return False, f"File system error writing to bins/: {e}"
    except Exception as e:
        return False, f"Unexpected error: {e}"


def download_all(
    skip_installed: bool = True,
    progress_callback: Callable[[str, int, int], None] | None = None,
) -> dict[str, tuple[bool, str]]:
    """
    Download all auto-downloadable binaries in parallel using 10 agents.
    skip_installed: if True, skip keys whose output_bins are already all present.
    progress_callback(key, bytes_done, total_bytes): called per-binary during download.
    Returns {key: (success, message)}.
    """
    installed = check_installed()
    results: dict[str, tuple[bool, str]] = {}

    to_download = []
    for key, info in BIN_REGISTRY.items():
        if not info.github_repo and key not in ("tor", "openvpn"):
            note = info.manual_note or "No auto-download available"
            results[key] = (False, f"Manual only — {note}\n  {info.manual_url}")
            continue

        if skip_installed and installed.get(key):
            results[key] = (True, "Already installed")
            continue

        to_download.append(key)

    def _worker(key: str) -> tuple[str, tuple[bool, str]]:
        def _cb(done: int, total: int):
            if progress_callback:
                progress_callback(key, done, total)
        return key, download_binary(key, progress_callback=_cb)

    # Use 10 agents as requested!
    with ThreadPoolExecutor(max_workers=10) as executor:
        worker_results = executor.map(_worker, to_download)

    for key, res in worker_results:
        results[key] = res

    return results


def _download_tor_binary(progress_callback: Callable[[int, int], None] | None = None) -> tuple[bool, str]:
    """Helper to download and extract Tor Expert Bundle."""
    import re
    import tarfile
    try:
        req = urllib.request.Request(
            "https://dist.torproject.org/torbrowser/",
            headers={"User-Agent": f"blackout-kit/{__version__}"},
        )
        with urllib.request.urlopen(req, timeout=_API_TIMEOUT) as resp:
            html = resp.read().decode("utf-8", errors="ignore")
    except Exception as e:
        return False, f"Failed to connect to Tor archive: {e}"

    versions = []
    for match in re.finditer(r'href="(\d+\.\d+(?:\.\d+)?)/"', html):
        versions.append(match.group(1))
    
    if not versions:
        version = "15.0.19"
    else:
        def version_key(v):
            return [int(x) for x in v.split(".")]
        versions.sort(key=version_key)
        version = versions[-1]

    download_url = f"https://dist.torproject.org/torbrowser/{version}/tor-expert-bundle-windows-x86_64-{version}.tar.gz"
    
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        req = urllib.request.Request(
            download_url,
            headers={"User-Agent": f"blackout-kit/{__version__}"},
        )
        
        with urllib.request.urlopen(req, timeout=_DL_TIMEOUT) as resp:
            cl = resp.headers.get("Content-Length")
            total_size = int(cl) if cl else 0
            downloaded = 0
            with open(tmp_path, "wb") as f:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    if progress_callback:
                        progress_callback(downloaded, total_size or downloaded)

        with tarfile.open(tmp_path, "r:gz") as tf:
            members = tf.getmembers()
            tor_exe_member = next((m for m in members if m.name.endswith("tor.exe")), None)
            if not tor_exe_member:
                return False, "tor.exe not found in downloaded tar.gz"
            
            prefix = ""
            if "/" in tor_exe_member.name:
                prefix = tor_exe_member.name.rsplit("/", 1)[0] + "/"
            
            BINS_DIR.mkdir(parents=True, exist_ok=True)
            for member in members:
                if member.name.startswith(prefix) and not member.isdir():
                    rel_path = member.name[len(prefix):]
                    if "/" not in rel_path:
                        dest = BINS_DIR / rel_path
                        f_in = tf.extractfile(member)
                        if f_in:
                            dest.write_bytes(f_in.read())
        
        return True, f"Installed Tor (Expert Bundle) v{version}"
    except Exception as e:
        return False, f"Tor download/extraction failed: {e}"
    finally:
        if tmp_path and tmp_path.exists():
            try:
                tmp_path.unlink()
            except Exception:
                pass


def _download_openvpn_binary(progress_callback: Callable[[int, int], None] | None = None) -> tuple[bool, str]:
    """Helper to download OpenVPN MSI and extract openvpn.exe and DLLs using msiexec."""
    import re
    import subprocess
    import shutil
    try:
        req = urllib.request.Request(
            "https://build.openvpn.net/downloads/releases/",
            headers={"User-Agent": f"blackout-kit/{__version__}"},
        )
        with urllib.request.urlopen(req, timeout=_API_TIMEOUT) as resp:
            html = resp.read().decode("utf-8", errors="ignore")
    except Exception as e:
        return False, f"Failed to connect to OpenVPN build archive: {e}"

    msi_files = []
    for match in re.finditer(r'href="(OpenVPN-[\d\.\-]+-amd64\.msi)"', html):
        msi_files.append(match.group(1))

    if not msi_files:
        msi_file = "OpenVPN-2.7.5-I001-amd64.msi"
    else:
        def msi_key(name):
            parts = re.findall(r'\d+', name)
            return [int(x) for x in parts]
        msi_files.sort(key=msi_key)
        msi_file = msi_files[-1]

    download_url = f"https://build.openvpn.net/downloads/releases/{msi_file}"

    tmp_path = None
    temp_dir = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".msi", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        req = urllib.request.Request(
            download_url,
            headers={"User-Agent": f"blackout-kit/{__version__}"},
        )
        
        with urllib.request.urlopen(req, timeout=_DL_TIMEOUT) as resp:
            cl = resp.headers.get("Content-Length")
            total_size = int(cl) if cl else 0
            downloaded = 0
            with open(tmp_path, "wb") as f:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    if progress_callback:
                        progress_callback(downloaded, total_size or downloaded)

        temp_dir = Path(tempfile.mkdtemp())
        
        cmd = ["msiexec", "/a", str(tmp_path), "/qb", f"TARGETDIR={temp_dir}"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            cmd = ["msiexec", "/a", str(tmp_path), "/qn", f"TARGETDIR={temp_dir}"]
            subprocess.run(cmd, check=True)

        openvpn_exe = None
        for p in temp_dir.rglob("openvpn.exe"):
            openvpn_exe = p
            break
        
        if not openvpn_exe:
            return False, "openvpn.exe not found in extracted MSI contents"

        bin_dir = openvpn_exe.parent
        BINS_DIR.mkdir(parents=True, exist_ok=True)
        
        for item in bin_dir.iterdir():
            if item.is_file() and (item.suffix.lower() == ".exe" or item.suffix.lower() == ".dll"):
                shutil.copy(item, BINS_DIR / item.name)

        return True, f"Installed OpenVPN (extracted from {msi_file})"
    except Exception as e:
        return False, f"OpenVPN download/extraction failed: {e}"
    finally:
        if tmp_path and tmp_path.exists():
            try:
                tmp_path.unlink()
            except Exception:
                pass
        if temp_dir and temp_dir.exists():
            try:
                shutil.rmtree(temp_dir)
            except Exception:
                pass


def _download_psiphon_binary(progress_callback: Callable[[int, int], None] | None = None) -> tuple[bool, str]:
    """Helper to download Psiphon console binary directly."""
    download_url = "https://raw.githubusercontent.com/Psiphon-Inc/psiphon-tunnel-core/master/psiphon-tunnel-core-x86_64.exe"
    dest_path = BINS_DIR / "psiphon-tunnel-core.exe"
    BINS_DIR.mkdir(parents=True, exist_ok=True)
    temp_dest = dest_path.with_suffix(".tmp")
    try:
        req = urllib.request.Request(
            download_url,
            headers={"User-Agent": f"blackout-kit/{__version__}"},
        )
        with urllib.request.urlopen(req, timeout=_DL_TIMEOUT) as resp:
            cl = resp.headers.get("Content-Length")
            total_size = int(cl) if cl else 0
            downloaded = 0
            with open(temp_dest, "wb") as f:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    if progress_callback:
                        progress_callback(downloaded, total_size or downloaded)

        if dest_path.exists():
            dest_path.unlink()
        temp_dest.rename(dest_path)
        return True, "Installed Psiphon Tunnel Core"
    except Exception as e:
        return False, f"Psiphon download failed: {e}"
    finally:
        if temp_dest.exists():
            try:
                temp_dest.unlink()
            except Exception:
                pass
