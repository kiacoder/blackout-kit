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

PROJECT_ROOT = Path(__file__).parent.parent
BINS_DIR     = PROJECT_ROOT / "bins"

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

    "xray": BinInfo(
        key           = "xray",
        display_name  = "Xray-core",
        description   = "V2Ray core — required for SNI and most configs",
        github_repo   = "XTLS/Xray-core",
        asset_pattern = "Xray-windows-64.zip",
        asset_exclude = None,
        extract_map   = {"xray.exe": "xray.exe"},
        output_bins   = ["xray.exe"],
        required      = True,
        manual_url    = "https://github.com/XTLS/Xray-core/releases",
        manual_note   = "",
    ),

    "goodbyedpi": BinInfo(
        key           = "goodbyedpi",
        display_name  = "GoodbyeDPI + WinDivert",
        description   = "TCP fragmentation bypass — includes WinDivert kernel driver",
        github_repo   = "ValdikSS/GoodbyeDPI",
        asset_pattern = "goodbyedpi-*.zip",
        asset_exclude = None,
        extract_map   = {
            "*/x86_64/goodbyedpi.exe":  "goodbyedpi.exe",
            "*/x86_64/WinDivert.dll":   "WinDivert.dll",
            "*/x86_64/WinDivert64.sys": "WinDivert64.sys",
        },
        output_bins   = ["goodbyedpi.exe", "WinDivert.dll", "WinDivert64.sys"],
        required      = False,
        manual_url    = "https://github.com/ValdikSS/GoodbyeDPI/releases",
        manual_note   = "",
    ),

    "sing-box": BinInfo(
        key           = "sing-box",
        display_name  = "sing-box",
        description   = "TUN mode — system-wide transparent proxy (no proxy port needed)",
        github_repo   = "SagerNet/sing-box",
        asset_pattern = "sing-box-*-windows-amd64.zip",
        asset_exclude = "legacy",   # skip sing-box-*-legacy-windows-7.zip
        extract_map   = {"*/sing-box.exe": "sing-box.exe"},
        output_bins   = ["sing-box.exe"],
        required      = False,
        manual_url    = "https://github.com/SagerNet/sing-box/releases",
        manual_note   = "",
    ),

    "warp-plus": BinInfo(
        key           = "warp-plus",
        display_name  = "WARP+",
        description   = "Cloudflare WARP — clean IPs, fewer captchas, partial blackouts",
        github_repo   = "bepass-org/warp-plus",
        asset_pattern = "warp-plus_windows-amd64.zip",
        asset_exclude = None,
        extract_map   = {"warp-plus.exe": "warp-plus.exe"},
        output_bins   = ["warp-plus.exe"],
        required      = False,
        manual_url    = "https://github.com/bepass-org/warp-plus/releases",
        manual_note   = "",
    ),

    "sni-spoofing": BinInfo(
        key           = "sni-spoofing",
        display_name  = "SNI Spoofing",
        description   = "SNI packet injector — required for the sni engine",
        github_repo   = None,   # Only .rar format — Python cannot extract without external tool
        asset_pattern = None,
        asset_exclude = None,
        extract_map   = {},
        output_bins   = ["SNI-Spoofing_by_patterniha_v1.exe"],
        required      = True,
        manual_url    = "https://github.com/patterniha/SNI-Spoofing/releases",
        manual_note   = "Release is .rar format — extract manually with WinRAR or 7-Zip",
    ),

    "psiphon": BinInfo(
        key           = "psiphon",
        display_name  = "Psiphon Tunnel Core",
        description   = "Psiphon VPN — last resort for heavy blackouts",
        github_repo   = None,   # Official releases only have Android/iOS libraries
        asset_pattern = None,
        asset_exclude = None,
        extract_map   = {},
        output_bins   = ["psiphon-tunnel-core-x86_64.exe"],
        required      = False,
        manual_url    = "https://github.com/Psiphon-Labs/psiphon-tunnel-core",
        manual_note   = "No pre-built Windows binary in releases — build from source (Go)",
    ),

    "mhrv": BinInfo(
        key           = "mhrv",
        display_name  = "mhrv-rs",
        description   = "Master HTTP Relay VPN (Rust) — MITM relay via Google Apps Script",
        github_repo   = "therealaleph/MasterHttpRelayVPN-RUST",
        asset_pattern = "mhrv-rs-windows-amd64.zip",
        asset_exclude = None,
        extract_map   = {"mhrv-rs.exe": "mhrv-rs.exe"},
        output_bins   = ["mhrv-rs.exe"],
        required      = False,
        manual_url    = "https://github.com/therealaleph/MasterHttpRelayVPN-RUST/releases",
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
        asset_pattern = None,
        asset_exclude = None,
        extract_map   = {"wireguard.exe": "wireguard.exe", "wg.exe": "wg.exe"},
        output_bins   = ["wireguard.exe", "wg.exe"],
        required      = False,
        manual_url    = "https://github.com/DrEm-s/wireguard-windows-portable/releases",
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


# ──────────────────────────── Public API ─────────────────────────

def check_installed() -> dict[str, bool]:
    """Return {key: True/False} — True when all expected output_bins files exist in bins/."""
    engine_bin = BINS_DIR / "blackout-engine.exe"
    engine_dll = BINS_DIR / "blackout_core.dll"
    has_engine = engine_bin.exists() or engine_dll.exists()
    status = {}
    for key, info in BIN_REGISTRY.items():
        if has_engine and key in ("xray", "sing-box", "mhrv", "sni-spoofing"):
            status[key] = True
        else:
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

    is_zip_mode = info.asset_pattern is not None

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
        if not info.github_repo:
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
