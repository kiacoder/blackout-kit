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
import hashlib
import json
import os
import sys
import tempfile
import threading
import urllib.error
import urllib.request
import zipfile
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from . import BINS_DIR, __version__

_PROVENANCE_FILE = BINS_DIR / ".provenance.json"
_DOWNLOAD_LOCK = threading.Lock()

_GITHUB_RELEASES_API = "https://api.github.com/repos/{repo}/releases/latest"
_API_TIMEOUT         = 10    # seconds — GitHub API lookup
_DL_TIMEOUT          = 300   # seconds — binary download (5 min for large files)

# Per-session cache: repo → release dict — avoids hammering the 60 req/hr rate limit
_release_cache: dict[str, dict] = {}
_cache_lock = threading.Lock()

# Per-session cache: installed binaries status — invalidated on download
_check_installed_cache: dict[str, bool] | None = None
_check_installed_lock = threading.Lock()


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

    "linux_engine": BinInfo(
        key           = "linux_engine",
        display_name  = "Blackout Engine (Linux x86_64)",
        description   = "Embedded XRay and sing-box runtime for Linux TUN",
        github_repo   = "kiacoder/blackout-kit",
        asset_pattern = "blackout-engine-linux-amd64",
        asset_exclude = None,
        extract_map   = {"blackout-engine-linux-amd64": "blackout-engine"},
        output_bins   = ["blackout-engine"],
        required      = False,
        manual_url    = "https://github.com/kiacoder/blackout-kit/releases",
        manual_note   = "Download the Linux x86_64 engine asset and place it in bins/ as blackout-engine.",
    ),

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
        display_name  = "SoftEther VPN installer",
        description   = "SoftEther VPN installer (not the client runtime)",
        github_repo   = "SoftEtherVPN/SoftEtherVPN_Stable",
        asset_pattern = None,
        asset_exclude = None,
        extract_map   = {"softether-vpnclient-*.exe": "softether-installer.exe"},
        output_bins   = ["softether-installer.exe"],
        required      = False,
        manual_url    = "https://github.com/SoftEtherVPN/SoftEtherVPN_Stable/releases",
        manual_note   = "Run the installer, then make vpnclient.exe and vpncmd.exe available before connecting.",
    ),

    "softether-client": BinInfo(
        key           = "softether-client",
        display_name  = "SoftEther VPN client runtime",
        description   = "vpnclient.exe and vpncmd.exe required for SoftEther connections",
        github_repo   = None,
        asset_pattern   = None,
        asset_exclude   = None,
        extract_map     = {},
        output_bins     = ["vpnclient.exe", "vpncmd.exe"],
        required        = False,
        manual_url      = "https://www.softether.org/5-download",
        manual_note     = "Install SoftEther VPN Client or place both client executables in bins/.",
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


def _extract_from_zip(
    zip_path: Path,
    extract_map: dict[str, str],
    destination: Path | None = None,
) -> tuple[bool, str]:
    """
    Extract files from zip_path according to extract_map.
    extract_map: {fnmatch_pattern_for_zip_member: output_filename_in_bins/}

    Tries case-sensitive match first, then case-insensitive fallback.
    Returns (True, "") on success or (False, missing_pattern) on first missing file.
    """
    output_dir = destination or BINS_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

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

                try:
                    dest = output_dir / out_name
                    resolved = dest.resolve()
                    if not resolved.is_relative_to(output_dir.resolve()):
                        return False, "unsafe_output_path"
                    dest.write_bytes(zf.read(matched))
                except OSError as exc:
                    return False, f"write_error: {exc}"
    except zipfile.BadZipFile:
        return False, "corrupt_zip"
    except Exception as exc:
        return False, f"extract_error: {exc}"

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
    if not path.is_file():
        return False, "File not found"

    size = path.stat().st_size
    if size == 0:
        return False, "File is empty (0 bytes)"

    ext = path.suffix.lower()

    try:
        raw = path.read_bytes()
    except (OSError, MemoryError) as exc:
        return False, f"Verification read error: {exc}"

    if ext in (".exe", ".dll", ".sys"):
        if not raw.startswith(_PE_MAGIC):
            return False, "Missing MZ DOS header — not a valid PE executable"
        # PE signature is at offset 0x3C (pointer to PE header)
        pe_offset = int.from_bytes(raw[0x3C:0x40], "little")
        if pe_offset + 4 > len(raw) or raw[pe_offset:pe_offset + 4] != _PE_SIGNATURE:
            return False, (
                f"PE signature not found (offset {pe_offset:#x}) — "
                "file is corrupted or not a valid Windows binary"
            )
    elif path.name == "blackout-engine" or path.name.startswith("blackout-engine-linux-"):
        if not raw.startswith(b"\x7fELF"):
            return False, "Missing ELF header — not a valid Linux executable"

    return True, ""


def sha256_file(path: Path) -> str:
    """Return the SHA-256 digest of one local file in bounded chunks."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _asset_sha256(asset: dict) -> str | None:
    value = asset.get("digest")
    if not isinstance(value, str):
        return None
    algorithm, separator, digest = value.partition(":")
    if separator != ":" or algorithm.lower() != "sha256":
        return None
    normalized = digest.strip().lower()
    if len(normalized) != 64 or any(char not in "0123456789abcdef" for char in normalized):
        return None
    return normalized


def _verify_download_digest(path: Path, asset: dict) -> tuple[bool, str]:
    expected = _asset_sha256(asset)
    if expected is None:
        return False, "Trusted SHA-256 digest metadata is missing for this release asset"
    actual = sha256_file(path)
    if actual != expected:
        return False, "Downloaded release asset SHA-256 does not match trusted metadata"
    return True, ""


def _promote_staged_outputs(
    staged_dir: Path,
    output_names: list[str],
    provenance: list[dict[str, str]] | None = None,
) -> tuple[bool, str]:
    """Promote verified outputs and provenance as one recoverable transaction."""
    import os
    import shutil

    BINS_DIR.mkdir(parents=True, exist_ok=True)
    bins_root = BINS_DIR.resolve()
    backup_dir = Path(tempfile.mkdtemp(prefix=".blackout-backup-", dir=BINS_DIR))
    backups: dict[str, Path] = {}
    promoted: list[Path] = []
    provenance_backup = backup_dir / ".provenance.json"
    provenance_existed = _PROVENANCE_FILE.is_file()
    try:
        if provenance_existed:
            shutil.copy2(_PROVENANCE_FILE, provenance_backup)

        for name in output_names:
            source = staged_dir / name
            destination = BINS_DIR / name
            if not source.is_file():
                return False, f"Expected staged output is missing: {name}"
            resolved = destination.resolve()
            if not resolved.is_relative_to(bins_root):
                return False, "unsafe_output_path"
            if destination.exists():
                backup = backup_dir / name
                backup.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(destination, backup)
                backups[name] = backup

        for name in output_names:
            destination = BINS_DIR / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            os.replace(staged_dir / name, destination)
            promoted.append(destination)

        if provenance is not None:
            _merge_provenance(provenance)
        return True, ""
    except Exception as exc:
        for destination in promoted:
            try:
                destination.unlink(missing_ok=True)
            except OSError:
                pass
        for name, backup in backups.items():
            try:
                os.replace(backup, BINS_DIR / name)
            except OSError:
                pass
        try:
            if provenance_existed:
                os.replace(provenance_backup, _PROVENANCE_FILE)
            else:
                _PROVENANCE_FILE.unlink(missing_ok=True)
        except OSError:
            pass
        return False, f"Could not install verified outputs: {exc}"
    finally:
        shutil.rmtree(backup_dir, ignore_errors=True)


# ──────────────────────────── Public API ─────────────────────────

def _artifact_status(info: BinInfo) -> str:
    outputs = [BINS_DIR / name for name in info.output_bins]
    if not all(path.is_file() for path in outputs):
        return "missing"
    provenance = {
        record.get("output"): record
        for record in _read_provenance()
        if record.get("output")
    }
    for path in outputs:
        valid, _detail = verify_binary(path)
        if not valid:
            return "invalid"
        if (
            sys.platform.startswith("linux")
            and path.name == "blackout-engine"
            and not os.access(path, os.X_OK)
        ):
            return "invalid"
        record = provenance.get(path.name)
        if record is not None:
            expected = record.get("output_sha256") or record.get("sha256", "")
            if not expected or sha256_file(path) != expected.lower():
                return "invalid"
    return "verified" if all(path.name in provenance for path in outputs) else "manual_unverified"


def artifact_status() -> dict[str, str]:
    """Return safe installation states for each registered artifact."""
    status = {key: _artifact_status(info) for key, info in BIN_REGISTRY.items()}
    softether_dir = Path("C:/Program Files/SoftEther VPN Client")
    client_files = [BINS_DIR / name for name in ("vpnclient.exe", "vpncmd.exe")]
    system_files = [softether_dir / name for name in ("vpnclient.exe", "vpncmd.exe")]
    status["softether-client"] = (
        "manual_unverified"
        if all(path.is_file() for path in client_files)
        or (sys.platform == "win32" and all(path.is_file() for path in system_files))
        else "missing"
    )
    return status


def check_installed() -> dict[str, bool]:
    """Return {key: True/False} for current structurally valid artifacts."""
    with _check_installed_lock:
        return {
            key: state in {"verified", "manual_unverified"}
            for key, state in artifact_status().items()
        }


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


def _download_stream(
    url: str,
    destination: Path,
    *,
    expected_size: int = 0,
    progress_callback: Callable[[int, int], None] | None = None,
    total_size: int = 0,
    downloaded_so_far: int = 0,
) -> tuple[bool, str, int]:
    """Download one asset to a staging file and return its byte count."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": f"blackout-kit/{__version__}"},
    )
    downloaded = 0
    with urllib.request.urlopen(req, timeout=_DL_TIMEOUT) as resp:
        with destination.open("wb") as stream:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                stream.write(chunk)
                downloaded += len(chunk)
                if progress_callback:
                    progress_callback(downloaded_so_far + downloaded, total_size)
    if expected_size > 0 and downloaded != expected_size:
        return False, "Downloaded file size mismatch (truncated or corrupted)", downloaded
    return True, "", downloaded


def download_binary(
    key: str,
    progress_callback: Callable[[int, int], None] | None = None,
) -> tuple[bool, str]:
    return _download_verified_binary(key, progress_callback)


def _trusted_download_url(url: str) -> bool:
    from urllib.parse import urlsplit

    parsed = urlsplit(str(url or ""))
    return parsed.scheme == "https" and parsed.hostname in {
        "github.com",
        "objects.githubusercontent.com",
        "raw.githubusercontent.com",
    }


def _read_provenance() -> list[dict[str, str]]:
    try:
        payload = json.loads(_PROVENANCE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return []
    records = payload.get("artifacts") if isinstance(payload, dict) else None
    if not isinstance(records, list):
        return []
    return [
        {str(key): str(value) for key, value in record.items()}
        for record in records
        if isinstance(record, dict)
    ]


def _write_provenance(records: list[dict[str, str]]) -> None:
    payload = {"schema_version": 1, "artifacts": records}
    BINS_DIR.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=BINS_DIR, prefix=".provenance-", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, sort_keys=True, separators=(",", ":"))
        Path(temporary).replace(_PROVENANCE_FILE)
    except Exception:
        try:
            Path(temporary).unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _merge_provenance(records: list[dict[str, str]]) -> None:
    merged = _read_provenance()
    by_output = {
        record.get("output") or record.get("key"): record
        for record in merged
        if record.get("output") or record.get("key")
    }
    for record in records:
        identity = record.get("output") or record.get("key")
        if identity:
            by_output[identity] = record
    _write_provenance(list(by_output.values()))


def verify_provenance() -> dict[str, str]:
    """Compare installed artifact hashes with recorded verified provenance."""
    results: dict[str, str] = {}
    for record in _read_provenance():
        output = record.get("output")
        expected = (record.get("output_sha256") or record.get("sha256", "")).lower()
        if not output:
            continue
        path = BINS_DIR / output
        if not path.is_file():
            results[output] = "missing"
            continue
        if expected and sha256_file(path) == expected:
            results[output] = "OK"
        else:
            results[output] = "modified"
    return results


def verify_bins_integrity() -> dict[str, str]:
    """Verify structure and, when available, recorded artifact hashes."""
    results = {}
    if BINS_DIR.exists():
        for path in BINS_DIR.iterdir():
            if path.is_file() and not path.name.endswith(".json"):
                ok, message = verify_binary(path)
                results[path.name] = "OK" if ok else message
    for name, status in verify_provenance().items():
        if status != "OK":
            results[name] = f"Provenance {status}"
    return results


def _download_verified_binary(
    key: str,
    progress_callback: Callable[[int, int], None] | None = None,
) -> tuple[bool, str]:
    """Download one release only after digest and structural verification."""
    global _check_installed_cache
    with _DOWNLOAD_LOCK:
        with _check_installed_lock:
            _check_installed_cache = None

        info = BIN_REGISTRY.get(key)
        if not info:
            return False, f"Unknown binary key: '{key}'. Valid keys: {', '.join(BIN_REGISTRY)}"
        if not info.github_repo:
            note = f"  Note: {info.manual_note}" if info.manual_note else ""
            return False, f"Manual download required; Blackout Kit cannot verify this source automatically.\n  Visit: {info.manual_url}{note}"

        release = _fetch_release(info.github_repo)
        if not release:
            return False, (
                "GitHub API unavailable — check your internet connection.\n"
                f"  Manual fallback: {info.manual_url}"
            )
        if release.get("message"):
            message = str(release["message"])
            if "rate limit" in message.lower():
                return False, "GitHub API rate limit hit (60 req/hr unauthenticated) — retry in a few minutes."
            return False, f"GitHub API error: {message}"

        tag = str(release.get("tag_name", "unknown"))
        assets = release.get("assets", [])
        asset = _find_asset(assets, info.asset_pattern, info.asset_exclude) if info.asset_pattern else None
        asset_name = str(asset.get("name", "")) if asset else ""
        is_zip_mode = asset_name.lower().endswith(".zip") or bool(
            info.asset_pattern and info.asset_pattern.lower().endswith(".zip")
        )

        if is_zip_mode:
            if asset is None:
                return False, f"No asset matching '{info.asset_pattern}' in release {tag}."
            assets_to_download = [(asset, None)]
        else:
            assets_to_download = []
            for pattern, output_name in info.extract_map.items():
                selected = _find_asset(assets, pattern, info.asset_exclude)
                if selected is None:
                    return False, f"No asset matching '{pattern}' in release {tag}."
                assets_to_download.append((selected, output_name))

        for selected, _output_name in assets_to_download:
            url = selected.get("browser_download_url")
            if not _trusted_download_url(url):
                return False, "Release asset URL is not an allowed HTTPS GitHub download URL"
            if _asset_sha256(selected) is None:
                return False, "Trusted SHA-256 digest metadata is missing for this release asset"

        stage_dir = Path(tempfile.mkdtemp(prefix="blackout-download-"))
        provenance: list[dict[str, str]] = []
        try:
            total_size = sum(int(selected.get("size", 0) or 0) for selected, _ in assets_to_download)
            downloaded = 0
            if is_zip_mode:
                selected, _ = assets_to_download[0]
                archive = stage_dir / "release.zip"
                ok, message, size = _download_stream(
                    selected["browser_download_url"],
                    archive,
                    expected_size=int(selected.get("size", 0) or 0),
                    progress_callback=progress_callback,
                    total_size=total_size,
                    downloaded_so_far=downloaded,
                )
                if not ok:
                    return False, message
                ok, message = _verify_download_digest(archive, selected)
                if not ok:
                    return False, message
                if not zipfile.is_zipfile(archive):
                    return False, f"Downloaded file is not a valid ZIP (asset: {selected.get('name', '')})."
                ok, missing = _extract_from_zip(archive, info.extract_map, stage_dir)
                if not ok:
                    return False, f"Archive extraction failed: {missing}"
                digest = _asset_sha256(selected) or ""
                for output_name in info.output_bins:
                    staged = stage_dir / output_name
                    if output_name == "blackout-engine" and sys.platform.startswith("linux"):
                        staged.chmod(staged.stat().st_mode | 0o111)
                    valid, detail = verify_binary(staged)
                    if not valid:
                        return False, f"Structural verification failed for {output_name}: {detail}"
                    provenance.append({
                        "key": info.key,
                        "output": output_name,
                        "repository": info.github_repo,
                        "release": tag,
                        "asset": str(selected.get("name", "")),
                        "sha256": digest,
                        "output_sha256": sha256_file(staged),
                        "verification": "sha256_and_structural",
                    })
            else:
                for selected, output_name in assets_to_download:
                    staged = stage_dir / str(output_name)
                    ok, message, size = _download_stream(
                        selected["browser_download_url"],
                        staged,
                        expected_size=int(selected.get("size", 0) or 0),
                        progress_callback=progress_callback,
                        total_size=total_size,
                        downloaded_so_far=downloaded,
                    )
                    if not ok:
                        return False, message
                    downloaded += size
                    ok, message = _verify_download_digest(staged, selected)
                    if not ok:
                        return False, message
                    valid, detail = verify_binary(staged)
                    if not valid:
                        return False, f"Structural verification failed for {output_name}: {detail}"
                    provenance.append({
                        "key": info.key,
                        "output": str(output_name),
                        "repository": info.github_repo,
                        "release": tag,
                        "asset": str(selected.get("name", "")),
                        "sha256": _asset_sha256(selected) or "",
                        "output_sha256": sha256_file(staged),
                        "verification": "sha256_and_structural",
                    })

            ok, message = _promote_staged_outputs(stage_dir, info.output_bins, provenance)
            if not ok:
                return False, message
            return True, f"Installed {info.display_name} ({tag}); SHA-256 verified"
        except urllib.error.URLError as exc:
            return False, f"Download failed: {exc.reason}"
        except OSError as exc:
            return False, f"File system error writing to bins/: {exc}"
        except Exception as exc:
            return False, f"Unexpected error: {exc}"
        finally:
            import shutil
            shutil.rmtree(stage_dir, ignore_errors=True)


# Manual source helpers remain private and are intentionally not used by the
# verified automatic download path. Manual files are always labeled unverified.


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
            try:
                total_size = int(cl) if cl else 0
            except ValueError:
                total_size = 0
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
    import shutil
    import subprocess
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
            try:
                total_size = int(cl) if cl else 0
            except ValueError:
                total_size = 0
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
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        except subprocess.TimeoutExpired:
            return False, "OpenVPN MSI extraction timed out (120s)"
        if result.returncode != 0:
            cmd = ["msiexec", "/a", str(tmp_path), "/qn", f"TARGETDIR={temp_dir}"]
            try:
                subprocess.run(cmd, check=True, timeout=120)
            except subprocess.TimeoutExpired:
                return False, "OpenVPN MSI extraction timed out (120s)"
            except subprocess.CalledProcessError as e:
                return False, f"MSI extraction failed (exit code {e.returncode})"

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
            try:
                total_size = int(cl) if cl else 0
            except ValueError:
                total_size = 0
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
