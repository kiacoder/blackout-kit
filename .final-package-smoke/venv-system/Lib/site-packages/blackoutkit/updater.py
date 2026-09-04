"""
Blackout Kit - Auto-updater and preflight readiness checker.

Auto-updater:
  Checks GitHub releases API for new Python source files.
  Downloads and replaces the blackoutkit/ package on update.
  Does NOT update binaries in bins/ — user manages those manually.

Preflight (offline-first readiness):
  Verifies the tool is ready for use during a complete internet blackout.
  Checks: binaries present, configs saved, scan cache fresh, configs decryptable.
"""
import hashlib
import json
import shutil
import sys
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path


from . import __version__

from . import PROJECT_ROOT, APP_DATA_DIR
GITHUB_REPO   = "kiacoder/blackout-kit"
RELEASES_API  = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
UPDATE_TIMEOUT = 10  # seconds
_UPDATE_TRUSTED_HOSTS = frozenset({
    "github.com",
    "api.github.com",
    "objects.githubusercontent.com",
    "raw.githubusercontent.com",
})


# ─────────────────────────── Version helpers ────────────────────

def _parse_version(v: str) -> tuple[int, ...]:
    """Convert "1.2.3" → (1, 2, 3) for comparison."""
    v = v.lstrip("v")
    try:
        return tuple(int(x) for x in v.split("."))
    except Exception:
        return (0, 0, 0)


def check_for_update() -> dict | None:
    """
    Check GitHub releases API for a newer version.
    Returns release info dict on update available, None if up-to-date or no internet.
    """
    try:
        req = urllib.request.Request(
            RELEASES_API,
            headers={"User-Agent": f"blackout-kit/{__version__}"},
        )
        with urllib.request.urlopen(req, timeout=UPDATE_TIMEOUT) as resp:
            data = json.loads(resp.read())
    except Exception:
        return None  # No internet or API down — that's fine

    latest_tag = data.get("tag_name", "")
    latest_ver = _parse_version(latest_tag)
    current    = _parse_version(__version__)

    if latest_ver <= current:
        return None  # Already up-to-date

    assets = data.get("assets", [])
    source_asset = next(
        (
            asset for asset in assets
            if isinstance(asset, dict)
            and str(asset.get("name", "")).lower() == "blackout-source.zip"
        ),
        None,
    )

    return {
        "version": latest_tag,
        "body": data.get("body", "No release notes."),
        "zipball_url": source_asset.get("browser_download_url", "") if source_asset else "",
        "source_asset": source_asset,
        "html_url": data.get("html_url", ""),
        "assets": assets,
    }


def _asset_digest(asset: dict | None) -> str | None:
    value = asset.get("digest") if isinstance(asset, dict) else None
    if not isinstance(value, str):
        return None
    algorithm, separator, digest = value.partition(":")
    digest = digest.strip().lower()
    if separator != ":" or algorithm.lower() != "sha256" or len(digest) != 64:
        return None
    if any(char not in "0123456789abcdef" for char in digest):
        return None
    return digest


def _trusted_update_url(url: str) -> bool:
    from urllib.parse import urlsplit

    parsed = urlsplit(str(url or ""))
    return parsed.scheme == "https" and parsed.hostname in _UPDATE_TRUSTED_HOSTS


def _release_update_asset(release: dict, *, frozen: bool) -> tuple[str | None, dict | None, str]:
    if frozen:
        asset = next(
            (
                item for item in release.get("assets", [])
                if isinstance(item, dict) and str(item.get("name", "")).lower() == "blackout.exe"
            ),
            None,
        )
        return (asset.get("browser_download_url") if asset else None, asset, ".exe")
    url = release.get("zipball_url", "")
    asset = release.get("source_asset")
    return (str(url) if url else None, asset if isinstance(asset, dict) else None, ".zip")


def download_and_apply(release: dict) -> bool:
    """Download and apply an update only after trusted digest verification."""
    from .theme import console
    import os
    import subprocess

    is_frozen = getattr(sys, "frozen", False)
    url, asset, suffix = _release_update_asset(release, frozen=is_frozen)
    if not url or not _trusted_update_url(url):
        console.print("[error]Update source is not an approved HTTPS GitHub URL.[/error]")
        return False
    expected_digest = _asset_digest(asset)
    if expected_digest is None:
        console.print("[error]Update rejected: trusted SHA-256 digest metadata is missing.[/error]")
        return False

    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            tmp_path = Path(tmp.name)

        req = urllib.request.Request(url, headers={"User-Agent": f"blackout-kit/{__version__}"})
        hasher = hashlib.sha256()
        with urllib.request.urlopen(req, timeout=120) as resp:
            content_length = int(resp.headers.get("Content-Length", 0) or 0)
            from .theme import create_download_progress
            with create_download_progress() as progress:
                task = progress.add_task(
                    f"Downloading update ({suffix})...",
                    total=content_length if content_length > 0 else None,
                )
                with tmp_path.open("wb") as stream:
                    while True:
                        chunk = resp.read(8192)
                        if not chunk:
                            break
                        stream.write(chunk)
                        hasher.update(chunk)
                        progress.advance(task, len(chunk))

        actual_digest = hasher.hexdigest()
        if actual_digest != expected_digest:
            console.print("[error]Update rejected: SHA-256 does not match trusted metadata.[/error]")
            return False

        if is_frozen:
            from .downloader import verify_binary

            valid, detail = verify_binary(tmp_path)
            if not valid:
                console.print(f"[error]Update rejected: invalid executable structure ({detail}).[/error]")
                return False
            current_exe = Path(sys.executable)
            old_exe = current_exe.with_name(current_exe.name + ".old")
            if old_exe.exists():
                old_exe.unlink()
            os.rename(current_exe, old_exe)
            shutil.move(str(tmp_path), current_exe)
            console.print("  [bold green]Update applied successfully![/bold green]")
            subprocess.Popen([str(current_exe)] + sys.argv[1:], creationflags=0x00000008)
            sys.exit(0)

        with zipfile.ZipFile(tmp_path) as zf:
            bad_file = zf.testzip()
            if bad_file:
                console.print(f"[error]Corrupt archive entry: {bad_file}[/error]")
                return False
            names = zf.namelist()
            if not names:
                console.print("[error]Archive is empty (no files).[/error]")
                return False
            prefix = names[0].split("/")[0] + "/"
            backup_dir = APP_DATA_DIR / "backup_src"
            if backup_dir.exists():
                shutil.rmtree(backup_dir)
            backup_dir.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(PROJECT_ROOT / "blackoutkit", backup_dir)
            for member in names:
                if not member.startswith(prefix + "blackoutkit/"):
                    continue
                relative = member[len(prefix):]
                dest = PROJECT_ROOT / relative
                if not dest.resolve().is_relative_to((PROJECT_ROOT / "blackoutkit").resolve()):
                    raise ValueError("Path traversal attempt detected")
                if member.endswith("/"):
                    dest.mkdir(parents=True, exist_ok=True)
                else:
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(zf.read(member))
        return True
    except zipfile.BadZipFile:
        console.print("[error]Downloaded file is not a valid ZIP archive.[/error]")
        return False
    except Exception as exc:
        console.print(f"[error]Update failed: {exc}[/error]")
        if not is_frozen:
            backup = APP_DATA_DIR / "backup_src"
            if backup.exists():
                try:
                    failed_dir = PROJECT_ROOT / f"blackoutkit_failed_{int(time.time())}"
                    if (PROJECT_ROOT / "blackoutkit").exists():
                        os.rename(PROJECT_ROOT / "blackoutkit", failed_dir)
                    os.rename(backup, PROJECT_ROOT / "blackoutkit")
                except Exception:
                    pass
        return False
    finally:
        if tmp_path:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass


# ─────────────────────────── Preflight check ────────────────────

class PreflightResult:
    def __init__(self, name: str, ok: bool, critical: bool, message: str):
        self.name     = name
        self.ok       = ok
        self.critical = critical  # Critical failures = tool will NOT work offline
        self.message  = message


def run_preflight() -> list[PreflightResult]:
    """
    Check if Blackout Kit is ready for use during a complete internet blackout.
    Returns list of PreflightResult items.
    """
    results: list[PreflightResult] = []
    from . import BINS_DIR
    bins_dir = BINS_DIR

    from .downloader import BIN_REGISTRY, check_installed
    installed = check_installed()
    engine_bin = bins_dir / "blackout-engine.exe"
    has_engine = engine_bin.exists()

    # ── Binary Registry checks ───────────────────────────────────
    for key, info in BIN_REGISTRY.items():
        if info.required:
            name_prefix = "Required"
            is_critical = True
        else:
            name_prefix = "Optional"
            is_critical = False

        if installed.get(key):
            if has_engine and key in ("xray", "sing-box", "mhrv", "sni-spoofing"):
                size_kb = engine_bin.stat().st_size // 1024
                results.append(PreflightResult(
                    f"{name_prefix}: {info.display_name}", True, is_critical,
                    f"Present (via blackout-engine.exe: {size_kb} KB)",
                ))
            else:
                first = bins_dir / info.output_bins[0]
                size_kb = first.stat().st_size // 1024
                results.append(PreflightResult(
                    f"{name_prefix}: {info.display_name}", True, is_critical,
                    f"Present ({size_kb} KB)",
                ))
        else:
            if is_critical:
                results.append(PreflightResult(
                    f"{name_prefix}: {info.display_name}", False, is_critical,
                    f"MISSING — {info.display_name} is required for core bypass stack!",
                ))
            else:
                results.append(PreflightResult(
                    f"{name_prefix}: {info.display_name}", False, is_critical,
                    "Not installed (reduces fallback options)",
                ))

    # ── Config file ──────────────────────────────────────────────
    from .config.manager import load_configs
    from . import security as sec

    if sec.configs_are_obfuscated():
        ok = sec.deobfuscate_configs()
        if ok:
            configs = load_configs()
            sec.obfuscate_configs()  # Re-encrypt
            results.append(PreflightResult(
                "V2Ray configs (encrypted)", True, True,
                f"{len(configs)} config(s) saved and decryptable",
            ))
        else:
            results.append(PreflightResult(
                "V2Ray configs (encrypted)", False, True,
                "Encrypted but cannot decrypt — may be corrupted",
            ))
    else:
        configs = load_configs()
        if configs:
            sni_ok = sum(1 for c in configs if c.is_sni_compatible())
            results.append(PreflightResult(
                "V2Ray configs", True, True,
                f"{len(configs)} config(s) saved, {sni_ok} SNI-compatible",
            ))
        else:
            results.append(PreflightResult(
                "V2Ray configs", False, True,
                "No configs saved — use 'blackout config add' or 'blackout config import'",
            ))

    # ── IP scan cache ────────────────────────────────────────────
    from .scanner.ip_scanner import load_cache, cache_age_str, _CACHE_FILE

    cached = load_cache()
    age    = cache_age_str()
    if cached:
        results.append(PreflightResult(
            "IP scan cache", True, False,
            f"{len(cached)} IPs cached  (age: {age})",
        ))
    elif _CACHE_FILE.exists():
        results.append(PreflightResult(
            "IP scan cache", False, False,
            f"Cache expired ({age}) — run 'blackout scan' to refresh",
        ))
    else:
        results.append(PreflightResult(
            "IP scan cache", False, False,
            "No cache — run 'blackout scan' now while you have internet!",
        ))

    # ── Settings file ────────────────────────────────────────────
    from . import settings as cfg
    s = cfg.load()
    if s.get("sni_connect_ip"):
        results.append(PreflightResult(
            "Saved Cloudflare IP", True, False,
            f"{s['sni_connect_ip']} (fallback if scan fails)",
        ))
    else:
        results.append(PreflightResult(
            "Saved Cloudflare IP", False, False,
            "Not set — run 'blackout scan' and apply the best IP",
        ))

    # ── App data directory ───────────────────────────────────────
    if APP_DATA_DIR.exists():
        results.append(PreflightResult("App data dir (~/.blackout-kit)", True, False, "OK"))
    else:
        results.append(PreflightResult(
            "App data dir (~/.blackout-kit)", False, False,
            "Missing — will be created on first run",
        ))

    return results


def preflight_summary(results: list[PreflightResult]) -> tuple[bool, int, int]:
    """
    Returns (ready_for_blackout, critical_fails, total_fails).
    """
    critical = sum(1 for r in results if not r.ok and r.critical)
    total    = sum(1 for r in results if not r.ok)
    ready    = critical == 0
    return ready, critical, total
