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

    # Find the source zip asset
    zipball = data.get("zipball_url", "")

    return {
        "version":     latest_tag,
        "body":        data.get("body", "No release notes."),
        "zipball_url": zipball,
        "html_url":    data.get("html_url", ""),
        "assets":      data.get("assets", []),
    }


def download_and_apply(release: dict) -> bool:
    """
    Stream-download the release zip (or .exe if frozen),
    verify integrity, and replace the source (or swap the .exe).
    """
    from .theme import console
    import os
    import subprocess

    is_frozen = getattr(sys, "frozen", False)
    
    if is_frozen:
        # Looking for the blackout.exe asset
        url = None
        for asset in release.get("assets", []):
            if asset.get("name", "").lower() == "blackout.exe":
                url = asset.get("browser_download_url")
                break
        if not url:
            console.print("[error]No blackout.exe found in the latest release assets.[/error]")
            return False
        suffix = ".exe"
    else:
        url = release.get("zipball_url", "")
        suffix = ".zip"

    if not url:
        return False

    tmp_path: Path | None = None

    try:
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            tmp_path = Path(tmp.name)

        req = urllib.request.Request(
            url, headers={"User-Agent": f"blackout-kit/{__version__}"}
        )

        hasher = hashlib.sha256()

        with urllib.request.urlopen(req, timeout=120) as resp:
            content_length = int(resp.headers.get("Content-Length", 0) or 0)

            from .theme import create_download_progress
            with create_download_progress() as progress:
                task = progress.add_task(
                    f"Downloading update ({suffix})...",
                    total=content_length if content_length > 0 else None,
                )
                chunks: list[bytes] = []
                while True:
                    chunk = resp.read(8192)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    hasher.update(chunk)
                    progress.advance(task, len(chunk))

        data       = b"".join(chunks)
        sha256_hex = hasher.hexdigest()
        tmp_path.write_bytes(data)

        console.print(f"  [dim]SHA256:  {sha256_hex}[/dim]")

        if is_frozen:
            # ── Binary Executable Hot-Swap ──
            current_exe = Path(sys.executable)
            old_exe = current_exe.with_name(current_exe.name + ".old")
            
            console.print("  [dim]Hot-swapping executable...[/dim]")
            # Remove previous old exe if exists
            if old_exe.exists():
                try:
                    old_exe.unlink()
                except Exception:
                    pass
            
            # Windows allows renaming a running executable!
            os.rename(current_exe, old_exe)
            
            # Move the newly downloaded exe to the original path
            shutil.move(str(tmp_path), current_exe)
            
            console.print("  [bold green]Update applied successfully![/bold green]")
            console.print("  [dim]Restarting application...[/dim]")
            
            # Restart the app
            subprocess.Popen([str(current_exe)] + sys.argv[1:], creationflags=0x00000008) # CREATE_NO_WINDOW
            sys.exit(0)

        else:
            # ── Source Zip Update ──
            console.print("  [dim]Verifying archive integrity...[/dim]")
            try:
                with zipfile.ZipFile(tmp_path) as zf:
                    bad_file = zf.testzip()
                    if bad_file:
                        console.print(f"  [error]Corrupt archive entry: {bad_file}[/error]")
                        return False
            except zipfile.BadZipFile:
                console.print("  [error]Downloaded file is not a valid ZIP archive.[/error]")
                return False

            console.print("  [dim]Archive OK — applying update...[/dim]")

            with zipfile.ZipFile(tmp_path) as zf:
                names  = zf.namelist()
                if not names:
                    console.print("  [error]Archive is empty (no files).[/error]")
                    return False
                prefix = names[0].split("/")[0] + "/"

                backup_dir = APP_DATA_DIR / "backup_src"
                if backup_dir.exists():
                    shutil.rmtree(backup_dir)
                shutil.copytree(PROJECT_ROOT / "blackoutkit", backup_dir)

                for member in names:
                    if not member.startswith(prefix + "blackoutkit/"):
                        continue
                    relative = member[len(prefix):]
                    dest     = PROJECT_ROOT / relative
                    
                    resolved_dest = dest.resolve()
                    if not resolved_dest.is_relative_to((PROJECT_ROOT / "blackoutkit").resolve()):
                        raise Exception("Path traversal attempt detected!")

                    if member.endswith("/"):
                        dest.mkdir(parents=True, exist_ok=True)
                    else:
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        dest.write_bytes(zf.read(member))

            tmp_path.unlink(missing_ok=True)
            return True

    except Exception as e:
        console.print(f"[error]Update failed: {e}[/error]")
        if not is_frozen:
            backup = APP_DATA_DIR / "backup_src"
            if backup.exists():
                try:
                    failed_dir = PROJECT_ROOT / f"blackoutkit_failed_{int(time.time())}"
                    if (PROJECT_ROOT / "blackoutkit").exists():
                        import os
                        os.rename(PROJECT_ROOT / "blackoutkit", failed_dir)
                    import os
                    os.rename(backup, PROJECT_ROOT / "blackoutkit")
                except Exception:
                    pass
        if tmp_path:
            try:
                tmp_path.unlink(missing_ok=True)
            except Exception:
                pass
        return False


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
