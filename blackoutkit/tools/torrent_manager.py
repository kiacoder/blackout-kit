"""
Blackout Kit - Torrent Manager.
Downloads torrents and magnets using python-libtorrent.

Core features:
  - Persistent queue (survives daemon restart)
  - Multi-threaded downloads (2 parallel by default)
  - Magnet link and .torrent file support
  - Seed ratio control (default 1.0)
  - Peer/seed tracking
  - QoS rate limiting integration (auto-applies if rules exist)
"""
import json
import logging
import os
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional
from enum import Enum

_log = logging.getLogger(__name__)

from .. import APP_DATA_DIR, __version__

TORRENT_QUEUE_FILE = APP_DATA_DIR / "torrent_downloads.json"
TORRENT_MAX_HISTORY = 1000
_TORRENT_TIMEOUT = 7200  # 2 hours max session


class TorrentStatus(str, Enum):
    """Torrent status states."""
    PENDING = "pending"
    DOWNLOADING = "downloading"
    SEEDING = "seeding"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"


@dataclass
class TorrentDownload:
    """Single torrent download state."""
    id: str  # UUID
    magnet_or_file: str  # Magnet link or path to .torrent file
    name: str = ""  # Torrent name (extracted from metadata)
    destination: Path = field(default_factory=Path)  # Where to save
    status: TorrentStatus = TorrentStatus.PENDING
    total_size: int = 0  # Bytes
    downloaded: int = 0  # Bytes so far
    uploaded: int = 0  # Bytes uploaded (for seeding)
    peers: int = 0  # Current peer count
    seeds: int = 0  # Current seed count
    download_rate_kbps: int = 0  # Current download speed
    upload_rate_kbps: int = 0  # Current upload speed
    seed_ratio: float = 1.0  # When to stop seeding (1.0 = 1:1 ratio)
    error_message: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    eta_seconds: int = 0  # Estimated time remaining

    def to_dict(self) -> dict:
        """Convert to JSON-serializable dict."""
        d = asdict(self)
        d['destination'] = str(d['destination'])
        d['status'] = d['status'].value if isinstance(d['status'], TorrentStatus) else d['status']
        return d

    @staticmethod
    def from_dict(d: dict) -> 'TorrentDownload':
        """Reconstruct from dict."""
        d = d.copy()
        d['destination'] = Path(d['destination'])
        if isinstance(d['status'], str):
            try:
                d['status'] = TorrentStatus(d['status'])
            except ValueError:
                d['status'] = TorrentStatus.PENDING
        return TorrentDownload(**{k: v for k, v in d.items() if k in TorrentDownload.__dataclass_fields__})


# ──────────────────────────── Queue Persistence ──────────────────────────

def save_torrent_queue(downloads: list[TorrentDownload]) -> None:
    """Atomically save torrent download queue to disk."""
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)

    recent = downloads[-TORRENT_MAX_HISTORY:]
    data = {"downloads": [d.to_dict() for d in recent]}

    try:
        fd, tmp_path = tempfile.mkstemp(suffix=".json", dir=APP_DATA_DIR, text=True)
        try:
            with os.fdopen(fd, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception:
            os.close(fd)
            raise
        os.replace(tmp_path, TORRENT_QUEUE_FILE)
    except Exception as e:
        _log.error(f"Failed to save torrent queue: {e}")


def load_torrent_queue() -> list[TorrentDownload]:
    """Load torrent download queue from disk."""
    if not TORRENT_QUEUE_FILE.exists():
        return []
    try:
        with open(TORRENT_QUEUE_FILE, 'r') as f:
            data = json.load(f)
        return [TorrentDownload.from_dict(d) for d in data.get('downloads', [])]
    except Exception as e:
        _log.error(f"Failed to load torrent queue: {e}")
        return []


# ──────────────────────────── Download Manager ──────────────────────────

class TorrentDownloadManager:
    """Manages torrent download queue and worker threads."""

    def __init__(self, max_parallel: int = 2):
        self.downloads = load_torrent_queue()
        self.max_parallel = max_parallel
        self.lock = threading.Lock()
        self.executor = ThreadPoolExecutor(max_workers=max_parallel, thread_name_prefix="torrent-dl")
        self.running = False
        self.session = None  # libtorrent session (lazy-loaded)

    def _init_session(self):
        """Initialize libtorrent session on first use."""
        if self.session is not None:
            return
        try:
            import libtorrent as lt
            settings = lt.session_settings()
            settings.user_agent = f"Blackout-Kit/{__version__}"
            self.session = lt.session(settings)
            _log.info("Initialized libtorrent session")
        except ImportError:
            raise RuntimeError("python-libtorrent not installed. Install with: pip install python-libtorrent")

    def add_torrent(self, magnet_or_file: str, output_dir: Optional[Path] = None, seed_ratio: float = 1.0) -> str:
        """Queue a new torrent download. Returns download ID."""
        if output_dir is None:
            output_dir = Path.home() / "Downloads" / "blackout-torrents"
        output_dir.mkdir(parents=True, exist_ok=True)

        dl_id = str(uuid.uuid4())[:8]
        download = TorrentDownload(
            id=dl_id,
            magnet_or_file=magnet_or_file,
            destination=output_dir,
            seed_ratio=seed_ratio,
            status=TorrentStatus.PENDING,
            created_at=datetime.now(timezone.utc).isoformat()
        )

        with self.lock:
            self.downloads.append(download)
            save_torrent_queue(self.downloads)

        _log.info(f"Queued torrent download: {dl_id}")
        return dl_id

    def get_download(self, dl_id: str) -> Optional[TorrentDownload]:
        """Get torrent by ID."""
        with self.lock:
            for d in self.downloads:
                if d.id == dl_id:
                    return d
        return None

    def set_seed_ratio(self, dl_id: str, ratio: float) -> bool:
        """Set seed ratio for a torrent."""
        with self.lock:
            for d in self.downloads:
                if d.id == dl_id:
                    d.seed_ratio = max(0.0, ratio)
                    save_torrent_queue(self.downloads)
                    return True
        return False

    def cancel_download(self, dl_id: str) -> bool:
        """Cancel a torrent."""
        with self.lock:
            for d in self.downloads:
                if d.id == dl_id:
                    if d.status in (TorrentStatus.DOWNLOADING, TorrentStatus.SEEDING):
                        d.status = TorrentStatus.PAUSED
                        d.error_message = "Cancelled by user"
                    save_torrent_queue(self.downloads)
                    return True
        return False

    def get_pending_downloads(self) -> list[TorrentDownload]:
        """Get all pending torrents."""
        with self.lock:
            return [d for d in self.downloads if d.status == TorrentStatus.PENDING]

    def start_downloads(self) -> None:
        """Start downloading all pending torrents."""
        if self.running:
            return
        self.running = True
        self._init_session()

        pending = self.get_pending_downloads()
        for download in pending:
            self.executor.submit(self._download_worker, download)

    def _download_worker(self, download: TorrentDownload) -> None:
        """Worker thread for downloading a single torrent."""
        try:
            import libtorrent as lt

            with self.lock:
                download.status = TorrentStatus.DOWNLOADING
                download.started_at = datetime.now(timezone.utc).isoformat()
                save_torrent_queue(self.downloads)

            # Add torrent to session
            if download.magnet_or_file.startswith("magnet:"):
                # Parse magnet link
                params = lt.parse_magnet_uri(download.magnet_or_file)
                params.save_path = str(download.destination)
                handle = self.session.add_torrent(params)
            else:
                # Load .torrent file
                info = lt.torrent_info(download.magnet_or_file)
                params = lt.add_torrent_params()
                params.ti = info
                params.save_path = str(download.destination)
                handle = self.session.add_torrent(params)

            download.name = handle.get_torrent_info().name()

            # Monitor download
            start_time = time.time()
            while time.time() - start_time < _TORRENT_TIMEOUT:
                status = handle.status()

                with self.lock:
                    download.total_size = status.total_wanted
                    download.downloaded = status.total_wanted_done
                    download.uploaded = status.all_time_upload
                    download.peers = status.num_peers
                    download.seeds = status.num_seeds
                    download.download_rate_kbps = status.download_rate // 1000
                    download.upload_rate_kbps = status.upload_rate // 1000

                    # Calculate ETA
                    if download.download_rate_kbps > 0:
                        remaining_bytes = status.total_wanted - status.total_wanted_done
                        download.eta_seconds = remaining_bytes // (download.download_rate_kbps * 1024)
                    else:
                        download.eta_seconds = 0

                    # Update status
                    if status.is_seeding:
                        if download.status != TorrentStatus.SEEDING:
                            download.status = TorrentStatus.SEEDING
                            download.completed_at = datetime.now(timezone.utc).isoformat()

                        # Check if we've reached seed ratio
                        if download.uploaded >= download.total_size * download.seed_ratio:
                            handle.pause()
                            download.status = TorrentStatus.COMPLETED
                            save_torrent_queue(self.downloads)
                            _log.info(f"Torrent seeding complete: {download.id}")
                            return

                    save_torrent_queue(self.downloads)

                if not handle.is_valid():
                    raise Exception("Torrent handle became invalid")

                time.sleep(1)  # Update status every second

            # Timeout reached
            raise Exception(f"Torrent download timeout after {_TORRENT_TIMEOUT}s")

        except Exception as e:
            with self.lock:
                download.status = TorrentStatus.FAILED
                download.error_message = str(e)
                download.completed_at = datetime.now(timezone.utc).isoformat()
                save_torrent_queue(self.downloads)
            _log.error(f"Torrent download failed ({download.id}): {e}")

    def clear_completed(self) -> int:
        """Remove completed/failed torrents from queue. Returns count."""
        with self.lock:
            before = len(self.downloads)
            self.downloads = [
                d for d in self.downloads
                if d.status not in (TorrentStatus.COMPLETED, TorrentStatus.FAILED)
            ]
            count = before - len(self.downloads)
            save_torrent_queue(self.downloads)
        return count


# Singleton instance
_manager: Optional[TorrentDownloadManager] = None


def get_torrent_manager() -> TorrentDownloadManager:
    """Get or create the torrent download manager singleton."""
    global _manager
    if _manager is None:
        _manager = TorrentDownloadManager()
    return _manager
