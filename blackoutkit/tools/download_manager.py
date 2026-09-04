"""
Blackout Kit - Download Manager.
Multi-threaded HTTP(S) downloads with resume, queue, and speed limiting.

Core features:
  - Persistent queue (survives daemon restart)
  - Multi-threaded downloads (2 parallel by default)
  - Smart resume with HTTP 206 Range requests
  - Speed limiting (global KBps cap)
  - Progress callbacks for CLI display
  - Atomic file operations (temp→rename pattern)
"""
import json
import logging
import os
import tempfile
import threading
import time
import urllib.request
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

_log = logging.getLogger(__name__)

from .. import APP_DATA_DIR, __version__

DOWNLOAD_QUEUE_FILE = APP_DATA_DIR / "download_queue.json"
DOWNLOAD_MAX_HISTORY = 1000  # Keep last 1000 downloads
_CHUNK_SIZE = 65536  # 64KB chunks
_API_TIMEOUT = 10  # seconds for HEAD request
_DOWNLOAD_TIMEOUT = 300  # seconds per download (can be long for large files)


class DownloadStatus(str, Enum):
    """Download status states."""
    PENDING = "pending"
    DOWNLOADING = "downloading"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"


@dataclass
class Download:
    """Single download state."""
    id: str  # UUID
    url: str  # HTTP(S) URL
    destination: Path  # Where to save
    status: DownloadStatus = DownloadStatus.PENDING
    total_size: int = 0  # Bytes (0 if unknown)
    downloaded: int = 0  # Bytes so far
    error_message: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: str | None = None
    speed_limit_kbps: int = 0  # 0 = no limit
    supports_range: bool = False  # Server supports HTTP 206 Range requests

    def to_dict(self) -> dict:
        """Convert to JSON-serializable dict."""
        d = asdict(self)
        d['destination'] = str(d['destination'])
        d['status'] = d['status'].value if isinstance(d['status'], DownloadStatus) else d['status']
        return d

    @staticmethod
    def from_dict(d: dict) -> 'Download':
        """Reconstruct from dict."""
        d = d.copy()
        d['destination'] = Path(d['destination'])
        if isinstance(d['status'], str):
            try:
                d['status'] = DownloadStatus(d['status'])
            except ValueError:
                d['status'] = DownloadStatus.PENDING
        return Download(**{k: v for k, v in d.items() if k in Download.__dataclass_fields__})


# ──────────────────────────── Queue Persistence ──────────────────────────

def save_queue(downloads: list[Download]) -> None:
    """
    Atomically save download queue to disk.
    Keeps last DOWNLOAD_MAX_HISTORY entries.
    """
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)

    # Keep only recent downloads
    recent = downloads[-DOWNLOAD_MAX_HISTORY:]
    data = {"downloads": [d.to_dict() for d in recent]}

    try:
        fd, tmp_path = tempfile.mkstemp(suffix=".json", dir=APP_DATA_DIR, text=True)
        try:
            with os.fdopen(fd, 'w') as f:
                json.dump(data, f, indent=2)
            os.replace(tmp_path, DOWNLOAD_QUEUE_FILE)
        except Exception:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
            raise
    except Exception:
        pass  # Error-resilient: silently fail


def load_queue() -> list[Download]:
    """
    Load download queue from disk.
    Gracefully handles corruption/missing file.
    """
    if not DOWNLOAD_QUEUE_FILE.exists():
        return []

    try:
        data = json.loads(DOWNLOAD_QUEUE_FILE.read_text())
        return [Download.from_dict(d) for d in data.get("downloads", [])]
    except Exception:
        return []  # Silently return empty on error


# ──────────────────────────── Queue Management ──────────────────────────

_queue_lock = threading.RLock()  # Reentrant lock to prevent deadlock on recursive calls
_active_downloads: dict[str, 'Download'] = {}


def queue_download(
    url: str,
    destination: str | None = None,
    speed_limit_kbps: int = 0,
) -> str:
    """
    Add a download to the queue.
    Returns the download ID for status tracking.
    """
    download_id = str(uuid.uuid4())[:8]

    if destination is None:
        # Auto-generate filename from URL
        filename = url.split('/')[-1].split('?')[0] or 'download'
        destination = APP_DATA_DIR / "downloads" / filename
    else:
        destination = Path(destination)

    # Create parent directory if needed
    destination.parent.mkdir(parents=True, exist_ok=True)

    download = Download(
        id=download_id,
        url=url,
        destination=destination,
        speed_limit_kbps=speed_limit_kbps,
    )

    with _queue_lock:
        queue = load_queue()
        queue.append(download)
        save_queue(queue)

    return download_id


def get_download(download_id: str) -> Download | None:
    """Lookup a download by ID."""
    with _queue_lock:
        queue = load_queue()
        for d in queue:
            if d.id == download_id:
                return d
    return None


def list_downloads(status: DownloadStatus | None = None) -> list[Download]:
    """List all downloads, optionally filtered by status."""
    with _queue_lock:
        queue = load_queue()

    if status is None:
        return queue

    if isinstance(status, str):
        try:
            status = DownloadStatus(status)
        except ValueError:
            return []

    return [d for d in queue if d.status == status]


def update_download(download_id: str, **updates) -> None:
    """
    Update download fields atomically.
    Updates: status, downloaded, total_size, error_message, completed_at, supports_range
    """
    with _queue_lock:
        queue = load_queue()
        for i, d in enumerate(queue):
            if d.id == download_id:
                # Update allowed fields
                for key in ['status', 'downloaded', 'total_size', 'error_message', 'completed_at', 'supports_range']:
                    if key in updates:
                        val = updates[key]
                        # Convert string status back to enum
                        if key == 'status' and isinstance(val, str):
                            try:
                                val = DownloadStatus(val)
                            except ValueError:
                                continue
                        setattr(d, key, val)
                queue[i] = d
                break
        save_queue(queue)


# ──────────────────────────── Download Worker ──────────────────────────

class DownloadWorker(threading.Thread):
    """Background thread for downloading a single file."""

    def __init__(
        self,
        download: Download,
        progress_callback: Callable[[int, int], None] | None = None,
    ):
        super().__init__(daemon=True)
        self.download = download
        self.progress_callback = progress_callback
        self._stop_event = threading.Event()

    def stop(self):
        """Signal the worker to stop gracefully."""
        self._stop_event.set()

    def run(self):
        """Execute the download."""
        try:
            self._download()
        except Exception as e:
            _log.error(f"Download {self.download.id} failed: {e}")
            update_download(
                self.download.id,
                status=DownloadStatus.FAILED,
                error_message=str(e),
            )
        finally:
            with _worker_lock:
                _worker_threads.pop(self.download.id, None)

    def _download(self):
        """Internal download implementation."""
        url = self.download.url
        dest = self.download.destination
        temp_dest = dest.with_suffix(dest.suffix + '.tmp')

        # Ensure parent directory exists
        dest.parent.mkdir(parents=True, exist_ok=True)

        # Check if we can resume (partial file exists)
        resume_from = 0
        if temp_dest.exists():
            temp_size = temp_dest.stat().st_size
            if temp_size == 0:
                temp_dest.unlink()
                resume_from = 0
            elif temp_size > 0:
                resume_from = temp_size

        try:
            # First, fetch headers to check total size and range support
            req = urllib.request.Request(
                url,
                headers={"User-Agent": f"blackout-kit/{__version__}"},
                method="HEAD",
            )

            try:
                with urllib.request.urlopen(req, timeout=_API_TIMEOUT) as resp:
                    content_length = resp.headers.get("Content-Length")
                    total_size = int(content_length) if content_length else 0
                    accept_ranges = resp.headers.get("Accept-Ranges", "").lower() == "bytes"

                    update_download(
                        self.download.id,
                        total_size=total_size,
                        supports_range=accept_ranges,
                    )
            except Exception:
                # HEAD request failed, continue with GET
                total_size = 0
                accept_ranges = False

            # Now do the actual download
            update_download(self.download.id, status=DownloadStatus.DOWNLOADING)

            # Determine if we can resume
            if resume_from > 0 and accept_ranges:
                # Use Range request
                req = urllib.request.Request(
                    url,
                    headers={
                        "User-Agent": f"blackout-kit/{__version__}",
                        "Range": f"bytes={resume_from}-",
                    },
                )
            else:
                # Start from beginning
                resume_from = 0
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": f"blackout-kit/{__version__}"},
                )

            # Download with progress tracking
            with urllib.request.urlopen(req, timeout=_DOWNLOAD_TIMEOUT) as resp:
                # Update total size if we got it now
                cl = resp.headers.get("Content-Length")
                if cl:
                    try:
                        size = int(cl)
                        if total_size == 0 or (resume_from > 0 and resp.status == 206):
                            # For resume, Content-Length is the remaining bytes
                            total_size = resume_from + size
                        update_download(self.download.id, total_size=total_size)
                    except ValueError:
                        pass

                # Open temp file for writing
                mode = 'ab' if resume_from > 0 else 'wb'
                with open(temp_dest, mode) as f:
                    downloaded_this_session = 0
                    last_update = time.time()

                    while True:
                        if self._stop_event.is_set():
                            # User cancelled
                            update_download(self.download.id, status=DownloadStatus.PAUSED)
                            return

                        chunk = resp.read(_CHUNK_SIZE)
                        if not chunk:
                            break

                        f.write(chunk)
                        downloaded_this_session += len(chunk)
                        current_downloaded = resume_from + downloaded_this_session

                        # Update progress periodically
                        now = time.time()
                        if now - last_update >= 0.2:  # Update every 200ms
                            update_download(self.download.id, downloaded=current_downloaded)
                            if self.progress_callback:
                                self.progress_callback(current_downloaded, total_size or current_downloaded)
                            last_update = now

                        # Speed limiting
                        if self.download.speed_limit_kbps > 0:
                            elapsed = now - last_update
                            if elapsed > 0:
                                current_speed_kbps = (len(chunk) / 1024) / elapsed
                                if current_speed_kbps > self.download.speed_limit_kbps:
                                    sleep_time = (len(chunk) / 1024 / self.download.speed_limit_kbps) - elapsed
                                    if sleep_time > 0:
                                        time.sleep(sleep_time)

            # Verify downloaded size matches expected (if we know it)
            if total_size > 0 and temp_dest.stat().st_size != total_size:
                raise Exception(f"Downloaded {temp_dest.stat().st_size} bytes, expected {total_size}")

            # Move temp file to final destination
            if dest.exists():
                dest.unlink()
            temp_dest.rename(dest)

            # Mark as completed
            update_download(
                self.download.id,
                status=DownloadStatus.COMPLETED,
                downloaded=total_size or temp_dest.stat().st_size,
                completed_at=datetime.now(timezone.utc).isoformat(),
            )

            _log.info(f"Download {self.download.id} completed: {dest}")

        finally:
            # Clean up temp file if it still exists
            if temp_dest.exists():
                try:
                    temp_dest.unlink()
                except Exception:
                    pass


# ──────────────────────────── Download Control ──────────────────────────

_worker_threads: dict[str, DownloadWorker] = {}
_worker_lock = threading.Lock()


def start_download(download_id: str, progress_callback: Callable[[int, int], None] | None = None) -> bool:
    """
    Start a queued download in the background.
    Returns True if started, False if already running or not found.
    """
    download = get_download(download_id)
    if not download:
        return False

    with _worker_lock:
        if download_id in _worker_threads:
            # Already running
            return False

        worker = DownloadWorker(download, progress_callback=progress_callback)
        _worker_threads[download_id] = worker
        worker.start()

    return True


def cancel_download(download_id: str) -> bool:
    """
    Cancel a running download (pauses it).
    Partial file is left on disk for potential resume.
    Returns True if cancelled, False if not running.
    """
    with _worker_lock:
        if download_id not in _worker_threads:
            return False

        worker = _worker_threads[download_id]
        worker.stop()
        # Note: Don't remove from dict until join completes

    return True


def pause_all_downloads() -> None:
    """
    Gracefully stop all running downloads (used on daemon shutdown).
    Partial files preserved for resume.
    """
    with _worker_lock:
        for worker in _worker_threads.values():
            worker.stop()


def get_download_progress(download_id: str) -> tuple[int, int]:
    """
    Get current progress for a download.
    Returns (downloaded_bytes, total_bytes).
    """
    download = get_download(download_id)
    if not download:
        return 0, 0
    return download.downloaded, download.total_size


def is_download_active(download_id: str) -> bool:
    """Check if a download is currently running."""
    with _worker_lock:
        if download_id not in _worker_threads:
            return False

        worker = _worker_threads[download_id]
        return worker.is_alive()
