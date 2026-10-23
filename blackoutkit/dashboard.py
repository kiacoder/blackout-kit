"""
Real-time status dashboard for Blackout Kit daemon.
Displays live metrics: engine status, connections, throughput, system health.
"""
import time

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import daemon

# Colors for status states
COLOR_OK = "green"
COLOR_WARNING = "yellow"
COLOR_CRITICAL = "red"
COLOR_NEUTRAL = "cyan"


class LiveDashboard:
    """Real-time TUI dashboard for daemon status and metrics."""

    def __init__(self, refresh_interval: float = 0.5):
        """
        Initialize the dashboard.

        Args:
            refresh_interval: Seconds between status refreshes (default 0.5s).
        """
        self.refresh_interval = refresh_interval
        self.console = Console()
        self._last_update = 0.0
        self._metrics_history = []
        # io_bytes is a cumulative counter; throughput is its derivative, so a
        # previous sample is required. The daemon never wrote throughput_* at
        # all, which is why the dashboard showed 0.00 Mbps forever.
        self._last_io: tuple[int, int, float] | None = None

    def get_daemon_status(self) -> dict:
        """
        Fetch current daemon status from IPC metrics.

        Returns:
            Dictionary with keys:
            - active: bool (daemon running)
            - pid: int | None (process ID)
            - engine: str | None (engine name)
            - uptime: float (seconds)
            - connected: bool (proxy connected)
            - throughput_down: float (Mbps)
            - throughput_up: float (Mbps)
            - active_connections: int
            - last_activity_sec: float (seconds ago)
            - health: str ('OK' | 'WARNING' | 'CRITICAL')
        """
        metrics = daemon.stream_daemon_ipc_metrics()
        state = daemon.get_state() or {}

        # The daemon writes `status` and `io_bytes`; it has never written
        # `connected`, `throughput_*`, `active_connections` or
        # `last_activity_sec`. Reading the latter meant a healthy tunnel showed
        # as "Disconnected, 0.00 Mbps, 0 connections" for ever. Derive what can
        # be derived from what is actually there, and be explicit about what
        # cannot be known.
        status_value = str(state.get("status") or "").lower()
        down_mbps, up_mbps = self._throughput_mbps(state.get("io_bytes"))

        status = {
            "active": metrics.get("active", False),
            "pid": metrics.get("pid"),
            "engine": metrics.get("engine") or "None",
            "uptime": metrics.get("uptime", 0.0),
            "started_at": metrics.get("started_at"),
            "status": status_value or "unknown",
            "connected": status_value == "connected",
            "throughput_down": down_mbps,
            "throughput_up": up_mbps,
            # Not tracked by the daemon; shown as n/a rather than as a
            # confident zero.
            "active_connections": None,
            "last_activity_sec": None,
            "memory_mb": metrics.get("memory_mb"),
            "restarts": state.get("restarts"),
            "last_failure": state.get("last_failure"),
        }

        # Calculate health status
        status["health"] = self._calculate_health(status)

        return status

    def _throughput_mbps(self, io_bytes) -> tuple[float, float]:
        """Convert the daemon's cumulative io_bytes counter into Mbps.

        Returns (down, up) in megabits per second since the previous sample, or
        (0.0, 0.0) on the first sample - there is no rate to report yet.
        """
        if not io_bytes or len(io_bytes) != 2:
            return 0.0, 0.0
        try:
            down_now, up_now = int(io_bytes[0]), int(io_bytes[1])
        except (TypeError, ValueError):
            return 0.0, 0.0

        now = time.monotonic()
        previous = self._last_io
        self._last_io = (down_now, up_now, now)
        if previous is None:
            return 0.0, 0.0

        prev_down, prev_up, prev_time = previous
        elapsed = now - prev_time
        if elapsed <= 0:
            return 0.0, 0.0

        # A counter that went backwards means the daemon restarted; report zero
        # for this sample rather than a nonsense spike.
        down_delta = max(0, down_now - prev_down)
        up_delta = max(0, up_now - prev_up)
        scale = 8.0 / 1_000_000.0 / elapsed
        return down_delta * scale, up_delta * scale

    def _calculate_health(self, status: dict) -> str:
        """
        Determine system health based on metrics.

        Rules:
        - CRITICAL: daemon not active
        - WARNING: not connected, or high activity with no throughput
        - OK: daemon active and responding normally
        """
        if not status["active"]:
            return "CRITICAL"

        if not status["connected"]:
            # A daemon that is up and reconnecting is a warning, not a fault;
            # one that reported `failed` is closer to critical.
            if status.get("status") == "failed":
                return "CRITICAL"
            return "WARNING"

        # If connected and active, health is OK
        return "OK"

    def render_dashboard(self, status: dict) -> Panel:
        """
        Render formatted dashboard display.

        Args:
            status: Dictionary from get_daemon_status()

        Returns:
            Rich Panel containing the full dashboard.
        """
        # Status indicator
        active_icon = "✅" if status["active"] else "❌"
        active_text = Text(f"{active_icon} {status['engine']}", style="bold cyan")

        # Connection status
        connected_icon = "🟢" if status["connected"] else "🔴"
        connected_status = Text(
            f"{connected_icon} {'Connected' if status['connected'] else 'Disconnected'}",
            style=COLOR_OK if status["connected"] else COLOR_CRITICAL,
        )

        # Throughput display
        throughput_text = Text(
            f"↓ {status['throughput_down']:.2f} Mbps  ↑ {status['throughput_up']:.2f} Mbps",
            style=COLOR_NEUTRAL,
        )

        # Active connections: the daemon does not track a count, so say so
        # instead of printing a confident "0 connections".
        connections = status.get("active_connections")
        conn_text = Text(
            "n/a (not tracked)" if connections is None else f"{connections} connections",
            style=COLOR_NEUTRAL,
        )

        # System health
        health = status["health"]
        health_color = {
            "OK": COLOR_OK,
            "WARNING": COLOR_WARNING,
            "CRITICAL": COLOR_CRITICAL,
        }.get(health, COLOR_NEUTRAL)
        health_text = Text(f"System: {health}", style=health_color)

        # Uptime
        uptime_sec = status["uptime"]
        uptime_str = self._format_uptime(uptime_sec)
        uptime_text = Text(f"Uptime: {uptime_str}", style=COLOR_NEUTRAL)

        # Last activity
        last_activity_sec = status.get("last_activity_sec")
        if last_activity_sec is None:
            last_activity_str = "n/a"
        elif last_activity_sec < 60:
            last_activity_str = f"{int(last_activity_sec)}s ago"
        elif last_activity_sec < 3600:
            last_activity_str = f"{int(last_activity_sec / 60)}m ago"
        else:
            last_activity_str = f"{int(last_activity_sec / 3600)}h ago"
        last_activity_text = Text(f"Last activity: {last_activity_str}", style=COLOR_NEUTRAL)

        # PID info
        pid_text = Text(
            f"PID: {status['pid'] or 'N/A'}",
            style=COLOR_NEUTRAL,
        )

        # Build table for metrics
        table = Table(title="Blackout Kit Daemon Status", box=None, padding=(0, 2))
        table.add_column("Metric", style="cyan", no_wrap=True)
        table.add_column("Value", style="magenta")

        table.add_row("Engine", active_text)
        table.add_row("Status", connected_status)
        table.add_row("Throughput", throughput_text)
        table.add_row("Connections", conn_text)
        table.add_row("System Health", health_text)
        table.add_row("Uptime", uptime_text)
        table.add_row("Last Activity", last_activity_text)
        table.add_row("Process ID", pid_text)
        if status.get("memory_mb"):
            table.add_row(
                "Memory",
                Text(f"{status['memory_mb']:.1f} MB", style=COLOR_NEUTRAL),
            )
        if status.get("restarts") is not None:
            table.add_row(
                "Restarts",
                Text(str(status["restarts"]), style=COLOR_NEUTRAL),
            )

        # Wrap in a panel
        panel = Panel(
            table,
            title="[bold cyan]Blackout Kit Live Dashboard[/bold cyan]",
            border_style="cyan",
            expand=False,
        )

        return panel

    @staticmethod
    def _format_uptime(seconds: float) -> str:
        """Format seconds into human-readable uptime string."""
        if seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            return f"{int(seconds / 60)}m {int(seconds % 60)}s"
        else:
            hours = int(seconds / 3600)
            minutes = int((seconds % 3600) / 60)
            return f"{hours}h {minutes}m"

    def show(self, follow: bool = True) -> None:
        """
        Display the dashboard and optionally update in real-time.

        Args:
            follow: If True, continuously refresh. If False, show once and exit.
        """
        if not follow:
            # Single snapshot
            status = self.get_daemon_status()
            panel = self.render_dashboard(status)
            self.console.print(panel)
            return

        # Live continuous update mode.
        #
        # Live() needs a renderable; it was given a generator, so rich raised
        # NotRenderableError before the first frame and the "real-time"
        # dashboard never rendered at all. Render once, then update in a loop.
        def frame() -> Panel:
            try:
                return self.render_dashboard(self.get_daemon_status())
            except Exception as e:  # keep the dashboard alive on a bad sample
                return Panel(
                    Text(f"Dashboard error: {e}", style="red"),
                    title="[bold red]Error[/bold red]",
                    border_style="red",
                )

        refresh_hz = max(0.5, 1.0 / self.refresh_interval)
        try:
            with Live(
                frame(),
                refresh_per_second=refresh_hz,
                console=self.console,
                screen=False,
            ) as live:
                while True:
                    time.sleep(self.refresh_interval)
                    live.update(frame())
        except KeyboardInterrupt:
            # Ctrl+C is how you leave a live dashboard - not an error.
            pass
        except Exception as e:
            self.console.print(f"[red]Dashboard error: {e}[/red]")

    def get_summary_text(self) -> str:
        """
        Return a one-line summary of daemon status (for CLI output).

        Returns:
            Status string like "[✅ gdpi] Connected | 5.23↓ / 1.45↑ Mbps | 4 connections"
        """
        status = self.get_daemon_status()

        active_icon = "✅" if status["active"] else "❌"
        engine = status["engine"]
        connected_icon = "🟢" if status["connected"] else "🔴"

        parts = [
            f"{active_icon} {engine}",
            f"{connected_icon} {'Connected' if status['connected'] else 'Disconnected'}",
            f"{status['throughput_down']:.2f}↓ / {status['throughput_up']:.2f}↑ Mbps",
            f"{status['active_connections']} connections",
        ]

        return " | ".join(parts)


def show_dashboard_once() -> None:
    """CLI entry point: Display daemon status once and exit."""
    dashboard = LiveDashboard()
    dashboard.show(follow=False)


def follow_dashboard() -> None:
    """CLI entry point: Display live dashboard with continuous updates."""
    dashboard = LiveDashboard()
    dashboard.show(follow=True)
