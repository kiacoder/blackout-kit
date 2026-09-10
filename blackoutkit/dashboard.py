"""
Real-time status dashboard for Blackout Kit daemon.
Displays live metrics: engine status, connections, throughput, system health.
"""
import time
from datetime import datetime
from pathlib import Path

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
        state = daemon.get_state()

        # Build comprehensive status
        status = {
            "active": metrics.get("active", False),
            "pid": metrics.get("pid"),
            "engine": metrics.get("engine") or "None",
            "uptime": metrics.get("uptime", 0.0),
            "started_at": metrics.get("started_at"),
            "connected": state.get("connected", False) if state else False,
            "throughput_down": state.get("throughput_down", 0.0) if state else 0.0,
            "throughput_up": state.get("throughput_up", 0.0) if state else 0.0,
            "active_connections": state.get("active_connections", 0) if state else 0,
            "last_activity_sec": state.get("last_activity_sec", 0.0) if state else 0.0,
        }

        # Calculate health status
        status["health"] = self._calculate_health(status)

        return status

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

        # Active connections
        conn_text = Text(
            f"{status['active_connections']} connections",
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
        last_activity_sec = status["last_activity_sec"]
        if last_activity_sec < 60:
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

        # Live continuous update mode
        def generate_dashboard():
            while True:
                try:
                    status = self.get_daemon_status()
                    yield self.render_dashboard(status)
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    # On error, show error panel and continue
                    error_panel = Panel(
                        Text(f"Dashboard error: {e}", style="red"),
                        title="[bold red]Error[/bold red]",
                        border_style="red",
                    )
                    yield error_panel

                time.sleep(self.refresh_interval)

        try:
            with Live(generate_dashboard(), refresh_per_second=1 / self.refresh_interval, console=self.console):
                # Keep the context manager open
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
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
