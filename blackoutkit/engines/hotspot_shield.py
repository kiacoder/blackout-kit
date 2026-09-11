"""
Hotspot Shield VPN Engine for Blackout Kit.

Uses the running Hotspot Shield Windows Store app to tunnel traffic.
Detects the HssStore virtual adapter created by the HS app.
Free tier: 95 rotating servers across 4 CDN networks
Paid tier: User-provided credentials for premium access
"""
from __future__ import annotations

import logging
import random
import subprocess
import time
from pathlib import Path
from typing import Optional

from .base import Engine

_log = logging.getLogger(__name__)

# Extracted from Hotspot Shield Windows app logs (2026-02-01 to 2026-09-10)
FREE_TIER_SERVERS = {
    "topenginefactory.com": [
        "mh-cr-us-nyc-pr-p-1", "mh-cr-us-nyc-pr-p-2", "mh-cr-us-nyc-pr-p-3",
        "mh-cr-us-nyc-pr-p-4", "mh-cr-us-nyc-pr-p-5", "mh-cr-us-nyc-pr-p-6",
        "mh-cr-us-nyc-pr-p-7", "mh-cr-us-nyc-pr-p-8", "mh-cr-us-nyc-pr-p-9",
        "mh-cr-us-nyc-pr-p-10", "mh-cr-us-nyc-pr-p-12", "mh-cr-us-nyc-pr-p-13",
        "mh-cr-us-nyc-pr-p-14", "mh-cr-us-nyc-pr-p-15", "mh-cr-us-nyc-pr-p-16",
        "mh-cr-us-nyc-pr-p-17", "mh-cr-us-nyc-pr-p-18", "mh-cr-us-nyc-pr-p-19",
        "mh-cr-us-nyc-pr-p-20", "mh-cr-us-nyc-pr-p-21", "mh-cr-us-nyc-pr-p-22",
        "mh-cr-us-nyc-pr-p-23", "mh-cr-us-nyc-pr-p-24", "mh-cr-us-nyc-pr-p-25",
        "mh-cr-us-nyc-pr-p-26", "mh-cr-us-nyc-pr-p-27", "mh-cr-us-nyc-pr-p-28",
        "mh-cr-us-nyc-pr-p-29", "mh-cr-us-nyc-pr-p-30", "mh-cr-us-nyc-pr-p-31",
        "dp-cr-us-nyc-pr-p-27",
    ],
    "thisequal.com": [
        "ms-cr-us-nyc-pr-p-1", "ms-cr-us-nyc-pr-p-2", "ms-cr-us-nyc-pr-p-3",
        "ms-cr-us-nyc-pr-p-4", "ms-cr-us-nyc-pr-p-5", "ms-cr-us-nyc-pr-p-6",
        "ms-cr-us-nyc-pr-p-7", "ms-cr-us-nyc-pr-p-8", "ms-cr-us-nyc-pr-p-9",
        "ms-cr-us-nyc-pr-p-10", "ms-cr-us-nyc-pr-p-11", "ms-cr-us-nyc-pr-p-12",
        "ms-cr-us-nyc-pr-p-13", "ms-cr-us-nyc-pr-p-14", "ms-cr-us-nyc-pr-p-15",
        "ms-cr-us-nyc-pr-p-16", "ms-cr-us-nyc-pr-p-17", "ms-cr-us-nyc-pr-p-18",
        "ms-cr-us-nyc-pr-p-19", "ms-cr-us-nyc-pr-p-20", "ms-cr-us-nyc-pr-p-21",
        "ms-cr-us-nyc-pr-p-22", "ms-cr-us-nyc-pr-p-23", "ms-cr-us-nyc-pr-p-24",
        "ms-cr-us-nyc-pr-p-25", "ms-cr-us-nyc-pr-p-26", "ms-cr-us-nyc-pr-p-27",
        "ms-cr-us-nyc-pr-p-28", "ms-cr-us-nyc-pr-p-29", "ms-cr-us-nyc-pr-p-30",
        "ms-cr-us-nyc-pr-p-31", "ms-cr-us-nyc-pr-p-32",
    ],
    "civilizationnews.com": [
        "dp-cr-us-nyc-pr-p-1", "dp-cr-us-nyc-pr-p-2", "dp-cr-us-nyc-pr-p-3",
        "dp-cr-us-nyc-pr-p-4", "dp-cr-us-nyc-pr-p-6", "dp-cr-us-nyc-pr-p-7",
        "dp-cr-us-nyc-pr-p-10", "dp-cr-us-nyc-pr-p-11", "dp-cr-us-nyc-pr-p-13",
        "dp-cr-us-nyc-pr-p-14", "dp-cr-us-nyc-pr-p-15", "dp-cr-us-nyc-pr-p-16",
        "dp-cr-us-nyc-pr-p-17", "dp-cr-us-nyc-pr-p-18", "dp-cr-us-nyc-pr-p-19",
        "dp-cr-us-nyc-pr-p-20", "dp-cr-us-nyc-pr-p-21", "dp-cr-us-nyc-pr-p-22",
        "dp-cr-us-nyc-pr-p-23", "dp-cr-us-nyc-pr-p-24", "dp-cr-us-nyc-pr-p-25",
        "dp-cr-us-nyc-pr-p-26", "dp-cr-us-nyc-pr-p-28", "dp-cr-us-nyc-pr-p-29",
        "dp-cr-us-nyc-pr-p-30",
    ],
    "northghost.com": [
        "dp-cr-us-nyc-pr-p-28", "dp-cr-us-nyc-pr-p-29", "dp-cr-us-nyc-pr-p-30",
        "ms-cr-us-nyc-pr-p-28", "ms-cr-us-nyc-pr-p-29", "ms-cr-us-nyc-pr-p-30",
        "ms-cr-us-nyc-pr-p-31", "ms-cr-us-nyc-pr-p-32", "mh-cr-us-nyc-pr-p-32",
    ],
}

# Credentials for Hotspot Shield account (free or paid tier)
DEFAULT_FREE_TIER_USERNAME = "mojanabiri@gmail.com"
DEFAULT_FREE_TIER_PASSWORD = "123456"


class HotspotShieldEngine(Engine):
    """Hotspot Shield VPN engine using the HS Windows Store app's tunnel."""

    name = "hotspot-shield"
    description = "Hotspot Shield — 95 free rotating VPN servers worldwide"

    def __init__(
        self,
        account_type: str = "free",
        username: Optional[str] = None,
        password: Optional[str] = None,
    ):
        super().__init__()
        self.account_type = account_type
        self.username = username or DEFAULT_FREE_TIER_USERNAME
        self.password = password or DEFAULT_FREE_TIER_PASSWORD
        self.current_server: Optional[str] = None
        self._connected = False
        # Windows Store app package name
        self._hss_package = "6F71D7A7.HotspotShieldFreeVPN_nsbqstbb9qxb6"

    def get_all_servers(self) -> list[str]:
        """Get all available servers."""
        servers = []
        for domain, prefixes in FREE_TIER_SERVERS.items():
            servers.extend([f"{prefix}.{domain}" for prefix in prefixes])
        return servers

    def select_random_server(self) -> str:
        """Select a random server (for reference; HS app manages actual server)."""
        all_servers = self.get_all_servers()
        self.current_server = random.choice(all_servers)
        _log.info(f"Selected server reference: {self.current_server}")
        return self.current_server

    def _is_hss_app_running(self) -> bool:
        """Check if Hotspot Shield app is running."""
        try:
            result = subprocess.run(
                ["tasklist", "/FI", "IMAGENAME eq HssStore.Client.exe"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return "HssStore.Client.exe" in result.stdout
        except Exception as e:
            _log.warning(f"Could not check HS app status: {e}")
            return False

    def _is_hssstore_adapter_active(self) -> bool:
        """Check if HssStore virtual adapter exists and is routing traffic."""
        try:
            result = subprocess.run(
                ["powershell", "-Command", "Get-NetRoute | Select-Object -Property InterfaceAlias"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return "HssStore" in result.stdout
        except Exception as e:
            _log.debug(f"Could not check HssStore adapter: {e}")
            return False

    def _launch_hss_app(self) -> bool:
        """Launch the Hotspot Shield Windows Store app."""
        try:
            _log.info(f"Launching HS Windows Store app: {self._hss_package}")
            # Windows Store apps are launched via explorer with the appsFolder protocol
            subprocess.Popen(
                ["explorer.exe", f"shell:appsFolder\\{self._hss_package}!App"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            # Wait for app and adapter to come up
            for attempt in range(12):  # Up to 60 seconds
                time.sleep(5)
                if self._is_hss_app_running() and self._is_hssstore_adapter_active():
                    _log.info("HS app launched and connected")
                    return True

            _log.warning("HS app launched but adapter not active yet")
            return self._is_hss_app_running()

        except Exception as e:
            _log.exception(f"Error launching HS app: {e}")
            return False

    def start(self) -> bool:
        """
        Start VPN by ensuring Hotspot Shield app is running and connected.

        Returns:
            True if HS app is running and VPN is active, False otherwise.
        """
        try:
            _log.info("Starting Hotspot Shield engine...")

            # Select a random server (for reference; HS app manages actual selection)
            self.select_random_server()

            # Check if HS app is already running
            if not self._is_hss_app_running():
                _log.info("HS app not running, launching...")
                if not self._launch_hss_app():
                    _log.error("Failed to launch HS app")
                    return False
            else:
                _log.info("HS app already running")

            # Verify VPN tunnel is active
            if self._is_hssstore_adapter_active():
                self._connected = True
                _log.info("HssStore adapter active, VPN connected")
                return True
            else:
                _log.warning("HS app running but HssStore adapter not active yet")
                # Wait a bit more
                time.sleep(5)
                if self._is_hssstore_adapter_active():
                    self._connected = True
                    return True
                return False

        except Exception as e:
            _log.exception(f"Start error: {e}")
            return False

    def stop(self) -> None:
        """Disconnect from Hotspot Shield VPN."""
        try:
            _log.info("Stopping Hotspot Shield engine...")
            if self._connected or self._is_hssstore_adapter_active():
                _log.info("Disconnecting HS VPN...")
                # Kill HS app to disconnect
                try:
                    subprocess.run(
                        ["taskkill", "/IM", "HssStore.Client.exe", "/F"],
                        capture_output=True,
                        timeout=5,
                    )
                    self._connected = False
                    _log.info("HS app terminated")
                except Exception as e:
                    _log.warning(f"Error terminating HS app: {e}")
        except Exception as e:
            _log.exception(f"Stop error: {e}")
        finally:
            super().stop()

    def is_running(self) -> bool:
        """Check if HS VPN is currently connected."""
        # Check both internal state and actual adapter status
        is_app_running = self._is_hss_app_running()
        is_adapter_active = self._is_hssstore_adapter_active()
        self._connected = is_app_running and is_adapter_active
        return self._connected
