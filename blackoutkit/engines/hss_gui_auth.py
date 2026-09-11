"""
Hotspot Shield GUI authentication handler.
Provides interactive credential input for IKEv2+EAP connections.
"""
import logging
import subprocess
import sys
import threading
import time
from pathlib import Path

_log = logging.getLogger(__name__)

# Try to import PySimpleGUI, fall back gracefully
try:
    import PySimpleGUI as sg
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False


class HSSAuthGUI:
    """Interactive GUI for Hotspot Shield VPN authentication."""

    def __init__(self, profile_name: str, default_username: str = "", default_password: str = ""):
        self.profile_name = profile_name
        self.default_username = default_username
        self.default_password = default_password
        self.connection_result = {"success": False, "error": None}
        self.window = None

    def show_auth_dialog(self) -> dict:
        """Show credential input dialog. Returns {'success': bool, 'error': str, 'username': str}."""
        if not GUI_AVAILABLE:
            return self._fallback_console_auth()

        # Configure PySimpleGUI theme
        sg.theme("DarkBlue3")
        sg.set_options(font=("Courier", 10))

        # Create layout
        layout = [
            [sg.Text("Hotspot Shield VPN Authentication", font=("Arial", 14, "bold"))],
            [sg.Text(f"Profile: {self.profile_name}", size=(40, 1))],
            [sg.Text("")],
            [sg.Text("Username:", size=(12, 1)), sg.InputText(self.default_username, key="username", size=(28, 1))],
            [sg.Text("Password:", size=(12, 1)), sg.InputText(self.default_password, key="password", size=(28, 1), password_char="•")],
            [sg.Text("")],
            [
                sg.Button("🔗 Connect", size=(12, 1), bind_return_key=True),
                sg.Button("Cancel", size=(12, 1)),
            ],
            [sg.Text("", key="status", size=(45, 1), text_color="white")],
            [
                sg.ProgressBar(
                    max_value=100,
                    orientation="h",
                    size=(45, 20),
                    key="progress",
                    visible=False,
                ),
            ],
        ]

        self.window = sg.Window(
            "Hotspot Shield VPN",
            layout,
            finalize=True,
            size=(500, 280),
            keep_on_top=True,
            element_justification="center",
        )

        # Event loop
        while True:
            event, values = self.window.read(timeout=100)

            if event == sg.WINDOW_CLOSED or event == "Cancel":
                self.window.close()
                return {"success": False, "error": "User cancelled"}

            if event == "🔗 Connect":
                username = values["username"].strip()
                password = values["password"].strip()

                if not username or not password:
                    sg.popup_error("Please enter both username and password", title="Input Error")
                    continue

                # Show progress and connect in background
                self.window["progress"].update(visible=True)
                self.window["status"].update("Connecting...", text_color="yellow")
                self.window.refresh()

                # Run connection in thread
                result = self._attempt_connection(username, password)

                if result["success"]:
                    self.window["status"].update("✅ Connected!", text_color="green")
                    self.window["progress"].update(100, visible=True)
                    self.window.refresh()
                    time.sleep(1)
                    self.window.close()
                    return result
                else:
                    self.window["status"].update(f"❌ Error: {result['error']}", text_color="red")
                    self.window["progress"].update(visible=False)
                    self.window.refresh()
                    time.sleep(2)

        self.window.close()
        return self.connection_result

    def _attempt_connection(self, username: str, password: str) -> dict:
        """Attempt to dial VPN with given credentials."""
        try:
            cmd = [
                "rasdial",
                self.profile_name,
                username,
                password,
            ]

            _log.debug(f"Attempting connection: {self.profile_name}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            output = result.stdout + result.stderr

            # Log full output for debugging
            _log.debug(f"rasdial output: {output}")
            _log.debug(f"rasdial exit code: {result.returncode}")

            # Check for success indicators
            success_indicators = ["Successfully", "connected", "connected to"]
            success = result.returncode == 0 or any(ind.lower() in output.lower() for ind in success_indicators)

            if success:
                _log.info(f"VPN connection successful: {self.profile_name}")
                return {"success": True, "error": None, "username": username}
            else:
                # Extract error message
                if output:
                    lines = output.split("\n")
                    error_lines = [line.strip() for line in lines if line.strip() and "Remote Access error" in line]
                    error_msg = error_lines[0] if error_lines else output.split("\n")[0]
                else:
                    error_msg = f"Exit code: {result.returncode}"

                _log.error(f"VPN connection failed: {error_msg}")
                return {"success": False, "error": error_msg, "username": username}

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Connection timeout (30s)", "username": username}
        except Exception as e:
            _log.exception(f"Connection error: {e}")
            return {"success": False, "error": str(e), "username": username}

    def _fallback_console_auth(self) -> dict:
        """Fallback to console input if PySimpleGUI not available."""
        _log.warning("PySimpleGUI not available, using console auth")

        try:
            print("\n" + "=" * 60)
            print("HOTSPOT SHIELD VPN AUTHENTICATION")
            print("=" * 60)
            print(f"Profile: {self.profile_name}\n")

            username = input(f"Username [{self.default_username}]: ").strip() or self.default_username
            password = input("Password: ").strip() or self.default_password

            if not username or not password:
                return {"success": False, "error": "Missing credentials", "username": ""}

            print("\n🔗 Connecting...")
            result = self._attempt_connection(username, password)

            if result["success"]:
                print("✅ Connected!\n")
            else:
                print(f"❌ Error: {result['error']}\n")

            return result

        except KeyboardInterrupt:
            return {"success": False, "error": "User cancelled", "username": ""}
        except Exception as e:
            return {"success": False, "error": str(e), "username": ""}


def show_auth_dialog(
    profile_name: str,
    default_username: str = "",
    default_password: str = "",
) -> dict:
    """Convenience function to show auth dialog. Returns result dict."""
    auth = HSSAuthGUI(profile_name, default_username, default_password)
    return auth.show_auth_dialog()
