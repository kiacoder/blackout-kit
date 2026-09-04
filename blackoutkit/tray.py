"""
Blackout Kit - System Tray Integration
Provides a background system tray icon for daemon management.
"""
import sys
import threading
from pathlib import Path


def _create_image():
    try:
        # Try loading custom icon first
        import sys

        from PIL import Image, ImageDraw
        if getattr(sys, 'frozen', False):
            icon_path = Path(sys._MEIPASS) / "bins" / "icon.png"
        else:
            icon_path = Path(__file__).parent.parent / "bins" / "icon.png"

        if icon_path.exists():
            return Image.open(str(icon_path))
            
        # Fallback to generating one with transparency
        img = Image.new('RGBA', (64, 64), color=(0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        d.text((10, 20), 'BK', fill=(255, 0, 0, 255))
        return img
    except ImportError:
        return None

def start_tray(engine_name: str, stop_callback=None):
    """
    Start the system tray icon (blocking).
    If stop_callback is provided, it is called when the user clicks 'Quit'.
    """
    if sys.platform != "win32":
        return

    try:
        import pystray
        from pystray import MenuItem as item
    except ImportError:
        return

    image = _create_image()
    if not image:
        return

    def on_quit(icon, item):
        icon.stop()
        if stop_callback:
            # We must call stop_callback in a thread, because icon.stop() 
            # tears down the event loop, but we want to make sure the app shuts down cleanly.
            threading.Thread(target=stop_callback, daemon=False).start()

    menu = pystray.Menu(
        item(f"Blackout Kit ({engine_name})", lambda: None, enabled=False),
        pystray.Menu.SEPARATOR,
        item('Quit / Disconnect', on_quit)
    )

    icon = pystray.Icon("blackout-kit", image, "Blackout Kit Active", menu)
    icon.run()
