import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

from blackoutkit.tray import _create_image, start_tray

@patch.dict("sys.modules", {"PIL": MagicMock(), "PIL.Image": MagicMock(), "PIL.ImageDraw": MagicMock()})
@patch("pathlib.Path.exists")
def test_create_image_exists(mock_exists):
    import PIL.Image
    mock_exists.return_value = True
    PIL.Image.open.return_value = "img_obj"
    img = _create_image()
    assert img == "img_obj"

@patch.dict("sys.modules", {"PIL": MagicMock(), "PIL.Image": MagicMock(), "PIL.ImageDraw": MagicMock()})
@patch("pathlib.Path.exists")
def test_create_image_fallback(mock_exists):
    import PIL.Image
    mock_exists.return_value = False
    PIL.Image.new.return_value = "new_img"
    img = _create_image()
    assert img == "new_img"

@patch.dict("sys.modules", {"PIL": None})
def test_create_image_no_pil():
    assert _create_image() is None

@patch("sys.platform", "linux")
def test_start_tray_linux():
    start_tray("sni")

@patch("sys.platform", "win32")
@patch.dict("sys.modules", {"pystray": None})
def test_start_tray_no_pystray():
    start_tray("sni")

@patch("sys.platform", "win32")
@patch.dict("sys.modules", {"pystray": MagicMock()})
@patch("blackoutkit.tray._create_image")
def test_start_tray_no_image(mock_create):
    mock_create.return_value = None
    start_tray("sni")

@patch("sys.platform", "win32")
@patch.dict("sys.modules", {"pystray": MagicMock(), "pystray.MenuItem": MagicMock()})
@patch("blackoutkit.tray._create_image")
def test_start_tray_success(mock_create):
    import pystray
    mock_create.return_value = "img"
    mock_icon_cls = MagicMock()
    pystray.Icon = mock_icon_cls
    mock_icon_instance = mock_icon_cls.return_value
    
    start_tray("sni")
    mock_icon_instance.run.assert_called_once()

@patch("sys.platform", "win32")
@patch.dict("sys.modules", {"pystray": MagicMock(), "pystray.MenuItem": MagicMock()})
@patch("blackoutkit.tray._create_image")
def test_start_tray_on_quit(mock_create):
    import pystray
    mock_create.return_value = "img"
    
    mock_item = MagicMock()
    pystray.MenuItem = mock_item
    
    cb_called = False
    def my_cb():
        nonlocal cb_called
        cb_called = True
        
    start_tray("sni", stop_callback=my_cb)
    
    on_quit_cb = None
    for call in mock_item.call_args_list:
        if call.args[0] == 'Quit / Disconnect':
            on_quit_cb = call.args[1]
            break
            
    assert on_quit_cb is not None
    mock_icon = MagicMock()
    on_quit_cb(mock_icon, None)
    mock_icon.stop.assert_called_once()
    
    import time
    time.sleep(0.1)
    assert cb_called is True
