import pytest
from unittest.mock import patch, MagicMock

import psutil
from blackoutkit.watchdog import monitor

@patch("blackoutkit.security.disable_kill_switch")
@patch("blackoutkit.proxy_manager.clear_system_proxy")
@patch("psutil.Process")
def test_monitor_wait_success(mock_process, mock_clear, mock_disable):
    mock_proc = MagicMock()
    mock_process.return_value = mock_proc
    
    monitor(1234)
    
    mock_process.assert_called_once_with(1234)
    mock_proc.wait.assert_called_once()
    mock_clear.assert_called_once()
    mock_disable.assert_called_once()

@patch("blackoutkit.security.disable_kill_switch")
@patch("blackoutkit.proxy_manager.clear_system_proxy")
@patch("psutil.Process", side_effect=psutil.NoSuchProcess(1234))
def test_monitor_no_such_process(mock_process, mock_clear, mock_disable):
    monitor(1234)
    mock_clear.assert_called_once()
    mock_disable.assert_called_once()

@patch("time.sleep")
@patch("psutil.pid_exists", side_effect=[True, False])
@patch("psutil.Process", side_effect=Exception("wait failed"))
@patch("blackoutkit.proxy_manager.clear_system_proxy")
@patch("blackoutkit.security.disable_kill_switch")
def test_monitor_wait_exception_fallback(mock_disable, mock_clear, mock_process, mock_pid_exists, mock_sleep):
    monitor(1234)
    mock_sleep.assert_called_once_with(1)
    mock_clear.assert_called_once()
    mock_disable.assert_called_once()

@patch("blackoutkit.proxy_manager.clear_system_proxy", side_effect=Exception("clear err"))
@patch("blackoutkit.security.disable_kill_switch", side_effect=Exception("disable err"))
@patch("psutil.Process", side_effect=psutil.NoSuchProcess(1234))
def test_monitor_exceptions_in_cleanup(mock_process, mock_disable, mock_clear):
    monitor(1234)
    mock_clear.assert_called_once()
    mock_disable.assert_called_once()
