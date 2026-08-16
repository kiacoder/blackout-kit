import pytest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
from blackoutkit.scanner.ip_scanner import generate_cloudflare_ips, check_ip

def test_generate_cloudflare_ips():
    ips = generate_cloudflare_ips(10)
    assert len(ips) == 10
    
    ips2 = generate_cloudflare_ips(100)
    assert len(ips2) > 80

@pytest.mark.asyncio
async def test_check_ip_success():
    mock_reader = MagicMock()
    mock_writer = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    with patch("asyncio.open_connection", new=AsyncMock(return_value=(mock_reader, mock_writer))):
        result = await check_ip("127.0.0.1", port=443, timeout=1.0)

    assert result is not None
    assert result[0] == "127.0.0.1"
    assert isinstance(result[1], float)
    mock_writer.close.assert_called_once()
    mock_writer.wait_closed.assert_awaited_once()


@pytest.mark.asyncio
async def test_check_ip_closes_writer_when_wait_closed_fails():
    mock_writer = MagicMock()
    mock_writer.wait_closed = AsyncMock(side_effect=OSError("close failure"))
    with patch("asyncio.open_connection", new=AsyncMock(return_value=(MagicMock(), mock_writer))):
        result = await check_ip("127.0.0.1", port=443, timeout=1.0)

    assert result is not None
    mock_writer.close.assert_called_once()
    mock_writer.wait_closed.assert_awaited_once()

@pytest.mark.asyncio
async def test_check_ip_timeout():
    with patch("asyncio.open_connection", new=AsyncMock(side_effect=asyncio.TimeoutError)):
        result = await check_ip("127.0.0.1", port=443, timeout=0.1)

    assert result is None
