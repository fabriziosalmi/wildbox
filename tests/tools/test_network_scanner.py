"""
Tests for the Secure Network Scanner.
"""
import pytest
from pydantic import ValidationError

# Make the test path-independent
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../open-security-tools/app')))

from tools.network_scanner.schemas import SecureNetworkScannerInput
from tools.network_scanner.main import execute_secure_scanner

@pytest.mark.asyncio
async def test_scan_single_ip_alive():
    """Test scanning a single IP that is expected to be alive (localhost)."""
    input_data = SecureNetworkScannerInput(network="127.0.0.1")
    result = await execute_secure_scanner(input_data)
    
    assert result.success is True
    assert len(result.hosts) == 1
    assert result.hosts[0].ip_address == "127.0.0.1"
    assert result.hosts[0].status == "alive"
    assert "1 alive" in result.summary

@pytest.mark.asyncio
async def test_network_too_large():
    """Test that a network larger than the allowed limit is rejected."""
    # /21 has 2048 addresses, which is larger than the default 1024 limit
    input_data = SecureNetworkScannerInput(network="192.168.0.0/21")
    result = await execute_secure_scanner(input_data)
    
    assert result.success is False
    assert "Network is too large" in result.error
    assert len(result.hosts) == 0



@pytest.mark.asyncio
async def test_scan_small_network():
    """Test scanning a small /30 network."""
    # This will scan .1 and .2
    input_data = SecureNetworkScannerInput(network="192.168.255.0/30")
    result = await execute_secure_scanner(input_data)
    
    assert result.success is True
    assert len(result.hosts) == 2
    # We don't know which will be alive, but we expect them to be unreachable
    assert result.hosts[0].status == "unreachable"
    assert result.hosts[1].status == "unreachable"
    assert "0 alive" in result.summary
