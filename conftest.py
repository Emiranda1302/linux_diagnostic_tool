"""
Pytest configuration and shared fixtures
"""

import pytest
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


@pytest.fixture
def sample_ip():
    """Sample IP address for testing"""
    return "192.168.1.100"


@pytest.fixture
def sample_port():
    """Sample port for testing"""
    return 8080


@pytest.fixture
def sample_process_dict():
    """Sample process dictionary"""
    return {
        'pid': 1234,
        'name': 'python3',
        'username': 'testuser',
        'cmdline': 'python3 script.py',
        'created_time_epoch': 1609459200.0,
        'start_time': '2021-01-01 00:00:00',
        'uptime_s': 86400.0
    }


@pytest.fixture
def sample_memory_dict():
    """Sample memory info dictionary"""
    return {
        'ram_total': 16.0,
        'ram_used': 8.5,
        'ram_free': 7.5,
        'ram_percent': 53.1,
        'swap_total': 4.0,
        'swap_used': 0.5,
        'swap_percent': 12.5
    }


@pytest.fixture
def sample_port_info():
    """Sample port information"""
    return {
        'process': 'nginx',
        'ip': '0.0.0.0',
        'port': 80,
        'status': 'LISTEN'
    }


# Pytest configuration
def pytest_configure(config):
    """Add custom markers"""
    config.addinivalue_line(
        "markers", "integration: mark test as integration test"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )
    config.addinivalue_line(
        "markers", "security: mark test as security focused"
    )
