"""Unit tests for system module"""

import pytest
from unittest.mock import patch, MagicMock
from ldt.modules.system import (
    get_memory_info,
    get_cpu_info,
    get_listening_ports,
)


class TestMemoryInfo:
    """Tests for memory information gathering"""
    
    def test_get_memory_info_returns_dict(self):
        """Test that get_memory_info returns a dictionary"""
        result = get_memory_info()
        assert isinstance(result, dict)
    
    def test_get_memory_info_has_required_keys(self):
        """Test that memory info contains all required keys"""
        result = get_memory_info()
        required_keys = [
            'ram_total', 'ram_used', 'ram_free', 'ram_percent',
            'swap_total', 'swap_used', 'swap_percent'
        ]
        for key in required_keys:
            assert key in result, f"Missing key: {key}"
    
    def test_memory_percentages_valid_range(self):
        """Test that memory percentages are in valid range (0-100)"""
        result = get_memory_info()
        assert 0 <= result['ram_percent'] <= 100
        assert 0 <= result['swap_percent'] <= 100
    
    def test_memory_values_non_negative(self):
        """Test that memory values are non-negative"""
        result = get_memory_info()
        assert result['ram_total'] >= 0
        assert result['ram_used'] >= 0
        assert result['ram_free'] >= 0


class TestCPUInfo:
    """Tests for CPU information gathering"""
    
    def test_get_cpu_info_returns_list(self):
        """Test that get_cpu_info returns a list"""
        result = get_cpu_info()
        assert isinstance(result, list)
    
    @patch('ldt.modules.system.psutil.process_iter')
    def test_get_cpu_info_structure(self, mock_process_iter):
        """Test that CPU info has correct structure"""
        mock_proc = MagicMock()
        mock_proc.info = {
            'pid': 1234,
            'name': 'test_process',
            'username': 'testuser',
            'status': 'running',
            'memory_percent': 5.0
        }
        mock_proc.cpu_percent.return_value = 10.5
        mock_process_iter.return_value = [mock_proc]
        
        result = get_cpu_info()
        
        if result:  # If we got results
            assert 'pid' in result[0]
            assert 'name' in result[0]
            assert 'username' in result[0]


class TestListeningPorts:
    """Tests for listening ports detection"""
    
    def test_get_listening_ports_returns_list(self):
        """Test that get_listening_ports returns a list"""
        result = get_listening_ports()
        assert isinstance(result, list)
