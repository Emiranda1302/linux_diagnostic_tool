"""
Comprehensive unit tests for system module
Tests cover: CPU, Memory, Ports, Failed Logins
Coverage target: 85%+
"""

import pytest
import psutil
from unittest.mock import patch, MagicMock, mock_open
from datetime import datetime
import re

from ldt.modules.system import (
    get_running_processes,
    get_cpu_info,
    get_memory_info,
    get_listening_ports,
    get_failed_logins,
)


# ============================================================================
# TEST FIXTURES
# ============================================================================

@pytest.fixture
def mock_process():
    """Mock psutil.Process object"""
    mock = MagicMock()
    mock.info = {
        'pid': 1234,
        'name': 'python3',
        'username': 'testuser',
        'cmdline': ['python3', 'script.py'],
        'create_time': 1609459200.0,
    }
    return mock


@pytest.fixture
def mock_connection():
    """Mock psutil connection object"""
    mock = MagicMock()
    mock.status = 'LISTEN'
    mock.pid = 1234
    mock.laddr.ip = '127.0.0.1'
    mock.laddr.port = 8080
    return mock


# ============================================================================
# TESTS: get_running_processes
# ============================================================================

class TestGetRunningProcesses:
    """Tests for get_running_processes function"""
    
    @patch('ldt.modules.system.psutil.process_iter')
    @patch('ldt.modules.system.time.time')
    def test_get_running_processes_returns_list(self, mock_time, mock_process_iter, mock_process):
        """Test that function returns a list"""
        mock_time.return_value = 1609460000.0
        mock_process_iter.return_value = [mock_process]
        
        result = get_running_processes()
        
        assert isinstance(result, list)
        assert len(result) > 0
    
    @patch('ldt.modules.system.psutil.process_iter')
    @patch('ldt.modules.system.time.time')
    def test_process_has_required_fields(self, mock_time, mock_process_iter, mock_process):
        """Test that each process has all required fields"""
        mock_time.return_value = 1609460000.0
        mock_process_iter.return_value = [mock_process]
        
        result = get_running_processes()
        process = result[0]
        
        required_fields = [
            'pid', 'name', 'username', 'cmdline',
            'created_time_epoch', 'start_time', 'uptime_s'
        ]
        
        for field in required_fields:
            assert field in process, f"Missing field: {field}"
    
    @patch('ldt.modules.system.psutil.process_iter')
    @patch('ldt.modules.system.time.time')
    def test_uptime_calculation(self, mock_time, mock_process_iter, mock_process):
        """Test that uptime is calculated correctly"""
        current_time = 1609460000.0
        create_time = 1609459200.0
        expected_uptime = 800.0
        
        mock_time.return_value = current_time
        mock_process.info['create_time'] = create_time
        mock_process_iter.return_value = [mock_process]
        
        result = get_running_processes()
        
        assert result[0]['uptime_s'] == expected_uptime
    
    @patch('ldt.modules.system.psutil.process_iter')
    def test_handles_no_such_process_exception(self, mock_process_iter, capsys):
        """Test that NoSuchProcess exception is handled gracefully"""
        mock_proc = MagicMock()
        mock_proc.info = {'pid': 1234, 'name': 'test'}
        mock_proc.__iter__.side_effect = psutil.NoSuchProcess(1234)
        
        with patch('ldt.modules.system.time.time', return_value=1609460000.0):
            result = get_running_processes()
        
        # Should return a list even with exception
        assert isinstance(result, list)


# ============================================================================
# TESTS: get_cpu_info
# ============================================================================

class TestGetCPUInfo:
    """Tests for get_cpu_info function"""
    
    @patch('ldt.modules.system.psutil.process_iter')
    @patch('ldt.modules.system.time.sleep')
    def test_get_cpu_info_returns_list(self, mock_sleep, mock_process_iter, mock_process):
        """Test that get_cpu_info returns a list"""
        mock_process.cpu_percent.return_value = 25.5
        mock_process.info['status'] = 'running'
        mock_process.info['cpu_percent'] = 25.5
        mock_process.info['memory_percent'] = 5.0
        
        mock_process_iter.return_value = [mock_process]
        
        result = get_cpu_info()
        
        assert isinstance(result, list)
    
    @patch('ldt.modules.system.psutil.process_iter')
    @patch('ldt.modules.system.time.sleep')
    def test_cpu_info_structure(self, mock_sleep, mock_process_iter, mock_process):
        """Test that CPU info has correct structure"""
        mock_process.cpu_percent.return_value = 25.5
        mock_process.info = {
            'pid': 1234,
            'name': 'python3',
            'username': 'testuser',
            'status': 'running',
            'cpu_percent': 25.5,
            'memory_percent': 5.0
        }
        
        mock_process_iter.return_value = [mock_process]
        
        result = get_cpu_info()
        
        if result:
            cpu_data = result[0]
            assert 'pid' in cpu_data
            assert 'name' in cpu_data
            assert 'cpu_percent' in cpu_data
            assert 'memory_percent' in cpu_data
    
    @patch('ldt.modules.system.psutil.process_iter')
    @patch('ldt.modules.system.time.sleep')
    def test_cpu_percent_non_negative(self, mock_sleep, mock_process_iter, mock_process):
        """Test that CPU percentage is non-negative"""
        mock_process.cpu_percent.return_value = 15.0
        mock_process.info['cpu_percent'] = 15.0
        mock_process_iter.return_value = [mock_process]
        
        result = get_cpu_info()
        
        if result:
            assert result[0]['cpu_percent'] >= 0


# ============================================================================
# TESTS: get_memory_info
# ============================================================================

class TestGetMemoryInfo:
    """Tests for get_memory_info function"""
    
    def test_get_memory_info_returns_dict(self):
        """Test that get_memory_info returns a dictionary"""
        result = get_memory_info()
        assert isinstance(result, dict)
    
    def test_memory_info_has_required_keys(self):
        """Test that result contains all required keys"""
        result = get_memory_info()
        
        required_keys = [
            'ram_total', 'ram_used', 'ram_free', 'ram_percent',
            'swap_total', 'swap_used', 'swap_percent'
        ]
        
        for key in required_keys:
            assert key in result, f"Missing key: {key}"
    
    def test_memory_percentages_valid_range(self):
        """Test that memory percentages are between 0-100"""
        result = get_memory_info()
        
        assert 0 <= result['ram_percent'] <= 100, "RAM percent out of range"
        assert 0 <= result['swap_percent'] <= 100, "Swap percent out of range"
    
    def test_memory_values_non_negative(self):
        """Test that all memory values are non-negative"""
        result = get_memory_info()
        
        assert result['ram_total'] >= 0, "RAM total is negative"
        assert result['ram_used'] >= 0, "RAM used is negative"
        assert result['ram_free'] >= 0, "RAM free is negative"
        assert result['swap_total'] >= 0, "Swap total is negative"
    
    def test_ram_used_less_than_total(self):
        """Test that used RAM is less than total RAM"""
        result = get_memory_info()
        assert result['ram_used'] <= result['ram_total'], \
            "Used RAM cannot exceed total RAM"
    
    def test_memory_values_are_float(self):
        """Test that memory values are float type"""
        result = get_memory_info()
        
        for key in ['ram_total', 'ram_used', 'ram_free', 'ram_percent',
                    'swap_total', 'swap_used', 'swap_percent']:
            assert isinstance(result[key], (int, float)), \
                f"{key} is not numeric"


# ============================================================================
# TESTS: get_listening_ports
# ============================================================================

class TestGetListeningPorts:
    """Tests for get_listening_ports function"""
    
    @patch('ldt.modules.system.psutil.net_connections')
    @patch('ldt.modules.system.psutil.Process')
    def test_get_listening_ports_returns_list(self, mock_process_class, 
                                               mock_connections, mock_connection):
        """Test that get_listening_ports returns a list"""
        mock_connections.return_value = [mock_connection]
        mock_proc = MagicMock()
        mock_proc.name.return_value = 'nginx'
        mock_process_class.return_value = mock_proc
        
        result = get_listening_ports()
        
        assert isinstance(result, list)
    
    @patch('ldt.modules.system.psutil.net_connections')
    @patch('ldt.modules.system.psutil.Process')
    def test_listening_port_structure(self, mock_process_class, 
                                      mock_connections, mock_connection):
        """Test that port info has correct structure"""
        mock_connections.return_value = [mock_connection]
        mock_proc = MagicMock()
        mock_proc.name.return_value = 'nginx'
        mock_process_class.return_value = mock_proc
        
        result = get_listening_ports()
        
        if result:
            port_info = result[0]
            assert 'process' in port_info
            assert 'ip' in port_info
            assert 'port' in port_info
            assert 'states' in port_info
    
    @patch('ldt.modules.system.psutil.net_connections')
    @patch('ldt.modules.system.psutil.Process')
    def test_only_listening_sockets_returned(self, mock_process_class,
                                             mock_connections, mock_connection):
        """Test that only LISTEN status connections are returned"""
        listening_conn = MagicMock()
        listening_conn.status = 'LISTEN'
        listening_conn.pid = 1234
        listening_conn.laddr.ip = '127.0.0.1'
        listening_conn.laddr.port = 8080
        
        established_conn = MagicMock()
        established_conn.status = 'ESTABLISHED'
        
        mock_connections.return_value = [listening_conn, established_conn]
        mock_proc = MagicMock()
        mock_proc.name.return_value = 'test_process'
        mock_process_class.return_value = mock_proc
        
        result = get_listening_ports()
        
        # Only listening connections should be returned
        assert all(conn['states'] == 'LISTEN' for conn in result)
    
    @patch('ldt.modules.system.psutil.net_connections')
    @patch('ldt.modules.system.psutil.Process')
    def test_port_number_is_valid(self, mock_process_class, 
                                   mock_connections, mock_connection):
        """Test that port numbers are in valid range"""
        mock_connections.return_value = [mock_connection]
        mock_proc = MagicMock()
        mock_proc.name.return_value = 'test'
        mock_process_class.return_value = mock_proc
        
        result = get_listening_ports()
        
        if result:
            for conn in result:
                assert 1 <= conn['port'] <= 65535, \
                    f"Port {conn['port']} is out of valid range"


# ============================================================================
# TESTS: get_failed_logins
# ============================================================================

class TestGetFailedLogins:
    """Tests for get_failed_logins function"""
    
    @patch('ldt.modules.system.subprocess.run')
    def test_get_failed_logins_returns_list(self, mock_run):
        """Test that get_failed_logins returns a list"""
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_run.return_value = mock_result
        
        result = get_failed_logins()
        
        assert isinstance(result, list)
    
    @patch('ldt.modules.system.subprocess.run')
    def test_failed_login_structure(self, mock_run):
        """Test that failed login has correct structure"""
        log_line = "Jan 01 12:34:56 hostname sshd[1234]: Failed password for invalid user testuser from 192.168.1.100 port 12345"
        
        mock_result = MagicMock()
        mock_result.stdout = log_line
        mock_run.return_value = mock_result
        
        result = get_failed_logins()
        
        if result:
            login = result[0]
            assert 'timestamp' in login
            assert 'username' in login or 'status' in login
            assert 'remote_ip' in login
            assert 'port' in login
    
    @patch('ldt.modules.system.subprocess.run')
    def test_empty_log_returns_empty_list(self, mock_run):
        """Test that empty logs return empty list"""
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_run.return_value = mock_result
        
        result = get_failed_logins()
        
        assert isinstance(result, list)
        assert len(result) == 0
    
    @patch('ldt.modules.system.subprocess.run')
    def test_journalctl_called_with_correct_args(self, mock_run):
        """Test that journalctl is called with correct arguments"""
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_run.return_value = mock_result
        
        get_failed_logins()
        
        # Verify subprocess was called correctly
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        assert 'journalctl' in call_args
        assert '-u' in call_args
        assert 'ssh' in call_args


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

class TestSystemModuleIntegration:
    """Integration tests for the system module"""
    
    def test_all_functions_callable(self):
        """Test that all major functions are callable"""
        assert callable(get_running_processes)
        assert callable(get_cpu_info)
        assert callable(get_memory_info)
        assert callable(get_listening_ports)
        assert callable(get_failed_logins)
    
    def test_no_import_errors(self):
        """Test that module imports without errors"""
        # If we got this far, imports succeeded
        assert True


# ============================================================================
# PERFORMANCE TESTS
# ============================================================================

class TestSystemModulePerformance:
    """Performance tests for system functions"""
    
    @pytest.mark.timeout(5)
    def test_get_memory_info_performance(self):
        """Test that get_memory_info completes in reasonable time"""
        import time
        start = time.time()
        get_memory_info()
        elapsed = time.time() - start
        
        assert elapsed < 1.0, f"get_memory_info took {elapsed}s (should be <1s)"
    
    @pytest.mark.timeout(10)
    def test_get_running_processes_performance(self):
        """Test that get_running_processes completes in reasonable time"""
        import time
        start = time.time()
        get_running_processes()
        elapsed = time.time() - start
        
        assert elapsed < 5.0, f"get_running_processes took {elapsed}s (should be <5s)"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
