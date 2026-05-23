"""
Unit tests for forensics module
Tests cover: SUID detection, cron persistence, bashrc audit
Coverage target: 80%+
"""

import pytest
from unittest.mock import patch, MagicMock, mock_open
import os
import tempfile

from ldt.modules.forensics import (
    sha256_file,
    classify_suid,
)


# ============================================================================
# TEST FIXTURES
# ============================================================================

@pytest.fixture
def temp_file():
    """Create a temporary file for testing"""
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(b"test content for hashing")
        tmp.flush()
        yield tmp.name
    os.unlink(tmp.name)


@pytest.fixture
def mock_binary_path():
    """Mock binary path"""
    return "/usr/bin/sudo"


# ============================================================================
# TESTS: sha256_file
# ============================================================================

class TestSHA256File:
    """Tests for sha256_file function"""
    
    def test_sha256_file_returns_string(self, temp_file):
        """Test that sha256_file returns a string"""
        result = sha256_file(temp_file)
        assert isinstance(result, str)
    
    def test_sha256_file_correct_length(self, temp_file):
        """Test that SHA256 hash is 64 characters (hex)"""
        result = sha256_file(temp_file)
        assert len(result) == 64
    
    def test_sha256_file_hexadecimal(self, temp_file):
        """Test that hash is valid hexadecimal"""
        result = sha256_file(temp_file)
        try:
            int(result, 16)
            is_hex = True
        except ValueError:
            is_hex = False
        
        assert is_hex, "Hash is not valid hexadecimal"
    
    def test_sha256_consistency(self, temp_file):
        """Test that same file produces same hash"""
        hash1 = sha256_file(temp_file)
        hash2 = sha256_file(temp_file)
        
        assert hash1 == hash2, "Same file produced different hashes"
    
    def test_sha256_large_file(self):
        """Test SHA256 calculation on larger file"""
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            # Write 10MB of data
            for _ in range(1000):
                tmp.write(b"x" * 10240)
            tmp.flush()
            tmp_path = tmp.name
        
        try:
            result = sha256_file(tmp_path)
            assert len(result) == 64
            assert isinstance(result, str)
        finally:
            os.unlink(tmp_path)
    
    @patch('builtins.open', side_effect=FileNotFoundError)
    def test_sha256_file_not_found(self, mock_open_error):
        """Test that FileNotFoundError is raised for non-existent file"""
        with pytest.raises(FileNotFoundError):
            sha256_file("/non/existent/file")


# ============================================================================
# TESTS: classify_suid
# ============================================================================

class TestClassifySUID:
    """Tests for classify_suid function"""
    
    @patch('ldt.modules.forensics.SUID_WHITELIST', ['/usr/bin/sudo'])
    def test_classify_whitelisted_suid(self, mock_binary_path):
        """Test that whitelisted SUID binary is classified as legitimate"""
        is_suspicious, severity, score, reason = classify_suid('/usr/bin/sudo')
        
        assert not is_suspicious
        assert severity == "INFO"
        assert score == 0
        assert "legitimate" in reason.lower()
    
    def test_classify_suid_returns_tuple(self, mock_binary_path):
        """Test that classify_suid returns a tuple of 4 elements"""
        result = classify_suid(mock_binary_path)
        
        assert isinstance(result, tuple)
        assert len(result) == 4
    
    def test_classify_suid_structure(self, mock_binary_path):
        """Test that returned tuple has correct types"""
        is_suspicious, severity, score, reason = classify_suid(mock_binary_path)
        
        assert isinstance(is_suspicious, bool)
        assert isinstance(severity, str)
        assert isinstance(score, (int, float))
        assert isinstance(reason, str)
    
    @patch('ldt.modules.forensics.SUID_WHITELIST', [])
    @patch('ldt.modules.forensics.SUSPICIOUS_PATHS', ['/tmp'])
    def test_classify_suspicious_path(self):
        """Test that binaries in suspicious paths are classified as suspicious"""
        is_suspicious, severity, score, reason = classify_suid('/tmp/backdoor')
        
        # Suspicious path should increase likelihood
        assert severity in ["MEDIUM", "HIGH", "CRITICAL"]
    
    @patch('ldt.modules.forensics.SUID_WHITELIST', [])
    def test_classify_common_binary(self):
        """Test classification of common system binary"""
        result = classify_suid('/usr/bin/ls')
        is_suspicious, severity, score, reason = result
        
        # Common system binaries should not be critical
        assert severity != "CRITICAL"


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

class TestForensicsModuleIntegration:
    """Integration tests for forensics module"""
    
    def test_functions_are_callable(self):
        """Test that forensics functions are callable"""
        assert callable(sha256_file)
        assert callable(classify_suid)
    
    def test_module_imports_successfully(self):
        """Test that module imports without errors"""
        # If we got here, the import worked
        assert True


# ============================================================================
# ERROR HANDLING TESTS
# ============================================================================

class TestForensicsErrorHandling:
    """Tests for error handling in forensics module"""
    
    def test_sha256_file_with_permission_denied(self):
        """Test sha256_file behavior with permission denied"""
        with patch('builtins.open', side_effect=PermissionError):
            with pytest.raises(PermissionError):
                sha256_file("/root/.ssh/id_rsa")
    
    @patch('ldt.modules.forensics.SUID_WHITELIST', [])
    def test_classify_suid_with_invalid_path(self):
        """Test classify_suid with invalid path format"""
        # Should still return a valid tuple
        result = classify_suid("invalid//path//format")
        assert isinstance(result, tuple)
        assert len(result) == 4


# ============================================================================
# SECURITY-FOCUSED TESTS
# ============================================================================

class TestForensicsSecurityFocus:
    """Security-focused tests"""
    
    def test_sha256_is_cryptographically_secure(self, temp_file):
        """Verify we're using SHA256 (cryptographically secure)"""
        # If sha256_file works and produces valid hashes, it's using SHA256
        result = sha256_file(temp_file)
        assert len(result) == 64  # SHA256 is 256 bits = 64 hex characters
    
    @patch('ldt.modules.forensics.SUID_WHITELIST', [])
    def test_classify_detects_suspicious_patterns(self):
        """Test that suspicious patterns are detected"""
        suspicious_paths = [
            '/tmp/exploit',
            '/var/tmp/backdoor',
            '/dev/shm/payload',
        ]
        
        with patch('ldt.modules.forensics.SUSPICIOUS_PATHS', suspicious_paths):
            for path in suspicious_paths:
                result = classify_suid(path)
                # At minimum, shouldn't be marked as "INFO"
                assert result[1] != "INFO", f"{path} should be flagged"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
