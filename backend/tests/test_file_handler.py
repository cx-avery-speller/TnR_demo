"""
Tests for file_handler utility functions, specifically YAML processing security
"""
import pytest
import sys
import os
import tempfile
import yaml

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.file_handler import process_yaml_file


class TestYAMLProcessing:
    """Test YAML file processing with security focus"""

    def test_process_yaml_file_with_safe_content(self):
        """Test processing safe YAML content"""
        # Create temporary YAML file with safe content
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml_content = """
name: Test Project
version: 1.0.0
settings:
  debug: false
  timeout: 30
features:
  - authentication
  - logging
  - monitoring
"""
            f.write(yaml_content)
            temp_path = f.name

        try:
            result = process_yaml_file(temp_path)

            # Verify no error
            assert 'error' not in result

            # Verify content was parsed correctly
            assert result['name'] == 'Test Project'
            assert result['version'] == '1.0.0'
            assert result['settings']['debug'] is False
            assert result['settings']['timeout'] == 30
            assert 'authentication' in result['features']
            assert 'logging' in result['features']
            assert 'monitoring' in result['features']
        finally:
            # Clean up
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_process_yaml_file_with_nested_structures(self):
        """Test processing YAML with nested data structures"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml_content = """
database:
  host: localhost
  port: 5432
  credentials:
    username: testuser
    password: testpass
api:
  endpoints:
    - /api/users
    - /api/projects
    - /api/tasks
  rate_limit: 100
"""
            f.write(yaml_content)
            temp_path = f.name

        try:
            result = process_yaml_file(temp_path)

            # Verify no error
            assert 'error' not in result

            # Verify nested structures
            assert result['database']['host'] == 'localhost'
            assert result['database']['port'] == 5432
            assert result['database']['credentials']['username'] == 'testuser'
            assert len(result['api']['endpoints']) == 3
            assert '/api/users' in result['api']['endpoints']
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_process_yaml_file_with_unicode(self):
        """Test processing YAML with unicode characters"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False, encoding='utf-8') as f:
            yaml_content = """
title: "Tëst Prøjëct"
description: "Unicode test: 你好世界 مرحبا العالم"
emoji: "🚀🔒✅"
"""
            f.write(yaml_content)
            temp_path = f.name

        try:
            result = process_yaml_file(temp_path)

            # Verify no error
            assert 'error' not in result

            # Verify unicode handling
            assert 'Tëst Prøjëct' in result['title']
            assert '你好世界' in result['description']
            assert '🚀' in result['emoji']
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_process_yaml_file_prevents_arbitrary_code_execution(self):
        """
        Critical security test: Verify yaml.safe_load() is used instead of yaml.load()
        This test ensures the CVE-2017-18342 vulnerability is fixed
        """
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            # Malicious YAML that would execute code with yaml.load()
            # but is safely parsed as a string with yaml.safe_load()
            yaml_content = """
malicious: !!python/object/apply:os.system
  args: ['echo "vulnerable"']
"""
            f.write(yaml_content)
            temp_path = f.name

        try:
            result = process_yaml_file(temp_path)

            # With yaml.safe_load(), this should raise an error and be caught
            # The result should contain an error message, not execute code
            assert 'error' in result
            assert 'could not determine a constructor' in result['error'].lower() or \
                   'arbitrary python object' in result['error'].lower() or \
                   'yaml' in result['error'].lower()
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_process_yaml_file_rejects_python_objects(self):
        """
        Security test: Verify Python object serialization is blocked
        """
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            # Attempt to deserialize a Python object (should fail with safe_load)
            yaml_content = """
data: !!python/object:__main__.CustomClass
  attribute: value
"""
            f.write(yaml_content)
            temp_path = f.name

        try:
            result = process_yaml_file(temp_path)

            # Should return error, not deserialize the object
            assert 'error' in result
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_process_yaml_file_handles_invalid_syntax(self):
        """Test handling of invalid YAML syntax"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            # Invalid YAML syntax
            yaml_content = """
name: Test
invalid:
  - item1
    - item2
  bad_indent: value
"""
            f.write(yaml_content)
            temp_path = f.name

        try:
            result = process_yaml_file(temp_path)

            # Should return error for invalid syntax
            assert 'error' in result
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_process_yaml_file_with_empty_file(self):
        """Test processing empty YAML file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("")
            temp_path = f.name

        try:
            result = process_yaml_file(temp_path)

            # Empty YAML should return None or empty dict
            # No error should occur
            assert result is None or result == {}
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_process_yaml_file_with_nonexistent_file(self):
        """Test handling of non-existent file"""
        result = process_yaml_file('/tmp/nonexistent_yaml_file_12345.yaml')

        # Should return error
        assert 'error' in result

    def test_process_yaml_file_with_large_file(self):
        """Test processing large YAML file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            # Create a large YAML with many entries
            f.write("items:\n")
            for i in range(1000):
                f.write(f"  - id: {i}\n")
                f.write(f"    name: item_{i}\n")
                f.write(f"    value: {i * 10}\n")
            temp_path = f.name

        try:
            result = process_yaml_file(temp_path)

            # Should parse successfully
            assert 'error' not in result
            assert 'items' in result
            assert len(result['items']) == 1000
            assert result['items'][0]['id'] == 0
            assert result['items'][999]['id'] == 999
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_yaml_safe_load_directly(self):
        """
        Direct test to verify yaml.safe_load() behavior with malicious content
        This validates that PyYAML 6.0.1 correctly blocks unsafe operations
        """
        malicious_yaml = """
!!python/object/apply:os.system
args: ['echo vulnerable']
"""

        # This should raise an exception with safe_load
        with pytest.raises(yaml.YAMLError):
            yaml.safe_load(malicious_yaml)

    def test_yaml_safe_load_with_valid_data(self):
        """
        Verify yaml.safe_load() works correctly with valid data
        """
        valid_yaml = """
name: Test
count: 42
items:
  - first
  - second
enabled: true
"""

        # This should work fine
        data = yaml.safe_load(valid_yaml)
        assert data['name'] == 'Test'
        assert data['count'] == 42
        assert len(data['items']) == 2
        assert data['enabled'] is True


class TestYAMLVersionCompatibility:
    """Test PyYAML 6.0.1 compatibility"""

    def test_pyyaml_version(self):
        """Verify PyYAML version is 6.0.1 or higher"""
        import yaml
        version = yaml.__version__

        # Parse version
        major, minor, patch = map(int, version.split('.'))

        # Should be at least 6.0.1 (CVE-2017-18342 fixed in 5.1b1)
        assert major >= 6
        if major == 6 and minor == 0:
            assert patch >= 1

    def test_safe_load_function_exists(self):
        """Verify yaml.safe_load() function exists"""
        import yaml
        assert hasattr(yaml, 'safe_load')
        assert callable(yaml.safe_load)

    def test_unsafe_loader_warning(self):
        """Verify that UnsafeLoader exists but requires explicit use"""
        import yaml

        # UnsafeLoader should exist for backward compatibility
        # but should not be used by default
        assert hasattr(yaml, 'UnsafeLoader')


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
