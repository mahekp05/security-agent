"""Tests for configuration management system.

Tests loading, validation, env var overrides, and singleton pattern.
"""

import os
import pytest
import yaml
from pathlib import Path
from tempfile import NamedTemporaryFile

from src.core.config import Config, ConfigError, get_config


class TestConfigLoading:
    """Test YAML config loading."""
    
    def test_load_default_config(self):
        """Test loading default config from project."""
        config = Config()
        assert config.data is not None
        assert 'models' in config.data
        assert 'detector' in config.data['models']
    
    def test_config_file_not_found(self):
        """Test error when config file missing."""
        with pytest.raises(ConfigError, match="Config file not found"):
            Config("/nonexistent/path/config.yaml")
    
    def test_invalid_yaml(self):
        """Test error on invalid YAML syntax."""
        with NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("{ invalid yaml ][")
            f.flush()
            path = f.name
        
        try:
            with pytest.raises(ConfigError, match="Invalid YAML"):
                Config(path)
        finally:
            Path(path).unlink()


class TestConfigValidation:
    """Test config validation rules."""
    
    def test_missing_models_section(self):
        """Test validation fails if 'models' section missing."""
        with NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump({'chunking': {}}, f)
            f.flush()
            path = f.name
        
        try:
            with pytest.raises(ConfigError, match="Config missing 'models' section"):
                Config(path)
        finally:
            Path(path).unlink()
    
    def test_missing_required_model_field(self):
        """Test validation fails if model missing required field."""
        with NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump({
                'models': {
                    'detector': {
                        'model_name': 'test',
                        'max_tokens': 10000,
                        'safety_margin': 0.9,
                        # Missing: temperature
                    }
                }
            }, f)
            f.flush()
            path = f.name
        
        try:
            with pytest.raises(ConfigError, match="missing required field"):
                Config(path)
        finally:
            Path(path).unlink()
    
    def test_token_limit_exceeds_api_max(self):
        """Test validation fails if tokens exceed 32768."""
        with NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump({
                'models': {
                    'detector': {
                        'model_name': 'test',
                        'max_tokens': 35000,
                        'safety_margin': 0.9,
                        'temperature': 0.1,
                    }
                }
            }, f)
            f.flush()
            path = f.name
        
        try:
            with pytest.raises(ConfigError, match="exceeds HF API limit"):
                Config(path)
        finally:
            Path(path).unlink()
    
    def test_safety_margin_below_minimum(self):
        """Test validation fails if safety margin < 0.85."""
        with NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump({
                'models': {
                    'detector': {
                        'model_name': 'test',
                        'max_tokens': 10000,
                        'safety_margin': 0.80,
                        'temperature': 0.1,
                    }
                }
            }, f)
            f.flush()
            path = f.name
        
        try:
            with pytest.raises(ConfigError, match="safety_margin.*below minimum"):
                Config(path)
        finally:
            Path(path).unlink()


class TestEnvVarOverrides:
    """Test environment variable override functionality."""
    
    def test_token_override(self):
        """Test SECURITY_AGENT_DETECTOR_TOKENS env var override."""
        Config.reset()
        os.environ['SECURITY_AGENT_DETECTOR_TOKENS'] = '20000'
        try:
            config = Config()
            # Get the budget (which applies safety margin)
            budget = config.get_budget('detector')
            # 20000 * 0.90 = 18000
            assert budget == 18000
        finally:
            del os.environ['SECURITY_AGENT_DETECTOR_TOKENS']
            Config.reset()
    
    def test_temperature_override(self):
        """Test SECURITY_AGENT_DETECTOR_TEMPERATURE env var override."""
        Config.reset()
        os.environ['SECURITY_AGENT_DETECTOR_TEMPERATURE'] = '0.5'
        try:
            config = Config()
            temp = config.get_temperature('detector')
            assert temp == 0.5
        finally:
            del os.environ['SECURITY_AGENT_DETECTOR_TEMPERATURE']
            Config.reset()
    
    def test_chunking_enabled_override(self):
        """Test SECURITY_AGENT_CHUNKING_ENABLED env var override."""
        Config.reset()
        os.environ['SECURITY_AGENT_CHUNKING_ENABLED'] = 'false'
        try:
            config = Config()
            assert config.is_chunking_enabled() is False
        finally:
            del os.environ['SECURITY_AGENT_CHUNKING_ENABLED']
            Config.reset()
    
    def test_invalid_token_override(self):
        """Test error on non-integer token override."""
        Config.reset()
        os.environ['SECURITY_AGENT_DETECTOR_TOKENS'] = 'not_a_number'
        try:
            with pytest.raises(ConfigError, match="Invalid integer"):
                Config()
        finally:
            del os.environ['SECURITY_AGENT_DETECTOR_TOKENS']
            Config.reset()
    
    def test_invalid_temperature_override(self):
        """Test error on non-float temperature override."""
        Config.reset()
        os.environ['SECURITY_AGENT_DETECTOR_TEMPERATURE'] = 'not_a_float'
        try:
            with pytest.raises(ConfigError, match="Invalid float"):
                Config()
        finally:
            del os.environ['SECURITY_AGENT_DETECTOR_TEMPERATURE']
            Config.reset()


class TestConfigAccessors:
    """Test config accessor methods."""
    
    def test_get_model_config(self):
        """Test get_model_config returns full config dict."""
        config = Config()
        detector_cfg = config.get_model_config('detector')
        assert 'model_name' in detector_cfg
        assert 'max_tokens' in detector_cfg
        assert 'temperature' in detector_cfg
    
    def test_get_model_config_unknown_agent(self):
        """Test error on unknown agent type."""
        config = Config()
        with pytest.raises(ConfigError, match="Unknown agent type"):
            config.get_model_config('unknown')
    
    def test_get_budget_applies_safety_margin(self):
        """Test get_budget applies safety margin."""
        config = Config()
        budget = config.get_budget('detector')
        max_tokens = config.get_model_config('detector')['max_tokens']
        safety_margin = config.get_model_config('detector')['safety_margin']
        expected = int(max_tokens * safety_margin)
        assert budget == expected
    
    def test_get_model_name(self):
        """Test get_model_name returns correct model."""
        config = Config()
        name = config.get_model_name('detector')
        assert isinstance(name, str)
        assert len(name) > 0
    
    def test_get_temperature(self):
        """Test get_temperature returns correct value."""
        config = Config()
        temp = config.get_temperature('judge')
        assert isinstance(temp, float)
        assert 0.0 <= temp <= 1.0


class TestSingletonPattern:
    """Test singleton pattern enforcement."""
    
    def test_load_returns_same_instance(self):
        """Test Config.load() returns same instance on repeated calls."""
        Config.reset()
        config1 = Config.load()
        config2 = Config.load()
        assert config1 is config2
    
    def test_reset_clears_singleton(self):
        """Test Config.reset() clears singleton."""
        config1 = Config.load()
        Config.reset()
        config2 = Config.load()
        assert config1 is not config2
    
    def test_get_config_helper(self):
        """Test get_config() convenience function."""
        Config.reset()
        config = get_config()
        assert isinstance(config, Config)
        assert config is Config._instance


class TestChunkingConfig:
    """Test chunking configuration access."""
    
    def test_is_chunking_enabled_default(self):
        """Test chunking is enabled by default."""
        config = Config()
        assert config.is_chunking_enabled() is True
    
    def test_get_chunking_config(self):
        """Test get_chunking_config returns dict."""
        config = Config()
        chunk_cfg = config.get_chunking_config()
        assert isinstance(chunk_cfg, dict)
        assert 'enabled' in chunk_cfg or chunk_cfg == {}


class TestLoggingAndDebug:
    """Test logging and debug output."""
    
    def test_log_active_config(self):
        """Test log_active_config generates formatted output."""
        config = Config()
        log_output = config.log_active_config()
        
        # Should be multi-line string
        assert isinstance(log_output, str)
        assert len(log_output) > 0
        assert '\n' in log_output
        
        # Should contain key information
        assert 'SECURITY AGENT CONFIG' in log_output
        assert 'detector' in log_output
        assert 'tokens' in log_output
