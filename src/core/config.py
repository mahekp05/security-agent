"""Configuration management for security-agent.

Loads YAML config, validates parameters, merges environment variable overrides.
Provides singleton Config instance for application-wide access.
"""

import os
import sys
from pathlib import Path
from typing import Optional, Dict, Any
import yaml


class ConfigError(Exception):
    """Configuration validation error."""
    pass


class Config:
    """Configuration manager - loads YAML, validates, merges env vars."""
    
    _instance: Optional['Config'] = None
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize config from YAML file."""
        if config_path is None:
            # Default: config/model_config.yaml relative to project root
            config_path = Path(__file__).parent.parent.parent / "config" / "model_config.yaml"
        
        self.config_path = Path(config_path)
        self.data: Dict[str, Any] = {}
        self._load()
        self._validate()
        self._apply_env_overrides()
        self._validate()  # Re-validate to catch invalid env var overrides
    
    def _load(self) -> None:
        """Load YAML config file."""
        if not self.config_path.exists():
            raise ConfigError(f"Config file not found: {self.config_path}")
        
        try:
            with open(self.config_path, 'r') as f:
                self.data = yaml.safe_load(f)
            if self.data is None:
                self.data = {}
        except yaml.YAMLError as e:
            raise ConfigError(f"Invalid YAML in {self.config_path}: {e}")
    
    def _validate(self) -> None:
        """Validate config parameters (called before and after env var overrides).
        
        Checks:
        - All required fields present
        - Token limits <= 32,768 (HF API hard limit)
        - Safety margin >= 0.85 (security constraint)
        """
        if 'models' not in self.data:
            raise ConfigError("Config missing 'models' section")
        
        # Check each model has required fields
        required_model_fields = ['model_name', 'max_tokens', 'safety_margin', 'temperature']
        for agent_type, model_cfg in self.data['models'].items():
            for field in required_model_fields:
                if field not in model_cfg:
                    raise ConfigError(f"Model '{agent_type}' missing required field: {field}")
            
            # Validate token limits
            max_tokens = model_cfg['max_tokens']
            safety_margin = model_cfg['safety_margin']
            
            if max_tokens > 32768:
                raise ConfigError(
                    f"Model '{agent_type}' max_tokens ({max_tokens}) exceeds HF API limit (32768)"
                )
            if safety_margin < 0.85:
                raise ConfigError(
                    f"Model '{agent_type}' safety_margin ({safety_margin}) below minimum (0.85)"
                )
    
    def _apply_env_overrides(self) -> None:
        """Apply environment variable overrides to config."""
        # Example: SECURITY_AGENT_DETECTOR_TOKENS=26000
        # Example: SECURITY_AGENT_DETECTOR_TEMPERATURE=0.2
        
        for agent_type in self.data.get('models', {}).keys():
            # Token override
            env_key = f"SECURITY_AGENT_{agent_type.upper()}_TOKENS"
            if env_key in os.environ:
                try:
                    self.data['models'][agent_type]['max_tokens'] = int(os.environ[env_key])
                except ValueError:
                    raise ConfigError(f"Invalid integer for {env_key}: {os.environ[env_key]}")
            
            # Temperature override
            env_key = f"SECURITY_AGENT_{agent_type.upper()}_TEMPERATURE"
            if env_key in os.environ:
                try:
                    self.data['models'][agent_type]['temperature'] = float(os.environ[env_key])
                except ValueError:
                    raise ConfigError(f"Invalid float for {env_key}: {os.environ[env_key]}")
        
        # Chunking enabled override
        if "SECURITY_AGENT_CHUNKING_ENABLED" in os.environ:
            enabled = os.environ["SECURITY_AGENT_CHUNKING_ENABLED"].lower() == 'true'
            if 'chunking' not in self.data:
                self.data['chunking'] = {}
            self.data['chunking']['enabled'] = enabled
    
    @classmethod
    def load(cls, config_path: Optional[str] = None) -> 'Config':
        """Load config (singleton pattern)."""
        if cls._instance is None:
            cls._instance = cls(config_path)
        return cls._instance
    
    @classmethod
    def reset(cls) -> None:
        """Reset singleton (for testing)."""
        cls._instance = None
    
    def get_model_config(self, agent_type: str) -> Dict[str, Any]:
        """Get config for a specific agent (detector, prosecutor, defender, judge)."""
        if agent_type not in self.data.get('models', {}):
            raise ConfigError(f"Unknown agent type: {agent_type}")
        return self.data['models'][agent_type]
    
    def get_budget(self, agent_type: str) -> int:
        """Get token budget (safety margin applied)."""
        model_cfg = self.get_model_config(agent_type)
        max_tokens = model_cfg['max_tokens']
        safety_margin = model_cfg['safety_margin']
        return int(max_tokens * safety_margin)
    
    def get_model_name(self, agent_type: str) -> str:
        """Get model name for agent."""
        return self.get_model_config(agent_type)['model_name']
    
    def get_temperature(self, agent_type: str) -> float:
        """Get temperature for agent."""
        return self.get_model_config(agent_type)['temperature']
    
    def is_chunking_enabled(self) -> bool:
        """Check if chunking is enabled."""
        return self.data.get('chunking', {}).get('enabled', True)
    
    def get_chunking_config(self) -> Dict[str, Any]:
        """Get chunking parameters."""
        return self.data.get('chunking', {})
    
    def log_active_config(self) -> str:
        """Return formatted config summary for logging."""
        lines = ["=== SECURITY AGENT CONFIG ==="]
        lines.append(f"Config file: {self.config_path}")
        lines.append("")
        lines.append("Models:")
        for agent_type, cfg in self.data.get('models', {}).items():
            budget = self.get_budget(agent_type)
            lines.append(
                f"  {agent_type:12} - {cfg['model_name']:35} "
                f"tokens: {cfg['max_tokens']:5} (budget: {budget:5}) "
                f"temp: {cfg['temperature']:.1f}"
            )
        
        lines.append("")
        lines.append("Chunking:")
        chunk_cfg = self.get_chunking_config()
        lines.append(f"  Enabled: {chunk_cfg.get('enabled', True)}")
        lines.append(f"  Max chunk: {chunk_cfg.get('max_chunk_tokens', 'N/A')} tokens")
        lines.append(f"  Overlap: {chunk_cfg.get('overlap_tokens', 'N/A')} tokens")
        
        return "\n".join(lines)


def get_config() -> Config:
    """Get singleton config instance."""
    return Config.load()
