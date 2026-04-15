"""LLM client management with config-driven model selection.

Uses Config for all model names, temperatures, and token limits.
Supports multiple agent types: detector, prosecutor, defender, judge.
"""

import os
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv
from langchain_huggingface import ChatHuggingFace, HuggingFaceEndpoint
from src.core.config import Config, get_config


def _load_env() -> None:
    """Load environment variables from a project-level .env if present."""
    project_root = Path(__file__).parent.parent.parent
    env_path = project_root / ".env"
    if env_path.exists():
        load_dotenv(env_path)
    else:
        load_dotenv()


def get_llm(
    agent_type: str = "detector",
    config: Optional[Config] = None,
    temperature: Optional[float] = None
) -> ChatHuggingFace:
    """Create configured LLM client for specified agent type.
    
    Args:
        agent_type: "detector", "prosecutor", "defender", or "judge"
        config: Config instance (uses singleton if None)
        temperature: Override temperature (uses config if None)
    
    Returns:
        ChatHuggingFace instance with token limits from config
    
    Raises:
        ValueError: If HUGGINGFACEHUB_API_TOKEN not set
    """
    # Load .env file to populate os.environ if not already loaded
    _load_env()
    
    if config is None:
        config = get_config()
    
    # Get token and validate
    hf_token = os.getenv("HUGGINGFACEHUB_API_TOKEN")
    if not hf_token:
        raise ValueError(
            "HUGGINGFACEHUB_API_TOKEN is missing. "
            "Configure as environment variable or GitHub secret."
        )
    
    # Get config for this agent type
    model_cfg = config.get_model_config(agent_type)
    model_name = model_cfg['model_name']
    if temperature is None:
        temperature = model_cfg['temperature']
    
    # Extract token limits from config
    max_tokens = model_cfg.get('max_tokens', 26000)
    output_reserve = model_cfg.get('output_reserve', 500)
    max_new_tokens = max_tokens - output_reserve
    
    # Create HuggingFace endpoint with token limits enforced
    llm = HuggingFaceEndpoint(
        model=model_name,
        temperature=temperature,
        max_new_tokens=max_new_tokens,  # Limit output tokens from config
    )
    
    return ChatHuggingFace(llm=llm)


# Backward compatibility: legacy function names
def get_triage_llm(temperature: Optional[float] = None) -> ChatHuggingFace:
    """Legacy function: creates Judge LLM (32B model).
    
    Deprecated: Use get_llm(agent_type="judge") instead.
    """
    return get_llm(agent_type="judge", temperature=temperature)