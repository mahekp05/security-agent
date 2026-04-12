import os

from pathlib import Path
from dotenv import load_dotenv
from langchain_huggingface import ChatHuggingFace, HuggingFaceEndpoint

# Load variables from the .env file into os.environ
project_root = Path(__file__).parent.parent.parent
env_path = project_root / ".env"
if env_path.exists():
    load_dotenv(env_path)
else:
    load_dotenv()

# We can retrieve it just to make sure it's loaded (optional, LangChain will find it automatically)
hf_token = os.getenv("HUGGINGFACEHUB_API_TOKEN")
if not hf_token:
    raise ValueError("HUGGINGFACEHUB_API_TOKEN is missing in the .env file!")

def get_llm(temperature: float = 0.2):
    """Create the configured LLM client.

    Notes:
        We load `.env` if present for local development, but we avoid raising
        at import time so CI/GitHub runners can handle missing secrets more
        gracefully.
    """
    # Load variables from the .env file into os.environ (local dev)
    load_dotenv()

    hf_token = os.getenv("HUGGINGFACEHUB_API_TOKEN")
    if not hf_token:
        raise ValueError("HUGGINGFACEHUB_API_TOKEN is missing (configure as an env var or GitHub secret)")

    llm = HuggingFaceEndpoint(
        model="Qwen/Qwen2.5-Coder-7B-Instruct",
        temperature=temperature,
    )
    return ChatHuggingFace(llm=llm)

def get_triage_llm(temperature: float = 0.0):
    """Reasoning-optimized LLM for Judge only (32B = better logic, Nscale-compatible)"""
    llm = HuggingFaceEndpoint(
        model="Qwen/Qwen2.5-Coder-32B-Instruct",
        temperature=temperature,
    )
    return ChatHuggingFace(llm=llm)