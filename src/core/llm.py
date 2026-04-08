import os

from dotenv import load_dotenv
from langchain_huggingface import ChatHuggingFace, HuggingFaceEndpoint


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
        repo_id="Qwen/Qwen2.5-Coder-7B-Instruct",
        temperature=temperature,
    )
    return ChatHuggingFace(llm=llm)
