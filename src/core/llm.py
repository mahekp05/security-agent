import os
from dotenv import load_dotenv
from langchain_huggingface import ChatHuggingFace, HuggingFaceEndpoint

# Load variables from the .env file into os.environ
load_dotenv()

# We can retrieve it just to make sure it's loaded (optional, LangChain will find it automatically)
hf_token = os.getenv("HUGGINGFACEHUB_API_TOKEN")
if not hf_token:
    raise ValueError("HUGGINGFACEHUB_API_TOKEN is missing in the .env file!")

def get_llm(temperature: float = 0.2):
    llm = HuggingFaceEndpoint(
        repo_id="Qwen/Qwen2.5-Coder-7B-Instruct",
        temperature=temperature,
    )
    return ChatHuggingFace(llm=llm)
