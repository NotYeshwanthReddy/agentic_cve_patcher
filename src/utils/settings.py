from langchain_openai import AzureChatOpenAI
from dotenv import load_dotenv
import os
from src.utils.logger import get_logger

load_dotenv()

logger = get_logger(__name__)

llm = AzureChatOpenAI(
    azure_deployment=os.getenv("AZURE_OPENAI_MODEL"),
    openai_api_key=os.getenv("AZURE_OPENAI_API_KEY"),
    azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
    api_version=os.getenv("AZURE_OPENAI_API_VERSION")
)

logger.info(f"LLM initialized with deployment: {os.getenv('AZURE_OPENAI_MODEL')} at endpoint: {os.getenv('AZURE_OPENAI_ENDPOINT')}")
