from langchain_openai import AzureChatOpenAI
import os

llm = AzureChatOpenAI(
    azure_deployment=os.getenv("AZURE_OPENAI_MODEL"),
    openai_api_key=os.getenv("AZURE_OPENAI_API_KEY"),
    azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
    api_version=os.getenv("AZURE_OPENAI_API_VERSION")
)