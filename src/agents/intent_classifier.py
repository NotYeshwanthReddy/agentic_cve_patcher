import json
from src.utils.settings import llm
from src.utils.logger import get_logger

logger = get_logger(__name__)


def classify_intent(message: str) -> dict:
    """Classify intent and extract data. Returns {'intent': str, 'data': str}."""
    logger.info(f"Entering classify_intent with message: {message[:50]}...")
    prompt = (
        "Analyze the user's message and classify their intent.\n"
        "Possible intents: LIST_VULNS (when user wants to see vulnerabilities), "
        "ANALYZE_VULN (when user wants to analyze a specific vulnerability ID), "
        "CREATE_JIRA_STORY (when user wants to create a JIRA story for a specific vulnerability ID), "
        "FETCH_JIRA_STORY (when user wants to fetch a JIRA story for a specific vulnerability ID), "
        "HELP (when user asks for help, features, capabilities, or what the app can do), "
        "or OTHER (for any other request).\n"
        "For ANALYZE_VULN, CREATE_JIRA_STORY, FETCH_JIRA_STORY intent, extract the Vuln ID number in the 'data' field.\n"
        "Reply with ONLY a valid JSON object in this exact format:\n"
        '{"intent": "<intent>", "data": "<data>"}\n'
        "For LIST_VULNS, ANALYZE_VULN, CREATE_JIRA_STORY, FETCH_JIRA_STORY, HELP, or OTHER intents, set 'data' to empty string.\n"
        f"Message: '''{message}'''"
    )
    try:
        resp = llm.invoke(prompt).content.strip()
        # Try to parse JSON, handling markdown code blocks if present
        if "```" in resp:
            resp = resp.split("```")[1].replace("json", "").strip()
        result = json.loads(resp)
        return {
            "intent": result.get("intent", "OTHER").upper(),
            "data": result.get("data", "")
        }
    except Exception:
        return {"intent": "OTHER", "data": ""}

