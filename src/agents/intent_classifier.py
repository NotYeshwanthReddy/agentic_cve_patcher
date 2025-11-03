import json
from src.utils.settings import llm


def classify_intent(message: str) -> dict:
    """Classify intent and extract data. Returns {'intent': str, 'data': str}."""
    prompt = (
        "Analyze the user's message and classify their intent.\n"
        "Possible intents: LIST_VULNS (when user wants to see vulnerabilities), "
        "RESOLVE_VULN (when user wants to resolve a specific vulnerability), "
        "or OTHER (for any other request).\n"
        "For RESOLVE_VULN intent, extract the Vuln ID number in the 'data' field.\n"
        "Reply with ONLY a valid JSON object in this exact format:\n"
        '{"intent": "<intent>", "data": "<data>"}\n'
        "For LIST_VULNS or OTHER intents, set 'data' to empty string.\n"
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

