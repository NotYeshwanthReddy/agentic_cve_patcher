from typing import TypedDict, Optional

# Define the structure of the graph state
class GraphState(TypedDict):
    user_input: str
    intent: str
    intent_data: Optional[str]
    command: str
    output: str
    vuln_data: Optional[dict]
    rhsa_id: Optional[str]
    cve_data: Optional[dict]
    csaf_data: Optional[dict]
    epic_key: Optional[str]
    story_key: Optional[str]
