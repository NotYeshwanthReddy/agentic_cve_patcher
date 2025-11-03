from typing import TypedDict, Optional

# Define the structure of the graph state
class GraphState(TypedDict):
    user_input: str
    intent: str
    intent_data: Optional[str]
    command: str
    output: str
    vuln_data: Optional[dict]
