from typing import TypedDict

# Define the structure of the graph state
class GraphState(TypedDict):
    user_input: str
    command: str
    output: str
