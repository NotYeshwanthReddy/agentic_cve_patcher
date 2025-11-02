from langgraph.graph import StateGraph, START, END
from dotenv import load_dotenv
from tools.ssh_client import ssh_node
from src.utils.settings import llm
from src.state import GraphState
load_dotenv()


def llm_node(state):
    prompt = f"User wants to: {state['user_input']}. " \
             "Decide what Linux command should be run and return only the command."
    command = llm.invoke(prompt).content.strip()
    return {"command": command}


graph = StateGraph(GraphState)
graph.add_node("llm", llm_node)
graph.add_node("ssh", ssh_node)
graph.add_edge(START, "llm")
graph.add_edge("llm", "ssh")
graph.add_edge("ssh", END)

app = graph.compile()
