from langgraph.graph import StateGraph, START, END
from dotenv import load_dotenv
from src.tools.ssh_client import ssh_node
from src.tools.jira_tools import jira_update_node
from src.utils.settings import llm
from src.utils.data_handler import sample_vulns
from src.state import GraphState
from src.agents.intent_classifier import classify_intent
from src.agents.vuln_resolver import resolve_vuln_node

load_dotenv()


def classify_intent_node(state):
    """Return {'intent': str, 'intent_data': str} in the state."""
    user_input = state.get("user_input", "")
    result = classify_intent(user_input)
    return {"intent": result["intent"], "intent_data": result["data"]}


def list_vulns_node(state):
    items = sample_vulns(5)
    output = "Vuln ID — Vuln Name\n{}\nWhich Vuln ID shall we resolve.?\nsample input: `Resolve Vuln ID 241573`".format("\n".join(items))
    return {"output": output}


def llm_node(state):
    prompt = f"User wants to: {state['user_input']}. Decide what Linux command should be run and return only the command."
    command = llm.invoke(prompt).content.strip()
    return {"command": command}


graph = StateGraph(GraphState)
graph.add_node("classify", classify_intent_node)
graph.add_node("list_vulns", list_vulns_node)
graph.add_node("resolve_vuln", resolve_vuln_node)
graph.add_node("jira_update", jira_update_node)
graph.add_node("llm", llm_node)
graph.add_node("ssh", ssh_node)

graph.add_edge(START, "classify")
graph.add_conditional_edges("classify", 
                            lambda s: s.get("intent"), 
                            {"LIST_VULNS": "list_vulns",
                             "RESOLVE_VULN": "resolve_vuln",
                             "OTHER": "llm"
                            })
graph.add_edge("resolve_vuln", "jira_update")
graph.add_edge("jira_update", END)
graph.add_edge("llm", "ssh")
graph.add_edge("list_vulns", END)
graph.add_edge("ssh", END)

app = graph.compile()
