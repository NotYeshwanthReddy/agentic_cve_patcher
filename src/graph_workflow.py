from langgraph.graph import StateGraph, START, END
from dotenv import load_dotenv
from src.tools.ssh_client import ssh_node
from src.tools.jira_tools import jira_create_node
from src.utils.data_handler import sample_vulns
from src.utils.logger import get_logger
from src.utils.sqlite_checkpointer import get_checkpointer
from src.state import GraphState
from src.agents.intent_classifier import classify_intent
from src.agents.analyze_vulnerability import analyze_vuln_node

load_dotenv()

logger = get_logger(__name__)


def classify_intent_node(state):
    """Return {'intent': str, 'intent_data': str} in the state."""
    logger.info("Entering classify_intent_node")
    user_input = state.get("user_input", "")
    result = classify_intent(user_input)
    return {"intent": result["intent"], "intent_data": result["data"]}


def list_vulns_node(state):
    logger.info("Entering list_vulns_node")
    items = sample_vulns(5)
    output = "Vuln ID — Vuln Name\n{}\nWhich Vuln ID shall we resolve.?\nsample input: `Analyze Vuln ID 241573`".format("\n".join(items))
    return {"output": output}


def helper_node(state):
    """Return help message with all available functionalities."""
    logger.info("Entering helper_node")
    help_message = """This chat app can do the following.

1. list vulnerabilities

2. Analyze vulnerability by ID (example: `Analyze Vuln ID 241573`)

3. Create JIRA story for resolution progress (example: `Create JIRA story for this vulnerability.`)

4. fetch jira story, sub-task details and its status/progress (example: `Fetch JIRA story status`)

5. Query GraphDB (Gremlin API)

6. Generate Plan for fixing the vulnerability

7. Verify vulnerability existance

8. Patch the vulnerability

9. Verify if patching is done successfully or not.

10. Generate report of how the patching is done and save it to a markdown file."""
    return {"output": help_message}


def fetch_jira_node(state):
    """Fetch JIRA story, sub-task details and its status/progress."""    
    return {"output": "Fetching JIRA story, sub-task details and its status/progress."}


graph = StateGraph(GraphState)
graph.add_node("classify", classify_intent_node)
graph.add_node("list_vulns", list_vulns_node)
graph.add_node("analyze_vuln", analyze_vuln_node)
graph.add_node("jira_create_node", jira_create_node)
graph.add_node("fetch_jira_node", fetch_jira_node)
graph.add_node("ssh", ssh_node)
graph.add_node("helper", helper_node)

graph.add_edge(START, "classify")
graph.add_conditional_edges("classify", 
                            lambda s: s.get("intent"), 
                            {"LIST_VULNS": "list_vulns",
                             "ANALYZE_VULN": "analyze_vuln",
                             "CREATE_JIRA_STORY": "jira_create_node",
                             "FETCH_JIRA_STORY": "fetch_jira_node",
                             "HELP": "helper",
                             "OTHER": "ssh"
                            })
graph.add_edge("analyze_vuln", END)
graph.add_edge("jira_create_node", END)
graph.add_edge("fetch_jira_node", END)
graph.add_edge("list_vulns", END)
graph.add_edge("helper", END)
graph.add_edge("ssh", END)

# Compile with SQLite checkpointer for state persistence
checkpointer = get_checkpointer()
app = graph.compile(checkpointer=checkpointer)
# app = graph.compile()
