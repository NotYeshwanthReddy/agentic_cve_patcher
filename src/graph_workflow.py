from langgraph.graph import StateGraph, START, END
from dotenv import load_dotenv
from src.tools.ssh_client import ssh_node
from src.tools.jira_tools import jira_create_node, jira_fetch_node, jira_update_node
from src.tools.gremlin_tools import gremlin_node
from src.tools.planner_tools import planner_node
from src.tools.patcher_tools import patcher_node
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
    return {"output": output, "current_step": 1}


def helper_node(state):
    """Return help message with all available functionalities."""
    logger.info("Entering helper_node")
    help_message = """This chat app can do the following:

1. See vulnerabilities (example: `list vulnerabilities` or `show vulnerabilities`)
2. Analyze a specific vulnerability ID \n(example: `analyze vulnerability ID 241573` or `analyze vuln ID 241573`)
3. Create a JIRA story \n(example: `create JIRA story` or `create JIRA story for this vulnerability`)
4. Fetch JIRA story status for a specific story/sub-task with ID number \n(example: `fetch JIRA story status` or `fetch JIRA sub-task status`)
5. Update JIRA story or sub-task status \n(example: `update JIRA story status to IN PROGRESS` or `update JIRA sub-task DS-24 to DONE`)
6. Query GraphDB for vulnerability impact, blast radius, responsible teams, or comprehensive analysis (example: `query GraphDB for vulnerability impact for CVE-2022-3602`)
7. Generate a plan for fixing/remediating a vulnerability (example: `generate plan for fixing this vulnerability` or `generate plan for remediation`)
8. Patch/fix a vulnerability using the remediation plan (example: `patch vulnerability` or `patch this vulnerability`)
9. Execute SSH commands (example: `execute SSH command to update python3-setuptools package` or `run SSH command to list all files`)
10. Get help, features, capabilities, or what the app can do (example: `help` or `what can you do`)"""
    return {"output": help_message}



graph = StateGraph(GraphState)
graph.add_node("classify", classify_intent_node)
graph.add_node("list_vulns", list_vulns_node)
graph.add_node("analyze_vuln", analyze_vuln_node)
graph.add_node("jira_create_node", jira_create_node)
graph.add_node("jira_fetch_node", jira_fetch_node)
graph.add_node("jira_update_node", jira_update_node)
graph.add_node("gremlin", gremlin_node)
graph.add_node("planner", planner_node)
graph.add_node("patcher", patcher_node)
graph.add_node("ssh", ssh_node)
graph.add_node("helper", helper_node)

graph.add_edge(START, "classify")
graph.add_conditional_edges("classify", 
                            lambda s: s.get("intent"), 
                            {"LIST_VULNS": "list_vulns",
                             "ANALYZE_VULN": "analyze_vuln",
                             "CREATE_JIRA_STORY": "jira_create_node",
                             "FETCH_JIRA_STORY": "jira_fetch_node",
                             "UPDATE_JIRA_STORY": "jira_update_node",
                             "QUERY_GRAPHDB": "gremlin",
                             "GENERATE_PLAN": "planner",
                             "PATCH_VULN": "patcher",
                             "SSH": "ssh",
                             "HELP": "helper",
                             "OTHER": "helper"
                            })
graph.add_edge("analyze_vuln", END)
graph.add_edge("jira_create_node", END)
graph.add_edge("jira_fetch_node", END)
graph.add_edge("jira_update_node", END)
graph.add_edge("gremlin", END)
graph.add_edge("planner", END)
graph.add_edge("patcher", END)
graph.add_edge("list_vulns", END)
graph.add_edge("helper", END)
graph.add_edge("ssh", END)

# Compile with SQLite checkpointer for state persistence
checkpointer = get_checkpointer()
app = graph.compile(checkpointer=checkpointer)
# app = graph.compile()
