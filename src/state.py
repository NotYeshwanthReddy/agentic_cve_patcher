from typing import TypedDict, Optional, List, Dict, Any

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
    cve_summary: Optional[str]  # Summary of CVE data
    csaf_summary: Optional[str]  # Summary of CSAF data
    jira_issues: Optional[Dict[str, Any]]  # Stores epic_key, story_key, and subtask_keys
    remediation_plan: Optional[Dict[str, Any]]  # Stores the remediation plan JSON
    patcher_logs: Optional[List[Dict[str, Any]]]  # Logs from patcher execution
    patcher_errors: Optional[List[Dict[str, Any]]]  # Errors and suggestions from patcher
