"""Module for Gremlin GraphDB operations."""
import json
import os
from typing import Optional, Dict, Any, List
from src.utils.gremlin_client import GremlinClient
from src.utils.settings import llm
from src.utils.logger import get_logger

logger = get_logger(__name__)

_gremlin_client = None

def get_gremlin_client() -> GremlinClient:
    """Get or create Gremlin client instance."""
    global _gremlin_client
    if _gremlin_client is None:
        endpoint = os.getenv("GREMLIN_ENDPOINT")
        database = os.getenv("GREMLIN_DB")
        graph = os.getenv("GREMLIN_GRAPH_NAME")
        primary_key = os.getenv("GREMLIN_PRIMARY_KEY")
        
        if not all([endpoint, database, graph, primary_key]):
            raise ValueError("Missing Gremlin configuration. Please set GREMLIN_ENDPOINT, GREMLIN_DB, GREMLIN_GRAPH_NAME, and GREMLIN_PRIMARY_KEY")
        
        _gremlin_client = GremlinClient(endpoint, database, graph, primary_key)
    return _gremlin_client


def format_gremlin_result(result: Dict[str, Any], operation: str) -> str:
    """Format Gremlin query result for display."""
    if "error" in result:
        return f"Error: {result['error']}"
    
    output_parts = [f"**{operation} Results:**\n"]
    
    if "cve_id" in result:
        output_parts.append(f"CVE ID: {result['cve_id']}\n\n")
    
    if "counts" in result:
        output_parts.append("**Counts:**\n")
        for key, value in result["counts"].items():
            output_parts.append(f"- {key.replace('_', ' ').title()}: {value}\n")
        output_parts.append("\n")
    
    if "summary" in result:
        summary = result["summary"]
        output_parts.append("**Summary:**\n")
        output_parts.append(f"- Total Affected Hosts: {summary.get('total_affected_hosts', 0)}\n")
        output_parts.append(f"- Total Affected Apps: {summary.get('total_affected_apps', 0)}\n")
        output_parts.append(f"- Total Responsible Teams: {summary.get('total_responsible_teams', 0)}\n")
        if summary.get("unique_teams"):
            output_parts.append(f"- Unique Teams: {', '.join(summary['unique_teams'][:10])}")
            if len(summary['unique_teams']) > 10:
                output_parts.append(f" (and {len(summary['unique_teams']) - 10} more)")
            output_parts.append("\n")
    
    # List IDs for each category
    for key in ["packages", "hosts", "applications", "services", "downstream_services", "systems"]:
        if key in result and result[key]:
            output_parts.append(f"\n**{key.replace('_', ' ').title()}:**\n")
            ids = result[key][:20]  # Show first 20
            output_parts.append(", ".join(ids))
            if len(result[key]) > 20:
                output_parts.append(f" (and {len(result[key]) - 20} more)")
            output_parts.append("\n")
    
    return "".join(output_parts)


def gremlin_node(state):
    """Execute Gremlin GraphDB operations based on user request."""
    logger.info("Entering gremlin_node")
    user_input = state.get("user_input", "")
    
    # Use LLM to determine operation and extract parameters
    prompt = (
        f"User query: '{user_input}'\n"
        "Determine the Gremlin operation requested:\n"
        "- 'analyze_vulnerability_impact': Analyze vulnerability impact by CVE ID\n"
        "- 'blast_radius_hosts': Calculate blast radius by host IDs\n"
        "- 'blast_radius_apps': Calculate blast radius by app IDs\n"
        "- 'blast_radius_cve': Calculate blast radius by CVE ID\n"
        "- 'responsible_teams_host': Get responsible teams for host ID\n"
        "- 'responsible_teams_app': Get responsible teams for app ID\n"
        "- 'comprehensive_analysis': Comprehensive CVE analysis with blast radius and teams\n"
        "Extract necessary parameters:\n"
        "- For CVE operations: extract CVE ID (e.g., 'CVE-2022-3602')\n"
        "- For host/app operations: extract IDs as comma-separated list\n"
        "- For hops: extract number (default 3 if not specified)\n"
        "Reply with ONLY valid JSON: {\"operation\": \"<operation>\", \"cve_id\": \"<cve_id or empty>\", \"host_ids\": [\"<id>\"], \"app_ids\": [\"<id>\"], \"hops\": <number>}"
    )
    
    try:
        resp = llm.invoke(prompt).content.strip()
        if "```" in resp:
            resp = resp.split("```")[1].replace("json", "").strip()
        result = json.loads(resp)
        operation = result.get("operation", "analyze_vulnerability_impact")
        cve_id = result.get("cve_id", "").strip()
        host_ids = result.get("host_ids", [])
        app_ids = result.get("app_ids", [])
        hops = int(result.get("hops", 3))
    except Exception as e:
        logger.error(f"Failed to parse user request: {e}")
        return {"output": f"Error parsing request: {str(e)}"}
    
    try:
        client = get_gremlin_client()
        result_data = None
        
        if operation == "analyze_vulnerability_impact":
            if not cve_id:
                return {"output": "CVE ID is required for vulnerability impact analysis."}
            result_data = client.analyze_vulnerability_impact(cve_id, hops)
            
        elif operation == "blast_radius_hosts":
            if not host_ids:
                return {"output": "Host IDs are required for blast radius calculation."}
            result_data = client.blast_radius_by_hosts(host_ids, hops)
            
        elif operation == "blast_radius_apps":
            if not app_ids:
                return {"output": "App IDs are required for blast radius calculation."}
            result_data = client.blast_radius_by_apps(app_ids, hops)
            
        elif operation == "blast_radius_cve":
            if not cve_id:
                return {"output": "CVE ID is required for blast radius calculation."}
            result_data = client.blast_radius_by_cve(cve_id, hops)
            
        elif operation == "responsible_teams_host":
            if not host_ids:
                return {"output": "Host ID is required to get responsible teams."}
            teams = client.teams_for_hosts(host_ids) if len(host_ids) > 1 else client.team_for_host(host_ids[0])
            result_data = {"host_ids": host_ids, "teams": teams, "count": len(teams)}
            
        elif operation == "responsible_teams_app":
            if not app_ids:
                return {"output": "App ID is required to get responsible teams."}
            teams = client.teams_for_apps(app_ids) if len(app_ids) > 1 else client.team_for_app(app_ids[0])
            result_data = {"app_ids": app_ids, "teams": teams, "count": len(teams)}
            
        elif operation == "comprehensive_analysis":
            if not cve_id:
                return {"output": "CVE ID is required for comprehensive analysis."}
            result_data = client.comprehensive_cve_analysis(cve_id, hops)
            
        else:
            return {"output": f"Unknown operation: {operation}"}
        
        formatted_output = format_gremlin_result(result_data, operation.replace("_", " ").title())
        return {"output": formatted_output, "gremlin_result": result_data}
        
    except ValueError as e:
        return {"output": f"Configuration error: {str(e)}"}
    except Exception as e:
        logger.error(f"Gremlin operation failed: {e}")
        return {"output": f"Error executing Gremlin operation: {str(e)}"}

