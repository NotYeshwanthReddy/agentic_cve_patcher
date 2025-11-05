"""Module for generating vulnerability remediation plans."""
import json
import os
from typing import Optional, Dict, Any
from src.utils.settings import llm
from src.utils.logger import get_logger

logger = get_logger(__name__)


def planner_node(state):
    """Generate a comprehensive vulnerability remediation plan using CVE and CSAF data."""
    logger.info("Entering planner_node")
    
    vuln_data = state.get("vuln_data")
    cve_data = state.get("cve_data")
    csaf_data = state.get("csaf_data")
    rhsa_id = state.get("rhsa_id")
    
    if not vuln_data:
        return {"output": "No vulnerability data found. Please analyze the vulnerability first.\nExample: `Analyze Vuln ID 241573`"}
    
    if not cve_data and not csaf_data:
        return {"output": "No CVE or CSAF data available. Please analyze the vulnerability first to fetch CVE/CSAF data."}
    
    vuln_id = vuln_data.get("Vuln ID", "Unknown")
    vuln_name = vuln_data.get("Vuln Name", "Unknown")
    
    # Prepare data summary for LLM
    cve_summary = llm.invoke(f"Summarize the CVE data and do not miss any important details: {cve_data}").content.strip() if cve_data else "Not available"
    csaf_summary = llm.invoke(f"Summarize the CSAF data and do not miss any important details: {csaf_data}").content.strip() if csaf_data else "Not available"
    
    # Generate concise plan using LLM in JSON format
    prompt = (
        f"Generate a SHORT, CONCISE remediation plan in JSON format for agents to fix:\n"
        f"Vulnerability ID: {vuln_id}\n"
        f"Vulnerability Name: {vuln_name}\n"
        f"RHSA ID: {rhsa_id or 'Not available'}\n\n"
        f"Key CVE/CSAF details (full data available in state):\n{cve_summary[:1000]}\n{csaf_summary[:1000]}\n\n"
        f"Return ONLY valid JSON with this exact structure:\n"
        f'{{\n'
        f'  "check_packages": {{\n'
        f'    "command": "<command to check installed package versions>",\n'
        f'    "description": "<brief description>"\n'
        f'  }},\n'
        f'  "apply_remediation": {{\n'
        f'    "command": "<specific patch/update command or config change>",\n'
        f'    "type": "<patch|update|config>",\n'
        f'    "description": "<brief description - refer to CVE/CSAF data for details>"\n'
        f'  }},\n'
        f'  "verify_fix": {{\n'
        f'    "command": "<command to verify vulnerability is resolved>",\n'
        f'    "expected_result": "<what to expect if fixed>"\n'
        f'  }},\n'
        f'  "production_report": {{\n'
        f'    "template_fields": ["vuln_id", "patch_applied", "verification_status", "notes"],\n'
        f'    "description": "<brief template description>"\n'
        f'  }}\n'
        f'}}\n\n'
        f"Keep it SHORT - only essential commands. Reference CVE/CSAF data instead of repeating details.\n"
        f"Reply with ONLY the JSON object, no markdown, no explanations."
    )
    
    try:
        resp = llm.invoke(prompt).content.strip()
        # Extract JSON from response if wrapped in markdown
        if "```" in resp:
            resp = resp.split("```")[1].replace("json", "").strip()
        
        plan = json.loads(resp)
        
        # Save plan to resources folder
        resources_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "resources")
        os.makedirs(resources_dir, exist_ok=True)
        plan_file = os.path.join(resources_dir, "plan.json")
        
        try:
            with open(plan_file, "w") as f:
                json.dump(plan, f, indent=2)
            logger.info(f"Plan saved to {plan_file}")
        except Exception as e:
            logger.error(f"Failed to save plan to file: {e}")
        
        # Format output for display (pretty JSON)
        output = f"# Vulnerability Remediation Plan\n\n"
        output += f"**Vulnerability ID:** {vuln_id}\n"
        output += f"**Vulnerability Name:** {vuln_name}\n"
        if rhsa_id:
            output += f"**RHSA ID:** {rhsa_id}\n"
        output += f"\n---\n\n```json\n{json.dumps(plan, indent=2)}\n```\n"
        output += f"\nPlan saved to: `resources/plan.json`\n"
        
        return {"output": output, "remediation_plan": plan}
        
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON plan: {e}")
        return {"output": f"Error: Failed to parse remediation plan as JSON. {str(e)}"}
    except Exception as e:
        logger.error(f"Failed to generate plan: {e}")
        return {"output": f"Error generating remediation plan: {str(e)}"}

