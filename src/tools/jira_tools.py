import json
from typing import Optional, Dict, Any, List
from src.utils.jira_client import get_jira_client, create_epic, create_story, create_subtask, get_issue, update_progress
from src.utils.settings import llm
from src.utils.logger import get_logger

logger = get_logger(__name__)


# Sub-task templates for vulnerability resolution workflow
SUBTASK_TEMPLATES = [
    {
        "summary": "Perform Vulnerability Analysis and Blast Radius Analysis",
        "description": "Analyze the vulnerability impact and assess the blast radius to understand affected systems and potential risks."
    },
    {
        "summary": "Gather patch and mitigation details",
        "description": "Collect patch and mitigation information from CVE and CSAF data received from RHSA API."
    },
    {
        "summary": "SSH into the system and verify if the vulnerability is present",
        "description": "Connect to the target system via SSH and verify the presence of the vulnerability."
    },
    {
        "summary": "Apply the fix (patch/update)",
        "description": "Apply the necessary patch or update to resolve the vulnerability."
    },
    {
        "summary": "Verify that the vulnerability is resolved",
        "description": "Confirm that the applied fix has successfully resolved the vulnerability."
    }
]


def create_vuln_resolution_subtasks(story_key: str, cve_data: Optional[Dict] = None, 
                                     csaf_data: Optional[Dict] = None) -> List[Dict[str, str]]:
    """
    Create sub-tasks under a story for vulnerability resolution workflow.
    
    Args:
        story_key: The JIRA story key to create sub-tasks under
        cve_data: Optional CVE data to include in descriptions
        csaf_data: Optional CSAF data to include in descriptions
        
    Returns:
        List of sub-task keys (dicts with 'key' field)
    """
    logger.info(f"Entering create_vuln_resolution_subtasks for story_key: {story_key}")
    subtask_keys = []
    
    for template in SUBTASK_TEMPLATES:
        try:
            # Enhance description with CVE/CSAF data if available
            description = template["description"]
            
            # Add CVE/CSAF details to the second sub-task (gathering patch details)
            if "Gather patch" in template["summary"]:
                if cve_data:
                    description += f"\n\nCVE Data Available: {len(cve_data)} fields"
                if csaf_data:
                    description += f"\n\nCSAF Data Available: {len(csaf_data)} fields"
            
            subtask = create_subtask(story_key, template["summary"], description)
            subtask_keys.append({"key": subtask.get("key")})
            logger.info(f"Created sub-task {subtask.get('key')}: {template['summary']}")
        except Exception as e:
            logger.error(f"Failed to create sub-task '{template['summary']}': {e}")
            continue
    
    return subtask_keys


def find_epic_by_app_code(app_code: str) -> Optional[str]:
    """Find EPIC key that contains APP_CODE in its summary."""
    logger.info(f"Entering find_epic_by_app_code with app_code: {app_code}")
    client = get_jira_client()
    epics = client.list_epics()
    app_code_upper = app_code.upper()
    for epic in epics:
        summary = epic.get("summary", "").upper()
        if app_code_upper in summary:
            return epic.get("key")
    
    return None


def map_csv_to_jira_fields(vuln_data: Dict[str, Any], jira_field_names: list) -> Dict[str, Any]:
    """Map CSV column names to JIRA custom field names using LLM."""
    logger.info(f"Entering map_csv_to_jira_fields with {len(vuln_data)} CSV fields")
    # Create mapping prompt
    csv_keys = list(vuln_data.keys())
    prompt = (
        f"Map CSV column names to JIRA custom field names.\n\n"
        f"CSV columns: {csv_keys}\n"
        f"JIRA custom fields: {jira_field_names}\n\n"
        f"Return ONLY valid JSON mapping: {{\"CSV_COLUMN_NAME\": \"JIRA_FIELD_NAME\", ...}}\n"
        f"Map each CSV column to its corresponding JIRA field. Skip fields that don't match.\n"
        f"Handle variations like 'App Code' -> 'APP_CODE', 'Crown Jewel Indicator' -> 'CROWN_JEWEL_INDICATOR'."
    )
    
    try:
        response = llm.invoke(prompt).content.strip()
        # Extract JSON from response
        if "```" in response:
            response = response.split("```")[1].replace("json", "").strip()
        mapping = json.loads(response)
        return mapping
    except Exception as e:
        print(f"Warning: LLM mapping failed: {e}. Using fallback mapping.")
        # Fallback: simple uppercase with underscore replacement
        mapping = {}
        for csv_key in csv_keys:
            jira_name = csv_key.upper().replace(" ", "_").replace("(", "_").replace(")", "").replace("/", "_")
            if jira_name in jira_field_names:
                mapping[csv_key] = jira_name
        return mapping


def prepare_custom_fields(vuln_data: Dict[str, Any], meta_fields: Dict) -> Dict[str, Any]:
    """Prepare custom fields for JIRA update from vulnerability data."""
    logger.info("Entering prepare_custom_fields")
    # Get available JIRA field names
    jira_field_names = [fdata.get("name", "") for fdata in meta_fields.values()]
    
    # Map CSV columns to JIRA field names
    field_mapping = map_csv_to_jira_fields(vuln_data, jira_field_names)
    
    # Create field_id to value mapping
    fields = {}
    for csv_key, jira_field_name in field_mapping.items():
        value = vuln_data.get(csv_key)
        if not value or str(value).lower() in ["nan", "none", ""]:
            continue
            
        # Find field_id for this JIRA field name
        for field_id, field_data in meta_fields.items():
            if field_data.get("name") == jira_field_name:
                field_type = field_data.get("schema", {}).get("type", "")
                
                # Handle different field types
                if field_type == "date" and "/" in str(value):
                    from datetime import datetime
                    try:
                        fields[field_id] = datetime.strptime(str(value), "%m/%d/%Y").strftime("%Y-%m-%d")
                    except:
                        fields[field_id] = str(value)
                elif field_type == "option":
                    fields[field_id] = {"value": str(value)}
                else:
                    fields[field_id] = str(value)
                break
    
    return fields


def update_story_with_vuln_data(story_key: str, vuln_data: Dict[str, Any], rhsa_id: Optional[str] = None) -> Dict:
    """Update a JIRA story with vulnerability data from state."""
    logger.info(f"Entering update_story_with_vuln_data for story_key: {story_key}")
    client = get_jira_client()
    issue = client.jira.issue(story_key)
    
    meta = client.jira.createmeta(projectKeys=client.project_key, issuetypeNames="Story", expand="projects.issuetypes.fields")
    
    if meta and meta.get("projects"):
        available_fields = meta["projects"][0]["issuetypes"][0]["fields"]
        fields = prepare_custom_fields(vuln_data, available_fields)
        
        # Add RHSA ID if present
        if rhsa_id:
            for field_id, field_data in available_fields.items():
                if "rhsa" in field_data.get("name", "").lower():
                    fields[field_id] = rhsa_id
                    break
        
        if fields:
            issue.update(fields=fields)
    
    return {"updated": True}


def jira_fetch_node(state):
    """Fetch JIRA story, sub-task details and its status/progress."""
    logger.info("Entering jira_fetch_node")
    user_input = state.get("user_input", "")
    jira_issues = state.get("jira_issues") or {}
    
    # Get story and sub-task keys from state
    story_key = jira_issues.get("story_key")
    subtask_keys = jira_issues.get("subtask_keys", [])
    
    if not story_key:
        return {"output": "No JIRA story found. Create a JIRA story first.\nExample: `Create JIRA story for this vulnerability.`"}
    
    # Use LLM to determine what user wants (story, subtasks, or both)
    prompt = (
        f"User query: '{user_input}'\n"
        "Determine what the user wants:\n"
        "- 'story' if they want story status/details\n"
        "- 'subtasks' if they want sub-task status/details\n"
        "- 'both' if they want both story and sub-tasks\n"
        "Reply with ONLY valid JSON: {\"request_type\": \"story\" | \"subtasks\" | \"both\"}"
    )
    
    try:
        resp = llm.invoke(prompt).content.strip()
        if "```" in resp:
            resp = resp.split("```")[1].replace("json", "").strip()
        result = json.loads(resp)
        request_type = result.get("request_type", "both").lower()
    except Exception:
        request_type = "both"
    
    output_parts = []
    
    # Fetch story details if requested
    if request_type in ["story", "both"]:
        story = get_issue(story_key)
        output_parts.append(f"**Story: {story_key}**\n")
        output_parts.append(f"Summary: {story.get('summary', 'N/A')}\n")
        output_parts.append(f"Status: {story.get('status', 'N/A')}\n")
        # output_parts.append(f"Progress: {story.get('progress', {}).get('percent', 0)}%\n")
    
    # Fetch sub-task details if requested
    if request_type in ["subtasks", "both"] and subtask_keys:
        output_parts.append(f"\n**Sub-tasks ({len(subtask_keys)}):**\n")
        for subtask_key in subtask_keys:
            try:
                subtask = get_issue(subtask_key)
                output_parts.append(f"- {subtask_key}: {subtask.get('summary', 'N/A')} | Status: {subtask.get('status', 'N/A')}\n")
            except Exception as e:
                logger.error(f"Failed to fetch subtask {subtask_key}: {e}")
                output_parts.append(f"- {subtask_key}: Error fetching details\n")
    
    return {"output": "".join(output_parts) if output_parts else "No data to display."}


def jira_update_node(state):
    """Update JIRA story or sub-task status/progress."""
    logger.info("Entering jira_update_node")
    user_input = state.get("user_input", "")
    jira_issues = state.get("jira_issues") or {}
    
    story_key = jira_issues.get("story_key")
    subtask_keys = jira_issues.get("subtask_keys", [])
    
    if not story_key:
        return {"output": "No JIRA story found. Create a JIRA story first."}
    
    # Use LLM to determine: what to update (story/subtask), target status, and subtask identifier if needed
    prompt = (
        f"User query: '{user_input}'\n"
        "Determine:\n"
        "1. What to update: 'story' or 'subtask' (use 'story' if unclear)\n"
        "2. Target status: 'BACKLOG', 'SELECTED FOR DEVELOPMENT', 'IN PROGRESS', or 'DONE'\n"
        "3. If subtask, extract identifier: JIRA key (e.g., 'DS-47') or summary text (e.g., 'Gather patch') - leave empty if story\n"
        "Reply with ONLY valid JSON: {\"target\": \"story\" | \"subtask\", \"status\": \"BACKLOG\" | \"SELECTED FOR DEVELOPMENT\" | \"IN PROGRESS\" | \"DONE\", \"subtask_id\": \"<key or summary>\" | \"\"}"
    )
    
    try:
        resp = llm.invoke(prompt).content.strip()
        if "```" in resp:
            resp = resp.split("```")[1].replace("json", "").strip()
        result = json.loads(resp)
        target = result.get("target", "story").lower()
        status = result.get("status", "IN PROGRESS").upper()
        subtask_id = result.get("subtask_id", "").strip()
    except Exception:
        target = "story"
        status = "IN PROGRESS"
        subtask_id = ""
    
    client = get_jira_client()
    
    # Find the specific issue to update
    if target == "story":
        issue_key = story_key
    else:
        # Find matching subtask by key or summary
        issue_key = None
        if subtask_id:
            # Try to match by key first
            for key in subtask_keys:
                if subtask_id.upper() in key.upper():
                    issue_key = key
                    break
            
            # If not found by key, try to match by summary
            if not issue_key:
                for key in subtask_keys:
                    try:
                        subtask = get_issue(key)
                        if subtask_id.lower() in subtask.get("summary", "").lower():
                            issue_key = key
                            break
                    except Exception:
                        continue
        
        # Fallback to first subtask if no match found
        if not issue_key:
            issue_key = subtask_keys[0] if subtask_keys else None
    
    if not issue_key:
        return {"output": f"No {'story' if target == 'story' else 'subtask'} found to update."}
    
    # Get available transitions and find matching one
    issue = client.jira.issue(issue_key)
    transitions = client.jira.transitions(issue)
    
    # Find transition that matches the target status (flexible matching)
    status_upper = status.upper()
    transition = next((t for t in transitions if status_upper in t["name"].upper() or status_upper.replace(" ", "") in t["name"].upper().replace(" ", "")), None)
    
    if transition:
        client.jira.transition_issue(issue, transition["id"])
        updated_issue = get_issue(issue_key)
        return {"output": f"Updated {target} {issue_key} to status: {updated_issue.get('status', status)}"}
    else:
        # Fallback: use update_progress with status mapping
        status_map = {"BACKLOG": 0, "SELECTED FOR DEVELOPMENT": 25, "IN PROGRESS": 50, "DONE": 100}
        progress = status_map.get(status_upper, 50)
        update_progress(issue_key, progress)
        updated_issue = get_issue(issue_key)
        return {"output": f"Updated {target} {issue_key} status to: {updated_issue.get('status', status)}"}


def jira_create_node(state):
    """Update JIRA: find/create epic, create story if needed."""
    logger.info("Entering jira_create_node")
    vuln_data = state.get("vuln_data")
    if not vuln_data:
        return {"output": "No vulnerability data provided. Analyze the vulnerability first.\nExample: `Analyze Vuln ID 241573`"}
    
    app_code = str(vuln_data.get("App Code", "")).strip()
    app_name = str(vuln_data.get("App Name", "")).strip()
    
    if not app_code:
        return {"output": state.get("output", "") + "\nWarning: APP_CODE not found in vulnerability data."}
    
    client = get_jira_client()
    
    # Get existing jira_issues or initialize
    jira_issues = state.get("jira_issues") or {}
    epic_key = jira_issues.get("epic_key")
    
    # Step 1 & 2: Find or create epic
    if not epic_key:
        epic_key = find_epic_by_app_code(app_code)
        if not epic_key:
            # Step 3: Create new epic
            epic_summary = f"{app_code} - {app_name}" if app_name else app_code
            epic = create_epic(epic_summary, f"Epic for application {app_code}")
            epic_key = epic.get("key")
    
    # Step 4 & 5: Create story if story_key doesn't exist
    story_key = jira_issues.get("story_key")
    
    if not story_key:
        vuln_id = str(vuln_data.get("Vuln ID", ""))
        vuln_name = str(vuln_data.get("Vuln Name", ""))
        asset_name = str(vuln_data.get("Asset Name", ""))
        story_summary = f"Patch for Vuln ID:{vuln_id} | Asset Name:{asset_name} | Vuln Name:{vuln_name}"
        
        # Prepare custom fields before creating story
        meta = client.jira.createmeta(projectKeys=client.project_key, issuetypeNames="Story", expand="projects.issuetypes.fields")
        custom_fields = {}
        if meta and meta.get("projects"):
            available_fields = meta["projects"][0]["issuetypes"][0]["fields"]
            custom_fields = prepare_custom_fields(vuln_data, available_fields)
        
        # Create story with custom fields
        story = create_story(epic_key, story_summary, custom_fields=custom_fields)
        story_key = story.get("key")
        
        # Update story with RHSA ID if present
        if story_key:
            rhsa_id = state.get("rhsa_id")
            if rhsa_id:
                meta = client.jira.createmeta(projectKeys=client.project_key, issuetypeNames="Story", expand="projects.issuetypes.fields")
                if meta and meta.get("projects"):
                    available_fields = meta["projects"][0]["issuetypes"][0]["fields"]
                    issue = client.jira.issue(story_key)
                    for field_id, field_data in available_fields.items():
                        if "rhsa" in field_data.get("name", "").lower():
                            issue.update(fields={field_id: rhsa_id})
                            break
    
    # Step 6: Create sub-tasks under the story
    subtask_keys = []
    if story_key:
        cve_data = state.get("cve_data")
        csaf_data = state.get("csaf_data")
        subtasks = create_vuln_resolution_subtasks(story_key, cve_data, csaf_data)
        subtask_keys = [st.get("key") for st in subtasks if st.get("key")]
    
    # Store all JIRA issue keys in a dict
    jira_issues = {
        "epic_key": epic_key,
        "story_key": story_key,
        "subtask_keys": subtask_keys
    }
    
    subtask_summary = f", {len(subtask_keys)} sub-task(s)" if subtask_keys else ""
    output = state.get("output", "") + f"\nJIRA: Epic {epic_key}, Story {story_key}{subtask_summary} ready."
    
    return {
        "jira_issues": jira_issues,
        "output": output
    }
