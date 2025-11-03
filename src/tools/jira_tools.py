import json
from typing import Optional, Dict, Any
from src.utils.jira_client import get_jira_client, create_epic, create_story
from src.utils.settings import llm
from src.utils.logger import get_logger

logger = get_logger(__name__)


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


def jira_update_node(state):
    """Update JIRA: find/create epic, create story if needed."""
    logger.info("Entering jira_update_node")
    vuln_data = state.get("vuln_data")
    if not vuln_data:
        return {"output": state.get("output", "")}
    
    app_code = str(vuln_data.get("App Code", "")).strip()
    app_name = str(vuln_data.get("App Name", "")).strip()
    
    if not app_code:
        return {"output": state.get("output", "") + "\nWarning: APP_CODE not found in vulnerability data."}
    
    client = get_jira_client()
    epic_key = state.get("epic_key")
    
    # Step 1 & 2: Find or create epic
    if not epic_key:
        epic_key = find_epic_by_app_code(app_code)
        if not epic_key:
            # Step 3: Create new epic
            epic_summary = f"{app_code} - {app_name}" if app_name else app_code
            epic = create_epic(epic_summary, f"Epic for application {app_code}")
            epic_key = epic.get("key")
    
    # Step 4 & 5: Create story if story_key doesn't exist
    story_key = state.get("story_key")
    
    if not story_key:
        vuln_id = str(vuln_data.get("Vuln ID", ""))
        vuln_name = str(vuln_data.get("Vuln Name", "Vulnerability"))
        story_summary = f"Patch {vuln_id}: {vuln_name}"
        
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
    
    output = state.get("output", "") + f"\nJIRA: Epic {epic_key}, Story {story_key} ready."
    
    return {
        "epic_key": epic_key,
        "story_key": story_key,
        "output": output
    }
