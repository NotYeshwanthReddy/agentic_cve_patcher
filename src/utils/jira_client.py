import os
from jira import JIRA
from typing import Optional, Dict, Any, List
from dotenv import load_dotenv

load_dotenv()

JIRA_URL = os.getenv("JIRA_URL", "").rstrip("/")
JIRA_API_TOKEN = os.getenv("JIRA_API_TOKEN", "")
JIRA_EMAIL = os.getenv("JIRA_EMAIL", "")
JIRA_PROJECT_KEY = os.getenv("JIRA_PROJECT_KEY", "")

class JiraClient:
    def __init__(self):
        self.jira = JIRA(options={"server": JIRA_URL}, basic_auth=(JIRA_EMAIL, JIRA_API_TOKEN))
        self.project_key = JIRA_PROJECT_KEY
    
    def _simplify_issue(self, issue) -> Dict[str, Any]:
        """Convert JIRA Issue object to simplified dict."""
        progress = getattr(issue.fields, "aggregateprogress", None) or getattr(issue.fields, "progress", None)
        return {
            "key": issue.key,
            "summary": issue.fields.summary,
            "type": issue.fields.issuetype.name,
            "status": issue.fields.status.name,
            "progress": {
                "progress": getattr(progress, "progress", 0) if progress else 0,
                "total": getattr(progress, "total", 0) if progress else 0,
                "percent": round((getattr(progress, "progress", 0) or 0) * 100.0 / (getattr(progress, "total", 0) or 1)) if progress and getattr(progress, "total", 0) else 0
            },
            "fields": issue.raw["fields"]
        }
    
    def create_epic(self, summary: str, description: Optional[str] = None) -> Dict:
        """Create an EPIC in JIRA."""
        fields = {
            "project": {"key": self.project_key},
            "summary": summary,
            "issuetype": {"name": "Epic"}
        }
        if description:
            fields["description"] = description
        issue = self.jira.create_issue(fields=fields)
        return {"key": issue.key, "id": issue.id}
    
    def create_story(self, epic_key: str, summary: str, description: Optional[str] = None, 
                     vuln_data: Optional[Dict] = None, custom_fields: Optional[Dict] = None) -> Dict:
        """Create a story under an epic with vulnerability properties."""
        fields = {
            "project": {"key": self.project_key},
            "summary": summary,
            "issuetype": {"name": "Story"}
        }
        
        # Add custom fields if provided
        if custom_fields:
            fields.update(custom_fields)
        
        # Add description if provided (but don't include vuln_data details in description)
        if description:
            fields["description"] = description
        
        # Try to find Epic Link field before creation
        epic_link_field_id = None
        try:
            meta = self.jira.createmeta(projectKeys=self.project_key, issuetypeNames="Story", expand="projects.issuetypes.fields")
            if meta and meta.get("projects"):
                available_fields = meta["projects"][0]["issuetypes"][0]["fields"]
                # Look for Epic Link field by schema custom type (most reliable)
                for fid, fdata in available_fields.items():
                    field_schema = fdata.get("schema", {})
                    schema_custom = field_schema.get("custom", "")
                    field_name = fdata.get("name", "").lower()
                    
                    # Check for GreenHopper/JIRA Agile Epic Link field
                    if schema_custom == "com.pyxis.greenhopper.jira:gh-epic-link":
                        epic_link_field_id = fid
                        break
                    # Also check by name as fallback
                    elif "epic link" in field_name and schema_custom.startswith("com."):
                        epic_link_field_id = fid
                        break
        except Exception as e:
            print(f"Warning: Could not find Epic Link field: {e}")
        
        # Create issue first
        issue = self.jira.create_issue(fields=fields)
        
        # Link to epic after creation
        if epic_key:
            linked = False
            if epic_link_field_id:
                try:
                    issue.update(fields={epic_link_field_id: epic_key})
                    print(f"Successfully linked story {issue.key} to epic {epic_key} using Epic Link field")
                    linked = True
                except Exception as e:
                    print(f"Warning: Could not link story to epic using field {epic_link_field_id}: {e}")
            
            # Try alternative: use JIRA Agile REST API
            if not linked:
                try:
                    epic_issue = self.jira.issue(epic_key)
                    epic_id = epic_issue.id
                    url = f"{self.jira._options['server']}/rest/agile/1.0/epic/{epic_id}/issue"
                    response = self.jira._session.post(url, json={"issues": [issue.key]})
                    if response.status_code in [200, 201, 204]:
                        print(f"Successfully linked story {issue.key} to epic {epic_key} via Agile REST API")
                        linked = True
                    else:
                        print(f"Warning: REST API returned status {response.status_code}: {response.text}")
                except Exception as e2:
                    print(f"Warning: Could not link story to epic via REST API: {e2}")
        
        return {"key": issue.key, "id": issue.id}
    
    def create_subtask(self, story_key: str, summary: str, description: Optional[str] = None) -> Dict:
        """Create a sub-task under a story."""
        parent = self.jira.issue(story_key)
        fields = {
            "project": {"key": self.project_key},
            "summary": summary,
            "issuetype": {"name": "Sub-task"},
            "parent": {"key": story_key}
        }
        if description:
            fields["description"] = description
        issue = self.jira.create_issue(fields=fields)
        return {"key": issue.key, "id": issue.id}
    
    def update_progress(self, issue_key: str, progress: int) -> Dict:
        """Update progress (0-100) by transitioning issue status."""
        issue = self.jira.issue(issue_key)
        transitions = self.jira.transitions(issue)
        transition_map = {100: "Done", 50: "In Progress", 0: "To Do"}
        target_status = transition_map.get(progress, transition_map[min(transition_map.keys(), key=lambda x: abs(x-progress))])
        
        transition = next((t for t in transitions if target_status in t["name"]), None)
        if transition:
            self.jira.transition_issue(issue, transition["id"])
        return {}
    
    def update_details(self, issue_key: str, fields: Dict[str, Any]) -> Dict:
        """Update issue details with provided fields."""
        issue = self.jira.issue(issue_key)
        issue.update(fields=fields)
        return {}
    
    def search_issues(self, jql: str, max_results: int = 100) -> List[Dict[str, Any]]:
        """Search issues using JQL."""
        issues = self.jira.search_issues(jql, maxResults=max_results)
        return [self._simplify_issue(issue) for issue in issues]
    
    def list_epics(self, project_key: Optional[str] = None, max_results: int = 100) -> List[Dict[str, Any]]:
        """List all epics in a project."""
        proj = project_key or self.project_key
        jql = f'project = {proj} AND issuetype = Epic ORDER BY updated DESC'
        return self.search_issues(jql, max_results)
    
    def list_stories(self, epic_key: Optional[str] = None, project_key: Optional[str] = None, max_results: int = 200) -> List[Dict[str, Any]]:
        """List stories, optionally filtered by epic."""
        if epic_key:
            jql = f'"Epic Link" = {epic_key} ORDER BY updated DESC'
        else:
            proj = project_key or self.project_key
            jql = f'project = {proj} AND issuetype = Story ORDER BY updated DESC'
        return self.search_issues(jql, max_results)
    
    def list_subtasks(self, parent_key: str, max_results: int = 200) -> List[Dict[str, Any]]:
        """List sub-tasks under a parent issue."""
        jql = f'parent = {parent_key} ORDER BY updated DESC'
        return self.search_issues(jql, max_results)
    
    def get_issue(self, issue_key: str, fields: Optional[List[str]] = None) -> Dict[str, Any]:
        """Get a single issue by key."""
        issue = self.jira.issue(issue_key)
        return self._simplify_issue(issue)


_jira_client = None

def get_jira_client() -> JiraClient:
    """Get or create JIRA client instance."""
    global _jira_client
    if _jira_client is None:
        _jira_client = JiraClient()
    return _jira_client

def create_epic(summary: str, description: Optional[str] = None) -> Dict:
    """Create an EPIC."""
    return get_jira_client().create_epic(summary, description)

def create_story(epic_key: str, summary: str, description: Optional[str] = None, 
                 vuln_data: Optional[Dict] = None, custom_fields: Optional[Dict] = None) -> Dict:
    """Create a story under an epic."""
    return get_jira_client().create_story(epic_key, summary, description, vuln_data, custom_fields)

def create_subtask(story_key: str, summary: str, description: Optional[str] = None) -> Dict:
    """Create a sub-task under a story."""
    return get_jira_client().create_subtask(story_key, summary, description)

def update_progress(issue_key: str, progress: int) -> Dict:
    """Update progress of an issue (0-100)."""
    return get_jira_client().update_progress(issue_key, progress)

def update_details(issue_key: str, **kwargs) -> Dict:
    """Update issue details. Example: update_details('PROJ-123', summary='New title', description='New desc')."""
    return get_jira_client().update_details(issue_key, kwargs)

def list_epics(project_key: Optional[str] = None, max_results: int = 100) -> List[Dict[str, Any]]:
    """List all epics in a project."""
    return get_jira_client().list_epics(project_key, max_results)

def list_stories(epic_key: Optional[str] = None, project_key: Optional[str] = None, max_results: int = 200) -> List[Dict[str, Any]]:
    """List stories, optionally filtered by epic."""
    return get_jira_client().list_stories(epic_key, project_key, max_results)

def list_subtasks(parent_key: str, max_results: int = 200) -> List[Dict[str, Any]]:
    """List sub-tasks under a parent issue."""
    return get_jira_client().list_subtasks(parent_key, max_results)

def get_issue(issue_key: str, fields: Optional[List[str]] = None) -> Dict[str, Any]:
    """Get a single issue by key."""
    return get_jira_client().get_issue(issue_key, fields)


if __name__ == "__main__":
    # Vulnerability properties
    props = {
        "APP_CODE": "0Z50",
        "APP_NAME": "CM Data Fabric",
        "ASSET_NAME": "GUEDLVAOZ50005",
        "CROWN_JEWEL": "FALSE",
        "DATA_SOURCE": "TENABLE_SC",
        "ENV": "Dev",
        "EXPOSURE": "Internal",
        "FIRST_DETECTION": "7/19/2025",
        "FIX_BY": "9/17/2025",
        "PRIORITY": "P3",
        "TREATMENT_OWNER": "TI - AIX/UNIX Team",
        "VULN_ID": "242108",
        "VULN_NAME": "RHEL8 : python-setuptools (RHSA-2025:11036)",
        "APP_COORDINATOR": "Vyas, Dhaval",
        "APP_CUSTODIAN": "Talayian, Bahar",
        "SOLUTION": "Update the RHEL python-setuptools package based on the guidance in RHSA-2025:11036."
    }
    
    try:
        client = get_jira_client()
        issue = client.jira.issue('DS-3')
        
        summary = f"Patch {props['VULN_ID']}: {props['VULN_NAME']}"
        description = f"Solving the vulnerability {props['VULN_ID']}: {props['VULN_NAME']} by {props['SOLUTION']}"
        
        fields = {"summary": summary, "description": description}
        
        # Get field metadata and map custom fields
        meta = client.jira.createmeta(projectKeys=client.project_key, issuetypeNames="Story", expand="projects.issuetypes.fields")
        if meta and meta.get("projects"):
            available_fields = meta["projects"][0]["issuetypes"][0]["fields"]
            
            for field_id, field_data in available_fields.items():
                field_name = field_data.get("name", "")
                if field_name in props:
                    value = props[field_name]
                    field_type = field_data.get("schema", {}).get("type", "")
                    
                    if field_type == "date":
                        from datetime import datetime
                        fields[field_id] = datetime.strptime(value, "%m/%d/%Y").strftime("%Y-%m-%d")
                    elif field_type == "option":
                        fields[field_id] = {"value": str(value)}
                    else:
                        fields[field_id] = str(value)
        
        # Update priority
        priorities = client.jira.priorities()
        priority_match = next((p for p in priorities if props["PRIORITY"].lower() in p.name.lower()), None)
        if priority_match:
            fields["priority"] = {"name": priority_match.name}
        
        issue.update(fields=fields)
        print(f"Successfully updated story DS-2 with {len(props)} fields")
    except Exception as ex:
        print(f"Error updating story DS-2: {ex}")
