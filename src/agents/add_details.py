"""Module for adding user-provided details to state variables."""
import json
import re
from typing import Dict, Any, List, Optional
from src.utils.settings import llm
from src.utils.logger import get_logger

logger = get_logger(__name__)


def extract_cve_ids(text: str) -> List[str]:
    """Extract CVE IDs from text using regex pattern."""
    # Pattern to match CVE IDs: CVE-YYYY-NNNNN
    cve_pattern = r'CVE-\d{4}-\d{4,}'
    cve_ids = re.findall(cve_pattern, text, re.IGNORECASE)
    # Remove duplicates and sort
    return sorted(list(set(cve_ids)))


def merge_remediation_plans(existing_plan: Dict[str, Any], user_changes: Dict[str, Any], user_input: str) -> Dict[str, Any]:
    """
    Merge user-provided changes with existing remediation plan.
    Uses LLM to intelligently understand and apply changes.
    """
    logger.info("Entering merge_remediation_plans")
    
    existing_plan_str = json.dumps(existing_plan, indent=2) if existing_plan else "None"
    user_changes_str = json.dumps(user_changes, indent=2) if user_changes else "None"
    
    prompt = f"""You need to merge changes to a remediation plan. The user may have provided:
1. A complete new plan (replace everything)
2. Partial changes (only update specific sections)
3. Textual instructions about what to change

Existing remediation plan:
```json
{existing_plan_str}
```

User-provided changes/instructions:
```json
{user_changes_str}
```

User's original message: '''{user_input}'''

Your task:
1. Understand what changes the user wants to make to the existing plan
2. If the user provided a complete plan, use it (but preserve any important context from existing plan if needed)
3. If the user provided partial changes or instructions, merge them intelligently with the existing plan:
   - Update only the sections that were changed
   - Add new sections if provided
   - Remove sections only if explicitly requested
   - Preserve all other existing sections unchanged
4. Return the COMPLETE merged remediation plan as a JSON object

Return ONLY a valid JSON object - the complete merged remediation plan:
{{
    "pre_checks": {{...}},
    "check_packages": {{...}},
    "apply_remediation": {{...}},
    "verify_fix": {{...}},
    "rollback_plan": {{...}},
    "production_report": {{...}}
}}

Important:
- Return the COMPLETE plan, not just the changes
- If user provided complete plan, use it
- If user provided partial changes, merge with existing plan
- Preserve structure and all existing sections unless explicitly changed
"""
    
    try:
        resp = llm.invoke(prompt).content.strip()
        # Try to parse JSON, handling markdown code blocks if present
        if "```" in resp:
            resp = resp.split("```")[1].replace("json", "").strip()
        merged_plan = json.loads(resp)
        logger.info(f"Merged remediation plan with keys: {list(merged_plan.keys())}")
        return merged_plan
    except Exception as e:
        logger.error(f"Error merging remediation plans: {e}")
        # Fallback: if user provided a complete plan, use it; otherwise merge manually
        if user_changes and isinstance(user_changes, dict):
            if existing_plan:
                # Simple merge: update existing plan with user changes
                merged = existing_plan.copy()
                merged.update(user_changes)
                # Deep merge for nested dicts
                for key, value in user_changes.items():
                    if isinstance(value, dict) and key in merged and isinstance(merged[key], dict):
                        merged[key] = {**merged[key], **value}
                return merged
            else:
                return user_changes
        return existing_plan or {}


def parse_state_updates(user_input: str, current_state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parse user input to determine which state variables to update.
    Returns a dictionary with state updates.
    """
    logger.info(f"Entering parse_state_updates with input: {user_input[:100]}...")
    
    # Build context about current state
    current_cve_ids = current_state.get("cve_ids") or []
    current_additional_info = current_state.get("additional_info") or ""
    current_remediation_plan = current_state.get("remediation_plan")
    
    # Format existing plan for prompt
    existing_plan_str = json.dumps(current_remediation_plan, indent=2) if current_remediation_plan else "None"
    
    prompt = f"""Analyze the user's message and determine which state variables should be updated.

Available state variables:
1. cve_ids: A list of CVE ID strings (e.g., ["CVE-2025-47273", "CVE-2025-47222"])
2. additional_info: A string containing additional information like application paths, package paths, system details, etc.
3. remediation_plan: A JSON object containing a remediation plan with keys like pre_checks, check_packages, apply_remediation, verify_fix, rollback_plan, production_report

Current state:
- cve_ids: {current_cve_ids if current_cve_ids else "None"}
- additional_info: {current_additional_info[:200] if current_additional_info else "None"}
- remediation_plan: {existing_plan_str[:500] if current_remediation_plan else "None"}

User message: '''{user_input}'''

Your task:
1. Identify if the user is providing CVE IDs (they will be in format CVE-YYYY-NNNNN)
2. Identify if the user is providing additional information (like paths, system details, configuration, etc.)
3. Identify if the user wants to update the remediation plan. This could be:
   - A complete new plan (JSON object)
   - Partial changes to specific sections (e.g., "change apply_remediation command to X")
   - Textual instructions about what to modify
4. For CVE IDs: Extract ONLY the NEW CVE IDs from the user's message (not the existing ones).
5. For additional_info: Extract ONLY the NEW information from the user's message and format it clearly.
6. For remediation_plan: 
   - If the user provided a complete JSON plan, extract it
   - If the user provided partial changes or instructions, extract what they want to change
   - The changes can be in JSON format, code blocks, or natural language instructions

Return ONLY a valid JSON object in this exact format:
{{
    "update_cve_ids": <true or false>,
    "cve_ids": <list of NEW CVE ID strings found in the message, or null if not updating>,
    "update_additional_info": <true or false>,
    "additional_info": <string with NEW additional info from the message, or null if not updating>,
    "update_remediation_plan": <true or false>,
    "remediation_plan_changes": <the changes/updates the user wants to make to the plan. This can be:
        - A complete plan (if user provided full replacement)
        - Partial changes (only the sections to update)
        - null if not updating>
}}

Important: 
- Only return NEW values/changes from the user's message. Do NOT include existing state values.
- For remediation_plan_changes: Extract what the user wants to change. If they provided a complete plan, return it. If they provided partial changes or instructions, return only what needs to be changed.
- If not updating a field, set the update flag to false and the value to null.
"""
    
    try:
        resp = llm.invoke(prompt).content.strip()
        # Try to parse JSON, handling markdown code blocks if present
        if "```" in resp:
            resp = resp.split("```")[1].replace("json", "").strip()
        result = json.loads(resp)
        
        updates = {}
        
        # Handle CVE IDs update
        if result.get("update_cve_ids", False):
            new_cve_ids = result.get("cve_ids")
            if new_cve_ids and isinstance(new_cve_ids, list):
                # Merge with existing, remove duplicates, sort
                merged = list(set((current_cve_ids or []) + new_cve_ids))
                updates["cve_ids"] = sorted(merged)
                logger.info(f"Updating cve_ids: {updates['cve_ids']}")
        
        # Handle additional_info update
        if result.get("update_additional_info", False):
            new_info = result.get("additional_info")
            if new_info and isinstance(new_info, str):
                if current_additional_info:
                    updates["additional_info"] = f"{current_additional_info}\n\n---\n\n{new_info}"
                else:
                    updates["additional_info"] = new_info
                logger.info(f"Updating additional_info: {updates['additional_info'][:100]}...")
        
        # Handle remediation_plan update
        if result.get("update_remediation_plan", False):
            plan_changes = result.get("remediation_plan_changes")
            if plan_changes and isinstance(plan_changes, dict):
                # Merge changes with existing plan
                if current_remediation_plan:
                    merged_plan = merge_remediation_plans(current_remediation_plan, plan_changes, user_input)
                    updates["remediation_plan"] = merged_plan
                    logger.info(f"Merged remediation_plan with keys: {list(merged_plan.keys())}")
                else:
                    # No existing plan, use the provided plan/changes as the new plan
                    updates["remediation_plan"] = plan_changes
                    logger.info(f"Setting new remediation_plan with keys: {list(plan_changes.keys())}")
        
        return updates
        
    except Exception as e:
        logger.error(f"Error parsing state updates: {e}")
        # Fallback: try to extract CVE IDs using regex
        cve_ids = extract_cve_ids(user_input)
        if cve_ids:
            merged = list(set((current_cve_ids or []) + cve_ids))
            return {"cve_ids": sorted(merged)}
        # If no CVE IDs found, treat as additional_info
        if user_input.strip():
            if current_additional_info:
                return {"additional_info": f"{current_additional_info}\n\n---\n\n{user_input}"}
            else:
                return {"additional_info": user_input}
        return {}


def add_details_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Node that parses user input and adds details to appropriate state variables.
    """
    logger.info("Entering add_details_node")
    
    user_input = state.get("user_input", "")
    if not user_input:
        return {"output": "No input provided to add details."}
    
    # Parse the user input to determine what to update
    updates = parse_state_updates(user_input, state)
    
    if not updates:
        return {"output": "I couldn't identify any details to add from your input. Please provide CVE IDs (format: CVE-YYYY-NNNNN), additional information like paths, system details, or a remediation plan (JSON format)."}
    
    # Build output message
    output_parts = ["Details added successfully:\n"]
    
    if "cve_ids" in updates:
        cve_list = updates["cve_ids"]
        output_parts.append(f"✓ CVE IDs: {', '.join(cve_list)}")
    
    if "additional_info" in updates:
        info_preview = updates["additional_info"][:200]
        if len(updates["additional_info"]) > 200:
            info_preview += "..."
        output_parts.append(f"✓ Additional Information: {info_preview}")
    
    if "remediation_plan" in updates:
        plan = updates["remediation_plan"]
        plan_keys = list(plan.keys()) if isinstance(plan, dict) else []
        existing_plan = state.get("remediation_plan")
        if existing_plan:
            # Identify what changed
            changed_sections = []
            for key in plan_keys:
                if key not in existing_plan or plan.get(key) != existing_plan.get(key):
                    changed_sections.append(key)
            if changed_sections:
                output_parts.append(f"✓ Remediation Plan: Updated sections ({', '.join(changed_sections[:5])}{'...' if len(changed_sections) > 5 else ''})")
            else:
                output_parts.append(f"✓ Remediation Plan: Updated with {len(plan_keys)} sections")
        else:
            output_parts.append(f"✓ Remediation Plan: Created with {len(plan_keys)} sections ({', '.join(plan_keys[:5])}{'...' if len(plan_keys) > 5 else ''})")
    
    output = "\n".join(output_parts)
    
    # Return updates to be merged into state
    return {
        "output": output,
        **updates
    }

