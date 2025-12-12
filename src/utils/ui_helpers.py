import json
from src.graph_workflow import app
from src.utils.logger import get_logger
from src.state import GraphState

logger = get_logger(__name__)

# Default values for all state fields to ensure complete state
DEFAULT_STATE: dict = {
    "user_input": "",
    "intent": "",
    "intent_data": None,
    "command": "",
    "output": "",
    "vuln_data": None,
    "rhsa_id": None,
    "cve_ids": None,
    "cve_data": None,
    "csaf_data": None,
    "cve_summary": None,
    "csaf_summary": None,
    "jira_issues": None,
    "remediation_plan": None,
    "patcher_logs": None,
    "patcher_errors": None,
    "current_step": 0,
    "additional_info": None,
}


def get_complete_state(partial_state: dict) -> dict:
    """Merge partial state with default values to ensure complete state."""
    # Merge partial state with defaults, partial state takes precedence
    complete_state = {**DEFAULT_STATE, **partial_state}
    return complete_state


def format_state_display(state_dict):
    """Format state dictionary as readable key-value pairs with scrollable containers."""
    logger.info("Entering format_state_display")
    if not state_dict:
        return "<div><strong>State Information</strong><br><br>No state data available.</div>"
    
    html_parts = ['<div style="display: flex; flex-direction: column; gap: 12px;">']
    html_parts.append('<h3 style="margin: 0 0 10px 0;">State Information</h3>')
    
    key_style = "font-weight: bold; color: #2563eb; margin-bottom: 4px;"
    container_style = (
        "max-height: 200px; overflow-y: auto; overflow-x: hidden; "
        "padding: 8px; background: #f3f4f6; border-radius: 4px; "
        "border: 1px solid #d1d5db; margin-bottom: 8px;"
    )
    value_style = "font-family: monospace; font-size: 0.9em; word-break: break-word; white-space: pre-wrap;"
    
    for key, value in state_dict.items():
        if value is None:
            html_parts.append(
                f'<div><div style="{key_style}">{key}</div>'
                f'<div style="{container_style}"><span style="{value_style}">None</span></div></div>'
            )
        elif isinstance(value, dict):
            json_str = json.dumps(value, indent=2)
            pre_style = f"{value_style} margin: 0;"
            html_parts.append(
                f'<div><div style="{key_style}">{key}</div>'
                f'<div style="{container_style}"><pre style="{pre_style}">{json_str}</pre></div></div>'
            )
        else:
            escaped_value = str(value).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            html_parts.append(
                f'<div><div style="{key_style}">{key}</div>'
                f'<div style="{container_style}"><span style="{value_style}">{escaped_value}</span></div></div>'
            )
    
    html_parts.append('</div>')
    return ''.join(html_parts)


def get_current_step(state: dict) -> int:
    """Determine current step based on state. Returns step index (1-based)."""
    # Prioritize saved current_step from state
    saved_step = state.get("current_step", 0)
    if saved_step and saved_step > 0:
        return saved_step
    
    # Fallback to inference if current_step not set
    intent = state.get("intent", "")
    
    # Step 1: start (list_vulns_node)
    if intent == "LIST_VULNS":
        return 1
    
    # Step 2: get_details (analyze_vuln_node)
    if state.get("vuln_data"):
        return 2
    
    # Step 3: impact/blast radius (gremlin_node)
    if state.get("cve_data") or state.get("csaf_data"):
        if not state.get("remediation_plan"):
            return 3
    
    # Step 4: Plan Generation (planner_node)
    if state.get("remediation_plan") and not state.get("patcher_logs"):
        return 4
    
    # Steps 5-8: patcher_node stages
    patcher_logs = state.get("patcher_logs", [])
    if patcher_logs:
        # Determine stage based on log step names
        all_steps = [log.get("step", "") for log in patcher_logs]
        has_pre_check = any("pre_check" in s for s in all_steps)
        has_check_packages = any("check_packages" in s for s in all_steps)
        has_apply_remediation = any("apply_remediation" in s for s in all_steps)
        has_verify_fix = any("verify_fix" in s for s in all_steps)
        
        if has_verify_fix:
            # Check if output contains report
            output = state.get("output", "")
            if "Execution Report" in output:
                # Check if we're at end (no errors or all complete)
                patcher_errors = state.get("patcher_errors", [])
                if not patcher_errors or len(patcher_errors) == 0:
                    return 9  # end
                return 8  # report
            return 7  # verify
        elif has_apply_remediation:
            return 6  # patch
        elif has_check_packages:
            return 6  # patch
        elif has_pre_check:
            return 5  # system pre-checks
        else:
            return 5  # default to pre-checks
    
    return 0  # No step active


def render_stepper(current_step: int) -> str:
    """Render horizontal stepper HTML."""
    STEPS = ["start", "get_details", "impact/blast radius", "Plan Generation", 
             "system pre-checks", "patch", "verify", "report", "end"]
    
    html = """
    <style>
        .stepper-container {
            display: flex;
            justify-content: space-between;
            align-items: center;
            width: 100%;
            margin: 20px auto;
            position: relative;
            padding: 10px 0;
        }
        .stepper-container::before {
            content: "";
            position: absolute;
            top: 22px;
            left: 0;
            right: 0;
            height: 3px;
            background: #ccc;
            z-index: 1;
        }
        .step {
            text-align: center;
            flex: 1;
            z-index: 2;
        }
        .circle {
            width: 45px;
            height: 45px;
            border-radius: 50%;
            border: 2px solid #ccc;
            background-color: #eee;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 14px;
            margin: auto;
        }
        .active .circle {
            background-color: #1f6feb;
            color: white;
            border-color: #1f6feb;
        }
        .label {
            margin-top: 7px;
            font-size: 11px;
            word-break: break-word;
        }
    </style>
    <div class="stepper-container">
    """
    
    for i, step in enumerate(STEPS, start=1):
        active_class = "active" if i <= current_step else ""
        html += f"""
        <div class="step {active_class}">
            <div class="circle">{i}</div>
            <div class="label">{step}</div>
        </div>
        """
    
    html += "</div>"
    return html


def chat_fn(message, history):
    """Process message and return output along with formatted state data."""
    logger.info(f"Entering chat_fn with message: {message[:50] if message else 'None'}...")
    
    # Use thread_id for conversation persistence (default session)
    thread_id = "default_session"
    config = {"configurable": {"thread_id": thread_id}}
    
    # Try to get existing state, fallback to defaults if it fails
    try:
        current_state = app.get_state(config)
        existing_state = current_state.values if current_state else DEFAULT_STATE.copy()
    except (AttributeError, Exception) as e:
        logger.warning(f"Could not get state from checkpoint: {e}, using defaults")
        existing_state = DEFAULT_STATE.copy()
    
    # Update only user_input, preserving all other fields
    initial_state = {**existing_state, "user_input": message or ""}
    
    # Invoke with state persistence
    result = app.invoke(initial_state, config=config)
    
    # Ensure we have complete state (merge with defaults in case any fields are missing)
    complete_state = get_complete_state(result)
    
    output = complete_state.get("output") or ""
    state_display = format_state_display(complete_state)
    current_step = get_current_step(complete_state)
    stepper_html = render_stepper(current_step)
    
    return output, state_display, stepper_html

