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
    "cve_data": None,
    "csaf_data": None,
    "cve_summary": None,
    "csaf_summary": None,
    "jira_issues": None,
    "remediation_plan": None,
    "patcher_logs": None,
    "patcher_errors": None,
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
    return output, state_display

