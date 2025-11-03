import json
from src.graph_workflow import app


def format_state_display(state_dict):
    """Format state dictionary as readable key-value pairs with scrollable containers."""
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
    result = app.invoke({"user_input": message or ""})
    output = result.get("output") or ""
    state_display = format_state_display(result)
    return output, state_display

