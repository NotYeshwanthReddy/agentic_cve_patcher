import gradio as gr
import json
import os
from src.utils.ui_helpers import chat_fn
from src.utils.logger import get_logger

logger = get_logger(__name__)

# File path for storing chat history
CHAT_HISTORY_FILE = "data/chat_history.json"

def load_chat_history():
    """Load chat history from file."""
    try:
        if os.path.exists(CHAT_HISTORY_FILE):
            with open(CHAT_HISTORY_FILE, 'r', encoding='utf-8') as f:
                history = json.load(f)
                logger.info(f"Loaded chat history with {len(history)} messages")
                return history
    except Exception as e:
        logger.warning(f"Error loading chat history: {e}")
    return []

def save_chat_history(history):
    """Save chat history to file."""
    try:
        os.makedirs(os.path.dirname(CHAT_HISTORY_FILE), exist_ok=True)
        with open(CHAT_HISTORY_FILE, 'w', encoding='utf-8') as f:
            json.dump(history, f, ensure_ascii=False, indent=2)
        logger.info(f"Saved chat history with {len(history)} messages")
    except Exception as e:
        logger.error(f"Error saving chat history: {e}")


with gr.Blocks(title="CVE Patcher Assistant") as demo:
    gr.Markdown("# CVE Patcher Assistant")
    gr.Markdown("Chat with your assistant to resolve vulnerabilities.")
    
    # Store chat history in state to persist across page refreshes
    # Initialize with saved history from file
    initial_history = load_chat_history()
    chat_history = gr.State(value=initial_history)
    
    # Progress stepper
    stepper_display = gr.HTML(value="")
    
    with gr.Row():
        with gr.Column(scale=2):
            # Initialize chatbot with saved history
            chatbot = gr.Chatbot(height=500, label="Chat", value=initial_history)
            msg = gr.Textbox(
                label="Message",
                placeholder="Type your message here...",
                scale=4
            )
            submit_btn = gr.Button("Submit", variant="primary")
        
        with gr.Column(scale=1):
            state_display = gr.HTML(
                value="<div><strong>State Information</strong><br><br>No state data available.</div>",
                label="State",
                elem_classes=["state-panel"]
                # height=500
            )
    
    def respond(message, stored_history):
        logger.info("Entering respond function")
        # Always use stored_history as the source of truth
        current_history = stored_history if stored_history else []
        output, state_text, stepper_html = chat_fn(message, current_history)
        # Update the stored history
        updated_history = current_history + [(message, output)]
        # Save to file for persistence
        save_chat_history(updated_history)
        return updated_history, updated_history, state_text, stepper_html, ""
    
    def load_history():
        """Load stored history when page refreshes - always load from file"""
        from src.utils.ui_helpers import get_current_step, render_stepper
        from src.graph_workflow import app
        
        history = load_chat_history()
        # Restore stepper based on current state
        try:
            thread_id = "default_session"
            config = {"configurable": {"thread_id": thread_id}}
            current_state = app.get_state(config)
            if current_state and current_state.values:
                step = get_current_step(current_state.values)
                stepper_html = render_stepper(step)
            else:
                stepper_html = ""
        except:
            stepper_html = ""
        return history, history, stepper_html
    
    # Load history when the page loads (on page refresh)
    # This updates both the state and the chatbot display
    demo.load(load_history, None, [chat_history, chatbot, stepper_display])
    
    msg.submit(respond, [msg, chat_history], [chat_history, chatbot, state_display, stepper_display, msg])
    submit_btn.click(respond, [msg, chat_history], [chat_history, chatbot, state_display, stepper_display, msg])


def launch_ui():
    logger.info("Entering launch_ui")
    demo.launch(share=True)


if __name__ == "__main__":
    launch_ui()
