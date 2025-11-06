import gradio as gr
from src.utils.ui_helpers import chat_fn
from src.utils.logger import get_logger

logger = get_logger(__name__)


with gr.Blocks(title="CVE Patcher Assistant") as demo:
    gr.Markdown("# CVE Patcher Assistant")
    gr.Markdown("Chat with your assistant to resolve vulnerabilities.")
    
    with gr.Row():
        with gr.Column(scale=2):
            chatbot = gr.Chatbot(height=500, label="Chat")
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
    
    def respond(message, history):
        logger.info("Entering respond function")
        output, state_text = chat_fn(message, history)
        history.append((message, output))
        return history, state_text, ""
    
    msg.submit(respond, [msg, chatbot], [chatbot, state_display, msg])
    submit_btn.click(respond, [msg, chatbot], [chatbot, state_display, msg])


def launch_ui():
    logger.info("Entering launch_ui")
    demo.launch(share=True)


if __name__ == "__main__":
    launch_ui()
