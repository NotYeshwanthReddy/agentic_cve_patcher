import gradio as gr
from src.graph_workflow import app

def chat_fn(message, history):
    result = app.invoke({"user_input": message})
    return result["output"]  # ✅ Return just the response text

def launch_ui():
    gr.ChatInterface(
        fn=chat_fn,
        title="Remote Shell Assistant",
        description="Chat with your remote Linux server via SSH."
    ).launch()

if __name__ == "__main__":
    launch_ui()
