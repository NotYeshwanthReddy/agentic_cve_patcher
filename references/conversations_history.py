import gradio as gr

# Store past conversations
conversation_history = {
    "Vulnerability 10011": ["Hi", "Hello!", "How are you?"],
    "Vulnerability 10012": ["What is AI?", "AI is ..."],
    "Vulnerability 10013": ["What is the capital of France?", "The capital of France is Paris."],
    "Vulnerability 10014": ["What is the capital of Germany?", "The capital of Germany is Berlin."],
    "Vulnerability 10015": ["What is the capital of Italy?", "The capital of Italy is Rome."],
    "Vulnerability 10016": ["What is the capital of Spain?", "The capital of Spain is Madrid."],
    "Vulnerability 10017": ["What is the capital of Portugal?", "The capital of Portugal is Lisbon."],
    "Vulnerability 10018": ["What is the capital of Greece?", "The capital of Greece is Athens."],
    "Vulnerability 10019": ["What is the capital of Turkey?", "The capital of Turkey is Ankara."],
    "Vulnerability 100110": ["What is the capital of Russia?", "The capital of Russia is Moscow."],
}

def on_new_message(message, history):
    """Handles new chat messages and stores them."""
    history = history + [(message, f"Echo: {message}")]

    # Save updated active conversation to history
    conversation_history["Current Conversation"] = [
        f"User: {m}, Bot: {r}" for m, r in history
    ]

    # Update sidebar list
    return history, list(conversation_history.keys())


def load_conversation(selected_key):
    """Print conversation in console when clicked."""
    if selected_key in conversation_history:
        print("\n=== CLICKED CONVERSATION ===")
        for line in conversation_history[selected_key]:
            print(line)
        print("================================\n")
    # No UI updates needed
    return


with gr.Blocks(css="""
.vertical-radio .wrap .item {
    display: block !important;    /* stack vertically */
    margin-bottom: 6px;
}
""") as demo:

    # gr.Markdown("## Chat with Left-Side Conversation History")

    with gr.Row():
        # ----- LEFT SIDEBAR -----
        history_list = gr.Radio(
            label="Conversation History",
            choices=list(conversation_history.keys()),
            interactive=True,
            elem_classes="vertical-radio",
        )

        # ----- CHAT UI -----
        with gr.Column():
            chatbot = gr.Chatbot(label="Chat Window")
            msg = gr.Textbox(label="Type a message")
            send_btn = gr.Button("Send")

    # Send message
    send_btn.click(
        fn=on_new_message,
        inputs=[msg, chatbot],
        outputs=[chatbot, history_list]
    )

    msg.submit(
        fn=on_new_message,
        inputs=[msg, chatbot],
        outputs=[chatbot, history_list]
    )

    history_list.select(load_conversation, inputs=history_list, outputs=[])

demo.launch()
