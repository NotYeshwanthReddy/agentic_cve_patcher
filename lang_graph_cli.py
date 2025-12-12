"""Simple CLI to interact with the lang-graph without Gradio.

Usage: python lang_graph_cli.py

This script imports the same `chat_fn` used by the Gradio UI and exposes a REPL.
"""
import sys
from src.utils.ui_helpers import chat_fn
import re

WELCOME = "CVE Patcher Assistant (CLI). Type 'exit' or 'quit' to leave. Type 'help' for features."


def repl():
    print(WELCOME)
    history = []
    try:
        while True:
            try:
                user = input("You: ")
            except EOFError:
                break
            if not user:
                continue
            if user.strip().lower() in ("exit", "quit"):
                print("Goodbye.")
                break
            if user.strip().lower() in ("print state" or "print state variables"):
                # state_display is HTML; print a short preview by stripping tags naively
                print("\n--- State (compact) ---")
                text_preview = re.sub(r'<[^>]+>', '', state_display)
                print(text_preview)
                print("\n-----------------------\n")
                continue
            # Call existing chat function which returns (output, state_display, stepper_html)
            output, state_display, stepper_html = chat_fn(user, history)
            # Update history the same way as Gradio (message, response)
            history = history + [(user, output)]
            # Print output and a compact state summary
            print("Assistant:\n" + (output or "(no output)"))

    except KeyboardInterrupt:
        print("\nInterrupted. Exiting.")


if __name__ == "__main__":
    repl()
