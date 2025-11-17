import gradio as gr

STEPS = ["Prospect", "Tour", "Offer", "Contract", "Settled"]

def render_progress(current_step):
    html = """
    <style>
        .stepper-container {
            display: flex;
            justify-content: space-between;
            align-items: center;
            width: 95%;
            margin: 30px auto;
            position: relative;
            padding-bottom: 20px;
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
            width: 120px;
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
            font-size: 18px;
            margin: auto;
        }

        .active .circle {
            background-color: #1f6feb;
            color: white;
            border-color: #1f6feb;
        }

        .label {
            margin-top: 7px;
            font-size: 15px;
        }
    </style>

    <div class="stepper-container">
    """

    # Build all steps
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


def next_step(curr_step):
    if curr_step < len(STEPS):
        curr_step += 1
    return curr_step, render_progress(curr_step)


with gr.Blocks() as demo:
    gr.Markdown("## Step Progress Demo")

    state = gr.State(1)
    html_display = gr.HTML(render_progress(1))

    btn = gr.Button("Next Step")
    btn.click(
        next_step,
        inputs=state,
        outputs=[state, html_display]
    )

demo.launch()
