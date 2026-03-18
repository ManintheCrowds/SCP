# PURPOSE: Example Daggr workflow for SCP content safety pipeline.
# DEPENDENCIES: pip install scp daggr gradio
# MODIFICATION NOTES: Standalone example; uses scp package.

"""
SCP Daggr Workflow: inspect -> sanitize -> contain -> quarantine.
Example integration of SCP with Daggr and Gradio.
"""

from scp.scp_utils import run_pipeline

from daggr import FnNode, Graph
import gradio as gr


def scp_full_pipeline(content: str) -> dict:
    """Run pipeline (inspect -> sanitize -> contain). Returns combined result."""
    pipeline_result = run_pipeline(content, sink="llm_context", options={"quarantine_on_block": True})
    return {"pipeline": pipeline_result, "inspect": pipeline_result.get("report", {})}


# Single node for simplicity
graph = Graph(
    name="SCP Content Safety Pipeline",
    nodes=[
        FnNode(
            fn=scp_full_pipeline,
            inputs={"content": gr.Textbox(label="Content to process", lines=8, placeholder="Paste content to inspect, sanitize, and contain...")},
            outputs={"result": gr.JSON(label="SCP result (inspect + pipeline)")},
        )
    ],
)


if __name__ == "__main__":
    print("Starting SCP Daggr workflow...")
    print("Open the URL shown below in your browser")
    graph.launch()
