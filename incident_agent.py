import logging
import sqlite3

from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, START, StateGraph

from nodes import (
    analyze_incident,
    collect_evidence,
    containment,
    generate_report,
    plan_response,
    request_approval,
    triage_incident,
)
from state import IncidentState
from config import CHECKPOINT_DB


logger = logging.getLogger(__name__)


def build_incident_graph():
    """
    Build and compile the incident response LangGraph.

    A dedicated SQLite connection is created for the compiled
    graph's checkpointer. The connection is configured for
    Streamlit's execution model by disabling the same-thread
    restriction.
    """

    logger.info("Building incident response graph")

    workflow = StateGraph(IncidentState)

    # Register workflow nodes
    workflow.add_node("triage", triage_incident)
    workflow.add_node("collect_evidence", collect_evidence)
    workflow.add_node("analyze", analyze_incident)
    workflow.add_node("plan_response", plan_response)
    workflow.add_node("human_approval", request_approval)
    workflow.add_node("containment", containment)
    workflow.add_node("report", generate_report)

    # Define workflow
    workflow.add_edge(START, "triage")
    workflow.add_edge("triage", "collect_evidence")
    workflow.add_edge("collect_evidence", "analyze")
    workflow.add_edge("analyze", "plan_response")
    workflow.add_edge("plan_response", "human_approval")
    workflow.add_edge("human_approval", "containment")
    workflow.add_edge("containment", "report")
    workflow.add_edge("report", END)

    # Create the SQLite connection only when the graph is built.
    connection = sqlite3.connect(
        str(CHECKPOINT_DB),
        check_same_thread=False,
    )

    # Create LangGraph SQLite checkpointer.
    checkpointer = SqliteSaver(connection)

    # Compile the workflow with checkpoint persistence.
    graph = workflow.compile(checkpointer=checkpointer)

    return graph
