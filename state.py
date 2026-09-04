from typing import Annotated, Any, TypedDict
import operator


class IncidentState(TypedDict, total=False):
    """
    Shared state for the incident response workflow.

    The state is progressively populated as the
    investigation moves through the LangGraph nodes.
    """

    # ==========================================
    # INCIDENT INPUT
    # ==========================================

    incident: dict[str, Any]

    # ==========================================
    # INVESTIGATION DATA
    # ==========================================

    evidence: Annotated[list[dict[str, Any]], operator.add]

    decisions: Annotated[list[dict[str, Any]], operator.add]

    timeline: Annotated[list[str], operator.add]

    # ==========================================
    # TRIAGE
    # ==========================================

    severity: str

    # ==========================================
    # AI ANALYSIS
    # ==========================================

    hypothesis: str

    confidence: float

    reasoning: str

    # ==========================================
    # RESPONSE PLANNING
    # ==========================================

    recommended_action: str

    # ==========================================
    # HUMAN APPROVAL
    # ==========================================

    containment_approved: bool

    approval_comment: str

    # ==========================================
    # CONTAINMENT
    # ==========================================

    containment_result: str

    # ==========================================
    # FINAL OUTPUT
    # ==========================================

    final_report: str
