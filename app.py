import uuid
import logging
import re
from typing import Any

import streamlit as st
from langgraph.types import Command

from incident_agent import build_incident_graph
from checkpoint_manager import (
    archive_investigation,
    create_investigation,
    delete_investigation,
    get_investigations,
    update_investigation,
)
from state import IncidentState


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="Incident Response Agent",
    page_icon="🚨",
    layout="wide",
)


@st.cache_resource
def get_incident_graph():
    """Create and cache one checkpointer-backed graph per app process."""
    return build_incident_graph()


incident_graph = get_incident_graph()


# ============================================================
# SESSION STATE
# ============================================================

if "thread_id" not in st.session_state:
    st.session_state.thread_id = None

if "investigation_started" not in st.session_state:
    st.session_state.investigation_started = False


# ============================================================
# GRAPH CONFIG
# ============================================================


def get_config():
    """
    Return the LangGraph configuration for the current investigation.
    """

    return {
        "configurable": {
            "thread_id": st.session_state.thread_id,
        }
    }


# ============================================================
# GET LIVE GRAPH STATE
# ============================================================


def get_current_state():
    """
    Retrieve the current investigation state directly from LangGraph.

    LangGraph checkpoint state is treated as the source of truth
    for the UI.
    """

    if not st.session_state.thread_id:
        return None

    try:
        return incident_graph.get_state(get_config())

    except Exception as exc:
        st.error(f"Could not retrieve investigation state: {exc}")

        return None


# ============================================================
# RESUME INVESTIGATION
# ============================================================


def resume_investigation(
    approved: bool,
    comment: str,
):
    """
    Resume the paused LangGraph workflow with the human decision.
    """

    try:
        logger.info("Resuming investigation: approved=%s", approved)

        with st.spinner("Resuming investigation..."):
            incident_graph.invoke(
                Command(
                    resume={
                        "approved": approved,
                        "comment": comment,
                    }
                ),
                config=get_config(),
            )

        current_state = incident_graph.get_state(get_config())

        if current_state.next == () and "final_report" in current_state.values:
            update_investigation(
                st.session_state.thread_id,
                status="Completed",
                severity=current_state.values.get("severity"),
            )

        st.rerun()

    except Exception as exc:
        logger.exception("Could not resume investigation")
        st.error(f"Could not resume investigation: {exc}")


# ============================================================
# HEADER
# ============================================================

st.title("🚨 Incident Response Agent")

st.caption("LangGraph-based simulated cybersecurity incident investigation system")


# ============================================================
# SIDEBAR
# ============================================================
SCENARIOS = {
    "Suspicious Authentication / Brute Force": {
        "title": "Suspicious Authentication / Brute Force",
        "description": "Multiple failed login attempts followed by a successful authentication.",
        "severity_hint": "high",
        "logs": [
            "Multiple failed login attempts detected",
            "Successful login from unusual location",
            "Authentication from unknown IP address",
        ],
    },
    "Malware Infection": {
        "title": "Malware Infection",
        "description": "A suspicious process was detected running on an endpoint.",
        "severity_hint": "high",
        "logs": [
            "Suspicious process detected",
            "Unknown executable launched",
            "Endpoint antivirus alert triggered",
        ],
    },
    "Phishing Attempt": {
        "title": "Phishing Attempt",
        "description": "A suspicious email containing a potentially malicious link was reported.",
        "severity_hint": "medium",
        "logs": [
            "Suspicious email reported",
            "Malicious URL detected",
            "User clicked suspicious link",
        ],
    },
    "Ransomware Activity": {
        "title": "Ransomware Activity",
        "description": "Multiple files were detected being encrypted by a suspicious process.",
        "severity_hint": "critical",
        "logs": [
            "Multiple files encrypted",
            "Suspicious encryption process detected",
            "Ransomware behavior detected",
        ],
    },
    "Data Exfiltration": {
        "title": "Data Exfiltration",
        "description": "Unusual outbound data transfer was detected from an internal endpoint.",
        "severity_hint": "high",
        "logs": [
            "Large outbound data transfer detected",
            "Unusual external connection detected",
            "Sensitive data transfer suspected",
        ],
    },
    "DDoS / Unusual Traffic": {
        "title": "DDoS / Unusual Traffic",
        "description": "A sudden increase in network traffic was detected against a service.",
        "severity_hint": "high",
        "logs": [
            "Unusual network traffic detected",
            "Large number of requests received",
            "Traffic spike detected",
        ],
    },
    "Insider Threat": {
        "title": "Insider Threat",
        "description": "Suspicious activity involving a privileged or internal user was detected.",
        "severity_hint": "high",
        "logs": [
            "Privileged user accessed sensitive resources",
            "Unusual internal activity detected",
            "Sensitive files accessed unexpectedly",
        ],
    },
    "Suspicious Endpoint Activity": {
        "title": "Suspicious Endpoint Activity",
        "description": "Suspicious behavior was detected on an endpoint.",
        "severity_hint": "medium",
        "logs": [
            "Suspicious endpoint activity detected",
            "Unknown process observed",
            "Unusual system behavior detected",
        ],
    },
    "Custom Incident": {
        "title": "Custom Security Incident",
        "description": "User-defined security incident.",
        "severity_hint": "medium",
        "logs": [],
    },
}

with st.sidebar:
    # SAVED INVESTIGATIONS

    st.header("💾 Saved Investigations")

    saved_investigations = get_investigations()

    if saved_investigations:
        investigation_labels = [
            (
                f"{investigation['title']} | "
                f"{investigation['severity'].upper()} | "
                f"{investigation['status']}"
            )
            for investigation in saved_investigations
        ]

        selected_label = st.selectbox(
            "Select saved investigation",
            ["Select an investigation"] + investigation_labels,
            key="saved_investigation_selector",
        )

        if selected_label != "Select an investigation":
            selected_index = investigation_labels.index(selected_label)
            selected_investigation = saved_investigations[selected_index]

            st.caption(f"Scenario: {selected_investigation['scenario']}")
            st.caption(f"Updated: {selected_investigation['updated_at']}")

            col_resume, col_archive, col_delete = st.columns(3)

            with col_resume:
                if st.button(
                    "▶ Resume",
                    use_container_width=True,
                ):
                    selected_thread = selected_investigation["thread_id"]
                    config = {"configurable": {"thread_id": selected_thread}}

                    try:
                        saved_state = incident_graph.get_state(config)

                        if saved_state.values:
                            st.session_state.thread_id = selected_thread
                            st.session_state.investigation_started = True
                            st.rerun()
                        else:
                            st.error("Saved investigation could not be loaded.")

                    except Exception as exc:
                        st.error(f"Resume failed: {exc}")

            with col_archive:
                if st.button(
                    "Archive",
                    use_container_width=True,
                ):
                    selected_thread = selected_investigation["thread_id"]

                    if archive_investigation(selected_thread):
                        st.success("Investigation archived.")
                        st.rerun()
                    else:
                        st.error("Could not archive investigation.")

            with col_delete:
                if st.button(
                    "Delete",
                    use_container_width=True,
                ):
                    selected_thread = selected_investigation["thread_id"]

                    if delete_investigation(selected_thread):
                        if st.session_state.thread_id == selected_thread:
                            st.session_state.thread_id = None
                            st.session_state.investigation_started = False

                        st.success("Investigation deleted.")
                        st.rerun()
                    else:
                        st.error("Could not delete investigation.")

    st.divider()

    # NEW INVESTIGATION

    st.header("New Investigation")

    scenario_names = list(SCENARIOS.keys())

    scenario = str(
        st.selectbox(
            "Incident Scenario",
            scenario_names,
            key="scenario_selector",
        )
    )

    # CUSTOM INCIDENT

    selected_incident: dict[str, Any]

    if scenario == "Custom Incident":
        st.subheader("Custom Incident")

        custom_title = st.text_input(
            "Incident Title",
            value="Custom Security Incident",
        )

        custom_description = st.text_area(
            "Description",
            value="",
            height=100,
        )

        custom_severity = st.selectbox(
            "Severity",
            [
                "low",
                "medium",
                "high",
                "critical",
            ],
            index=1,
        )

        custom_logs_text = st.text_area(
            "Logs",
            value="",
            height=150,
            help="Enter one log or event per line.",
        )

        logs = [line.strip() for line in custom_logs_text.splitlines() if line.strip()]

        selected_incident = {
            "title": custom_title,
            "description": custom_description,
            "severity_hint": custom_severity,
            "logs": logs,
        }

    # PREDEFINED INCIDENT

    else:
        selected_incident = dict(SCENARIOS[scenario])

        st.subheader("Selected Scenario")

        st.write(
            selected_incident.get(
                "description",
                "No description available.",
            )
        )

        st.caption(
            "Severity hint: "
            + str(
                selected_incident.get(
                    "severity_hint",
                    "unknown",
                )
            ).upper()
        )

    st.divider()

    # START INVESTIGATION

    if st.button(
        "Start Investigation",
        type="primary",
        use_container_width=True,
    ):
        new_thread_id = f"incident-{uuid.uuid4()}"

        create_investigation(
            thread_id=new_thread_id,
            title=str(
                selected_incident.get(
                    "title",
                    "Security Investigation",
                )
            ),
            scenario=scenario,
            severity=str(
                selected_incident.get(
                    "severity_hint",
                    "medium",
                )
            ),
            status="Running",
        )

        st.session_state.thread_id = new_thread_id
        st.session_state.investigation_started = True

        initial_state: IncidentState = {
            "incident": selected_incident,
            "evidence": [],
            "decisions": [],
            "timeline": [],
        }

        config = {"configurable": {"thread_id": new_thread_id}}

        with st.status("Running investigation...", expanded=True) as progress:
            for update in incident_graph.stream(
                initial_state,
                config=config,
                stream_mode="updates",
            ):
                for node_name in update:
                    st.write(f"Completed stage: {node_name}")

            current_state = incident_graph.get_state(config)
            result = dict(current_state.values)

            if "human_approval" in current_state.next:
                progress.update(
                    label="Investigation paused for human approval",
                    state="complete",
                )
            else:
                progress.update(
                    label="Investigation completed",
                    state="complete",
                )

        update_investigation(
            new_thread_id,
            severity=result.get(
                "severity",
                selected_incident.get(
                    "severity_hint",
                    "medium",
                ),
            ),
            status="Awaiting Approval",
        )

        st.rerun()

    # RESET CURRENT INVESTIGATION

    if st.session_state.get("investigation_started"):
        st.divider()

        if st.button(
            "Reset Current Investigation",
            use_container_width=True,
        ):
            st.session_state.thread_id = None
            st.session_state.investigation_started = False
            st.rerun()


# ============================================================
# HOME SCREEN
# ============================================================

if not st.session_state.investigation_started:
    st.info(
        "Select a prebuilt simulated cybersecurity incident "
        "or create your own custom incident."
    )

    st.subheader("Available Incident Types")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown(
            """
🔐 **Authentication Attack**

🦠 **Malware Infection**

🎣 **Phishing Attempt**

🔒 **Ransomware Activity**
"""
        )

    with col2:
        st.markdown(
            """
📤 **Data Exfiltration**

🌐 **DDoS / Unusual Traffic**

👤 **Insider Threat**

💻 **Suspicious Endpoint Activity**
"""
        )

    st.divider()

    st.subheader("Investigation Workflow")

    st.code(
        incident_graph.get_graph().draw_mermaid(),
        language="mermaid",
    )


# ============================================================
# INVESTIGATION SCREEN
# ============================================================

else:
    # --------------------------------------------------------
    # GET LIVE STATE
    # --------------------------------------------------------

    current_state = get_current_state()

    if not current_state:
        st.error("The current investigation state could not be loaded.")

        st.stop()

    # --------------------------------------------------------
    # SOURCE OF TRUTH
    # --------------------------------------------------------

    result = dict(current_state.values)

    # --------------------------------------------------------
    # CHECK GRAPH STATUS
    # --------------------------------------------------------

    is_waiting_for_approval = "human_approval" in current_state.next

    is_completed = "final_report" in result

    # --------------------------------------------------------
    # STATUS
    # --------------------------------------------------------

    st.subheader("Investigation Status")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        severity_value = result.get(
            "severity",
            result.get("incident", {}).get(
                "severity_hint",
                "pending",
            ),
        )

        st.metric(
            "Severity",
            str(severity_value).upper(),
        )

    with col2:
        evidence_count = len(
            result.get(
                "evidence",
                [],
            )
        )

        st.metric(
            "Evidence",
            evidence_count,
        )

    with col3:
        if is_waiting_for_approval:
            approval_status = "Pending"

        elif result.get("containment_approved") is True:
            approval_status = "Approved"

        elif "containment_approved" in result:
            approval_status = "Rejected"

        else:
            approval_status = "Pending"

        st.metric(
            "Approval",
            approval_status,
        )

    with col4:
        if is_waiting_for_approval:
            workflow_status = "Paused"

        elif is_completed:
            workflow_status = "Completed"

        else:
            workflow_status = "Running"

        st.metric(
            "Status",
            workflow_status,
        )

    st.divider()

    # --------------------------------------------------------
    # INCIDENT DETAILS
    # --------------------------------------------------------

    incident = result.get(
        "incident",
        {},
    )

    st.subheader("📌 Incident Details")

    st.write(f"**Scenario:** {incident.get('scenario', 'Custom')}")

    st.write(f"**Title:** {incident.get('title', 'Unknown')}")

    st.write(f"**Description:** {incident.get('description', 'Not available')}")

    # --------------------------------------------------------
    # AI ANALYSIS
    # --------------------------------------------------------

    st.subheader("🔎 AI Investigation Assessment")

    hypothesis = result.get(
        "hypothesis",
        "Analysis not completed.",
    )

    confidence = result.get("confidence")

    reasoning = result.get("reasoning")

    # --------------------------------------------------------
    # DETERMINE ANALYSIS SOURCE
    # --------------------------------------------------------

    analysis_source = None

    decisions = result.get(
        "decisions",
        [],
    )

    for decision in decisions:
        if decision.get("stage") == "analysis":
            analysis_source = decision.get("analysis_source")

    if analysis_source == "Ollama LLM":
        analysis_engine = "Ollama / Llama 3.1"

    elif analysis_source == "Rule-based fallback":
        analysis_engine = "Rule-based fallback"

    else:
        analysis_engine = "Not available"

    # --------------------------------------------------------
    # AI SUMMARY
    # --------------------------------------------------------

    st.info(hypothesis)

    # --------------------------------------------------------
    # AI METRICS
    # --------------------------------------------------------

    analysis_col1, analysis_col2 = st.columns(2)

    with analysis_col1:
        if confidence is not None:
            try:
                confidence_value = float(confidence)

                st.metric(
                    "AI Confidence",
                    f"{confidence_value:.0%}",
                )

            except (
                TypeError,
                ValueError,
            ):
                st.metric(
                    "AI Confidence",
                    "Unavailable",
                )

        else:
            st.metric(
                "AI Confidence",
                "Unavailable",
            )

    with analysis_col2:
        st.metric(
            "Analysis Engine",
            analysis_engine,
        )

    # --------------------------------------------------------
    # AI REASONING
    # --------------------------------------------------------

    if reasoning:
        with st.expander("View AI Reasoning"):
            st.write(reasoning)

    # --------------------------------------------------------
    # RESPONSE PLAN
    # --------------------------------------------------------

    st.subheader("🛡 Recommended Response")

    recommended_action = result.get(
        "recommended_action",
        "Response plan not available.",
    )

    st.warning(recommended_action)

    # --------------------------------------------------------
    # EVIDENCE
    # --------------------------------------------------------

    with st.expander("🔍 Evidence Collected"):
        evidence = result.get(
            "evidence",
            [],
        )

        if evidence:
            for index, item in enumerate(
                evidence,
                start=1,
            ):
                st.write(f"### Evidence {index}")

                st.json(item)

        else:
            st.write("No evidence collected.")

    # --------------------------------------------------------
    # DECISIONS
    # --------------------------------------------------------

    with st.expander("📋 Investigation Decisions"):
        if decisions:
            for index, decision in enumerate(
                decisions,
                start=1,
            ):
                st.write(f"### Decision {index}")

                st.json(decision)

        else:
            st.write("No decisions recorded.")

    # --------------------------------------------------------
    # TIMELINE
    # --------------------------------------------------------

    with st.expander("⏱ Investigation Timeline"):
        timeline = result.get(
            "timeline",
            [],
        )

        if timeline:
            for event in timeline:
                st.write(f"• {event}")

        else:
            st.write("No timeline events recorded.")

    # --------------------------------------------------------
    # HUMAN APPROVAL
    # --------------------------------------------------------

    if is_waiting_for_approval:
        st.divider()

        st.subheader("👤 Human Approval Required")

        # ----------------------------------------------------
        # READ ACTUAL INTERRUPT PAYLOAD
        # ----------------------------------------------------

        approval_request = None

        if current_state.tasks:
            for task in current_state.tasks:
                interrupts = getattr(
                    task,
                    "interrupts",
                    [],
                )

                if interrupts:
                    approval_request = interrupts[0].value

                    break

        # ----------------------------------------------------
        # DISPLAY APPROVAL REQUEST
        # ----------------------------------------------------

        if approval_request:
            st.info(
                approval_request.get(
                    "message",
                    "Human approval is required.",
                )
            )

            approval_col1, approval_col2 = st.columns(2)

            with approval_col1:
                st.write("**Severity**")

                st.write(
                    str(
                        approval_request.get(
                            "severity",
                            severity_value,
                        )
                    ).upper()
                )

            with approval_col2:
                approval_confidence = approval_request.get("confidence")

                st.write("**AI Confidence**")

                if approval_confidence is not None:
                    try:
                        st.write(f"{float(approval_confidence):.0%}")

                    except (
                        TypeError,
                        ValueError,
                    ):
                        st.write("Unavailable")

                else:
                    st.write("Unavailable")

            st.write("**AI Assessment:**")

            st.write(
                approval_request.get(
                    "hypothesis",
                    hypothesis,
                )
            )

            st.write("**Proposed Action:**")

            st.warning(
                approval_request.get(
                    "recommended_action",
                    recommended_action,
                )
            )

            approval_reasoning = approval_request.get("reasoning")

            if approval_reasoning:
                with st.expander("View Analysis Reasoning"):
                    st.write(approval_reasoning)

        else:
            st.info(
                "The investigation is paused. Review the "
                "assessment and recommended containment."
            )

        # ----------------------------------------------------
        # DECISION COMMENT
        # ----------------------------------------------------

        comment = st.text_area(
            "Decision comment",
            placeholder=("Explain why you approved or rejected the containment..."),
        )

        approve_col, reject_col = st.columns(2)

        # ----------------------------------------------------
        # APPROVE
        # ----------------------------------------------------

        with approve_col:
            if st.button(
                "✅ Approve Containment",
                use_container_width=True,
            ):
                resume_investigation(
                    approved=True,
                    comment=comment,
                )

        # ----------------------------------------------------
        # REJECT
        # ----------------------------------------------------

        with reject_col:
            if st.button(
                "❌ Reject Containment",
                use_container_width=True,
            ):
                resume_investigation(
                    approved=False,
                    comment=comment,
                )

    # --------------------------------------------------------
    # FINAL INCIDENT REPORT
    # --------------------------------------------------------

    if is_completed:
        st.divider()

        st.subheader("📄 Final Incident Report")

        final_report = result.get(
            "final_report",
            "",
        )

        if final_report:
            st.code(
                final_report,
                language="text",
            )

            report_title = str(
                incident.get(
                    "title",
                    "incident-report",
                )
            )
            report_filename = (
                re.sub(
                    r"[^a-zA-Z0-9]+",
                    "-",
                    report_title,
                )
                .strip("-")
                .lower()
                or "incident-report"
            )

            st.download_button(
                "Download Report",
                data=final_report,
                file_name=f"{report_filename}.md",
                mime="text/markdown",
                use_container_width=True,
            )

        else:
            st.warning("The investigation completed, but no final report was found.")
