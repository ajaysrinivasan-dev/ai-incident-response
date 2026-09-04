import uuid

import streamlit as st
from langgraph.types import Command

from incident_agent import incident_graph
from checkpoint_manager import (
    get_saved_threads,
    checkpoint_database_exists,
)


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="Incident Response Agent",
    page_icon="🚨",
    layout="wide",
)


# ============================================================
# PREBUILT INCIDENT SCENARIOS
# ============================================================

INCIDENT_SCENARIOS = {
    "Suspicious Authentication / Brute Force": {
        "title": "Suspicious Authentication Activity",
        "severity": "high",
        "description": (
            "Multiple failed login attempts were detected "
            "followed by a successful authentication."
        ),
        "logs": [
            "Failed login from user account admin",
            "Failed login from user account admin",
            "Failed login from user account admin",
            "Failed login from user account admin",
            "Successful login after repeated failures",
        ],
    },
    "Malware Infection": {
        "title": "Possible Malware Infection",
        "severity": "high",
        "description": (
            "Suspicious processes and unusual endpoint activity were detected."
        ),
        "logs": [
            "Suspicious process detected on endpoint",
            "Unknown executable started",
            "Security alert triggered for unusual behavior",
            "Unusual outbound network connection detected",
        ],
    },
    "Phishing Attempt": {
        "title": "Possible Phishing Attack",
        "severity": "medium",
        "description": (
            "A user interacted with a suspicious email "
            "and unusual authentication activity followed."
        ),
        "logs": [
            "User received suspicious email",
            "User clicked external link in email",
            "Credentials entered on unrecognized page",
            "Unusual login detected from new location",
        ],
    },
    "Ransomware Activity": {
        "title": "Possible Ransomware Activity",
        "severity": "high",
        "description": (
            "Multiple files were rapidly modified and suspicious "
            "encryption-related activity was detected."
        ),
        "logs": [
            "Large number of files modified rapidly",
            "File extensions changed unexpectedly",
            "Suspicious encryption process detected",
            "Ransom note detected on endpoint",
        ],
    },
    "Data Exfiltration": {
        "title": "Possible Data Exfiltration",
        "severity": "high",
        "description": (
            "Unusually large outbound data transfers and access "
            "to sensitive information were detected."
        ),
        "logs": [
            "Large outbound data transfer detected",
            "Sensitive files accessed",
            "Connection established with unknown external server",
            "Unusual network activity detected",
        ],
    },
    "DDoS / Unusual Traffic": {
        "title": "Possible DDoS Attack",
        "severity": "high",
        "description": (
            "The system experienced an unusual volume of network "
            "traffic affecting availability."
        ),
        "logs": [
            "Sudden increase in inbound network requests",
            "Repeated requests from multiple external sources",
            "Server response time increased significantly",
            "Service availability degraded",
        ],
    },
    "Insider Threat": {
        "title": "Possible Insider Threat",
        "severity": "medium",
        "description": (
            "An internal user accessed unusual sensitive data "
            "and performed unexpected file activity."
        ),
        "logs": [
            "Employee accessed unusual sensitive files",
            "Access occurred outside normal working hours",
            "Large number of files copied",
            "Unusual removable media activity detected",
        ],
    },
    "Suspicious Endpoint Activity": {
        "title": "Suspicious Endpoint Activity",
        "severity": "medium",
        "description": (
            "The endpoint showed unusual process and network "
            "behavior requiring investigation."
        ),
        "logs": [
            "Unknown process started",
            "Process consumed unusually high resources",
            "Unexpected outbound connection detected",
            "Endpoint security alert generated",
        ],
    },
}


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

        st.rerun()

    except Exception as exc:
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

    saved_threads = get_saved_threads()

    # Build friendly labels for saved investigations
    saved_investigations = []

    if checkpoint_database_exists() and saved_threads:
        for thread_id in saved_threads:
            try:
                saved_config = {"configurable": {"thread_id": thread_id}}

                saved_state = incident_graph.get_state(saved_config)
                saved_values = saved_state.values or {}

                incident_data = saved_values.get("incident", {})
                incident_type = incident_data.get("type", "Unknown Incident")

                severity = saved_values.get("severity", "Not assessed")

                saved_investigations.append(
                    {
                        "thread_id": thread_id,
                        "incident_type": incident_type,
                        "severity": severity,
                    }
                )

            except Exception:
                continue

    if saved_investigations:
        saved_options = [
            (f"{item['incident_type']} ({item['severity'].upper()})")
            for item in saved_investigations
        ]

        selected_label = st.selectbox(
            "Select Investigation",
            saved_options,
            key="saved_investigation_selector",
        )

        selected_investigation = next(
            (
                item
                for item in saved_investigations
                if (f"{item['incident_type']} ({item['severity'].upper()})")
                == selected_label
            ),
            None,
        )

        if selected_investigation:
            if st.button(
                "Load Investigation",
                use_container_width=True,
            ):
                st.session_state.thread_id = selected_investigation["thread_id"]
                st.session_state.investigation_started = True
                st.rerun()

    else:
        st.caption("No saved investigations found.")

    st.divider()

    # NEW INVESTIGATION

    st.header("New Investigation")

    scenario_names = list(SCENARIOS.keys())

    scenario = st.selectbox(
        "Incident Scenario",
        scenario_names,
        key="scenario_selector",
    )

    # CUSTOM INCIDENT

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
        selected_incident = SCENARIOS[scenario]

        st.subheader("Selected Scenario")

        st.write(
            selected_incident.get(
                "description",
                "No description available.",
            )
        )

        st.caption(
            "Severity hint: "
            + selected_incident.get(
                "severity_hint",
                "unknown",
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

        st.session_state.thread_id = new_thread_id
        st.session_state.investigation_started = True

        initial_state = {
            "incident": selected_incident,
            "evidence": [],
            "decisions": [],
            "timeline": [],
        }

        config = {"configurable": {"thread_id": new_thread_id}}

        incident_graph.invoke(
            initial_state,
            config=config,
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
        """Incident Input
      ↓
Triage
      ↓
Evidence Collection
      ↓
AI Analysis
      ↓
Response Planning
      ↓
Human Approval
      ↓
Simulated Containment
      ↓
Final Report""",
        language="text",
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

        else:
            st.warning("The investigation completed, but no final report was found.")
