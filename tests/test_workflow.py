import uuid

from langgraph.types import Command

from incident_agent import build_incident_graph


def test_workflow_pauses_for_human_approval():
    graph = build_incident_graph()

    incident = {
        "type": "Phishing",
        "severity_hint": "High",
        "description": "User received a suspicious phishing email",
        "logs": [
            "Suspicious email received",
            "User clicked an external link",
            "Credentials entered on suspicious website",
        ],
    }

    config = {"configurable": {"thread_id": "test-phishing-approval-v2"}}

    result = graph.invoke(
        {
            "incident": incident,
        },
        config,
    )

    state = graph.get_state(config)

    assert "human_approval" in state.next
    assert result is not None

    evidence = state.values.get(
        "evidence",
        [],
    )

    decisions = state.values.get(
        "decisions",
        [],
    )

    assert evidence
    assert decisions

    for item in evidence:
        assert "timestamp" in item

    for decision in decisions:
        assert "timestamp" in decision


def test_workflow_resumes_after_rejection():
    graph = build_incident_graph()

    config = {"configurable": {"thread_id": f"test-phishing-rejection-{uuid.uuid4()}"}}

    graph.invoke(
        {
            "incident": {
                "title": "Rejected Containment Test",
                "severity_hint": "Medium",
                "logs": ["Suspicious email reported"],
            }
        },
        config,
    )

    state_before_resume = graph.get_state(config)

    assert "human_approval" in state_before_resume.next

    graph.invoke(
        Command(
            resume={
                "approved": False,
                "comment": "Containment requires additional review.",
            }
        ),
        config,
    )

    final_state = graph.get_state(config)

    assert final_state.next == ()
    assert "final_report" in final_state.values
    assert final_state.values["containment_approved"] is False
    assert "NOT EXECUTED" in final_state.values["containment_result"]

    decision_stages = {
        decision["stage"] for decision in final_state.values["decisions"]
    }

    assert "document_only" in decision_stages
    assert "containment" not in decision_stages


def test_workflow_resumes_after_approval():
    graph = build_incident_graph()

    incident = {
        "type": "Phishing",
        "severity_hint": "High",
        "description": "User received a suspicious phishing email",
        "logs": [
            "Suspicious email received",
            "User clicked an external link",
            "Credentials entered on suspicious website",
        ],
    }

    config = {"configurable": {"thread_id": "test-phishing-resume-v2"}}

    graph.invoke(
        {
            "incident": incident,
        },
        config,
    )

    state_before_resume = graph.get_state(config)

    assert "human_approval" in state_before_resume.next

    graph.invoke(
        Command(
            resume={
                "approved": True,
                "comment": "Approved for simulated containment.",
            }
        ),
        config,
    )

    final_state = graph.get_state(config)

    assert final_state.next == ()
    assert "final_report" in final_state.values
    assert final_state.values["containment_approved"] is True

    decisions = final_state.values.get(
        "decisions",
        [],
    )

    assert decisions

    for decision in decisions:
        assert "timestamp" in decision
