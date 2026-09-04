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

    config = {"configurable": {"thread_id": "test-phishing-approval"}}

    result = graph.invoke(
        {
            "incident": incident,
        },
        config,
    )

    state = graph.get_state(config)

    assert "human_approval" in state.next
    assert result is not None


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

    config = {"configurable": {"thread_id": "test-phishing-resume"}}

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
