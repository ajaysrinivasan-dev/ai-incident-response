from nodes import (
    analyze_incident,
    collect_evidence,
    plan_response,
    triage_incident,
)


def test_triage_incident():
    state = {
        "incident": {
            "severity_hint": "High",
            "description": "Suspicious login detected",
        }
    }

    result = triage_incident(state)

    assert result["severity"] == "high"
    assert "triage" in result["timeline"][0].lower()

    evidence = result["evidence"][0]
    decision = result["decisions"][0]

    assert "timestamp" in evidence
    assert "timestamp" in decision

    assert evidence["source"] == "triage"
    assert evidence["type"] == "initial_assessment"

    assert decision["stage"] == "triage"


def test_collect_evidence():
    state = {
        "incident": {
            "severity_hint": "High",
            "description": "Suspicious login detected",
            "logs": [
                "Failed login attempt",
                "Successful login from unknown location",
            ],
        }
    }

    result = collect_evidence(state)

    assert "evidence" in result
    assert len(result["evidence"]) == 2

    first_evidence = result["evidence"][0]
    second_evidence = result["evidence"][1]

    assert isinstance(first_evidence, dict)
    assert isinstance(second_evidence, dict)

    assert "type" in first_evidence
    assert "source" in first_evidence
    assert "timestamp" in first_evidence

    assert first_evidence["source"] == "simulated_log_1"
    assert second_evidence["source"] == "simulated_log_2"

    assert first_evidence["type"] == "log"
    assert second_evidence["type"] == "log"

    decision = result["decisions"][0]

    assert "timestamp" in decision
    assert decision["stage"] == "evidence_collection"


def test_analyze_incident_fallback():
    state = {
        "incident": {
            "severity_hint": "High",
            "description": "Possible unauthorized account access",
        },
        "evidence": [
            {
                "type": "log",
                "value": (
                    "Multiple failed login attempts "
                    "followed by successful login"
                ),
            }
        ],
    }

    result = analyze_incident(state)

    assert "hypothesis" in result
    assert "confidence" in result
    assert "reasoning" in result

    assert isinstance(result["hypothesis"], str)
    assert isinstance(result["confidence"], float)
    assert 0.0 <= result["confidence"] <= 1.0

    decision = result["decisions"][0]

    assert "timestamp" in decision
    assert decision["stage"] == "analysis"
    assert "analysis_source" in decision
    assert "confidence" in decision


def test_plan_response():
    state = {
        "incident": {
            "severity_hint": "Critical",
            "description": "Critical security incident",
        },
        "severity": "critical",
        "hypothesis": "Ransomware attack",
        "confidence": 0.9,
        "reasoning": "Suspicious encryption activity detected.",
    }

    result = plan_response(state)

    assert "recommended_action" in result
    assert isinstance(result["recommended_action"], str)
    assert len(result["recommended_action"]) > 0

    decision = result["decisions"][0]

    assert "timestamp" in decision
    assert decision["stage"] == "response_planning"
    assert decision["severity"] == "critical"
