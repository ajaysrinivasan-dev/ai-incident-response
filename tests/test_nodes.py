import pytest

from nodes import (
    analyze_incident,
    collect_evidence,
    containment,
    generate_report,
    plan_response,
    reassess_severity,
    request_approval,
    triage_incident,
)
from state import IncidentState


@pytest.fixture
def force_fallback(monkeypatch):
    def unavailable(*args, **kwargs):
        raise ConnectionError("Ollama unavailable for deterministic test")

    monkeypatch.setattr("nodes._analyze_with_ollama", unavailable)


def test_triage_incident():
    state: IncidentState = {
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
    state: IncidentState = {
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


def test_analyze_incident_fallback(force_fallback):
    state: IncidentState = {
        "incident": {
            "severity_hint": "High",
            "description": "Possible unauthorized account access",
        },
        "evidence": [
            {
                "type": "log",
                "value": (
                    "Multiple failed login attempts followed by successful login"
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


@pytest.mark.parametrize(
    ("details", "expected"),
    [
        (
            "Failed login followed by successful login",
            "unauthorized account access",
        ),
        ("Suspicious process detected", "malware infection"),
        ("Suspicious email reported", "phishing attempt"),
        ("Ransomware encrypted files", "ransomware activity"),
        ("Large data transfer detected", "data exfiltration"),
        ("Unusual traffic detected", "denial-of-service"),
        ("Privileged user activity detected", "insider threat"),
    ],
)
def test_analyze_incident_fallback_categories(details, expected, force_fallback):
    result = analyze_incident(
        {
            "incident": {},
            "evidence": [{"details": details}],
        }
    )

    assert expected in result["hypothesis"].lower()


def test_analyze_incident_fallback_for_unknown_evidence(force_fallback):
    result = analyze_incident(
        {
            "incident": {},
            "evidence": [{"details": "Routine maintenance completed"}],
        }
    )

    assert "insufficient evidence" in result["hypothesis"].lower()


def test_severity_reassessment_escalates_compromised_credentials():
    result = reassess_severity(
        {
            "incident": {},
            "initial_severity": "high",
            "severity": "high",
            "evidence": [{"details": "Credentials compromised after malicious link"}],
        }
    )

    assert result["severity"] == "critical"
    assert "credential compromise" in result["severity_reassessment_reason"].lower()


def test_phishing_indicators_trigger_severity_escalation():
    result = reassess_severity(
        {
            "initial_severity": "high",
            "evidence": [
                {"details": "User clicked suspicious link"},
                {"details": "Credentials entered on unrecognized page"},
            ],
        }
    )

    assert result["severity"] == "critical"


def test_severity_reassessment_preserves_severity_without_strong_indicators():
    result = reassess_severity(
        {
            "incident": {},
            "initial_severity": "high",
            "severity": "high",
            "evidence": [{"details": "Suspicious email reported"}],
        }
    )

    assert result["severity"] == "high"
    assert "did not meet" in result["severity_reassessment_reason"]


def test_analysis_maps_evidence_to_mitre_techniques(force_fallback):
    result = analyze_incident(
        {
            "incident": {"type": "Phishing"},
            "evidence": [
                {"details": "Failed login after suspicious email and malicious link"}
            ],
        }
    )

    technique_ids = {technique["id"] for technique in result["mitre_techniques"]}

    assert "T1110" in technique_ids
    assert "T1566" in technique_ids


def test_plan_response():
    state: IncidentState = {
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


def test_containment_executes_after_approval():
    result = containment({"containment_approved": True})

    assert "SIMULATED CONTAINMENT" in result["containment_result"]


def test_generate_report_handles_minimal_state():
    result = generate_report({})

    assert isinstance(result["final_report"], str)
    assert result["final_report"]


@pytest.mark.parametrize("invalid_approval", [None, "true", "false", 1, 0])
def test_request_approval_rejects_invalid_response(
    monkeypatch,
    invalid_approval,
):
    monkeypatch.setattr(
        "nodes.interrupt",
        lambda _: {"approved": invalid_approval},
    )

    try:
        request_approval({})
    except ValueError as exc:
        assert str(exc) == ("Human approval response must contain a boolean approval.")
    else:
        raise AssertionError("Expected invalid approval response to fail.")
