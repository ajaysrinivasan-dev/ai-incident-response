# Incident Response Agent

A LangGraph-based simulated cybersecurity incident investigation system with
Ollama-powered analysis and a deterministic offline fallback.

The application demonstrates how an incident can move through multiple investigation stages while maintaining state, supporting human approval, and allowing interrupted investigations to be resumed using persistent checkpointing.

## Features

* Multiple prebuilt incident scenarios
* Custom incident input
* Incident triage
* Evidence collection
* Incident analysis
* Response planning
* Human approval before containment
* Simulated containment actions
* Final incident report generation
* Persistent SQLite checkpointing
* Resume previous investigations
* Investigation evidence and decisions stored in graph state
* Saved investigation metadata with archive and delete actions
* Markdown report export from completed investigations
* Live compiled LangGraph topology display
* Initial workflow progress streaming in the Streamlit interface
* Evidence-based severity reassessment
* MITRE ATT&CK technique mapping for supported indicators
* Explicit approval and document-only rejection branches

## Incident Scenarios

The application includes the following simulated scenarios:

* Suspicious Authentication / Brute Force
* Malware Infection
* Phishing Attempt
* Ransomware Activity
* Data Exfiltration
* DDoS / Unusual Traffic
* Insider Threat
* Suspicious Endpoint Activity
* Custom Incident

## Workflow

Incident Input
      |
      v
Triage
      |
      v
Evidence Collection
      |
      v
Analysis
      |
      v
Response Planning
      |
      v
Human Approval
   /        \\
  v          v
Approved   Rejected
  |          |
  v          v
Containment Document Only
   \        /
      v
Final Report

## Human Approval

The investigation pauses after the response plan is created.

A human reviewer can:

* Approve the containment action
* Reject the containment action
* Add a decision comment

After approval or rejection, the LangGraph workflow resumes from the checkpoint.
Approval routes to simulated containment. Rejection routes directly to a
document-only stage, records the analyst comment, and skips containment.

## Checkpointing

The project uses SQLite checkpointing to save investigation state.

This allows the system to:

* Preserve investigation progress
* Store graph state
* Resume interrupted investigations
* Continue from the human approval stage

The checkpoint database is stored locally as:

incident_checkpoints.db

Set `INCIDENT_CHECKPOINT_DB` to use a different database path.

## Project Structure

langgraph_pro/
│
├── app.py
├── incident_agent.py
├── nodes.py
├── state.py
├── checkpoint_manager.py
├── config.py
├── requirements.txt
├── pyproject.toml
├── tests/
├── data/
├── README.md
└── .gitignore


## Technologies Used

* Python
* Streamlit
* LangGraph
* SQLite
* Ollama

## Configuration

The application supports these environment variables:

* `INCIDENT_CHECKPOINT_DB`: SQLite database path. The default is
      `incident_checkpoints.db` in the project directory.
* `OLLAMA_HOST`: Ollama server address used by the Ollama client. For a
      container connecting to Ollama on the host, use the Docker host address
      appropriate for your operating system, commonly `http://host.docker.internal:11434`.
* `OLLAMA_MODEL`: Ollama model name. Defaults to `llama3.1`.

Custom incident input is limited to 200 characters for the title, 4,000
characters for the description, 100 log entries, and 2,000 characters per log
entry. The Ollama prompt applies the same bounds for direct graph callers.

Ollama is intentionally not installed or started inside the application
container.

## Prerequisites

* Python 3.14
* Ollama installed and running locally
* The `llama3.1` model available in Ollama

Pull the model before starting the application:

```bash
ollama pull llama3.1
```

## Installation

Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Running the Application

Start the Streamlit application:

```bash
streamlit run app.py
```

The application will open in your browser.

Run the tests with:

```bash
python -m pytest
```

Run Ruff and mypy with:

```bash
python -m ruff check .
python -m ruff format --check .
python -m mypy
```

## Docker

Build the application image:

```bash
docker build -t langgraph-incident-response .
```

Run it with a persistent SQLite directory and an external Ollama server:

```bash
docker run --rm -p 8501:8501 \
      -v "$(pwd)/runtime-data:/app/runtime-data" \
      -e INCIDENT_CHECKPOINT_DB=/app/runtime-data/incident_checkpoints.db \
      -e OLLAMA_HOST=http://host.docker.internal:11434 \
      langgraph-incident-response
```

The container does not include an Ollama server. Ollama must be running on the
host or another reachable machine, with `llama3.1` pulled there. The mounted
directory keeps investigation checkpoints outside the disposable container.

## Continuous Integration

GitHub Actions runs on pushes and pull requests. The CI workflow installs the
pinned dependencies and runs pytest, Ruff linting, Ruff formatting checks, and
mypy.


## How It Works

1. Select a prebuilt incident scenario or create a custom incident.
2. Start the investigation.
3. The system performs triage and collects evidence.
4. The evidence is analyzed.
5. A recommended response is generated.
6. The workflow pauses for human approval.
7. The human reviewer approves or rejects containment.
8. The workflow resumes from the saved checkpoint.
9. Approved investigations perform simulated containment; rejected investigations use the document-only branch.
10. A final incident response report is generated.

Completed reports can be downloaded as Markdown files from the investigation
screen. During initial execution, the UI streams completed graph stages until
the workflow pauses for human approval.

## Simulated Environment

This project is designed for demonstration and educational purposes.

All cybersecurity incidents, evidence, containment actions, and responses are simulated.

The application does not perform real security monitoring, system isolation, network blocking, or other actions on actual systems.

Ollama is used only to analyze the simulated incident data. If Ollama is
unavailable or returns an invalid response, the application uses deterministic
rule-based fallback analysis.

## Troubleshooting

If analysis always uses the fallback, check that Ollama is running and that
`llama3.1` has been pulled. If an investigation cannot be resumed, verify that
the configured SQLite database path is writable and that the original
checkpoint database is still present.

## Purpose

The purpose of this project is to demonstrate a stateful AI workflow using LangGraph.

The project shows how LangGraph can be used to build an incident response workflow with:

* Multiple processing stages
* Shared graph state
* Human-in-the-loop approval
* Workflow interruption and resumption
* Persistent checkpointing
* Final report generation
