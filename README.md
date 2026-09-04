# Incident Response Agent

A LangGraph-based simulated cybersecurity incident investigation system.

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
      |
      v
Simulated Containment
      |
      v
Final Report

## Human Approval

The investigation pauses after the response plan is created.

A human reviewer can:

* Approve the containment action
* Reject the containment action
* Add a decision comment

After approval or rejection, the LangGraph workflow resumes from the checkpoint and continues to the containment and reporting stages.

## Checkpointing

The project uses SQLite checkpointing to save investigation state.

This allows the system to:

* Preserve investigation progress
* Store graph state
* Resume interrupted investigations
* Continue from the human approval stage

The checkpoint database is stored locally as:

incident_checkpoints.db

## Project Structure

langgraph_pro/
│
├── app.py
├── incident_agent.py
├── nodes.py
├── state.py
├── checkpoint_manager.py
├── requirements.txt
├── README.md
└── incident_checkpoints.db


## Technologies Used

* Python
* Streamlit
* LangGraph
* SQLite
* LangChain

## Installation

Install the required dependencies:

bash
pip install -r requirements.txt

## Running the Application

Start the Streamlit application:

bash
streamlit run app.py

The application will open in your browser.

## How It Works

1. Select a prebuilt incident scenario or create a custom incident.
2. Start the investigation.
3. The system performs triage and collects evidence.
4. The evidence is analyzed.
5. A recommended response is generated.
6. The workflow pauses for human approval.
7. The human reviewer approves or rejects containment.
8. The workflow resumes from the saved checkpoint.
9. Simulated containment is performed.
10. A final incident response report is generated.

## Simulated Environment

This project is designed for demonstration and educational purposes.

All cybersecurity incidents, evidence, containment actions, and responses are simulated.

The application does not perform real security monitoring, system isolation, network blocking, or other actions on actual systems.

## Purpose

The purpose of this project is to demonstrate a stateful AI workflow using LangGraph.

The project shows how LangGraph can be used to build an incident response workflow with:

* Multiple processing stages
* Shared graph state
* Human-in-the-loop approval
* Workflow interruption and resumption
* Persistent checkpointing
* Final report generation
