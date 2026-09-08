# SilentEye DFIR Console

**A lightweight Windows DFIR and threat-hunting console powered by osquery, with heuristic triage scoring, hunt-contextual timelines, evidence export, and local analyst-assistance workflows.**

SilentEye helps analysts move from raw endpoint telemetry to prioritized investigation without requiring a full enterprise SIEM or EDR platform.

---

## 🔥 Overview

SilentEye is an interactive terminal-based DFIR console designed for Windows investigations.

It combines:

- 🔎 **osquery** for endpoint artifact collection
- 🖥️ **Textual** for an interactive terminal user interface
- 📊 **Custom heuristic scoring** for triage prioritization
- 🕒 **Contextual timeline pivots** for investigation support
- 🧠 **Local Analyst Assist** for deterministic investigation guidance
- 📦 **CSV and JSON exports** for evidence preservation and reporting

SilentEye is intended for:

- SOC analysts
- Incident responders
- Threat hunters
- DFIR students
- Security engineers
- Home-lab investigations

<img width="1538" height="826" alt="SilentEye DFIR Console" src="https://github.com/user-attachments/assets/58ca4bc7-3d8c-4785-86cc-402cc14e13ce" />

---

# 🚀 Key Features

## 🔎 DFIR Hunting

SilentEye includes pre-built osquery hunts for common Windows investigation areas:

- Startup Items
- Scheduled Tasks
- Services
- WMI Persistence
- Listening Ports
- Registry Discovery
- PowerShell Activity
- Recent Files
- UserAssist
- Shimcache
- Drivers
- Context Timeline

The built-in hunts focus on artifacts commonly associated with:

- Persistence
- User execution
- Suspicious scripting
- Unusual service configuration
- Scheduled task abuse
- WMI persistence
- Network listeners
- Driver anomalies
- Registry-based persistence
- PowerShell activity

SilentEye also allows analysts to edit or run custom osquery SQL directly from the interface.

---

## 📊 Heuristic Triage Scoring

SilentEye automatically enriches supported hunt results with a local heuristic score.

Each result can include:

- **Triage Priority:** Low / Medium / High
- **Triage Score:** 0–100
- **Detection reasoning**
- **Recommended analyst action**

Example:

```text
Triage Priority: High
Triage Score: 85
Recommended Action: Contain / Investigate

Reasons:
- task is hidden
- task action uses common LOLBin or script interpreter
- task references unusual path or execution target
```

The score is designed to help analysts prioritize investigation.

> **A High triage score does not automatically mean an artifact is malicious.**

SilentEye highlights conditions that deserve analyst review and correlation with additional evidence.

---

## 🕒 Hunt-Contextual Timeline

Press:

```text
Ctrl+T
```

to pivot from the current hunt into a related timeline view.

SilentEye can combine investigation context from artifacts such as:

- UserAssist
- Shimcache
- Registry Run keys
- RunOnce keys
- Image File Execution Options
- Services
- Scheduled Tasks
- WMI consumers
- PowerShell activity

Timeline behavior changes depending on the hunt being investigated.

### Example: Services

```text
Services
   ↓
Ctrl+T
   ↓
Service + Registry Service Context
```

### Example: Scheduled Tasks

```text
Scheduled Tasks
   ↓
Ctrl+T
   ↓
Scheduled Task + Registry Persistence Context
```

### Example: PowerShell

```text
PowerShell Activity
   ↓
Ctrl+T
   ↓
PowerShell + Registry Run-Key Context
```

The current implementation is **hunt-contextual**.

It builds context around the active investigation category rather than generating a timeline around one individually selected artifact.

<img width="1406" height="825" alt="SilentEye Context Timeline" src="https://github.com/user-attachments/assets/ee5075c0-96cf-40fb-a53e-6aff516c0e55" />

---

## 🧠 Local Analyst Assist

Select a result and press:

```text
F6
```

to open **Analyst Assist**.

Analyst Assist produces a local, deterministic investigation summary based on SilentEye's triage logic and the evidence contained in the selected row.

It provides:

- Analyst assessment
- Triage priority
- Triage score
- Detection reasoning
- Key indicators
- Recommended next steps
- Evidence snapshot
- Suggested finding write-up

### Analyst Assist Workflow

```text
osquery Result
      ↓
SilentEye Scoring
      ↓
Triage Priority
      ↓
Analyst Assist
      ↓
Investigation Guidance
      ↓
Evidence Collection
```

Analyst Assist is **not currently backed by an LLM**.

It does not send endpoint evidence to an external AI service.

The current analysis workflow remains entirely local.

<img width="1617" height="808" alt="SilentEye Analyst Assist" src="https://github.com/user-attachments/assets/53adc0a2-46c6-428e-8de4-e07fae6bd29b" />

---

## 📦 Evidence Export

SilentEye can export investigation results for additional analysis, documentation, or reporting.

### Export All Results

```text
Ctrl+E
```

### Export High-Priority Results Only

```text
Ctrl+Shift+E
```

Exports are generated in:

```text
./exports/
```

Supported formats:

- JSON
- CSV

Files are timestamped and named according to the active investigation.

Example:

```text
exports/
├── Scheduled_Tasks_all_20260908_143522.json
├── Scheduled_Tasks_all_20260908_143522.csv
├── Scheduled_Tasks_high_20260908_143610.json
└── Scheduled_Tasks_high_20260908_143610.csv
```

<img width="815" height="353" alt="SilentEye Exports" src="https://github.com/user-attachments/assets/7c4ca082-b319-43f7-a13f-16ecdd514798" />

---

## 🔍 Row Inspection and Clipboard Support

SilentEye allows analysts to inspect complete artifact details without relying only on the visible table columns.

| Action | Shortcut |
|---|---|
| Run Query | `Ctrl+Enter`, `Ctrl+R`, or `F5` |
| Inspect Row | `Enter` or `I` |
| Copy Row | `C` |
| Copy Cell | `Y` |
| Analyst Assist | `F6` |
| Context Timeline | `Ctrl+T` |
| Export All | `Ctrl+E` |
| Export High Priority | `Ctrl+Shift+E` |

---

# 🔄 Investigation Workflow

SilentEye is designed around a straightforward DFIR workflow:

```text
Collect
   ↓
Hunt
   ↓
Prioritize
   ↓
Inspect
   ↓
Correlate
   ↓
Build Context
   ↓
Export Evidence
   ↓
Respond
```

A typical investigation may look like:

```text
Suspicious Endpoint
      ↓
Run Scheduled Tasks Hunt
      ↓
Review High-Priority Results
      ↓
Inspect Suspicious Task
      ↓
Use Analyst Assist
      ↓
Pivot to Context Timeline
      ↓
Review Neighboring Artifacts
      ↓
Export Findings
      ↓
Continue Investigation / Containment
```

---

# 🛠️ Installation

## Requirements

SilentEye currently targets **Windows** systems.

Required components:

- Windows 10 / 11 or Windows Server
- Python 3.10+
- osquery
- Textual

Some DFIR artifacts require an elevated PowerShell session for complete visibility.

---

## Option 1: Automated Setup

Clone the repository:

```powershell
git clone https://github.com/garciarubenjr/SilentEye-DFIR-Console.git
cd SilentEye-DFIR-Console
```

Run PowerShell as Administrator:

```powershell
.\install.ps1
```

The installer will:

- Validate Windows
- Detect Python 3.10+
- Create an isolated `.venv`
- Install dependencies from `requirements.txt`
- Detect osquery
- Validate osquery execution
- Create the `exports` directory
- Validate the Textual dependency
- Compile `silenteye.py` to check for Python syntax errors

The installer intentionally **does not silently download or execute Python or osquery installers**.

If either dependency is missing, the installer will stop and provide installation guidance.

---

## Rebuild the Virtual Environment

If the Python environment needs to be recreated:

```powershell
.\install.ps1 -RebuildVenv
```

---

## Skip osquery Validation

For development or interface testing:

```powershell
.\install.ps1 -SkipOsqueryCheck
```

> SilentEye still requires osquery for real DFIR hunts.

---

# 🔧 Manual Installation

## 1. Install Python

Install Python 3.10 or newer:

[Python Downloads](https://www.python.org/downloads/)

Verify:

```powershell
python --version
```

---

## 2. Create a Virtual Environment

```powershell
python -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

---

## 3. Install Dependencies

```powershell
python -m pip install -r requirements.txt
```

Current Python dependency:

```text
textual
```

---

## 4. Install osquery

Install osquery from:

[osquery Downloads](https://osquery.io/downloads/)

Verify:

```powershell
osqueryi --version
```

SilentEye checks for osquery in:

```text
PATH
C:\Program Files\osquery\osqueryi.exe
C:\ProgramData\chocolatey\bin\osqueryi.exe
```

---

# ▶️ Running SilentEye

If using the automated installer:

```powershell
.\.venv\Scripts\python.exe .\silenteye.py
```

Or activate the virtual environment first:

```powershell
.\.venv\Scripts\Activate.ps1
python .\silenteye.py
```

For the most complete Windows artifact visibility, launch PowerShell as Administrator before running SilentEye.

---

# 🧪 Usage Guide

## Run a Hunt

Select a hunt from the left panel.

Run it with:

```text
Ctrl+Enter
```

or:

```text
Ctrl+R
```

or:

```text
F5
```

You can also click:

```text
Run Query
```

---

## Inspect a Result

Select a result and press:

```text
Enter
```

or:

```text
I
```

SilentEye opens a detailed view containing the available fields for that artifact.

---

## Copy Evidence

Copy an entire selected row:

```text
C
```

Copy the selected cell:

```text
Y
```

---

## Analyst Assist

Select an artifact and press:

```text
F6
```

The local Analyst Assist view provides investigation guidance based on the artifact and its triage score.

---

## Context Timeline

Press:

```text
Ctrl+T
```

SilentEye builds a related timeline based on the current hunt context.

---

## Export Results

Export all findings:

```text
Ctrl+E
```

Export only High-priority findings:

```text
Ctrl+Shift+E
```

---

# 🛡️ osquery Execution Safety

SilentEye executes osquery with:

```text
shell=False
```

and places a timeout on each query.

The default query timeout is:

```text
45 seconds
```

This prevents a single slow or problematic query from running indefinitely.

---

# 📊 Triage Philosophy

SilentEye intentionally separates **suspicious** from **confirmed malicious**.

An artifact may receive a higher triage score because it contains characteristics such as:

- User-writable execution paths
- Script execution
- LOLBin usage
- Hidden scheduled tasks
- Unsigned drivers
- Suspicious PowerShell content
- WMI persistence
- Unusual service locations
- Suspicious listening ports

These indicators should trigger investigation—not automatic conclusions.

The preferred workflow is:

```text
Indicator
   ↓
Triage
   ↓
Analyst Review
   ↓
Correlation
   ↓
Evidence
   ↓
Decision
```

---

# 🔐 DFIR Best Practices

SilentEye is designed for investigation and evidence-driven response.

Avoid immediately:

- Killing suspicious processes
- Deleting suspicious files
- Removing persistence mechanisms
- Modifying artifacts before evidence is collected

Prefer:

- Record the finding
- Inspect the artifact
- Preserve relevant evidence
- Export investigation results
- Build timeline context
- Correlate with additional telemetry
- Determine scope
- Contain only when justified

---

# ⚠️ Known Limitations

## Administrator Privileges

Some Windows artifacts and registry locations require Administrator privileges.

Running SilentEye without elevation may result in incomplete visibility.

---

## Evented Tables

Some osquery tables depend on Windows logging configuration.

For example:

```text
powershell_events
```

may require PowerShell Script Block Logging and appropriate eventing support.

---

## osquery Table Availability

osquery table availability may vary depending on:

- osquery version
- Windows version
- System configuration
- Logging configuration
- Privilege level

SilentEye attempts to provide hints when certain tables are unavailable.

---

## Timeline Context

The current timeline system pivots based on the active hunt category.

It does not yet build a timeline around one exact selected artifact.

---

## Heuristic Scoring

SilentEye's scoring engine is rule-based.

Scores are designed for analyst prioritization and should not be interpreted as proof of compromise.

---

## Query Execution

osquery currently runs synchronously from the application.

A 45-second timeout is used to prevent indefinite execution.

Future versions may move query execution to background workers to keep the TUI fully responsive during longer hunts.

---

# 📁 Project Structure

```text
SilentEye-DFIR-Console/
├── silenteye.py
├── install.ps1
├── requirements.txt
├── README.md
│
├── exports/
│   ├── *.json
│   └── *.csv
│
└── .venv/
```

The `.venv/` and `exports/` directories are generated locally and should not be committed to the repository.

---

# 🧰 Technology Stack

| Component | Purpose |
|---|---|
| Python | Application logic |
| Textual | Terminal user interface |
| osquery | Windows endpoint telemetry |
| PowerShell | Installation workflow |
| JSON | Evidence export |
| CSV | Evidence export |

SilentEye currently uses only one third-party Python package:

```text
textual
```

---

# 🧭 Roadmap

Planned improvements include:

- [ ] Selected-artifact timeline correlation
- [ ] Background osquery workers
- [ ] Enhanced scoring and false-positive suppression
- [ ] Additional Windows artifacts
- [ ] Cross-hunt correlation engine
- [ ] Evidence hashing
- [ ] Case-based export structure
- [ ] One-click investigation report generation
- [ ] Optional LLM-backed analysis
- [ ] Multi-host analysis
- [ ] Configuration-based scoring rules
- [ ] Automated testing

Any future LLM integration should remain optional so analysts can continue using SilentEye entirely locally.

---

# ⭐ Use Cases

SilentEye can be used for:

- SOC triage
- Endpoint investigation
- Incident response
- Threat hunting
- Windows persistence analysis
- DFIR training
- Security research
- Home-lab investigations
- Analyst workflow development
- Cybersecurity portfolio demonstration

---

# 🔒 Security and Privacy

The current version of SilentEye does not require a cloud service or external AI model.

Artifact analysis, scoring, timeline generation, and Analyst Assist are performed locally.

Exported evidence remains on the analyst's system unless the analyst intentionally transfers it elsewhere.

---

# ⚠️ Disclaimer

SilentEye is intended for:

- Authorized security investigations
- Educational environments
- DFIR laboratories
- Systems you own or have explicit permission to analyze

Do not use SilentEye to access or investigate systems without authorization.

Analysts remain responsible for validating findings before taking containment or remediation actions.

---

# 👤 Author

**Ruben Garcia Jr.**

Cybersecurity | Penetration Testing | Wireless Security | Security Engineering

GitHub: [@garciarubenjr](https://github.com/garciarubenjr)

---

# 💡 Project Philosophy

SilentEye was built to help bridge the gap between:

```text
Raw Endpoint Telemetry
        ↓
Investigation Context
        ↓
Triage Prioritization
        ↓
Analyst Decision-Making
```

The goal is not to replace the analyst.

The goal is to help the analyst identify what deserves attention, understand why it matters, preserve useful evidence, and move through a Windows DFIR investigation more efficiently.

---

## 🚀 Support the Project

If SilentEye is useful to you:

- ⭐ Star the repository
- 🍴 Fork it for your own DFIR lab
- 🐛 Open an issue with feedback
- 🛠️ Contribute improvements

---

**SilentEye — Hunt. Prioritize. Correlate. Investigate.**
