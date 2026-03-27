# SilentEye DFIR Console

**A lightweight DFIR (Digital Forensics & Incident Response) hunting console powered by osquery with scoring, contextual timelines, exports, and analyst-focused AI summaries.**

---

## 🔥 Overview

SilentEye is a terminal-based DFIR tool designed for real-world investigations. It helps analysts quickly identify suspicious activity, prioritize findings, and build timelines without needing heavy enterprise tooling.

Built with:

* 🧠 **osquery** (endpoint visibility)
* 🖥️ **Textual (TUI)** (interactive interface)
* 📊 **Custom scoring engine** (triage focus)
* 🤖 **AI-style analysis layer** (analyst assistance)

---

## 🚀 Features

### 🔎 DFIR Hunting

Pre-built hunts for:

* Startup Items
* Scheduled Tasks
* Services
* WMI Persistence
* Listening Ports
* PowerShell Activity
* Recent Files
* UserAssist
* Shimcache
* Drivers

---

### 🧠 Intelligent Scoring

Each result is automatically enriched with:

* Severity (Low / Medium / High)
* Score (0–100)
* Detection reasoning
* Recommended action

---

### 🕒 Contextual Timeline

* Press **Ctrl+T**
* Builds a timeline based on your current investigation

Includes:

* Execution artifacts (UserAssist, Shimcache)
* Registry persistence (Run, RunOnce, IFEO, Services)

---

### 🤖 AI Analysis (Local)

* Press **F6** on a selected row

Generates:

* Analyst assessment
* Key indicators
* Recommended next steps
* Ready-to-use write-up

---

### 📦 Export Capabilities

* **Ctrl+E** → Export all findings
* **Ctrl+Shift+E** → Export High severity only

Formats:

* JSON
* CSV

Saved to:

```
./exports/
```

---

## 🛠️ Installation

### Option 1: Automated (Recommended)

Run PowerShell as Administrator:

```powershell
./install.ps1
```

This will:

* Install Python (if missing)
* Install dependencies
* Check/install osquery (optional via Chocolatey)
* Prepare project folders

---

### Option 2: Manual Setup

#### 1. Install Python (3.10+)

[https://www.python.org/downloads/](https://www.python.org/downloads/)

#### 2. Install dependencies

```bash
pip install -r requirements.txt
```

#### 3. Install osquery

[https://osquery.io/downloads](https://osquery.io/downloads)

Verify:

```bash
osqueryi --version
```

---

## ▶️ Running SilentEye

```bash
python silenteye.py
```

---

## 🧪 Usage Guide

### Run a Hunt

* Select from left panel
* Press:

  * **Ctrl+Enter** OR
  * **F5** OR
  * Click "Run Query"

---

### Navigate Results

* Arrow keys to move
* Press:

  * **Enter / I** → inspect row
  * **C** → copy row

---

### AI Analysis

* Select a row
* Press **F6**

---

### Timeline

* Press **Ctrl+T**

---

### Export

* **Ctrl+E** → Export all
* **Ctrl+Shift+E** → Export high only

---

## ⚠️ Known Issues

### 1. Registry visibility (non-admin)

* Some registry paths require Administrator privileges
* Timeline may appear incomplete

### 2. Timeline behavior

* Ctrl+T may fallback to default timeline in some contexts (e.g., Registry Discovery)

### 3. Clipboard issues (Windows)

* Copy/paste may not work in elevated terminals depending on shell

### 4. Scheduled Tasks

* Some queries require admin privileges to return full results

### 5. Evented Tables

* `powershell_events` requires script block logging enabled

---

## 🔐 DFIR Best Practices

This tool is designed for investigation—not destruction.

Avoid:

* Killing processes immediately
* Deleting files without evidence collection

Instead:

* Export findings
* Build timeline
* Correlate artifacts
* Then respond

---

## 🧭 Roadmap

* [ ] Fix registry timeline fallback logic
* [ ] Enriched timeline mode
* [ ] LLM-backed AI analysis
* [ ] One-click report generation
* [ ] Multi-host support

---

## 📁 Project Structure

```
SilentEye/
├── silenteye.py
├── install.ps1
├── requirements.txt
├── README.md
└── exports/
```

---

## ⭐ Use Cases

* SOC triage
* Incident response
* Threat hunting labs
* DFIR training
* Portfolio demonstration

---

## ⚠️ Disclaimer

For educational and authorized use only.

Do not use on systems you do not have permission to assess.

---

## 💡 Author Note

SilentEye was built to bridge the gap between:

* raw telemetry (osquery)
* and analyst decision-making

It focuses on speed, clarity, and practical DFIR workflows.

---

## 🚀 If You Like This Project

* ⭐ Star the repo
* 🍴 Fork it
* 🧠 Contribute ideas or improvements

---

**SilentEye = Fast DFIR, Real Decisions**
