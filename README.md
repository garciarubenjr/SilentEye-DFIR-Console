# SilentEye DFIR Console

**A lightweight Windows DFIR and threat-hunting console powered by osquery, with heuristic triage scoring, hunt-contextual timelines, evidence export, and local analyst-assistance workflows.**

SilentEye is designed to help analysts move from raw endpoint telemetry to prioritized investigation faster—without requiring a full enterprise SIEM or EDR platform.

---

## Overview

SilentEye is an interactive terminal-based DFIR console for Windows investigations.

It combines:

- **osquery** for endpoint artifact collection
- **Textual** for an interactive terminal user interface
- **Custom heuristic scoring** for triage prioritization
- **Contextual timeline pivots** for investigation support
- **Local Analyst Assist** for deterministic investigation guidance
- **CSV and JSON exports** for evidence preservation and reporting

SilentEye is intended for:

- SOC analysts
- Incident responders
- Threat hunters
- DFIR students
- Security engineers
- Home-lab investigations

<img width="1538" height="826" alt="SilentEye DFIR Console" src="https://github.com/user-attachments/assets/58ca4bc7-3d8c-4785-86cc-402cc14e13ce" />

---

# Key Features

## DFIR Hunting

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

## Heuristic Triage Scoring

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
