import csv
import json
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Footer, Header, ListItem, ListView, Static, TextArea


APP_ROOT = Path(__file__).resolve().parent
EXPORT_DIR = APP_ROOT / "exports"
OSQUERY_TIMEOUT_SECONDS = 45


RAW_HUNT_QUERIES: Dict[str, str] = {
    "Startup Items": r"""
SELECT
    name,
    path,
    type,
    source
FROM startup_items
WHERE path != ''
  AND (
        path LIKE 'C:\Users\%%'
        OR path LIKE '%%\AppData\%%'
        OR path LIKE '%%\Temp\%%'
        OR path LIKE '%%\ProgramData\%%'
        OR path NOT LIKE 'C:\Windows\%%'
      )
ORDER BY name;
""".strip(),

    "Scheduled Tasks": r"""
SELECT
    name,
    action,
    path,
    enabled,
    state,
    hidden,
    CASE
        WHEN last_run_time IS NOT NULL AND last_run_time > 0
        THEN datetime(last_run_time, 'unixepoch')
        ELSE ''
    END AS last_run_utc,
    CASE
        WHEN next_run_time IS NOT NULL AND next_run_time > 0
        THEN datetime(next_run_time, 'unixepoch')
        ELSE ''
    END AS next_run_utc,
    last_run_message,
    last_run_code
FROM scheduled_tasks
WHERE action != ''
  AND (
        hidden = 1
        OR path LIKE 'C:\Users\%%'
        OR path LIKE '%%\AppData\%%'
        OR path LIKE '%%\Temp\%%'
        OR path LIKE '%%\ProgramData\%%'
        OR path NOT LIKE 'C:\Windows\%%'
        OR action LIKE '%%powershell%%'
        OR action LIKE '%%cmd.exe%%'
        OR action LIKE '%%wscript%%'
        OR action LIKE '%%cscript%%'
      )
ORDER BY hidden DESC, next_run_time DESC, last_run_time DESC;
""".strip(),

    "Services": r"""
SELECT
    name,
    display_name,
    status,
    start_type,
    path
FROM services
WHERE path != ''
  AND (
        path LIKE 'C:\Users\%%'
        OR path LIKE '%%\AppData\%%'
        OR path LIKE '%%\Temp\%%'
        OR path LIKE '%%\ProgramData\%%'
        OR path NOT LIKE 'C:\Windows\%%'
      )
ORDER BY name;
""".strip(),

    "WMI Persistence": r"""
SELECT
    f.name AS filter_name,
    f.query AS wql_query,
    c.name AS consumer_name,
    c.scripting_engine,
    c.script_file_name,
    c.script_text
FROM wmi_event_filters f
JOIN wmi_filter_consumer_binding b
    ON b.filter LIKE '%%' || f.name || '%%'
JOIN wmi_script_event_consumers c
    ON b.consumer LIKE '%%' || c.name || '%%'
WHERE c.script_text IS NOT NULL
   OR c.script_file_name IS NOT NULL;
""".strip(),

    "Listening Ports": r"""
SELECT
    p.name,
    p.pid,
    l.address,
    l.port,
    l.protocol
FROM processes p
JOIN listening_ports l
    ON p.pid = l.pid
ORDER BY l.port, p.name;
""".strip(),


    "Context Timeline": r"""
SELECT 'userassist' AS artifact_type, path, last_execution_time AS ts, sid AS context
FROM userassist
UNION ALL
SELECT 'shimcache' AS artifact_type, path, modified_time AS ts, CAST(execution_flag AS TEXT) AS context
FROM shimcache
ORDER BY ts DESC
LIMIT 200;
""".strip(),

    "Registry Discovery": r"""
SELECT
    key,
    path,
    name,
    type,
    data,
    mtime
FROM registry
WHERE
    path LIKE '%Run%'
    OR path LIKE '%RunOnce%'
    OR path LIKE '%Image File Execution Options%'
    OR path LIKE '%CurrentControlSet\\Services%'
    OR key LIKE '%Run%'
    OR key LIKE '%RunOnce%'
ORDER BY mtime DESC
LIMIT 150;
""".strip(),
    "PowerShell Activity": r"""
SELECT
    datetime,
    script_name,
    script_path,
    script_text,
    cosine_similarity
FROM powershell_events
WHERE script_text LIKE '%%Invoke%%'
   OR script_text LIKE '%%Download%%'
   OR script_text LIKE '%%EncodedCommand%%'
   OR script_text LIKE '%%IEX%%'
   OR cosine_similarity < 0.80
ORDER BY time DESC
LIMIT 100;
""".strip(),

    "Recent Files": r"""
SELECT
    uid,
    filename,
    path,
    type,
    mtime,
    shortcut_path
FROM recent_files
ORDER BY mtime DESC
LIMIT 100;
""".strip(),

    "UserAssist": r"""
SELECT
    path,
    count,
    last_execution_time,
    sid
FROM userassist
ORDER BY last_execution_time DESC
LIMIT 100;
""".strip(),

    "Shimcache": r"""
SELECT
    entry,
    path,
    modified_time,
    execution_flag
FROM shimcache
ORDER BY modified_time DESC
LIMIT 100;
""".strip(),

    "Drivers": r"""
SELECT
    device_name,
    image,
    service,
    provider,
    manufacturer,
    signed,
    CASE
        WHEN date IS NOT NULL AND date > 0
        THEN datetime(date, 'unixepoch')
        ELSE ''
    END AS driver_date
FROM drivers
WHERE signed = 0
   OR image LIKE 'C:\Users\%%'
   OR image LIKE '%%\AppData\%%'
   OR image LIKE '%%\Temp\%%'
   OR image NOT LIKE 'C:\Windows\System32\drivers%%'
ORDER BY signed ASC, provider, device_name;
""".strip(),
}



REGISTRY_TIMELINE_SQL = r"""
SELECT
    CASE
        WHEN path LIKE '%Image File Execution Options%' THEN 'registry_ifeo'
        WHEN path LIKE '%CurrentControlSet\\Services%' THEN 'registry_service'
        ELSE 'registry_run'
    END AS artifact_type,
    path,
    name,
    data,
    mtime AS ts,
    key AS context
FROM registry
WHERE
    path LIKE '%Run%'
    OR path LIKE '%RunOnce%'
    OR path LIKE '%Image File Execution Options%'
    OR path LIKE '%CurrentControlSet\\Services%'
    OR key LIKE '%Run%'
    OR key LIKE '%RunOnce%'
ORDER BY mtime DESC
LIMIT 200;
""".strip()


def build_contextual_timeline_sql(hunt_label: Optional[str], current_sql: str) -> str:
    label = hunt_label or "Custom Query"

    if label == "UserAssist":
        return """
SELECT 'userassist' AS artifact_type, path, last_execution_time AS ts, sid AS context
FROM userassist
ORDER BY ts DESC
LIMIT 200;
""".strip()

    if label == "Shimcache":
        return """
SELECT 'shimcache' AS artifact_type, path, modified_time AS ts, CAST(execution_flag AS TEXT) AS context
FROM shimcache
ORDER BY ts DESC
LIMIT 200;
""".strip()

    if label == "Scheduled Tasks":
        return """
SELECT 'scheduled_task' AS artifact_type, path, name, action AS data, next_run_time AS ts, state AS context
FROM scheduled_tasks
WHERE action != '' AND next_run_time IS NOT NULL AND next_run_time > 0
UNION ALL
SELECT
    CASE
        WHEN path LIKE '%Image File Execution Options%' THEN 'registry_ifeo'
        WHEN path LIKE '%CurrentControlSet\\Services%' THEN 'registry_service'
        ELSE 'registry_run'
    END AS artifact_type, path, name, data, mtime AS ts, key AS context
FROM registry
WHERE
    path LIKE '%Run%'
    OR path LIKE '%RunOnce%'
    OR path LIKE '%Image File Execution Options%'
    OR path LIKE '%CurrentControlSet\\Services%'
    OR key LIKE '%Run%'
    OR key LIKE '%RunOnce%'
ORDER BY ts DESC
LIMIT 250;
""".strip()

    if label == "Startup Items":
        return """
SELECT 'startup_item' AS artifact_type, path, name, source AS data, CAST('' AS BIGINT) AS ts, type AS context
FROM startup_items
UNION ALL
SELECT
    CASE
        WHEN path LIKE '%Image File Execution Options%' THEN 'registry_ifeo'
        WHEN path LIKE '%CurrentControlSet\\Services%' THEN 'registry_service'
        ELSE 'registry_run'
    END AS artifact_type, path, name, data, mtime AS ts, key AS context
FROM registry
WHERE
    path LIKE '%Run%'
    OR path LIKE '%RunOnce%'
    OR path LIKE '%Image File Execution Options%'
    OR path LIKE '%CurrentControlSet\\Services%'
    OR key LIKE '%Run%'
    OR key LIKE '%RunOnce%'
ORDER BY ts DESC
LIMIT 250;
""".strip()

    if label == "Services":
        return """
SELECT 'service' AS artifact_type, path, name, display_name AS data, CAST('' AS BIGINT) AS ts, status AS context
FROM services
UNION ALL
SELECT 'registry_service' AS artifact_type, path, name, data, mtime AS ts, key AS context
FROM registry
WHERE path LIKE 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\%%'
ORDER BY ts DESC
LIMIT 250;
""".strip()

    if label == "WMI Persistence":
        return """
SELECT 'wmi_consumer' AS artifact_type, c.script_file_name AS path, c.name, c.script_text AS data, CAST('' AS BIGINT) AS ts, c.scripting_engine AS context
FROM wmi_script_event_consumers c
UNION ALL
SELECT 'registry_run' AS artifact_type, path, name, data, mtime AS ts, key AS context
FROM registry
WHERE
    path LIKE 'HKEY_USERS\\%%\\Software\\Microsoft\\Windows\\CurrentVersion\\Run%%'
    OR path LIKE 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run%%'
ORDER BY ts DESC
LIMIT 250;
""".strip()

    if label == "PowerShell Activity":
        return """
SELECT 'powershell' AS artifact_type, script_path AS path, script_name AS name, script_text AS data, time AS ts, CAST(cosine_similarity AS TEXT) AS context
FROM powershell_events
UNION ALL
SELECT 'registry_run' AS artifact_type, path, name, data, mtime AS ts, key AS context
FROM registry
WHERE
    path LIKE 'HKEY_USERS\\%%\\Software\\Microsoft\\Windows\\CurrentVersion\\Run%%'
    OR path LIKE 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run%%'
ORDER BY ts DESC
LIMIT 250;
""".strip()

    if label == "Context Timeline":
        return """
SELECT 'userassist' AS artifact_type, path, path AS name, sid AS data, last_execution_time AS ts, sid AS context
FROM userassist
UNION ALL
SELECT 'shimcache' AS artifact_type, path, path AS name, CAST(execution_flag AS TEXT) AS data, modified_time AS ts, CAST(execution_flag AS TEXT) AS context
FROM shimcache
UNION ALL
SELECT
    CASE
        WHEN path LIKE '%Image File Execution Options%' THEN 'registry_ifeo'
        WHEN path LIKE '%CurrentControlSet\\Services%' THEN 'registry_service'
        ELSE 'registry_run'
    END AS artifact_type, path, name, data, mtime AS ts, key AS context
FROM registry
WHERE
    path LIKE '%Run%'
    OR path LIKE '%RunOnce%'
    OR path LIKE '%Image File Execution Options%'
    OR path LIKE '%CurrentControlSet\\Services%'
    OR key LIKE '%Run%'
    OR key LIKE '%RunOnce%'
ORDER BY ts DESC
LIMIT 300;
""".strip()

    # Default: registry-aware timeline around current investigation context
    return """
SELECT 'userassist' AS artifact_type, path, path AS name, sid AS data, last_execution_time AS ts, sid AS context
FROM userassist
UNION ALL
SELECT 'shimcache' AS artifact_type, path, path AS name, CAST(execution_flag AS TEXT) AS data, modified_time AS ts, CAST(execution_flag AS TEXT) AS context
FROM shimcache
UNION ALL
SELECT
    CASE
        WHEN path LIKE '%Image File Execution Options%' THEN 'registry_ifeo'
        WHEN path LIKE '%CurrentControlSet\\Services%' THEN 'registry_service'
        ELSE 'registry_run'
    END AS artifact_type, path, name, data, mtime AS ts, key AS context
FROM registry
WHERE
    path LIKE '%Run%'
    OR path LIKE '%RunOnce%'
    OR path LIKE '%Image File Execution Options%'
    OR path LIKE '%CurrentControlSet\\Services%'
    OR key LIKE '%Run%'
    OR key LIKE '%RunOnce%'
ORDER BY ts DESC
LIMIT 300;
""".strip()

COLUMN_PRIORITY = [
    "severity",
    "score",
    "recommended_action",
    "reasons",
    "artifact_type",
    "ts",
    "timeline_time",
    "context",
    "filter_name",
    "consumer_name",
    "name",
    "display_name",
    "device_name",
    "filename",
    "path",
    "image",
    "service",
    "provider",
    "manufacturer",
    "pid",
    "address",
    "port",
    "protocol",
    "action",
    "state",
    "status",
    "enabled",
    "hidden",
    "signed",
    "script_name",
    "script_path",
    "script_text",
    "wql_query",
    "count",
    "sid",
    "type",
    "source",
    "last_run_utc",
    "next_run_utc",
    "driver_date",
    "mtime",
    "modified_time",
    "last_execution_time",
    "entry",
    "last_run_message",
    "last_run_code",
    "cosine_similarity",
]

UNSUPPORTED_TABLE_HINTS = {
    "recent_files": "This osquery build does not expose the recent_files table on this host.",
    "powershell_events": "powershell_events may require PowerShell Script Block Logging and eventing support.",
    "scheduled_tasks": "scheduled_tasks often requires Administrator privileges on Windows.",
}

SAFE_PREFIXES = (
    "c:\\windows\\",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
)

SUSPICIOUS_PATH_MARKERS = (
    "\\users\\",
    "\\appdata\\",
    "\\temp\\",
    "\\public\\",
)

SCRIPT_EXTENSIONS = (
    ".ps1",
    ".vbs",
    ".js",
    ".bat",
    ".cmd",
)

TIMESTAMP_FIELDS = {
    "mtime",
    "modified_time",
    "last_execution_time",
    "time",
    "last_run_time",
    "next_run_time",
    "date",
}


def split_sql_statements(sql: str) -> List[str]:
    return [stmt.strip() for stmt in sql.split(";") if stmt.strip()]


def sort_columns(keys: List[str]) -> List[str]:
    priority_rank = {name: i for i, name in enumerate(COLUMN_PRIORITY)}
    return sorted(keys, key=lambda key: (priority_rank.get(key, 9999), key.lower()))


def find_osquery() -> Optional[str]:
    detected = shutil.which("osqueryi") or shutil.which("osqueryi.exe")
    if detected:
        return detected

    if sys.platform.startswith("win"):
        candidates = [
            Path(r"C:\Program Files\osquery\osqueryi.exe"),
            Path(r"C:\ProgramData\chocolatey\bin\osqueryi.exe"),
        ]
        for candidate in candidates:
            if candidate.is_file():
                return str(candidate)

    return None


def normalize_windows_path(path: str) -> str:
    value = str(path or "").strip().replace("/", "\\")
    if value.startswith('"'):
        value = value[1:]
    return value.lower()


def copy_text_to_clipboard(text: str) -> Optional[str]:
    try:
        if sys.platform.startswith("win"):
            subprocess.run("clip", input=text, text=True, shell=True, check=True)
            return None
        if sys.platform == "darwin":
            subprocess.run(["pbcopy"], input=text, text=True, check=True)
            return None
        if shutil.which("xclip"):
            subprocess.run(["xclip", "-selection", "clipboard"], input=text, text=True, check=True)
            return None
        if shutil.which("xsel"):
            subprocess.run(["xsel", "--clipboard", "--input"], input=text, text=True, check=True)
            return None
        return "No clipboard tool found on this system."
    except Exception as exc:
        return f"Clipboard copy failed: {exc}"


def sanitize_filename(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in (value or "custom_query"))
    return cleaned.strip("_") or "custom_query"


def export_rows_json(path: Path, rows: List[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2, ensure_ascii=False)


def export_rows_csv(path: Path, rows: List[dict], columns: List[str]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            out = {}
            for col in columns:
                value = row.get(col, "")
                if isinstance(value, (list, dict)):
                    out[col] = json.dumps(value, ensure_ascii=False)
                else:
                    out[col] = value
            writer.writerow(out)


def as_int(value, default=0):
    try:
        return int(float(str(value)))
    except Exception:
        return default


def lower_text(value) -> str:
    return str(value or "").strip().lower()


def format_timestamp(value) -> str:
    try:
        if value in (None, "", "0"):
            return ""
        ts = int(float(str(value)))
        return datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(value)


def normalize_timeline_timestamp(row: dict) -> dict:
    if "ts" in row:
        row["timeline_time"] = format_timestamp(row.get("ts"))
    return row


def score_timeline(row: dict) -> tuple[int, List[str]]:
    score = 10
    reasons = []
    artifact = lower_text(row.get("artifact_type"))
    path = row.get("path", "")
    context = lower_text(row.get("context"))
    data = lower_text(row.get("data"))

    if artifact == "userassist":
        score += 10
        reasons.append("user execution artifact")
    elif artifact == "shimcache":
        score += 15
        reasons.append("execution evidence artifact")
    elif artifact.startswith("registry"):
        score += 20
        reasons.append("registry persistence or execution-related artifact")
    elif artifact in {"scheduled_task", "service", "wmi_consumer", "powershell"}:
        score += 15
        reasons.append("high-value timeline artifact type")

    if path_is_unusual(path):
        score += 30
        reasons.append("timeline item points to unusual path")

    suspicious_blobs = [".ps1", ".vbs", ".js", ".bat", ".cmd", ".exe", "powershell", "rundll32", "mshta", "wscript", "cscript"]
    if any(x in lower_text(path) for x in suspicious_blobs) or any(x in data for x in suspicious_blobs):
        score += 15
        reasons.append("timeline item references executable, script, or LOLBin content")

    if context in {"1", "true"}:
        score += 10
        reasons.append("execution flag or positive context indicator present")

    return min(score, 100), reasons


def path_is_unusual(path: str) -> bool:
    p = normalize_windows_path(path)
    if not p:
        return False

    if any(marker in p for marker in SUSPICIOUS_PATH_MARKERS):
        return True

    executable_path = p.split(" --", 1)[0].split(" -", 1)[0].strip().rstrip('"')
    if executable_path.endswith(SCRIPT_EXTENSIONS):
        return True

    return not p.startswith(SAFE_PREFIXES)


def classify(score: int) -> tuple[str, str]:
    if score >= 80:
        return "High", "Contain / Investigate"
    if score >= 50:
        return "Medium", "Investigate"
    return "Low", "Observe"


def score_startup_item(row: dict) -> tuple[int, List[str]]:
    score = 15
    reasons = []
    path = row.get("path", "")
    if path_is_unusual(path):
        score += 45
        reasons.append("startup path outside standard trusted locations")
    if any(x in lower_text(path) for x in ["\\appdata\\", "\\temp\\", "\\users\\public", ".vbs", ".js", ".bat", ".cmd", ".ps1"]):
        score += 25
        reasons.append("startup item uses user-writable or script-heavy location")
    return min(score, 100), reasons


def score_scheduled_task(row: dict) -> tuple[int, List[str]]:
    score = 20
    reasons = []
    if as_int(row.get("hidden")) == 1:
        score += 25
        reasons.append("task is hidden")
    action = lower_text(row.get("action"))
    path = row.get("path", "")
    if any(x in action for x in ["powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32"]):
        score += 30
        reasons.append("task action uses common LOLBin or script interpreter")
    if path_is_unusual(path) or path_is_unusual(action):
        score += 30
        reasons.append("task references unusual path or execution target")
    if lower_text(row.get("enabled")) in ("1", "true"):
        score += 5
        reasons.append("task is enabled")
    return min(score, 100), reasons


def score_service(row: dict) -> tuple[int, List[str]]:
    score = 15
    reasons = []
    path = row.get("path", "")
    if path_is_unusual(path):
        score += 40
        reasons.append("service binary path is unusual")
    if any(x in lower_text(path) for x in ["\\temp\\", "\\appdata\\", ".ps1", ".vbs", ".js"]):
        score += 25
        reasons.append("service path points to script or user-writable location")
    if lower_text(row.get("status")) == "running":
        score += 10
        reasons.append("service is running")
    return min(score, 100), reasons


def score_wmi(row: dict) -> tuple[int, List[str]]:
    score = 70
    reasons = ["WMI script consumer persistence is inherently high signal"]
    script_text = lower_text(row.get("script_text"))
    script_file = lower_text(row.get("script_file_name"))
    if any(x in script_text for x in ["powershell", "download", "iex", "cmd.exe", "wscript", "cscript"]):
        score += 20
        reasons.append("consumer script contains suspicious execution keywords")
    if script_file and path_is_unusual(script_file):
        score += 10
        reasons.append("consumer script file path is unusual")
    return min(score, 100), reasons


def score_listening_port(row: dict) -> tuple[int, List[str]]:
    score = 10
    reasons = []
    port = as_int(row.get("port"))
    name = lower_text(row.get("name"))
    address = lower_text(row.get("address"))
    suspicious_ports = {4444, 5555, 1337, 8081, 9001, 31337}
    if port in suspicious_ports:
        score += 45
        reasons.append(f"listening on commonly suspicious port {port}")
    if address in ("0.0.0.0", "::"):
        score += 10
        reasons.append("listening on all interfaces")
    if name in {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe"}:
        score += 35
        reasons.append("script or LOLBin process is listening on a port")
    return min(score, 100), reasons


def score_powershell(row: dict) -> tuple[int, List[str]]:
    score = 25
    reasons = []
    script_text = lower_text(row.get("script_text"))
    cosine = row.get("cosine_similarity")
    if any(x in script_text for x in ["encodedcommand", "iex", "downloadstring", "invoke-webrequest", "frombase64string"]):
        score += 35
        reasons.append("script contains suspicious PowerShell tradecraft")
    try:
        if cosine not in (None, "") and float(cosine) < 0.80:
            score += 25
            reasons.append("script has low cosine similarity and may be obfuscated")
    except Exception:
        pass
    if path_is_unusual(row.get("script_path", "")):
        score += 10
        reasons.append("script path is unusual")
    return min(score, 100), reasons


def score_user_activity(row: dict) -> tuple[int, List[str]]:
    score = 10
    reasons = []
    path = row.get("path", "")
    if path_is_unusual(path):
        score += 25
        reasons.append("artifact points to unusual path")
    if any(x in lower_text(path) for x in [".ps1", ".vbs", ".js", ".bat", ".cmd", ".exe"]):
        score += 15
        reasons.append("artifact references executable or script content")
    return min(score, 100), reasons


def score_shimcache(row: dict) -> tuple[int, List[str]]:
    score = 15
    reasons = []
    path = row.get("path", "")
    if path_is_unusual(path):
        score += 35
        reasons.append("shimcache entry path is unusual")
    if as_int(row.get("execution_flag"), default=-1) == 1:
        score += 15
        reasons.append("execution flag indicates the file executed")
    return min(score, 100), reasons


def score_driver(row: dict) -> tuple[int, List[str]]:
    score = 20
    reasons = []
    if as_int(row.get("signed")) == 0:
        score += 45
        reasons.append("driver is unsigned")
    image = row.get("image", "")
    if path_is_unusual(image):
        score += 25
        reasons.append("driver image path is unusual")
    provider = lower_text(row.get("provider"))
    manufacturer = lower_text(row.get("manufacturer"))
    if not provider or provider == "unknown":
        score += 10
        reasons.append("driver provider is blank or unknown")
    if not manufacturer or manufacturer == "unknown":
        score += 5
        reasons.append("driver manufacturer is blank or unknown")
    return min(score, 100), reasons


def enrich_row(row: dict, hunt_label: Optional[str]) -> dict:
    enriched = dict(row)
    score = 0
    reasons: List[str] = []

    if hunt_label == "Startup Items":
        score, reasons = score_startup_item(row)
    elif hunt_label == "Scheduled Tasks":
        score, reasons = score_scheduled_task(row)
    elif hunt_label == "Services":
        score, reasons = score_service(row)
    elif hunt_label == "WMI Persistence":
        score, reasons = score_wmi(row)
    elif hunt_label == "Listening Ports":
        score, reasons = score_listening_port(row)
    elif hunt_label == "PowerShell Activity":
        score, reasons = score_powershell(row)
    elif hunt_label in {"Recent Files", "UserAssist"}:
        score, reasons = score_user_activity(row)
    elif hunt_label == "Shimcache":
        score, reasons = score_shimcache(row)
    elif hunt_label == "Drivers":
        score, reasons = score_driver(row)
    elif hunt_label == "Context Timeline":
        score, reasons = score_timeline(row)

    severity, action = classify(score)
    enriched["severity"] = severity
    enriched["score"] = score
    enriched["recommended_action"] = action
    enriched["reasons"] = "; ".join(reasons) if reasons else "no strong anomaly markers"
    return enriched


class RowDetailModal(ModalScreen[None]):
    CSS = """
    RowDetailModal {
        align: center middle;
        background: rgba(0, 0, 0, 0.65);
    }
    #detail-shell {
        width: 85%;
        height: 85%;
        border: round #3b82f6;
        background: #0b0f14;
        padding: 1 1;
    }
    #detail-title {
        height: 1;
        color: #dbeafe;
        text-style: bold;
        margin-bottom: 1;
    }
    #detail-body {
        height: 1fr;
        border: round #223247;
        background: #111318;
        color: #e5e7eb;
    }
    #detail-help {
        height: 1;
        color: #94a3b8;
        margin-top: 1;
    }
    """
    BINDINGS = [("escape", "dismiss_modal", "Close"), ("q", "dismiss_modal", "Close"), ("c", "copy_modal_text", "Copy")]

    def __init__(self, title: str, body: str) -> None:
        super().__init__()
        self.title_text = title
        self.body_text = body

    def compose(self) -> ComposeResult:
        with Vertical(id="detail-shell"):
            yield Static(self.title_text, id="detail-title")
            yield TextArea(self.body_text, id="detail-body", read_only=True)
            yield Static("Esc/Q = close | C = copy details", id="detail-help")

    def action_dismiss_modal(self) -> None:
        self.dismiss()

    def action_copy_modal_text(self) -> None:
        error = copy_text_to_clipboard(self.body_text)
        if error:
            self.notify(error, severity="error")
        else:
            self.notify("Detail view copied to clipboard.", severity="information")



class AnalystAssistModal(ModalScreen[None]):
    CSS = """
    AnalystAssistModal {
        align: center middle;
        background: rgba(0, 0, 0, 0.65);
    }
    #assist-shell {
        width: 85%;
        height: 85%;
        border: round #10b981;
        background: #0b0f14;
        padding: 1 1;
    }
    #assist-title {
        height: 1;
        color: #d1fae5;
        text-style: bold;
        margin-bottom: 1;
    }
    #assist-body {
        height: 1fr;
        border: round #223247;
        background: #111318;
        color: #e5e7eb;
    }
    #assist-help {
        height: 1;
        color: #94a3b8;
        margin-top: 1;
    }
    """

    BINDINGS = [
        ("escape", "dismiss_modal", "Close"),
        ("q", "dismiss_modal", "Close"),
        ("c", "copy_modal_text", "Copy"),
    ]

    def __init__(self, title: str, body: str) -> None:
        super().__init__()
        self.title_text = title
        self.body_text = body

    def compose(self) -> ComposeResult:
        with Vertical(id="assist-shell"):
            yield Static(self.title_text, id="assist-title")
            yield TextArea(self.body_text, id="assist-body", read_only=True)
            yield Static("Esc/Q = close | C = copy analysis", id="assist-help")

    def action_dismiss_modal(self) -> None:
        self.dismiss()

    def action_copy_modal_text(self) -> None:
        error = copy_text_to_clipboard(self.body_text)
        if error:
            self.notify(error, severity="error")
        else:
            self.notify("Analyst assistance copied to clipboard.", severity="information")


def build_analyst_assistance(row: dict, hunt_label: Optional[str], visible_columns: List[str]) -> str:
    severity = str(row.get("severity", "Unknown"))
    score = str(row.get("score", ""))
    action = str(row.get("recommended_action", "Investigate"))
    reasons = str(row.get("reasons", "no strong anomaly markers"))
    hunt = hunt_label or "Custom Query"

    artifact = (
        row.get("name")
        or row.get("device_name")
        or row.get("filename")
        or row.get("filter_name")
        or row.get("consumer_name")
        or row.get("artifact_type")
        or "Unknown artifact"
    )
    primary_path = (
        row.get("path")
        or row.get("image")
        or row.get("script_path")
        or row.get("script_file_name")
        or ""
    )

    indicators = []
    for field in ["action", "data", "script_text", "service", "provider", "manufacturer", "context"]:
        value = str(row.get(field, "") or "").strip()
        if value:
            indicators.append(f"- {field}={value[:180]}")
    indicators_text = "\n".join(indicators[:5]) or "- No extra indicators captured"

    evidence = []
    for col in visible_columns:
        if col in {"severity", "score", "recommended_action", "reasons"}:
            continue
        value = row.get(col, "")
        if value not in ("", None):
            evidence.append(f"- {col}: {value}")
    evidence_text = "\n".join(evidence[:12]) or "- No additional evidence fields"

    if severity == "High":
        assessment = (
            "This is a high-priority triage finding. The row contains persistence, execution, path, "
            "or signature indicators that deserve immediate review."
        )
        next_steps = [
            "Validate the artifact path, signer/provider, and execution context.",
            "Collect hashes, metadata, command content, and neighboring artifacts.",
            "Pivot into timeline, registry, services, tasks, startup items, and network activity.",
            "Consider containment if the host shows active malicious behavior."
        ]
    elif severity == "Medium":
        assessment = (
            "This is suspicious enough to investigate but not enough on its own to declare malicious. "
            "It likely reflects unusual execution, pathing, or persistence behavior."
        )
        next_steps = [
            "Confirm whether the artifact belongs to approved software or admin tooling.",
            "Review command text, path location, signer/provider, and timeline correlation.",
            "Pivot to related persistence or execution artifacts on the same host.",
            "Escalate if the same artifact appears across multiple hunts or systems."
        ]
    else:
        assessment = (
            "This finding is currently lower priority based on the available indicators. "
            "Keep it in context and correlate with other evidence before dismissing it."
        )
        next_steps = [
            "Verify whether the path and vendor are expected in your environment.",
            "Keep the finding for context while reviewing higher-priority items.",
            "Re-check if new evidence changes the risk picture.",
            "Document why it was retained or cleared."
        ]

    return f"""ANALYST ASSISTANCE
Hunt: {hunt}
Artifact: {artifact}
Primary Path: {primary_path}
Triage Priority: {severity}
Triage Score: {score}
Recommended Action: {action}

Assessment
{assessment}

Why it was scored this way
{reasons}

Key Indicators
{indicators_text}

Recommended Analyst Next Steps
1. {next_steps[0]}
2. {next_steps[1]}
3. {next_steps[2]}
4. {next_steps[3]}

Evidence Snapshot
{evidence_text}

Suggested Write-up
This {hunt.lower()} finding involving '{artifact}' was assigned {severity.lower()} triage priority with a score of {score}. The strongest indicators were: {reasons}. Recommended action: {action}.
"""

class SilentEyeDFIR(App):
    TITLE = "SilentEye DFIR Console"

    CSS = """
    Screen { background: #0b0f14; color: #d8dee9; }
    Header, Footer { background: #111827; color: #e5e7eb; }
    Horizontal { height: 1fr; }
    #left-pane {
        width: 30; min-width: 30; height: 1fr; margin: 1 1 1 1;
        border: round #223247; background: #111318;
    }
    #left-title { padding: 1 1 0 1; color: #e5e7eb; text-style: bold; }
    #preset-list { height: 1fr; padding: 0 1 1 1; }
    #right-pane { width: 1fr; height: 1fr; margin: 1 1 1 0; }
    #query-box {
        height: 8; border: round #f59e0b; background: #111318; color: #e5e7eb; margin-bottom: 1;
    }
    #query-actions {
        height: 3;
        margin-bottom: 1;
    }
    #run-button {
        width: 18;
        min-width: 18;
        background: #0b74c9;
        color: #ffffff;
        text-style: bold;
    }
    #export-button {
        width: 16;
        min-width: 16;
        margin-left: 1;
        background: #2563eb;
        color: #ffffff;
        text-style: bold;
    }
    #export-high-button {
        width: 16;
        min-width: 16;
        margin-left: 1;
        background: #7c3aed;
        color: #ffffff;
        text-style: bold;
    }
    #timeline-button {
        width: 16;
        min-width: 16;
        margin-left: 1;
        background: #0f766e;
        color: #ffffff;
        text-style: bold;
    }
    #assist-button {
        width: 16;
        min-width: 16;
        margin-left: 1;
        background: #059669;
        color: #ffffff;
        text-style: bold;
    }
    #run-help {
        width: 1fr;
        padding: 1 0 0 1;
        color: #94a3b8;
    }
    #table-box { height: 1fr; border: round #223247; background: #111318; }
    #results-table { height: 1fr; }
    #status-box {
        height: 3; border: round #223247; background: #0a0d12; color: #e5e7eb; padding: 0 1; margin-top: 1;
    }
    ListView > .list-view--highlight { background: #0b74c9; color: #ffffff; text-style: bold; }
    DataTable { background: #111318; color: #e5e7eb; }
    DataTable > .datatable--header { background: #1b2430; color: #dbeafe; text-style: bold; }
    DataTable > .datatable--cursor { background: #0b74c9; color: #ffffff; }
    .sev-high { color: #ff6b6b; text-style: bold; }
    .sev-medium { color: #ffd166; text-style: bold; }
    .sev-low { color: #95d5b2; }
    TextArea { background: #111318; color: #e5e7eb; }
    """

    BINDINGS = [
        ("ctrl+enter", "run_current_query", "Run Query"),
        ("ctrl+r", "run_current_query", "Run Query"),
        ("f5", "run_current_query", "Run Query"),
        ("ctrl+e", "export_current_results", "Export All"),
        ("ctrl+shift+e", "export_high_results", "Export High"),
        ("ctrl+t", "load_timeline_view", "Timeline View"),
        ("f6", "analyst_assist_selected_row", "Analyst Assist"),
        ("c", "copy_selected_row", "Copy Row"),
        ("y", "copy_selected_cell", "Copy Cell"),
        ("i", "inspect_selected_row", "Inspect Row"),
        ("enter", "inspect_selected_row", "Inspect Row"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.current_rows: List[dict] = []
        self.visible_columns: List[str] = []
        self.current_hunt_label: Optional[str] = None
        self.current_sql: str = ""
        self.last_executed_sql: str = ""
        self.last_executed_hunt_label: Optional[str] = None
        self.is_timeline_view: bool = False
        self.export_dir = EXPORT_DIR

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Horizontal():
            with Vertical(id="left-pane"):
                yield Static("DFIR Hunts", id="left-title")
                self.preset_list = ListView(
                    *[ListItem(Static(label)) for label in RAW_HUNT_QUERIES.keys()],
                    id="preset-list",
                )
                yield self.preset_list
            with Vertical(id="right-pane"):
                self.query_input = TextArea("", id="query-box")
                yield self.query_input
                with Horizontal(id="query-actions"):
                    self.run_button = Button("Run Query", id="run-button")
                    yield self.run_button
                    self.export_button = Button("Export All", id="export-button")
                    yield self.export_button
                    self.export_high_button = Button("Export High", id="export-high-button")
                    yield self.export_high_button
                    self.timeline_button = Button("Timeline", id="timeline-button")
                    yield self.timeline_button
                    self.assist_button = Button("Analyst Assist", id="assist-button")
                    yield self.assist_button
                    yield Static("Run: Ctrl+Enter/Ctrl+R/F5 | Export: Ctrl+E | High Only: Ctrl+Shift+E | Timeline: Ctrl+T | Assist: F6", id="run-help")
                with Vertical(id="table-box"):
                    self.results_table = DataTable(id="results-table")
                    self.results_table.cursor_type = "row"
                    yield self.results_table
                self.status_box = Static(
                    "Ctrl+Enter = run query | C = copy row | Y = copy cell | I/Enter = inspect row",
                    id="status-box",
                )
                yield self.status_box
        yield Footer()

    def on_mount(self) -> None:
        first_label = next(iter(RAW_HUNT_QUERIES))
        self.current_hunt_label = first_label
        self.query_input.text = RAW_HUNT_QUERIES[first_label]
        self.preset_list.index = 0
        self.status_box.update("Ready. Ctrl+Enter runs a hunt. Rows are scored for triage.")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "run-button":
            current_sql = self.query_input.text.strip()
            self.current_sql = current_sql
            preset_sql = RAW_HUNT_QUERIES.get(self.current_hunt_label or "", "").strip()
            if self.current_hunt_label == "Context Timeline":
                pass
            elif current_sql != preset_sql:
                self.current_hunt_label = None
                self.is_timeline_view = False
            else:
                self.is_timeline_view = False
            self.run_query(current_sql)
        elif event.button.id == "export-button":
            self.action_export_current_results()
        elif event.button.id == "export-high-button":
            self.action_export_high_results()
        elif event.button.id == "timeline-button":
            self.action_load_timeline_view()
        elif event.button.id == "assist-button":
            self.action_analyst_assist_selected_row()

    def action_load_timeline_view(self) -> None:
        source_label = self.last_executed_hunt_label or self.current_hunt_label
        source_sql = self.last_executed_sql or self.current_sql or self.query_input.text.strip()

        timeline_sql = build_contextual_timeline_sql(source_label, source_sql)

        self.current_hunt_label = "Context Timeline"
        self.current_sql = timeline_sql
        self.is_timeline_view = True
        self.query_input.text = timeline_sql
        self.run_query(timeline_sql)

    def action_run_current_query(self) -> None:
        current_sql = self.query_input.text.strip()
        self.current_sql = current_sql
        preset_sql = RAW_HUNT_QUERIES.get(self.current_hunt_label or "", "").strip()
        if self.current_hunt_label == "Context Timeline":
            pass
        elif current_sql != preset_sql:
            self.current_hunt_label = None
            self.is_timeline_view = False
        else:
            self.is_timeline_view = False
        self.run_query(current_sql)

    def action_analyst_assist_selected_row(self) -> None:
        if not self.current_rows or not self.visible_columns:
            self.status_box.update("No result row available for analyst assistance.")
            return
        row_index = self._get_selected_row_index()
        if row_index is None:
            self.status_box.update("Select a row in the results table first.")
            return
        try:
            row = self.current_rows[row_index]
            body = build_analyst_assistance(row, self.current_hunt_label, self.visible_columns)
            self.push_screen(AnalystAssistModal(f"Analyst Assistance #{row_index + 1}", body))
        except Exception as exc:
            self.status_box.update(f"Analyst assistance failed: {exc}")

    def action_export_current_results(self) -> None:
        self._export_rows(self.current_rows, suffix="all")

    def action_export_high_results(self) -> None:
        high_rows = [row for row in self.current_rows if str(row.get("severity", "")).lower() == "high"]
        self._export_rows(high_rows, suffix="high")

    def _export_rows(self, rows: List[dict], suffix: str) -> None:
        if not rows:
            self.status_box.update("No rows available to export.")
            return

        self.export_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        label = sanitize_filename(self.current_hunt_label or self.last_executed_hunt_label or "custom_query")

        json_path = self.export_dir / f"{label}_{suffix}_{stamp}.json"
        csv_path = self.export_dir / f"{label}_{suffix}_{stamp}.csv"

        export_rows_json(json_path, rows)
        columns = self.visible_columns or sort_columns([k for row in rows for k in row.keys() if k != "__statement"])
        export_rows_csv(csv_path, rows, columns)

        self.status_box.update(f"Exported {len(rows)} row(s) to {json_path.name} and {csv_path.name} in {self.export_dir}")

    def action_copy_selected_row(self) -> None:
        if not self.current_rows or not self.visible_columns:
            self.status_box.update("Nothing to copy yet.")
            return
        row_index = self._get_selected_row_index()
        if row_index is None:
            self.status_box.update("Select a row in the results table first.")
            return
        payload = self._format_row_details(self.current_rows[row_index], self.visible_columns)
        error = copy_text_to_clipboard(payload)
        self.status_box.update(error or f"Copied row {row_index + 1} to clipboard.")

    def action_copy_selected_cell(self) -> None:
        if not self.current_rows or not self.visible_columns:
            self.status_box.update("Nothing to copy yet.")
            return
        row_index = self._get_selected_row_index()
        col_index = self._get_selected_column_index()
        if row_index is None or col_index is None:
            self.status_box.update("Select a cell in the results table first.")
            return
        row = self.current_rows[row_index]
        col_name = self.visible_columns[col_index]
        value = self.format_cell(row.get(col_name, ""), col_name)
        error = copy_text_to_clipboard(value)
        self.status_box.update(error or f"Copied cell value from '{col_name}'.")

    def action_inspect_selected_row(self) -> None:
        if not self.current_rows or not self.visible_columns:
            self.status_box.update("No result row available to inspect.")
            return
        row_index = self._get_selected_row_index()
        if row_index is None:
            self.status_box.update("Select a row in the results table first.")
            return
        row = self.current_rows[row_index]
        body = self._format_row_details(row, self.visible_columns)
        self.push_screen(RowDetailModal(f"Row Details #{row_index + 1}", body))

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        row_index = event.cursor_row
        if 0 <= row_index < len(self.current_rows):
            row = self.current_rows[row_index]
            body = self._format_row_details(row, self.visible_columns)
            self.push_screen(RowDetailModal(f"Row Details #{row_index + 1}", body))

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        self.load_selected_preset(auto_run=True)

    def load_selected_preset(self, auto_run: bool = False) -> None:
        index = self.preset_list.index or 0
        label = list(RAW_HUNT_QUERIES.keys())[index]
        self.current_hunt_label = label
        self.is_timeline_view = False
        self.query_input.text = RAW_HUNT_QUERIES[label]
        self.current_sql = self.query_input.text
        if auto_run:
            self.run_query(self.query_input.text)
        else:
            self.status_box.update(f"Loaded preset '{label}'. Press Ctrl+Enter, Ctrl+R, F5, or click Run Query.")

    def run_query(self, sql: str) -> None:
        self.last_executed_sql = sql
        self.last_executed_hunt_label = self.current_hunt_label
        osquery_path = find_osquery()
        if not osquery_path:
            self.status_box.update("osqueryi was not found. Install osquery or add osqueryi.exe to PATH.")
            return

        statements = split_sql_statements(sql)
        if not statements:
            self.status_box.update("No SQL statement found.")
            return

        all_rows: List[dict] = []
        errors: List[str] = []

        for idx, statement in enumerate(statements, start=1):
            try:
                result = subprocess.run(
                    [osquery_path, "--json", statement],
                    capture_output=True,
                    text=True,
                    shell=False,
                    timeout=OSQUERY_TIMEOUT_SECONDS,
                )
            except subprocess.TimeoutExpired:
                errors.append(
                    f"Statement {idx}: query exceeded {OSQUERY_TIMEOUT_SECONDS}-second timeout."
                )
                continue
            except Exception as exc:
                errors.append(f"Statement {idx}: launch failed: {exc}")
                continue

            stderr = (result.stderr or "").strip()
            stdout = (result.stdout or "").strip()

            if result.returncode != 0:
                lowered = stderr.lower()
                extra_hint = ""
                for table_name, hint in UNSUPPORTED_TABLE_HINTS.items():
                    if table_name in lowered:
                        extra_hint = f" Hint: {hint}"
                        break
                errors.append(f"Statement {idx}: {stderr or 'osqueryi returned an error.'}{extra_hint}")
                continue

            try:
                parsed = json.loads(stdout) if stdout else []
            except json.JSONDecodeError as exc:
                errors.append(f"Statement {idx}: invalid JSON: {exc}")
                continue

            if not isinstance(parsed, list):
                errors.append(f"Statement {idx}: unexpected output format.")
                continue

            for row in parsed:
                if isinstance(row, dict):
                    row["__statement"] = statement
                    row = normalize_timeline_timestamp(row)
                    all_rows.append(enrich_row(row, self.current_hunt_label))

        self.render_rows(all_rows, len(statements), errors)

    def apply_severity_row_styles(self) -> None:
        if not self.current_rows or not self.visible_columns:
            return
        if "severity" not in self.visible_columns:
            return

        severity_col = self.visible_columns.index("severity")
        for row_index, row in enumerate(self.current_rows):
            severity = str(row.get("severity", "")).strip().lower()
            if severity == "high":
                component_class = "sev-high"
            elif severity == "medium":
                component_class = "sev-medium"
            else:
                component_class = "sev-low"

            for col_index in range(len(self.visible_columns)):
                try:
                    self.results_table.add_class(row_index, col_index, component_class)
                except Exception:
                    pass

            try:
                self.results_table.add_class(row_index, severity_col, component_class)
            except Exception:
                pass

    def render_rows(self, rows: List[dict], statement_count: int, errors: List[str]) -> None:
        table = self.results_table
        table.clear(columns=True)
        self.current_rows = rows
        self.visible_columns = []

        if not rows and not errors:
            self.status_box.update(
                f"No results returned from {statement_count} statement(s). "
                "For evented tables like powershell_events, logging may be disabled. Some registry paths may also need Administrator access."
            )
            return

        if rows:
            keyset = set()
            for row in rows:
                keyset.update(row.keys())
            keyset.discard("__statement")
            self.visible_columns = sort_columns(list(keyset))

        if self.visible_columns:
            table.add_columns(*self.visible_columns)
            for row in rows:
                values = [self.format_cell(row.get(col, ""), col) for col in self.visible_columns]
                table.add_row(*values)
            self.apply_severity_row_styles()

        if errors:
            preview = " | ".join(errors[:2])
            if len(errors) > 2:
                preview += f" | +{len(errors) - 2} more"
            self.status_box.update(f"Loaded {len(rows)} row(s) from {statement_count} statement(s). Errors: {preview}")
        else:
            highs = sum(1 for row in rows if row.get("severity") == "High")
            meds = sum(1 for row in rows if row.get("severity") == "Medium")
            self.status_box.update(
                f"Loaded {len(rows)} row(s). High: {highs} | Medium: {meds}. "
                "Use C to copy, I to inspect, F6 for analyst assistance, Ctrl+E to export all, Ctrl+Shift+E for High-only, and Ctrl+T for timeline."
            )

    def _get_selected_row_index(self) -> Optional[int]:
        try:
            row_index = self.results_table.cursor_row
        except Exception:
            return None
        if row_index is None or row_index < 0 or row_index >= len(self.current_rows):
            return None
        return row_index

    def _get_selected_column_index(self) -> Optional[int]:
        try:
            column_index = self.results_table.cursor_column
        except Exception:
            return None
        if column_index is None or column_index < 0 or column_index >= len(self.visible_columns):
            return None
        return column_index

    def _format_row_details(self, row: dict, columns: List[str]) -> str:
        lines = []
        for column in columns:
            value = row.get(column, "")
            if value is None:
                value = ""
            if isinstance(value, (list, dict)):
                value = json.dumps(value, ensure_ascii=False, indent=2)
            else:
                value = self.format_cell(value, column)
            lines.append(f"{column}: {value}")
        return "\n".join(lines)

    @staticmethod
    def format_cell(value, column_name: Optional[str] = None) -> str:
        if value is None:
            return ""
        if isinstance(value, (list, dict)):
            return json.dumps(value, ensure_ascii=False)

        text_value = str(value)

        if column_name and column_name in TIMESTAMP_FIELDS:
            return format_timestamp(value)

        try:
            val_int = int(float(text_value))
            if 1_000_000_000 < val_int < 2_500_000_000:
                return format_timestamp(val_int)
        except Exception:
            pass

        return text_value


if __name__ == "__main__":
    SilentEyeDFIR().run()
