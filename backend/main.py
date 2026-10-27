import ipaddress
import json
import os
import re
from pathlib import Path
from typing import Any

import pandas as pd
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Path as ApiPath, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend.firebase_auth import verify_firebase_token

load_dotenv()

ROOT_DIR = Path(__file__).resolve().parent.parent

# NexusAI Sentinel writes these files after analyzing Windows Security CSV logs.
SENTINEL_RESULTS_DIR = Path(
    os.getenv(
        "NEXUSAI_SENTINEL_RESULTS_DIR",
        str(ROOT_DIR / "data" / "sentinel_demo_results"),
    )
)
SENTINEL_ALERTS_FILE = Path(
    os.getenv(
        "NEXUSAI_SENTINEL_ALERTS_FILE",
        str(SENTINEL_RESULTS_DIR / "windows_security_alerts.csv"),
    )
)
SENTINEL_SUMMARY_FILE = Path(
    os.getenv(
        "NEXUSAI_SENTINEL_SUMMARY_FILE",
        str(SENTINEL_RESULTS_DIR / "windows_security_summary.json"),
    )
)

# Backward-compatible fallback for the older analytics dataset.
LEGACY_DATA_FILE = Path(
    os.getenv("NEXUSAI_DATA_FILE", str(ROOT_DIR / "data" / "analysis_results.csv"))
)

app = FastAPI(
    title="NexusAI Sentinel Security Analytics API",
    version="1.2.0",
    description=(
        "Authenticated API for reviewing NexusAI Sentinel alerts generated from "
        "Windows Security event logs, searching source IPs, and summarizing activity."
    ),
)

DEFAULT_ORIGINS = [
    # Production frontend domains
    "https://smartech-ai.netlify.app",
    "https://smartech-ai.pages.dev",
    "https://cbce2f2d.smartech-ai.pages.dev",
    # Local development frontends
    "http://localhost:5173",
    "http://localhost:5176",
    "http://localhost:5177",
    "http://localhost:5178",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5176",
    "http://127.0.0.1:5177",
    "http://127.0.0.1:5178",
]
CONFIGURED_ORIGINS = [
    item.strip()
    for item in os.getenv("FRONTEND_ORIGINS", "").split(",")
    if item.strip()
]
ALLOWED_ORIGINS = list(dict.fromkeys(DEFAULT_ORIGINS + CONFIGURED_ORIGINS))

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    # Permit the main Pages domain and preview deployments for this project only.
    allow_origin_regex=r"https://([a-z0-9-]+\.)?smartech-ai\.pages\.dev",
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
)


class AssistantRequest(BaseModel):
    question: str = Field(min_length=1, max_length=2000)


def active_alerts_file() -> Path:
    """Prefer Sentinel output; use the old analytics CSV only as a fallback."""
    if SENTINEL_ALERTS_FILE.is_file():
        return SENTINEL_ALERTS_FILE
    if LEGACY_DATA_FILE.is_file():
        return LEGACY_DATA_FILE
    # Return the expected Sentinel path so status/error handling stays predictable.
    return SENTINEL_ALERTS_FILE


def read_alerts() -> list[dict[str, Any]]:
    """Read Sentinel alerts or the configured legacy analytics CSV."""
    data_file = active_alerts_file()
    if not data_file.is_file():
        return []

    try:
        frame = pd.read_csv(data_file, dtype=str, keep_default_na=False)
        return frame.to_dict(orient="records")
    except (OSError, UnicodeError, pd.errors.ParserError, pd.errors.EmptyDataError) as exc:
        raise HTTPException(
            status_code=500,
            detail="The security analysis data file could not be read.",
        ) from exc


def read_sentinel_summary() -> dict[str, Any]:
    """Read summary metadata emitted by the Sentinel analysis engine."""
    if not SENTINEL_SUMMARY_FILE.is_file():
        return {}
    try:
        with SENTINEL_SUMMARY_FILE.open("r", encoding="utf-8") as file:
            value = json.load(file)
        return value if isinstance(value, dict) else {}
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise HTTPException(
            status_code=500,
            detail="The Sentinel summary file could not be read.",
        ) from exc


def _column_token(value: Any) -> str:
    """Normalize column labels so Title, title, and alert_title can be matched."""
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def first_value(row: dict[str, Any], *names: str) -> Any:
    """Return the first non-empty value, matching CSV column names case-insensitively."""
    indexed = {_column_token(key): value for key, value in row.items()}
    for name in names:
        value = indexed.get(_column_token(name))
        if value is not None and str(value).strip():
            return value
    return ""


def extract_accounts(events: list[dict[str, Any]]) -> list[str]:
    """Collect actual account names without counting alert summaries as accounts."""
    accounts: set[str] = set()
    for event in events:
        raw = str(event.get("username", "")).strip()
        if not raw or raw.lower() in {"unknown", "n/a", "none"}:
            continue
        for candidate in raw.split(","):
            name = candidate.strip()
            if not name or re.fullmatch(r"\d+\s+distinct\s+accounts?", name, flags=re.I):
                continue
            if name.lower() in {"unknown", "n/a", "none"}:
                continue
            accounts.add(name)
    return sorted(accounts, key=str.casefold)


def normalize_risk(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in {
        "critical", "high", "severe", "ط¹ط§ظ„ظٹ", "ط¹ط§ظ„ظٹط©", "ظ…ط±طھظپط¹", "ظ…ط±طھظپط¹ط©"
    }:
        return "High"
    if text in {"medium", "moderate", "ظ…طھظˆط³ط·", "ظ…طھظˆط³ط·ط©"}:
        return "Medium"
    if text in {"low", "informational", "info", "ظ…ظ†ط®ظپط¶", "ظ…ظ†ط®ظپط¶ط©"}:
        return "Low"
    return "Unknown"


def safe_nonnegative_int(value: Any) -> int | None:
    try:
        number = float(str(value).strip())
        if not number.is_integer() or number < 0:
            return None
        return int(number)
    except (TypeError, ValueError, OverflowError):
        return None


def count_from_summary(summary: dict[str, Any], *keys: str) -> int | None:
    for key in keys:
        count = safe_nonnegative_int(summary.get(key))
        if count is not None:
            return count
    return None


def recommendation_for(risk: str, event: str, failed_login: bool) -> str:
    if failed_login and risk == "High":
        return (
            "Investigate repeated failed-login activity, verify the account and source, "
            "and follow your organization's incident-response process."
        )
    if failed_login and risk == "Medium":
        return "Review authentication logs for this source and check for related account activity."
    if failed_login:
        return "Monitor authentication activity and correlate with other available logs."
    if risk == "High":
        return "Review the event details and validate its impact before taking action."
    if risk == "Medium":
        return "Review related events and confirm whether the activity is expected."
    if risk == "Low":
        return "Record the event and continue routine monitoring."
    return "Review the source record; there is insufficient information to recommend a risk-specific action."


def normalize_event(row: dict[str, Any]) -> dict[str, Any]:
    """Normalize legacy rows and Windows Sentinel alert rows for the frontend."""
    result = dict(row)

    event = str(
        first_value(
            row,
            "alert_name",
            "title",
            "rule_name",
            "event_type",
            "Event Type",
            "event",
            "action",
            "rule_id",
            "EventID",
            "event_id",
        )
        or "Unknown event"
    ).strip()
    username = str(
        first_value(
            row,
            "username",
            "TargetUserName",
            "target_user",
            "user",
            "User",
            "account",
            "account_name",
        )
        or "Unknown"
    ).strip()
    source_ip = str(
        first_value(
            row,
            "source_ip",
            "IpAddress",
            "source_ip_address",
            "ip_address",
            "ip",
            "Source IP",
        )
        or ""
    ).strip()
    timestamp = str(
        first_value(
            row,
            "timestamp",
            "TimeCreated",
            "first_seen_utc",
            "first_seen",
            "window_start",
            "StartTime",
            "start_time",
            "time",
            "Timestamp",
            "last_seen_utc",
            "last_seen",
        )
        or "N/A"
    ).strip()
    risk = normalize_risk(
        first_value(row, "risk_level", "severity", "risk", "Risk Level", "priority")
    )
    # Sentinel CSV uses Count for the number of records matched by an alert rule.
    # Counts from overlapping alert rules must not be added together.
    attempts_raw = first_value(
        row,
        "failed_attempts",
        "failed_attempt_count",
        "Failed Attempts",
        "Count",
        "evidence_event_count",
        "record_count",
        "event_count",
        "attempt_count",
    )
    attempts = safe_nonnegative_int(attempts_raw) if str(attempts_raw).strip() else None

    result["event_type"] = event or "Unknown event"
    result["username"] = username or "Unknown"
    result["source_ip"] = source_ip or "N/A"
    result["timestamp"] = timestamp or "N/A"
    result["risk_level"] = risk
    if attempts is not None:
        result["failed_attempts"] = attempts

    event_id = str(first_value(row, "EventID", "event_id", "event_id_number")).strip()
    signals = " ".join(
        str(first_value(row, key))
        for key in (
            "rule_id", "rule_name", "alert_name", "title", "description", "Message",
            "event_type", "EventType", "event", "action"
        )
    ).lower()
    # AUTH-003 is a successful logon correlated with earlier failures; it is
    # not itself a failed-login event. Avoid classifying it as failed merely
    # because the title mentions the prior failed attempts.
    if "auth-003" in signals or "successful logon" in signals:
        is_failed_login = False
    else:
        is_failed_login = (
            event_id == "4625"
            or "auth-001" in signals
            or "auth-002" in signals
            or "failed" in signals
            or "failure" in signals
            or "logon failure" in signals
            or "failed logon" in signals
            or "ظپط´ظ„" in signals
        )
    result["is_failed_login"] = bool(is_failed_login)

    supplied_recommendation = first_value(
        row, "recommendation", "action_recommendation", "recommended_action"
    )
    result["recommendation"] = (
        str(supplied_recommendation).strip()
        if supplied_recommendation
        else recommendation_for(risk, event, is_failed_login)
    )
    return result


def risk_priority(risk: str) -> int:
    return {"Unknown": 0, "Low": 1, "Medium": 2, "High": 3}.get(risk, 0)


def is_failed_login(row: dict[str, Any]) -> bool:
    return bool(row.get("is_failed_login"))


def normalize_ip_or_400(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail="Invalid IP address. Enter a valid IPv4 or IPv6 address.",
        ) from exc


def get_normalized_events() -> list[dict[str, Any]]:
    return [normalize_event(row) for row in read_alerts()]


@app.get("/", tags=["Service"])
def root() -> dict[str, str]:
    return {
        "project": "NexusAI Sentinel",
        "status": "running",
        "message": "NexusAI Sentinel Security Analytics API is ready.",
        "docs": "/docs",
    }


@app.get("/health", tags=["Service"])
def health() -> dict[str, str]:
    return {"status": "healthy", "project": "NexusAI Sentinel"}


@app.get("/api/sentinel/status", tags=["Sentinel"])
def get_sentinel_status(
    current_user: dict = Depends(verify_firebase_token),
) -> dict[str, Any]:
    alerts_file = active_alerts_file()
    return {
        "sentinel_alerts_available": SENTINEL_ALERTS_FILE.is_file(),
        "sentinel_summary_available": SENTINEL_SUMMARY_FILE.is_file(),
        "active_data_source": (
            "NexusAI Sentinel" if alerts_file == SENTINEL_ALERTS_FILE else "Legacy analytics CSV"
        ) if alerts_file.is_file() else "No data file found",
        "alerts_count": len(read_alerts()),
        "message": (
            "Sentinel results are connected."
            if SENTINEL_ALERTS_FILE.is_file()
            else "Sentinel alert output was not found at the configured location."
        ),
    }


@app.get("/api/sentinel/summary", tags=["Sentinel"])
def get_sentinel_summary(
    current_user: dict = Depends(verify_firebase_token),
) -> dict[str, Any]:
    summary = read_sentinel_summary()
    return {
        "available": bool(summary),
        "summary": summary,
        "alerts_count": len(read_alerts()),
        "data_source": "windows_security_summary.json" if summary else "not available",
    }


@app.get("/api/summary", tags=["Analytics"])
def get_summary(
    current_user: dict = Depends(verify_firebase_token),
) -> dict[str, int]:
    events = get_normalized_events()
    source_summary = read_sentinel_summary() if SENTINEL_ALERTS_FILE.is_file() else {}

    total_events = count_from_summary(
        source_summary, "total_events", "valid_events", "events_analyzed", "total_log_events"
    )
    failed_logins = count_from_summary(
        source_summary,
        "failed_login_events", "failed_logon_events", "failed_logons", "failed_logins",
        "failed_4625_events",
    )

    return {
        # Prefer actual source-event totals from the engine summary. If unavailable,
        # fall back to the number of rows in the active CSV.
        "total_events": total_events if total_events is not None else len(events),
        "failed_login_events": (
            failed_logins if failed_logins is not None
            else sum(1 for row in events if is_failed_login(row))
        ),
        "high_risk_events": sum(1 for row in events if row["risk_level"] == "High"),
        "medium_risk_events": sum(1 for row in events if row["risk_level"] == "Medium"),
        "low_risk_events": sum(1 for row in events if row["risk_level"] == "Low"),
        "unknown_risk_events": sum(1 for row in events if row["risk_level"] == "Unknown"),
    }


@app.get("/api/alerts", tags=["Analytics"])
def get_alerts(
    current_user: dict = Depends(verify_firebase_token),
    risk: str | None = Query(
        default=None, description="Optional risk filter: High, Medium, Low, Unknown"
    ),
    limit: int = Query(default=200, ge=1, le=1000),
) -> list[dict[str, Any]]:
    events = get_normalized_events()
    if risk:
        normalized_filter = normalize_risk(risk)
        if normalized_filter == "Unknown" and risk.strip().lower() not in {
            "unknown", "ط؛ظٹط± ظ…ط¹ط±ظˆظپ"
        }:
            raise HTTPException(status_code=400, detail="Invalid risk filter.")
        events = [row for row in events if row["risk_level"] == normalized_filter]
    events.sort(key=lambda row: str(row.get("timestamp", "")), reverse=True)
    return events[:limit]


@app.get(
    "/api/ip-analysis/{ip_address}",
    tags=["IP Analysis"],
    summary="Analyze an IP address against available security logs",
)
def analyze_ip(
    ip_address: str = ApiPath(
        ..., min_length=2, max_length=45, description="IPv4 or IPv6 address"
    ),
    current_user: dict = Depends(verify_firebase_token),
) -> dict[str, Any]:
    searched_ip = normalize_ip_or_400(ip_address)
    events = get_normalized_events()

    matching_events = []
    for event in events:
        source_ip = str(event.get("source_ip", "")).strip()
        if not source_ip or source_ip == "N/A":
            continue
        try:
            normalized_source = str(ipaddress.ip_address(source_ip))
        except ValueError:
            continue
        if normalized_source == searched_ip:
            matching_events.append(event)

    matching_events.sort(key=lambda row: str(row.get("timestamp", "")), reverse=True)
    failed_events = [row for row in matching_events if is_failed_login(row)]

    recorded_counts = [
        count
        for row in failed_events
        if (count := safe_nonnegative_int(row.get("failed_attempts"))) is not None
    ]
    # Sentinel alerts can overlap (e.g., AUTH-001 and AUTH-002 may describe
    # the same Event 4625 rows). Use the largest matching count rather than
    # summing alert counts, which would overstate the number of attempts.
    attempts_recorded = max(recorded_counts, default=None)
    rows_with_attempt_counts = len(recorded_counts)

    risk_level = max(
        (row["risk_level"] for row in matching_events),
        key=risk_priority,
        default="Unknown",
    )
    usernames = extract_accounts(matching_events)

    return {
        "ip_address": searched_ip,
        "found": bool(matching_events),
        "total_events": len(matching_events),
        "failed_login_events": len(failed_events),
        "failed_attempts_recorded": attempts_recorded,
        "rows_with_attempt_counts": rows_with_attempt_counts,
        "risk_level": risk_level,
        "usernames": usernames,
        "events": matching_events,
        "analysis_basis": "Configured NexusAI Sentinel alert CSV or legacy analytics CSV",
        "risk_note": (
            "Risk is a triage indicator based on recorded alert classifications, "
            "not proof that an attack occurred."
        ),
        "attempts_note": (
            "This value is the largest evidence_event_count/Count reported by a matching "
            "failed-login alert, "
            "not a deduplicated forensic total. Overlapping alert rules may describe the "
            "same records, so their counts are not added together."
        ),
        "message": (
            "Matching events or alerts found in the available data."
            if matching_events
            else "No matching events or alerts were found in the available data."
        ),
    }


@app.post("/api/assistant", tags=["Assistant"])
def assistant(
    request: AssistantRequest,
    current_user: dict = Depends(verify_firebase_token),
) -> dict[str, str]:
    question = request.question.strip()
    if not question:
        raise HTTPException(status_code=400, detail="Enter a question first.")

    # Transparent placeholder: no external AI model is connected yet.
    return {
        "answer": (
            "The NexusAI assistant is not connected to an AI model yet, so it has not "
            "generated an AI answer. Your question was received: " + question
        )
    }
