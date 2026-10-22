

import ipaddress
import os
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

DATA_FILE = Path(
    os.getenv(
        "NEXUSAI_DATA_FILE",
        str(ROOT_DIR / "data" / "analysis_results.csv"),
    )
)

app = FastAPI(
    title="NexusAI Security Analytics API",
    version="1.1.0",
    description=(
        "Authenticated API for searching IP addresses in security logs, "
        "reviewing events, and summarizing observed authentication activity."
    ),
)

DEFAULT_ORIGINS = [
    "https://smartech-ai.netlify.app",
    "http://localhost:5173",
    "http://localhost:5176",
    "http://localhost:5177",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5176",
    "http://127.0.0.1:5177",
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
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
)


class AssistantRequest(BaseModel):
    question: str = Field(min_length=1, max_length=2000)


def read_alerts() -> list[dict[str, Any]]:
    """Read analyzed security events from the configured CSV file."""
    if not DATA_FILE.exists():
        return []

    try:
        frame = pd.read_csv(DATA_FILE, dtype=str, keep_default_na=False)
        return frame.to_dict(orient="records")
    except (OSError, UnicodeError, pd.errors.ParserError, pd.errors.EmptyDataError) as exc:
        raise HTTPException(
            status_code=500,
            detail="The security analysis data file could not be read.",
        ) from exc


def first_value(row: dict[str, Any], *names: str) -> Any:
    """Return the first non-empty value from supported column aliases."""
    for name in names:
        value = row.get(name)
        if value is not None and str(value).strip():
            return value
    return ""


def normalize_risk(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in {"critical", "high", "عالي", "عالية", "مرتفع", "مرتفعة"}:
        return "High"
    if text in {"medium", "moderate", "متوسط", "متوسطة"}:
        return "Medium"
    if text in {"low", "منخفض", "منخفضة"}:
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
    """Normalize known column names without discarding original CSV fields."""
    result = dict(row)
    event = str(first_value(row, "event_type", "event", "Event Type", "action") or "Unknown event").strip()
    username = str(first_value(row, "username", "user", "User", "account") or "Unknown").strip()
    source_ip = str(first_value(row, "source_ip", "ip_address", "ip", "Source IP") or "").strip()
    timestamp = str(first_value(row, "timestamp", "time", "Timestamp") or "N/A").strip()
    risk = normalize_risk(first_value(row, "risk_level", "risk", "Risk Level", "severity"))
    attempts_raw = first_value(row, "failed_attempts", "failed_attempt_count", "Failed Attempts")
    attempts = safe_nonnegative_int(attempts_raw) if str(attempts_raw).strip() else None

    result["event_type"] = event
    result["username"] = username or "Unknown"
    result["source_ip"] = source_ip or "N/A"
    result["timestamp"] = timestamp or "N/A"
    result["risk_level"] = risk
    if attempts is not None:
        result["failed_attempts"] = attempts

    event_lower = event.lower()
    is_failed_login = (
        ("login" in event_lower and ("fail" in event_lower or "denied" in event_lower))
        or "failed" in event_lower
        or "فشل" in event
    )
    result["is_failed_login"] = bool(is_failed_login)

    supplied_recommendation = first_value(row, "recommendation", "action_recommendation")
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
        "project": "NexusAI",
        "status": "running",
        "message": "NexusAI Security Analytics API is ready.",
        "docs": "/docs",
    }


@app.get("/health", tags=["Service"])
def health() -> dict[str, str]:
    return {"status": "healthy", "project": "NexusAI"}


@app.get("/api/summary", tags=["Analytics"])
def get_summary(
    current_user: dict = Depends(verify_firebase_token),
) -> dict[str, int]:
    events = get_normalized_events()
    return {
        "total_events": len(events),
        "failed_login_events": sum(1 for row in events if is_failed_login(row)),
        "high_risk_events": sum(1 for row in events if row["risk_level"] == "High"),
        "medium_risk_events": sum(1 for row in events if row["risk_level"] == "Medium"),
        "low_risk_events": sum(1 for row in events if row["risk_level"] == "Low"),
        "unknown_risk_events": sum(1 for row in events if row["risk_level"] == "Unknown"),
    }


@app.get("/api/alerts", tags=["Analytics"])
def get_alerts(
    current_user: dict = Depends(verify_firebase_token),
    risk: str | None = Query(default=None, description="Optional risk filter: High, Medium, Low, Unknown"),
    limit: int = Query(default=200, ge=1, le=1000),
) -> list[dict[str, Any]]:
    events = get_normalized_events()
    if risk:
        normalized_filter = normalize_risk(risk)
        if normalized_filter == "Unknown" and risk.strip().lower() not in {"unknown", "غير معروف"}:
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
    ip_address: str = ApiPath(..., min_length=2, max_length=45, description="IPv4 or IPv6 address"),
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

    # These are values recorded in individual rows, not necessarily unique attempts.
    attempts_recorded = 0
    rows_with_attempt_counts = 0
    for row in failed_events:
        count = safe_nonnegative_int(row.get("failed_attempts"))
        if count is not None:
            attempts_recorded += count
            rows_with_attempt_counts += 1

    risk_level = max(
        (row["risk_level"] for row in matching_events),
        key=risk_priority,
        default="Unknown",
    )
    usernames = sorted({
        str(row.get("username", "")).strip()
        for row in matching_events
        if str(row.get("username", "")).strip()
        and str(row.get("username", "")).strip() != "Unknown"
    })

    return {
        "ip_address": searched_ip,
        "found": bool(matching_events),
        "total_events": len(matching_events),
        "failed_login_events": len(failed_events),
        "failed_attempts_recorded": attempts_recorded if rows_with_attempt_counts else None,
        "rows_with_attempt_counts": rows_with_attempt_counts,
        "risk_level": risk_level,
        "usernames": usernames,
        "events": matching_events,
        "analysis_basis": "Configured CSV security logs only",
        "risk_note": (
            "Risk is taken from recorded event classifications. It is a triage indicator, "
            "not proof that an attack occurred."
        ),
        "attempts_note": (
            "The failed_attempts total adds values from matching failed-event rows. "
            "If source values are cumulative, this sum can double-count attempts."
        ),
        "message": (
            "Matching events found in the available logs."
            if matching_events
            else "No matching events were found in the available logs."
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

    # Deliberately transparent: no external AI provider is connected.
    return {
        "answer": (
            "The NexusAI assistant is not connected to an AI model yet, so it has not "
            "generated an AI answer. Your question was received: " + question
        )
    }
