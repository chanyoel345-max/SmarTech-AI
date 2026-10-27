import hashlib
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Path as ApiPath, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

try:
    from sklearn.ensemble import IsolationForest
except ImportError:  # Keep the API running even if the optional ML package is missing.
    IsolationForest = None

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

# Live Windows Security events received from the optional local collector.
# Render's filesystem is ephemeral on the free tier; use a persistent disk path
# via NEXUSAI_LIVE_EVENTS_DB if one is configured.
LIVE_EVENTS_DB = Path(
    os.getenv(
        "NEXUSAI_LIVE_EVENTS_DB",
        str(Path(tempfile.gettempdir()) / "nexusai_live_events.sqlite3"),
    )
)
INGEST_TOKEN = os.getenv("NEXUSAI_INGEST_TOKEN", "").strip()

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


class WindowsEventBatch(BaseModel):
    events: list[dict[str, Any]] = Field(min_length=1, max_length=100)


def active_alerts_file() -> Path:
    """Prefer Sentinel output; use the old analytics CSV only as a fallback."""
    if SENTINEL_ALERTS_FILE.is_file():
        return SENTINEL_ALERTS_FILE
    if LEGACY_DATA_FILE.is_file():
        return LEGACY_DATA_FILE
    # Return the expected Sentinel path so status/error handling stays predictable.
    return SENTINEL_ALERTS_FILE


def _connect_live_db() -> sqlite3.Connection:
    LIVE_EVENTS_DB.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(LIVE_EVENTS_DB), timeout=10)
    connection.execute(
        "CREATE TABLE IF NOT EXISTS live_events ("
        "event_uid TEXT PRIMARY KEY, payload TEXT NOT NULL, received_at TEXT NOT NULL)"
    )
    connection.commit()
    return connection


def read_live_events(limit: int = 5000) -> list[dict[str, Any]]:
    """Read recent collector events from local SQLite storage."""
    connection: sqlite3.Connection | None = None
    try:
        connection = _connect_live_db()
        rows = connection.execute(
            "SELECT payload FROM live_events ORDER BY rowid DESC LIMIT ?", (limit,)
        ).fetchall()
        return [json.loads(row[0]) for row in reversed(rows)]
    except (OSError, sqlite3.Error, json.JSONDecodeError):
        # A live collector database failure should not take down CSV analytics.
        return []
    finally:
        if connection is not None:
            connection.close()


def _save_live_events(rows: list[dict[str, Any]]) -> int:
    accepted = 0
    connection = _connect_live_db()
    try:
        for raw in rows:
            record = dict(raw)
            host = str(record.get("source_host", "unknown-host")).strip() or "unknown-host"
            record_id = str(record.get("record_id", "")).strip()
            identity = f"{host}|{record_id}" if record_id else json.dumps(
                record, sort_keys=True, ensure_ascii=False, default=str
            )
            event_uid = hashlib.sha256(identity.encode("utf-8")).hexdigest()
            record["source_type"] = "windows_live"
            record["received_at"] = datetime.now(timezone.utc).isoformat()
            cursor = connection.execute(
                "INSERT OR IGNORE INTO live_events(event_uid, payload, received_at) VALUES (?, ?, ?)",
                (event_uid, json.dumps(record, ensure_ascii=False, default=str), record["received_at"]),
            )
            accepted += max(cursor.rowcount, 0)
        connection.commit()
    finally:
        connection.close()
    return accepted


def read_alerts() -> list[dict[str, Any]]:
    """Read Sentinel/legacy CSV rows and append real Windows events received by the collector."""
    records: list[dict[str, Any]] = []
    data_file = active_alerts_file()
    if data_file.is_file():
        try:
            frame = pd.read_csv(data_file, dtype=str, keep_default_na=False)
            records = frame.to_dict(orient="records")
        except (OSError, UnicodeError, pd.errors.ParserError, pd.errors.EmptyDataError) as exc:
            raise HTTPException(
                status_code=500,
                detail="The security analysis data file could not be read.",
            ) from exc
    records.extend(read_live_events())
    return records


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
    if text in {"critical", "high", "severe", "عالي", "عالية", "مرتفع", "مرتفعة"}:
        return "High"
    if text in {"medium", "moderate", "متوسط", "متوسطة"}:
        return "Medium"
    if text in {"low", "informational", "info", "منخفض", "منخفضة"}:
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
    """Normalize rows and explicitly label whether they are demo or live Windows data."""
    result = dict(row)
    source_type = str(row.get("source_type", "")).strip().lower()
    if source_type != "windows_live":
        source_type = "demo"
    result["source_type"] = source_type
    result["source_label"] = "أحداث Windows مباشرة" if source_type == "windows_live" else "بيانات تجريبية"

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

    live_rows = [row for row in events if row.get("source_type") == "windows_live"]
    live_failed = sum(1 for row in live_rows if is_failed_login(row))

    return {
        # Keep the source summary as the baseline, and add any newly ingested live events.
        "total_events": (total_events if total_events is not None else len(events) - len(live_rows)) + len(live_rows),
        "failed_login_events": (
            (failed_logins if failed_logins is not None else sum(1 for row in events if is_failed_login(row) and row.get("source_type") != "windows_live"))
            + live_failed
        ),
        "high_risk_events": sum(1 for row in events if row["risk_level"] == "High"),
        "medium_risk_events": sum(1 for row in events if row["risk_level"] == "Medium"),
        "low_risk_events": sum(1 for row in events if row["risk_level"] == "Low"),
        "unknown_risk_events": sum(1 for row in events if row["risk_level"] == "Unknown"),
        "live_windows_events": len(live_rows),
        "demo_events": sum(1 for row in events if row.get("source_type") != "windows_live"),
    }


@app.get("/api/alerts", tags=["Analytics"])
def get_alerts(
    current_user: dict = Depends(verify_firebase_token),
    risk: str | None = Query(
        default=None, description="Optional risk filter: High, Medium, Low, Unknown"
    ),
    limit: int = Query(default=200, ge=1, le=1000),
    source: str = Query(default="all", description="Data source: all, demo, or windows_live"),
) -> list[dict[str, Any]]:
    events = get_normalized_events()
    normalized_source = source.strip().lower()
    if normalized_source not in {"all", "demo", "windows_live"}:
        raise HTTPException(status_code=400, detail="Invalid source filter. Use all, demo, or windows_live.")
    if normalized_source != "all":
        events = [row for row in events if row.get("source_type") == normalized_source]
    if risk:
        normalized_filter = normalize_risk(risk)
        if normalized_filter == "Unknown" and risk.strip().lower() not in {
            "unknown", "غير معروف", "غير محدد", "غير محددة"
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


@app.post("/api/ingest/windows-events", tags=["Live Monitoring"])
def ingest_windows_events(
    batch: WindowsEventBatch,
    x_nexusai_ingest_token: str = Header(default="", alias="X-NexusAI-Ingest-Token"),
) -> dict[str, Any]:
    """Receive 4624/4625 Windows Security events from the local collector using a shared secret."""
    if not INGEST_TOKEN:
        raise HTTPException(
            status_code=503,
            detail="Live ingestion is not configured. Set NEXUSAI_INGEST_TOKEN in the backend environment.",
        )
    if not secrets.compare_digest(x_nexusai_ingest_token, INGEST_TOKEN):
        raise HTTPException(status_code=401, detail="Invalid collector token.")

    cleaned: list[dict[str, Any]] = []
    skipped = 0
    for raw in batch.events:
        event_id = str(raw.get("event_id", raw.get("EventID", ""))).strip()
        if event_id not in {"4624", "4625"}:
            skipped += 1
            continue
        username = str(raw.get("username", raw.get("TargetUserName", "Unknown"))).strip() or "Unknown"
        source_ip = str(raw.get("source_ip", raw.get("ip_address", raw.get("IpAddress", "N/A")))).strip() or "N/A"
        timestamp = str(raw.get("timestamp", "")).strip() or datetime.now(timezone.utc).isoformat()
        is_failed = event_id == "4625"
        cleaned.append({
            "event_id": event_id,
            "record_id": str(raw.get("record_id", "")).strip(),
            "source_host": str(raw.get("source_host", "Unknown host")).strip() or "Unknown host",
            "timestamp": timestamp,
            "username": username,
            "source_ip": source_ip,
            "event_type": "login_failed" if is_failed else "login_success",
            "failed_attempts": 1 if is_failed else 0,
            "risk_level": "Low",
            "is_failed_login": is_failed,
            "recommendation": recommendation_for("Low", "login_failed" if is_failed else "login_success", is_failed),
        })

    accepted = _save_live_events(cleaned) if cleaned else 0
    return {
        "accepted": accepted,
        "skipped": skipped,
        "received": len(batch.events),
        "stored_live_events": len(read_live_events()),
        "message": "Windows Security events received. Repeated event IDs from the same host are ignored.",
    }


def _hour_feature(value: Any) -> float:
    text = str(value or "")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return float(parsed.hour) + float(parsed.minute) / 60.0
    except (TypeError, ValueError):
        return 12.0


@app.get("/api/ai/anomalies", tags=["AI Analytics"])
def analyze_anomalies(
    current_user: dict = Depends(verify_firebase_token),
) -> dict[str, Any]:
    """Rank available alert/event rows with an Isolation Forest anomaly detector."""
    if IsolationForest is None:
        raise HTTPException(
            status_code=503,
            detail="scikit-learn is not installed on the backend. Add scikit-learn to the backend requirements and redeploy.",
        )

    events = get_normalized_events()
    if len(events) < 4:
        raise HTTPException(
            status_code=422,
            detail=f"The anomaly detector needs at least 4 records; only {len(events)} are available.",
        )

    ip_failures: dict[str, int] = {}
    user_failures: dict[str, int] = {}
    for row in events:
        if is_failed_login(row):
            ip = str(row.get("source_ip", "N/A")).strip() or "N/A"
            username = str(row.get("username", "Unknown")).strip() or "Unknown"
            ip_failures[ip] = ip_failures.get(ip, 0) + 1
            user_failures[username] = user_failures.get(username, 0) + 1

    feature_rows: list[list[float]] = []
    for row in events:
        ip = str(row.get("source_ip", "N/A")).strip() or "N/A"
        username = str(row.get("username", "Unknown")).strip() or "Unknown"
        attempts = safe_nonnegative_int(row.get("failed_attempts")) or 0
        failed = is_failed_login(row)
        feature_rows.append([
            float(attempts),
            float(failed),
            float(risk_priority(str(row.get("risk_level", "Unknown")))),
            float(ip_failures.get(ip, 0) if failed else 0),
            float(user_failures.get(username, 0) if failed else 0),
            _hour_feature(row.get("timestamp")),
        ])

    model = IsolationForest(n_estimators=100, contamination="auto", random_state=42)
    model.fit(feature_rows)
    decision_values = [float(value) for value in model.decision_function(feature_rows)]
    predictions = [int(value) for value in model.predict(feature_rows)]
    order = sorted(range(len(events)), key=lambda index: decision_values[index])
    relative_scores = {index: round(100 * (len(order) - 1 - rank) / max(len(order) - 1, 1)) for rank, index in enumerate(order)}

    ranked: list[dict[str, Any]] = []
    for index, row in enumerate(events):
        failed = is_failed_login(row)
        ip = str(row.get("source_ip", "N/A")).strip() or "N/A"
        username = str(row.get("username", "Unknown")).strip() or "Unknown"
        attempts = safe_nonnegative_int(row.get("failed_attempts")) or 0
        reasons: list[str] = []
        if attempts >= 5:
            reasons.append(f"عدد المحاولات المسجل في الصف مرتفع ({attempts}).")
        if failed and ip_failures.get(ip, 0) >= 2:
            reasons.append(f"تكرر مصدر IP في {ip_failures[ip]} سجلات دخول فاشل.")
        if username.lower() in {"unknown", "n/a", "none", ""} and failed:
            reasons.append("اسم الحساب غير محدد في السجل.")
        if not reasons:
            reasons.append("ترتيب شذوذ نسبي مقارنةً ببقية السجلات المحملة.")
        ranked.append({
            "timestamp": row.get("timestamp", "N/A"),
            "username": username,
            "source_ip": ip,
            "event_type": row.get("event_type", "Unknown event"),
            "failed_attempts": attempts,
            "risk_level": row.get("risk_level", "Unknown"),
            "source_type": row.get("source_type", "demo"),
            "source_label": row.get("source_label", "بيانات تجريبية"),
            "is_anomaly": predictions[index] == -1,
            "anomaly_score": relative_scores[index],
            "model_decision_value": round(decision_values[index], 5),
            "reasons": reasons,
        })

    ranked.sort(key=lambda item: item["anomaly_score"], reverse=True)
    live_count = sum(1 for row in events if row.get("source_type") == "windows_live")
    return {
        "model": "IsolationForest",
        "model_type": "Unsupervised machine-learning anomaly detection",
        "sample_size": len(events),
        "live_windows_events": live_count,
        "demo_events": len(events) - live_count,
        "source_count_note": "كل سجل يحمل مصدره: أحداث Windows مباشرة أو بيانات تجريبية. يظل تحليل الشذوذ تجريبيًا.",
        "scored_records": len(ranked),
        "anomalies_flagged": sum(1 for row in ranked if row["is_anomaly"]),
        "score_note": "الدرجة ترتيب نسبي بين السجلات المحملة (0–100)، وليست احتمالًا لوقوع هجوم.",
        "data_note": (
            "النموذج يقيّم السجلات المتاحة فقط. العينة الحالية صغيرة جدًا؛ النتائج استكشافية "
            "ولا تثبت وقوع هجوم أو دقة النموذج. اجمعي بيانات مصرحًا بها أكثر وراجعي النتائج بشريًا."
        ),
        "monitoring_note": "الأحداث الحية لا تصل إلا عند تشغيل جامع Windows المحلي وضبط NEXUSAI_INGEST_TOKEN؛ هذا لا يراقب بقية الشبكة تلقائيًا.",
        "results": ranked,
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
