
import os
import ipaddress
from pathlib import Path
from typing import Any

import pandas as pd
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

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
    title="NexusAI API",
    version="1.0.0",
    description="Prototype API for NexusAI IT infrastructure analytics",
)

# CORS: السماح لموقع الإنتاج والتطوير المحلي بالاتصال بالـ API.
default_origins = [
    "https://smartech-ai.netlify.app",
    "http://localhost:5173",
    "http://localhost:5176",
    "http://localhost:5177",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5176",
    "http://127.0.0.1:5177",
]

configured_origins = [
    origin.strip()
    for origin in os.getenv("FRONTEND_ORIGINS", "").split(",")
    if origin.strip()
]

allowed_origins = list(dict.fromkeys(default_origins + configured_origins))

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AssistantRequest(BaseModel):
    question: str


def read_alerts() -> list[dict[str, Any]]:
    """قراءة أحداث وتحليلات الأمان من ملف CSV."""
    if not DATA_FILE.exists():
        return []

    try:
        frame = pd.read_csv(DATA_FILE).fillna("")
        return frame.to_dict(orient="records")
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="تعذر قراءة بيانات التحليل.",
        ) from exc


def normalize_risk(value: Any) -> str:
    text = str(value or "").strip().lower()

    if text in {"high", "critical", "عالي", "مرتفعة"}:
        return "High"

    if text in {"medium", "moderate", "متوسط", "متوسطة"}:
        return "Medium"

    if text in {"low", "منخفض", "منخفضة"}:
        return "Low"

    return "Unknown"


def first_value(row: dict[str, Any], *names: str) -> Any:
    for name in names:
        if name in row and str(row[name]).strip():
            return row[name]

    return ""





def recommendation_for(risk: str) -> str:
    if risk == "High":
        return "راجع الحدث فورًا، وتحقق من الحساب ومصدر الاتصال قبل اتخاذ إجراء."

    if risk == "Medium":
        return "راجع السجلات المرتبطة وراقب تكرار الحدث."

    if risk == "Low":
        return "استمر في المراقبة الدورية وتوثيق الحدث."

    return "تحقق من بيانات الحدث وصحة تصنيف مستوى المخاطر."


def enrich_alert(row: dict[str, Any]) -> dict[str, Any]:
    result = dict(row)

    risk = normalize_risk(
        first_value(
            row,
            "risk_level",
            "risk",
            "Risk Level",
            "severity",
        )
    )

    result["risk_level"] = risk

    result["event_type"] = (
        first_value(row, "event_type", "event", "Event Type", "action")
        or "Security event"
    )

    result["username"] = (
        first_value(row, "username", "user", "User", "account")
        or "Unknown"
    )

    result["source_ip"] = (
        first_value(row, "source_ip", "ip_address", "ip", "Source IP")
        or "N/A"
    )

    result["timestamp"] = (
        first_value(row, "timestamp", "time", "Timestamp")
        or "N/A"
    )

    result["recommendation"] = (
        first_value(row, "recommendation", "action_recommendation")
        or recommendation_for(risk)
    )

    return result


@app.get("/")
def root() -> dict[str, str]:
    return {
        "project": "NexusAI",
        "status": "running",
        "message": "NexusAI API is ready",
    }


@app.get("/health")
def health() -> dict[str, str]:
    return {
        "status": "healthy",
        "project": "NexusAI",
    }


@app.get("/api/summary")
def get_summary(
    current_user: dict = Depends(verify_firebase_token),
) -> dict[str, int]:
    # تجهيز الصفوف قبل حساب المؤشرات.
    rows = [enrich_alert(row) for row in read_alerts()]

    failed_logins = sum(
        1
        for row in rows
        if (
            "fail" in str(row.get("event_type", "")).lower()
            or "failed" in str(row.get("event_type", "")).lower()
            or "فشل" in str(row.get("event_type", ""))
        )
    )

    return {
        "total_events": len(rows),
        "failed_login_events": failed_logins,
        "high_risk_events": sum(
            1 for row in rows if row["risk_level"] == "High"
        ),
        "medium_risk_events": sum(
            1 for row in rows if row["risk_level"] == "Medium"
        ),
        "low_risk_events": sum(
            1 for row in rows if row["risk_level"] == "Low"
        ),
    }


@app.get("/api/ip-analysis/{ip_address}")
def analyze_ip(
    ip_address: str,
    current_user: dict = Depends(verify_firebase_token),
) -> dict[str, Any]:
    # التحقق من صحة عنوان IP.
    try:
        searched_ip = str(ipaddress.ip_address(ip_address.strip()))
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="عنوان IP غير صالح. تحققي من العنوان وأعيدي المحاولة.",
        )

    # قراءة السجلات الفعلية.
    rows = [enrich_alert(row) for row in read_alerts()]

    # البحث عن العنوان المطلوب.
    matching_rows = [
        row for row in rows
        if str(row.get("source_ip", "")).strip() == searched_ip
    ]

    if not matching_rows:
        return {
            "ip_address": searched_ip,
            "found": False,
            "total_events": 0,
            "failed_login_events": 0,
            "failed_attempts_recorded": 0,
            "risk_level": "Unknown",
            "usernames": [],
            "events": [],
            "message": "لم يُعثر على هذا العنوان في السجلات المتاحة.",
        }

    # تحديد أحداث الدخول الفاشلة.
    failed_events = [
        row for row in matching_rows
        if (
            "fail" in str(row.get("event_type", "")).lower()
            or "فشل" in str(row.get("event_type", ""))
        )
    ]

    # جمع عدد المحاولات المسجلة إن كان الحقل متوفرًا.
    failed_attempts_recorded = 0
    for row in failed_events:
        try:
            value = int(float(row.get("failed_attempts", 0) or 0))
            failed_attempts_recorded += max(value, 0)
        except (TypeError, ValueError, OverflowError):
            # إذا كانت القيمة غير صالحة، نتركها دون احتساب.
            continue

    # اختيار أعلى مستوى خطورة موجود في السجلات.
    risk_priority = {
        "Unknown": 0,
        "Low": 1,
        "Medium": 2,
        "High": 3,
    }
    risk_level = max(
        (row["risk_level"] for row in matching_rows),
        key=lambda risk: risk_priority.get(risk, 0),
    )

    usernames = sorted({
        str(row.get("username", "")).strip()
        for row in matching_rows
        if str(row.get("username", "")).strip()
        and str(row.get("username", "")).strip() != "Unknown"
    })

    return {
        "ip_address": searched_ip,
        "found": True,
        "total_events": len(matching_rows),
        "failed_login_events": len(failed_events),
        "failed_attempts_recorded": failed_attempts_recorded,
        "risk_level": risk_level,
        "usernames": usernames,
        "events": sorted(
            matching_rows,
            key=lambda row: str(row.get("timestamp", "")),
            reverse=True,
        ),
        "message": (
            "مستوى الخطورة مستمد من تصنيفات السجلات المتاحة، "
            "ولا يُثبت وحده وجود هجوم."
        ),
    }
@app.get("/api/alerts")
def get_alerts(
    current_user: dict = Depends(verify_firebase_token),
) -> list[dict[str, Any]]:
    rows = [enrich_alert(row) for row in read_alerts()]

    return sorted(
        rows,
        key=lambda row: str(row.get("timestamp", "")),
        reverse=True,
    )
def get_alerts(
    current_user: dict = Depends(verify_firebase_token),
) -> list[dict[str, Any]]:
    rows = [enrich_alert(row) for row in read_alerts()]

    return sorted(
        rows,
        key=lambda row: str(row.get("timestamp", "")),
        reverse=True,
    )


@app.post("/api/assistant")
def assistant(
    request: AssistantRequest,
    current_user: dict = Depends(verify_firebase_token),
) -> dict[str, str]:
    question = request.question.strip()

    if not question:
        raise HTTPException(
            status_code=400,
            detail="اكتبي سؤالًا أولًا.",
        )

    # نموذج أولي: لا يوجد مزود ذكاء اصطناعي متصل حتى الآن.
    return {
        "answer": (
            "مساعد NexusAI في وضع النموذج الأولي حاليًا. "
            "لم يتم ربط مزود ذكاء اصطناعي بعد، لذلك لم تُنشأ إجابة مولدة. "
            "سؤالك المسجل: " + question
        )
    }
