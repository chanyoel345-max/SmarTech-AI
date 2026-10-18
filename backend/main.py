import os
from pathlib import Path
from typing import Any

import pandas as pd
from fastapi import FastAPI, HTTPException, Depends
from backend.firebase_auth import verify_firebase_token
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_FILE = Path(os.getenv("NEXUSAI_DATA_FILE", ROOT_DIR / "data" / "analysis_results.csv"))

app = FastAPI(
    title="NexusAI API",
    version="1.0.0",
    description="Prototype API for NexusAI IT infrastructure analytics",
)

allowed_origins = [
    origin.strip()
    for origin in os.getenv(
        "FRONTEND_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173,https://smartech-ai.netlify.app",
    ).split(",")
    if origin.strip()
]

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
    if not DATA_FILE.exists():
        return []
    try:
        frame = pd.read_csv(DATA_FILE).fillna("")
        return frame.to_dict(orient="records")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not read analysis data: {exc}") from exc


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


def enrich_alert(row: dict[str, Any]) -> dict[str, Any]:
    result = dict(row)
    risk = normalize_risk(first_value(row, "risk_level", "risk", "Risk Level", "severity"))
    result["risk_level"] = risk
    result["event_type"] = first_value(row, "event_type", "event", "Event Type", "action") or "Security event"
    result["username"] = first_value(row, "username", "user", "User", "account") or "Unknown"
    result["source_ip"] = first_value(row, "source_ip", "ip_address", "ip", "Source IP") or "N/A"
    result["timestamp"] = first_value(row, "timestamp", "time", "Timestamp") or "N/A"
    result["recommendation"] = first_value(row, "recommendation", "action_recommendation") or recommendation_for(risk)
    return result


def recommendation_for(risk: str) -> str:
    if risk == "High":
        return "راجع الحدث فورًا، وتحقق من الحساب ومصدر الاتصال قبل اتخاذ إجراء."
    if risk == "Medium":
        return "راجع السجلات المرتبطة وراقب تكرار الحدث."
    if risk == "Low":
        return "استمر في المراقبة الدورية وتوثيق الحدث."
    return "تحقق من بيانات الحدث وصحة تصنيف مستوى المخاطر."


@app.get("/")
def root() -> dict[str, str]:
    return {"project": "NexusAI", "status": "running", "message": "NexusAI API is ready"}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "healthy", "project": "NexusAI"}

@app.get("/api/summary")
def get_summary(
    current_user: dict = Depends(verify_firebase_token),
) -> dict[str, int]:
    failed_logins = sum(
        1 for row in rows
        if "fail" in str(row.get("event_type", "")).lower()
        or "failed" in str(row.get("event_type", "")).lower()
        or "فشل" in str(row.get("event_type", ""))
    )
    return {
        "total_events": len(rows),
        "failed_login_events": failed_logins,
        "high_risk_events": sum(1 for row in rows if row["risk_level"] == "High"),
        "medium_risk_events": sum(1 for row in rows if row["risk_level"] == "Medium"),
        "low_risk_events": sum(1 for row in rows if row["risk_level"] == "Low"),
    }

@app.get("/api/alerts")
def get_alerts(
    current_user: dict = Depends(verify_firebase_token),
) -> list[dict[str, Any]]:
    rows = [enrich_alert(row) for row in read_alerts()]
    return sorted(rows, key=lambda row: str(row.get("timestamp", "")), reverse=True)

@app.post("/api/assistant")
def assistant(
    request: AssistantRequest,
    current_user: dict = Depends(verify_firebase_token),
) -> dict[str, str]:
    question = request.question.strip()
    if not question:
        raise HTTPException(status_code=400, detail="اكتبي سؤالًا أولًا.")
    # This is an honest prototype response, not a connected LLM.
    return {
        "answer": (
            "مساعد NexusAI في وضع النموذج الأولي حاليًا. "
            "لم يتم ربط مزود ذكاء اصطناعي بعد، لذلك لم تُنشأ إجابة مولدة. "
            "سؤالك المسجل: " + question
        )
    }
