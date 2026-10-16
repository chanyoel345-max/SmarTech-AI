
from pathlib import Path

import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

BASE_DIR = Path(__file__).resolve().parent.parent
RESULTS_FILE = BASE_DIR / "data" / "analysis_results.csv"

app = FastAPI(
    title="NexusAI API",
    description="Security log analytics API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Development only
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def home():
    return {
        "project": "NexusAI",
        "status": "running",
        "message": "Security analytics API is ready",
    }


@app.get("/api/summary")
def get_summary():
    if not RESULTS_FILE.exists():
        raise HTTPException(
            status_code=404,
            detail="Run the analytics script first.",
        )

    df = pd.read_csv(RESULTS_FILE)
    failed = df[df["event"] == "login_failed"]

    return {
        "total_events": int(len(df)),
        "failed_login_events": int(len(failed)),
        "high_risk_events": int((df["risk_level"] == "High").sum()),
        "medium_risk_events": int((df["risk_level"] == "Medium").sum()),
        "low_risk_events": int((df["risk_level"] == "Low").sum()),
    }


@app.get("/api/alerts")
def get_alerts():
    if not RESULTS_FILE.exists():
        raise HTTPException(
            status_code=404,
            detail="Run the analytics script first.",
        )

    df = pd.read_csv(RESULTS_FILE)
    alerts = df[df["risk_level"].isin(["High", "Medium"])]

    return alerts.to_dict(orient="records")
