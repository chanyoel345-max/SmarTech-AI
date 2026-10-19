
import os
import json
import firebase_admin
from firebase_admin import auth, credentials
from fastapi import Header, HTTPException


def initialize_firebase():
    if firebase_admin._apps:
        return

    service_account_json = os.getenv("FIREBASE_SERVICE_ACCOUNT_JSON")

    if not service_account_json:
        raise RuntimeError(
            "FIREBASE_SERVICE_ACCOUNT_JSON is not configured"
        )

    try:
        service_account_info = json.loads(service_account_json)
        credential = credentials.Certificate(service_account_info)
        firebase_admin.initialize_app(credential)
    except Exception as exc:
        raise RuntimeError(
            "Firebase Admin credentials could not be initialized"
        ) from exc


def verify_firebase_token(
    authorization: str = Header(default=None)
):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Missing authentication token"
        )

    token = authorization.split(" ", 1)[1]

    try:
        initialize_firebase()
        return auth.verify_id_token(token)
    except HTTPException:
        raise
    except Exception as exc:
        print(
            f"Firebase authentication failed: "
            f"{type(exc).__name__}: {exc}"
        )
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired authentication token"
        )
