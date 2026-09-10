import os
import json
import hmac
import hashlib
from datetime import datetime, timedelta, timezone

import requests
from fastapi import FastAPI, Request, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware

import firebase_admin
from firebase_admin import credentials, firestore, auth as firebase_auth

# ---------- Setup ----------
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten this to your actual GitHub Pages URL once live
    allow_methods=["*"],
    allow_headers=["*"],
)

# Firebase service account JSON is stored as a single environment variable on Render
# (Render doesn't let you upload files easily, so the whole JSON key goes in as text)
firebase_creds_json = os.environ["FIREBASE_SERVICE_ACCOUNT_JSON"]
cred = credentials.Certificate(json.loads(firebase_creds_json))
firebase_admin.initialize_app(cred)
db = firestore.client()

PAYSTACK_SECRET_KEY = os.environ["PAYSTACK_SECRET_KEY"]


def grant_vip(uid: str, plan_id: str, days: int):
    expires_at = datetime.now(timezone.utc) + timedelta(days=days)
    db.collection("bpp_users").document(uid).set(
        {"vip": True, "vipPlan": plan_id, "vipExpiresAt": expires_at},
        merge=True,
    )
    return expires_at


def mark_reference_used(reference: str, uid: str, source: str):
    db.collection("used_references").document(reference).set(
        {"uid": uid, "verifiedAt": firestore.SERVER_TIMESTAMP, "source": source}
    )


def is_reference_used(reference: str) -> bool:
    return db.collection("used_references").document(reference).get().exists


def verify_with_paystack(reference: str) -> dict:
    resp = requests.get(
        f"https://api.paystack.co/transaction/verify/{reference}",
        headers={"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"},
        timeout=15,
    )
    return resp.json()


# ---------- Called from the app right after the Paystack popup succeeds ----------
@app.post("/paystack/verify")
async def verify_payment(request: Request, authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing Firebase auth token")

    id_token = authorization.split(" ", 1)[1]
    try:
        decoded = firebase_auth.verify_id_token(id_token)
    except Exception:
        raise HTTPException(401, "Invalid or expired login. Please log in again.")

    uid = decoded["uid"]
    body = await request.json()
    reference = body.get("reference")
    if not reference:
        raise HTTPException(400, "Missing payment reference.")

    if is_reference_used(reference):
        raise HTTPException(409, "This payment has already been processed.")

    result = verify_with_paystack(reference)
    if not result.get("status") or result["data"]["status"] != "success":
        raise HTTPException(400, "Payment could not be verified.")

    metadata = result["data"].get("metadata") or {}
    plan_id = metadata.get("planId")
    days = metadata.get("days")
    if not plan_id or not days:
        raise HTTPException(400, "Missing plan info on this payment.")

    mark_reference_used(reference, uid, "verify_endpoint")
    expires_at = grant_vip(uid, plan_id, int(days))

    return {"success": True, "vipExpiresAt": expires_at.isoformat()}


# ---------- Called directly by Paystack's servers, independent of the user's browser ----------
@app.post("/paystack/webhook")
async def paystack_webhook(request: Request, x_paystack_signature: str = Header(None)):
    raw_body = await request.body()

    expected_signature = hmac.new(
        PAYSTACK_SECRET_KEY.encode("utf-8"), raw_body, hashlib.sha512
    ).hexdigest()

    if x_paystack_signature != expected_signature:
        raise HTTPException(401, "Invalid signature")

    event = json.loads(raw_body)

    if event.get("event") == "charge.success":
        data = event["data"]
        reference = data["reference"]
        metadata = data.get("metadata") or {}
        uid = metadata.get("uid")
        plan_id = metadata.get("planId")
        days = metadata.get("days")

        if uid and plan_id and days and not is_reference_used(reference):
            mark_reference_used(reference, uid, "webhook")
            grant_vip(uid, plan_id, int(days))

    # Always return 200 quickly so Paystack doesn't keep retrying
    return {"received": True}


@app.get("/")
async def health_check():
    return {"status": "Billionaire Prediction Pro payments backend is running"}
