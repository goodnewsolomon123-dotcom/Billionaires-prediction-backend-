import os, json, hmac, hashlib, requests
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, Request, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import firebase_admin
from firebase_admin import credentials, firestore, auth as fa
from google.api_core.exceptions import AlreadyExists

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
firebase_admin.initialize_app(credentials.Certificate(json.loads(os.environ["FIREBASE_SERVICE_ACCOUNT_JSON"])))
db = firestore.client()
SK = os.environ["PAYSTACK_SECRET_KEY"]


def record(ref, uid, fee_id, paid_kobo):
    fee = db.collection("acad_fees").document(fee_id).get()
    if not fee.exists:
        raise HTTPException(400, "Unknown fee")
    f = fee.to_dict()
    if paid_kobo < int(f["amount"]) * 100:
        raise HTTPException(400, "Amount paid is less than the fee")
    try:
        db.collection("acad_payments").document(ref).create({
            "uid": uid, "feeId": fee_id, "title": f["title"], "amount": paid_kobo / 100,
            "reference": ref, "createdAt": firestore.SERVER_TIMESTAMP})
    except AlreadyExists:
        pass


def enroll(ref, uid, paid_kobo):
    s = db.collection("acad_settings").document("main").get().to_dict() or {}
    amt, months = int(s.get("feeAmount", 20000)), int(s.get("feeMonths", 4))
    if paid_kobo < amt * 100:
        raise HTTPException(400, "Amount paid is less than the fee")
    try:
        db.collection("acad_payments").document(ref).create({
            "uid": uid, "feeId": "enrol", "title": f"Academy fee ({months} months)", "amount": paid_kobo / 100,
            "reference": ref, "createdAt": firestore.SERVER_TIMESTAMP})
    except AlreadyExists:
        return
    er = db.collection("acad_enroll").document(uid)
    cur = er.get()
    start = datetime.now(timezone.utc)
    if cur.exists:
        pu = cur.to_dict().get("paidUntil")
        if pu and pu > start:
            start = pu
    er.set({"uid": uid, "paidUntil": start + timedelta(days=30 * months)}, merge=True)


@app.post("/paystack/verify")
async def verify(request: Request, authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Please log in again")
    try:
        uid = fa.verify_id_token(authorization.split(" ", 1)[1])["uid"]
    except Exception:
        raise HTTPException(401, "Please log in again")
    ref = (await request.json()).get("reference")
    if not ref:
        raise HTTPException(400, "Missing reference")
    r = requests.get(f"https://api.paystack.co/transaction/verify/{ref}",
                     headers={"Authorization": f"Bearer {SK}"}, timeout=15).json()
    if not r.get("status") or r["data"]["status"] != "success":
        raise HTTPException(400, "Payment not successful")
    md = r["data"].get("metadata") or {}
    if md.get("uid") != uid:
        raise HTTPException(400, "Payment does not match this account")
    if md.get("type") == "enrol":
        enroll(ref, uid, r["data"]["amount"])
    elif md.get("feeId"):
        record(ref, uid, md["feeId"], r["data"]["amount"])
    else:
        raise HTTPException(400, "Unknown payment type")
    return {"success": True}


@app.post("/paystack/webhook")
async def webhook(request: Request, x_paystack_signature: str = Header(None)):
    raw = await request.body()
    if x_paystack_signature != hmac.new(SK.encode(), raw, hashlib.sha512).hexdigest():
        raise HTTPException(401, "Invalid signature")
    ev = json.loads(raw)
    if ev.get("event") == "charge.success":
        d = ev["data"]
        md = d.get("metadata") or {}
        try:
            if md.get("uid") and md.get("type") == "enrol":
                enroll(d["reference"], md["uid"], d["amount"])
            elif md.get("uid") and md.get("feeId"):
                record(d["reference"], md["uid"], md["feeId"], d["amount"])
        except HTTPException:
            pass
    return {"received": True}


@app.get("/")
async def health():
    return {"status": "School portal payments backend is running"}
