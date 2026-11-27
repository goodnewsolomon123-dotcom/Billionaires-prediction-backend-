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
GROQ_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")


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


@app.post("/ai/tutor")
def ai_tutor(body: dict, authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Please log in again")
    try:
        fa.verify_id_token(authorization.split(" ", 1)[1])
    except Exception:
        raise HTTPException(401, "Please log in again")
    if not GROQ_KEY:
        raise HTTPException(503, "AI tutor is not configured yet (missing GROQ_API_KEY)")
    course = str(body.get("course") or "this course")[:80]
    msgs = [{"role": m["role"], "content": str(m.get("content", ""))[:2000]}
            for m in (body.get("messages") or [])[-12:]
            if isinstance(m, dict) and m.get("role") in ("user", "assistant")]
    if not msgs or msgs[-1]["role"] != "user":
        raise HTTPException(400, "Ask a question first")
    system = (f"You are a friendly AI tutor at Oscar Daxton Academy for the course: {course}. "
              "Explain step by step in simple English with short examples. Stay on this course; "
              "politely redirect unrelated questions. Keep answers clear and not too long.")
    try:
        r = requests.post("https://api.groq.com/openai/v1/chat/completions",
                          headers={"Authorization": f"Bearer {GROQ_KEY}"},
                          json={"model": GROQ_MODEL, "messages": [{"role": "system", "content": system}] + msgs,
                                "temperature": 0.5, "max_tokens": 700}, timeout=30)
        data = r.json()
    except Exception:
        raise HTTPException(502, "The AI tutor could not be reached. Try again.")
    if r.status_code != 200:
        raise HTTPException(502, "AI tutor error: " + str((data.get("error") or {}).get("message", r.status_code))[:200])
    return {"reply": data["choices"][0]["message"]["content"]}


@app.get("/")
async def health():
    return {"status": "School portal payments backend is running"}
