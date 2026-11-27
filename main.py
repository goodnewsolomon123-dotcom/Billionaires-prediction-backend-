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
GROQ_MODEL = os.environ.get("GROQ_MODEL", "")
_PREF = ["llama-3.3-70b-versatile", "openai/gpt-oss-120b", "openai/gpt-oss-20b", "llama-3.1-8b-instant"]
_SKIP = ("whisper", "guard", "tts", "playai", "orpheus", "distil", "compound", "safeguard", "embed")
_mc = {"t": 0.0, "m": None}


def pick_model(force=False):
    import time
    if not force and _mc["m"] and time.time() - _mc["t"] < 600:
        return _mc["m"]
    ids = []
    try:
        r = requests.get("https://api.groq.com/openai/v1/models", headers={"Authorization": f"Bearer {GROQ_KEY}"}, timeout=15)
        ids = [m["id"] for m in r.json().get("data", []) if m.get("active", True)]
    except Exception:
        pass
    chat = [i for i in ids if not any(k in i.lower() for k in _SKIP)]
    pick = next((m for m in ([GROQ_MODEL] if GROQ_MODEL else []) + _PREF if m in ids), None) or (chat[0] if chat else (GROQ_MODEL or _PREF[0]))
    _mc.update(t=time.time(), m=pick)
    return pick


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


ADMIN_EMAILS = set(e.strip().lower() for e in os.environ.get(
    "ADMIN_EMAILS", "engroscar516@gmail.com,uzodinmachuks677@gmail.com").split(","))


def has_access(tok):
    if (tok.get("email") or "").lower() in ADMIN_EMAILS and tok.get("email_verified"):
        return True
    uid = tok["uid"]
    u = db.collection("acad_users").document(uid).get().to_dict() or {}
    if u.get("status") != "verified":
        return False
    pu = (db.collection("acad_enroll").document(uid).get().to_dict() or {}).get("paidUntil")
    return bool(pu and pu > datetime.now(timezone.utc))


@app.post("/ai/tutor")
def ai_tutor(body: dict, authorization: str = Header(None)):
    import re
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Please log in again")
    try:
        tok = fa.verify_id_token(authorization.split(" ", 1)[1])
    except Exception:
        raise HTTPException(401, "Please log in again")
    if not GROQ_KEY:
        raise HTTPException(503, "AI tutor is not configured yet (missing GROQ_API_KEY)")
    if not has_access(tok):
        raise HTTPException(403, "Your class opens after you pay and the academy approves your account.")
    uid = tok["uid"]
    course = str(body.get("course") or "this course")[:80]
    act = body.get("action") if body.get("action") in ("start", "next") else "chat"
    hist = [{"role": m["role"], "content": str(m.get("content", ""))[:2500]}
            for m in (body.get("messages") or [])[-10:]
            if isinstance(m, dict) and m.get("role") in ("user", "assistant")]
    key = re.sub(r"[^A-Za-z0-9]+", "_", course)
    pr = db.collection("acad_progress").document(uid)
    n = int((pr.get().to_dict() or {}).get(key, 0) or 0)
    if act == "next":
        n = max(n, 1) + 1
    elif act == "start":
        n = max(n, 1)
    if act != "chat":
        pr.set({key: n}, merge=True)
    lessons = sorted([d.to_dict() for d in db.collection("acad_items").where("to", "==", course).stream()
                      if (d.to_dict() or {}).get("type") == "lesson"],
                     key=lambda x: x.get("createdAt") or datetime.min.replace(tzinfo=timezone.utc))
    mat = ""
    if 1 <= n <= len(lessons):
        L = lessons[n - 1]
        mat = (f"\nThe academy's own material for this lesson (teach from it, and add to it where it is thin):\n"
               f"Title: {L.get('title', '')}\n{str(L.get('body', ''))[:3500]}")
    system = (f"You are the class teacher at Oscar Daxton Academy for the course: {course}. The student has paid and "
              "is enrolled, so you teach the course lesson by lesson, from beginner level upward, in a logical order "
              "that suits this practical course. Write in plain text only: no markdown symbols (no #, *, or backticks). "
              "Use clear short paragraphs, numbered steps, and put commands or code on their own indented lines. "
              "Simple English, friendly and encouraging, with real-life examples. Stay on this course; politely "
              f"redirect anything unrelated. The student is on lesson {n}.{mat}")
    if act == "chat":
        if not hist or hist[-1]["role"] != "user":
            raise HTTPException(400, "Ask a question first")
        msgs, mx = hist, 800
        system += (" Answer the student's question or mark their answers to your check questions: say what is right, "
                   "correct mistakes gently, and when they seem ready tell them to tap Next lesson.")
    else:
        msgs = hist[-6:] + [{"role": "user", "content": (
            f"Teach lesson {n} of the {course} course now. Use this structure: 1) Lesson title and what I will be able "
            "to do after it. 2) The explanation with a real example. 3) A hands-on practice I can do step by step. "
            "4) Three short check questions for me to answer, then stop and wait for my answers.")}]
        mx = 1500

    def call(model):
        return requests.post("https://api.groq.com/openai/v1/chat/completions",
                             headers={"Authorization": f"Bearer {GROQ_KEY}"},
                             json={"model": model, "messages": [{"role": "system", "content": system}] + msgs,
                                   "temperature": 0.5, "max_tokens": mx}, timeout=45)
    try:
        r = call(pick_model())
        if r.status_code in (400, 403, 404) and "model" in r.text.lower():
            r = call(pick_model(force=True))
        data = r.json()
    except Exception:
        raise HTTPException(502, "The AI tutor could not be reached. Try again.")
    if r.status_code != 200:
        raise HTTPException(502, "AI tutor error: " + str((data.get("error") or {}).get("message", r.status_code))[:200])
    return {"reply": data["choices"][0]["message"]["content"], "lesson": n}


@app.get("/")
async def health():
    return {"status": "School portal payments backend is running"}
