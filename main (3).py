import os, re, json, hmac, hashlib, secrets, requests
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


def is_admin(tok):
    return (tok.get("email") or "").lower() in ADMIN_EMAILS and bool(tok.get("email_verified"))


def has_access(tok):
    if is_admin(tok):
        return True
    uid = tok["uid"]
    u = db.collection("acad_users").document(uid).get().to_dict() or {}
    if u.get("status") != "verified":
        return False
    pu = (db.collection("acad_enroll").document(uid).get().to_dict() or {}).get("paidUntil")
    return bool(pu and pu > datetime.now(timezone.utc))


def user_ctx(authorization):
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
    return tok


def llm(system, msgs, mx=800, temp=0.5):
    def call(model):
        return requests.post("https://api.groq.com/openai/v1/chat/completions",
                             headers={"Authorization": f"Bearer {GROQ_KEY}"},
                             json={"model": model, "messages": [{"role": "system", "content": system}] + msgs,
                                   "temperature": temp, "max_tokens": mx}, timeout=45)
    try:
        r = call(pick_model())
        if r.status_code in (400, 403, 404) and "model" in r.text.lower():
            r = call(pick_model(force=True))
        data = r.json()
    except Exception:
        raise HTTPException(502, "The AI tutor could not be reached. Try again.")
    if r.status_code != 200:
        raise HTTPException(502, "AI tutor error: " + str((data.get("error") or {}).get("message", r.status_code))[:200])
    return data["choices"][0]["message"]["content"]


def jlist(text):
    try:
        return json.loads(text[text.index("["): text.rindex("]") + 1])
    except Exception:
        return []


def ckey(course):
    return re.sub(r"[^A-Za-z0-9]+", "_", str(course))[:80]


def norm_topics(raw):
    out = []
    for t in raw or []:
        if isinstance(t, str) and t.strip():
            out.append({"t": t.strip()[:150], "body": "", "video": ""})
        elif isinstance(t, dict) and str(t.get("t", "")).strip():
            out.append({"t": str(t["t"]).strip()[:150], "body": str(t.get("body", ""))[:6000],
                        "video": str(t.get("video", ""))[:500]})
    return out


def gen_topics(course, count=12):
    ask = ("List " + str(count) + ' lesson topics for a practical beginner-to-advanced course called "' + course +
           '", in the best teaching order. Reply only with a JSON array of ' + str(count) + " short strings.")
    t = [str(x)[:120] for x in jlist(llm("You design practical course curricula. Reply with JSON only.",
                                         [{"role": "user", "content": ask}], 900, 0.3)) if x]
    if len(t) < 3:
        raise HTTPException(502, "Could not prepare the course topics. Try again.")
    return t[:30]


def get_course(course):
    ref = db.collection("acad_courses").document(ckey(course))
    d = ref.get().to_dict() or {}
    tp = norm_topics(d.get("topics"))
    if not tp:
        tp = norm_topics(gen_topics(course))
        ref.set({"course": course, "topics": tp, "createdAt": firestore.SERVER_TIMESTAMP}, merge=True)
    return {"topics": tp, "desc": str(d.get("desc", ""))[:1000], "ai": str(d.get("ai", ""))[:2000]}


def progress(uid, course):
    d = db.collection("acad_progress").document(uid).get().to_dict() or {}
    done = sorted(set(int(x) for x in d.get(ckey(course) + "_done", [])))
    return done, (max(done) if done else 0) + 1


def topic_arg(body, tok, course):
    try:
        n = int(body.get("topic") or 0)
    except Exception:
        n = 0
    C = get_course(course)
    if n < 1 or n > len(C["topics"]):
        raise HTTPException(400, "Unknown topic")
    if n > progress(tok["uid"], course)[1] and not is_admin(tok):
        raise HTTPException(403, "Pass the quiz for the previous topic first.")
    return n, C


def chat_ref(uid, course, n):
    return db.collection("acad_chats").document(f"{uid}_{ckey(course)}_{n}")


@app.post("/ai/outline")
def ai_outline(body: dict, authorization: str = Header(None)):
    tok = user_ctx(authorization)
    course = str(body.get("course") or "")[:80]
    if not course:
        raise HTTPException(400, "Missing course")
    C = get_course(course)
    done, unlocked = progress(tok["uid"], course)
    return {"topics": [t["t"] for t in C["topics"]], "manual": [bool(t["body"] or t["video"]) for t in C["topics"]],
            "desc": C["desc"], "done": done, "unlocked": 99 if is_admin(tok) else unlocked}


@app.post("/ai/history")
def ai_history(body: dict, authorization: str = Header(None)):
    tok = user_ctx(authorization)
    course = str(body.get("course") or "")[:80]
    manual, n = None, 0
    if body.get("topic"):
        n, C = topic_arg(body, tok, course)
        t = C["topics"][n - 1]
        if t["body"] or t["video"]:
            manual = {"body": t["body"], "video": t["video"]}
    d = chat_ref(tok["uid"], course, n).get().to_dict() or {}
    return {"messages": d.get("messages", []), "manual": manual}


@app.post("/ai/tutor")
def ai_tutor(body: dict, authorization: str = Header(None)):
    tok = user_ctx(authorization)
    uid = tok["uid"]
    course = str(body.get("course") or "this course")[:80]
    u = db.collection("acad_users").document(uid).get().to_dict() or {}
    first = (u.get("name") or "the student").split(" ")[0]
    res = sorted([r for r in (x.to_dict() for x in db.collection("acad_quiz_results").where("uid", "==", uid).stream())
                  if r.get("course") == course],
                 key=lambda r: r.get("createdAt") or datetime.min.replace(tzinfo=timezone.utc))[-5:]
    quiz = "; ".join(f"{r.get('title')}: {r.get('score')}/{r.get('total')}" for r in res)
    n, C, mat, extra = 0, None, "", ""
    if body.get("topic"):
        n, C = topic_arg(body, tok, course)
        t = C["topics"][n - 1]
        if t["body"]:
            mat = ("\nThe academy teacher's own lesson for this topic (teach from it faithfully, explain it, and add "
                   "to it only where it is thin):\n" + t["body"][:4000])
        extra = (" The course description: " + C["desc"] if C["desc"] else "") + \
                (" Instructions from the academy for this course: " + C["ai"] if C["ai"] else "")
    ref = chat_ref(uid, course, n)
    saved = ref.get().to_dict() or {}
    msgs, summ = saved.get("messages", []), saved.get("summary", "")
    system = ("You are the class teacher at Oscar Daxton Academy for the course: " + course + ". You are teaching " +
              first + ". Teach like an experienced professional instructor: be accurate, practical and patient; build "
              "on what the student already knows; one idea at a time; use real-world examples (workshop, office, "
              "everyday Nigerian context when natural); check understanding with short questions; correct mistakes "
              "kindly and explain why; never invent facts and say so when unsure; stay within this course and politely "
              "redirect anything else; keep replies focused, under about 350 words unless teaching a full topic. "
              "Refer back to earlier parts of this conversation when useful. Write in plain text only: no markdown "
              "symbols (no #, *, or backticks); use short paragraphs, numbered steps, and put commands or code on their "
              "own indented lines." + extra)
    if n:
        system += " The current topic is " + str(n) + " of " + str(len(C["topics"])) + ": " + C["topics"][n - 1]["t"] + "." + mat
    if summ:
        system += "\nSummary of your earlier conversation with this student: " + summ
    if quiz:
        system += "\nThe student's recent quiz results in this course: " + quiz + ". Support weak areas."
    if body.get("action") == "start" and n:
        reply = llm(system, [{"role": "user", "content": (
            "Teach this topic now. Structure: 1) the topic title and what I will be able to do after it. 2) the "
            "explanation with a real example. 3) a hands-on practice I can do step by step. 4) finish by telling me "
            "to tap the Quiz button at the top when I am ready, or to ask you anything first.")}], 1500)
        msgs.append({"role": "assistant", "content": reply})
    else:
        q = str(body.get("message") or "").strip()[:2000]
        if not q:
            raise HTTPException(400, "Ask a question first")
        msgs.append({"role": "user", "content": q})
        reply = llm(system, [{"role": m["role"], "content": m["content"]} for m in msgs[-16:]], 900)
        msgs.append({"role": "assistant", "content": reply})
    if len(msgs) > 60:
        old, msgs = msgs[:30], msgs[30:]
        try:
            summ = llm("You summarise tutoring conversations in under 150 words, keeping what the student learned, "
                       "struggled with and asked.", [{"role": "user", "content": "Earlier summary: " + summ +
                       "\nNew messages:\n" + "\n".join(m["role"] + ": " + m["content"][:600] for m in old)}], 300, 0.2)
        except HTTPException:
            pass
    ref.set({"messages": msgs, "summary": summ, "updatedAt": firestore.SERVER_TIMESTAMP})
    manual = None
    if n and body.get("action") == "start" and (C["topics"][n - 1]["body"] or C["topics"][n - 1]["video"]):
        manual = {"body": C["topics"][n - 1]["body"], "video": C["topics"][n - 1]["video"]}
    return {"reply": reply, "lesson": n, "manual": manual}


@app.post("/ai/quiz")
def ai_quiz(body: dict, authorization: str = Header(None)):
    tok = user_ctx(authorization)
    course = str(body.get("course") or "")[:80]
    n, C = topic_arg(body, tok, course)
    t = C["topics"][n - 1]
    ask = ('Write 5 multiple-choice questions to test a student on the topic "' + t["t"] + '" from the course "' +
           course + '". ' + (("Base them on this lesson material:\n" + t["body"][:2500] + "\n") if t["body"] else "") +
           'Each item is an object with keys q (the question), o (list of exactly 4 short options), a (index 0-3 of '
           'the correct option) and w (one-sentence explanation). Vary where the correct answer sits. Reply only '
           'with a JSON array.')
    qs = [x for x in jlist(llm("You write fair multiple-choice quizzes. Reply with JSON only.",
                               [{"role": "user", "content": ask}], 1400, 0.4))
          if isinstance(x, dict) and x.get("q") and isinstance(x.get("o"), list) and len(x["o"]) == 4
          and isinstance(x.get("a"), int) and 0 <= x["a"] <= 3][:5]
    if len(qs) < 3:
        raise HTTPException(502, "Could not make the quiz. Tap Quiz to try again.")
    db.collection("acad_quiz_keys").document(f"{tok['uid']}_{ckey(course)}_{n}").set(
        {"a": [q["a"] for q in qs], "w": [str(q.get("w", ""))[:300] for q in qs]})
    return {"questions": [{"q": str(q["q"])[:300], "o": [str(o)[:150] for o in q["o"]]} for q in qs]}


@app.post("/ai/grade")
def ai_grade(body: dict, authorization: str = Header(None)):
    tok = user_ctx(authorization)
    uid = tok["uid"]
    course = str(body.get("course") or "")[:80]
    n, C = topic_arg(body, tok, course)
    kr = db.collection("acad_quiz_keys").document(f"{uid}_{ckey(course)}_{n}")
    k = kr.get().to_dict()
    if not k:
        raise HTTPException(400, "Start a quiz first")
    ans = body.get("answers") or []
    if len(ans) != len(k["a"]):
        raise HTTPException(400, "Answer every question")
    score = sum(1 for x, y in zip(ans, k["a"]) if x == y)
    total = len(k["a"])
    passed = score * 100 >= 60 * total
    if passed:
        db.collection("acad_progress").document(uid).set({ckey(course) + "_done": firestore.ArrayUnion([n])}, merge=True)
    name = (db.collection("acad_users").document(uid).get().to_dict() or {}).get("name", "")
    db.collection("acad_quiz_results").add({"uid": uid, "name": name, "course": course, "topic": n,
                                            "title": C["topics"][n - 1]["t"], "score": score, "total": total,
                                            "passed": passed, "createdAt": firestore.SERVER_TIMESTAMP})
    kr.delete()
    return {"score": score, "total": total, "passed": passed,
            "review": [{"correct": k["a"][i], "why": k["w"][i]} for i in range(total)]}


def admin_ctx(authorization):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Please log in again")
    try:
        tok = fa.verify_id_token(authorization.split(" ", 1)[1])
    except Exception:
        raise HTTPException(401, "Please log in again")
    if not is_admin(tok):
        raise HTTPException(403, "Admins only")
    if not GROQ_KEY:
        raise HTTPException(503, "Missing GROQ_API_KEY")
    return tok


@app.post("/admin/outline")
def admin_outline(body: dict, authorization: str = Header(None)):
    admin_ctx(authorization)
    try:
        count = min(max(int(body.get("count") or 12), 4), 30)
    except Exception:
        count = 12
    return {"topics": gen_topics(str(body.get("course") or "")[:80], count)}


@app.post("/admin/lesson")
def admin_lesson(body: dict, authorization: str = Header(None)):
    admin_ctx(authorization)
    course, title = str(body.get("course") or "")[:80], str(body.get("title") or "")[:150]
    text = llm("You are an expert instructor writing a lesson for a practical course. Write plain text only: no "
               "markdown symbols. Use short paragraphs and numbered steps, with commands or code on their own lines.",
               [{"role": "user", "content": (
                   'Write the lesson "' + title + '" for the course "' + course + '". Include: what the student will be '
                   'able to do, a clear explanation with examples, step-by-step practice, common mistakes, and a short '
                   'summary. About 500 to 700 words.')}], 1800, 0.4)
    return {"body": text}


@app.post("/admin/test-student")
def admin_test_student(body: dict, authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Please log in again")
    try:
        tok = fa.verify_id_token(authorization.split(" ", 1)[1])
    except Exception:
        raise HTTPException(401, "Please log in again")
    if not is_admin(tok):
        raise HTTPException(403, "Admins only")
    act = body.get("action") or "create"
    pw = "Test-" + secrets.token_hex(4)
    if act == "create":
        course = str(body.get("course") or "")[:80]
        if not course:
            raise HTTPException(400, "Choose a course")
        bypass = bool(body.get("bypass", True))
        email = "student." + secrets.token_hex(3) + "@oda-test.example"
        name = "Test Student " + secrets.token_hex(1).upper()
        try:
            u = fa.create_user(email=email, password=pw, display_name=name)
        except Exception as e:
            raise HTTPException(502, "Could not create the test account: " + str(e)[:150])
        db.collection("acad_users").document(u.uid).set({
            "name": name, "role": "student", "cls": course, "dob": "2000-01-01", "phone": "0000000000",
            "email": email, "status": "verified" if bypass else "pending", "test": True,
            "createdAt": firestore.SERVER_TIMESTAMP})
        if bypass:
            db.collection("acad_enroll").document(u.uid).set(
                {"uid": u.uid, "paidUntil": datetime.now(timezone.utc) + timedelta(days=30)}, merge=True)
        return {"uid": u.uid, "email": email, "password": pw, "name": name}
    uid = str(body.get("uid") or "")
    d = db.collection("acad_users").document(uid).get().to_dict() or {}
    if not d.get("test"):
        raise HTTPException(400, "Only test accounts can be changed here")
    if act == "reset":
        fa.update_user(uid, password=pw)
        return {"uid": uid, "email": d.get("email"), "password": pw, "name": d.get("name")}
    if act == "delete":
        try:
            fa.delete_user(uid)
        except Exception:
            pass
        for c in ("acad_users", "acad_enroll", "acad_progress"):
            db.collection(c).document(uid).delete()
        return {"ok": True}
    raise HTTPException(400, "Unknown action")


@app.get("/")
async def health():
    return {"status": "School portal payments backend is running"}
