import os
import io
import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from PyPDF2 import PdfReader

from database import db, create_document, get_documents

app = FastAPI(title="Smart Study API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# -----------------------
# Helpers
# -----------------------

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    if not hashed:
        return False
    return pwd_context.verify(password, hashed)


def collection(name: str):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    return db[name]


def create_session(user_id: str) -> Dict[str, Any]:
    token = str(uuid.uuid4())
    session = {
        "user_id": user_id,
        "token": token,
        "created_at": datetime.now(timezone.utc),
        "expires_at": datetime.now(timezone.utc) + timedelta(days=7),
    }
    collection("session").insert_one(session)
    return {"token": token}


async def get_current_user(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing auth token")
    token = authorization.split(" ")[-1].strip()
    sess = collection("session").find_one({"token": token})
    if not sess:
        raise HTTPException(status_code=401, detail="Invalid session")
    if sess.get("expires_at") and sess["expires_at"] < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Session expired")
    user = collection("user").find_one({"_id": sess["user_id"]})
    if not user:
        # Some sessions store user_id as string _id. Try both
        user = collection("user").find_one({"_id": sess.get("user_id")})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return {"_id": str(user["_id"]), "email": user.get("email", ""), "name": user.get("name", "")}


# -----------------------
# Models
# -----------------------
class RegisterIn(BaseModel):
    name: str
    email: EmailStr
    password: str


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class QuizSubmitIn(BaseModel):
    note_id: str
    answers: List[int]


# -----------------------
# Simple text processing for summary + questions
# -----------------------
import re
from collections import Counter

def clean_text(text: str) -> str:
    text = re.sub(r"\s+", " ", text).strip()
    return text


def split_sentences(text: str) -> List[str]:
    # Simple sentence split
    sents = re.split(r"(?<=[.!?])\s+", text)
    return [s.strip() for s in sents if s.strip()]


def summarize_text(text: str, max_sentences: int = 5) -> str:
    text = clean_text(text)
    if not text:
        return ""
    sentences = split_sentences(text)
    if len(sentences) <= max_sentences:
        return " ".join(sentences)
    words = re.findall(r"\b\w+\b", text.lower())
    stop = set("a an the and or of for to in on with by is are was were be been as at from that this it its into your you we they them our their not can will should could would may might do does did have has had over under about after before during such more most other some any each few many because therefore however including include".split())
    words = [w for w in words if w not in stop and len(w) > 2]
    freq = Counter(words)
    scores = []
    for i, s in enumerate(sentences):
        s_words = [w for w in re.findall(r"\b\w+\b", s.lower()) if w not in stop]
        score = sum(freq.get(w, 0) for w in s_words)
        scores.append((score, i, s))
    top = sorted(scores, reverse=True)[:max_sentences]
    top_sorted = [s for _, _, s in sorted(top, key=lambda x: x[1])]  # keep original order
    return " ".join(top_sorted)


def generate_mcqs(text: str, num_questions: int = 5) -> List[Dict[str, Any]]:
    text = clean_text(text)
    sentences = split_sentences(text)
    if not sentences:
        return []
    words = re.findall(r"\b\w{4,}\b", text)
    unique_words = list(dict.fromkeys(words))
    questions = []
    idx = 0
    for s in sentences:
        key_words = re.findall(r"\b\w{5,}\b", s)
        if not key_words:
            continue
        answer = key_words[0]
        stem = s.replace(answer, "____", 1)
        # distractors
        distractors = [w for w in unique_words if w.lower() != answer.lower()][:3]
        options = distractors + [answer]
        if len(options) < 4:
            # pad with generic options
            options += ["option A", "option B", "option C"]
            options = options[:4]
        # shuffle deterministically by rotating
        correct_index = len(options) - 1
        options = options[1:] + options[:1]
        correct_index = (correct_index - 1) % 4
        questions.append({
            "question": stem,
            "options": options,
            "answer_index": correct_index
        })
        idx += 1
        if idx >= num_questions:
            break
    return questions


# -----------------------
# Routes
# -----------------------
@app.get("/")
def read_root():
    return {"message": "Smart Study backend running"}


@app.post("/auth/register")
def register(data: RegisterIn):
    users = collection("user")
    existing = users.find_one({"email": data.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user_doc = {
        "email": data.email,
        "name": data.name,
        "password_hash": hash_password(data.password),
        "created_at": datetime.now(timezone.utc),
        "role": "user"
    }
    res = users.insert_one(user_doc)
    token = create_session(res.inserted_id)["token"]
    return {"token": token, "user": {"id": str(res.inserted_id), "email": data.email, "name": data.name}}


@app.post("/auth/login")
def login(data: LoginIn):
    users = collection("user")
    user = users.find_one({"email": data.email})
    if not user or not verify_password(data.password, user.get("password_hash")):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_session(user["_id"])['token']
    return {"token": token, "user": {"id": str(user["_id"]), "email": user.get("email", ""), "name": user.get("name", "")}}


@app.post("/auth/guest")
def guest_login():
    """Create a quick guest session with a throwaway account to reduce friction."""
    users = collection("user")
    guest_id = f"guest-{uuid.uuid4().hex[:8]}"
    email = f"{guest_id}@guest.local"
    user_doc = {
        "email": email,
        "name": "Guest",
        "password_hash": None,
        "created_at": datetime.now(timezone.utc),
        "role": "guest"
    }
    res = users.insert_one(user_doc)
    token = create_session(res.inserted_id)["token"]
    return {"token": token, "user": {"id": str(res.inserted_id), "email": email, "name": "Guest"}}


@app.post("/notes/upload")
async def upload_note(
    title: str = Form(...),
    text: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    content_text = text or ""
    file_type = None
    if file is not None:
        filename = file.filename or "upload"
        content = await file.read()
        mime = file.content_type or ""
        if mime in ("application/pdf",) or filename.lower().endswith(".pdf"):
            try:
                reader = PdfReader(io.BytesIO(content))
                extracted = []
                for page in reader.pages:
                    try:
                        extracted.append(page.extract_text() or "")
                    except Exception:
                        pass
                content_text = (text + "\n" if text else "") + "\n".join(extracted)
                file_type = "pdf"
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Failed to read PDF: {str(e)[:100]}")
        elif mime.startswith("image/"):
            # OCR not available in this environment; ask user to paste text
            file_type = "image"
            if not text:
                raise HTTPException(status_code=415, detail="Image OCR not supported. Please provide text.")
        else:
            # treat as plain text file
            try:
                content_text = (text + "\n" if text else "") + content.decode("utf-8", errors="ignore")
                file_type = "text"
            except Exception:
                raise HTTPException(status_code=400, detail="Unsupported file type")

    if not content_text or len(content_text.strip()) < 10:
        raise HTTPException(status_code=400, detail="Please provide more detailed text content")

    summary = summarize_text(content_text, max_sentences=5)
    questions = generate_mcqs(content_text, num_questions=5)

    note_doc = {
        "user_id": current_user["_id"],
        "title": title,
        "content_text": content_text,
        "file_type": file_type or ("text" if not file else "unknown"),
        "summary": summary,
        "created_at": datetime.now(timezone.utc)
    }
    res = collection("note").insert_one(note_doc)
    note_id = str(res.inserted_id)

    for q in questions:
        q_doc = {
            "note_id": note_id,
            "question": q["question"],
            "options": q["options"],
            "answer_index": q["answer_index"],
            "created_at": datetime.now(timezone.utc)
        }
        collection("question").insert_one(q_doc)

    return {"note_id": note_id, "summary": summary, "questions": questions}


@app.get("/notes")
def list_notes(current_user: Dict[str, Any] = Depends(get_current_user)):
    notes = collection("note").find({"user_id": current_user["_id"]}).sort("created_at", -1)
    result = []
    for n in notes:
        result.append({
            "id": str(n["_id"]),
            "title": n.get("title"),
            "summary": n.get("summary", ""),
            "created_at": n.get("created_at")
        })
    return result


@app.get("/quiz/{note_id}")
def get_quiz(note_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    note = collection("note").find_one({"_id": note_id})
    if not note or note.get("user_id") != current_user["_id"]:
        note = collection("note").find_one({"_id": note_id})
        if not note or note.get("user_id") != current_user["_id"]:
            raise HTTPException(status_code=404, detail="Note not found")
    qs = collection("question").find({"note_id": note_id})
    questions = []
    for q in qs:
        questions.append({
            "question": q["question"],
            "options": q["options"],
        })
    return {"note_id": note_id, "title": note.get("title"), "questions": questions}


@app.post("/quiz/submit")
def submit_quiz(data: QuizSubmitIn, current_user: Dict[str, Any] = Depends(get_current_user)):
    note = collection("note").find_one({"_id": data.note_id})
    if not note or note.get("user_id") != current_user["_id"]:
        raise HTTPException(status_code=404, detail="Note not found")
    qs = list(collection("question").find({"note_id": data.note_id}))
    if not qs:
        raise HTTPException(status_code=400, detail="No questions for this note")
    score = 0
    total = min(len(qs), len(data.answers))
    for i in range(total):
        correct = qs[i]["answer_index"]
        if data.answers[i] == correct:
            score += 1
    collection("quizresult").insert_one({
        "user_id": current_user["_id"],
        "note_id": data.note_id,
        "score": score,
        "total": total,
        "created_at": datetime.now(timezone.utc)
    })
    return {"score": score, "total": total}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
            response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["connection_status"] = "Connected"
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️ Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️ Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"
    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
