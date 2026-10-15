"""CyberShield powered by AI backend. Run: uvicorn main:app --reload"""
import os
import json
import hashlib
import secrets
from datetime import datetime, timedelta
from collections import Counter

from fastapi import FastAPI, Depends, HTTPException, Header, UploadFile, File
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.orm import declarative_base, sessionmaker

from pathlib import Path
import analyzers

# SQLite by default; set DATABASE_URL=mysql+pymysql://user:pass@localhost/cybershield for MySQL
URL = os.getenv("DATABASE_URL", "sqlite:///cybershield.db")
engine = create_engine(URL, connect_args={"check_same_thread": False} if URL.startswith("sqlite") else {})
Session = sessionmaker(bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    name = Column(String(80))
    email = Column(String(120), unique=True, index=True)
    salt = Column(String(32))
    pw_hash = Column(String(128))
    token = Column(String(64), index=True)


class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    kind = Column(String(10))
    score = Column(Integer)
    level = Column(String(10))
    result = Column(Text)
    created = Column(DateTime, default=datetime.utcnow)


class Report(Base):
    """Community reported list: one row per (user, number/link/message)."""
    __tablename__ = "reports"
    __table_args__ = (UniqueConstraint("user_id", "key"),)
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    key = Column(String(300), index=True)
    created = Column(DateTime, default=datetime.utcnow)


Base.metadata.create_all(engine)
app = FastAPI(title="CyberShield powered by AI")


def db():
    s = Session()
    try:
        yield s
    finally:
        s.close()


def current_user(authorization: str = Header(default=""), s=Depends(db)):
    u = s.query(User).filter(User.token == authorization.replace("Bearer ", "")).first() if authorization else None
    if not u:
        raise HTTPException(401, "Please log in")
    return u


def hash_pw(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 100_000).hex()


class Reg(BaseModel):
    name: str = ""
    email: str
    password: str


class Content(BaseModel):
    content: str


@app.post("/api/register")
def register(r: Reg, s=Depends(db)):
    if len(r.password) < 6:
        raise HTTPException(400, "Password must be at least 6 characters")
    if s.query(User).filter(User.email == r.email.lower()).first():
        raise HTTPException(400, "Email already registered")
    salt, tok = secrets.token_hex(8), secrets.token_hex(24)
    s.add(User(name=r.name, email=r.email.lower(), salt=salt, pw_hash=hash_pw(r.password, salt), token=tok))
    s.commit()
    return {"token": tok, "name": r.name}


@app.post("/api/login")
def login(r: Reg, s=Depends(db)):
    u = s.query(User).filter(User.email == r.email.lower()).first()
    if not u or not secrets.compare_digest(u.pw_hash, hash_pw(r.password, u.salt)):
        raise HTTPException(401, "Wrong email or password")
    u.token = secrets.token_hex(24)
    s.commit()
    return {"token": u.token, "name": u.name}


def reputation(s, res):
    n = max([s.query(Report).filter(Report.key == k).count()
             for k in analyzers.keys_for(res["kind"], res["input"])] or [0])
    return analyzers.rescore(res, n) if n else res


def save(s, user, res):
    res = reputation(s, res)
    row = Scan(user_id=user.id, kind=res["kind"], score=res["score"], level=res["level"], result=json.dumps(res))
    s.add(row)
    s.commit()
    res["id"] = row.id
    return res


RUN = {"url": analyzers.scan_url, "sms": analyzers.scan_text}


@app.post("/api/scan/{kind}")
def scan(kind: str, body: Content, u=Depends(current_user), s=Depends(db)):
    if kind not in RUN:
        raise HTTPException(404, "Unknown scan type")
    if not body.content.strip():
        raise HTTPException(400, "Nothing to scan")
    return save(s, u, RUN[kind](body.content))


@app.post("/api/scan-qr")
async def scan_qr(file: UploadFile = File(...), u=Depends(current_user), s=Depends(db)):
    try:
        res = analyzers.scan_qr(await file.read())
    except ValueError as e:
        raise HTTPException(400, str(e))
    return save(s, u, res)


@app.post("/api/flag/{sid}")
def flag(sid: int, u=Depends(current_user), s=Depends(db)):
    row = s.query(Scan).filter(Scan.id == sid, Scan.user_id == u.id).first()
    if not row:
        raise HTTPException(404, "Scan not found")
    res = json.loads(row.result)
    keys = analyzers.keys_for(res["kind"], res["input"])
    if not keys:
        raise HTTPException(400, "Nothing to report for this scan")
    for k in keys:
        if not s.query(Report).filter(Report.user_id == u.id, Report.key == k).first():
            s.add(Report(user_id=u.id, key=k))
    s.commit()
    return {"count": max(s.query(Report).filter(Report.key == k).count() for k in keys)}


@app.get("/api/history")
def history(u=Depends(current_user), s=Depends(db)):
    rows = s.query(Scan).filter(Scan.user_id == u.id).order_by(Scan.id.desc()).limit(100).all()
    return [json.loads(r.result) | {"id": r.id, "created": r.created.strftime("%d %b %Y %H:%M")} for r in rows]


@app.get("/api/stats")
def stats(u=Depends(current_user), s=Depends(db)):
    rows = s.query(Scan).filter(Scan.user_id == u.id).order_by(Scan.id.desc()).all()
    today = datetime.utcnow().date()
    days = [today - timedelta(days=i) for i in range(6, -1, -1)]
    per_day = {d: 0 for d in days}
    kind_levels = {k: {"Low": 0, "Medium": 0, "High": 0} for k in ("url", "sms", "qr")}
    cats, recent = Counter(), []
    for r in rows:
        if r.created.date() in per_day:
            per_day[r.created.date()] += 1
        kind_levels.setdefault(r.kind, {"Low": 0, "Medium": 0, "High": 0})[r.level] += 1
        res = json.loads(r.result)
        if r.level != "Low":
            cats[res.get("category", "Other")] += 1
        if len(recent) < 6:
            recent.append({"id": r.id, "kind": r.kind, "input": res["input"][:60], "score": r.score,
                           "level": r.level, "created": r.created.strftime("%d %b %H:%M")})
    n = len(rows)
    return {"total": n, "levels": Counter(r.level for r in rows), "kinds": Counter(r.kind for r in rows),
            "avg": round(sum(r.score for r in rows) / n) if n else 0,
            "days": [d.strftime("%d %b") for d in days], "per_day": list(per_day.values()),
            "kind_levels": kind_levels, "categories": cats.most_common(5), "recent": recent,
            "my_reports": s.query(Report).filter(Report.user_id == u.id).count(),
            "community_reports": s.query(Report.key).distinct().count()}


@app.get("/api/report/{sid}")
def report(sid: int, u=Depends(current_user), s=Depends(db)):
    r = s.query(Scan).filter(Scan.id == sid, Scan.user_id == u.id).first()
    if not r:
        raise HTTPException(404, "Report not found")
    return json.loads(r.result) | {"id": r.id, "created": r.created.isoformat()}


@app.get("/")
def home():
    return FileResponse(Path(__file__).parent / "index.html")
