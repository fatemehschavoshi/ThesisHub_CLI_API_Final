from __future__ import annotations

# =======================
# FastAPI application
# =======================

from typing import Optional, List, Dict, Any, Literal
from datetime import datetime, date
from pathlib import Path
import io
import csv
import os
import tempfile

from fastapi import (
    FastAPI, HTTPException, Depends, Request, Form, UploadFile, File, Header, Response
)  # noqa: E402

from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field, validator

# ---- Core imports
from core.repo import (
    STUDENTS_F, TEACHERS_F, COURSES_F, THESIS_F, DEFENDED_F,
    read_json, atomic_write
)
from core.security import (
    verify_password, hash_password, issue_jwt, verify_jwt, login_rate_limiter, needs_rehash
)
from core.rules import (
    DEFAULT_SUPERVISE_CAP, DEFAULT_JUDGE_CAP, ensure_score_range,
    count_supervisions, count_judgings, future_or_today,
    grade_letter, grade_letter_fa, can_request_defense_gate, validate_defense_schedule
)
from core.files import validate_and_copy, FILES_DIR
from core.notifications import emit, list_recent as notif_list, purge_all as notif_purge
from core.audit import log
from core.search import search_archive

# Optional AI modules (graceful fallback)
try:
    from ai.analysis import extract_text, summarize, keywords_tfidf
except Exception:  # pragma: no cover
    extract_text = summarize = keywords_tfidf = None  # type: ignore
try:
    from ai.ocr import validate_images
except Exception:  # pragma: no cover
    def validate_images(*_, **__):  # type: ignore
        return {"available": False}

# ---------------- Path helpers (web assets) ----------------
BASE_DIR = Path(__file__).resolve().parents[1]
TEMPLATES_DIR = BASE_DIR / "web" / "templates"
STATIC_DIR = BASE_DIR / "web" / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(
    title="ThesisHub API",
    description="REST + صفحات HTML ساده برای ThesisHub",
    version="2.3.0",
)

# CORS for local dev tools / frontends (tighten in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static & templates
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


# =======================
# Utilities & Dependencies
# =======================

def _now_iso() -> str:
    """UTC ISO8601 with Z suffix."""
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def _require_student(code: str) -> dict:
    """Load student by code or raise 404."""
    s = next((x for x in read_json(STUDENTS_F) if x.get("student_code") == code), None)
    if not s:
        raise HTTPException(404, detail="دانشجو یافت نشد.")
    return s


def _require_prof(code: str) -> dict:
    """Load professor by code or raise 404."""
    t = next((x for x in read_json(TEACHERS_F) if x.get("teacher_code") == code), None)
    if not t:
        raise HTTPException(404, detail="استاد یافت نشد.")
    return t


def _require_course(course_id: str) -> dict:
    """Load course by id or raise 404."""
    c = next((x for x in read_json(COURSES_F) if x.get("course_id") == course_id), None)
    if not c:
        raise HTTPException(404, detail="درس یافت نشد.")
    return c


def _find_active_thesis(student_code: str, course_id: str) -> Optional[dict]:
    """Find active thesis record (any status) for a student/course."""
    th = read_json(THESIS_F)
    return next((t for t in th if t.get("student_code") == student_code and t.get("course_id") == course_id), None)


def _assert_role_distinct(supervisor: str, internal: str, external: str) -> None:
    """Ensure supervisor/internal/external are distinct."""
    if len({supervisor, internal, external}) != 3:
        raise HTTPException(400, detail="نقش‌ها باید متمایز باشند (راهنما/داخلی/خارجی).")


def _save_upload_to_tmp(uf: UploadFile, fallback_suffix: str) -> Path:
    """
    Persist FastAPI UploadFile into a temp file (streamed, chunked).
    Uses original filename extension when possible.
    """
    tmp_dir = FILES_DIR / "tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    suffix = Path(uf.filename or "").suffix or fallback_suffix
    fd, tmp_path = tempfile.mkstemp(prefix="upload_", suffix=suffix, dir=tmp_dir)
    try:
        with os.fdopen(fd, "wb") as f:
            while True:
                chunk = uf.file.read(1024 * 1024)  # 1MB chunks
                if not chunk:
                    break
                f.write(chunk)
    finally:
        try:
            uf.file.close()
        except Exception:
            pass
    return Path(tmp_path)


# ----- Password compatibility & migration helpers -----

def _stored_hash(user: dict) -> str:
    """Return stored hash; prefer password_hash; else legacy 'password' (if exists)."""
    return user.get("password_hash") or user.get("password") or ""

def _verify_user_password(plain: str, rec: dict) -> bool:
    """
    Backward-compatible password verification:
    - Prefer bcrypt hash in 'password_hash'.
    - If absent/invalid, fallback to legacy 'password' (may be hash or plain).
    """
    candidate = _stored_hash(rec)
    if not candidate:
        return False
    try:
        return verify_password(plain, candidate)
    except Exception:
        return plain == candidate  # last-resort: legacy plain text

def _maybe_upgrade_hash(user: dict, plain_password: str, *, users_path: Path, users_list: list) -> None:
    """
    Upgrade on successful login:
    - Migrate legacy 'password' to 'password_hash'.
    - Rehash if cost policy changed (needs_rehash=true).
    """
    current_hash = _stored_hash(user)
    legacy_used = ("password_hash" not in user) and bool(user.get("password"))

    try:
        needs_up = legacy_used or needs_rehash(current_hash)
    except Exception:
        needs_up = True

    if needs_up:
        user["password_hash"] = hash_password(plain_password)
        user.pop("password", None)
        atomic_write(users_path, users_list)

def _set_user_password(rec: dict, new_plain: str) -> None:
    """Always store bcrypt hash in 'password_hash'; drop legacy field."""
    rec["password_hash"] = hash_password(new_plain)
    rec.pop("password", None)


# ----- JWT Dependencies -----

def _get_bearer_token(authorization: Optional[str] = Header(None)) -> Optional[str]:
    """Extract Bearer token from Authorization header."""
    if not authorization:
        return None
    parts = authorization.split(" ", 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None


def current_student(token: Optional[str] = Depends(_get_bearer_token)) -> dict:
    """Resolve student from JWT; raise 401 if invalid/missing."""
    if not token:
        raise HTTPException(401, detail="توکن ارائه نشده است.")
    payload = verify_jwt(token, expected_role="student")
    return _require_student(payload.get("sub", ""))


def current_professor(token: Optional[str] = Depends(_get_bearer_token)) -> dict:
    """Resolve professor from JWT; raise 401 if invalid/missing."""
    if not token:
        raise HTTPException(401, detail="توکن ارائه نشده است.")
    payload = verify_jwt(token, expected_role="professor")
    return _require_prof(payload.get("sub", ""))


def current_admin_cookie(request: Request) -> dict:
    """Resolve admin via HttpOnly cookie 'admin_token'."""
    token = request.cookies.get("admin_token")
    if not token:
        raise HTTPException(401, detail="توکن ارائه نشده است.")
    payload = verify_jwt(token, expected_role="admin")
    return {"username": payload.get("sub", "admin")}


def current_judge_cookie(request: Request) -> dict:
    """Resolve judge via HttpOnly cookie 'judge_token' (role=professor)."""
    token = request.cookies.get("judge_token")
    if not token:
        raise HTTPException(401, detail="ورود داور معتبر نیست.")
    payload = verify_jwt(token, expected_role="professor")
    prof = _require_prof(payload.get("sub", ""))
    return prof


# ----- Admin auth helpers (env-driven) -----

def _admin_env_user() -> str:
    return os.getenv("THESIS_ADMIN_USER", "admin")

def _admin_env_pass() -> str:
    # If bcrypt$hash is provided, validate via bcrypt; otherwise plain compare (demo).
    return os.getenv("THESIS_ADMIN_PASS", "admin")

def _check_admin_password(plain: str, env_value: str) -> bool:
    """Support 'bcrypt$<hash>' or plain value for demo."""
    if env_value.startswith("bcrypt$"):
        hashed = env_value.split("bcrypt$", 1)[1]
        return verify_password(plain, hashed)
    return plain == env_value


# =======================
# Pydantic Models
# =======================

class LoginIn(BaseModel):
    code: str
    password: str

    @validator("code", "password")
    def not_empty(cls, v):
        if not v or not str(v).strip():
            raise ValueError("فیلد خالی است.")
        return v


class ThesisRequestIn(BaseModel):
    course_id: str


class ThesisMetadataIn(BaseModel):
    course_id: str
    title: str = Field(..., min_length=3, max_length=300)
    abstract: str = Field(..., min_length=10)
    keywords: List[str] = Field(default_factory=list)


class ThesisDefenseByPathIn(BaseModel):
    course_id: str
    pdf_path: str
    cover_path: str
    last_path: str


class ScheduleIn(BaseModel):
    student_code: str
    course_id: str
    defense_date: str  # ISO yyyy-mm-dd
    internal: str
    external: str


class ScoreIn(BaseModel):
    student_code: str
    course_id: str
    role: Literal["internal", "external", "supervisor"]
    score: float

    @validator("score")
    def _score_range(cls, v):
        ensure_score_range(v)
        return v


class FinalizeIn(BaseModel):
    student_code: str
    course_id: str
    semester: Literal["اول", "دوم"]
    result: Literal["defense", "re-defense"] = "defense"


class ChangePasswordIn(BaseModel):
    old_password: str
    new_password: str = Field(..., min_length=6)


# =======================
# Health & Admin (JSON)
# =======================

@app.get("/health", tags=["Admin"])
def health():
    """Basic health check."""
    return {"ok": True, "ts": _now_iso()}


@app.get("/admin/notifications", tags=["Admin"])
def admin_notifications(limit: int = 50, _: dict = Depends(current_admin_cookie)):
    """List recent notifications for debugging/monitoring."""
    return {"items": notif_list(limit=limit)}


@app.post("/admin/notifications/purge", tags=["Admin"])
def admin_notifications_purge(_: dict = Depends(current_admin_cookie)):
    """Purge all notifications (danger zone)."""
    notif_purge()
    return {"ok": True}


@app.get("/admin/metrics", tags=["Admin"])
def admin_metrics(_: dict = Depends(current_admin_cookie)):
    """Aggregate metrics for admin dashboard."""
    students = read_json(STUDENTS_F)
    teachers = read_json(TEACHERS_F)
    courses = read_json(COURSES_F)
    thesis = read_json(THESIS_F)
    defended = read_json(DEFENDED_F)

    def _count_status(st: str) -> int:
        return sum(1 for t in thesis if t.get("status") == st)

    per_prof_supervise: Dict[str, int] = {}
    for t in thesis:
        sup = t.get("supervisor")
        if sup:
            per_prof_supervise[sup] = per_prof_supervise.get(sup, 0) + 1

    per_prof_judge: Dict[str, int] = {}
    for t in thesis:
        j = t.get("judges") or {}
        for k in ("internal", "external"):
            code = j.get(k)
            if code:
                per_prof_judge[code] = per_prof_judge.get(code, 0) + 1

    return {
        "counts": {
            "students": len(students),
            "teachers": len(teachers),
            "courses": len(courses),
            "thesis_pending": _count_status("pending"),
            "thesis_approved": _count_status("approved"),
            "thesis_defense": _count_status("defense"),
            "defended_total": len(defended),
        },
        "loads": {
            "supervisions": per_prof_supervise,
            "judgings": per_prof_judge,
        },
        "recent_notifications": notif_list(limit=15),
    }


# =======================
# Admin Web (HTML)
# =======================

@app.get("/admin/login", response_class=HTMLResponse, tags=["Admin"])
def admin_login_page(request: Request):
    return templates.TemplateResponse("admin_login.html", {"request": request})

@app.post("/admin/login", tags=["Admin"])
def admin_login_form(response: Response, username: str = Form(...), password: str = Form(...)):
    """Set a HttpOnly cookie 'admin_token' instead of putting token in querystring."""
    user_env = _admin_env_user()
    pass_env = _admin_env_pass()
    if username != user_env or not _check_admin_password(password, pass_env):
        raise HTTPException(401, detail="اعتبارسنجی ادمین ناموفق بود.")
    token = issue_jwt(subject=username, role="admin", extra={"name": "Administrator"})
    response = RedirectResponse(url="/admin/dashboard", status_code=302)
    response.set_cookie("admin_token", token, httponly=True, samesite="lax")
    return response

@app.get("/admin/dashboard", response_class=HTMLResponse, tags=["Admin"])
def admin_dashboard(request: Request, _: dict = Depends(current_admin_cookie)):
    """Render simple admin dashboard using metrics API."""
    m = admin_metrics({})
    return templates.TemplateResponse(
        "admin_dashboard.html",
        {
            "request": request,
            "metrics": m,
            "ts": _now_iso(),
        },
    )


# =======================
# Auth (JWT) + Rate limiting
# =======================

@app.post("/auth/student/login", tags=["Auth"])
def auth_student_login(inp: LoginIn):
    """Student JWT login with rate limiting and hash upgrade."""
    key = f"login:student:{inp.code}"
    if not login_rate_limiter.allow(key):
        raise HTTPException(429, detail="تعداد تلاش‌های ورود زیاد است. کمی بعد تلاش کنید.")
    s = _require_student(inp.code)
    if not _verify_user_password(inp.password, s):
        raise HTTPException(401, detail="نام کاربری یا رمز عبور اشتباه است.")

    students = read_json(STUDENTS_F)
    me = next(x for x in students if x["student_code"] == s["student_code"])
    _maybe_upgrade_hash(me, inp.password, users_path=STUDENTS_F, users_list=students)

    token = issue_jwt(subject=inp.code, role="student", extra={"name": s.get("name", "")})
    emit("login_ok", {"role": "student", "code": inp.code}, audience="student", topic="auth")
    return {"token": token, "student": {"code": s["student_code"], "name": s.get("name")}}

@app.post("/auth/professor/login", tags=["Auth"])
def auth_prof_login(inp: LoginIn):
    """Professor JWT login with rate limiting and hash upgrade."""
    key = f"login:prof:{inp.code}"
    if not login_rate_limiter.allow(key):
        raise HTTPException(429, detail="تعداد تلاش‌های ورود زیاد است. کمی بعد تلاش کنید.")
    p = _require_prof(inp.code)
    if not _verify_user_password(inp.password, p):
        raise HTTPException(401, detail="نام کاربری یا رمز عبور اشتباه است.")

    teachers = read_json(TEACHERS_F)
    me = next(x for x in teachers if x["teacher_code"] == p["teacher_code"])
    _maybe_upgrade_hash(me, inp.password, users_path=TEACHERS_F, users_list=teachers)

    token = issue_jwt(subject=inp.code, role="professor", extra={"name": p.get("name", "")})
    emit("login_ok", {"role": "professor", "code": inp.code}, audience="professor", topic="auth")
    return {"token": token, "professor": {"code": p["teacher_code"], "name": p.get("name")}}


# =======================
# Courses
# =======================

@app.get("/courses", tags=["Courses"])
def get_courses(year: Optional[int] = None, semester: Optional[str] = None, only_available: bool = False):
    """List courses with optional filters."""
    cs = read_json(COURSES_F)
    if year is not None:
        cs = [c for c in cs if int(c.get("year", 0)) == int(year)]
    if semester is not None:
        cs = [c for c in cs if c.get("semester") == semester]
    if only_available:
        cs = [c for c in cs if int(c.get("capacity", 0)) > 0]
    return cs


# =======================
# Student endpoints (JWT)
# =======================

@app.get("/student/me", tags=["Student"])
def student_me(s: dict = Depends(current_student)):
    """Return current student profile."""
    return {"code": s["student_code"], "name": s.get("name"), "email": s.get("email", "")}

@app.get("/student/thesis", tags=["Student"])
def student_thesis_list(s: dict = Depends(current_student)):
    """List student's thesis records."""
    th = read_json(THESIS_F)
    return [t for t in th if t.get("student_code") == s["student_code"]]

@app.post("/student/thesis/request", status_code=201, tags=["Student"])
def student_thesis_request(inp: ThesisRequestIn, s: dict = Depends(current_student)):
    """Create thesis request if capacity is available and no active request exists."""
    course = _require_course(inp.course_id)
    if int(course.get("capacity", 0)) <= 0:
        raise HTTPException(400, detail="ظرفیت درس تکمیل است.")
    thesis = read_json(THESIS_F)
    exists = next((t for t in thesis if t["student_code"] == s["student_code"]
                   and t["course_id"] == inp.course_id and t["status"] in ["pending", "approved", "defense"]), None)
    if exists:
        raise HTTPException(400, detail="درخواست فعال قبلاً ثبت شده است.")
    thesis.append({
        "student_code": s["student_code"],
        "course_id": inp.course_id,
        "request_date": date.today().isoformat(),
        "approval_date": None,
        "status": "pending",
        "supervisor": course["teacher_code"],
        "title": "",
        "abstract": "",
        "keywords": [],
    })
    atomic_write(THESIS_F, thesis)
    courses = read_json(COURSES_F)
    for c in courses:
        if c["course_id"] == inp.course_id:
            c["capacity"] = int(c.get("capacity", 0)) - 1
    atomic_write(COURSES_F, courses)
    emit("thesis_requested", {"student": s["student_code"], "course": inp.course_id}, audience="professor", topic="thesis")
    return {"ok": True}

@app.post("/student/thesis/metadata", tags=["Student"])
def student_thesis_metadata(inp: ThesisMetadataIn, s: dict = Depends(current_student)):
    """Update thesis metadata (title/abstract/keywords)."""
    thesis = read_json(THESIS_F)
    rec = next((t for t in thesis if t["student_code"] == s["student_code"] and t["course_id"] == inp.course_id), None)
    if not rec:
        raise HTTPException(404, detail="رکورد پایان‌نامه یافت نشد.")
    rec["title"] = inp.title
    rec["abstract"] = inp.abstract
    rec["keywords"] = [k.strip() for k in inp.keywords if k.strip()]
    atomic_write(THESIS_F, thesis)
    emit("thesis_metadata", {"student": s["student_code"], "course": inp.course_id}, topic="thesis")
    return {"ok": True}

@app.post("/student/thesis/defense/upload", tags=["Student"])
async def student_defense_upload(
    course_id: str = Form(...),
    pdf: UploadFile = File(...),
    cover: UploadFile = File(...),
    last: UploadFile = File(...),
    s: dict = Depends(current_student),
):
    """
    Upload PDF/cover/last via multipart and request defense if allowed.
    - Streams to temp files
    - Validates cover/last with OCR if available
    """
    thesis = read_json(THESIS_F)
    rec = next((t for t in thesis if t["student_code"] == s["student_code"]
                and t["course_id"] == course_id and t["status"] == "approved"), None)
    if not rec:
        raise HTTPException(400, detail="پایان‌نامه تاییدشده‌ای برای دفاع یافت نشد.")

    ok, msg = can_request_defense_gate(rec.get("request_date"), rec.get("approval_date"))
    if not ok:
        raise HTTPException(400, detail=msg)

    tmp_pdf = _save_upload_to_tmp(pdf, ".pdf")
    tmp_cover = _save_upload_to_tmp(cover, ".jpg")
    tmp_last = _save_upload_to_tmp(last, ".jpg")

    ocr_report = validate_images(str(tmp_cover), str(tmp_last))
    if isinstance(ocr_report, dict) and ocr_report.get("available") and (ocr_report.get("ok") is False):
        raise HTTPException(400, detail="اعتبارسنجی OCR جلد/صفحه آخر ناموفق بود.")

    try:
        files = validate_and_copy(str(tmp_pdf), str(tmp_cover), str(tmp_last),
                                  out_prefix=f"{s['student_code']}_{course_id}")
    finally:
        for p in (tmp_pdf, tmp_cover, tmp_last):
            try:
                if p.exists():
                    p.unlink()
            except Exception:
                pass

    rec.update({
        "status": "defense",
        "defense_request_date": date.today().isoformat(),
        "files": files,
        "ocr_validation": ocr_report if isinstance(ocr_report, dict) else None,
    })
    atomic_write(THESIS_F, thesis)
    emit("defense_requested", {"student": s["student_code"], "course": course_id}, audience="professor", topic="defense")
    return {"ok": True, "files": files}

@app.post("/student/thesis/defense/by-path", tags=["Student"])
def student_defense_by_path(inp: ThesisDefenseByPathIn, s: dict = Depends(current_student)):
    """Defense request for CLI mode by providing file paths."""
    thesis = read_json(THESIS_F)
    rec = next((t for t in thesis if t["student_code"] == s["student_code"]
                and t["course_id"] == inp.course_id and t["status"] == "approved"), None)
    if not rec:
        raise HTTPException(400, detail="پایان‌نامه تاییدشده‌ای برای دفاع یافت نشد.")

    ok, msg = can_request_defense_gate(rec.get("request_date"), rec.get("approval_date"))
    if not ok:
        raise HTTPException(400, detail=msg)

    ocr_report = validate_images(inp.cover_path, inp.last_path)
    if isinstance(ocr_report, dict) and ocr_report.get("available") and (ocr_report.get("ok") is False):
        raise HTTPException(400, detail="اعتبارسنجی OCR جلد/صفحه آخر ناموفق بود.")

    files = validate_and_copy(inp.pdf_path, inp.cover_path, inp.last_path,
                              out_prefix=f"{s['student_code']}_{inp.course_id}")
    rec.update({
        "status": "defense",
        "defense_request_date": date.today().isoformat(),
        "files": files,
        "ocr_validation": ocr_report if isinstance(ocr_report, dict) else None,
    })
    atomic_write(THESIS_F, thesis)
    emit("defense_requested", {"student": s["student_code"], "course": inp.course_id}, audience="professor", topic="defense")
    return {"ok": True, "files": files}

@app.post("/student/change-password", tags=["Student"])
def student_change_password(inp: ChangePasswordIn, s: dict = Depends(current_student)):
    """Change student password; always store bcrypt hash."""
    students = read_json(STUDENTS_F)
    me = next(x for x in students if x["student_code"] == s["student_code"])
    if not _verify_user_password(inp.old_password, me):
        raise HTTPException(400, detail="رمز عبور قبلی صحیح نیست.")
    _set_user_password(me, inp.new_password)
    atomic_write(STUDENTS_F, students)
    emit("password_changed", {"role": "student", "code": s["student_code"]}, topic="auth")
    return {"ok": True}


# =======================
# Professor endpoints (JWT)
# =======================

@app.get("/professor/requests", tags=["Professor"])
def professor_requests(p: dict = Depends(current_professor)):
    """List professor's active thesis requests."""
    th = read_json(THESIS_F)
    mine = [t for t in th if t.get("supervisor") == p["teacher_code"] and t.get("status") in ["pending", "approved", "defense"]]
    return {"items": mine}

@app.post("/professor/approve", tags=["Professor"])
def professor_approve(inp: ScoreIn, p: dict = Depends(current_professor)):
    """Approve a pending thesis request (reuse ScoreIn for ids)."""
    th = read_json(THESIS_F)
    rec = next((t for t in th if t["student_code"] == inp.student_code and t["course_id"] == inp.course_id and t["status"] == "pending"), None)
    if not rec:
        raise HTTPException(404, detail="درخواست در حالت انتظار یافت نشد.")
    active = count_supervisions(th, p["teacher_code"])
    if active >= int(p.get("capacity_supervise", DEFAULT_SUPERVISE_CAP)):
        raise HTTPException(400, detail="ظرفیت راهنمایی شما تکمیل است.")
    rec["status"] = "approved"
    rec["approval_date"] = date.today().isoformat()
    rec["supervisor"] = p["teacher_code"]
    atomic_write(THESIS_F, th)
    emit("approved", {"student": inp.student_code, "course": inp.course_id, "supervisor": p["teacher_code"]}, topic="thesis")
    return {"ok": True}

@app.post("/professor/reject", tags=["Professor"])
def professor_reject(inp: ScoreIn, p: dict = Depends(current_professor)):
    """Reject a pending/approved thesis and release course capacity."""
    th = read_json(THESIS_F)
    rec = next((t for t in th if t["student_code"] == inp.student_code and t["course_id"] == inp.course_id and t["status"] in ["pending", "approved"]), None)
    if not rec:
        raise HTTPException(404, detail="درخواست قابل رد یافت نشد.")
    rec["status"] = "rejected"
    atomic_write(THESIS_F, th)
    courses = read_json(COURSES_F)
    for c in courses:
        if c["course_id"] == inp.course_id:
            c["capacity"] = int(c.get("capacity", 0)) + 1
    atomic_write(COURSES_F, courses)
    emit("rejected", {"student": inp.student_code, "course": inp.course_id}, topic="thesis")
    return {"ok": True}

@app.post("/professor/schedule", tags=["Professor"])
def professor_schedule(inp: ScheduleIn, p: dict = Depends(current_professor)):
    """Schedule defense date and assign internal/external judges."""
    th = read_json(THESIS_F)
    rec = next((t for t in th if t["student_code"] == inp.student_code and t["course_id"] == inp.course_id and t["status"] == "defense"), None)
    if not rec:
        raise HTTPException(404, detail="درخواست دفاع یافت نشد.")
    if not future_or_today(inp.defense_date):
        raise HTTPException(400, detail="تاریخ دفاع باید امروز یا آینده باشد.")

    # Extra validation per business rules
    try:
        validate_defense_schedule(
            approval_date_iso=rec.get("approval_date") or "",
            defense_date_iso=inp.defense_date,
            request_date_iso=rec.get("request_date")
        )
    except ValueError as e:
        raise HTTPException(400, detail=str(e))

    _assert_role_distinct(p["teacher_code"], inp.internal, inp.external)

    active_i = count_judgings(th, inp.internal)
    active_e = count_judgings(th, inp.external)
    teachers = read_json(TEACHERS_F)
    t_int = next((x for x in teachers if x["teacher_code"] == inp.internal), None)
    t_ext = next((x for x in teachers if x["teacher_code"] == inp.external), None)
    cap_i = int((t_int or {}).get("capacity_judge", DEFAULT_JUDGE_CAP))
    cap_e = int((t_ext or {}).get("capacity_judge", DEFAULT_JUDGE_CAP))
    if active_i >= cap_i:
        raise HTTPException(400, detail="ظرفیت داور داخلی تکمیل است.")
    if active_e >= cap_e:
        raise HTTPException(400, detail="ظرفیت داور خارجی تکمیل است.")

    rec["defense_date"] = inp.defense_date
    rec["judges"] = {"internal": inp.internal, "external": inp.external}
    atomic_write(THESIS_F, th)
    emit("defense_scheduled", {"student": inp.student_code, "course": inp.course_id, "date": inp.defense_date}, topic="defense")
    return {"ok": True}

@app.post("/professor/score", tags=["Professor"])
def professor_score(inp: ScoreIn, p: dict = Depends(current_professor)):
    """Submit a score by judge or supervisor with role validation."""
    th = read_json(THESIS_F)
    rec = next((t for t in th if t["student_code"] == inp.student_code and t["course_id"] == inp.course_id and t["status"] == "defense"), None)
    if not rec:
        raise HTTPException(404, detail="جلسه دفاع یافت نشد.")

    d = rec.get("defense_date")
    if not d:
        raise HTTPException(400, detail="تاریخ دفاع تعیین نشده است.")
    if date.fromisoformat(d) > date.today():
        raise HTTPException(400, detail="پیش از تاریخ دفاع نمی‌توان نمره ثبت کرد.")

    if inp.role == "internal" and p["teacher_code"] != rec.get("judges", {}).get("internal"):
        raise HTTPException(403, detail="شما داور داخلی این پایان‌نامه نیستید.")
    if inp.role == "external" and p["teacher_code"] != rec.get("judges", {}).get("external"):
        raise HTTPException(403, detail="شما داور خارجی این پایان‌نامه نیستید.")
    if inp.role == "supervisor" and p["teacher_code"] != rec.get("supervisor"):
        raise HTTPException(403, detail="فقط راهنما می‌تواند نمره راهنما را ثبت کند.")

    scores = rec.get("scores") or {"internal": None, "external": None, "supervisor": None}
    if inp.role == "supervisor" and (scores.get("internal") is None or scores.get("external") is None):
        raise HTTPException(400, detail="ابتدا هر دو داور باید نمره بدهند.")
    scores[inp.role] = float(inp.score)
    rec["scores"] = scores
    atomic_write(THESIS_F, th)
    emit("score_submitted", {"student": inp.student_code, "course": inp.course_id, "role": inp.role}, topic="defense")
    return {"ok": True, "scores": scores}

@app.post("/professor/finalize", tags=["Professor"])
def professor_finalize(inp: FinalizeIn, p: dict = Depends(current_professor)):
    """
    Finalize defense:
    - Compute final score and letter grades (EN/FA).
    - Append to archive (judges as object, include scores).
    - Free course capacity and remove active thesis record.
    """
    th = read_json(THESIS_F)
    rec = next((t for t in th if t["student_code"] == inp.student_code and t["course_id"] == inp.course_id and t["status"] == "defense"), None)
    if not rec:
        raise HTTPException(404, detail="جلسه دفاع یافت نشد.")
    scores = rec.get("scores", {})
    if None in [scores.get("internal"), scores.get("external"), scores.get("supervisor")]:
        raise HTTPException(400, detail="ثبت هر سه نمره الزامی است.")

    final_score = (scores["internal"] + scores["external"] + scores["supervisor"]) / 3.0
    letter_en = grade_letter(final_score)
    letter_fa = grade_letter_fa(final_score)

    # Optional AI metadata (best-effort)
    summary, kw = "", []
    try:
        if extract_text and summarize and keywords_tfidf and rec.get("files", {}).get("pdf"):
            text = extract_text(rec["files"]["pdf"])
            summary = summarize(text)
            kw = keywords_tfidf(text)
    except Exception:
        pass

    # Get course year/semester from course row (fallbacks to provided semester/year)
    courses = read_json(COURSES_F)
    course = next((c for c in courses if c.get("course_id") == inp.course_id), {})
    year = int(course.get("year", date.today().year))
    semester = course.get("semester", inp.semester)

    # Append to archive with judges as object and include scores
    archive = read_json(DEFENDED_F)
    archive.append({
        "student_code": inp.student_code,
        "course_id": inp.course_id,
        "title": rec.get("title", ""),
        "year": year,
        "semester": semester,
        "supervisor": rec.get("supervisor", p["teacher_code"]),
        "judges": {
            "internal": rec.get("judges", {}).get("internal", ""),
            "external": rec.get("judges", {}).get("external", "")
        },
        "scores": rec.get("scores", {}),
        "score": final_score,
        "grade_letter": letter_en,
        "grade_letter_fa": letter_fa,
        "result": inp.result,
        "files": rec.get("files", {}),
        "keywords": kw,
        "summary": summary,
        "finalized_at": datetime.utcnow().isoformat() + "Z",
    })
    atomic_write(DEFENDED_F, archive)

    # Free course capacity
    for c in courses:
        if c["course_id"] == inp.course_id:
            c["capacity"] = int(c.get("capacity", 0)) + 1
    atomic_write(COURSES_F, courses)

    # Remove from active list
    th = [t for t in th if not (t["student_code"] == inp.student_code and t["course_id"] == inp.course_id)]
    atomic_write(THESIS_F, th)

    emit("finalized", {"student": inp.student_code, "course": inp.course_id, "score": final_score}, topic="defense")
    return {"ok": True, "score": round(final_score, 2), "grade_letter": letter_en, "grade_letter_fa": letter_fa}

@app.post("/professor/change-password", tags=["Professor"])
def professor_change_password(inp: ChangePasswordIn, p: dict = Depends(current_professor)):
    """Change professor password; always store bcrypt hash."""
    teachers = read_json(TEACHERS_F)
    me = next(x for x in teachers if x["teacher_code"] == p["teacher_code"])
    if not _verify_user_password(inp.old_password, me):
        raise HTTPException(400, detail="رمز عبور قبلی صحیح نیست.")
    _set_user_password(me, inp.new_password)
    atomic_write(TEACHERS_F, teachers)
    emit("password_changed", {"role": "professor", "code": p["teacher_code"]}, topic="auth")
    return {"ok": True}


# =======================
# Judge helpers (web + REST)
# =======================

@app.get("/judge", response_class=HTMLResponse, tags=["Judge"])
def judge_login_page(request: Request):
    """Render judge login page (HTML demo)."""
    return templates.TemplateResponse("judge_login.html", {"request": request})

@app.post("/judge/login", response_class=HTMLResponse, tags=["Judge"])
def judge_login(request: Request, code: str = Form(...), password: str = Form(...)):
    """Judge login via HTML; set cookie-bound JWT."""
    prof = _require_prof(code)
    if not _verify_user_password(password, prof):
        raise HTTPException(401, detail="نام کاربری یا رمز عبور اشتباه است.")

    teachers = read_json(TEACHERS_F)
    me = next(x for x in teachers if x["teacher_code"] == prof["teacher_code"])
    _maybe_upgrade_hash(me, password, users_path=TEACHERS_F, users_list=teachers)

    th = read_json(THESIS_F)
    items = []
    for t in th:
        if t.get("status") != "defense":
            continue
        j = t.get("judges") or {}
        role = "internal" if j.get("internal") == code else ("external" if j.get("external") == code else None)
        if not role:
            continue
        s = (t.get("scores") or {}).get(role)
        if s is None:
            items.append({"student_code": t["student_code"], "course_id": t["course_id"], "role": role})
    token = issue_jwt(subject=code, role="professor", extra={"name": prof.get("name", ""), "judge": True})
    resp = templates.TemplateResponse("judge.html", {"request": request, "prof": prof, "items": items})
    resp.set_cookie("judge_token", token, httponly=True, samesite="lax")
    return resp

class JudgeScoreIn(BaseModel):
    judge_code: str
    student_code: str
    course_id: str
    score: float

    @validator("score")
    def _score(cls, v):
        ensure_score_range(v); return v

@app.post("/judge/score", tags=["Judge"])
def judge_score(inp: JudgeScoreIn, prof: dict = Depends(current_judge_cookie)):
    """Judge submits score; judge_code must match cookie subject."""
    if prof["teacher_code"] != inp.judge_code:
        raise HTTPException(403, detail="جلسه داوری برای شما مجاز نیست.")
    th = read_json(THESIS_F)
    rec = next((t for t in th if t["student_code"] == inp.student_code and t["course_id"] == inp.course_id and t["status"] == "defense"), None)
    if not rec:
        raise HTTPException(404, detail="جلسه دفاع یافت نشد.")
    j = rec.get("judges") or {}
    role = "internal" if j.get("internal") == inp.judge_code else ("external" if j.get("external") == inp.judge_code else None)
    if not role:
        raise HTTPException(403, detail="شما داور این پایان‌نامه نیستید.")
    scores = rec.get("scores") or {"internal": None, "external": None, "supervisor": None}
    scores[role] = float(inp.score)
    rec["scores"] = scores
    atomic_write(THESIS_F, th)
    emit("score_submitted", {"role": role, "student": inp.student_code, "course": inp.course_id}, topic="defense")
    return {"ok": True, "role": role}


# =======================
# Archive (search + show + CSV)
# =======================

@app.get("/archive/search", tags=["Archive"])
def archive_search_api(
    title: Optional[str] = None,
    keyword: Optional[str] = None,
    author: Optional[str] = None,
    year: Optional[int] = None,
    semester: Optional[str] = None,
    supervisor: Optional[str] = None,
    judge: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
):
    """Search defended theses archive."""
    data = read_json(DEFENDED_F)
    res = search_archive(data, title=title, keyword=keyword, author=author, year=year,
                         semester=semester, supervisor=supervisor, judge=judge)
    return {"count": len(res), "items": res[offset: offset + max(1, min(limit, 500))]}

@app.get("/archive/{student_code}/{course_id}", tags=["Archive"])
def archive_show(student_code: str, course_id: str):
    """Return defended thesis record by composite id."""
    for r in read_json(DEFENDED_F):
        if r.get("student_code") == student_code and r.get("course_id") == course_id:
            return r
    raise HTTPException(404, detail="رکورد آرشیو یافت نشد.")

@app.get("/professor/export.csv", tags=["Professor"])
def prof_secure_export_csv(p: dict = Depends(current_professor)):
    """Export professor's defended theses as CSV (JWT required)."""
    archive = read_json(DEFENDED_F)
    mine = [a for a in archive if a.get("supervisor") == p["teacher_code"]]
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["student_code", "course_id", "title", "year", "semester", "score", "grade_letter"])
    for r in mine:
        w.writerow([r.get("student_code"), r.get("course_id"), r.get("title"),
                    r.get("year"), r.get("semester"), r.get("score"), r.get("grade_letter")])
    out.seek(0)
    return StreamingResponse(iter([out.getvalue().encode("utf-8")]), media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=prof_report.csv"})

# Legacy route kept for backward-compat (same behavior)
@app.get("/prof/export.csv", tags=["Professor"])
def prof_legacy_export_csv(p: dict = Depends(current_professor)):
    return prof_secure_export_csv(p)


# =======================
# HTML pages for student/prof dashboards (demo)
# =======================

@app.get("/student/login", response_class=HTMLResponse, tags=["Student"])
def student_login_page(request: Request):
    """Render student login (demo HTML)."""
    return templates.TemplateResponse("login_student.html", {"request": request})

@app.post("/student/login", tags=["Student"])
def student_login_form(code: str = Form(...), password: str = Form(...)):
    """HTML login flow for student; upgrades hash if needed and redirects to dashboard."""
    s = _require_student(code)
    if not _verify_user_password(password, s):
        raise HTTPException(401, detail="ورود نامعتبر.")
    students = read_json(STUDENTS_F)
    me = next(x for x in students if x["student_code"] == s["student_code"])
    _maybe_upgrade_hash(me, password, users_path=STUDENTS_F, users_list=students)
    return RedirectResponse(url=f"/student/dashboard?code={code}", status_code=302)

@app.get("/student/dashboard", response_class=HTMLResponse, tags=["Student"])
def student_dashboard(request: Request, code: str):
    """Render student dashboard (demo HTML)."""
    stu = _require_student(code)
    th = read_json(THESIS_F)
    mine = [t for t in th if t["student_code"] == code]
    return templates.TemplateResponse("student.html", {"request": request, "student": stu, "thesis": mine})

@app.get("/prof/login", response_class=HTMLResponse, tags=["Professor"])
def prof_login_page(request: Request):
    """Render professor login (demo HTML)."""
    return templates.TemplateResponse("login_prof.html", {"request": request})

@app.post("/prof/login", tags=["Professor"])
def prof_login_form(code: str = Form(...), password: str = Form(...)):
    """HTML login flow for professor; upgrades hash if needed and redirects to dashboard."""
    t = _require_prof(code)
    if not _verify_user_password(password, t):
        raise HTTPException(401, detail="ورود نامعتبر.")
    teachers = read_json(TEACHERS_F)
    me = next(x for x in teachers if x["teacher_code"] == t["teacher_code"])
    _maybe_upgrade_hash(me, password, users_path=TEACHERS_F, users_list=teachers)
    return RedirectResponse(url=f"/prof/dashboard?code={code}", status_code=302)

@app.get("/prof/dashboard", response_class=HTMLResponse, tags=["Professor"])
def prof_dashboard(request: Request, code: str):
    """Render professor dashboard (demo HTML)."""
    prof = _require_prof(code)
    thesis = read_json(THESIS_F)
    supervised = [t for t in thesis if t.get("supervisor") == code]
    pending = [t for t in supervised if t["status"] == "pending"]
    approved = [t for t in supervised if t["status"] == "approved"]
    defense = [t for t in supervised if t["status"] == "defense"]
    archive = read_json(DEFENDED_F)
    mine_archive = [a for a in archive if a.get("supervisor") == code]
    stats = {"pending": len(pending), "approved": len(approved), "defense": len(defense), "archived": len(mine_archive)}
    return templates.TemplateResponse("professor.html", {"request": request, "prof": prof, "stats": stats, "defense": defense, "archive": mine_archive})


# =======================
# Global exception -> JSON (Persian message)
# =======================

@app.exception_handler(ValueError)
async def value_error_handler(_, exc: ValueError):
    """Normalize ValueError to JSON 400 with Persian detail."""
    return JSONResponse(status_code=400, content={"detail": str(exc) or "درخواست نامعتبر."})
