#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

# ---------- Std / 3rd party ----------
import os
import io
import csv
import tempfile
from pathlib import Path
from datetime import date, datetime
from functools import wraps
from typing import Dict, Any, List, Optional

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_file, abort, jsonify
)
from werkzeug.utils import secure_filename  # sanitize upload filenames

# ---------- Core imports ----------
from core.repo import (
    STUDENTS_F, TEACHERS_F, COURSES_F, THESIS_F, DEFENDED_F,
    read_json, atomic_write
)
from core.security import verify_password
from core.rules import (
    can_request_defense, future_or_today, ensure_score_range,
    grade_letter, grade_letter_fa, count_judgings, DEFAULT_JUDGE_CAP
)
from core.files import validate_and_copy, FILES_DIR
from core.notifications import emit
from core.audit import log

# (optional) AI helpers
try:
    from ai.analysis import extract_text, summarize, keywords_tfidf
except Exception:
    extract_text = summarize = keywords_tfidf = None  # degrade gracefully

# (optional) PDF minutes generator
try:
    from reports.minutes_pdf import render_minutes as _render_minutes
except Exception:
    _render_minutes = None


# ---------- Flask app ----------
BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
app = Flask(__name__, template_folder=str(TEMPLATES_DIR))

# Security & uploads (configurable via env)
app.secret_key = os.getenv("THESIS_SECRET", "change-me")  # set a strong value in production
app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("THESIS_MAX_UPLOAD_MB", "25")) * 1024 * 1024


# ---------- Session / Auth helpers ----------
def current_user() -> Optional[Dict[str, Any]]:
    """Return current user dict stored in session."""
    return session.get("user")


def login_user(*, role: str, code: str, name: str) -> None:
    """Persist minimal identity in session."""
    session["user"] = {"role": role, "code": code, "name": name, "ts": datetime.utcnow().isoformat() + "Z"}


def logout_user() -> None:
    """Remove user from session."""
    session.pop("user", None)


def role_required(*roles: str):
    """Decorator to require one of roles for route access."""
    def deco(fn):
        @wraps(fn)
        def inner(*args, **kwargs):
            u = current_user()
            if not u or u.get("role") not in roles:
                flash("ابتدا وارد شوید.", "warning")
                return redirect(url_for("home"))
            return fn(*args, **kwargs)
        return inner
    return deco


# ---------- Lightweight accessors ----------
def _students() -> List[dict]: return read_json(STUDENTS_F)
def _teachers() -> List[dict]: return read_json(TEACHERS_F)
def _courses() -> List[dict]:  return read_json(COURSES_F)
def _theses() -> List[dict]:   return read_json(THESIS_F)
def _defended() -> List[dict]: return read_json(DEFENDED_F)

def _save_theses(x: List[dict]) -> None:   atomic_write(THESIS_F, x)
def _save_students(x: List[dict]) -> None: atomic_write(STUDENTS_F, x)
def _save_teachers(x: List[dict]) -> None: atomic_write(TEACHERS_F, x)
def _save_defended(x: List[dict]) -> None: atomic_write(DEFENDED_F, x)
def _save_courses(x: List[dict]) -> None:  atomic_write(COURSES_F, x)

def _teacher_by_code(code: str) -> Optional[dict]:
    return next((t for t in _teachers() if t.get("teacher_code") == code), None)

def _student_by_code(code: str) -> Optional[dict]:
    return next((s for s in _students() if s.get("student_code") == code), None)

def _minutes_pdf_path(student_code: str, course_id: str) -> Path:
    """Return output path for generated minutes PDF."""
    out_dir = FILES_DIR / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir / f"minutes_{student_code}_{course_id}.pdf"


# ---------- Home ----------
@app.get("/")
def home():
    """Render home page."""
    return render_template("home.html")


@app.get("/logout")
def logout():
    """Logout current user and redirect to home."""
    u = current_user()
    if u:
        log("web_logout", u["code"], u["role"])
    logout_user()
    flash("با موفقیت خارج شدید.", "success")
    return redirect(url_for("home"))


# ---------- Student ----------
@app.get("/student/login")
def student_login_get():
    """Render student login form."""
    return render_template("login_student.html")


@app.post("/student/login")
def student_login_post():
    """Handle student login."""
    code = request.form.get("code", "").strip()
    pw = request.form.get("password", "")
    students = _students()
    for s in students:
        if s.get("student_code") == code:
            # support both legacy `password` and new `password_hash`
            hashed = s.get("password_hash") or s.get("password", "")
            if verify_password(pw, hashed):
                s["last_login"] = datetime.utcnow().isoformat() + "Z"
                _save_students(students)
                login_user(role="student", code=code, name=s.get("name", ""))
                emit("student_login", {"student": code})
                log("web_login", code, "student")
                return redirect(url_for("student_dashboard"))
            break
    flash("کد دانشجویی یا رمز عبور نادرست است.", "danger")
    return redirect(url_for("student_login_get"))


@app.get("/student")
@app.get("/student/dashboard")
@role_required("student")
def student_dashboard():
    """Student dashboard."""
    u = current_user()
    my = [t for t in _theses() if t.get("student_code") == u["code"]]
    return render_template("student.html", student={"name": u["name"], "student_code": u["code"]}, thesis=my)


@app.post("/student/thesis/metadata")
@role_required("student")
def student_metadata():
    """Save thesis abstract/keywords."""
    u = current_user()
    course_id = request.form.get("course_id", "").strip()
    abstract = request.form.get("abstract", "")
    keywords = [w.strip() for w in request.form.get("keywords", "").split(",") if w.strip()]

    theses = _theses()
    rec = next((t for t in theses if t.get("student_code") == u["code"] and t.get("course_id") == course_id), None)
    if not rec:
        flash("پایان‌نامه یافت نشد.", "danger")
        return redirect(url_for("student_dashboard"))

    rec["abstract"] = abstract
    rec["keywords"] = keywords
    _save_theses(theses)
    emit("student_metadata", {"student": u["code"], "course": course_id})
    flash("متادیتا ذخیره شد.", "success")
    return redirect(url_for("student_dashboard"))


@app.post("/student/thesis/defense")
@role_required("student")
def student_defense_request():
    """Submit defense request with required files."""
    u = current_user()
    course_id = request.form.get("course_id", "").strip()

    theses = _theses()
    rec = next((t for t in theses if t.get("student_code") == u["code"] and t.get("course_id") == course_id and t.get("status") == "approved"), None)
    if not rec:
        flash("درخواست تأیید‌شده یافت نشد.", "danger")
        return redirect(url_for("student_dashboard"))

    # rule check requires request_date and approval_date
    if not rec.get("approval_date") or not can_request_defense(rec.get("request_date"), rec.get("approval_date")):
        flash("کمتر از ۳ ماه از تاریخ تأیید گذشته است.", "warning")
        return redirect(url_for("student_dashboard"))

    pdf_f = request.files.get("pdf")
    cover_f = request.files.get("cover")
    last_f = request.files.get("last")
    if not (pdf_f and cover_f and last_f):
        flash("ارسال همه‌ی فایل‌ها الزامی است.", "danger")
        return redirect(url_for("student_dashboard"))

    # store upload to temp, then let file-manager move/validate
    with tempfile.TemporaryDirectory() as tmpd:
        p_pdf = Path(tmpd) / secure_filename(pdf_f.filename or "thesis.pdf")
        p_cov = Path(tmpd) / secure_filename(cover_f.filename or "cover.jpg")
        p_last = Path(tmpd) / secure_filename(last_f.filename or "last.jpg")
        pdf_f.save(p_pdf)
        cover_f.save(p_cov)
        last_f.save(p_last)

        # optional OCR validation (persist result if available)
        try:
            from ai.ocr import validate_images
            ocr = validate_images(str(p_cov), str(p_last))
        except Exception:
            ocr = {}

        files = validate_and_copy(str(p_pdf), str(p_cov), str(p_last), out_prefix=f"{u['code']}_{course_id}")

    rec.update({
        "status": "defense",
        "defense_request_date": date.today().isoformat(),
        "files": files,
        "ocr_validation": ocr if isinstance(ocr, dict) else {},
    })
    _save_theses(theses)
    emit("defense_requested", {"student": u["code"], "course": course_id})
    flash("درخواست دفاع ثبت شد.", "success")
    return redirect(url_for("student_dashboard"))


@app.post("/student/thesis/auto-metadata")
@role_required("student")
def student_auto_metadata():
    """AI: derive summary/keywords from uploaded thesis PDF if available."""
    if not (extract_text and summarize and keywords_tfidf):
        flash("ماژول‌های هوش مصنوعی فعال نیستند.", "warning")
        return redirect(url_for("student_dashboard"))

    u = current_user()
    course_id = request.form.get("course_id", "").strip()
    theses = _theses()
    rec = next((t for t in theses if t.get("student_code") == u["code"] and t.get("course_id") == course_id), None)
    if not rec or not rec.get("files", {}).get("pdf"):
        flash("فایل PDF برای تحلیل یافت نشد.", "danger")
        return redirect(url_for("student_dashboard"))

    try:
        text = extract_text(rec["files"]["pdf"])
        rec["summary"] = summarize(text)
        rec["keywords"] = list({*rec.get("keywords", []), *keywords_tfidf(text)})
        _save_theses(theses)
        flash("متادیتای خودکار تولید شد.", "success")
        emit("auto_metadata", {"student": u["code"], "course": course_id})
    except Exception as e:
        flash(f"خطا در تحلیل: {e}", "danger")
    return redirect(url_for("student_dashboard"))


# ---------- Professor ----------
@app.get("/prof/login")
def prof_login_get():
    """Render professor login form."""
    return render_template("login_prof.html")


@app.post("/prof/login")
def prof_login_post():
    """Handle professor login."""
    code = request.form.get("code", "").strip()
    pw = request.form.get("password", "")
    teachers = _teachers()
    for t in teachers:
        if t.get("teacher_code") == code:
            hashed = t.get("password_hash") or t.get("password", "")
            if verify_password(pw, hashed):
                t["last_login"] = datetime.utcnow().isoformat() + "Z"
                _save_teachers(teachers)
                login_user(role="professor", code=code, name=t.get("name", ""))
                emit("prof_login", {"teacher": code})
                log("web_login", code, "professor")
                return redirect(url_for("prof_dashboard"))
            break
    flash("کد استاد یا رمز نادرست است.", "danger")
    return redirect(url_for("prof_login_get"))


@app.get("/prof")
@app.get("/prof/dashboard")
@role_required("professor")
def prof_dashboard():
    """Professor dashboard with stats and archive list."""
    u = current_user()
    theses = _theses()
    mine = [t for t in theses if t.get("supervisor") == u["code"] and t.get("status") in {"pending", "approved", "defense"}]
    stats = {
        "pending": sum(1 for t in mine if t.get("status") == "pending"),
        "approved": sum(1 for t in mine if t.get("status") == "approved"),
        "defense": sum(1 for t in mine if t.get("status") == "defense"),
        "archived": sum(1 for a in _defended() if a.get("supervisor") == u["code"]),
    }
    archive = [a for a in _defended() if a.get("supervisor") == u["code"]]
    return render_template("professor.html", prof={"name": u["name"], "teacher_code": u["code"]}, stats=stats, archive=archive)


@app.post("/prof/reject")
@role_required("professor")
def prof_reject():
    """Professor rejects a pending/approved thesis request and frees capacity."""
    u = current_user()
    student_code = request.form.get("student_code", "").strip()
    course_id = request.form.get("course_id", "").strip()
    reason = request.form.get("reason", "")

    theses = _theses()
    courses = _courses()
    rec = next((t for t in theses if t.get("student_code") == student_code and t.get("course_id") == course_id and t.get("status") in {"pending", "approved"}), None)
    if not rec or rec.get("supervisor") != u["code"]:
        flash("درخواست معتبر یافت نشد.", "danger")
        return redirect(url_for("prof_dashboard"))

    rec["status"] = "rejected"
    # release capacity back to course
    for c in courses:
        if c.get("course_id") == course_id:
            c["capacity"] = int(c.get("capacity", 0)) + 1
    _save_courses(courses)
    _save_theses(theses)

    emit("rejected", {"student": student_code, "course": course_id, "by": u["code"], "reason": reason})
    log("reject", u["code"], f"{student_code}/{course_id}")
    flash("رد شد.", "success")
    return redirect(url_for("prof_dashboard"))


@app.post("/prof/schedule")
@role_required("professor")
def prof_schedule():
    """Professor schedules a defense session with internal/external judges."""
    u = current_user()
    student_code = request.form.get("student_code", "").strip()
    course_id = request.form.get("course_id", "").strip()
    defense_date = request.form.get("defense_date", "").strip()
    internal = request.form.get("internal", "").strip()
    external = request.form.get("external", "").strip()

    theses = _theses()
    rec = next((t for t in theses if t.get("student_code") == student_code and t.get("course_id") == course_id and t.get("status") == "defense"), None)
    if not rec or rec.get("supervisor") != u["code"]:
        flash("درخواست دفاع معتبر یافت نشد.", "danger")
        return redirect(url_for("prof_dashboard"))

    if not future_or_today(defense_date):
        flash("تاریخ دفاع باید امروز یا آینده باشد.", "warning")
        return redirect(url_for("prof_dashboard"))

    # distinct roles for supervisor vs judges
    if internal == external or internal == u["code"] or external == u["code"]:
        flash("راهنما و داوران باید مجزا باشند.", "danger")
        return redirect(url_for("prof_dashboard"))

    teachers = _teachers()
    t_internal = next((x for x in teachers if x.get("teacher_code") == internal), None)
    t_external = next((x for x in teachers if x.get("teacher_code") == external), None)
    cap_i = int((t_internal or {}).get("capacity_judge", DEFAULT_JUDGE_CAP))
    cap_e = int((t_external or {}).get("capacity_judge", DEFAULT_JUDGE_CAP))
    active_i = count_judgings(theses, internal)
    active_e = count_judgings(theses, external)
    if active_i >= cap_i:
        flash("ظرفیت داور داخلی تکمیل است.", "danger"); return redirect(url_for("prof_dashboard"))
    if active_e >= cap_e:
        flash("ظرفیت داور خارجی تکمیل است.", "danger"); return redirect(url_for("prof_dashboard"))

    rec["defense_date"] = defense_date
    rec["judges"] = {"internal": internal, "external": external}
    _save_theses(theses)
    emit("defense_scheduled", {"student": student_code, "course": course_id, "date": defense_date, "internal": internal, "external": external})
    log("schedule", u["code"], f"{student_code}/{course_id} {defense_date}")
    flash("جلسه دفاع زمان‌بندی شد.", "success")
    return redirect(url_for("prof_dashboard"))


@app.post("/prof/finalize")
@role_required("professor")
def prof_finalize():
    """Finalize a defense: compute final score, archive, free capacity, generate minutes (optional)."""
    u = current_user()
    student_code = request.form.get("student_code", "").strip()
    course_id = request.form.get("course_id", "").strip()
    title = request.form.get("title", "").strip()
    year_in = request.form.get("year", "").strip()
    semester_in = request.form.get("semester", "").strip()
    result = request.form.get("result", "defense").strip()
    attendees = [x.strip() for x in request.form.get("attendees", "").split(",") if x.strip()]

    theses = _theses()
    courses = _courses()
    rec = next((t for t in theses if t.get("student_code") == student_code and t.get("course_id") == course_id and t.get("status") == "defense"), None)
    if not rec or rec.get("supervisor") != u["code"]:
        flash("پرونده دفاع معتبر یافت نشد.", "danger")
        return redirect(url_for("prof_dashboard"))

    scores = rec.get("scores", {})
    if None in [scores.get("internal"), scores.get("external"), scores.get("supervisor")]:
        flash("ثبت نمره هر سه نقش الزامی است.", "warning")
        return redirect(url_for("prof_dashboard"))

    final_score = (scores["internal"] + scores["external"] + scores["supervisor"]) / 3.0
    letter_en = grade_letter(final_score)
    letter_fa = grade_letter_fa(final_score)

    # optional NLP
    summary = ""
    kw: List[str] = []
    if extract_text and summarize and keywords_tfidf and rec.get("files", {}).get("pdf"):
        try:
            text = extract_text(rec["files"]["pdf"])
            summary = summarize(text)
            kw = keywords_tfidf(text)
        except Exception:
            summary, kw = "", []

    # read year/semester from course if not provided
    course_row = next((c for c in courses if c.get("course_id") == course_id), {})
    year = int(year_in) if year_in else int(course_row.get("year", date.today().year))
    semester = semester_in or course_row.get("semester", "")

    # archive
    archive = _defended()
    archive.append({
        "student_code": student_code,
        "course_id": course_id,
        "title": title or rec.get("title", ""),
        "year": year,
        "semester": semester,
        "supervisor": u["code"],
        "judges": {
            "internal": rec.get("judges", {}).get("internal", ""),
            "external": rec.get("judges", {}).get("external", "")
        },
        "scores": rec.get("scores", {}),
        "score": final_score,
        "grade_letter": letter_en,
        "grade_letter_fa": letter_fa,
        "result": result,
        "files": rec.get("files", {}),
        "keywords": kw,
        "summary": summary,
        "attendees": attendees,
        "finalized_at": datetime.utcnow().isoformat() + "Z"
    })
    _save_defended(archive)

    # free course capacity back
    for c in courses:
        if c.get("course_id") == course_id:
            c["capacity"] = int(c.get("capacity", 0)) + 1
    _save_courses(courses)

    # remove from active list
    theses = [t for t in theses if not (t.get("student_code") == student_code and t.get("course_id") == course_id)]
    _save_theses(theses)

    # optional: generate minutes PDF
    if _render_minutes:
        try:
            out_pdf = _minutes_pdf_path(student_code, course_id)
            stu_name = (_student_by_code(student_code) or {}).get("name", student_code)
            sup_name = (_teacher_by_code(u["code"]) or {}).get("name", u["code"])
            j_int_code = rec.get("judges", {}).get("internal", "")
            j_ext_code = rec.get("judges", {}).get("external", "")
            j_int_name = (_teacher_by_code(j_int_code) or {}).get("name", j_int_code)
            j_ext_name = (_teacher_by_code(j_ext_code) or {}).get("name", j_ext_code)

            _render_minutes(
                str(out_pdf),
                title=title or rec.get("title", ""),
                student=stu_name,
                supervisor=sup_name,
                judges={"internal": j_int_name, "external": j_ext_name},
                year=year,
                semester=semester,
                final_score=final_score,
                grade_letter=letter_en,  # keep EN letter inside PDF metadata
                result=result,
                student_code=student_code,
                course_id=course_id,
                defense_date=rec.get("defense_date"),
                scores={
                    "internal": scores.get("internal"),
                    "external": scores.get("external"),
                    "supervisor": scores.get("supervisor"),
                },
                attendees=attendees,
                metadata={
                    "Author": stu_name,
                    "Title": f"صورتجلسه دفاع - {title or rec.get('title','')}",
                    "Subject": "Thesis Defense Minutes",
                    "Keywords": kw or rec.get("keywords", []),
                },
            )
            emit("minutes_generated", {"student": student_code, "course": course_id, "file": str(out_pdf)})
        except Exception as e:
            log("minutes_error", u["code"], str(e))

    emit("finalized", {"student": student_code, "course": course_id, "score": final_score})
    flash(f"آرشیو شد. نمره نهایی: {final_score:.2f} ({letter_fa})", "success")
    return redirect(url_for("prof_dashboard"))


@app.get("/prof/export.csv")
@role_required("professor")
def prof_export_csv():
    """Export archive of current supervisor to CSV."""
    u = current_user()
    rows = [["student_code", "course_id", "title", "year", "semester", "score", "grade_letter"]]
    for a in _defended():
        if a.get("supervisor") == u["code"]:
            rows.append([
                a.get("student_code", ""),
                a.get("course_id", ""),
                a.get("title", ""),
                a.get("year", ""),
                a.get("semester", ""),
                a.get("score", ""),
                a.get("grade_letter", ""),
            ])
    buf = io.StringIO()
    csv.writer(buf).writerows(rows)
    return send_file(
        io.BytesIO(buf.getvalue().encode("utf-8")),
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"archive_{u['code']}.csv",
    )


# ---------- Judge ----------
@app.get("/judge/login")
def judge_login_get():
    """Render judge login form."""
    return render_template("judge_login.html")


@app.post("/judge/login")
def judge_login_post():
    """Handle judge login."""
    code = request.form.get("code", "").strip()
    pw = request.form.get("password", "")
    teachers = _teachers()
    for t in teachers:
        if t.get("teacher_code") == code:
            hashed = t.get("password_hash") or t.get("password", "")
            if verify_password(pw, hashed):
                t["last_login"] = datetime.utcnow().isoformat() + "Z"
                _save_teachers(teachers)
                login_user(role="judge", code=code, name=t.get("name", ""))
                emit("judge_login", {"teacher": code})
                log("web_login", code, "judge")
                return redirect(url_for("judge_dashboard"))
            break
    flash("کد/رمز نادرست است.", "danger")
    return redirect(url_for("judge_login_get"))


@app.get("/judge")
@app.get("/judge/dashboard")
@role_required("judge", "professor")
def judge_dashboard():
    """Judge dashboard listing items awaiting their score."""
    u = current_user()
    theses = _theses()
    items = []
    for t in theses:
        if t.get("status") != "defense":
            continue
        j = t.get("judges")
        if isinstance(j, dict):
            j_dict = j
        elif isinstance(j, list) and len(j) >= 2:
            j_dict = {"internal": j[0], "external": j[1]}
        else:
            j_dict = {}

        role = None
        if j_dict.get("internal") == u["code"]:
            role = "internal"
        elif j_dict.get("external") == u["code"]:
            role = "external"

        if not role:
            continue

        scores = t.get("scores", {})
        if scores.get(role) is None:
            items.append({"student_code": t["student_code"], "course_id": t["course_id"], "role": role})

    prof = _teacher_by_code(u["code"]) or {"teacher_code": u["code"], "name": u["name"]}
    return render_template("judge.html", prof=prof, items=items)


@app.post("/judge/score")
@role_required("judge", "professor")
def judge_submit_score():
    """Submit judge score for a defense if the defense date has arrived."""
    u = current_user()
    student_code = request.form.get("student_code", "").strip()
    course_id = request.form.get("course_id", "").strip()
    score = request.form.get("score", "").strip()

    try:
        score = ensure_score_range(float(score))
    except Exception:
        flash("نمره نامعتبر است (۰ تا ۲۰).", "danger")
        return redirect(url_for("judge_dashboard"))

    theses = _theses()
    rec = next((t for t in theses if t.get("student_code") == student_code and
                t.get("course_id") == course_id and t.get("status") == "defense"), None)
    if not rec:
        flash("پرونده دفاع یافت نشد.", "danger")
        return redirect(url_for("judge_dashboard"))

    d = rec.get("defense_date")
    if not d:
        flash("تاریخ دفاع ثبت نشده است.", "danger")
        return redirect(url_for("judge_dashboard"))
    if date.fromisoformat(d) > date.today():
        flash("ثبت نمره پیش از تاریخ دفاع مجاز نیست.", "warning")
        return redirect(url_for("judge_dashboard"))

    j = rec.get("judges")
    if isinstance(j, dict):
        j_dict = j
    elif isinstance(j, list) and len(j) >= 2:
        j_dict = {"internal": j[0], "external": j[1]}
    else:
        j_dict = {}

    role = None
    if j_dict.get("internal") == u["code"]:
        role = "internal"
    if j_dict.get("external") == u["code"]:
        role = "external" if role is None else role

    if not role:
        flash("شما داور این پرونده نیستید.", "danger")
        return redirect(url_for("judge_dashboard"))

    scores = rec.get("scores") or {"internal": None, "external": None, "supervisor": None}
    scores[role] = score
    rec["scores"] = scores
    _save_theses(theses)

    emit("score_submitted", {"student": student_code, "course": course_id, "by": u["code"], "role": role, "score": score})
    flash("نمره ثبت شد.", "success")
    return redirect(url_for("judge_dashboard"))


# ---------- Admin ----------
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "admin123")


@app.get("/admin/login")
def admin_login_get():
    """Render admin login."""
    return render_template("admin_login.html")


@app.post("/admin/login")
def admin_login_post():
    """Handle admin login."""
    user = request.form.get("user", "")
    pw = request.form.get("password", "")
    if user == ADMIN_USER and pw == ADMIN_PASS:
        login_user(role="admin", code="admin", name="Admin")
        log("web_login", "admin", "admin")
        return redirect(url_for("admin_dashboard"))
    flash("اطلاعات ادمین نادرست است.", "danger")
    return redirect(url_for("admin_login_get"))


@app.get("/admin")
@app.get("/admin/dashboard")
@role_required("admin")
def admin_dashboard():
    """Admin dashboard with quick stats and notifications."""
    stats = {
        "students": len(_students()),
        "teachers": len(_teachers()),
        "courses": len(_courses()),
        "thesis_active": len(_theses()),
        "defended": len(_defended()),
    }
    try:
        from core.notifications import list_recent
        recent = list_recent(15)
    except Exception:
        recent = []
    return render_template("admin_dashboard.html", stats=stats, notifications=recent)


@app.post("/admin/seed")
@role_required("admin")
def admin_seed():
    """Seed minimal data if backing JSON files are empty."""
    students, teachers, courses = _students(), _teachers(), _courses()
    changed = False
    if not students:
        atomic_write(STUDENTS_F, [
            {"name": "Alice", "student_code": "s001", "password": "$2b$12$abcdefghijklmnopqrstuv", "email": "alice@example.com", "last_login": None, "status": "active"},
            {"name": "Bob",   "student_code": "s002", "password": "$2b$12$abcdefghijklmnopqrstuv", "email": "bob@example.com",   "last_login": None, "status": "active"},
        ])
        changed = True
    if not teachers:
        atomic_write(TEACHERS_F, [
            {"name": "Prof One",   "teacher_code": "t001", "password": "$2b$12$abcdefghijklmnopqrstuv", "capacity_supervise": 5, "capacity_judge": 10, "email": "one@uni.edu",   "last_login": None, "status": "active"},
            {"name": "Prof Two",   "teacher_code": "t002", "password": "$2b$12$abcdefghijklmnopqrstuv", "capacity_supervise": 5, "capacity_judge": 10, "email": "two@uni.edu",   "last_login": None, "status": "active"},
            {"name": "Prof Three", "teacher_code": "t003", "password": "$2b$12$abcdefghijklmnopqrstuv", "capacity_supervise": 5, "capacity_judge": 10, "email": "three@uni.edu", "last_login": None, "status": "active"},
        ])
        changed = True
    if not courses:
        atomic_write(COURSES_F, [
            {"course_id": "C01", "course_title": "Thesis A", "teacher_code": "t001", "year": 1404, "semester": "اول", "capacity": 2, "resources": ["paper1"], "sessions": 16, "units": 6},
            {"course_id": "C02", "course_title": "Thesis B", "teacher_code": "t002", "year": 1404, "semester": "اول", "capacity": 1, "resources": ["paper2"], "sessions": 16, "units": 6},
        ])
        changed = True

    flash("Seed انجام شد." if changed else "داده‌ها از قبل وجود دارند.", "success" if changed else "info")
    return redirect(url_for("admin_dashboard"))


@app.get("/admin/health.json")
@role_required("admin")
def admin_health():
    """Simple cross-ref validation used by admin dashboard."""
    ok = True
    errs = []
    students, teachers, courses, thesis, defended = _students(), _teachers(), _courses(), _theses(), _defended()

    # uniqueness
    for label, arr, key in [("students", students, "student_code"),
                            ("teachers", teachers, "teacher_code"),
                            ("courses", courses, "course_id")]:
        seen = set()
        for r in arr:
            k = r.get(key)
            if not k or k in seen:
                ok = False; errs.append(f"Duplicate or missing {key} in {label}: {k}")
            seen.add(k)

    # FK checks
    for t in thesis:
        if not any(s.get("student_code") == t.get("student_code") for s in students):
            ok = False
            errs.append(f"Thesis FK error student {t.get('student_code')}")
        if not any(c.get("course_id") == t.get("course_id") for c in courses):
            ok = False
            errs.append(f"Thesis FK error course {t.get('course_id')}")

    return jsonify({"ok": ok, "errors": errs})


# ---------- Files (safe serve) ----------
@app.get("/files/<path:rel>")
def serve_file(rel: str):
    """Serve files only from FILES_DIR to avoid path traversal."""
    safe = (FILES_DIR / rel).resolve()
    if not str(safe).startswith(str(FILES_DIR.resolve())) or not safe.exists():
        abort(404)
    return send_file(safe)


# ---------- Entry ----------
if __name__ == "__main__":
    # Default to 5000; override with PORT env
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=os.getenv("FLASK_DEBUG", "1") == "1")
