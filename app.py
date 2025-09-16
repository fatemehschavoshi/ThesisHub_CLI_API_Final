#!/usr/bin/env python3
from __future__ import annotations

# ======================== Imports ========================
import csv
import json
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, date
from pathlib import Path

import typer
from rich import print
from rich.table import Table
from rich.panel import Panel

# ---- Core imports
from core.repo import (
    STUDENTS_F, TEACHERS_F, COURSES_F, THESIS_F, DEFENDED_F, NOTIF_F,
    read_json, atomic_write,
    register_student, register_teacher
)
from core.security import (
    verify_password, hash_password, needs_rehash,
    login_rate_limiter, issue_jwt, verify_jwt
)
from core.rules import (
    DEFAULT_SUPERVISE_CAP, DEFAULT_JUDGE_CAP,
    can_request_defense, count_supervisions, count_judgings,
    future_or_today, grade_letter, grade_letter_fa, ensure_score_range
)
from core.files import validate_and_copy, FILES_DIR
from core.search import search_archive
from core.notifications import emit
from core.audit import log

# ---- Optional AI modules (graceful fallback)
try:
    from ai.analysis import extract_text, summarize, keywords_tfidf
except Exception:
    extract_text = summarize = keywords_tfidf = None  # degrade gracefully

try:
    from ai.ocr import validate_images
except Exception:
    def validate_images(*args, **kwargs): return {}

# Optional PDF minutes
try:
    from reports.minutes_pdf import render_minutes as _render_minutes
except Exception:
    _render_minutes = None

# ======================== Typer Apps ========================
app = typer.Typer(add_completion=False, help="ThesisHub CLI")
student_app = typer.Typer(help="Student commands")
prof_app = typer.Typer(help="Professor (supervisor) commands")
judge_app = typer.Typer(help="Judge-only commands")
archive_app = typer.Typer(help="Archive/thesis search commands")
admin_app = typer.Typer(help="Admin/maintenance commands")

app.add_typer(student_app, name="student")
app.add_typer(prof_app, name="professor")
app.add_typer(judge_app, name="judge")
app.add_typer(archive_app, name="archive")
app.add_typer(admin_app, name="admin")


# ======================== Helpers ========================
def _load_all() -> Tuple[list, list, list, list, list]:
    return (
        read_json(STUDENTS_F),
        read_json(TEACHERS_F),
        read_json(COURSES_F),
        read_json(THESIS_F),
        read_json(DEFENDED_F),
    )

def _course_by_id(course_id: str) -> Optional[Dict[str, Any]]:
    for c in read_json(COURSES_F):
        if c.get("course_id") == course_id:
            return c
    return None

def _today_iso() -> str:
    return datetime.now().date().isoformat()

def _minutes_pdf_path(student_code: str, course_id: str) -> Path:
    out_dir = FILES_DIR / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir / f"minutes_{student_code}_{course_id}.pdf"

def _ensure_semester(value: str):
    if value not in {"اول", "دوم"}:
        raise typer.BadParameter("semester must be 'اول' or 'دوم'")

def _rehash_if_needed(entity_list: list, key_field: str, code: str, plain: str, password_field: str, json_path: Path):
    """Transparent hash upgrade if bcrypt policy changes."""
    for rec in entity_list:
        if rec.get(key_field) == code:
            if needs_rehash(rec.get(password_field, "")):
                rec[password_field] = hash_password(plain)
                atomic_write(json_path, entity_list)
                log("rehash", code, json_path.name)
            return

def _require_course_ownership(supervisor_code: str, thesis_rec: dict):
    """Ensure professor is the assigned supervisor of this thesis request."""
    if thesis_rec.get("supervisor") != supervisor_code:
        raise typer.BadParameter("Only the assigned supervisor can perform this action")

def _scores_complete(scores: dict) -> bool:
    return all(scores.get(k) is not None for k in ("internal", "external", "supervisor"))


# ======================== Auth (password/JWT) ========================
def _student_auth(*, code: Optional[str] = None, password: Optional[str] = None, token: Optional[str] = None) -> Dict[str, Any]:
    students = read_json(STUDENTS_F)
    if token:
        payload = verify_jwt(token, expected_role="student")
        code = payload.get("sub")
        for s in students:
            if s.get("student_code") == code:
                return s
        raise typer.BadParameter("Token OK but student not found")
    key = f"login:student:{code}"
    if not login_rate_limiter.allow(key):
        raise typer.BadParameter("Too many attempts; try later")
    for s in students:
        stored_hash = s.get("password") or s.get("password_hash", "")
        if s.get("student_code") == code and verify_password(password or "", stored_hash):
            stored_key = "password" if "password" in s else "password_hash"
            _rehash_if_needed(students, "student_code", code, password or "", stored_key, STUDENTS_F)
            return s
    raise typer.BadParameter("Invalid student credentials")

def _prof_auth(*, code: Optional[str] = None, password: Optional[str] = None, token: Optional[str] = None) -> Dict[str, Any]:
    teachers = read_json(TEACHERS_F)
    if token:
        payload = verify_jwt(token, expected_role="professor")
        code = payload.get("sub")
        for t in teachers:
            if t.get("teacher_code") == code:
                return t
        raise typer.BadParameter("Token OK but professor not found")
    key = f"login:prof:{code}"
    if not login_rate_limiter.allow(key):
        raise typer.BadParameter("Too many attempts; try later")
    for t in teachers:
        stored_hash = t.get("password") or t.get("password_hash", "")
        if t.get("teacher_code") == code and verify_password(password or "", stored_hash):
            stored_key = "password" if "password" in t else "password_hash"
            _rehash_if_needed(teachers, "teacher_code", code, password or "", stored_key, TEACHERS_F)
            return t
    raise typer.BadParameter("Invalid professor credentials")

def _judge_auth(*, code: Optional[str] = None, password: Optional[str] = None, token: Optional[str] = None) -> Dict[str, Any]:
    """Judge is also a teacher; role=professor in token, but limited commands."""
    return _prof_auth(code=code, password=password, token=token)


# ======================== Admin / Maintenance ========================
@admin_app.command("init")
def init():
    """Create empty data files if not exist."""
    for f in [STUDENTS_F, TEACHERS_F, COURSES_F, THESIS_F, DEFENDED_F, NOTIF_F]:
        if not f.exists():
            atomic_write(f, [])
    typer.secho("Initialized data files.", fg=typer.colors.GREEN)

@admin_app.command("seed")
def seed():
    """Seed sample users/courses if empty."""
    students, teachers, courses, thesis, defended = _load_all()
    if not students:
        atomic_write(STUDENTS_F, [
            {"name": "Alice", "student_code": "s001", "password": hash_password("pass"), "email": "alice@example.com"},
            {"name": "Bob",   "student_code": "s002", "password": hash_password("pass"), "email": "bob@example.com"},
        ])
    if not teachers:
        atomic_write(TEACHERS_F, [
            {"name": "Prof One",   "teacher_code": "t001", "password": hash_password("pass"), "capacity_supervise": 5, "capacity_judge": 10, "email": "one@uni.edu"},
            {"name": "Prof Two",   "teacher_code": "t002", "password": hash_password("pass"), "capacity_supervise": 5, "capacity_judge": 10, "email": "two@uni.edu"},
            {"name": "Prof Three", "teacher_code": "t003", "password": hash_password("pass"), "capacity_supervise": 5, "capacity_judge": 10, "email": "three@uni.edu"},
        ])
    if not courses:
        atomic_write(COURSES_F, [
            {"course_id": "C01", "course_title": "Thesis A", "teacher_code": "t001", "year": 1404, "semester": "اول", "capacity": 2, "resources": ["paper1"], "sessions": 16, "units": 6},
            {"course_id": "C02", "course_title": "Thesis B", "teacher_code": "t002", "year": 1404, "semester": "اول", "capacity": 1, "resources": ["paper2"], "sessions": 16, "units": 6},
        ])
    if not thesis:
        atomic_write(THESIS_F, [])
    if not defended:
        atomic_write(DEFENDED_F, [])
    if not read_json(NOTIF_F):
        atomic_write(NOTIF_F, [])
    typer.secho("Seeded sample data.", fg=typer.colors.GREEN)

@admin_app.command("health")
def health_check(json_out: bool = typer.Option(False, help="Print JSON object instead of colored text")):
    """Validate data integrity & cross-references."""
    students, teachers, courses, thesis, defended = _load_all()

    ok = True
    issues: List[str] = []

    # unique keys
    for label, arr, key in [
        ("students", students, "student_code"),
        ("teachers", teachers, "teacher_code"),
        ("courses",  courses,  "course_id"),
    ]:
        seen = set()
        for r in arr:
            k = r.get(key)
            if not k:
                ok = False; issues.append(f"{label}: missing {key}")
            if k in seen:
                ok = False; issues.append(f"{label}: duplicate {key}={k}")
            seen.add(k)

    # FK checks
    sset = {s.get("student_code") for s in students}
    cset = {c.get("course_id") for c in courses}
    for t in thesis:
        if t.get("student_code") not in sset:
            ok = False; issues.append(f"thesis FK: unknown student {t.get('student_code')}")
        if t.get("course_id") not in cset:
            ok = False; issues.append(f"thesis FK: unknown course {t.get('course_id')}")

    report = {
        "ok": ok,
        "counts": {
            "students": len(students),
            "teachers": len(teachers),
            "courses": len(courses),
            "thesis_active": len(thesis),
            "defended": len(defended),
        },
        "issues": issues,
    }
    if json_out:
        print(Panel.fit(json.dumps(report, ensure_ascii=False, indent=2)))
    else:
        if ok:
            print(Panel.fit("[green]HEALTH OK[/green]"))
        else:
            print(Panel.fit("[red]HEALTH ISSUES FOUND[/red]"))
            for i in issues:
                print(f"[red]- {i}[/red]")

@admin_app.command("backup")
def admin_backup(outdir: str = typer.Option("./backup", help="Directory to store JSON snapshots")):
    """Backup all JSON files into a timestamped directory."""
    od = Path(outdir)
    od.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    dst = od / f"snapshot_{ts}"
    dst.mkdir()
    for f in [STUDENTS_F, TEACHERS_F, COURSES_F, THESIS_F, DEFENDED_F, NOTIF_F]:
        (dst / f.name).write_text(Path(f).read_text(encoding="utf-8"), encoding="utf-8")
    typer.secho(f"Backup saved to {dst}", fg=typer.colors.GREEN)

@admin_app.command("purge-notifs")
def purge_notifications():
    """Clear notifications JSON."""
    atomic_write(NOTIF_F, [])
    typer.secho("Notifications cleared.", fg=typer.colors.GREEN)


# ======================== Student Commands ========================
@student_app.command("register")
def student_register(name: str, student_code: str, password: str, email: str = ""):
    """(Optional) Register a new student."""
    rec = register_student(name, student_code, password, email)
    print(Panel.fit(f"[green]Student registered[/green]\n{json.dumps(rec, ensure_ascii=False, indent=2)}"))
    emit("student_registered", {"student": student_code})
    log("student_register", student_code, "")

@student_app.command("login")
def student_login(code: str, password: str, jwt: bool = typer.Option(True, help="Return a JWT if configured")):
    """Password login; returns a JWT if THESIS_JWT_SECRET set."""
    s = _student_auth(code=code, password=password)
    typer.secho("Login OK", fg=typer.colors.GREEN)
    if jwt:
        try:
            token = issue_jwt(subject=code, role="student", extra={"name": s.get("name", "")})
            print(Panel.fit(f"[cyan]JWT[/cyan]\n{token}"))
        except Exception as e:
            print(f"[yellow]JWT not configured[/yellow]: {e}")

@student_app.command("whoami")
def student_whoami(token: str):
    payload = verify_jwt(token, expected_role="student")
    print(Panel.fit(json.dumps(payload, ensure_ascii=False, indent=2)))

@student_app.command("change-password")
def student_change_password(student_code: str, old: str, new: str):
    students = read_json(STUDENTS_F)
    for s in students:
        if s.get("student_code") == student_code:
            stored_key = "password" if "password" in s else "password_hash"
            if verify_password(old, s.get(stored_key, "")):
                s[stored_key] = hash_password(new)
                atomic_write(STUDENTS_F, students)
                print("[green]OK[/green] password changed")
                log("student_change_password", student_code, "")
                return
    print("[red]Failed[/red] invalid credentials")

@student_app.command("courses")
def student_courses(year: Optional[int] = None, semester: Optional[str] = None, only_available: bool = True):
    """List thesis courses (optionally filter by year/semester)."""
    courses = read_json(COURSES_F)
    if year is not None:
        courses = [c for c in courses if int(c.get("year", 0)) == int(year)]
    if semester is not None:
        courses = [c for c in courses if c.get("semester") == semester]
    if only_available:
        courses = [c for c in courses if int(c.get("capacity", 0)) > 0]

    tbl = Table(title="Courses")
    for col in ["CourseID", "Title", "Teacher", "Year", "Semester", "Capacity"]:
        tbl.add_column(col)
    for c in courses:
        tbl.add_row(c["course_id"], c["course_title"], c["teacher_code"], str(c["year"]), c["semester"], str(c["capacity"]))
    print(tbl)

@student_app.command("request")
def student_request(code: Optional[str] = typer.Option(None), password: Optional[str] = typer.Option(None),
                    token: Optional[str] = typer.Option(None, help="JWT instead of code/password"),
                    course_id: str = typer.Option(...)):
    """Submit a new thesis request (status=pending). Reserve course capacity."""
    if token:
        s = _student_auth(token=token)
        code = s["student_code"]
    else:
        _ = _student_auth(code=code, password=password)

    course = _course_by_id(course_id)
    if not course:
        raise typer.BadParameter("Course not found")
    if int(course.get("capacity", 0)) <= 0:
        raise typer.BadParameter("Course is full")

    thesis = read_json(THESIS_F)
    exists = next((t for t in thesis if t["student_code"] == code and t["course_id"] == course_id and t["status"] in ["pending", "approved", "defense"]), None)
    if exists:
        raise typer.BadParameter("Active request already exists")

    thesis.append({
        "student_code": code,
        "course_id": course_id,
        "request_date": _today_iso(),
        "approval_date": None,
        "status": "pending",
        "supervisor": course["teacher_code"],
        "title": "",
        "abstract": "",
        "keywords": [],
        "files": {},
        "scores": {"internal": None, "external": None, "supervisor": None}
    })
    atomic_write(THESIS_F, thesis)

    # Reserve capacity at request time (prevents race)
    courses = read_json(COURSES_F)
    for c in courses:
        if c["course_id"] == course_id:
            c["capacity"] = max(0, int(c.get("capacity", 0)) - 1)
    atomic_write(COURSES_F, courses)

    emit("thesis_requested", {"student": code, "course": course_id})
    log("request", code, course_id)
    typer.secho("Request submitted", fg=typer.colors.GREEN)

@student_app.command("cancel")
def student_cancel(code: Optional[str] = None, password: Optional[str] = None, token: Optional[str] = None,
                   course_id: str = typer.Option(...)):
    """Cancel a pending request (frees course capacity)."""
    if token:
        s = _student_auth(token=token)
        code = s["student_code"]
    else:
        _ = _student_auth(code=code, password=password)

    thesis = read_json(THESIS_F)
    rec = next((t for t in thesis if t["student_code"] == code and t["course_id"] == course_id and t["status"] == "pending"), None)
    if not rec:
        raise typer.BadParameter("No pending request to cancel")

    thesis = [t for t in thesis if not (t["student_code"] == code and t["course_id"] == course_id and t["status"] == "pending")]
    atomic_write(THESIS_F, thesis)

    # free capacity
    courses = read_json(COURSES_F)
    for c in courses:
        if c["course_id"] == course_id:
            c["capacity"] = int(c.get("capacity", 0)) + 1
    atomic_write(COURSES_F, courses)

    emit("thesis_cancelled", {"student": code, "course": course_id})
    log("cancel", code, course_id)
    typer.secho("Cancelled.", fg=typer.colors.GREEN)

@student_app.command("status")
def student_status(code: Optional[str] = None, password: Optional[str] = None, token: Optional[str] = None):
    """Show all thesis requests for this student."""
    if token:
        s = _student_auth(token=token)
        code = s["student_code"]
    else:
        _ = _student_auth(code=code, password=password)

    thesis = read_json(THESIS_F)
    my = [t for t in thesis if t["student_code"] == code]
    tbl = Table(title=f"Thesis Requests for {code}")
    for col in ["Course", "Status", "Requested", "Approved", "DefenseDate", "Supervisor", "Title"]:
        tbl.add_column(col)
    for t in my:
        tbl.add_row(
            t["course_id"], t.get("status", ""), t.get("request_date", ""),
            str(t.get("approval_date", "")), str(t.get("defense_date", "")),
            t.get("supervisor", ""), t.get("title", "")
        )
    print(tbl)

@student_app.command("metadata")
def student_metadata(student_code: Optional[str] = None, password: Optional[str] = None, token: Optional[str] = None,
                     course_id: str = typer.Option(...),
                     title: str = typer.Option(..., help="عنوان پایان‌نامه"),
                     abstract: str = typer.Option(..., help="چکیده"),
                     keywords: str = typer.Option("", help="کلمات کلیدی با ویرگول")):
    """Save thesis title/abstract/keywords (by student)."""
    if token:
        s = _student_auth(token=token)
        student_code = s["student_code"]
    else:
        _ = _student_auth(code=student_code, password=password)

    thesis = read_json(THESIS_F)
    rec = next((t for t in thesis if t.get("student_code") == student_code and t.get("course_id") == course_id), None)
    if not rec:
        print("[red]Thesis not found[/red]"); return
    rec["title"] = title
    rec["abstract"] = abstract
    rec["keywords"] = [w.strip() for w in keywords.split(",") if w.strip()]
    atomic_write(THESIS_F, thesis)
    print("[green]OK[/green] metadata saved")
    log("student_metadata", student_code, course_id)

@student_app.command("defense-request")
def student_defense(code: Optional[str] = None, password: Optional[str] = None, token: Optional[str] = None,
                    course_id: str = typer.Option(...),
                    pdf: str = typer.Option(..., help="path to thesis PDF"),
                    cover: str = typer.Option(..., help="path to first-page image (jpg)"),
                    last: str = typer.Option(..., help="path to last-page image (jpg)")):
    """Request defense (>=3 months after approval, upload files, optional OCR validation)."""
    if token:
        s = _student_auth(token=token)
        code = s["student_code"]
    else:
        _ = _student_auth(code=code, password=password)

    thesis = read_json(THESIS_F)
    rec = next((t for t in thesis if t["student_code"] == code and t["course_id"] == course_id and t["status"] == "approved"), None)
    if not rec:
        raise typer.BadParameter("No approved thesis found")
    if not rec.get("approval_date"):
        raise typer.BadParameter("Approval date missing")
    # Correct signature: (request_date, approval_date)
    if not can_request_defense(rec.get("request_date"), rec.get("approval_date")):
        raise typer.BadParameter("Less than 3 months since approval/request")

    # OCR validation (optional)
    ocr = validate_images(cover, last)
    files = validate_and_copy(pdf, cover, last, out_prefix=f"{code}_{course_id}")

    rec.update({
        "status": "defense",
        "defense_request_date": _today_iso(),
        "files": files,
        "ocr_validation": ocr,
    })
    atomic_write(THESIS_F, thesis)
    emit("defense_requested", {"student": code, "course": course_id})
    log("defense_request", code, course_id)
    typer.secho("Defense requested", fg=typer.colors.GREEN)


# ======================== Archive Commands ========================
@archive_app.command("search")
def archive_search_cmd(
    title: str = typer.Option(None),
    keyword: str = typer.Option(None),
    author: str = typer.Option(None),
    year: int = typer.Option(None),
    semester: str = typer.Option(None),
    supervisor: str = typer.Option(None),
    judge: str = typer.Option(None),
):
    archive = read_json(DEFENDED_F)
    res = search_archive(archive, title=title, keyword=keyword, author=author, year=year, semester=semester, supervisor=supervisor, judge=judge)
    tbl = Table(title="Archive")
    cols = ["Student", "Course", "Title", "Year", "Sem", "Supervisor", "Judges", "Score", "Letter"]
    for c in cols:
        tbl.add_column(c)
    for r in res:
        judges_disp = r.get("judges", [])
        if isinstance(judges_disp, dict):
            judges_disp = [judges_disp.get("internal", ""), judges_disp.get("external", "")]
        tbl.add_row(
            r.get("student_code", ""), r.get("course_id", ""), r.get("title", ""),
            str(r.get("year", "")), r.get("semester", ""),
            r.get("supervisor", ""), ", ".join([j for j in judges_disp if j]),
            f"{float(r.get('score', 0)):.2f}", r.get("grade_letter", "")
        )
    print(tbl)

@archive_app.command("export-csv")
def archive_export_csv(out: str = typer.Option("archive_export.csv")):
    """Export defended_thesis to CSV."""
    rows = read_json(DEFENDED_F)
    if not rows:
        typer.echo("No data.")
        return
    keys = ["student_code","course_id","title","year","semester","supervisor","judges","score","grade_letter"]
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        for r in rows:
            r2 = r.copy()
            j = r2.get("judges", [])
            if isinstance(j, dict):
                j = [j.get("internal",""), j.get("external","")]
            r2["judges"] = ", ".join([x for x in j if x])
            w.writerow({k: r2.get(k, "") for k in keys})
    typer.secho(f"CSV written to {out}", fg=typer.colors.GREEN)

@archive_app.command("show")
def archive_show(student_code: str, course_id: str):
    """Show a single archived record."""
    for r in read_json(DEFENDED_F):
        if r.get("student_code") == student_code and r.get("course_id") == course_id:
            print(Panel.fit(json.dumps(r, ensure_ascii=False, indent=2)))
            return
    print("[red]Not found[/red]")


# ======================== Professor (Supervisor) ========================
@prof_app.command("register")
def professor_register(name: str, teacher_code: str, password: str, email: str = "",
                       capacity_supervise: int = 5, capacity_judge: int = 10):
    rec = register_teacher(name, teacher_code, password, email, capacity_supervise, capacity_judge)
    print(Panel.fit(f"[green]Professor registered[/green]\n{json.dumps(rec, ensure_ascii=False, indent=2)}"))
    emit("professor_registered", {"teacher": teacher_code})
    log("professor_register", teacher_code, "")

@prof_app.command("login")
def professor_login(code: str, password: str, jwt: bool = typer.Option(True, help="Return a JWT if configured")):
    p = _prof_auth(code=code, password=password)
    typer.secho("Login OK", fg=typer.colors.GREEN)
    if jwt:
        try:
            token = issue_jwt(subject=code, role="professor", extra={"name": p.get("name", "")})
            print(Panel.fit(f"[cyan]JWT[/cyan]\n{token}"))
        except Exception as e:
            print(f"[yellow]JWT not configured[/yellow]: {e}")

@prof_app.command("change-password")
def prof_change_password(teacher_code: str, old: str, new: str):
    teachers = read_json(TEACHERS_F)
    for t in teachers:
        if t.get("teacher_code") == teacher_code:
            stored_key = "password" if "password" in t else "password_hash"
            if verify_password(old, t.get(stored_key, "")):
                t[stored_key] = hash_password(new)
                atomic_write(TEACHERS_F, teachers)
                print("[green]OK[/green] password changed")
                log("prof_change_password", teacher_code, "")
                return
    print("[red]Failed[/red] invalid credentials")

@prof_app.command("requests")
def professor_requests(code: Optional[str] = None, password: Optional[str] = None, token: Optional[str] = None):
    if token:
        p = _prof_auth(token=token)
    else:
        p = _prof_auth(code=code, password=password)
    thesis = read_json(THESIS_F)
    mine = [t for t in thesis if t.get("supervisor") == p["teacher_code"] and t["status"] in ["pending", "approved", "defense"]]
    tbl = Table(title=f"Requests for supervisor {p['teacher_code']}")
    for c in ["Student", "Course", "Status", "Requested", "Approved", "Title"]:
        tbl.add_column(c)
    for t in mine:
        tbl.add_row(
            t["student_code"], t["course_id"], t["status"],
            t.get("request_date", ""), str(t.get("approval_date", "")),
            t.get("title", "")
        )
    print(tbl)

@prof_app.command("approve")
def professor_approve(code: Optional[str] = None, password: Optional[str] = None, token: Optional[str] = None,
                      student_code: str = typer.Option(...), course_id: str = typer.Option(...)):
    p = _prof_auth(token=token) if token else _prof_auth(code=code, password=password)
    thesis = read_json(THESIS_F)
    rec = next((t for t in thesis if t["student_code"] == student_code and t["course_id"] == course_id and t["status"] == "pending"), None)
    if not rec:
        raise typer.BadParameter("Pending request not found")

    # ownership check
    _require_course_ownership(p["teacher_code"], rec)

    # supervise capacity
    supervise_cap = p.get("capacity_supervise", DEFAULT_SUPERVISE_CAP)
    active_supervisions = count_supervisions(thesis, p["teacher_code"])
    if active_supervisions >= supervise_cap:
        raise typer.BadParameter("Supervisor capacity reached")

    rec["status"] = "approved"
    rec["approval_date"] = _today_iso()
    rec["supervisor"] = p["teacher_code"]
    atomic_write(THESIS_F, thesis)

    emit("approved", {"student": student_code, "course": course_id, "supervisor": p["teacher_code"]})
    log("approve", p["teacher_code"], f"{student_code}/{course_id}")
    typer.secho("Approved", fg=typer.colors.GREEN)

@prof_app.command("reject")
def professor_reject(code: Optional[str] = None, password: Optional[str] = None, token: Optional[str] = None,
                     student_code: str = typer.Option(...), course_id: str = typer.Option(...), reason: str = typer.Option("", help="optional reason")):
    p = _prof_auth(token=token) if token else _prof_auth(code=code, password=password)
    thesis = read_json(THESIS_F)
    courses = read_json(COURSES_F)
    rec = next((t for t in thesis if t["student_code"] == student_code and t["course_id"] == course_id and t["status"] in ["pending", "approved"]), None)
    if not rec:
        raise typer.BadParameter("Request not found")

    # ownership check
    _require_course_ownership(p["teacher_code"], rec)

    rec["status"] = "rejected"
    rec["rejection_reason"] = reason
    atomic_write(THESIS_F, thesis)

    for c in courses:
        if c["course_id"] == course_id:
            c["capacity"] = int(c.get("capacity", 0)) + 1
    atomic_write(COURSES_F, courses)

    emit("rejected", {"student": student_code, "course": course_id, "reason": reason})
    log("reject", p["teacher_code"], f"{student_code}/{course_id}")
    typer.secho("Rejected", fg=typer.colors.GREEN)

@prof_app.command("schedule")
def professor_schedule(code: Optional[str] = None, password: Optional[str] = None, token: Optional[str] = None,
                       student_code: str = typer.Option(...), course_id: str = typer.Option(...),
                       date_str: str = typer.Option(...), internal: str = typer.Option(...), external: str = typer.Option(...)):
    p = _prof_auth(token=token) if token else _prof_auth(code=code, password=password)
    thesis = read_json(THESIS_F)
    rec = next((t for t in thesis if t["student_code"] == student_code and t["course_id"] == course_id and t["status"] == "defense"), None)
    if not rec:
        raise typer.BadParameter("Defense request not found")

    # ownership check
    _require_course_ownership(p["teacher_code"], rec)

    if not future_or_today(date_str):
        raise typer.BadParameter("Defense date must be today or future")

    # judges & capacity & distinctness
    teachers = read_json(TEACHERS_F)
    t_internal = next((x for x in teachers if x["teacher_code"] == internal), None)
    t_external = next((x for x in teachers if x["teacher_code"] == external), None)
    if internal == external or internal == p["teacher_code"] or external == p["teacher_code"]:
        raise typer.BadParameter("Supervisor, internal, external must be distinct")
    cap_i = (t_internal or {}).get("capacity_judge", DEFAULT_JUDGE_CAP)
    cap_e = (t_external or {}).get("capacity_judge", DEFAULT_JUDGE_CAP)
    active_i = count_judgings(thesis, internal)
    active_e = count_judgings(thesis, external)
    if active_i >= cap_i:
        raise typer.BadParameter("Internal judge capacity reached")
    if active_e >= cap_e:
        raise typer.BadParameter("External judge capacity reached")

    rec["defense_date"] = date_str
    rec["judges"] = {"internal": internal, "external": external}
    atomic_write(THESIS_F, thesis)

    emit("defense_scheduled", {"student": student_code, "course": course_id, "date": date_str, "internal": internal, "external": external})
    log("schedule", p["teacher_code"], f"{student_code}/{course_id} {date_str}")
    typer.secho("Defense scheduled", fg=typer.colors.GREEN)

@prof_app.command("score")
def professor_score(code: Optional[str] = None, password: Optional[str] = None, token: Optional[str] = None,
                    student_code: str = typer.Option(...), course_id: str = typer.Option(...),
                    role: str = typer.Option(...), score: float = typer.Option(...)):
    """
    Submit a score by role (internal/external/supervisor).
    - Only assigned teacher can submit for their role.
    - Scores allowed only on/after defense_date.
    - Supervisor score allowed after both judges.
    """
    p = _prof_auth(token=token) if token else _prof_auth(code=code, password=password)
    thesis = read_json(THESIS_F)
    rec = next((t for t in thesis if t["student_code"] == student_code and t["course_id"] == course_id and t["status"] == "defense"), None)
    if not rec:
        raise typer.BadParameter("Defense not found")

    # ownership check if supervisor is scoring as supervisor
    if role.strip().lower() == "supervisor":
        _require_course_ownership(p["teacher_code"], rec)

    d = rec.get("defense_date")
    if not d:
        raise typer.BadParameter("Defense date not scheduled")
    if date.fromisoformat(d) > date.today():
        raise typer.BadParameter("Cannot score before defense date")

    role = role.strip().lower()
    if role not in {"internal", "external", "supervisor"}:
        raise typer.BadParameter("Role must be internal/external/supervisor")

    if role == "internal" and p["teacher_code"] != rec.get("judges", {}).get("internal"):
        raise typer.BadParameter("Only assigned internal judge can submit this score")
    if role == "external" and p["teacher_code"] != rec.get("judges", {}).get("external"):
        raise typer.BadParameter("Only assigned external judge can submit this score")
    if role == "supervisor" and p["teacher_code"] != rec.get("supervisor"):
        raise typer.BadParameter("Only supervisor can submit supervisor score")

    scores = rec.get("scores") or {"internal": None, "external": None, "supervisor": None}
    if role == "supervisor" and (scores.get("internal") is None or scores.get("external") is None):
        raise typer.BadParameter("Supervisor can score only after both judges have scored")

    score = ensure_score_range(score)
    scores[role] = score
    rec["scores"] = scores
    atomic_write(THESIS_F, thesis)

    emit("score_submitted", {"student": student_code, "course": course_id, "role": role})
    log("score", p["teacher_code"], f"{student_code}/{course_id} {role}:{score}")
    typer.secho("Score saved", fg=typer.colors.GREEN)

@prof_app.command("finalize")
def professor_finalize(code: Optional[str] = None, password: Optional[str] = None, token: Optional[str] = None,
                       student_code: str = typer.Option(...), course_id: str = typer.Option(...),
                       semester: Optional[str] = typer.Option(None, help="اختیاری؛ اگر ندهید از خود درس خوانده می‌شود"),
                       result: str = typer.Option("defense", help="defense or re-defense")):
    """
    Finalize defense → archive to defended_thesis.json, free capacity, remove active record,
    generate keywords/summary & optional minutes PDF.
    - Judges stored as object
    - Scores included in archive
    - Year/Semester derived from course row (semester CLI arg overrides if given)
    - Both EN/FA grade letters saved
    """
    p = _prof_auth(token=token) if token else _prof_auth(code=code, password=password)
    thesis = read_json(THESIS_F)
    courses = read_json(COURSES_F)

    rec = next((t for t in thesis if t["student_code"] == student_code and t["course_id"] == course_id and t["status"] == "defense"), None)
    if not rec:
        raise typer.BadParameter("Defense not found")

    # ownership check
    _require_course_ownership(p["teacher_code"], rec)

    scores = rec.get("scores", {})
    if not _scores_complete(scores):
        raise typer.BadParameter("All three scores required")

    final_score = (scores["internal"] + scores["external"] + scores["supervisor"]) / 3.0
    letter_en = grade_letter(final_score)
    letter_fa = grade_letter_fa(final_score)

    # AI metadata (optional, best-effort)
    summary = ""
    kw: List[str] = []
    if extract_text and summarize and keywords_tfidf and rec.get("files") and rec["files"].get("pdf"):
        try:
            text = extract_text(rec["files"]["pdf"])
            summary = summarize(text)
            kw = keywords_tfidf(text)
        except Exception:
            summary, kw = "", []

    # Course-derived year/semester (semester arg overrides if supplied)
    course_row = next((c for c in courses if c.get("course_id") == course_id), {})
    year_val = int(course_row.get("year", date.today().year))
    sem_val = semester or course_row.get("semester", "اول")
    if semester is not None:
        _ensure_semester(semester)  # validate when provided

    # Append to archive (judges as object + include scores + FA letter)
    archive = read_json(DEFENDED_F)
    archive.append({
        "student_code": student_code,
        "course_id": course_id,
        "title": rec.get("title", ""),
        "year": year_val,
        "semester": sem_val,
        "supervisor": rec.get("supervisor", p["teacher_code"]),
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
        "finalized_at": datetime.utcnow().isoformat() + "Z"
    })
    atomic_write(DEFENDED_F, archive)

    # Free course capacity
    for c in courses:
        if c["course_id"] == course_id:
            c["capacity"] = int(c.get("capacity", 0)) + 1
    atomic_write(COURSES_F, courses)

    # Remove from active list
    thesis = [t for t in thesis if not (t["student_code"] == student_code and t["course_id"] == course_id)]
    atomic_write(THESIS_F, thesis)

    # Optional minutes PDF (robust to judges dict)
    if _render_minutes:
        try:
            out_pdf = _minutes_pdf_path(student_code, course_id)
            judges_list = [
                {"role": "internal", "code": rec.get("judges", {}).get("internal", "")},
                {"role": "external", "code": rec.get("judges", {}).get("external", "")},
            ]
            _render_minutes(
                str(out_pdf),
                title=rec.get("title", ""),
                student=student_code,
                supervisor=p["teacher_code"],
                judges=judges_list,
                year=year_val,
                semester=sem_val,
                final_score=final_score,
                grade_letter=letter_en,
                result=result,
            )
            emit("minutes_generated", {"student": student_code, "course": course_id, "file": str(out_pdf)})
        except Exception as e:
            log("minutes_error", p["teacher_code"], str(e))

    emit("finalized", {"student": student_code, "course": course_id, "score": final_score})
    log("finalize", p["teacher_code"], f"{student_code}/{course_id} {final_score:.2f}")
    typer.secho(f"Finalized and archived (score={final_score:.2f}, letter={letter_fa})", fg=typer.colors.GREEN)

@prof_app.command("export-csv")
def prof_export_csv(code: Optional[str] = None, password: Optional[str] = None, token: Optional[str] = None,
                    out: str = typer.Option("supervisions_export.csv")):
    """Export all defended theses supervised by this professor."""
    p = _prof_auth(token=token) if token else _prof_auth(code=code, password=password)
    rows = [r for r in read_json(DEFENDED_F) if r.get("supervisor") == p["teacher_code"]]
    keys = ["student_code","course_id","title","year","semester","score","grade_letter"]
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in keys})
    typer.secho(f"CSV written to {out}", fg=typer.colors.GREEN)


# ======================== Judge (داور) ========================
@judge_app.command("login")
def judge_login(code: str, password: str, jwt: bool = typer.Option(True, help="Return a JWT if configured")):
    t = _judge_auth(code=code, password=password)
    typer.secho("Login OK (judge)", fg=typer.colors.GREEN)
    if jwt:
        try:
            token = issue_jwt(subject=code, role="professor", extra={"name": t.get("name", ""), "judge": True})
            print(Panel.fit(f"[cyan]JWT[/cyan]\n{token}"))
        except Exception as e:
            print(f"[yellow]JWT not configured[/yellow]: {e}")

@judge_app.command("assignments")
def judge_assignments(code: Optional[str] = None, password: Optional[str] = None, token: Optional[str] = None):
    """List theses where this teacher is internal/external judge and needs scoring."""
    t = _judge_auth(token=token) if token else _judge_auth(code=code, password=password)
    thesis = read_json(THESIS_F)
    my = []
    for rec in thesis:
        if rec.get("status") != "defense":
            continue
        j = rec.get("judges", {})
        role = None
        if j.get("internal") == t["teacher_code"]:
            role = "internal"
        if j.get("external") == t["teacher_code"]:
            role = "external"
        if not role:
            continue
        sc = (rec.get("scores") or {}).get(role)
        if sc is None:
            my.append({"student_code": rec["student_code"], "course_id": rec["course_id"], "role": role})
    tbl = Table(title=f"Judge assignments for {t['teacher_code']}")
    for c in ["Student", "Course", "Role"]:
        tbl.add_column(c)
    for r in my:
        tbl.add_row(r["student_code"], r["course_id"], r["role"])
    print(tbl)

@judge_app.command("score")
def judge_score(code: Optional[str] = None, password: Optional[str] = None, token: Optional[str] = None,
                student_code: str = typer.Option(...), course_id: str = typer.Option(...),
                role: str = typer.Option(..., help="internal/external"), score: float = typer.Option(...)):
    """Submit internal/external score by judge (enforces role & date)."""
    t = _judge_auth(token=token) if token else _judge_auth(code=code, password=password)
    role = role.strip().lower()
    if role not in ("internal", "external"):
        raise typer.BadParameter("Judge role must be internal or external")

    thesis = read_json(THESIS_F)
    rec = next((r for r in thesis if r.get("student_code")==student_code and r.get("course_id")==course_id and r.get("status")=="defense"), None)
    if not rec:
        raise typer.BadParameter("Defense not found")

    d = rec.get("defense_date")
    if not d:
        raise typer.BadParameter("Defense date not scheduled")
    if date.fromisoformat(d) > date.today():
        raise typer.BadParameter("Cannot score before defense date")

    if role == "internal" and t["teacher_code"] != rec.get("judges", {}).get("internal"):
        raise typer.BadParameter("Only assigned internal judge can submit this score")
    if role == "external" and t["teacher_code"] != rec.get("judges", {}).get("external"):
        raise typer.BadParameter("Only assigned external judge can submit this score")

    score = ensure_score_range(score)
    scores = rec.get("scores") or {"internal": None, "external": None, "supervisor": None}
    scores[role] = score
    rec["scores"] = scores
    atomic_write(THESIS_F, thesis)
    emit("score_submitted", {"student": student_code, "course": course_id, "by": t["teacher_code"], "role": role, "score": score})
    log("score", t["teacher_code"], f"{student_code}/{course_id} {role}:{score}")
    typer.secho("Score saved", fg=typer.colors.GREEN)


# ======================== Entry ========================
if __name__ == "__main__":
    app()
