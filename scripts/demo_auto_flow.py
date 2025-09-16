#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Demo Auto Flow (headless) for ThesisHub

This script programmatically simulates a full thesis lifecycle WITHOUT the web UI:
- seed a fresh student/teachers/course
- create a pending thesis
- approve it (with backdated dates so defense can be requested)
- upload/copy files safely (valid PDF/JPEG signatures)
- set defense + judges
- submit judge scores
- finalize and archive (and try to generate the minutes PDF if reports.minutes_pdf is available)

Run from the project root (so that ./core and ./reports are importable).
Usage:
    python scripts/demo_auto_flow.py
Environment:
    OVERWRITE=1   -> drop/replace the same IDs if they exist (default: 1)
"""

from __future__ import annotations
import os, sys, io, json, time
from pathlib import Path
from datetime import datetime, timedelta, date, timezone

# --- make project importable if running from scripts/ ---
HERE = Path(__file__).resolve()
PROJ = HERE.parent.parent
if str(PROJ) not in sys.path:
    sys.path.insert(0, str(PROJ))

# --- project modules ---
from core import repo
from core.files import validate_and_copy, FILES_DIR
from core.rules import can_request_defense, ensure_score_range, grade_letter, grade_letter_fa

# optional minutes generator
try:
    from reports.minutes_pdf import render_minutes as render_minutes_pdf
except Exception:
    render_minutes_pdf = None

# --------------------------------------------------------
# helpers: write minimal valid PDF/JPEG
# --------------------------------------------------------
def write_min_pdf(path: Path, title: str = "Sample Thesis PDF"):
    # Minimal valid PDF with header and EOF marker
    content = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)

def write_min_jpg(path: Path):
    # Minimal JPEG: SOI (FFD8) + EOI (FFD9)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bytes([0xFF, 0xD8, 0xFF, 0xD9]))

def now_iso() -> str:
    # UTC, ISO-8601 seconds precision, trailing Z
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

# --------------------------------------------------------
# IDs for this demo run (kept distinct to avoid collisions)
# --------------------------------------------------------
STUDENT = {"name":"Demo Student","student_code":"S9001","password":"DemoPass!234","email":"demo.student@example.com"}
TEACHERS = [
    {"name":"Dr. Demo Supervisor","teacher_code":"T9101","password":"DemoPass!234","email":"sup@example.com","capacity_supervise":5,"capacity_judge":10},
    {"name":"Dr. Demo Internal","teacher_code":"T9102","password":"DemoPass!234","email":"int@example.com","capacity_supervise":5,"capacity_judge":10},
    {"name":"Dr. Demo External","teacher_code":"T9103","password":"DemoPass!234","email":"ext@example.com","capacity_supervise":5,"capacity_judge":10},
]
COURSE = {"course_title":"Thesis (Demo)","course_id":"C9001","teacher_code":"T9101","year":1404,"semester":"اول","capacity":1,"resources":["demo"],"sessions":16,"units":6,"type":"thesis","status":"active","created_at":now_iso()}

# --------------------------------------------------------
def main():
    overwrite = os.getenv("OVERWRITE","1") not in {"0","false","False"}

    print("== Demo Auto Flow starting ==")
    # 1) seed accounts (idempotent registrars in repo.py)
    #    If they exist and overwrite is off, keep them; else raise handled by our try/except.
    try:
        stu = repo.register_student(STUDENT["name"], STUDENT["student_code"], STUDENT["password"], STUDENT["email"])
        print("[+] student registered:", stu["student_code"])
    except Exception as e:
        if overwrite:
            # ignore if duplicate
            print("[=] student exists -> ok")
        else:
            raise

    for t in TEACHERS:
        try:
            rec = repo.register_teacher(t["name"], t["teacher_code"], t["password"], t["email"], t["capacity_supervise"], t["capacity_judge"])
            print("[+] teacher registered:", rec["teacher_code"])
        except Exception:
            if overwrite:
                print("[=] teacher exists -> ok")
            else:
                raise

    # Ensure course exists
    courses = repo.read_json(repo.COURSES_F)
    if not any(c.get("course_id")==COURSE["course_id"] for c in courses):
        courses.append(COURSE)
        repo.atomic_write(repo.COURSES_F, courses)
        print("[+] course added:", COURSE["course_id"])
    else:
        print("[=] course exists -> ok")

    # 2) create pending thesis
    thesis = {
        "student_code": STUDENT["student_code"],
        "course_id": COURSE["course_id"],
        "request_date": (date.today() - timedelta(days=110)).isoformat(),
        "approval_date": None,
        "status": "pending",
        "supervisor": "T9101",
        "judges": {"internal": None, "external": None},
        "title": "Demo: A Practical Study on ThesisHub",
        "abstract": "",
        "keywords": [],
        "defense_request_date": None,
        "defense_date": None,
        "scores": {"supervisor": None, "internal": None, "external": None},
        "files": {"pdf": None, "cover": None, "last": None},
        "ocr_validation": None
    }
    repo.upsert_thesis(thesis)
    print("[+] thesis created: pending")

    # 3) approve (backdate so defense can be requested)
    def _approve(theses):
        for t in theses:
            if t.get("student_code")==STUDENT["student_code"] and t.get("course_id")==COURSE["course_id"]:
                t["status"]="approved"
                t["approval_date"]=(date.today() - timedelta(days=100)).isoformat()
        return theses
    repo.update_atomic(repo.THESIS_F, _approve)
    print("[+] thesis approved (approval_date backdated 100 days)")

    # 4) upload/copy files safely
    tmp = Path("tmp_demo_files")
    tmp.mkdir(exist_ok=True)
    pdf_p = tmp/"demo.pdf"
    cov_p = tmp/"cover.jpg"
    last_p = tmp/"last.jpg"
    write_min_pdf(pdf_p)
    write_min_jpg(cov_p)
    write_min_jpg(last_p)

    out = validate_and_copy(str(pdf_p), str(cov_p), str(last_p), out_prefix=f"{STUDENT['student_code']}_{COURSE['course_id']}")
    print("[+] files copied into sandbox:", out)

    # 5) request defense (check rule), switch to defense, set judges + date
    theses = repo.read_json(repo.THESIS_F)
    rec = None
    for t in theses:
        if t.get("student_code")==STUDENT["student_code"] and t.get("course_id")==COURSE["course_id"]:
            rec = t; break
    assert rec, "thesis not found after approval"
    if not can_request_defense(rec.get("request_date"), rec.get("approval_date")):
        raise SystemExit("Rule failed: cannot request defense yet (backdating bug?)")

    rec.update({
        "status":"defense",
        "defense_request_date": date.today().isoformat(),
        "judges":{"internal":"T9102","external":"T9103"},
        "defense_date": date.today().isoformat(),
        "files": out
    })
    repo.atomic_write(repo.THESIS_F, theses)
    print("[+] thesis moved to defense; judges assigned")

    # 6) submit scores
    rec["scores"] = {"internal": 18.0, "external": 17.5, "supervisor": 19.0}
    repo.atomic_write(repo.THESIS_F, theses)
    print("[+] scores submitted:", rec["scores"])

    # 7) finalize & archive (via repo.archive_defense)
    avg = round((rec["scores"]["internal"] + rec["scores"]["external"] + rec["scores"]["supervisor"]) / 3.0, 2)
    letter = grade_letter(avg)
    letter_fa = grade_letter_fa(avg)
    archived = repo.archive_defense(
        student_code=STUDENT["student_code"],
        course_id=COURSE["course_id"],
        title=rec.get("title",""),
        year=int(COURSE["year"]),
        semester=COURSE["semester"],
        supervisor_code="T9101",
        judges=rec.get("judges"),
        scores=rec["scores"],
        attendees=[STUDENT["student_code"], "T9101", "T9102", "T9103"],
        files={
            "pdf": out["pdf"],
            "cover": out["cover"],
            "last": out["last"]
        }
    )
    print("[+] archived:", json.dumps(archived, ensure_ascii=False, indent=2))

    # Optional: minutes PDF
    if render_minutes_pdf:
        reports_dir = FILES_DIR / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        out_pdf = reports_dir / f"minutes_{STUDENT['student_code']}_{COURSE['course_id']}.pdf"
        try:
            render_minutes_pdf(
                str(out_pdf),
                title=rec.get("title",""),
                student=STUDENT["name"],
                supervisor=TEACHERS[0]["name"],
                judges={"internal": TEACHERS[1]["name"], "external": TEACHERS[2]["name"]},
                year=int(COURSE["year"]),
                semester=COURSE["semester"],
                final_score=avg,
                grade_letter=letter,
                result="defense",
                student_code=STUDENT["student_code"],
                course_id=COURSE["course_id"],
                defense_date=rec.get("defense_date"),
                attendees=[STUDENT["name"], TEACHERS[0]["name"], TEACHERS[1]["name"], TEACHERS[2]["name"]],
                scores=rec["scores"],
                metadata={"Author": STUDENT["name"], "Title": "صورتجلسه دفاع - Demo"}
            )
            print(f"[+] minutes PDF generated at: {out_pdf}")
        except Exception as e:
            print("[!] minutes rendering failed:", e)

    print("== Demo Auto Flow complete ==")

if __name__ == "__main__":
    main()
