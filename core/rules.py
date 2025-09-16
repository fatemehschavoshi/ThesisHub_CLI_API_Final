from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, date, timedelta
from typing import Dict, List, Optional, Tuple, Any

# =========================
# Constants / Defaults
# =========================
DEFAULT_SUPERVISE_CAP = 5
DEFAULT_JUDGE_CAP = 10

# Minimum waiting period (in days) before defense can be requested/scheduled
DEFENSE_WAIT_DAYS = 90

# Active statuses considered for supervision/judging load
ACTIVE_SUPERVISION_STATUSES = {"pending", "approved", "defense"}
ACTIVE_JUDGING_STATUSES = {"defense"}

VALID_SEMESTERS = {"اول", "دوم"}

# =========================
# Score & Grade utilities
# =========================
def ensure_score_range(score: float) -> float:
    """
    Validate score ∈ [0, 20]. Raises ValueError if outside the range.
    (No clamping.)
    """
    s = float(score)
    if s < 0 or s > 20:
        raise ValueError("Score must be between 0 and 20")
    return s


def grade_letter(score: float) -> str:
    """
    Letter mapping per spec:
      A: 17..20, B: 13..17, C: 10..13, D: <10
    Boundaries: [17,20], [13,17), [10,13), [0,10)
    """
    s = float(score)
    if 17.0 <= s <= 20.0:
        return "A"
    if 13.0 <= s < 17.0:
        return "B"
    if 10.0 <= s < 13.0:
        return "C"
    return "D"


def grade_letter_fa(score: float) -> str:
    """Persian translation of the grade letter."""
    return {"A": "الف", "B": "ب", "C": "ج", "D": "د"}[grade_letter(score)]


def final_score_letter(scores: Dict[str, float]) -> Tuple[float, str]:
    """
    Expect keys: internal, external, supervisor
    Returns (avg, letter)
    """
    s_int = ensure_score_range(scores.get("internal", 0))
    s_ext = ensure_score_range(scores.get("external", 0))
    s_sup = ensure_score_range(scores.get("supervisor", 0))
    avg = (s_int + s_ext + s_sup) / 3.0
    return avg, grade_letter(avg)  # For Persian UI use grade_letter_fa(avg)

# =========================
# Semester / Year helpers
# =========================
def normalize_semester(sem: str) -> str:
    """Normalize and validate semester to one of {'اول','دوم'}."""
    if sem is None:
        raise ValueError("semester is required")
    s = str(sem).strip()
    if s in VALID_SEMESTERS:
        return s
    m = s.lower()
    if m in {"1", "first"}:
        return "اول"
    if m in {"2", "second"}:
        return "دوم"
    raise ValueError("semester must be 'اول' or 'دوم'")


def validate_year(y: int) -> int:
    """Ensure year is a plausible academic year in SH (1300..1600)."""
    yi = int(y)
    if yi < 1300 or yi > 1600:
        raise ValueError("year out of plausible academic range")
    return yi

# =========================
# Date / Time utilities
# =========================
def parse_iso_date(s: str) -> date:
    """Strict ISO parser (YYYY-MM-DD or full ISO) → date."""
    try:
        return datetime.fromisoformat(s).date()
    except Exception:
        raise ValueError(f"Invalid ISO date: {s!r}")


def is_future_or_today(d: date) -> bool:
    return d >= date.today()


def future_or_today(date_str: str) -> bool:
    """Compatibility wrapper used by callers (returns bool)."""
    try:
        return is_future_or_today(parse_iso_date(date_str))
    except Exception:
        return False


def months_between(d1: date, d2: date) -> int:
    """Approximate calendar months difference (not used in core flows)."""
    if d2 < d1:
        d1, d2 = d2, d1
    return (d2.year - d1.year) * 12 + (d2.month - d1.month) - (1 if d2.day < d1.day else 0)


def at_least_days_after(base: date, target: date, days: int) -> bool:
    return target >= (base + timedelta(days=int(days)))

# =========================
# Defense rules
# =========================
def can_request_defense(
    request_or_approval_date_iso: str,
    approval_date_iso: Optional[str] = None,
    now: Optional[datetime] = None
) -> bool:
    """
    Flexible, backward-compatible checker.

    - If ONLY 'request_or_approval_date_iso' is provided, interpret it as the approval_date,
      and require: today ≥ approval_date + DEFENSE_WAIT_DAYS.

    - If BOTH request_date (as request_or_approval_date_iso) AND approval_date_iso are provided,
      require BOTH to be valid and: today ≥ request_date + DEFENSE_WAIT_DAYS.
    """
    today = (now or datetime.now()).date()

    if approval_date_iso is None:
        # Single-arg mode: treat input as approval_date
        try:
            approval_d = parse_iso_date(request_or_approval_date_iso)
        except Exception:
            return False
        return at_least_days_after(approval_d, today, DEFENSE_WAIT_DAYS)

    # Two-arg mode: request_date + approval_date must both be valid; wait counted from request_date
    try:
        request_d = parse_iso_date(request_or_approval_date_iso)
        _ = parse_iso_date(approval_date_iso)
    except Exception:
        return False

    return at_least_days_after(request_d, today, DEFENSE_WAIT_DAYS)


def validate_defense_schedule(
    approval_date_iso: str,
    defense_date_iso: str,
    request_date_iso: Optional[str] = None
) -> None:
    """
    Raise ValueError if scheduling rules are violated:
    - defense_date must be today or future
    - defense_date must not be before approval_date
    - if request_date provided, ensure at least DEFENSE_WAIT_DAYS since request_date
    """
    approval_d = parse_iso_date(approval_date_iso)
    defense_d = parse_iso_date(defense_date_iso)

    if not is_future_or_today(defense_d):
        raise ValueError("Defense date must be today or future")
    if defense_d < approval_d:
        raise ValueError("Defense date cannot be before approval date")
    if request_date_iso:
        req_d = parse_iso_date(request_date_iso)
        if not at_least_days_after(req_d, defense_d, DEFENSE_WAIT_DAYS):
            raise ValueError("Less than required minimum wait from request date")

# =========================
# Capacity / Counting
# =========================
def count_supervisions(thesis_list: List[dict], teacher_code: str) -> int:
    """Count active supervisions for a teacher across active statuses."""
    return sum(
        1 for t in thesis_list
        if t.get("supervisor") == teacher_code and t.get("status") in ACTIVE_SUPERVISION_STATUSES
    )


def count_judgings(thesis_list: List[dict], teacher_code: str) -> int:
    """
    Count active judgings (defense stage only). Supports both dict and list
    representations of judges:
      - dict: {"internal": "t002", "external": "t003"}
      - list: ["t002", "t003"] or [{"code": "t002", "role": "internal"}, ...]
    """
    def has_judge(t: dict) -> bool:
        j = t.get("judges")
        if isinstance(j, dict):
            return teacher_code in j.values()
        if isinstance(j, list):
            for x in j:
                if x == teacher_code:
                    return True
                if isinstance(x, dict) and x.get("code") == teacher_code:
                    return True
        return False

    return sum(
        1 for t in thesis_list
        if t.get("status") in ACTIVE_JUDGING_STATUSES and has_judge(t)
    )

# =========================
# Business rules (Phase 2)
# =========================
def _course_by_id(courses: List[dict], course_id: str) -> Optional[dict]:
    for c in courses:
        if c.get("course_id") == course_id:
            return c
    return None


def _teacher_by_code(teachers: List[dict], code: str) -> Optional[dict]:
    for t in teachers:
        if t.get("teacher_code") == code:
            return t
    return None


def _course_capacity_left_numeric(course: dict) -> int:
    """Numeric capacity model (aligns with API): just use 'capacity' as seats remaining."""
    try:
        return int(course.get("capacity", 0))
    except Exception:
        return 0


def check_capacity(course: dict, teacher: dict, theses: List[dict]) -> Tuple[bool, str]:
    """
    Validate both course and supervisor capacities.

    - Course capacity (numeric): course['capacity'] > 0
    - Supervisor capacity: remaining = teacher.capacity_supervise - active supervisions
    """
    # Course capacity
    if _course_capacity_left_numeric(course) <= 0:
        return False, "ظرفیت درس تکمیل است."

    # Supervisor capacity (dynamic load)
    tcode = teacher.get("teacher_code")
    try:
        sup_cap = int(teacher.get("capacity_supervise", DEFAULT_SUPERVISE_CAP))
    except Exception:
        sup_cap = DEFAULT_SUPERVISE_CAP
    active_sup = count_supervisions(theses, tcode)
    if active_sup >= sup_cap:
        return False, "ظرفیت راهنمایی استاد تکمیل است."

    return True, ""


def can_request_thesis(
    student_code: str,
    course_id: str,
    state: Dict[str, List[dict]]
) -> Tuple[bool, str]:
    """
    Rules for the initial thesis request:
    - Uniqueness on (student_code, course_id) among ACTIVE records
    - Course must exist and have remaining numeric capacity (>0)
    - Course's teacher (supervisor) must have remaining supervision capacity
    `state` expects keys: {"courses", "teachers", "theses"}
    """
    theses = state.get("theses", [])
    # Prevent duplicates on active statuses
    for t in theses:
        if t.get("student_code") == student_code and t.get("course_id") == course_id:
            if t.get("status") in ACTIVE_SUPERVISION_STATUSES:
                return False, "درخواست قبلی برای این درس در جریان است."

    # Course
    course = _course_by_id(state.get("courses", []), course_id)
    if not course:
        return False, "شناسه‌ی درس معتبر نیست."

    # Teacher
    teacher = _teacher_by_code(state.get("teachers", []), course.get("teacher_code", ""))
    if not teacher:
        return False, "استاد راهنما یافت نشد."

    # Capacities
    ok, msg = check_capacity(course, teacher, theses)
    if not ok:
        return False, msg

    return True, ""


def can_request_defense_gate(
    request_date_iso: Optional[str],
    approval_date_iso: Optional[str],
    today: Optional[date] = None
) -> Tuple[bool, str]:
    """
    Human-readable gate for defense request:
    - approval_date is required
    - if request_date is provided: today ≥ request_date + DEFENSE_WAIT_DAYS
      else: today ≥ approval_date + DEFENSE_WAIT_DAYS
    Returns (ok, message).
    """
    if not approval_date_iso:
        return False, "درخواست هنوز توسط استاد تایید نشده است."

    d = today or date.today()
    try:
        if request_date_iso:
            req = parse_iso_date(request_date_iso)
            if not at_least_days_after(req, d, DEFENSE_WAIT_DAYS):
                return False, "کمتر از سه ماه از تاریخ ثبت درخواست گذشته است."
        else:
            app = parse_iso_date(approval_date_iso)
            if not at_least_days_after(app, d, DEFENSE_WAIT_DAYS):
                return False, "کمتر از سه ماه از تاریخ تایید گذشته است."
    except Exception:
        return False, "تاریخ‌های وارد شده معتبر نیست."

    return True, ""
