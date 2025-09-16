from __future__ import annotations
"""
Repository layer for ThesisHub (drop-in, hardened).

- UTC+Z timestamps everywhere
- File lock with stale-lock cleanup
- Atomic write with directory fsync
- Robust read_json: backup fallback + audit warning
- Safe merge upsert for thesis (preserve existing fields)
- Unified password field: password_hash (repo-level)
- Centralized audit/notifications (with graceful fallback)
- Judges schema tolerance (accepts dict or legacy list, stores dict)
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, List, Dict, Tuple, Callable
from datetime import datetime, timezone
import json, os, time, uuid, shutil

# =========================
# Paths & constants
# =========================
ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

STUDENTS_F   = DATA_DIR / "students.json"
TEACHERS_F   = DATA_DIR / "teachers.json"
COURSES_F    = DATA_DIR / "courses.json"
THESIS_F     = DATA_DIR / "thesis.json"
DEFENDED_F   = DATA_DIR / "defended_thesis.json"
NOTIF_F      = DATA_DIR / "notifications.json"
AUDIT_F      = DATA_DIR / "audit.log"

BACKUP_DIR   = DATA_DIR / "_bak"
BACKUP_DIR.mkdir(parents=True, exist_ok=True)

# JSON defaults
_DEFAULTS: Dict[Path, Any] = {
    STUDENTS_F: [],
    TEACHERS_F: [],
    COURSES_F: [],
    THESIS_F: [],
    DEFENDED_F: [],
    NOTIF_F: [],
}

JSON_INDENT = 2
JSON_ENSURE_ASCII = False

# Locking
LOCK_TIMEOUT_SEC = 10.0           # wait time to acquire lock
LOCK_SLEEP_SEC   = 0.05
STALE_LOCK_SEC   = 60.0           # consider lock stale if older than this

# Backup retention
BACKUP_RETAIN_PER_FILE = 10       # set 0 to disable pruning


# =========================
# Time helpers (UTC+Z)
# =========================
def _now_iso() -> str:
    """Return UTC ISO-8601 with milliseconds and trailing 'Z'."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


# =========================
# Central audit/notifications (graceful fallbacks)
# =========================
try:
    from core.audit import log as _audit_log
    from core.audit import log_warn as _audit_warn
except Exception:
    def _audit_log(action: str, who: str = "repo", detail: str = "", **kw):
        try:
            AUDIT_F.parent.mkdir(parents=True, exist_ok=True)
            with AUDIT_F.open("a", encoding="utf-8") as f:
                f.write(f"{_now_iso()} | INFO     | repo         | {action:<24} | {detail}\n")
        except Exception:
            pass
    def _audit_warn(who: str, action: str, detail: str = "", **kw):
        try:
            AUDIT_F.parent.mkdir(parents=True, exist_ok=True)
            with AUDIT_F.open("a", encoding="utf-8") as f:
                f.write(f"{_now_iso()} | WARN     | {who:<12} | {action:<24} | {detail}\n")
        except Exception:
            pass

try:
    from core.notifications import emit as _emit
except Exception:
    def _emit(event: str, payload: Dict[str, Any], **kw):
        # Minimal compatible fallback: append to NOTIF_F (atomic via write_json)
        notif = {"id": str(uuid.uuid4()), "ts": _now_iso(), "event": event, "level": "info", "payload": payload}
        try:
            data = read_json(NOTIF_F)
            if not isinstance(data, list):
                data = []
            data.append(notif)
            write_json(NOTIF_F, data)
        except Exception:
            pass
        return notif


# =========================
# Lock helpers (sidecar .lock)
# =========================
@dataclass
class _Lock:
    path: Path
    locked: bool = False

def _lock_path(path: Path) -> Path:
    return path.with_suffix(path.suffix + ".lock")

def _fsync_dir(path: Path) -> None:
    """Fsync the directory containing 'path' to persist the rename in crash scenarios."""
    try:
        dfd = os.open(os.fspath(path.parent), os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except Exception:
        # best-effort
        pass

def _acquire_lock(path: Path, timeout: float = LOCK_TIMEOUT_SEC) -> _Lock:
    """
    Create-only sidecar lock. Cleans up stale locks (older than STALE_LOCK_SEC).
    Non-reentrant by design.
    """
    lockp = _lock_path(path)
    start = time.time()
    while True:
        try:
            # Try to create the lock atomically
            fd = os.open(os.fspath(lockp), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            try:
                # Write a tiny marker (timestamp) to help with stale detection
                os.write(fd, str(time.time()).encode("utf-8"))
            finally:
                os.close(fd)
            return _Lock(lockp, True)
        except FileExistsError:
            # Stale lock check
            try:
                st = lockp.stat()
                age = time.time() - st.st_mtime
                if age > STALE_LOCK_SEC:
                    # Consider stale: unlink and retry immediately
                    lockp.unlink(missing_ok=True)
                    continue
            except Exception:
                # If stat fails, attempt to remove and proceed
                try:
                    lockp.unlink(missing_ok=True)
                    continue
                except Exception:
                    pass
            if time.time() - start > timeout:
                raise TimeoutError(f"Timeout acquiring lock for {path}")
            time.sleep(LOCK_SLEEP_SEC)

def _release_lock(lock: _Lock):
    if lock.locked and lock.path.exists():
        try:
            lock.path.unlink(missing_ok=True)
        except Exception:
            pass


# =========================
# Atomic IO & backups
# =========================
def _rotate_backup(path: Path):
    """Copy current JSON to backup folder with timestamp suffix and prune old ones."""
    if not path.exists():
        return
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    dst = BACKUP_DIR / f"{path.stem}_{ts}.json"
    try:
        shutil.copy2(path, dst)
    except Exception:
        pass

    if BACKUP_RETAIN_PER_FILE > 0:
        snaps = sorted(BACKUP_DIR.glob(f"{path.stem}_*.json"), reverse=True)
        for old in snaps[BACKUP_RETAIN_PER_FILE:]:
            try:
                old.unlink(missing_ok=True)
            except Exception:
                pass

def _atomic_write_text(path: Path, text: str):
    """Write text atomically and fsync both file and directory."""
    tmp = path.with_suffix(path.suffix + f".tmp.{uuid.uuid4().hex}")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    _fsync_dir(path.parent)


# =========================
# Bootstrap files (atomic)
# =========================
def _ensure_file(path: Path, default: Any):
    if not path.exists():
        _atomic_write_text(path, json.dumps(default, ensure_ascii=JSON_ENSURE_ASCII, indent=JSON_INDENT))

# Defer creation until after atomic helpers are defined
for p, default in _DEFAULTS.items():
    _ensure_file(p, default)


# =========================
# JSON read/write (public)
# =========================
def read_json(path: Path) -> Any:
    """
    Read JSON safely. On corruption:
      - try the latest backup snapshots
      - if all fail, return default []/{} (based on _DEFAULTS)
    Emits an audit WARN when primary read fails.
    """
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as ex:
        _audit_warn("repo", "JSON_READ_FAILED", f"{path.name}: {ex}")
        candidates = sorted(BACKUP_DIR.glob(f"{path.stem}_*.json"), reverse=True)
        for cand in candidates:
            try:
                return json.loads(cand.read_text(encoding="utf-8"))
            except Exception:
                continue
        default = _DEFAULTS.get(path, [])
        return default if isinstance(default, (dict, list)) else []

def write_json(path: Path, data: Any):
    """Atomic + locked write with backup rotation."""
    lock = _acquire_lock(path)
    try:
        _rotate_backup(path)
        text = json.dumps(data, ensure_ascii=JSON_ENSURE_ASCII, indent=JSON_INDENT)
        _atomic_write_text(path, text)
    finally:
        _release_lock(lock)

# ---- Backward-compat alias (keeps older imports working)
def atomic_write(path: Path, data: Any):
    """Alias for write_json; keeps modules importing atomic_write working."""
    return write_json(path, data)

def update_atomic(path: Path, fn: Callable[[Any], Any] | None = None) -> Any:
    """
    Transactional update:
      1) acquire lock
      2) load
      3) apply fn(data) (mutate or return new)
      4) write atomically
      5) return fn's return (if any)
    """
    lock = _acquire_lock(path)
    try:
        data = read_json(path)
        ret = None
        if fn is not None:
            out = fn(data)
            # Support either in-place mutate or returning a new structure
            if out is not None and out is not data:
                data = out
            ret = out
        _rotate_backup(path)
        text = json.dumps(data, ensure_ascii=JSON_ENSURE_ASCII, indent=JSON_INDENT)
        _atomic_write_text(path, text)
        return ret
    finally:
        _release_lock(lock)

def append_json(path: Path, obj: Any):
    """Safe append for list-JSON using update_atomic (no nested locks)."""
    def _fn(data):
        if not isinstance(data, list):
            data = []
        data.append(obj)
        return data
    return update_atomic(path, _fn)


# =========================
# Schema validation (light)
# =========================
def _is_email(s: str) -> bool:
    return bool(s) and ("@" in s) and (" " not in s)

def validate_student(rec: Dict[str, Any]) -> Tuple[bool, str]:
    # Unified: store password as password_hash
    ok = isinstance(rec.get("name", ""), str) and isinstance(rec.get("student_code", ""), str)
    ok &= isinstance(rec.get("password_hash", ""), str)
    email = rec.get("email", "")
    if email and not _is_email(email):
        return False, "Invalid student email"
    return bool(ok), "OK"

def validate_teacher(rec: Dict[str, Any]) -> Tuple[bool, str]:
    ok = isinstance(rec.get("name", ""), str) and isinstance(rec.get("teacher_code", ""), str)
    ok &= isinstance(rec.get("password_hash", ""), str)
    try:
        int(rec.get("capacity_supervise", 5))
        int(rec.get("capacity_judge", 10))
    except Exception:
        return False, "capacity_supervise/judge must be numeric"
    email = rec.get("email", "")
    if email and not _is_email(email):
        return False, "Invalid teacher email"
    return bool(ok), "OK"


# =========================
# Registration & updates
# =========================
from core.security import hash_password
from core.rules import grade_letter, grade_letter_fa
try:
    from core.rules import ensure_score_range
except Exception:
    # Fallback clamp if project hasn't defined it yet
    def ensure_score_range(x: float) -> float:
        try:
            v = float(x)
        except Exception:
            v = 0.0
        return 0.0 if v < 0 else (20.0 if v > 20.0 else v)

def register_student(name: str, student_code: str, password: str, email: Optional[str] = None) -> dict:
    """Atomic registration for student (unique student_code)."""
    def _fn(students):
        if not isinstance(students, list):
            students = []
        if any(s.get("student_code") == student_code for s in students):
            raise ValueError("student_code already exists")
        rec = {
            "name": name,
            "student_code": student_code,
            "password_hash": hash_password(password),
            "email": email or "",
            "created_at": _now_iso(),
            "active": True,
        }
        ok, msg = validate_student(rec)
        if not ok:
            raise ValueError(f"Invalid student record: {msg}")
        students.append(rec)
        return students

    update_atomic(STUDENTS_F, _fn)
    _audit_log("REGISTER_STUDENT", "repo", student_code)
    # return the new record (fresh read)
    for s in read_json(STUDENTS_F):
        if s.get("student_code") == student_code:
            return s
    return {}

def register_teacher(name: str, teacher_code: str, password: str, email: Optional[str] = None,
                     capacity_supervise: int = 5, capacity_judge: int = 10) -> dict:
    """Atomic registration for teacher (unique teacher_code)."""
    def _fn(teachers):
        if not isinstance(teachers, list):
            teachers = []
        if any(t.get("teacher_code") == teacher_code for t in teachers):
            raise ValueError("teacher_code already exists")
        rec = {
            "name": name,
            "teacher_code": teacher_code,
            "password_hash": hash_password(password),
            "email": email or "",
            "capacity_supervise": int(capacity_supervise),
            "capacity_judge": int(capacity_judge),
            "created_at": _now_iso(),
            "active": True,
        }
        ok, msg = validate_teacher(rec)
        if not ok:
            raise ValueError(f"Invalid teacher record: {msg}")
        teachers.append(rec)
        return teachers

    update_atomic(TEACHERS_F, _fn)
    _audit_log("REGISTER_TEACHER", "repo", teacher_code)
    for t in read_json(TEACHERS_F):
        if t.get("teacher_code") == teacher_code:
            return t
    return {}


# =========================
# Thesis helpers
# =========================
def find_thesis(student_code: str, course_id: str) -> Optional[dict]:
    theses = read_json(THESIS_F)
    for th in theses:
        if th.get("student_code") == student_code and th.get("course_id") == course_id:
            return th
    return None

def _deep_merge(existing: dict, incoming: dict) -> dict:
    """
    Shallow+dict merge:
    - merge dict fields recursively
    - replace non-dicts directly
    - never delete existing keys unless incoming provides a value
    """
    out = dict(existing or {})
    for k, v in (incoming or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)  # type: ignore
        else:
            out[k] = v
    return out

def upsert_thesis(thesis: dict):
    """
    Insert or MERGE a thesis record by (student_code, course_id) atomically.
    Preserves existing fields unless explicitly overwritten by 'thesis'.
    """
    sc = thesis.get("student_code")
    cid = thesis.get("course_id")
    if not sc or not cid:
        raise ValueError("thesis must include student_code and course_id")

    def _fn(theses):
        if not isinstance(theses, list):
            theses = []
        replaced = False
        for i, th in enumerate(theses):
            if th.get("student_code") == sc and th.get("course_id") == cid:
                theses[i] = _deep_merge(th, thesis)
                replaced = True
                break
        if not replaced:
            theses.append(thesis)
        return theses

    update_atomic(THESIS_F, _fn)
    _audit_log("UPSERT_THESIS", "repo", f"{sc}/{cid}")

def add_thesis_metadata(student_code: str, course_id: str, abstract: str, keywords: List[str]) -> dict:
    """
    Attach/update metadata on a thesis request; creates pending if missing.
    """
    def _fn(theses):
        if not isinstance(theses, list):
            theses = []
        idx = None
        for i, th in enumerate(theses):
            if th.get("student_code") == student_code and th.get("course_id") == course_id:
                idx = i
                break
        if idx is None:
            th = {
                "student_code": student_code,
                "course_id": course_id,
                "request_date": _now_iso(),
                "approval_date": None,
                "status": "pending",
            }
            theses.append(th)
            idx = len(theses) - 1
        theses[idx]["abstract"] = abstract
        theses[idx]["keywords"] = list(keywords)
        return theses

    update_atomic(THESIS_F, _fn)
    _audit_log("ADD_THESIS_METADATA", "repo", f"{student_code}/{course_id}")
    return find_thesis(student_code, course_id)


# =========================
# Defense archive helpers
# =========================
def _normalize_judges(judges: Any) -> Dict[str, str]:
    """
    Accept legacy forms and normalize to {"internal": code, "external": code}.
    - If dict already: return sanitized subset.
    - If list of dicts: try to map by role.
    - If list of strings (codes): keep order [internal, external] if length >= 2.
    """
    if isinstance(judges, dict):
        return {
            "internal": str(judges.get("internal", "")),
            "external": str(judges.get("external", "")),
        }
    if isinstance(judges, list):
        # list of dicts with 'role'/'code'
        if judges and isinstance(judges[0], dict):
            role_map = {}
            for j in judges:
                r = (j.get("role") or "").lower()
                c = str(j.get("code") or "")
                if r in ("internal", "external"):
                    role_map[r] = c
            return {"internal": role_map.get("internal", ""), "external": role_map.get("external", "")}
        # list of codes
        if len(judges) >= 2 and all(isinstance(x, (str, int)) for x in judges[:2]):
            return {"internal": str(judges[0]), "external": str(judges[1])}
    # fallback empty
    return {"internal": "", "external": ""}

def archive_defense(
    student_code: str,
    course_id: str,
    title: str,
    year: int,
    semester: str,
    supervisor_code: str,
    judges: Any,
    scores: Dict[str, float],
    attendees: Optional[List[str]] = None,
    files: Dict[str, str] = {},
) -> dict:
    """
    Persist a finalized defense into defended_thesis.json (atomic, idempotent per student/course).
    Stores judges as {"internal": code, "external": code} (normalized).
    """
    s_sup = ensure_score_range(scores.get("supervisor", 0))
    s_int = ensure_score_range(scores.get("internal", 0))
    s_ext = ensure_score_range(scores.get("external", 0))
    avg = round((s_sup + s_int + s_ext) / 3.0, 2)

    rec = {
        "student_code": student_code,
        "course_id": course_id,
        "title": title,
        "year": int(year),
        "semester": semester,
        "supervisor": supervisor_code,
        "judges": _normalize_judges(judges),
        "scores": {"supervisor": s_sup, "internal": s_int, "external": s_ext},
        "score": avg,
        "grade_letter": grade_letter(avg),
        "grade_letter_fa": grade_letter_fa(avg),
        "attendees": list(attendees or []),
        "files": files,
        "finalized_at": _now_iso(),
    }

    def _fn(archive):
        if not isinstance(archive, list):
            archive = []
        archive = [r for r in archive
                   if not (r.get("student_code") == student_code and r.get("course_id") == course_id)]
        archive.append(rec)
        return archive

    update_atomic(DEFENDED_F, _fn)
    _audit_log("ARCHIVE_DEFENSE", "repo", f"{student_code}/{course_id} grade={rec['grade_letter']}")
    _emit("finalized", {"student": student_code, "course": course_id, "score": rec["score"]},
          level="success", topic="defense", actor=supervisor_code, source="repo")
    return rec


# =========================
# Notifications (wrapper)
# =========================
def push_notification(event: str, payload: Dict[str, Any]):
    """
    Thin wrapper for central notifications.emit (kept for backward compatibility).
    """
    _emit(event, payload, source="repo")
    _audit_log("NOTIF", "repo", f"{event} {payload}")
