# core/audit.py
from __future__ import annotations
from datetime import datetime
from pathlib import Path
from typing import Optional, Literal, Dict, Any
import json
import os
import re

# ------------------------------------------------------------------------------------
# Paths (backward compatible names)
# - Keep same public constants as before: AUDIT_LOG, AUDIT_JSON (jsonl file)
# ------------------------------------------------------------------------------------
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

AUDIT_LOG = DATA_DIR / "audit.log"
AUDIT_JSON = DATA_DIR / "audit.jsonl"   # keep same name as original code
AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)

# Rotation & retention (bytes and count). ENV overrideable.
ROTATE_BYTES = int(os.getenv("THESIS_AUDIT_ROTATE", "10485760"))  # 10 MB default
RETENTION = int(os.getenv("THESIS_AUDIT_RETENTION", "7"))         # keep last 7 rotated files

# Schema version for JSONL records (future-proofing)
SCHEMA_VERSION = 1

# Level type
Level = Literal["INFO", "WARN", "ERROR", "SECURITY"]

# Internal drop counter for visibility (not exported)
_DROPPED_WRITES = 0

# ------------------------------------------------------------------------------------
# Sanitization and masking (anti log-injection and PII light masking)
# ------------------------------------------------------------------------------------
_EMAIL_RE = re.compile(r"([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
_LONG_DIGIT_RE = re.compile(r"\b(\d{6,})\b")
_CTRL_RE = re.compile(r"[\r\n\t]")  # remove control chars from text log columns

def _mask_pii(s: str) -> str:
    """Mask likely sensitive tokens (emails, long digit sequences)."""
    s = _EMAIL_RE.sub(lambda m: f"{m.group(1)[:2]}***@***", s)
    s = _LONG_DIGIT_RE.sub(lambda m: m.group(1)[:2] + "***", s)
    return s

def _clean_text_col(s: str) -> str:
    """Prevent log injection: strip control chars and pipes, trim length."""
    s = s or ""
    s = _CTRL_RE.sub(" ", s)
    s = s.replace("|", "¦")  # visually similar but inert
    if len(s) > 2000:
        s = s[:2000] + "…"
    return s

def _sanitize_extra(obj: Any) -> Any:
    """Make extra JSON-serializable and mask shallow strings."""
    try:
        json.dumps(obj)
        if isinstance(obj, str):
            return _mask_pii(obj)
        if isinstance(obj, dict):
            return {str(k): _sanitize_extra(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple, set)):
            return [_sanitize_extra(x) for x in obj]
        return obj
    except Exception:
        if isinstance(obj, dict):
            return {str(k): _sanitize_extra(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple, set)):
            return [_sanitize_extra(x) for x in obj]
        return _mask_pii(str(obj))

# ------------------------------------------------------------------------------------
# File locking (best-effort, cross-platform)
# ------------------------------------------------------------------------------------
class _FileLock:
    """Simple advisory file lock. If locking fails, proceeds without locking."""
    def __init__(self, path: Path):
        self._path = path
        self._fd: Optional[int] = None

    def __enter__(self):
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._fd = os.open(str(self._path), os.O_CREAT | os.O_RDWR)
            try:
                if os.name == "nt":
                    import msvcrt  # type: ignore
                    msvcrt.locking(self._fd, msvcrt.LK_LOCK, 1)
                else:
                    import fcntl  # type: ignore
                    fcntl.flock(self._fd, fcntl.LOCK_EX)
            except Exception:
                pass
        except Exception:
            self._fd = None
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if self._fd is not None:
                if os.name == "nt":
                    import msvcrt  # type: ignore
                    try:
                        msvcrt.locking(self._fd, msvcrt.LK_UNLCK, 1)
                    except Exception:
                        pass
                else:
                    import fcntl  # type: ignore
                    try:
                        fcntl.flock(self._fd, fcntl.LOCK_UN)
                    except Exception:
                        pass
                os.close(self._fd)
        except Exception:
            pass

_LOCK_LOG   = DATA_DIR / ".audit.log.lock"
_LOCK_JSONL = DATA_DIR / ".audit.jsonl.lock"

def _fsync_dir(path: Path) -> None:
    """Fsync directory to persist directory entries on POSIX."""
    try:
        fd = os.open(str(path), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except Exception:
        pass

# ------------------------------------------------------------------------------------
# Rotation helpers
# ------------------------------------------------------------------------------------
def _rotate_if_needed(target: Path, lock: Path, prefix: str) -> None:
    """Rotate target file if exceeds ROTATE_BYTES. Keep last RETENTION rotated files."""
    try:
        size = target.stat().st_size if target.exists() else 0
    except Exception:
        return
    if size < ROTATE_BYTES:
        return
    stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    rotated = target.with_name(f"{prefix}-{stamp}{target.suffix}")
    with _FileLock(lock):
        try:
            if target.exists():  # re-check inside lock
                target.replace(rotated)
                # trim old
                rots = sorted(target.parent.glob(f"{prefix}-*{target.suffix}"))
                if len(rots) > RETENTION:
                    for old in rots[:-RETENTION]:
                        try:
                            old.unlink(missing_ok=True)
                        except Exception:
                            pass
        except Exception:
            # non-fatal
            pass

# ------------------------------------------------------------------------------------
# Core write routines (append + fsync)
# ------------------------------------------------------------------------------------
def _append_text_line(path: Path, lock: Path, line: str) -> None:
    """Append a line to a text file with O_APPEND and fsync."""
    global _DROPPED_WRITES
    try:
        with _FileLock(lock):
            fd = os.open(str(path), os.O_CREAT | os.O_WRONLY | os.O_APPEND)
            try:
                os.write(fd, line.encode("utf-8"))
                os.fsync(fd)
            finally:
                os.close(fd)
        _fsync_dir(path.parent)
    except Exception:
        _DROPPED_WRITES += 1

def _append_jsonl_record(path: Path, lock: Path, record: Dict[str, Any]) -> None:
    """Append JSON line with O_APPEND and fsync. Rotate if needed."""
    _rotate_if_needed(path, lock, prefix=path.stem)  # e.g., audit.jsonl -> audit-YYYY.jsonl
    line = json.dumps(record, ensure_ascii=False) + "\n"
    _append_text_line(path, lock, line)

# ------------------------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------------------------
def _timestamp() -> str:
    # UTC with milliseconds + 'Z'
    return datetime.utcnow().isoformat(timespec="milliseconds") + "Z"

def log(
    action: str,
    who: str,
    detail: str = "",
    *,
    level: Level = "INFO",
    role: Optional[str] = None,
    session: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Write audit record to both human-readable .log and structured .jsonl (atomic-ish).
    - Text log is injection-safe (control chars and pipes sanitized).
    - JSONL masks basic PII in string fields inside `extra`.
    - Files rotate when exceeding ROTATE_BYTES; keep RETENTION rotated copies.
    """
    ts = _timestamp()

    # Build safe text columns
    level_txt  = f"{level:<8}"
    who_txt    = f"{_clean_text_col(who):<12}"
    action_txt = f"{_clean_text_col(action):<24}"
    detail_txt = _clean_text_col(_mask_pii(detail))

    line_txt = f"{ts} | {level_txt} | {who_txt} | {action_txt} | {detail_txt}\n"

    # JSONL record
    record = {
        "schema_version": SCHEMA_VERSION,
        "ts": ts,
        "level": level,
        "who": who,
        "role": role,
        "action": action,
        "detail": _mask_pii(detail),
        "session": session,
        "extra": _sanitize_extra(extra or {}),
    }

    # Append to .log and .jsonl (with rotation, lock, fsync)
    _rotate_if_needed(AUDIT_LOG, _LOCK_LOG, prefix="audit")
    _append_text_line(AUDIT_LOG, _LOCK_LOG, line_txt)
    _append_jsonl_record(AUDIT_JSON, _LOCK_JSONL, record)

def log_security(who: str, action: str, detail: str = "", **kw):
    log(action, who, detail, level="SECURITY", **kw)

def log_error(who: str, action: str, detail: str = "", **kw):
    log(action, who, detail, level="ERROR", **kw)

def log_warn(who: str, action: str, detail: str = "", **kw):
    log(action, who, detail, level="WARN", **kw)
