# core/notifications.py
from __future__ import annotations

from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any, List, Literal
import json
import os
import uuid
import re

from .repo import NOTIF_F, read_json, atomic_write  # keep compat; we won't use append_json to avoid races

# -----------------------------------------------------------------------------
# Paths & constants
# -----------------------------------------------------------------------------
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

NOTIF_JSONL = DATA_DIR / "notifications.jsonl"
NOTIF_JSONL.parent.mkdir(parents=True, exist_ok=True)

# JSONL rotation policy (bytes). When exceeded, rotate to notifications-YYYYMMDD_HHMMSS.jsonl
JSONL_ROTATE_BYTES = int(os.getenv("THESIS_NOTIF_JSONL_ROTATE", "10485760"))  # 10 MB
JSONL_RETENTION = int(os.getenv("THESIS_NOTIF_JSONL_RETENTION", "5"))         # keep last N rotated files

# Keep only last N notifications in NOTIF_F (windowed list to prevent unbounded growth)
NOTIF_MEMORY_MAX = max(1, int(os.getenv("THESIS_NOTIF_MEMORY_MAX", "2000")))

# Limit payload size (serialized JSON length in bytes). Large payloads will be summarized.
PAYLOAD_MAX_BYTES = int(os.getenv("THESIS_NOTIF_PAYLOAD_MAX", "100000"))  # ~100KB
PAYLOAD_PREVIEW_CHARS = int(os.getenv("THESIS_NOTIF_PAYLOAD_PREVIEW", "4096"))

# Console logging toggle via env (0/1)
_CONSOLE_LOG_ENABLED = os.getenv("THESIS_NOTIF_CONSOLE", "1") not in {"0", "false", "False"}

# Optional console sink (rich is optional)
try:
    from rich import print as rprint  # type: ignore
    _HAS_RICH = True
except Exception:
    _HAS_RICH = False

# Allowed levels
Level = Literal["debug", "info", "warn", "error", "success"]
_LEVELS_SET = {"debug", "info", "warn", "error", "success"}

# Schema version to future-proof records
SCHEMA_VERSION = 1

# Internal drop counter for error visibility
_DROPPED_WRITES = 0


@dataclass
class Notification:
    # Identity & time
    id: str
    ts: str  # ISO 8601 UTC with 'Z'

    # Event core
    event: str
    level: Level
    payload: Dict[str, Any] = field(default_factory=dict)

    # Context & tracing
    source: str = "cli"                   # e.g., cli|api|job|test
    actor: Optional[str] = None           # e.g., s001 / t001 / admin / system
    topic: Optional[str] = None           # e.g., thesis|auth|files|courses|scores
    tags: List[str] = field(default_factory=list)
    audience: Optional[str] = None        # e.g., student|professor|all|internal
    correlation_id: Optional[str] = None  # for multi-step flows

    # Dedupe controls
    dedupe_key: Optional[str] = None      # if provided, dedupe is enabled
    dedupe_window_sec: int = 0            # dedupe window in seconds (>=1)

    # Meta
    schema_version: int = SCHEMA_VERSION

    @staticmethod
    def now_iso() -> str:
        """Return UTC timestamp with milliseconds and trailing 'Z'."""
        return datetime.utcnow().isoformat(timespec="milliseconds") + "Z"


# -----------------------------------------------------------------------------
# Utilities (sanitization, masking, locks, fsync, rotation)
# -----------------------------------------------------------------------------
_EMAIL_RE = re.compile(r"([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
_LONG_DIGIT_RE = re.compile(r"\b(\d{6,})\b")

def _mask_pii_text(s: str) -> str:
    """Mask likely sensitive tokens (emails, long digit sequences)."""
    s = _EMAIL_RE.sub(lambda m: f"{m.group(1)[:2]}***@***", s)
    s = _LONG_DIGIT_RE.sub(lambda m: m.group(1)[:2] + "***", s)
    return s

def _sanitize(obj: Any) -> Any:
    """Ensure payload is JSON-serializable and lightly mask PII in strings."""
    try:
        json.dumps(obj)  # probe serializability
        if isinstance(obj, str):
            return _mask_pii_text(obj)
        if isinstance(obj, dict):
            return {str(k): _sanitize(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple, set)):
            return [_sanitize(x) for x in obj]
        return obj
    except Exception:
        if isinstance(obj, dict):
            return {str(k): _sanitize(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple, set)):
            return [_sanitize(x) for x in obj]
        return _mask_pii_text(str(obj))

def _limit_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Cap payload size; if too large, replace with a compact, masked preview."""
    try:
        blob = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        if len(blob) <= PAYLOAD_MAX_BYTES:
            return payload
        # too big: compress to a masked preview string
        preview = _mask_pii_text(blob.decode("utf-8"))[:PAYLOAD_PREVIEW_CHARS]
        return {
            "_truncated": True,
            "size_bytes": len(blob),
            "preview": preview,
        }
    except Exception:
        # on any error, just stringify and preview
        s = _mask_pii_text(str(payload))[:PAYLOAD_PREVIEW_CHARS]
        return {"_truncated": True, "preview": s}

# Cross-platform file lock (best-effort)
class _FileLock:
    """Simple cross-platform advisory lock. Best-effort: if lock fails, proceeds without locking."""
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

_LOCK_JSONL = DATA_DIR / ".notifications.jsonl.lock"
_LOCK_NOTIF_F = DATA_DIR / ".notifications_list.lock"

def _fsync_dir(path: Path) -> None:
    """fsync directory to persist directory entry on POSIX."""
    try:
        fd = os.open(str(path), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except Exception:
        pass

def _append_jsonl(record: Dict[str, Any]) -> None:
    """
    Atomic-ish append to JSONL with rotation by size.
    Uses O_APPEND write + directory fsync. Best-effort across platforms.
    """
    global _DROPPED_WRITES
    line = json.dumps(record, ensure_ascii=False) + "\n"

    # Rotate if too large
    try:
        if NOTIF_JSONL.exists() and NOTIF_JSONL.stat().st_size + len(line.encode("utf-8")) > JSONL_ROTATE_BYTES:
            stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            rotated = NOTIF_JSONL.with_name(f"notifications-{stamp}.jsonl")
            with _FileLock(_LOCK_JSONL):
                if NOTIF_JSONL.exists():
                    NOTIF_JSONL.replace(rotated)
                rots = sorted(NOTIF_JSONL.parent.glob("notifications-*.jsonl"))
                if len(rots) > JSONL_RETENTION:
                    for old in rots[:-JSONL_RETENTION]:
                        try:
                            old.unlink(missing_ok=True)
                        except Exception:
                            pass
    except Exception:
        pass  # non-fatal

    # Append line
    try:
        with _FileLock(_LOCK_JSONL):
            fd = os.open(str(NOTIF_JSONL), os.O_CREAT | os.O_WRONLY | os.O_APPEND)
            try:
                os.write(fd, line.encode("utf-8"))
                os.fsync(fd)
            finally:
                os.close(fd)
        _fsync_dir(NOTIF_JSONL.parent)
    except Exception:
        _DROPPED_WRITES += 1  # track silently dropped writes

def _console_log(n: Notification) -> None:
    """Optional console sink for live debugging (rich if available)."""
    if not _CONSOLE_LOG_ENABLED:
        return
    lvl = (n.level or "info").upper()
    payload_text = _mask_pii_text(json.dumps(n.payload, ensure_ascii=False))
    msg = f"[{lvl}] {n.event} :: actor={n.actor or '-'} topic={n.topic or '-'} payload={payload_text}"
    try:
        if _HAS_RICH:
            color = {
                "DEBUG": "dim",
                "INFO": "cyan",
                "WARN": "yellow",
                "ERROR": "red",
                "SUCCESS": "green",
            }.get(lvl, "white")
            rprint(f"[{color}]{n.ts} | {msg}[/]")
        else:
            print(f"{n.ts} | {msg}")
    except Exception:
        pass  # non-fatal

def _recent_from_list(limit_scan: int = 400) -> List[Dict[str, Any]]:
    """
    Return tail of NOTIF_F efficiently. We read the full JSON once (file-backed list),
    then slice to last `limit_scan` items to keep work small.
    """
    data = read_json(NOTIF_F)
    if not isinstance(data, list):
        return []
    if limit_scan <= 0:
        return data
    return data[-abs(limit_scan):]

def _parse_ts(ts: Any) -> Optional[datetime]:
    """Robust ISO8601-ish parser for our stored timestamps."""
    if not ts:
        return None
    s = str(ts).strip()
    try:
        # Common path: drop trailing Z if present
        return datetime.fromisoformat(s.replace("Z", ""))
    except Exception:
        pass
    # Try without subseconds
    try:
        if "." in s:
            base = s.split(".", 1)[0]
            return datetime.fromisoformat(base)
    except Exception:
        pass
    return None

def _should_dedupe(n: Notification, scan_tail: int = 400) -> bool:
    """
    Return True if a similar event (same event + dedupe_key) exists within the window.
    Only scans the last `scan_tail` records from NOTIF_F.
    """
    if not n.dedupe_key or n.dedupe_window_sec <= 0:
        return False
    try:
        cutoff = datetime.utcnow() - timedelta(seconds=int(n.dedupe_window_sec))
    except Exception:
        return False

    tail = _recent_from_list(scan_tail)
    for item in reversed(tail):
        try:
            if item.get("event") != n.event:
                continue
            if item.get("dedupe_key") != n.dedupe_key:
                continue
            t = _parse_ts(item.get("ts") or item.get("timestamp"))
            if t and t >= cutoff:
                return True
        except Exception:
            continue
    return False

def _append_to_notif_list(rec: Dict[str, Any]) -> None:
    """
    Append to NOTIF_F (JSON list) with windowing to prevent unbounded growth.
    This replaces append_json() to avoid RMW races as much as possible by using atomic_write.
    """
    with _FileLock(_LOCK_NOTIF_F):
        data = read_json(NOTIF_F)
        if not isinstance(data, list):
            data = []
        data.append(rec)
        if len(data) > NOTIF_MEMORY_MAX:
            data = data[-NOTIF_MEMORY_MAX:]
        atomic_write(NOTIF_F, data)

# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------
def emit(
    event: str,
    payload: Dict[str, Any],
    *,
    level: Level = "info",
    source: str = "cli",
    actor: Optional[str] = None,
    topic: Optional[str] = None,
    tags: Optional[List[str]] = None,
    audience: Optional[str] = None,
    correlation_id: Optional[str] = None,
    dedupe_key: Optional[str] = None,
    dedupe_window_sec: int = 0,
) -> Notification:
    """
    Create and persist a notification.
    """
    # Runtime level validation (defensive; keeps API tolerant)
    lvl = (level or "info").lower()
    if lvl not in _LEVELS_SET:
        lvl = "info"

    # Sanitize + size-limit payload
    sanitized = _sanitize(payload or {})
    capped = _limit_payload(sanitized)

    n = Notification(
        id=str(uuid.uuid4()),
        ts=Notification.now_iso(),
        event=str(event),
        level=lvl,                # type: ignore[arg-type]
        payload=capped,
        source=str(source or "cli"),
        actor=actor,
        topic=topic,
        tags=list(tags or []),
        audience=audience,
        correlation_id=correlation_id,
        dedupe_key=dedupe_key,
        dedupe_window_sec=int(dedupe_window_sec or 0),
        schema_version=SCHEMA_VERSION,
    )

    # Optional dedupe (still logs to console for visibility if deduped)
    if _should_dedupe(n):
        _console_log(n)
        return n

    rec = asdict(n)

    # Append to small JSON list (windowed)
    _append_to_notif_list(rec)

    # Mirror to JSONL for analytics (append + rotation)
    _append_jsonl(rec)

    # Optional console sink
    _console_log(n)

    return n


def list_recent(limit: int = 20, event: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Return last N notifications, optionally filtered by event.
    Filtering is done over a slightly larger tail to reduce misses for sparse events.
    """
    tail = _recent_from_list(max(limit * 5, limit))
    if event:
        tail = [x for x in tail if x.get("event") == event]
    return tail[-abs(limit):]


def purge_all() -> None:
    """Purge all notifications (use with care)."""
    with _FileLock(_LOCK_NOTIF_F):
        atomic_write(NOTIF_F, [])
    try:
        with _FileLock(_LOCK_JSONL):
            NOTIF_JSONL.unlink(missing_ok=True)
    except Exception:
        pass


def export_jsonl(dst_path: str) -> Path:
    """
    Export the JSONL log to a safe location under data/exports (sandbox).
    Returns the destination Path.
    """
    export_dir = DATA_DIR / "exports"
    export_dir.mkdir(parents=True, exist_ok=True)
    dst_name = Path(dst_path).name or f"notifications-{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.jsonl"
    dst = (export_dir / dst_name).resolve()

    try:
        content = NOTIF_JSONL.read_text(encoding="utf-8") if NOTIF_JSONL.exists() else ""
        dst.write_text(content, encoding="utf-8")
        _fsync_dir(dst.parent)
    except Exception:
        pass
    return dst
