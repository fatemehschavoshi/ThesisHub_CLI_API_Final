# core/search.py
from __future__ import annotations
from typing import List, Dict, Any, Optional, Iterable, Tuple
import re

# --- Optional semester normalizer from rules (fallback if not available)
try:
    from core.rules import normalize_semester as _normalize_semester_rules  # type: ignore
except Exception:
    _normalize_semester_rules = None  # fallback below


# =========================
# Text normalization (fa/en)
# =========================
_DIGIT_MAP = str.maketrans(
    "۰۱۲۳۴۵۶۷۸۹٠١٢٣٤٥٦٧٨٩",
    "01234567890123456789",
)

_ARABIC_TO_PERSIAN = {
    "ي": "ی",  # Arabic Yeh
    "ك": "ک",  # Arabic Kaf
}

_ZWNJ = "\u200c"

_WS_RE = re.compile(r"\s+")


def _normalize_text(s: str) -> str:
    """
    Normalize Persian/English text for fuzzy matching:
    - None-safe → ""
    - strip + lowercase
    - convert Arabic Yeh/Kaf → Persian
    - remove ZWNJ, collapse spaces
    - convert Persian/Arabic digits → ASCII
    """
    if not s:
        return ""
    s = str(s)
    s = s.replace(_ZWNJ, " ")
    s = s.translate(_DIGIT_MAP)
    s = "".join(_ARABIC_TO_PERSIAN.get(ch, ch) for ch in s)
    s = s.strip().lower()
    s = _WS_RE.sub(" ", s)
    return s


def _fuzzy_contains(needle: str, hay: str) -> bool:
    if not needle:
        return True
    return _normalize_text(needle) in _normalize_text(hay)


def _any_fuzzy(needle: str, items: Iterable[Any]) -> bool:
    for it in items or []:
        if isinstance(it, dict):
            # Try common text holders
            cand = it.get("text") or it.get("label") or it.get("name") or it.get("keyword") or ""
        else:
            cand = str(it)
        if _fuzzy_contains(needle, cand):
            return True
    return False


def _judge_codes(rec: Dict[str, Any]) -> List[str]:
    """
    Extract judge codes from supported shapes:
      - dict: {"internal": "t002", "external": "t003"}
      - list[str]: ["t002", "t003"]
      - list[dict]: [{"code": "t002", ...}, ...]
    """
    j = rec.get("judges") or []
    out: List[str] = []
    if isinstance(j, dict):
        out.extend([str(v) for v in j.values() if v])
    elif isinstance(j, list):
        for x in j:
            if isinstance(x, dict):
                code = x.get("code")
                if code:
                    out.append(str(code))
            elif x:
                out.append(str(x))
    return out


def _normalize_semester_input(sem: Optional[str]) -> Optional[str]:
    if sem is None:
        return None
    if _normalize_semester_rules:
        try:
            return _normalize_semester_rules(sem)
        except Exception:
            # fall through to heuristic
            pass
    m = _normalize_text(sem)
    if m in {"اول", "1", "first", "fa", "fall"}:
        return "اول"
    if m in {"دوم", "2", "second", "sp", "spring"}:
        return "دوم"
    # unknown → keep as-is (exact match will likely fail, which is intended)
    return sem


def _safe_float(x: Any, default: float = 0.0) -> float:
    try:
        return float(x)
    except Exception:
        return default


def _safe_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default


def _grade_to_en(g: str) -> Optional[str]:
    """
    Accept English A/B/C/D or Persian الف/ب/ج/د and return A/B/C/D.
    """
    if not g:
        return None
    g = _normalize_text(g)
    if g in {"a", "b", "c", "d"}:
        return g.upper()
    fa_map = {"الف": "A", "ب": "B", "ج": "C", "د": "D"}
    return fa_map.get(g, None)


def _sort_key(sort_by: str, rec: Dict[str, Any]) -> Tuple:
    sb = (sort_by or "year").lower()
    if sb == "year":
        # newer first when reverse=True
        return (_safe_int(rec.get("year"), -10**9), _normalize_text(rec.get("title", "")))
    if sb == "score":
        return (_safe_float(rec.get("score"), float("-inf")), _safe_int(rec.get("year"), -10**9))
    if sb == "title":
        return (_normalize_text(rec.get("title", "")), _safe_int(rec.get("year"), -10**9))
    # fallback deterministic
    return (_safe_int(rec.get("year"), -10**9), _normalize_text(rec.get("title", "")))


def search_archive(
    archive: List[Dict[str, Any]],
    *,
    title: Optional[str] = None,
    keyword: Optional[str] = None,
    author: Optional[str] = None,          # student_code (exact) or fuzzy name if 'student_name' exists
    year: Optional[int] = None,
    year_from: Optional[int] = None,
    year_to: Optional[int] = None,
    semester: Optional[str] = None,
    supervisor: Optional[str] = None,      # exact code
    judge: Optional[str] = None,           # exact code
    min_score: Optional[float] = None,
    max_score: Optional[float] = None,
    # New optional filters (backward-compatible)
    grade: Optional[str] = None,           # A/B/C/D or الف/ب/ج/د
    result: Optional[str] = None,          # "defense" | "re-defense"
    # Sorting / paging
    sort_by: str = "year",
    desc: bool = True,
    limit: Optional[int] = None,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    """
    Flexible archive search with filters and optional sorting.

    Args:
        title: fuzzy match in title
        keyword: fuzzy match in keywords list (list[str] or list[dict])
        author: exact student_code OR fuzzy student_name (if present)
        year: exact match on defense year
        year_from, year_to: inclusive range filter on year
        semester: normalized to {'اول','دوم'} if possible
        supervisor: exact teacher_code
        judge: exact judge code (supports dict/list[str]/list[dict])
        min_score, max_score: numeric filters on score (inclusive)
        grade: A/B/C/D یا «الف/ب/ج/د»
        result: 'defense' یا 're-defense'
        sort_by: 'year' | 'score' | 'title'
        desc: reverse order if True
        limit: cap results; if None returns all
        offset: starting index for paging
    """
    results: List[Dict[str, Any]] = []

    sem_norm = _normalize_semester_input(semester)
    grade_norm = _grade_to_en(grade) if grade else None
    result_norm = _normalize_text(result) if result else None

    for rec in archive:
        # Title (fuzzy)
        if title and not _fuzzy_contains(title, rec.get("title", "")):
            continue

        # Keywords (fuzzy on any)
        if keyword:
            kws = rec.get("keywords") or []
            if not _any_fuzzy(keyword, kws):
                continue

        # Author (student_code exact OR fuzzy on student_name)
        if author:
            a = str(author)
            if a == rec.get("student_code"):
                pass
            else:
                # try fuzzy name if present
                stu_name = rec.get("student_name") or rec.get("author") or ""
                if not _fuzzy_contains(a, stu_name):
                    continue

        # Year & range
        y = _safe_int(rec.get("year"), 0)
        if year is not None and y != _safe_int(year):
            continue
        if year_from is not None and y < _safe_int(year_from):
            continue
        if year_to is not None and y > _safe_int(year_to):
            continue

        # Semester (normalized if possible)
        if sem_norm is not None:
            if _normalize_semester_input(rec.get("semester")) != sem_norm:
                continue

        # Supervisor (exact code)
        if supervisor is not None and supervisor != rec.get("supervisor"):
            continue

        # Judges (any shape)
        if judge is not None and judge not in _judge_codes(rec):
            continue

        # Score
        s = _safe_float(rec.get("score"), 0.0)
        if min_score is not None and s < float(min_score):
            continue
        if max_score is not None and s > float(max_score):
            continue

        # Grade (A/B/C/D) – record may have english letter; accept fa letters too
        if grade_norm is not None:
            gl = rec.get("grade_letter")
            if gl and _normalize_text(gl) in {"a", "b", "c", "d"}:
                if gl.upper() != grade_norm:
                    continue
            else:
                # If grade_letter missing or non-standard, skip grade filter
                pass

        # Result
        if result_norm is not None:
            if _normalize_text(rec.get("result", "")) != result_norm:
                continue

        results.append(rec)

    # Sort (type-safe)
    try:
        results.sort(key=lambda r: _sort_key(sort_by, r), reverse=bool(desc))
    except Exception:
        # graceful fallback: sort by year desc then title
        results.sort(key=lambda r: (_safe_int(r.get("year"), -10**9), _normalize_text(r.get("title", ""))), reverse=True)

    # Paging
    if offset and offset > 0:
        results = results[offset:]
    if limit is not None and limit > 0:
        results = results[:limit]

    return results
