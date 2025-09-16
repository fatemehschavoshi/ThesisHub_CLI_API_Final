# ai/ocr.py
from __future__ import annotations

# Explicit public API for star-imports
__all__ = ["validate_images"]

from dataclasses import dataclass, asdict
from typing import Dict, List, Tuple, Optional, Set
from pathlib import Path
import re
import unicodedata
import time

# Optional deps (Pillow + Tesseract via pytesseract)
try:
    import pytesseract
    from PIL import Image, ImageOps, ImageFilter
    _PIL_OK = True
except Exception:  # pragma: no cover
    _PIL_OK = False
    pytesseract = None  # type: ignore

# ------------------------------- Config --------------------------------
# Preferred language combos to try with Tesseract (ordered)
PREFERRED_LANGS = ["fas+eng", "fas", "eng"]

# Basic guards for image types we accept
IMG_EXTS: Set[str] = {".jpg", ".jpeg", ".png", ".tif", ".tiff", ".bmp", ".webp"}

# Acceptance policy (flexible n-of-m + key fields)
COVER_FIELDS_GROUPS = {
    "title": [r"title", r"عنوان"],
    "supervisor": [r"supervisor", r"advisor", r"راهنما"],
    "semester": [r"semester", r"term", r"نیمسال", r"ترم"],
    "year": [r"year", r"academic\s*year", r"سال(?:\s*تحصیلی)?"],
}
LAST_FIELDS_GROUPS = {
    "title": [r"title", r"عنوان"],
    "author": [r"author", r"student", r"نویسنده", r"دانشجو"],
    "supervisor": [r"supervisor", r"advisor", r"راهنما"],
}
# Policy: cover needs >=3 fields and must include {"title","supervisor"}
COVER_REQUIRED_MIN = 3
COVER_MUST_HAVE = {"title", "supervisor"}
# Policy: last page needs >=2 fields and must include {"title","author"} OR {"title","supervisor"}
LAST_REQUIRED_MIN = 2
LAST_MUST_HAVE_ONE_OF = [{"title", "author"}, {"title", "supervisor"}]

# Preview masking/limits
PREVIEW_MAX = 300  # chars
MASK_DIGITS = True

# Resource/time limits (soft; used for warnings only)
MAX_BYTES = 10 * 1024 * 1024  # 10MB per image (advisory)
OCR_WARN_SEC = 6.0            # warn if OCR takes longer

# ---------------------------- Normalization ----------------------------
_PERSIAN_DIGITS = str.maketrans("۰۱۲۳۴۵۶۷۸۹", "0123456789")
_AR2FA = str.maketrans({"ي": "ی", "ك": "ک"})
_DIACRITICS_RE = re.compile(r"[\u064B-\u065F\u0670]")  # Arabic diacritics
_ZWNJ = "\u200c"
_TATWEEL = "\u0640"

def _normalize_text(s: str) -> str:
    """Unicode NFC + Arabic→Persian + Persian digits→Latin + strip diacritics & extras."""
    if not s:
        return ""
    s = unicodedata.normalize("NFC", s)
    s = s.translate(_AR2FA).translate(_PERSIAN_DIGITS)
    s = s.replace(_ZWNJ, " ").replace(_TATWEEL, "")
    s = _DIACRITICS_RE.sub("", s)
    s = re.sub(r"[ \t]+", " ", s)
    s = re.sub(r"\s*\n\s*", "\n", s)
    return s.strip()

def _mask_preview(s: str) -> str:
    """Mask potentially sensitive sequences in a preview (digits/emails)."""
    if not s:
        return s
    t = s
    # Mask emails
    t = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "[email]", t)
    # Mask long digit sequences
    if MASK_DIGITS:
        t = re.sub(r"\d{3,}", lambda m: "●" * len(m.group(0)), t)
    return t[:PREVIEW_MAX]

# --------------------------- Image utilities ---------------------------
def _validate_image_path(path_str: str) -> Tuple[Optional[Path], Optional[str], Optional[int]]:
    """Validate path existence and extension; return (Path, error_code, size_bytes)."""
    try:
        p = Path(path_str).expanduser().resolve()
    except Exception:
        return None, "invalid_path", None
    if not p.exists():
        return None, "not_found", None
    if p.suffix.lower() not in IMG_EXTS:
        return None, f"bad_extension:{p.suffix.lower()}", None
    try:
        size = p.stat().st_size
        if size <= 0:
            return None, "empty_file", size
        return p, None, size
    except Exception:
        return None, "stat_error", None

def _open_image_safe(path: Path) -> Image.Image:
    """Open image with Pillow and fix EXIF orientation; convert to RGB/L if needed."""
    img = Image.open(path)
    try:
        img = ImageOps.exif_transpose(img)
    except Exception:
        pass
    if img.mode not in ("RGB", "L"):
        img = img.convert("RGB")
    return img

def _preprocess_for_ocr(img: Image.Image) -> Image.Image:
    """
    Lightweight preprocessing:
    - Convert to grayscale
    - Autocontrast
    - Optional mild denoise for large images
    - Simple sharpening
    """
    try:
        g = img.convert("L")
        g = ImageOps.autocontrast(g)
        if min(g.size) >= 800:
            g = g.filter(ImageFilter.MedianFilter(size=3))
        g = g.filter(ImageFilter.UnsharpMask(radius=1.0, percent=150, threshold=3))
        return g
    except Exception:
        return img

# ----------------------------- OCR utilities ----------------------------
def _detect_tesseract() -> Tuple[bool, List[str], Optional[str]]:
    """
    Check Tesseract availability and list of languages (best-effort).
    Returns (available, langs, error_code_or_none).
    """
    if not (_PIL_OK and pytesseract):
        return False, [], "deps_missing"

    # Version check
    try:
        _ = pytesseract.get_tesseract_version()
    except Exception:
        return False, [], "tesseract_not_found"

    # Language check (optional; may fail on some installs)
    langs: List[str] = []
    try:
        langs = pytesseract.get_languages(config="")  # type: ignore[attr-defined]
    except Exception:
        # Some builds do not expose get_languages; continue silently
        langs = []

    return True, langs, None

def _ocr_once(img: Image.Image, lang: Optional[str]) -> str:
    """Run Tesseract OCR once with a given language code (or None)."""
    try:
        text = pytesseract.image_to_string(img, lang=lang) if lang else pytesseract.image_to_string(img)
        return _normalize_text(text)
    except Exception:
        return ""

def _ocr_with_fallbacks(img: Image.Image, langs_avail: Set[str]) -> Tuple[str, Optional[str], float]:
    """
    Try preferred language combos; record which one worked and how long it took.
    Returns (text, lang_used, took_sec).
    """
    start = time.time()
    for lang in PREFERRED_LANGS:
        # If we have a langs list, ensure every component is available before trying
        if langs_avail:
            parts_ok = all(part in langs_avail for part in lang.split("+"))
            if not parts_ok:
                continue
        txt = _ocr_once(img, lang)
        if txt and len(txt) >= 4:
            return txt, lang, time.time() - start
    # last attempt without lang hint
    txt = _ocr_once(img, None)
    used = None if not txt else None
    return txt, used, time.time() - start

# --------------------------- Pattern validation ---------------------------
def _compile_group_regex(variants: List[str]) -> re.Pattern:
    """Compile case-insensitive pattern that matches any of the provided variants."""
    # Avoid \b for Persian; just use alternation of cleaned variants
    joined = "|".join(f"(?:{v})" for v in variants)
    return re.compile(joined, flags=re.IGNORECASE)

def _check_fields(text: str, groups: Dict[str, List[str]]) -> Tuple[Dict[str, bool], int]:
    """Return per-field-group matches and total matched count."""
    matches: Dict[str, bool] = {}
    total = 0
    for key, variants in groups.items():
        pat = _compile_group_regex(variants)
        ok = bool(pat.search(text))
        matches[key] = ok
        if ok:
            total += 1
    return matches, total

def _policy_cover_ok(matches: Dict[str, bool]) -> bool:
    """Cover acceptance: >=N fields and must include key fields."""
    if sum(1 for v in matches.values() if v) < COVER_REQUIRED_MIN:
        return False
    return all(matches.get(k, False) for k in COVER_MUST_HAVE)

def _policy_last_ok(matches: Dict[str, bool]) -> bool:
    """Last-page acceptance: >=N fields and must include one of required sets."""
    if sum(1 for v in matches.values() if v) < LAST_REQUIRED_MIN:
        return False
    return any(all(matches.get(k, False) for k in req) for req in LAST_MUST_HAVE_ONE_OF)

# ------------------------------ Data models ------------------------------
@dataclass
class OCRFieldCheck:
    field: str
    matched: bool

@dataclass
class OCRReport:
    available: bool
    ok: Optional[bool]
    cover_ok: Optional[bool] = None
    last_ok: Optional[bool] = None
    cover_text_preview: Optional[str] = None
    last_text_preview: Optional[str] = None
    cover_matches: Optional[List[OCRFieldCheck]] = None
    last_matches: Optional[List[OCRFieldCheck]] = None
    errors: Optional[List[str]] = None
    lang_used: Optional[str] = None
    took_sec_cover: Optional[float] = None
    took_sec_last: Optional[float] = None
    langs_available: Optional[List[str]] = None

    def to_dict(self) -> Dict[str, object]:
        d = asdict(self)
        # compact previews
        if d.get("cover_text_preview"):
            d["cover_text_preview"] = d["cover_text_preview"][:PREVIEW_MAX]
        if d.get("last_text_preview"):
            d["last_text_preview"] = d["last_text_preview"][:PREVIEW_MAX]
        return d

# ------------------------------ Public API ------------------------------
def validate_images(cover_path: str, last_path: str) -> Dict[str, object]:
    """
    Validate first / last thesis pages using OCR (if available).
    Contract:
      - available=False, ok=None when deps/Tesseract are not available or open errors occur.
      - ok=True only if both cover_ok and last_ok are True (policies applied).
      - Structured details include per-field matches, short masked previews, timings, and errors.
    """
    errors: List[str] = []

    # Dependency & tesseract availability
    available, langs, err = _detect_tesseract()
    if err:
        errors.append(err)

    report = OCRReport(
        available=available,
        ok=None,
        errors=errors or [],
        langs_available=langs or None,
    )

    if not available:
        return report.to_dict()

    # Validate paths
    cover_p, err_c, size_c = _validate_image_path(cover_path)
    last_p, err_l, size_l = _validate_image_path(last_path)
    if err_c:
        report.errors.append(f"cover:{err_c}")
    if err_l:
        report.errors.append(f"last:{err_l}")
    if err_c or err_l:
        return report.to_dict()

    # Size advisories
    if size_c and size_c > MAX_BYTES:
        report.errors.append("cover_size_warn")
    if size_l and size_l > MAX_BYTES:
        report.errors.append("last_size_warn")

    # Load & preprocess
    try:
        cimg = _open_image_safe(cover_p)  # type: ignore[arg-type]
        limg = _open_image_safe(last_p)   # type: ignore[arg-type]
        cimg_pp = _preprocess_for_ocr(cimg)
        limg_pp = _preprocess_for_ocr(limg)
    except Exception as e:
        report.errors.append(f"open_error:{e.__class__.__name__}")
        return report.to_dict()

    langs_avail = set(langs or [])
    # OCR with fallbacks
    ctext, clang, t_c = _ocr_with_fallbacks(cimg_pp, langs_avail)
    ltext, llang, t_l = _ocr_with_fallbacks(limg_pp, langs_avail)

    # Timings & warnings
    report.took_sec_cover = round(t_c, 3)
    report.took_sec_last = round(t_l, 3)
    if t_c > OCR_WARN_SEC:
        report.errors.append("cover_ocr_slow")
    if t_l > OCR_WARN_SEC:
        report.errors.append("last_ocr_slow")

    # Prefer first language that worked
    report.lang_used = clang or llang

    # Field checks (on normalized text)
    c_matches_map, _ = _check_fields(ctext, COVER_FIELDS_GROUPS)
    l_matches_map, _ = _check_fields(ltext, LAST_FIELDS_GROUPS)

    # Policy decisions
    report.cover_ok = _policy_cover_ok(c_matches_map)
    report.last_ok = _policy_last_ok(l_matches_map)
    report.ok = True if (report.cover_ok and report.last_ok) else False

    # Per-field details
    report.cover_matches = [OCRFieldCheck(k, v) for k, v in c_matches_map.items()]
    report.last_matches = [OCRFieldCheck(k, v) for k, v in l_matches_map.items()]

    # Masked previews
    report.cover_text_preview = _mask_preview(ctext)
    report.last_text_preview = _mask_preview(ltext)

    # Edge cases: empty OCR text
    if not ctext:
        report.errors.append("cover_ocr_empty")
    if not ltext:
        report.errors.append("last_ocr_empty")

    # Language availability warnings (if list obtained)
    if langs:
        need = {p for combo in PREFERRED_LANGS for p in combo.split("+")}
        missing = sorted([x for x in need if x not in langs])
        if missing:
            report.errors.append("lang_missing:" + ",".join(missing))

    return report.to_dict()
