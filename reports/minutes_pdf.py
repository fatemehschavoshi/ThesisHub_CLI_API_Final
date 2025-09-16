# reports/minutes_pdf.py
from __future__ import annotations

from typing import List, Dict, Optional, Tuple, Any
from pathlib import Path
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

# Optional (for QR code)
try:
    from reportlab.graphics.barcode import qr
    from reportlab.graphics.shapes import Drawing
    QR_AVAILABLE = True
except Exception:
    QR_AVAILABLE = False

# RTL shaping (optional)
_HAS_RTL = False
try:
    import arabic_reshaper  # type: ignore
    from bidi.algorithm import get_display  # type: ignore
    _HAS_RTL = True
except Exception:
    _HAS_RTL = False

# HMAC signing for QR fingerprint
try:
    from core.security import sign_data  # uses THESIS_JWT_SECRET or supplied secret
except Exception:
    sign_data = None  # graceful fallback if not available


def _rtl(s: Any) -> str:
    """Return visually-correct RTL string if libs are available (safe fallback)."""
    text = "" if s is None else str(s)
    if not text or not _HAS_RTL:
        return text
    try:
        reshaped = arabic_reshaper.reshape(text)
        return get_display(reshaped)
    except Exception:
        return text


# ----------- Fonts / i18n -----------
PREFERRED_FONTS = [
    ("Vazirmatn", [
        Path(__file__).resolve().parent / "fonts" / "Vazirmatn-Regular.ttf",
        Path(__file__).resolve().parent.parent / "fonts" / "Vazirmatn-Regular.ttf",
        Path("Vazirmatn-Regular.ttf"),
    ]),
    ("IRANSans", [
        Path(__file__).resolve().parent / "fonts" / "IRANSans.ttf",
        Path(__file__).resolve().parent.parent / "fonts" / "IRANSans.ttf",
        Path("IRANSans.ttf"),
    ]),
]
FALLBACK_FONT = "Helvetica"

def _register_first_available_font() -> str:
    for family, candidates in PREFERRED_FONTS:
        for p in candidates:
            try:
                if p.exists():
                    pdfmetrics.registerFont(TTFont(family, str(p)))
                    return family
            except Exception:
                continue
    return FALLBACK_FONT

FONT_MAIN = _register_first_available_font()


# ----------- Low-level text helpers -----------
def _text_width(c: canvas.Canvas, text: str, font_name: str, font_size: float) -> float:
    c.setFont(font_name, font_size)
    return c.stringWidth(text, font_name, font_size)

def _wrap_text(c: canvas.Canvas, text: str, max_width: float, font_name: str, font_size: float) -> List[str]:
    raw = "" if text is None else str(text)
    if not raw:
        return []
    words = raw.split()
    lines: List[str] = []
    acc: List[str] = []

    for w in words:
        test_logical = (" ".join(acc + [w])).strip()
        test_visual = _rtl(test_logical)
        if _text_width(c, test_visual, font_name, font_size) <= max_width:
            acc.append(w)
        else:
            if acc:
                lines.append(" ".join(acc))
            acc = [w]
    if acc:
        lines.append(" ".join(acc))
    return [_rtl(line) for line in lines]

def _draw_right(c: canvas.Canvas, x_right: float, y: float, text: str, font: str, size: float, color=colors.black):
    c.setFont(font, size)
    c.setFillColor(color)
    c.drawRightString(x_right, y, _rtl(text))

def _draw_left(c: canvas.Canvas, x_left: float, y: float, text: str, font: str, size: float, color=colors.black):
    c.setFont(font, size)
    c.setFillColor(color)
    c.drawString(x_left, y, _rtl(text))

def _draw_kv(
    c: canvas.Canvas,
    x_left: float,
    x_right: float,
    y: float,
    key: str,
    val: str,
    font: str,
    key_size: float = 11,
    val_size: float = 11,
    gap: float = 4*mm,
) -> float:
    """Right-aligned Persian key with wrapped value to the left area."""
    key_vis = _rtl(key)
    c.setFont(font, key_size)
    _draw_right(c, x_right, y, key_vis, font, key_size)

    val_area_right = x_right - gap
    val_area_left = x_left
    max_w = max(0.0, val_area_right - val_area_left)
    lines = _wrap_text(c, val, max_w, font, val_size) or [_rtl("-")]

    for i, line in enumerate(lines):
        if i == 0:
            _draw_right(c, val_area_right, y, line, font, val_size)
        else:
            y -= 5.5 * mm
            _draw_right(c, val_area_right, y, line, font, val_size)
    return y - 7 * mm

def _grade_letter_fa(letter: str) -> str:
    mapping = {"A": "الف", "B": "ب", "C": "ج", "D": "د"}
    return mapping.get((letter or "D").upper(), "د")

def _safe_join(items: List[str], sep: str = "، "):
    return sep.join([_rtl(s) for s in items if s])

def _draw_hr(c: canvas.Canvas, x1: float, x2: float, y: float, color=colors.grey) -> None:
    c.setStrokeColor(color)
    c.setLineWidth(0.6)
    c.line(x1, y, x2, y)

def _draw_signature_box(c: canvas.Canvas, x: float, y: float, w: float, h: float, label: str, font: str):
    c.setStrokeColor(colors.black)
    c.setLineWidth(0.8)
    c.rect(x, y - h, w, h, stroke=1, fill=0)
    _draw_left(c, x + 3*mm, y - h - 4*mm, label, font, 10, colors.black)
    _draw_left(c, x + 4*mm, y - 8*mm, "نام:", font, 9, colors.gray)
    _draw_left(c, x + 4*mm, y - 14*mm, "امضاء:", font, 9, colors.gray)
    _draw_left(c, x + 4*mm, y - 20*mm, "تاریخ:", font, 9, colors.gray)

def _draw_qr(c: canvas.Canvas, data: str, x: float, y: float, size: float):
    if not QR_AVAILABLE or not data:
        return
    try:
        code = qr.QrCodeWidget(data)
        b = code.getBounds()
        w = b[2] - b[0]
        h = b[3] - b[1]
        d = Drawing(size, size, transform=[size / w, 0, 0, size / h, 0, 0])
        d.add(code)
        d.drawOn(c, x, y)
    except Exception:
        pass

def _draw_watermark(c: canvas.Canvas, text: str, page_w: float, page_h: float):
    """Subtle watermark without alpha (use light gray)."""
    if not text:
        return
    c.saveState()
    c.setFillColorRGB(0.85, 0.85, 0.85)
    c.setFont(FONT_MAIN, 58)
    c.rotate(30)
    c.drawCentredString(page_w * 0.7, page_h * 0.25, _rtl(text))
    c.restoreState()

def _ensure_out_dir(path: str):
    p = Path(path).expanduser().resolve()
    p.parent.mkdir(parents=True, exist_ok=True)
    return str(p)

def _need_new_page(y: float, margin: float) -> bool:
    return y < (margin + 35*mm)

# ----------- Footer / Paging helpers -----------
def _utc_now_display() -> str:
    # UTC with minutes precision + Z suffix (consistent with project)
    return datetime.utcnow().strftime("%Y-%m-%d %H:%MZ")

def _draw_footer(c: canvas.Canvas, page_w: float, margin: float, font: str):
    """Standard footer with UTC timestamp and page number."""
    y_line = 25 * mm
    _draw_hr(c, margin, page_w - margin, y_line)
    # Left: UTC timestamp
    _draw_left(c, margin, 20*mm, f"زمان تولید (UTC): {_utc_now_display()}", font, 8.5, colors.gray)
    # Right: page number
    page_no = c.getPageNumber()
    _draw_right(c, page_w - margin, 20*mm, f"ThesisHub · سند رسمی صورتجلسه دفاع · صفحه {page_no}", font, 8.5, colors.gray)

def _finish_page(c: canvas.Canvas, page_w: float, margin: float, font: str):
    """Draw footer and advance to next page."""
    _draw_footer(c, page_w, margin, font)
    c.showPage()

# ----------- Safe number formatting -----------
def _fmt2(x) -> str:
    """Format numbers as '%.2f' with a safe fallback for exotic float types."""
    try:
        return "{:.2f}".format(float(x))
    except Exception:
        return str(x)

# ----------- QR fingerprint (HMAC) -----------
def build_qr_fingerprint(
    *,
    student_code: str,
    course_id: str,
    final_score: float,
    date_iso: str,
    version: str = "v1",
    secret: Optional[str] = None,
) -> str:
    """
    Canonical QR payload:
      THESIS|v1|student=S1001;course=C3001;score=17.83;date=2025-08-28;sig=<base64url>
    Signature = HMAC-SHA256 over the prefix without ';sig=...' using secret (or default).
    """
    data_fields = f"student={student_code};course={course_id};score={_fmt2(final_score)};date={date_iso}"
    prefix = f"THESIS|{version}|{data_fields}"
    sig = ""
    try:
        if sign_data:
            sig = sign_data(prefix, secret)
    except Exception:
        sig = ""
    return f"{prefix};sig={sig}" if sig else prefix

def _qr_is_signed(data: Optional[str]) -> bool:
    """Heuristic: consider signed if payload contains a non-empty ';sig=' field."""
    if not data or ";sig=" not in data:
        return False
    try:
        return bool(data.split(";sig=", 1)[1].strip())
    except Exception:
        return False


# ----------- Public API -----------
def render_minutes(
    out_path: str,
    *,
    title: str,
    student: str,                      # display name
    supervisor: str,                   # display name
    judges: Dict[str, str] | List[str] | List[Dict[str, str]],
    year: int,
    semester: str,                     # "اول"/"دوم"
    final_score: float,
    grade_letter: str,                 # "A"/"B"/...
    result: str,                       # "defense"/"re-defense" or localized
    # IDs for QR (optional but recommended)
    student_code: Optional[str] = None,
    course_id: Optional[str] = None,
    defense_date: Optional[str] = None,   # ISO yyyy-mm-dd (for QR date)
    qr_secret: Optional[str] = None,      # override secret for QR signing (optional)
    # Optional/advanced:
    attendees: Optional[List[str]] = None,
    scores: Optional[Dict[str, Optional[float]]] = None,  # {"internal": x, "external": y, "supervisor": z}
    logo_path: Optional[str] = None,
    qr_data: Optional[str] = None,          # if provided, used as-is; otherwise built from fingerprint fields
    watermark_text: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Render a formal thesis defense minutes PDF (Persian-first, RTL-aware), with standardized QR fingerprint.

    ENHANCEMENTS:
    - Footer shows UTC timestamp + page number on every page.
    - QR gets a small label indicating whether it is HMAC-signed or not.
    """

    # Prepare output path
    out_path = _ensure_out_dir(out_path)

    # Canvas & page
    c = canvas.Canvas(out_path, pagesize=A4)
    W, H = A4
    margin = 20*mm
    x_left = margin
    x_right = W - margin
    content_w = W - 2 * margin
    y = H - margin

    # PDF metadata (best-effort)
    try:
        md = metadata or {}
        c.setAuthor(_rtl(md.get("Author") or student))
        c.setTitle(_rtl(md.get("Title") or f"صورتجلسه دفاع - {title}"))
        c.setSubject(_rtl(md.get("Subject") or "صورتجلسه دفاع پایان‌نامه"))
        kws = md.get("Keywords")
        if isinstance(kws, (list, tuple)):
            c.setKeywords(", ".join([str(k) for k in kws]))
        elif isinstance(kws, str):
            c.setKeywords(kws)
        else:
            c.setKeywords("thesis, defense, minutes")
        c.setCreator("ThesisHub")
        c.setProducer("ThesisHub Report Engine")
    except Exception:
        pass

    # Watermark (optional, first page)
    if watermark_text:
        _draw_watermark(c, watermark_text, W, H)

    # Header: Logo (optional)
    if logo_path:
        p = Path(logo_path)
        if p.exists():
            try:
                max_h = 18*mm
                c.drawImage(str(p), x_left, y - max_h, width=30*mm, height=max_h,
                            preserveAspectRatio=True, mask='auto')
            except Exception:
                pass

    # Header: QR (standardized)
    built_qr = qr_data
    if not built_qr and student_code and course_id:
        qr_date = defense_date or datetime.utcnow().date().isoformat()
        built_qr = build_qr_fingerprint(
            student_code=student_code,
            course_id=course_id,
            final_score=final_score,
            date_iso=qr_date,
            version="v1",
            secret=qr_secret,
        )
    if built_qr:
        qr_x = x_right - 25*mm
        qr_y = y - 25*mm
        _draw_qr(c, built_qr, qr_x, qr_y, size=22*mm)
        # QR signature label
        lbl = "QR: امضاء‌شده" if _qr_is_signed(built_qr) else "QR: بدون امضاء"
        _draw_right(c, x_right, qr_y - 3*mm, lbl, FONT_MAIN, 8.5, colors.darkgray)

    # Title (center)
    title_vis = _rtl("صورتجلسه دفاع پایان‌نامه")
    c.setFont(FONT_MAIN, 16)
    c.setFillColor(colors.black)
    title_w = _text_width(c, title_vis, FONT_MAIN, 16)
    c.drawString((W - title_w) / 2.0, y - 4*mm, title_vis)

    y -= 16*mm
    _draw_hr(c, x_left, x_right, y); y -= 6*mm

    # Core info
    y = _draw_kv(c, x_left, x_right, y, "عنوان:", title, FONT_MAIN, key_size=12, val_size=12)
    if _need_new_page(y, margin):
        _finish_page(c, W, margin, FONT_MAIN); y = H - margin
        if watermark_text:
            _draw_watermark(c, watermark_text, W, H)

    y = _draw_kv(c, x_left, x_right, y, "دانشجو:", student, FONT_MAIN)
    y = _draw_kv(c, x_left, x_right, y, "استاد راهنما:", supervisor, FONT_MAIN)

    # Judges normalize
    def _norm_judges(j) -> Tuple[str, str]:
        internal, external = "", ""
        if not j:
            return internal, external
        if isinstance(j, dict):
            internal = str(j.get("internal") or "")
            external = str(j.get("external") or "")
            return internal, external
        if isinstance(j, list):
            for item in j:
                if isinstance(item, dict):
                    role = (item.get("role") or "").lower()
                    disp = item.get("name") or item.get("code") or ""
                    if role == "internal":
                        internal = str(disp)
                    elif role == "external":
                        external = str(disp)
            if not internal and not external:
                joined = " / ".join([str(x) for x in j if x])
                return joined, ""
        return internal, external

    j_internal, j_external = _norm_judges(judges)
    judges_line = f"داور داخلی: {j_internal or '-'} | داور خارجی: {j_external or '-'}"
    y = _draw_kv(c, x_left, x_right, y, "داوران:", judges_line, FONT_MAIN)
    y = _draw_kv(c, x_left, x_right, y, "سال/نیمسال:", f"{year} / {semester}", FONT_MAIN)

    # Localized result (keep as-is if already localized)
    result_disp = {
        "defense": "دفاع",
        "re-defense": "دفاع مجدد",
    }.get((result or "").lower(), result)
    y = _draw_kv(c, x_left, x_right, y, "نتیجه:", result_disp, FONT_MAIN)

    # Scores table (optional)
    if scores and any(v is not None for v in scores.values()):
        if _need_new_page(y, margin):
            _finish_page(c, W, margin, FONT_MAIN); y = H - margin
            if watermark_text:
                _draw_watermark(c, watermark_text, W, H)

        y -= 4*mm
        _draw_right(c, x_right, y, "ریز نمرات:", FONT_MAIN, 12)
        y -= 8*mm

        col_w_role = 60*mm
        col_w_score = 25*mm
        row_h = 8.5*mm
        table_w = col_w_role + col_w_score
        table_x = x_right - table_w

        # header
        c.setFillColor(colors.whitesmoke)
        c.rect(table_x, y - row_h, table_w, row_h, fill=1, stroke=0)
        _draw_right(c, table_x + col_w_role - 2*mm, y - 6*mm, "نقش", FONT_MAIN, 11, colors.black)
        _draw_right(c, table_x + table_w - 2*mm, y - 6*mm, "نمره", FONT_MAIN, 11, colors.black)
        y -= row_h

        def _row(label: str, value: Optional[float]):
            nonlocal y
            c.setFillColor(colors.white)
            c.rect(table_x, y - row_h, table_w, row_h, fill=1, stroke=1)
            _draw_right(c, table_x + col_w_role - 2*mm, y - 6*mm, label, FONT_MAIN, 10.5, colors.black)
            vstr = "-" if value is None else _fmt2(value)
            _draw_right(c, table_x + table_w - 2*mm, y - 6*mm, vstr, FONT_MAIN, 10.5, colors.black)
            y -= row_h

        _row("داور داخلی", scores.get("internal"))
        _row("داور خارجی", scores.get("external"))
        _row("استاد راهنما", scores.get("supervisor"))

        y -= 3*mm
        final_line = f"نمره نهایی: {_fmt2(final_score)}  ({_grade_letter_fa(grade_letter)} / {grade_letter})"
        _draw_right(c, x_right, y, final_line, FONT_MAIN, 11.5, colors.black)
        y -= 12*mm

    # Attendees (optional)
    if attendees:
        if _need_new_page(y, margin):
            _finish_page(c, W, margin, FONT_MAIN); y = H - margin
            if watermark_text:
                _draw_watermark(c, watermark_text, W, H)
        _draw_right(c, x_right, y, "حاضرین جلسه:", FONT_MAIN, 12)
        y -= 7*mm
        for i, p in enumerate(attendees, 1):
            y = _draw_kv(c, x_left, x_right, y, f"{i}.", str(p), FONT_MAIN, key_size=10.5, val_size=10.5)
            if _need_new_page(y, margin):
                _finish_page(c, W, margin, FONT_MAIN); y = H - margin
                if watermark_text:
                    _draw_watermark(c, watermark_text, W, H)

    # Signature boxes
    if _need_new_page(y, margin):
        _finish_page(c, W, margin, FONT_MAIN); y = H - margin
        if watermark_text:
            _draw_watermark(c, watermark_text, W, H)

    y -= 2*mm
    _draw_hr(c, x_left, x_right, y); y -= 8*mm
    _draw_right(c, x_right, y, "امضاء‌ها:", FONT_MAIN, 12)
    y -= 10*mm

    box_w = (content_w - 10*mm) / 2
    box_h = 25*mm

    # Row 1: Supervisor / Internal
    _draw_signature_box(c, x_right - (box_w + 10*mm + box_w), y, box_w, box_h, "استاد راهنما", FONT_MAIN)
    _draw_signature_box(c, x_right - box_w, y, box_w, box_h, "داور داخلی", FONT_MAIN)
    y -= (box_h + 12*mm)

    # Row 2: External
    _draw_signature_box(c, x_right - box_w, y, box_w, box_h, "داور خارجی", FONT_MAIN)
    y -= (box_h + 8*mm)

    # Footer + finalize
    _finish_page(c, W, margin, FONT_MAIN)
    c.save()
