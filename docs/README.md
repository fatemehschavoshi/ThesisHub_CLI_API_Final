# ThesisHub – Documentation

A hardened, file-backed thesis management system for universities, featuring:

- **Atomic JSON repository** with locks, backups, and fsync
- **Human-readable + JSONL audit logs** with rotation and retention
- **In-memory + JSONL notifications** with deduplication and rotation
- **Secure file ingestion** (PDF/JPEG signature check, atomic copy, SHA256 checksum)
- End-to-end **defense workflow**: request → approval → defense → archive
- **Scoring and grading rules** (supports FA/EN, letter grade mapping)
- **JWT authentication**, bcrypt+prehash password hashing, login rate-limiting
- **PDF minutes generator** (Persian-first, RTL-aware, QR fingerprint)
- **Fuzzy search** (FA/EN keywords, filters & sorting)
- **Flask web UI** for Student / Professor / Judge / Admin roles
- **Full CLI** (Typer + Rich) for headless usage and automation
- **Lightweight REST API** (FastAPI, optional)

---

## 1) Requirements

- Python **3.10+**
- pip / venv (recommended)
- OS: Linux, macOS, or Windows

Install dependencies:

```bash
pip install -r docs/requirements.txt
```

> **Optional:** Install `arabic-reshaper` and `python-bidi` for best RTL shaping in generated PDF minutes.

---

## 2) Project Layout

```
ThesisHub_CLI_API_Final/
├── app.py                  # CLI (Typer + Rich)
├── web/
│   ├── server.py           # Flask app (student/prof/judge/admin routes)
│   └── templates/          # Jinja2 templates
│       ├── login.html
│       ├── student/*.html
│       ├── professor/*.html
│       ├── judge/*.html
│       └── admin/*.html
├── core/
│   ├── repo.py             # atomic write, backups, register_* helpers
│   ├── rules.py            # capacity rules, score mapping, 90-day defense wait
│   ├── files.py            # file validation & atomic copy
│   ├── security.py         # bcrypt+SHA256, JWT, rate limiting
│   ├── search.py           # fuzzy archive search
│   ├── notifications.py    # in-memory + JSONL notifications
│   └── audit.py            # structured + human logs
├── api/
│   └── main.py             # optional FastAPI layer (JWT-protected)
├── ai/
│   ├── analysis.py         # text extraction & keyword generation (optional)
│   └── ocr.py              # cover/last-page OCR validation (optional)
├── reports/
│   └── minutes_pdf.py      # RTL-aware PDF minutes generator with QR
├── scripts/
│   └── demo_auto_flow.py   # E2E demo: request → approve → defense → archive
├── data/                   # JSON state + logs (auto-created)
│   ├── students.json
│   ├── teachers.json
│   ├── courses.json
│   ├── thesis.json
│   ├── defended_thesis.json
│   ├── notifications.json
│   ├── audit.jsonl
│   ├── audit.log
│   └── _bak/               # automatic versioned backups
├── files/
│   ├── pdfs/               # thesis PDF uploads
│   └── images/             # cover/last-page images
├── docs/
│   ├── README.md
│   └── PROJECT_DOCUMENT.md
├── requirements.txt
├── .env.example
└── .env
```

---

## 3) Environment Variables

Copy `.env.example` to `.env` and adjust as needed.

### Flask / App
- `THESIS_SECRET` – Flask session secret key (**required in production**)
- `PORT` – default `5000`
- `FLASK_DEBUG` – set `1` for development
- `THESIS_MAX_UPLOAD_MB` – max upload size in MB (default `25`)

### Security
- `THESIS_BCRYPT_COST` – bcrypt cost factor (default `12`)
- `THESIS_PEPPER` – optional password pepper
- `THESIS_JWT_SECRET` – JWT signing key
- `THESIS_JWT_ISSUER` – default `ThesisHub`
- `THESIS_JWT_ALGO` – default `HS256`
- `THESIS_JWT_TTL` – seconds, default `28800` (8h)
- `THESIS_JWT_LEEWAY` – clock skew allowance
- `THESIS_HMAC_SECRET` – HMAC secret for QR signing (defaults to JWT secret)

### Audit / Notifications
- `THESIS_AUDIT_ROTATE` – max audit log size before rotation (default 10 MB)
- `THESIS_AUDIT_RETENTION` – number of rotated copies (default 7)
- `THESIS_NOTIF_JSONL_ROTATE` – max JSONL notif log size (default 10 MB)
- `THESIS_NOTIF_JSONL_RETENTION` – rotated copies (default 5)
- `THESIS_NOTIF_MEMORY_MAX` – in-memory window size (default 2000)
- `THESIS_NOTIF_CONSOLE` – `1`/`0` console printing toggle

### Admin (demo)
- `ADMIN_USER` / `ADMIN_PASS` – credentials for `/admin/login`

---

## 4) Running

**Quick start (Windows PowerShell):**
```powershell
$env:FLASK_DEBUG="1"
flask --app web.server:app run --host=0.0.0.0 --port=5000
```

Then open in browser:
```
http://127.0.0.1:5000
```

**End-to-End demo (seed + auto flow):**
```powershell
$env:OVERWRITE="1"
python scripts/demo_auto_flow.py
```

This will reset `data/*.json`, create demo users/courses, and simulate the full flow (request → approve → defense → grading → archive).

---

## 5) CLI Usage

Example (student flow):
```bash
python app.py student login
python app.py student courses
python app.py student request --course-id C3001
python app.py student defense-request --course-id C3001 --pdf files/pdfs/thesis.pdf --cover files/images/cover.jpg --last files/images/last.jpg
```

Professor flow:
```bash
python app.py professor login
python app.py professor requests
python app.py professor approve --request-id REQ-1001
python app.py professor schedule --defense-id DEF-2001 --date 2025-12-22 --internal T2002 --external T2003
python app.py professor finalize --defense-id DEF-2001
```

Judge flow:
```bash
python app.py judge login
python app.py judge score --defense-id DEF-2001 --score 18.5
```

---

## 6) Data & File Handling

- JSON state under `data/` with **atomic writes** and automatic backups in `data/_bak/`.
- Uploads live under `files/`:
  - `files/pdfs/` – thesis PDFs
  - `files/images/` – cover/last images

`core/files.py` performs:
- PDF header/EOF validation
- JPEG magic number check
- Size enforcement + safe filename generation
- Atomic copy + `.sha256` sidecar file for integrity

---

## 7) Audit & Notifications

- **Audit logs:** `data/audit.log` (human) + `data/audit.jsonl` (machine-readable) with rotation and retention.
- **Notifications:** in-memory window (`notifications.json`) + JSONL mirror with dedup and rotation.

Usage in code:
```python
from core.audit import log_action
from core.notifications import notify, list_notifications
```

---

## 8) Business Rules

Defined in `core/rules.py`:
- Semester normalization: accepts «اول», «دوم», numeric, EN variants.
- Defense wait: ≥ 90 days from approval date.
- Score validation: `ensure_score_range`, average computation, letter mapping (A/B/C/D + Persian equivalent).
- Capacity validation: course capacity, supervisor (5), judge (10).

---

## 9) Reports (PDF Minutes)

`reports/minutes_pdf.py` generates RTL-aware PDF with:
- Shaped Persian text (if `arabic-reshaper` + `python-bidi` installed)
- QR fingerprint (HMAC-signed)
- Score table, signature boxes, watermark/logo
- Proper metadata

Output path:
```
files/reports/minutes_<student_code>_<course_id>.pdf
```

---

## 10) Search

`core/search.py` performs fuzzy search with filters:
- Title, keywords, author, year range, semester, supervisor, judge
- Min/max score, grade letter, result type (defense/re-defense)
- Sorting and paging supported

---

## 11) Optional AI

If `ai/analysis.py` and/or `ai/ocr.py` exist:
- Extract and summarize PDF text
- Auto-generate keywords
- OCR validate cover/last images

System gracefully skips if missing.

---

## 12) Troubleshooting

- **Permissions:** ensure `data/` and `files/` are writable.
- **RTL text issues:** install `arabic-reshaper` + `python-bidi` and add proper TTF fonts.
- **Upload too large:** raise `THESIS_MAX_UPLOAD_MB` in `.env`.
- **Defense request blocked:** check approval date (90-day rule).
- **Corrupted JSON:** restore from `data/_bak/` or rerun `scripts/demo_auto_flow.py`.

Logs:
- `data/audit.log` – human readable
- `data/notifications.jsonl` – event stream
