# PROJECT_DOCUMENT.md

> Full technical spec & design decisions for **ThesisHub**.  
> This document describes the architecture, data contracts, security model, file-handling policies, workflows, and deployment notes **as implemented in the current codebase**.

---

## 1. Architecture Overview

- **Web App (Flask)**: `web/server.py`  
  Routes for **Student**, **Professor (Supervisor)**, **Judge**, and **Admin** dashboards & actions. Uses Jinja2 templates in `web/templates/`. Session secret via `THESIS_SECRET`. Upload size via `THESIS_MAX_UPLOAD_MB`.
- **CLI (Typer + Rich)**: `app.py`  
  Full command set for admin ops, student/professor/judge flows, and archive/search. Rich tables/panels for output.
- **REST API (optional, FastAPI)**: `api/main.py`  
  JWT-protected endpoints (student/professor/admin), HTML forms for demo admin/judge pages, CSV exports, and the same business rules as web/CLI.
- **Core Services** (`core/`):
  - `repo.py`: Atomic JSON repository with sidecar locks, stale-lock cleanup, **backup rotation** (`data/_bak/`), robust `read_json()` with **fallback to latest backup** on corruption, `write_json()` atomic + fsync, **safe merge upsert** for thesis, **register_student/teacher()**, and archive helpers (`finalize_defense()`).
  - `audit.py`: Human log (`audit.log`) + JSONL stream (`audit.jsonl`) with **rotation/retention**, **PII masking**, **control‑char sanitization**, and constant‑time file appends with directory fsync.
  - `notifications.py`: In‑memory window (`notifications.json`) + JSONL mirror with **dedupe per `(event, dedupe_key)`**, TTL window, rotation/retention, and optional console echo.
  - `files.py`: Strict **file validation** (PDF/JPEG signatures), **size caps**, **safe filenames**, **atomic copy** with rollback, SHA256 **sidecar** files, and **de‑duplication** (by hash) or versioning.
  - `security.py`: Password policy, **bcrypt(+SHA256 prehash)**, backward‑compatible verify, **JWT issue/verify**, **HMAC** signing, constant‑time equals, secure random tokens, and a simple **rate‑limiter**.
  - `rules.py`: Business rules (90‑day wait, capacity accounting, grade mapping, semester/year validation) and schedule validation.
  - `search.py`: FA/EN text normalization, fuzzy contains, field filters, grade mapping (Fa/En), sorting, and paging.
- **Reports**: `reports/minutes_pdf.py` – RTL‑aware PDF minutes generator with QR fingerprint (HMAC‑signed), signature boxes, and metadata.

---

## 2. Data Contracts (JSON)

> All JSON files live under `data/` and are written **atomically** with backup snapshots in `data/_bak/`. Timestamps are UTC with `Z` suffix.

### 2.1 Students (`data/students.json`)
```json
{
  "name": "Ali Karimi",
  "student_code": "S1001",
  "password_hash": "<bcrypt>",
  "email": "ali@example.com",
  "created_at": "2025-08-01T09:30:00Z",
  "last_login": null,
  "active": true
}
```

### 2.2 Teachers (`data/teachers.json`)
```json
{
  "name": "Dr. Hosseini",
  "teacher_code": "T2001",
  "password_hash": "<bcrypt>",
  "email": "hosseini@example.com",
  "capacity_supervise": 5,
  "capacity_judge": 10,
  "roles": ["supervisor", "judge"],
  "created_at": "2025-08-01T09:15:00Z",
  "last_login": null,
  "active": true
}
```

### 2.3 Courses (`data/courses.json`)
```json
{
  "course_title": "Thesis (AI)",
  "course_id": "C3001",
  "teacher_code": "T2001",
  "year": 1404,
  "semester": "اول",
  "capacity": 2,
  "resources": ["Deep Learning", "NLP"],
  "sessions": 16,
  "units": 6,
  "type": "thesis",
  "description": "…",
  "status": "active",
  "created_at": "2025-08-01T10:00:00Z"
}
```

### 2.4 Active Theses (`data/thesis.json`)
```json
{
  "student_code": "S1001",
  "course_id": "C3001",
  "request_date": "2025-08-01",
  "approval_date": null,
  "status": "pending",                            // pending|approved|defense|rejected
  "supervisor": "T2001",
  "judges": { "internal": null, "external": null },
  "title": "",
  "abstract": "",
  "keywords": [],
  "defense_request_date": null,
  "defense_date": null,
  "scores": { "supervisor": null, "internal": null, "external": null },
  "files": {
    "pdf": null, "cover": null, "last": null
  },
  "ocr_validation": null
}
```
> After a defense-request upload, `files` becomes an object with **absolute OS paths** and integrity info:
```json
"files": {
  "pdf": "F:\\\\...\\\\files\\\\thesis\\\\S9001_C9001.pdf",
  "cover": "F:\\\\...\\\\files\\\\images\\\\S9001_C9001_cover.jpg",
  "last": "F:\\\\...\\\\files\\\\images\\\\S9001_C9001_last.jpg",
  "hashes": { "pdf": "<sha256>", "cover": "<sha256>", "last": "<sha256>" },
  "meta": {
    "pdf":   { "mime": "application/pdf", "size": 123456, "signature_ok": true },
    "cover": { "mime": "image/jpeg",      "size": 23456,  "signature_ok": true },
    "last":  { "mime": "image/jpeg",      "size": 23456,  "signature_ok": true }
  }
}
```

### 2.5 Archive (`data/defended_thesis.json`)
```json
{
  "student_code": "S1001",
  "course_id": "C3001",
  "title": "A Study on …",
  "year": 1404,
  "semester": "اول",
  "supervisor": "T2001",
  "judges": { "internal": "T2002", "external": "T2003" },
  "scores": { "supervisor": 18.5, "internal": 17.0, "external": 18.0 },
  "score": 17.83,
  "grade_letter": "A",
  "grade_letter_fa": "الف",
  "result": "defense",
  "files": { "...": "absolute paths as produced by files.py" },
  "keywords": ["Deep Learning", "NLP"],
  "summary": "…",
  "attendees": ["S1001", "T2001", "T2002", "T2003"],
  "finalized_at": "2025-08-28T12:00:00.000Z"
}
```

### 2.6 Notifications (`data/notifications.json` and `.jsonl` mirror)
```json
{
  "id": "uuid",
  "ts": "2025-08-28T12:30:00.000Z",
  "event": "student_registered",
  "level": "success",
  "payload": { "student": "S1001" },
  "source": "cli",
  "actor": "admin",
  "topic": "auth",
  "tags": ["register", "student"],
  "audience": "internal",
  "correlation_id": "flow-reg-001",
  "dedupe_key": "S1001|register",
  "dedupe_window_sec": 300,
  "schema_version": 1
}
```

---

## 3. Security Design (`core/security.py`)

- **Password hashing**: `hash_password()` uses **SHA‑256 prehash → bcrypt** (configurable `THESIS_BCRYPT_COST`) to avoid bcrypt’s 72‑byte truncation. `verify_password()` supports **legacy** hashes transparently. `needs_rehash()` signals upgrades.
- **Password policy**: `check_password_strength()` enforces length ≥ 8, class diversity (lower/upper/digit/symbol), not common, not equal to username.
- **JWT**: `issue_jwt(subject, role, ttl_s, issuer="ThesisHub")` and `verify_jwt(token, expected_role)` with **leeway**, issuer, (optional) audience. Claims: `sub`, `role`, `iat`, `exp`, `iss`.
- **HMAC**: `sign_data()` / `verify_signature()` using `THESIS_HMAC_SECRET` (fallbacks to JWT secret).
- **Rate limiting**: `RateLimiter(max_attempts, window_seconds)` with `allow(key)` and `remaining(key)`; used for login endpoints.
- **Constant‑time compare**: `constant_time_equals(a, b)` for signatures/tokens.
- **Tokens**: `random_token()` returns URL‑safe random strings (no padding).

Env keys used: `THESIS_JWT_SECRET`, `THESIS_JWT_ISSUER`, `THESIS_JWT_TTL`, `THESIS_JWT_LEEWAY`, `THESIS_HMAC_SECRET`, `THESIS_PEPPER`, `THESIS_BCRYPT_COST`.

---

## 4. Files & Validation (`core/files.py`)

- Accepted types: **PDF (.pdf)** for thesis, **JPEG (.jpg/.jpeg)** for cover & last page.
- Size caps (configurable via params): **PDF ≤ 50 MB**, **JPEG ≤ 10 MB**.
- Signature checks: PDF header `%PDF` and tail `%%EOF` (near end); JPEG magic `0xFFD8`.
- **Safe filenames**: normalization, removal of dangerous chars, max base length, FA/EN friendly; path traversal is blocked.
- **Atomic copy** with rollback on partial failure; directory **fsync** on POSIX.
- **Dedup/versioning**: by **SHA256 sidecars**; if dedup enabled, reuse identical existing files; otherwise auto‑version the destination names.
- Output locations:
  - `files/thesis/<prefix>.pdf`
  - `files/images/<prefix>_cover.jpg`
  - `files/images/<prefix>_last.jpg`

Returns a dict (stored under `thesis["files"]`) with absolute paths + `hashes` + `meta` (mime/size/signature_ok).

---

## 5. Audit & Notifications

- **Audit** (`core/audit.py`): append‑only text + JSONL with **rotation** (`THESIS_AUDIT_ROTATE`) and **retention** (`THESIS_AUDIT_RETENTION`). Columns sanitized (no control chars or pipe injection) and **PII masked** (emails & long digit sequences). Helper levels: `log()`, `log_error()`, `log_warn()`, `log_security()`.
- **Notifications** (`core/notifications.py`): windowed list in `notifications.json` (**size cap via `THESIS_NOTIF_MEMORY_MAX`**) + JSONL mirror with rotation/retention; **dedupe** by `(event, dedupe_key)` within `dedupe_window_sec`. Helpers: `emit()`/`notify()`, `list_recent()`.

---

## 6. Business Rules & Workflow (`core/rules.py` + flows)

- **Capacities**:
  - `DEFAULT_SUPERVISE_CAP=5`, `DEFAULT_JUDGE_CAP=10`.
  - Active supervision statuses: `{"pending","approved","defense"}`.
  - Active judging statuses: only `"defense"`.
  - Counters: `count_supervisions(theses, teacher_code)`, `count_judgings(theses, teacher_code)`.
- **Wait for defense**: `DEFENSE_WAIT_DAYS=90`.  
  - `can_request_defense(approval_date)` (1‑arg) **or** `can_request_defense(request_date, approval_date)` (2‑arg).  
  - `validate_defense_schedule(approval_date, defense_date, request_date?)` ensures **defense date is today/future** and consistent with approval/request.
- **Grades**: `ensure_score_range()`, `final_score_letter({"internal","external","supervisor"}) → (avg, letter)`; letters: **A [17..20], B [13..17), C [10..13), D [0..10)**; Persian mapping via `grade_letter_fa()`.
- **Semester/Year**: `normalize_semester("اول"|"دوم"|variants)`, `validate_year(1300..1600)`.

### End‑to‑End Defense Flow
1) **Student** requests thesis → `thesis.status="pending"`; course capacity decremented atomically.  
2) **Professor** approves → `status="approved"`, `approval_date=YYYY‑MM‑DD`.  
3) After 90 days, **Student** uploads **PDF/Cover/Last** → `status="defense"`, `defense_request_date` set; files validated and copied. (Optional AI: `ai/analysis.py`, `ai/ocr.py`.)  
4) **Professor** schedules defense (date + **internal/external judges**); checks: future/today, capacities via `count_judgings`, and **distinct roles** (supervisor cannot be judge).  
5) **Judges** (and supervisor) submit scores (after defense date).  
6) **Professor** finalizes: moves record to **archive** (`defended_thesis.json`), computes average + **grade letters (Fa/En)**, frees capacities, and (if available) generates **PDF minutes**.

---

## 7. Reports – PDF Minutes (`reports/minutes_pdf.py`)

- RTL‑aware rendering; if `arabic-reshaper` + `python-bidi` installed, text is correctly shaped.
- Preferred fonts: `Vazirmatn-Regular.ttf` → `IRANSans.ttf` → fallback `Helvetica` (auto‑detected from several paths).
- QR fingerprint: `THESIS|v1|student=S1001;course=C3001;score=17.83;date=2025‑08‑28;sig=<b64url>`; `sig` is **HMAC‑SHA256** (`THESIS_HMAC_SECRET` or JWT secret).  
  Helper: `build_qr_fingerprint()`; presence of signature is detected heuristically.
- Layout: title, parties (student/supervisor/judges), scores table, decision (defense/re‑defense), attendees, signatures, watermark/logo, and PDF metadata.
- Output path (web/CLI finalize): `files/reports/minutes_<student_code>_<course_id>.pdf`.

---

## 8. Search (`core/search.py`)

- **Normalization**: Persian digits → ASCII, normalize Arabic Yeh/Kaf, collapse whitespace, lowercase.  
- **Fuzzy contains** on normalized tokens.  
- **Filters**: title, keywords, author (name/code), **year range**, semester, supervisor, judge, min/max score, grade (A/B/C/D **or** الف/ب/ج/د), result.  
- **Sorting/Paging**: by year/score/title, asc/desc, with offset/limit.

---

## 9. Deployment Notes

- Set strong **`THESIS_SECRET`** and **`THESIS_JWT_SECRET`** in production.
- Put Flask behind a reverse proxy (nginx) for TLS and static file serving (`/files/*`).
- Ensure the app user has **write permissions** to `data/`, `data/_bak/`, `files/`.
- Consider `systemd`/`supervisor`/`pm2` for process management.
- Backups: app already snapshots JSONs into `data/_bak/` (pruned); plan **external backups** as well.

---

## 10. Future Work

- Expand REST API surface (OpenAPI/Swagger doc), and API keys for service‑to‑service.
- Background workers for OCR/analysis and report generation.
- Multi‑tenant separation (per faculty/department namespaces).
- Full‑text index (Whoosh/Lucene/Elasticsearch) for large archives.
- Real‑time notifications (Server‑Sent Events / WebSocket).

