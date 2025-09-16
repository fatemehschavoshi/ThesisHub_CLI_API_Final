# Demo Auto Flow (Headless)

This script executes a full thesis lifecycle **without any UI**—useful for smoke tests and demos.

**What it does (end-to-end):**
1) Seeds a student, professors, and a course **if missing**.  
2) Creates a thesis request in `pending` status.  
3) **Approves** the request with a **backdated** approval date (so the 90-day rule passes).  
4) Generates sample files (PDF + JPEG with valid signatures) and **atomically copies** them to `files/`.  
5) Switches status to `defense`, assigns **internal/external** judges, and sets a defense date.  
6) Submits scores for **supervisor**, **internal**, and **external**.  
7) Finalizes and **archives** the thesis; if the report module is present, it also generates the **PDF minutes**.

---

## How to run
```bash
# from the project root
python scripts/demo_auto_flow.py
```

**Environment variable**
- `OVERWRITE=1` → force reseed/overwrite demo records with the same IDs.  
- `OVERWRITE=0` → keep existing records with the same IDs (no destructive changes).

Examples:
```bash
# Linux/macOS
export OVERWRITE=1
python scripts/demo_auto_flow.py

# Windows PowerShell
$env:OVERWRITE="1"
python scripts/demo_auto_flow.py
```

---

## Dependencies
- Project core modules (`core/*`), already included.
- Optional for minutes PDF: `reportlab`
- Optional RTL shaping: `arabic-reshaper`, `python-bidi`
- Optional signing/JWT helpers: `PyJWT`

---

## Outputs
- Updated JSON data under `data/*.json` (with backups in `data/_bak/`).  
- Sample files in:
  - `files/thesis/` (PDF)
  - `files/images/` (cover / last JPEGs)
- If enabled: minutes PDF at:  
  `files/reports/minutes_<student_code>_<course_id>.pdf`

*(The script also emits notifications and writes audit entries for each transition.)*
