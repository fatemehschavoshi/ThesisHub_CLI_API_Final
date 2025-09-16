# core/files.py
from __future__ import annotations
from pathlib import Path
from typing import Dict, Optional, Tuple, List
import hashlib
import shutil
import os
import re
import time
import uuid
import unicodedata

# === Directories ===
FILES_DIR = Path(__file__).resolve().parent.parent / "files"
THESIS_DIR = FILES_DIR / "thesis"
IMAGES_DIR = FILES_DIR / "images"
THESIS_DIR.mkdir(parents=True, exist_ok=True)
IMAGES_DIR.mkdir(parents=True, exist_ok=True)

# === Policies ===
ALLOWED_PDF_EXT = {".pdf"}
ALLOWED_IMG_EXT = {".jpg", ".jpeg"}
PDF_MAX_BYTES = 50 * 1024 * 1024      # 50 MB
IMG_MAX_BYTES = 10 * 1024 * 1024      # 10 MB
MAX_BASENAME_LEN = 120                # guard against overly long filenames

# === Filename sanitation ===
# Allow: Persian letters + ASCII letters/digits + dot/dash/underscore
_SAFE_CHARS = re.compile(r"[^A-Za-z0-9\u0600-\u06FF._-]+")

def _secure_filename(name: str) -> str:
    """
    Safe, Persian-friendly filename:
    - Normalize to NFC and map Arabic variants to Persian (ي->ی, ك->ک)
    - Replace spaces with underscore
    - Keep only safe characters (fa letters + ASCII + . _ -)
    - Strip leading dots and enforce max length
    """
    if not name:
        return f"file_{int(time.time())}"
    # Unicode normalization + Arabic->Persian mapping
    name = unicodedata.normalize("NFC", name)
    name = name.replace("ي", "ی").replace("ك", "ک")
    name = name.strip().replace(" ", "_")
    name = _SAFE_CHARS.sub("_", name)
    name = name.lstrip(".")
    if not name:
        name = f"file_{int(time.time())}"
    # Enforce max base length (keep extension if any)
    if "." in name:
        base, ext = name.rsplit(".", 1)
        base = base[:MAX_BASENAME_LEN]
        name = f"{base}.{ext}"
    else:
        name = name[:MAX_BASENAME_LEN]
    return name

# === Hash / signature ===
def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def _pdf_has_eof(path: Path) -> bool:
    """
    Light check for '%%EOF' near the end of file to reduce false positives.
    """
    try:
        size = path.stat().st_size
        if size < 8:
            return False
        to_read = min(4096, size)
        with path.open("rb") as f:
            f.seek(-to_read, os.SEEK_END)
            tail = f.read(to_read)
        return b"%%EOF" in tail
    except Exception:
        return False

def _guess_mime_and_sig_ok(path: Path) -> Tuple[str, bool]:
    """
    Signature check:
    - PDF: starts with %PDF and contains %%EOF near the end
    - JPEG: starts with 0xFFD8
    """
    try:
        with path.open("rb") as f:
            header = f.read(5)
    except Exception:
        return "application/octet-stream", False

    ext = path.suffix.lower()
    if ext == ".pdf":
        good = header.startswith(b"%PDF") and _pdf_has_eof(path)
        return "application/pdf", good
    if ext in {".jpg", ".jpeg"}:
        return "image/jpeg", header[:2] == b"\xFF\xD8"
    return "application/octet-stream", False

def _size_ok(path: Path, max_bytes: int) -> bool:
    try:
        return path.stat().st_size <= max_bytes and path.stat().st_size > 0
    except Exception:
        return False

# === Path safety ===
def _ensure_within(base: Path, child: Path) -> None:
    """
    Ensure final target path resides under base directory (avoid path traversal).
    """
    try:
        base_r = base.resolve(strict=True)
        # Parent may not exist yet; resolve parent then join
        child_p = (child.parent.resolve(strict=True) / child.name).resolve()
    except FileNotFoundError:
        # Create parent then re-check
        child.parent.mkdir(parents=True, exist_ok=True)
        base_r = base.resolve(strict=True)
        child_p = (child.parent.resolve(strict=True) / child.name).resolve()
    if str(child_p).startswith(str(base_r)):
        return
    raise ValueError("Unsafe path detected")

# === Atomic write helpers ===
def _fsync_dir(path: Path) -> None:
    """
    fsync directory to persist the directory entry on POSIX.
    """
    try:
        fd = os.open(str(path), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except Exception:
        # best-effort
        pass

def _atomic_copy(src: Path, dst: Path) -> None:
    """
    Copy file atomically:
    - copy to tmp in same directory
    - fsync file
    - os.replace(tmp, dst)
    - fsync destination directory
    """
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_name(f".{dst.name}.tmp.{uuid.uuid4().hex}")
    with src.open("rb") as fin, open(tmp, "wb") as fout:
        shutil.copyfileobj(fin, fout, length=1024 * 1024)
        fout.flush()
        os.fsync(fout.fileno())
    os.replace(tmp, dst)
    _fsync_dir(dst.parent)

def _atomic_write_text(path: Path, text: str) -> None:
    """
    Atomic text write with fsync + directory fsync for sidecar files.
    """
    tmp = path.with_name(f".{path.name}.tmp.{uuid.uuid4().hex}")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    _fsync_dir(path.parent)

# === Versioning and dedup ===
def _versioned(dest: Path) -> Path:
    if not dest.exists():
        return dest
    stem, suf = dest.stem, dest.suffix
    i = 2
    while True:
        new = dest.with_name(f"{stem}_v{i}{suf}")
        if not new.exists():
            return new
        i += 1

def _find_duplicate_by_hash(target_dir: Path, sha256_hex: str, suffix: str) -> Optional[Path]:
    """
    Best-effort dedup: scan sibling files and compare stored hash if sidecar exists.
    Sidecar name: <filename>.sha256 (content = hex digest)
    """
    if not target_dir.exists():
        return None
    for p in target_dir.glob(f"*{suffix}"):
        side = p.with_suffix(p.suffix + ".sha256")
        try:
            if side.exists() and side.read_text(encoding="utf-8").strip() == sha256_hex:
                return p
        except Exception:
            continue
    return None

def _write_sidecar_hash(path: Path, sha256_hex: str) -> None:
    try:
        _atomic_write_text(path.with_suffix(path.suffix + ".sha256"), sha256_hex)
    except Exception:
        # best-effort
        pass

# === Public API ===
def validate_and_copy(
    pdf: str,
    cover: str,
    last: str,
    out_prefix: str,
    *,
    deduplicate: bool = True,
    pdf_max_bytes: int = PDF_MAX_BYTES,
    img_max_bytes: int = IMG_MAX_BYTES,
) -> Dict[str, object]:
    """
    Validate and copy thesis files safely.
    Returns dict with file paths, hashes and metadata.

    Parameters
    ----------
    pdf : str
        Path to thesis PDF
    cover : str
        Path to first page image (jpg/jpeg)
    last : str
        Path to last page image (jpg/jpeg)
    out_prefix : str
        Base filename (should include identifiers like `<student>_<course>`)
    deduplicate : bool
        If True, reuse existing identical file via SHA256 sidecar; else version.
    """
    pdf_p = Path(pdf).expanduser().resolve()
    cov_p = Path(cover).expanduser().resolve()
    last_p = Path(last).expanduser().resolve()

    # existence
    if not pdf_p.exists() or not cov_p.exists() or not last_p.exists():
        raise FileNotFoundError("One or more input files do not exist")

    # extension policy
    if pdf_p.suffix.lower() not in ALLOWED_PDF_EXT:
        raise ValueError("PDF must have .pdf extension")
    if cov_p.suffix.lower() not in ALLOWED_IMG_EXT or last_p.suffix.lower() not in ALLOWED_IMG_EXT:
        raise ValueError("Images must be .jpg or .jpeg")

    # size policy
    if not _size_ok(pdf_p, pdf_max_bytes):
        raise ValueError(f"PDF exceeds size limit ({pdf_max_bytes} bytes) or is empty")
    if not _size_ok(cov_p, img_max_bytes):
        raise ValueError(f"Cover image exceeds size limit ({img_max_bytes} bytes) or is empty")
    if not _size_ok(last_p, img_max_bytes):
        raise ValueError(f"Last image exceeds size limit ({img_max_bytes} bytes) or is empty")

    # signatures
    pdf_mime, pdf_sig = _guess_mime_and_sig_ok(pdf_p)
    cov_mime, cov_sig = _guess_mime_and_sig_ok(cov_p)
    last_mime, last_sig = _guess_mime_and_sig_ok(last_p)
    if not pdf_sig:
        raise ValueError("Invalid PDF signature (header/EOF)")
    if not cov_sig or not last_sig:
        raise ValueError("Invalid JPEG signature for cover/last")

    # sanitize out_prefix
    out_prefix = _secure_filename(out_prefix) or "thesis"

    # destination candidates
    pdf_dst = (THESIS_DIR / f"{out_prefix}.pdf")
    cov_dst = (IMAGES_DIR / f"{out_prefix}_cover{cov_p.suffix.lower()}")
    last_dst = (IMAGES_DIR / f"{out_prefix}_last{last_p.suffix.lower()}")

    # ensure safety
    _ensure_within(THESIS_DIR, pdf_dst)
    _ensure_within(IMAGES_DIR, cov_dst)
    _ensure_within(IMAGES_DIR, last_dst)

    # compute hashes (source)
    pdf_hash = _sha256(pdf_p)
    cov_hash = _sha256(cov_p)
    last_hash = _sha256(last_p)

    # deduplicate-or-version (names)
    if deduplicate:
        dup_pdf = _find_duplicate_by_hash(THESIS_DIR, pdf_hash, ".pdf")
        dup_cov = _find_duplicate_by_hash(IMAGES_DIR, cov_hash, cov_p.suffix.lower())
        dup_last = _find_duplicate_by_hash(IMAGES_DIR, last_hash, last_p.suffix.lower())
        if dup_pdf is not None:
            pdf_dst = dup_pdf
        elif pdf_dst.exists():
            pdf_dst = _versioned(pdf_dst)
        if dup_cov is not None:
            cov_dst = dup_cov
        elif cov_dst.exists():
            cov_dst = _versioned(cov_dst)
        if dup_last is not None:
            last_dst = dup_last
        elif last_dst.exists():
            last_dst = _versioned(last_dst)
    else:
        if pdf_dst.exists():  pdf_dst  = _versioned(pdf_dst)
        if cov_dst.exists():  cov_dst  = _versioned(cov_dst)
        if last_dst.exists(): last_dst = _versioned(last_dst)

    # copy with rollback on partial failures
    created: List[Path] = []
    try:
        if not pdf_dst.exists():
            _atomic_copy(pdf_p, pdf_dst)
            _write_sidecar_hash(pdf_dst, pdf_hash)
            created.append(pdf_dst)
        if not cov_dst.exists():
            _atomic_copy(cov_p, cov_dst)
            _write_sidecar_hash(cov_dst, cov_hash)
            created.append(cov_dst)
        if not last_dst.exists():
            _atomic_copy(last_p, last_dst)
            _write_sidecar_hash(last_dst, last_hash)
            created.append(last_dst)
    except Exception:
        # best-effort rollback of files created in this call
        for p in reversed(created):
            try:
                p.unlink(missing_ok=True)
                side = p.with_suffix(p.suffix + ".sha256")
                side.unlink(missing_ok=True)
            except Exception:
                pass
        raise

    return {
        "pdf": str(pdf_dst),
        "cover": str(cov_dst),
        "last": str(last_dst),
        "hashes": {
            "pdf": pdf_hash,
            "cover": cov_hash,
            "last": last_hash,
        },
        "meta": {
            "pdf": {"mime": pdf_mime, "size": pdf_dst.stat().st_size, "signature_ok": True},
            "cover": {"mime": cov_mime, "size": cov_dst.stat().st_size, "signature_ok": True},
            "last": {"mime": last_mime, "size": last_dst.stat().st_size, "signature_ok": True},
        }
    }

# ---- (Optional) Utility for attaching detailed results to thesis dict ----
def add_defense_result(thesis: dict, judges_scores: dict, final_score: float) -> dict:
    thesis["judges_scores"] = judges_scores
    thesis["score"] = final_score
    return thesis
