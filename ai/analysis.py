# ai/analysis.py
from __future__ import annotations

"""
AI helpers for ThesisHub: PDF text extraction, keywording, and summarization.

Public, backward-compatible API:
- extract_text(pdf_path, max_pages=None) -> str
- keywords_tfidf(text, top_k=10) -> List[str]
- summarize(text, max_sent=5) -> str

Optional, richer outputs (non-breaking):
- extract_text_info(..., return_info=True) -> Dict with text, page stats, warnings
- keywords_tfidf(..., return_info=True) -> Dict with keywords, method, warnings
- summarize(..., return_info=True) -> Dict with summary, picked sentences/idxs

Design highlights:
- Graceful degradation if dependencies (pypdf / scikit-learn) are missing.
- Lightweight Unicode normalization, Arabic→Persian letter mapping, Persian digits.
- Improved tokenizer (keeps AI/ML, hyphen/underscore compounds).
- Soft limits for file size/pages and a simple timeout hint via warnings.
- Optional audit logging via core.audit.log if available.
"""

# Explicit public API for star-imports
__all__ = ["extract_text", "keywords_tfidf", "summarize"]

from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Dict, Tuple, Any, Optional, Set
from collections import Counter
import re
import time
import unicodedata
import contextlib

__all__ = [
    "extract_text",
    "extract_text_info",
    "keywords_tfidf",
    "summarize",
]

# ---------------------------- Optional dependencies ----------------------------
try:
    from pypdf import PdfReader  # type: ignore
except Exception:
    try:
        from PyPDF2 import PdfReader  # type: ignore
    except Exception:  # pragma: no cover
        PdfReader = None  # type: ignore

try:
    from sklearn.feature_extraction.text import TfidfVectorizer  # type: ignore
except Exception:  # pragma: no cover
    TfidfVectorizer = None  # type: ignore

# Optional audit logger (no-op fallback)
try:
    from core.audit import log as _audit
except Exception:  # pragma: no cover
    def _audit(event: str, who: str = "", extra: str = "") -> None:
        return

# ---------------------------- Configuration ----------------------------
MAX_PDF_MB = 50             # hard cap for uploaded thesis PDFs
MAX_PAGES_DEFAULT = 300     # default page cap for very large PDFs
EXTRACT_TIMEOUT_SEC = 25    # soft advisory; we only warn if exceeded

# ---------------------------- Stopwords (FA/EN) ----------------------------
_STOP_FA: Set[str] = {
    "و","در","به","از","با","برای","این","آن","که","می","ها","های","را","شد","شود","کرد","کردن",
    "است","هست","نیست","باشد","بود","بودن","تا","یک","اما","یا","هم","بر","بین","روی","درباره",
    "ও","همچنین","بنابراین","زیرا","اگر","البته","مثلاً","مثال","مثلا","طبق","خواهد","شده",
    "می‌شود","می شود","حتی","دیگر","بدون","کنند","کنیم","کنم"
}
_STOP_EN: Set[str] = {
    "a","an","the","of","in","on","to","for","and","or","with","from","by","is","are","were","was",
    "be","been","will","would","should","could","can","may","that","this","these","those","as","at",
    "it","its","into","about","over","after","before","within","among","onto","we","you","they","he",
    "she","i","our","your","their","via","per","than","then","thus","also","such","using","used"
}
_DEFAULT_STOP: Set[str] = _STOP_FA | _STOP_EN

# ---------------------------- Normalization helpers ----------------------------
_PERSIAN_DIGITS = str.maketrans("۰۱۲۳۴۵۶۷۸۹", "0123456789")
_AR2FA = str.maketrans({"ي": "ی", "ك": "ک"})  # Arabic forms → Persian forms

def _norm(s: str) -> str:
    """Normalize Unicode (NFC), map Arabic→Persian letters, map Persian digits, squeeze spaces."""
    s = unicodedata.normalize("NFC", s or "")
    s = s.translate(_AR2FA).translate(_PERSIAN_DIGITS)
    s = s.replace("\u200c", " ")  # ZWNJ → space
    s = re.sub(r"[ \t]+", " ", s)
    s = re.sub(r"\s*\n\s*", "\n", s)
    return s.strip()

# ---------------------------- Sentence & tokenization ----------------------------
_SENT_SPLIT_RE = re.compile(r"([\.!?؟؛:])")
# Accept alnum words (FA/EN) and compounds with hyphen/underscore: deep-learning, foo_bar
_TOKEN_RE = re.compile(r"[A-Za-z\u0600-\u06FF0-9]+(?:[-_][A-Za-z\u0600-\u06FF0-9]+)*")

def _sentences(text: str) -> List[str]:
    """Split into sentences using lightweight punctuation rules (FA/EN)."""
    text = _norm(text)
    parts: List[str] = []
    buf: List[str] = []
    for chunk in _SENT_SPLIT_RE.split(text):
        if not chunk:
            continue
        if _SENT_SPLIT_RE.fullmatch(chunk):
            buf.append(chunk)
            parts.append("".join(buf).strip())
            buf = []
        else:
            buf.append(chunk)
    if buf:
        parts.append("".join(buf).strip())
    # de-duplicate near-duplicates
    out: List[str] = []
    last = ""
    for s in parts:
        if s and s.lower() != last.lower():
            out.append(s)
            last = s
    return out

def _tokens(text: str, *, stop: Optional[Set[str]] = None) -> List[str]:
    """Tokenize FA/EN words, keep 2-letter uppercase acronyms (AI/ML), drop short/stop tokens."""
    stop = stop or _DEFAULT_STOP
    toks: List[str] = []
    for m in _TOKEN_RE.finditer(text):
        t = m.group(0)
        if len(t) == 2 and t.isalpha() and t.isupper():
            toks.append(t.lower())
            continue
        if len(t) < 3:
            continue
        tl = t.lower()
        if tl in stop:
            continue
        toks.append(tl)
    return toks

# ---------------------------- Structured outputs ----------------------------
@dataclass
class ExtractInfo:
    text: str
    pages_total: int
    pages_read: int
    pages_failed: int
    size_mb: float
    took_sec: float
    warnings: List[str]

@dataclass
class SummaryInfo:
    summary: str
    sentences: List[str]
    idxs: List[int]
    took_sec: float
    warnings: List[str]

@dataclass
class KeywordsInfo:
    keywords: List[str]
    method: str
    took_sec: float
    warnings: List[str]

# ---------------------------- PDF extraction ----------------------------
def _pdf_read_all_text(path: Path, max_pages: Optional[int], warnings: List[str]) -> Tuple[str, int, int, int]:
    """Read up to max_pages with PdfReader, collect page stats; append warnings when needed."""
    if PdfReader is None:
        warnings.append("PdfReader is not available (pypdf/PyPDF2 missing).")
        return "", 0, 0, 0
    reader = PdfReader(str(path))
    n_pages = len(reader.pages)
    upto = min(n_pages, max_pages if max_pages is not None else n_pages)
    pages_failed = 0
    parts: List[str] = []
    for i in range(upto):
        try:
            txt = reader.pages[i].extract_text() or ""
            parts.append(txt)
        except Exception:
            # Keep going even if a page fails
            pages_failed += 1
    return _norm("\n".join(parts)), n_pages, upto - pages_failed, pages_failed

def extract_text(pdf_path: str, max_pages: int | None = None) -> str:
    """Backward-compatible convenience: return normalized text only."""
    return extract_text_info(pdf_path, max_pages=max_pages)["text"]

def extract_text_info(pdf_path: str, *, max_pages: int | None = None, return_info: bool = True) -> Dict[str, Any]:
    """
    Rich extraction:
    returns {"text","pages_total","pages_read","pages_failed","size_mb","took_sec","warnings":[...]}
    """
    t0 = time.time()
    p = Path(pdf_path).expanduser().resolve()
    warnings: List[str] = []
    if not p.exists():
        raise FileNotFoundError(f"PDF not found: {p}")

    size_mb = p.stat().st_size / (1024 * 1024)
    if size_mb > MAX_PDF_MB:
        warnings.append(f"PDF size {size_mb:.1f}MB exceeds allowed {MAX_PDF_MB}MB.")

    if max_pages is None:
        max_pages = MAX_PAGES_DEFAULT

    text = ""
    pages_total = pages_read = pages_failed = 0
    # We keep a simple ExitStack here in case of future timeouts/guards
    with contextlib.ExitStack():
        text, pages_total, pages_read, pages_failed = _pdf_read_all_text(p, max_pages, warnings)

    took = time.time() - t0
    if took > EXTRACT_TIMEOUT_SEC:
        warnings.append(f"Extraction took {took:.1f}s. Consider lowering max_pages.")

    info = ExtractInfo(
        text=text,
        pages_total=pages_total,
        pages_read=pages_read,
        pages_failed=pages_failed,
        size_mb=size_mb,
        took_sec=took,
        warnings=warnings,
    )
    _audit("ai_extract", "system", f"{p.name} read={pages_read}/{pages_total} warn={len(warnings)}")
    return asdict(info) if return_info else info  # type: ignore[return-value]

# ---------------------------- Keywords ----------------------------
def keywords_tfidf(
    text: str,
    top_k: int = 10,
    *,
    stopwords: Optional[Set[str]] = None,
    return_info: bool = False,
) -> List[str] | Dict[str, Any]:
    """
    Extract top keywords (uni/bi-grams).
    - If scikit-learn is available: TF-IDF over one document (behaves like TF with IDF=1).
    - Else: frequency-based fallback.
    When return_info=True, returns a dict with method and warnings.
    """
    t0 = time.time()
    warnings: List[str] = []
    stop = stopwords or _DEFAULT_STOP

    text = _norm(text)
    if not text:
        out: List[str] = []
        info = KeywordsInfo(out, method="empty", took_sec=0.0, warnings=["empty text"])
        return asdict(info) if return_info else out

    if TfidfVectorizer is not None:
        try:
            vec = TfidfVectorizer(
                analyzer="word",
                token_pattern=_TOKEN_RE.pattern,
                ngram_range=(1, 2),
                lowercase=True,
                max_features=5000,
                min_df=1,
                sublinear_tf=True,
                norm="l2",
            )
            X = vec.fit_transform([text])
            vocab = vec.get_feature_names_out()
            scores = X.toarray()[0]
            pairs = [(term, score) for term, score in zip(vocab, scores)]
            # drop items made entirely of stopwords
            pairs = [(k, v) for (k, v) in pairs if any(w.lower() not in stop for w in k.split())]
            pairs.sort(key=lambda x: x[1], reverse=True)

            selected: List[str] = []
            for term, _ in pairs:
                words = term.split()
                # skip bigrams fully contained by already-selected unigrams
                if len(words) == 2 and all(w in selected for w in words):
                    continue
                if term not in selected:
                    selected.append(term)
                if len(selected) >= top_k:
                    break

            took = time.time() - t0
            info = KeywordsInfo(selected, method="tfidf", took_sec=took, warnings=warnings)
            return asdict(info) if return_info else selected
        except Exception as e:
            warnings.append(f"tfidf failed: {e!s}")

    # Frequency fallback
    toks = _tokens(text, stop=stop)
    cnt = Counter(toks)
    selected = [w for w, _ in cnt.most_common(max(1, int(top_k)))]
    took = time.time() - t0
    info = KeywordsInfo(selected, method="freq", took_sec=took, warnings=warnings)
    return asdict(info) if return_info else selected

# ---------------------------- Summarization ----------------------------
def summarize(
    text: str,
    max_sent: int = 5,
    *,
    stopwords: Optional[Set[str]] = None,
    return_info: bool = False,
) -> str | Dict[str, Any]:
    """
    Very lightweight extractive summarization:
    - Score(sentence) = sum(token_freq) / len(tokens)^0.8
    - Keep chronological order among top-k scored sentences.
    When return_info=True, include picked sentence indices and warnings.
    """
    t0 = time.time()
    warnings: List[str] = []
    stop = stopwords or _DEFAULT_STOP

    text = _norm(text)
    if not text:
        info = SummaryInfo("", [], [], 0.0, ["empty text"])
        return asdict(info) if return_info else ""

    sents = _sentences(text)
    if not sents:
        info = SummaryInfo("", [], [], 0.0, ["no sentences"])
        return asdict(info) if return_info else ""

    if len(sents) <= max_sent:
        summ = " ".join(sents)
        info = SummaryInfo(summ, sents, list(range(len(sents))), time.time() - t0, warnings)
        return asdict(info) if return_info else summ

    # Global frequency over the document
    freq: Dict[str, int] = Counter(_tokens(text, stop=stop))
    if not freq:
        # Lead summary fallback
        pick_idxs = list(range(min(max_sent, len(sents))))
        summ = " ".join(sents[i] for i in pick_idxs)
        info = SummaryInfo(summ, [sents[i] for i in pick_idxs], pick_idxs, time.time() - t0, ["fallback lead"])
        return asdict(info) if return_info else summ

    scored: List[Tuple[float, int]] = []
    for idx, s in enumerate(sents):
        toks = _tokens(s, stop=stop)
        if not toks:
            continue
        score = sum(freq.get(t, 0) for t in toks) / (len(toks) ** 0.8)
        # small redundancy penalty: reward unique tokens within the sentence
        uniq_ratio = len(set(toks)) / max(1, len(toks))
        score *= (0.8 + 0.2 * uniq_ratio)
        scored.append((score, idx))

    scored.sort(key=lambda x: x[0], reverse=True)
    pick_idxs = sorted([i for _, i in scored[:max_sent]])
    sentences = [sents[i] for i in pick_idxs]
    summ = " ".join(sentences)

    info = SummaryInfo(summ, sentences, pick_idxs, time.time() - t0, warnings)
    return asdict(info) if return_info else summ
