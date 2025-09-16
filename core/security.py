# core/security.py
from __future__ import annotations
"""
Security utilities for ThesisHub.

- Password policy & validation
- bcrypt hashing with configurable cost and optional PEPPER
- Pre-hash (SHA-256) to avoid bcrypt 72-byte truncation
- Backward-compatible verify (legacy + prehash)
- needs_rehash() to detect when a stored hash should be upgraded
- Constant-time comparison
- Secure random token generator & HMAC signing helpers
- JWT issue/verify (PyJWT) with role-based claims, leeway, optional aud/nbf
- Simple in-memory rate limiter for login endpoints
"""

from dataclasses import dataclass
from typing import Optional, Tuple, Dict, Any, Deque
from collections import deque
import os
import re
import time
import hmac
import base64
import secrets
import hashlib

import bcrypt

# ---- Optional: PyJWT
try:
    import jwt  # pyjwt
    _JWT_AVAILABLE = True
except Exception:
    jwt = None
    _JWT_AVAILABLE = False


# =========================
# Configuration
# =========================
_BCRYPT_COST_DEFAULT = 12
try:
    _cfg_cost = int(os.getenv("THESIS_BCRYPT_COST", str(_BCRYPT_COST_DEFAULT)))
    if _cfg_cost < 10 or _cfg_cost > 16:
        _cfg_cost = _BCRYPT_COST_DEFAULT
except Exception:
    _cfg_cost = _BCRYPT_COST_DEFAULT

# Optional application-wide PEPPER
_PEPPER = os.getenv("THESIS_PEPPER", "")

# JWT configuration
_JWT_SECRET = os.getenv("THESIS_JWT_SECRET", "")
_JWT_ISSUER = os.getenv("THESIS_JWT_ISSUER", "ThesisHub")
_JWT_ALGO = os.getenv("THESIS_JWT_ALGO", "HS256")
_JWT_TTL = int(os.getenv("THESIS_JWT_TTL", "28800"))  # 8h
_JWT_LEEWAY = int(os.getenv("THESIS_JWT_LEEWAY", "0"))  # seconds, default 0
_JWT_AUDIENCE = os.getenv("THESIS_JWT_AUDIENCE", "")  # optional

# HMAC secret (separate from JWT secret)
_HMAC_SECRET = os.getenv("THESIS_HMAC_SECRET", "")

# =========================
# Password policy
# =========================
_COMMON_PASSWORDS = {
    "123456", "123456789", "password", "qwerty", "111111", "123123",
    "000000", "abc123", "iloveyou", "12345678", "pass", "admin",
    "letmein", "monkey", "dragon", "welcome"
}

@dataclass(frozen=True)
class PasswordCheck:
    ok: bool
    message: str = ""
    score: int = 0  # 0-4


def check_password_strength(pw: str, *, username: str = "") -> PasswordCheck:
    """
    Rules:
    - length >= 8
    - at least 3 of 4 classes: lower / upper / digits / symbols
    - not in common list
    - not equal to username
    """
    if not isinstance(pw, str):
        return PasswordCheck(False, "Password must be a string", 0)
    if len(pw) < 8:
        return PasswordCheck(False, "Password must be at least 8 characters", 0)
    if pw.lower() in _COMMON_PASSWORDS:
        return PasswordCheck(False, "Password is too common", 0)
    if username and pw.lower() == username.strip().lower():
        return PasswordCheck(False, "Password must not equal username", 0)

    classes = 0
    classes += bool(re.search(r"[a-z]", pw))
    classes += bool(re.search(r"[A-Z]", pw))
    classes += bool(re.search(r"[0-9]", pw))
    classes += bool(re.search(r"[^A-Za-z0-9]", pw))

    if classes < 3:
        return PasswordCheck(False, "Use a mix of upper/lowercase letters, digits, and symbols", classes)

    return PasswordCheck(True, "OK", classes)


# =========================
# Hashing & verification
# =========================
def _pepperize_bytes(plain: str) -> bytes:
    return (plain + _PEPPER).encode("utf-8")


def _prehash(plain: str) -> bytes:
    """
    Pre-hash (SHA-256) to avoid bcrypt 72-byte truncation.
    Returns 32-byte digest.
    """
    return hashlib.sha256(_pepperize_bytes(plain)).digest()


def hash_password(plain: str) -> str:
    """
    Hash a password using bcrypt (configurable cost) with pre-hash to avoid 72-byte truncation.
    Backward compatibility: existing legacy hashes (bcrypt of (plain+pepper) directly) still verify in verify_password.
    """
    if not isinstance(plain, str):
        raise TypeError("plain must be str")

    # (Optional) enforce policy:
    # pc = check_password_strength(plain)
    # if not pc.ok:
    #     raise ValueError(f"Weak password: {pc.message}")

    salt = bcrypt.gensalt(rounds=_cfg_cost)
    # NEW scheme: bcrypt(SHA256(plain+pepper))
    return bcrypt.hashpw(_prehash(plain), salt).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """
    Constant-time bcrypt verification.
    Tries both NEW scheme (bcrypt(SHA256(plain+pepper))) and LEGACY scheme (bcrypt(plain+pepper)).
    """
    try:
        # Try NEW scheme first
        if bcrypt.checkpw(_prehash(plain), hashed.encode("utf-8")):
            return True
        # Fallback: LEGACY (for previously stored hashes)
        return bcrypt.checkpw(_pepperize_bytes(plain), hashed.encode("utf-8"))
    except Exception:
        return False


def needs_rehash(hashed: str) -> bool:
    """
    True if stored hash uses a lower bcrypt cost than current policy.
    Note: cannot distinguish legacy vs prehash format from bcrypt string; only cost is checked.
    """
    try:
        parts = hashed.split("$")
        cost = int(parts[2])
        return cost < _cfg_cost
    except Exception:
        # Unknown/invalid hash → suggest rehash
        return True


# =========================
# Token & HMAC utilities
# =========================
def constant_time_equals(a: str, b: str) -> bool:
    try:
        return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
    except Exception:
        return False


def random_token(nbytes: int = 32) -> str:
    """
    URL-safe random token string (no padding).
    Suitable for reset/CSRF/session IDs.
    """
    return base64.urlsafe_b64encode(secrets.token_bytes(nbytes)).rstrip(b"=").decode("ascii")


def sign_data(data: str, secret: Optional[str] = None) -> str:
    """
    HMAC-SHA256 signature for opaque tokens.
    Uses THESIS_HMAC_SECRET if provided; falls back to JWT secret; then to a hardcoded fallback.
    """
    key = (secret or _HMAC_SECRET or _JWT_SECRET or "fallback_hmac_secret").encode("utf-8")
    mac = hmac.new(key, data.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).rstrip(b"=").decode("ascii")


def verify_signature(data: str, signature: str, secret: Optional[str] = None) -> bool:
    expected = sign_data(data, secret)
    return constant_time_equals(expected, signature)


# =========================
# JWT
# =========================
def issue_jwt(
    subject: str,
    *,
    role: str,
    extra: Optional[Dict[str, Any]] = None,
    ttl_seconds: Optional[int] = None,
    audience: Optional[str] = None,
    not_before: Optional[int] = None,  # epoch seconds
) -> str:
    """
    Issue a signed JWT with standard claims + custom role.

    Claims:
    - sub, iss, iat, exp, jti, role
    - aud (optional), nbf (optional)
    """
    if not _JWT_AVAILABLE or not _JWT_SECRET:
        raise RuntimeError("JWT is not configured. Set THESIS_JWT_SECRET and install PyJWT.")

    now = int(time.time())
    ttl = int(ttl_seconds or _JWT_TTL)
    payload: Dict[str, Any] = {
        "sub": subject,
        "iss": _JWT_ISSUER,
        "iat": now,
        "exp": now + ttl,
        "jti": random_token(16),
        "role": role,
    }
    aud = audience or (_JWT_AUDIENCE or None)
    if aud:
        payload["aud"] = aud
    if not_before is not None:
        payload["nbf"] = int(not_before)
    if extra:
        payload.update(extra)
    return jwt.encode(payload, _JWT_SECRET, algorithm=_JWT_ALGO)


def verify_jwt(token: str, *, expected_role: Optional[str] = None, audience: Optional[str] = None) -> Dict[str, Any]:
    """
    Verify and decode JWT. Raises jwt exceptions if invalid/expired.
    - Validates iss
    - Validates role if expected_role is provided
    - Supports optional audience and leeway (THESIS_JWT_LEEWAY)
    """
    if not _JWT_AVAILABLE or not _JWT_SECRET:
        raise RuntimeError("JWT is not configured. Set THESIS_JWT_SECRET and install PyJWT.")

    options = {"require": ["exp", "iat", "iss"]}
    aud = audience or (_JWT_AUDIENCE or None)

    payload = jwt.decode(
        token,
        _JWT_SECRET,
        algorithms=[_JWT_ALGO],
        issuer=_JWT_ISSUER,
        audience=aud,
        leeway=_JWT_LEEWAY,
        options=options,
    )
    if payload.get("iss") != _JWT_ISSUER:
        raise jwt.InvalidIssuerError("Invalid issuer")
    if expected_role and payload.get("role") != expected_role:
        raise jwt.InvalidTokenError("Role mismatch")
    return payload


# =========================
# Rate Limiter (anti brute-force)
# =========================
class RateLimiter:
    """
    In-memory sliding window rate limiter (per-process).

    Example:
        limiter = RateLimiter(max_attempts=5, window_seconds=60)
        if not limiter.allow("login:s001"):
            # block / delay
    """
    def __init__(self, max_attempts: int, window_seconds: int):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._buckets: Dict[str, Deque[float]] = {}

    def allow(self, key: str) -> bool:
        now = time.time()
        dq = self._buckets.setdefault(key, deque())
        cutoff = now - self.window_seconds
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= self.max_attempts:
            return False
        dq.append(now)
        return True

    def remaining(self, key: str) -> int:
        now = time.time()
        dq = self._buckets.get(key, deque())
        cutoff = now - self.window_seconds
        count = sum(1 for t in dq if t >= cutoff)
        return max(0, self.max_attempts - count)


# Default limiter for login attempts: 5 attempts / 60 seconds per principal
login_rate_limiter = RateLimiter(max_attempts=5, window_seconds=60)
