import os
import json
import re
import time
import uuid
import hashlib
import logging
from typing import Any, Dict, List, Optional

import boto3
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from mangum import Mangum

# -------------------------
# Logging (PII-safe)
# -------------------------
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def safe_log_value(value: str, *, max_len: int = 120) -> str:
    """
    Guardrail: never allow long free-text (e.g. CV content) into logs.
    Also redacts obvious email/phone patterns even for short strings.
    """
    if value is None:
        return ""
    value = str(value)

    if len(value) > max_len:
        return "[REDACTED_FREE_TEXT]"

    value = re.sub(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "[REDACTED_EMAIL]",
        value,
    )
    value = re.sub(r"\b(\+?\d[\d\s().-]{7,}\d)\b", "[REDACTED_PHONE]", value)
    return value


# ✅ 1) Create the app FIRST
app = FastAPI(title="CV Anonymiser")

# ✅ 2) Then add middleware
frontend_origin = os.getenv("FRONTEND_ORIGIN", "*")
allow_origins = ["*"] if frontend_origin == "*" else [frontend_origin]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

ssm = boto3.client("ssm")
dynamodb = boto3.resource("dynamodb")

RULES_PARAM_NAME = os.getenv("RULES_PARAM_NAME", "/cv-anonymiser/redaction-rules")
AUDIT_TABLE_NAME = os.getenv("AUDIT_TABLE_NAME", "")
SALT_FALLBACK = os.getenv("SALT_FALLBACK", "demo-salt-change-me")  # used only if param missing

_rules_cache: Optional[Dict[str, Any]] = None
_rules_cache_loaded_at: float = 0.0
RULES_CACHE_SECONDS = 60


class AnonymiseRequest(BaseModel):
    text: str


def _load_rules() -> Dict[str, Any]:
    global _rules_cache, _rules_cache_loaded_at

    now = time.time()
    if _rules_cache and (now - _rules_cache_loaded_at) < RULES_CACHE_SECONDS:
        return _rules_cache

    try:
        resp = ssm.get_parameter(Name=RULES_PARAM_NAME, WithDecryption=True)
        val = resp["Parameter"]["Value"]
        rules = json.loads(val)
        if not isinstance(rules, dict):
            raise ValueError("Rules param JSON must be an object")
    except Exception:
        # For MVP: fall back safely (still no raw CV stored)
        rules = {"redact": ["email", "phone"], "salt": SALT_FALLBACK}

    _rules_cache = rules
    _rules_cache_loaded_at = now
    return rules


def _redact_email(text: str) -> str:
    return re.sub(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "[REDACTED_EMAIL]",
        text,
    )


def _redact_phone(text: str) -> str:
    return re.sub(r"\b(\+?\d[\d\s().-]{7,}\d)\b", "[REDACTED_PHONE]", text)


def _apply_redaction(text: str, redact: List[str]) -> tuple[str, Dict[str, int]]:
    counts: Dict[str, int] = {}
    out = text

    if "email" in redact:
        before = out
        out = _redact_email(out)
        counts["email"] = 0 if before == out else 1  # MVP signal

    if "phone" in redact:
        before = out
        out = _redact_phone(out)
        counts["phone"] = 0 if before == out else 1

    return out, counts


def _salted_hash(text: str, salt: str) -> str:
    h = hashlib.sha256()
    h.update((salt + text).encode("utf-8"))
    return h.hexdigest()


def _write_audit(request_id: str, cv_hash: str, rule_counts: Dict[str, int]) -> bool:
    """
    Writes a minimal audit row (no PII). Returns True if written, else False.
    """
    if not AUDIT_TABLE_NAME:
        return False  # allow running without audit table during early MVP

    table = dynamodb.Table(AUDIT_TABLE_NAME)

    now = int(time.time())
    ttl = now + (7 * 24 * 60 * 60)  # 7 days

    item = {
        "requestId": request_id,
        "ts": now,
        "ttl": ttl,
        "cvHash": cv_hash,          # no raw CV stored
        "ruleCounts": rule_counts,  # no raw CV stored
    }

    table.put_item(Item=item)
    return True


@app.get("/health")
def health() -> Dict[str, Any]:
    # Safe log (no PII)
    logger.info("health_check")
    return {"ok": True}


@app.post("/anonymise")
def anonymise(req: AnonymiseRequest) -> Dict[str, Any]:
    start = time.time()

    # IMPORTANT: never log req.text (PII risk)
    text = (req.text or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail="text is required")

    rules = _load_rules()
    redact = rules.get("redact", ["email", "phone"])
    salt = rules.get("salt", SALT_FALLBACK)

    anonymised, counts = _apply_redaction(text, redact)
    request_id = str(uuid.uuid4())

    # Only store salted hash + counts (no raw CV stored)
    cv_hash = _salted_hash(text, salt)
    audit_written = _write_audit(request_id, cv_hash, counts)

    duration_ms = int((time.time() - start) * 1000)

    # PII-safe structured log: no text, no anonymised CV, no emails/phones.
    logger.info(
        "anonymise_complete",
        extra={
            "requestId": request_id,
            "rulesApplied": redact,
            "ruleCounts": counts,
            "durationMs": duration_ms,
            "auditWritten": audit_written,
            "origin": safe_log_value(frontend_origin),  # short + redacted
        },
    )

    return {
        "requestId": request_id,
        "anonymisedText": anonymised,
        "rulesApplied": redact,
    }


# Lambda entrypoint for API Gateway proxy
handler = Mangum(app)