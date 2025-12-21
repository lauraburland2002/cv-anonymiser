import json
import os
import time
import uuid
import hashlib

import boto3
from fastapi import FastAPI
from mangum import Mangum

app = FastAPI()
ssm = boto3.client("ssm")
dynamodb = boto3.resource("dynamodb")

RULES_PARAM_NAME = os.environ["RULES_PARAM_NAME"]
AUDIT_TABLE_NAME = os.environ["AUDIT_TABLE_NAME"]

table = dynamodb.Table(AUDIT_TABLE_NAME)


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/anonymise")
def anonymise(payload: dict):
    text = (payload or {}).get("text", "")
    if not isinstance(text, str) or not text.strip():
        return {"error": "Missing 'text' field"}, 400

    # Fetch rules from SSM (SecureString)
    rules_resp = ssm.get_parameter(Name=RULES_PARAM_NAME, WithDecryption=True)
    rules = json.loads(rules_resp["Parameter"]["Value"])
    salt = rules.get("salt", "demo-salt")

    # Demo redaction (replace with your real logic)
    redacted = text.replace("@", "[at]")

    # Audit: NO raw CV stored (store salted hash + metadata)
    request_id = str(uuid.uuid4())
    salted_hash = hashlib.sha256((salt + text).encode("utf-8")).hexdigest()

    now = int(time.time())
    ttl = now + (7 * 24 * 60 * 60)  # 7 days

    table.put_item(
        Item={
            "requestId": request_id,
            "createdAt": now,
            "ttl": ttl,
            "cvHash": salted_hash,
            "rulesApplied": rules.get("redact", []),
        }
    )

    return {
        "requestId": request_id,
        "anonymisedText": redacted,
    }


handler = Mangum(app)