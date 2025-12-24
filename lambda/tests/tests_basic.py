from fastapi.testclient import TestClient

import app


client = TestClient(app.app)


def test_health_endpoint_returns_ok():
    """
    Basic smoke test:
    - App loads
    - /health endpoint exists
    - Returns expected shape
    """
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"ok": True}


def test_apply_redaction_does_not_crash():
    """
    Safety test:
    - Redaction logic runs
    - Returns correct data types
    - No assumptions about regex behaviour
    """
    text = "Test input"
    redact = ["email", "phone"]

    anonymised, counts = app._apply_redaction(text, redact)

    assert isinstance(anonymised, str)
    assert isinstance(counts, dict)