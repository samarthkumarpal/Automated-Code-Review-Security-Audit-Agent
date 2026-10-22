
import hashlib
import hmac
import json
import os

from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def make_signature(secret: str, payload: bytes) -> str:
    digest = hmac.new(
        secret.encode("utf-8"),
        payload,
        hashlib.sha256,
    ).hexdigest()
    return f"sha256={digest}"


def test_health_returns_200():
    response = client.get("/health")

    assert response.status_code == 200


def test_health_returns_expected_service():
    response = client.get("/health")

    assert response.json() == {
        "status": "ok",
        "service": "Automated Code Review & Security Audit Agent",
    }


def test_webhook_rejects_missing_signature(monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "test-secret")

    response = client.post(
        "/webhooks/github",
        json={},
        headers={"X-GitHub-Event": "ping"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid webhook signature"


def test_webhook_rejects_invalid_signature(monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "test-secret")

    response = client.post(
        "/webhooks/github",
        content=json.dumps({}).encode(),
        headers={
            "X-GitHub-Event": "ping",
            "X-Hub-Signature-256": "sha256=invalid",
        },
    )

    assert response.status_code == 401


def test_webhook_accepts_valid_ping_signature(monkeypatch):
    secret = "test-secret"
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", secret)

    payload = json.dumps({"zen": "Testing safely"}).encode()
    signature = make_signature(secret, payload)

    response = client.post(
        "/webhooks/github",
        content=payload,
        headers={
            "Content-Type": "application/json",
            "X-GitHub-Event": "ping",
            "X-Hub-Signature-256": signature,
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "message": "GitHub webhook ping received",
    }
