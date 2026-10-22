
import hashlib
import hmac
import json

from fastapi.testclient import TestClient

import main

client = TestClient(main.app)


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


def test_webhook_rejects_invalid_signature(monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "test-secret")

    response = client.post(
        "/webhooks/github",
        content=b'{"zen":"hello"}',
        headers={
            "X-GitHub-Event": "ping",
            "X-Hub-Signature-256": "sha256=invalid",
        },
    )

    assert response.status_code == 401


def test_webhook_accepts_valid_ping(monkeypatch):
    secret = "test-secret"
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", secret)

    body = b'{"zen":"hello"}'
    signature = "sha256=" + hmac.new(
        secret.encode("utf-8"),
        body,
        hashlib.sha256,
    ).hexdigest()

    response = client.post(
        "/webhooks/github",
        content=body,
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
