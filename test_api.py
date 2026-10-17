import hashlib
import hmac
import json

from fastapi.testclient import TestClient
import app.main as main

client = TestClient(main.app)


def test_health():
    response = client.get('/health')
    assert response.status_code == 200
    assert response.json() == {'status': 'ok'}


def test_review_requires_gemini_key(monkeypatch):
    monkeypatch.delenv('GEMINI_API_KEY', raising=False)
    response = client.post('/review', json={'filename': 'demo.py', 'code': "print('hello')"})
    assert response.status_code == 503
    assert response.json()['detail'] == 'GEMINI_API_KEY is not configured'


def test_review_uses_structured_result(monkeypatch):
    from app.main import Finding, ReviewResponse
    monkeypatch.setenv('GEMINI_API_KEY', 'test-key')
    expected = ReviewResponse(summary='Potential SQL injection.', findings=[Finding(
        severity='high', category='security', title='Potential SQL injection', line=2,
        explanation='Untrusted input is interpolated into SQL.',
        recommendation='Use parameterized queries.')], static_analysis=[])
    monkeypatch.setattr(main, 'run_bandit', lambda code: [])
    monkeypatch.setattr(main, 'review_with_gemini', lambda filename, code, static: expected)
    response = client.post('/review', json={'filename': 'demo.py', 'code': 'query = input()'})
    assert response.status_code == 200
    assert response.json()['findings'][0]['severity'] == 'high'


def test_github_webhook_rejects_bad_signature(monkeypatch):
    monkeypatch.setenv('GITHUB_WEBHOOK_SECRET', 'test-secret')
    response = client.post('/webhooks/github', content=b'{"zen":"hello"}', headers={
        'X-GitHub-Event': 'ping', 'X-Hub-Signature-256': 'sha256=bad'})
    assert response.status_code == 401


def test_github_webhook_accepts_valid_ping(monkeypatch):
    secret = 'test-secret'
    monkeypatch.setenv('GITHUB_WEBHOOK_SECRET', secret)
    body = b'{"zen":"hello"}'
    signature = 'sha256=' + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    response = client.post('/webhooks/github', content=body, headers={
        'Content-Type': 'application/json', 'X-GitHub-Event': 'ping',
        'X-Hub-Signature-256': signature})
    assert response.status_code == 200
    assert response.json()['status'] == 'ok'
