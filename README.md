# Automated Code Review & Security Audit Agent (Gemini edition)

FastAPI review API using Google's Gemini API for structured review findings and Bandit for Python static analysis. Includes a GitHub webhook signature-verification starter route, tests, Dockerfile, and GitHub Actions CI.

## 1. Setup on macOS

```bash
cd automated_code_review_security_agent
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env
```

Get a key from https://aistudio.google.com/apikey. Edit `.env` locally and set `GEMINI_API_KEY` and optionally `GEMINI_MODEL`. Never commit or share `.env`. The default model is `gemini-2.5-flash`; use a model currently available to your account if needed.

Load the `.env` variables into the current shell before starting the server. Easiest: `set -a; source .env; set +a` (ensure values are shell-compatible and do not add spaces around `=`), then run:

```bash
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000/docs and test `POST /review` with:

```json
{
  "filename": "unsafe_query.py",
  "code": "def get_user(cursor, username):\n    query = f\"SELECT * FROM users WHERE name = '{username}'\"\n    cursor.execute(query)\n    return cursor.fetchone()"
}
```

A successful response includes `summary`, `findings`, and `static_analysis`. The LLM findings can vary; Bandit primarily checks Python-specific patterns. Submitted code is analyzed, not executed.

## 2. Tests

```bash
pytest -q
```

Tests mock the model call; they do not use API credits.

## 3. GitHub webhook starter

Set a long random `GITHUB_WEBHOOK_SECRET` in `.env`, reload the variables, and expose the local server securely for development with a tunnel such as ngrok. Configure a GitHub webhook to POST to `/webhooks/github`, content type `application/json`, and subscribe to Pull requests. The endpoint validates `X-Hub-Signature-256`. It currently acknowledges verified pull-request events only; fetching PR diffs and posting review comments are not implemented yet.

Do not expose this unauthenticated development server to the public internet without HTTPS, request-size limits, rate limiting, and appropriate GitHub app/token permissions. Never execute submitted repository code.

## 4. Docker

```bash
docker build -t code-review-agent .
docker run --rm -p 8000:8000 --env-file .env code-review-agent
```

## 5. GitHub Actions

The included workflow installs dependencies and runs tests for pushes and pull requests. It does not need an API key because the tests mock Gemini.

## Notes

- Free Gemini API availability, model IDs, and quotas can change. Check https://ai.google.dev/gemini-api/docs/pricing and AI Studio.
- Never commit `.env` or share API keys. Revoke any key accidentally exposed.
- Findings are advisory; require human review before treating them as confirmed vulnerabilities.
