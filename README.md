# API Security + Data-Accuracy Test Kit (sample)

**Important:** the target here is `demo_api/app.py`, a tiny FastAPI "shop" with **deliberately seeded flaws**. It is a demo, never a real system. Each flaw switches off with `DEMO_FIXED=1`, so the same tests fail before the fix and pass after it.

## Run it (3 commands)

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt   # Python 3.10+
.venv/bin/python tools/report.py          # runs vulnerable + fixed builds, writes reports/ and runs/
DEMO_FIXED=0 .venv/bin/uvicorn demo_api.app:app --host 127.0.0.1 --port 8000   # live API for the curl repros
```

Example repro against the live server (from the report, finding F1):

```bash
curl -s -H 'Authorization: Bearer bob-token' http://127.0.0.1:8000/orders/1   # bob reads alice's order
```

Four of the report's curl commands (F1, F4, F6, F7) were run against a live server; the output is in `runs/live-curl.txt`.

## What is inside

| Path | What it is |
|---|---|
| `docs/pricing-spec.md` | The "client documentation": access rules, money rules, lockout rule. Tests are written from it. |
| `demo_api/app.py` | Demo API with 7 seeded flaws (BOLA, BFLA, mass assignment, SQL injection, password-hash exposure, double-applied discount, no login lockout). |
| `tests/permission_matrix.py` | Role x endpoint x method -> expected status, as plain data (22 cells). |
| `tests/test_security_findings.py` | One test per risk, tagged with an OWASP API Security Top 10 (2023) id and a severity. |
| `tests/test_functional.py` | Schema, field types, money format, boundary values (negative/zero/huge quantity, page size 0/101/1,000,000). |
| `tests/conftest.py` | Records each real request/response as evidence (pytest only). |
| `tools/report.py` | Runs both builds and writes the English and Chinese reports. |
| `reports/sample-report.en.md`, `reports/sample-report.zh.md` | The deliverable (see below). |
| `runs/vulnerable.txt`, `runs/fixed.txt` | Raw pytest output from both runs. |

Every test has a docstring with what it checks, why it matters, severity and repro steps.

## Measured results (from `runs/summary.json`)

| | Vulnerable build | Fixed build (`DEMO_FIXED=1`) |
|---|---|---|
| Tests run | 49 | 49 |
| Failed | 17 | 0 |
| Distinct findings | 7: 3 Critical, 2 High, 2 Medium, 0 Low | 0 |
| Permission-matrix cells wrong | 5 of 22 | 0 of 22 |
| Suite runtime | under 1 s (0.58 s) | under 1 s (0.56 s) |

Findings: F2 BFLA on `/admin/*` (Critical), F3 mass assignment of `role` (Critical), F4 unauthenticated SQL injection in product search (Critical), F1 BOLA on `/orders/{id}` (High), F6 coupon discount applied twice: a 29.97 cart is charged 24.28 instead of 26.97 (High), F5 password hashes in user objects (Medium), F7 no login lockout (Medium).

## What a client engagement delivers

The same structure, built for **your** API:

1. A permission matrix written from your docs or source (every role x endpoint x method), run as tests.
2. Targeted tests for the OWASP API Security Top 10 (2023) risks that apply to your API, plus data-accuracy tests against your business rules (prices, rounding, totals, units, date ranges).
3. Functional and format checks: response schema, field types, boundary values.
4. A report in English and/or Chinese with a severity table, curl repro and real evidence for each finding, fix suggestions with code, and a re-test table after your fixes.
5. The test suite itself, so you can re-run it in CI.

Testing is done only against environments the client owns and authorizes in writing (staging or local preferred). No testing of third-party systems.

The flaws here are planted, so this shows the method and deliverable, not a real-world hit rate.

---

Built by Nightshift Labs, an AI engineering agent operated by Ivan Mollov.
