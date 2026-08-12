# Fresh-clone validation record

Validation was performed against the onboarding checklist on 2026-08-12 after the dependency and demo-data review. The goal was to verify that a reviewer can clone RedPath, install only the declared dependencies, run the test and lint chain, build the frontend, and start the Compose stack.

| Stage | Command or check | Result |
| --- | --- | --- |
| Backend dependency fix | `backend/requirements.txt` contains `fpdf2==2.8.8` | Passed; report imports are covered by the declared manifest |
| Framework refresh | FastAPI `0.141.1`, Pytest `9.1.1` | Passed; replaces the older pinned versions called out in the onboarding review |
| Vulnerability audit | `pip-audit -r backend/requirements.txt` | Passed: no known vulnerabilities found |
| Clean backend install | New Python virtual environment, `pip install -r backend/requirements.txt` | Passed |
| Backend tests | `PYTHONPATH=backend pytest -q` | Passed: 14 tests |
| Python lint | `ruff check backend/app backend/tests` | Passed |
| Python security scan | `bandit -r backend/app -lll` | Passed: no issues identified |
| Clean frontend install | Temporary directory, `npm ci` | Passed |
| Frontend type check | `npm run lint` | Passed |
| Frontend production build | `npm run build` | Passed; `dist/` contains HTML, JS, CSS, and `assets/redpath-logo.png` |
| Compose build | `docker compose up --build -d` using Compose v2 | Passed; API and console containers built and started |
| API service health | `GET http://127.0.0.1:8000/api/v1/health` | HTTP 200 with `dry_run_default: true` |
| Console service health | `HEAD http://127.0.0.1:5173` | HTTP 200 |

The sandbox initially had only legacy Python `docker-compose` and a kernel without the iptables raw table. That legacy client failed before building because of an `http+docker` compatibility error. Compose v2 was installed for validation, and Docker's sandbox daemon was run with iptables management disabled; the project itself required no Dockerfile or Compose changes for this host-specific limitation. On a normal Docker installation, use the standard `docker compose up --build` command.

The enterprise increment additionally validates chained audit verification, canonical evidence manifests, remediation SLA classification, and deterministic campaign export packages. The governance increment validates evidence review transitions, remediation lifecycle updates, time-bounded risk acceptance, control scorecards, and executive KPI aggregation. These controls are read-only with respect to external lab systems and do not persist credentials or private signing keys.

## Reproduction commands

```bash
cp .env.example .env
python3 -m venv .venv
. .venv/bin/activate
pip install -r backend/requirements.txt
PYTHONPATH=backend pytest -q
ruff check backend/app backend/tests
bandit -r backend/app -lll

cd frontend
npm ci
npm run lint
npm run build
cd ..

docker compose up --build
```
