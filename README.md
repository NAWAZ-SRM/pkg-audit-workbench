# Dependency Vulnerability Timeline

Dependency Vulnerability Timeline is a full-stack security analysis tool that accepts a `requirements.txt` or `package.json`, then returns:

- a **time-based vulnerability view** (when issues were disclosed and patched),
- a **conflict analysis** (dependency and Python compatibility clashes), and
- a **best-effort version resolution plan** for safer upgrades.

Unlike flat CVE list tools, this project focuses on both **timeline context** and **resolution strategy**.

---

## Core Features

- **Interactive D3 timeline** of CVE disclosure and patch events per package.
- **Conflict detection** for:
  - inter-package version constraints,
  - Python compatibility mismatches.
- **Fixpoint-style resolver** that recommends safer package versions and a Python version target.
- **Multi-source enrichment** using OSV, NVD, PyPI, and npm metadata.
- **Sample files and copy helpers** in UI for fast demos.

---

## Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| Frontend | React + Vite | Upload flow, state-driven UI, result panels |
| Visualization | D3.js | Timeline rendering, filters, interaction |
| Backend | FastAPI | Analysis orchestration and API contract |
| Parsing | pip-requirements-parser + JSON parser | Dependency extraction |
| Version logic | packaging | Version/specifier comparison |
| Vulnerability data | OSV API | Primary vulnerability dataset |
| Severity enrichment | NVD API | CVSS score + severity enrichment |
| Registry metadata | PyPI JSON + npm Registry | Constraint + version metadata |
| HTTP | httpx + asyncio | Concurrent upstream calls |
| Deploy | Render (backend) + Vercel (frontend) | Production hosting |

---

## System Architecture (High Level)

1. Parse uploaded dependency file (`requirements.txt` / `package.json`).
2. Fetch vulnerability + metadata in parallel (OSV, PyPI/npm, NVD enrichment).
3. Detect conflicts (version + Python compatibility).
4. Run resolver to compute an improved dependency set.
5. Return structured response for Timeline / Conflicts / Resolution panels.

Backend endpoint surface:

- `POST /analyse`
- `GET /health`

---

## Repository Structure

```text
backend/
  main.py
  api/
  parser/
  resolver/
  models/
  utils/

frontend/
  src/
    components/
    hooks/
    utils/
  public/samples/
```

---

## Quick Start (Local)

### Prerequisites

- Python 3.11+
- Node.js 18+
- npm

### 1) Clone

```bash
git clone <your-repo-url>
cd vulnerablity_timeline
```

### 2) Start backend

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r backend/requirements.txt

# Recommended (run from repo root)
python -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

Alternative (if you run command from `backend/`):

```bash
cd backend
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

### 3) Start frontend (new terminal)

```bash
cd frontend
npm install
cp .env.example .env
```

Set this in `frontend/.env`:

```env
VITE_API_BASE_URL=http://127.0.0.1:8000
```

Then run:

```bash
npm run dev
```

Open: `http://localhost:5173`

---

## API Contract (Current)

### `POST /analyse`

Accepts multipart form data:

- field name: `file`
- supported filenames: `requirements.txt`, `.txt`, `.json`

Returns structured analysis JSON containing:

- ecosystem
- package vulnerability reports
- conflicts
- resolution plan
- analysed timestamp

### `GET /health`

Returns:

```json
{ "status": "ok" }
```

---

## Environment Variables

### Backend

| Variable | Purpose | Default |
|---|---|---|
| `NVD_API_KEY` | NVD CVSS enrichment key | unset |
| `OSV_BATCH_SIZE` | OSV batch size | `100` |
| `PYPI_CONCURRENCY_LIMIT` | PyPI request concurrency cap | `20` |
| `NVD_RATE_LIMIT` | NVD requests/sec throttle | `5` |
| `RESOLVER_MAX_ITERATIONS` | Fixpoint iteration cap | `10` |
| `ALLOWED_ORIGINS` | CORS allow list (comma-separated) | `*` |

### Frontend

| Variable | Purpose |
|---|---|
| `VITE_API_BASE_URL` | Backend base URL (e.g., `http://127.0.0.1:8000`) |

---

## Deployment

- Backend deployment config: `render.yaml`
- Frontend deployment config: `frontend/vercel.json`

Typical setup:

- Deploy backend on Render.
- Set frontend `VITE_API_BASE_URL` to deployed backend URL.
- Deploy frontend on Vercel.

---

## Troubleshooting

### “Analysis failed” with generic request error

Check first:

1. Backend is reachable: `curl http://127.0.0.1:8000/health`
2. `frontend/.env` has a valid URL format (must include `http://` or `https://`)
3. Frontend dev server restarted after env changes

### Common local mistake

Incorrect:

```env
VITE_API_BASE_URL=http:127.0.0.1:8000
```

Correct:

```env
VITE_API_BASE_URL=http://127.0.0.1:8000
```

---

## Known Limitations (V1)

- Transitive dependency resolution is out of scope (direct deps only).
- npm peer dependency resolution is best-effort.
- Some OSV records may not provide `patched_at`.
- NVD severity is CVE-level, not package-version-specific.
- Frontend upload UI limits files to 500KB.
- Private registries (Artifactory/Nexus) are not integrated.

---

## Project Context

This implementation follows the PRD in:

- `vulnerability_timeline.prd.md`

Use that document as the source of truth for architecture, contracts, edge cases, and scope.
