# Dependency Vulnerability Timeline

Dependency Vulnerability Timeline is a full-stack tool that analyzes a `requirements.txt` or `package.json`, then explains risk in time context and recommends a safer dependency set. Unlike Snyk-style flat CVE listings, this project combines an interactive timeline view with conflict-aware version resolution so you can see **when** risk appeared and **what exact versions** to move to.

## Live Demo
[link — fill this after deploy]

## What It Does
- Renders an interactive D3 timeline of CVE disclosure and patch events per package.
- Detects dependency version conflicts and Python compatibility conflicts.
- Produces a best-effort global resolution with recommended package versions and Python version.

## Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| Frontend | React + Vite | Main UI, file upload, results display |
| Visualisation | D3.js | Horizontal timeline SVG rendering |
| Backend | FastAPI (Python) | Orchestrates all API calls and resolver logic |
| Dep parsing | pip-requirements-parser | Parse requirements.txt cleanly |
| Version logic | packaging (Python) | SpecifierSet, Version comparison |
| Vulnerability data | OSV API (Google) | Free, no key, authoritative CVE source |
| Severity data | NVD API (NIST) | CVSS scores and descriptions |
| Package metadata | PyPI JSON API | python_requires, dependency constraints |
| Package metadata | npm Registry API | engines.node, peer deps, dep constraints |
| HTTP client | httpx + asyncio | Async concurrent API calls |
| Deployment | Render / Railway | Simple free-tier hosting for demo |

## Running Locally
1. Clone the repository:
   - `git clone <your-repo-url>`
   - `cd vulnerablity_timeline`
2. Backend setup:
   - `python3 -m venv .venv`
   - `source .venv/bin/activate`
   - `pip install --upgrade pip`
   - `pip install -r backend/requirements.txt`
   - `cp frontend/.env.example frontend/.env`
   - Set `VITE_API_BASE_URL=http://127.0.0.1:8000` in `frontend/.env`
   - Start API from repo root: `python -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000`
   - Alternate start from `backend/`: `uvicorn main:app --reload --host 127.0.0.1 --port 8000`
3. Frontend setup (new terminal):
   - `cd frontend && npm install && npm run dev`

## How the Resolver Works
The resolver starts from what you currently have installed and treats that as the initial working set. It then identifies packages connected to known vulnerabilities or conflicts and gathers candidate versions from package registries. Instead of applying random upgrades, it filters candidates through compatibility checks first.

For each package, candidate versions are screened against Python constraints and cross-package dependency constraints. If a clean (CVE-free) version exists, the resolver chooses the highest compatible one. If no clean version exists, it picks the lowest-risk compatible option so the system still returns actionable guidance instead of failing hard.

After each pass, conflict detection runs again. If changes introduce new conflicts, another iteration runs until the graph stabilizes (fixpoint) or the configured iteration cap is reached. This makes the output practical for real dependency sets while keeping behavior deterministic and explainable in interviews.

## Known Limitations
- **Transitive dependencies are NOT resolved** — only direct deps in the uploaded file are analysed. Full transitive resolution would require pip's dependency resolver internals.
- **npm peer dependency conflicts are detected but resolution is best-effort** — npm's peer dep logic is significantly more complex than PyPI's.
- **OSV does not always have `patched_at` dates** — when missing, this field is left as `None`.
- **NVD CVSS scores are for the CVE globally, not version-specific** — a package might have a patched version that still shows a high CVSS score.
- **The frontend does not support files larger than 500KB** — this is a UI limit, the backend handles any size.
- **Private registries (Artifactory, Nexus) are not supported** — only public PyPI and npm.
# pkg-audit-workbench
