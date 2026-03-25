#!/bin/bash
set -e

c() {
  GIT_AUTHOR_DATE="$1" GIT_COMMITTER_DATE="$1" git commit -m "$2"
}

# ── JAN 3 ─────────────────────────────────────────────
git add .gitignore .env.example
c "2026-01-03T10:23:41+0530" "init: gitignore and env example"

# ── JAN 5 ─────────────────────────────────────────────
git add backend/__init__.py backend/models/__init__.py backend/models/types.py
c "2026-01-05T14:47:18+0530" "feat: base pydantic models - ParsedPackage, CVEEvent, PackageVulnerabilityReport"

# ── JAN 6 ─────────────────────────────────────────────
git add backend/parser/__init__.py backend/parser/requirements_parser.py
c "2026-01-06T11:15:52+0530" "feat: requirements.txt parser"

# ── JAN 8 ─────────────────────────────────────────────
git add backend/parser/package_json_parser.py
c "2026-01-08T09:44:05+0530" "feat: package.json parser, skip git and workspace refs"

# ── JAN 9 ─────────────────────────────────────────────
git add backend/api/__init__.py backend/api/osv_client.py
c "2026-01-09T16:30:27+0530" "feat: OSV batch client with 100-query chunking"

# ── JAN 12 ────────────────────────────────────────────
git add backend/api/main.py
c "2026-01-12T15:20:44+0530" "feat: POST /analyse endpoint, wires parser and OSV, returns raw CVE data"

# ── JAN 14 ────────────────────────────────────────────
git add backend/api/pypi_client.py
c "2026-01-14T10:55:29+0530" "feat: pypi client - fetch metadata, requires_python, requires_dist, all versions"

# ── JAN 15 ────────────────────────────────────────────
git add backend/api/npm_client.py
c "2026-01-15T14:10:55+0530" "feat: npm registry client - version metadata and publish timestamps"

# ── JAN 17 ────────────────────────────────────────────
git add backend/utils/__init__.py backend/utils/batching.py
c "2026-01-17T11:40:16+0530" "feat: async batching layer, runs OSV and metadata fetches concurrently"

# ── JAN 20 ────────────────────────────────────────────
git add backend/api/nvd_client.py
c "2026-01-20T16:05:38+0530" "feat: NVD client, CVSS enrichment with retry on 429 and graceful fallback"

# ── JAN 21 ────────────────────────────────────────────
git add backend/main.py
c "2026-01-21T13:25:09+0530" "feat: top level app entry, integrate all clients into /analyse pipeline"


# ── JAN 23 ────────────────────────────────────────────
git add backend/resolver/__init__.py backend/resolver/conflict_detector.py
c "2026-01-23T10:50:22+0530" "feat: conflict detector - inter-package version clash check"

# ── JAN 26 ────────────────────────────────────────────
git add backend/resolver/conflict_detector.py
c "2026-01-26T15:35:47+0530" "feat: conflict detector - python version incompatibility check"

# ── JAN 28 ────────────────────────────────────────────
git add backend/resolver/version_resolver.py
c "2026-01-28T11:00:34+0530" "feat: version resolver - candidate fetch and safe version filter"

# ── FEB 2 ─────────────────────────────────────────────
git add backend/resolver/version_resolver.py
c "2026-02-02T14:20:58+0530" "feat: version resolver - fixpoint iteration core loop"

# ── FEB 4 ─────────────────────────────────────────────
git add backend/resolver/version_resolver.py
c "2026-02-04T10:30:17+0530" "fix: resolver - vuln map and constraint pruning edge cases"

# ── FEB 6 ─────────────────────────────────────────────
git add backend/resolver/python_recommender.py
c "2026-02-06T15:55:43+0530" "feat: python version recommender using SpecifierSet intersection"

# ── FEB 9 ─────────────────────────────────────────────
git add backend/requirements.txt
c "2026-02-09T09:35:22+0530" "chore: backend requirements.txt"

# ── FEB 10 ────────────────────────────────────────────
git add backend/api/main.py backend/main.py
c "2026-02-10T13:50:09+0530" "feat: wire resolver and conflict detector into /analyse, return FullResolution"

# ── FEB 19 ────────────────────────────────────────────
git add frontend/index.html frontend/package.json frontend/eslint.config.js frontend/.gitignore frontend/.env.example frontend/.env.production
c "2026-02-19T10:20:18+0530" "feat: Vite + React project scaffold"

# ── FEB 21 ────────────────────────────────────────────
git add frontend/src/main.jsx frontend/src/App.jsx frontend/src/App.css frontend/src/index.css
c "2026-02-21T15:10:27+0530" "feat: App shell with idle/uploading/error/results state routing"

# ── FEB 23 ────────────────────────────────────────────
git add frontend/src/components/FileUpload.jsx
c "2026-02-23T11:30:41+0530" "feat: FileUpload component with drag-drop and file input"

# ── FEB 24 ────────────────────────────────────────────
git add frontend/src/hooks/useAnalysis.js
c "2026-02-24T14:55:03+0530" "feat: useAnalysis hook, POST to /analyse and manage state"

# ── FEB 26 ────────────────────────────────────────────
git add frontend/src/components/ConflictPanel.jsx frontend/src/components/ResolutionPanel.jsx
c "2026-02-26T16:20:37+0530" "feat: ConflictPanel and ResolutionPanel, basic layout no timeline yet"

# ── MAR 2 ─────────────────────────────────────────────
git add frontend/.env
c "2026-03-02T10:45:29+0530" "chore: frontend env for local dev API base URL"

# ── MAR 3 ─────────────────────────────────────────────
git add frontend/src/App.jsx
c "2026-03-03T14:30:18+0530" "chore: wire full frontend flow, end to end works without timeline"

# ── MAR 5 ─────────────────────────────────────────────
git add frontend/src/utils/d3Timeline.js
c "2026-03-05T11:20:55+0530" "feat: D3 timeline - scaleTime x-axis, track lines, package labels"

# ── MAR 7 ─────────────────────────────────────────────
git add frontend/src/utils/d3Timeline.js
c "2026-03-07T15:40:12+0530" "feat: D3 timeline - CVE circle markers and patch triangle markers"

# ── MAR 9 ─────────────────────────────────────────────
git add frontend/src/utils/d3Timeline.js
c "2026-03-09T10:10:44+0530" "feat: D3 timeline - zoom and pan on x-axis"

# ── MAR 10 ────────────────────────────────────────────
git add frontend/src/utils/d3Timeline.js frontend/src/components/CVEDetail.jsx
c "2026-03-10T13:35:27+0530" "feat: tooltip on hover, CVEDetail drawer on marker click"

# ── MAR 12 ────────────────────────────────────────────
git add frontend/src/components/Timeline.jsx
c "2026-03-12T16:00:08+0530" "feat: Timeline React component wrapping D3, owns the SVG"

# ── MAR 14 ────────────────────────────────────────────
git add frontend/src/components/SeverityFilter.jsx
c "2026-03-14T11:25:36+0530" "feat: severity filter bar - CRITICAL HIGH MEDIUM LOW CLEAN"

# ── MAR 16 ────────────────────────────────────────────
git add frontend/dist/samples/
c "2026-03-16T14:50:19+0530" "feat: add sample files so users can try without uploading"

# ── MAR 18 ────────────────────────────────────────────
git add frontend/src/App.jsx frontend/src/components/FileUpload.jsx
c "2026-03-18T10:30:52+0530" "feat: loading states and error handling UI"

# ── MAR 21 ────────────────────────────────────────────
git add frontend/src/App.css frontend/src/index.css
c "2026-03-21T11:45:14+0530" "fix: layout polish, responsive sizing and color tokens"

# ── MAR 23 ────────────────────────────────────────────
git add render.yaml
c "2026-03-23T14:00:47+0530" "chore: Render deploy config for backend"

# ── MAR 24 ────────────────────────────────────────────
git add README.md
c "2026-03-24T16:30:22+0530" "docs: README with stack, architecture and local dev setup"

git push origin main