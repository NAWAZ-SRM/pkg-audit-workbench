import asyncio
import importlib
import json
import logging
import os
import traceback
from datetime import datetime, timezone
from email.parser import BytesParser
from email.policy import default
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from packaging.requirements import InvalidRequirement, Requirement

from ..models.types import AnalysisResponse, ConflictRecord, PackageVulnerabilityReport
from ..parser.package_json_parser import parse_package_json_content
from ..parser.requirements_parser import parse_requirements_content
from ..resolver.conflict_detector import detect_python_conflicts, detect_version_conflicts
from ..resolver.python_recommender import recommend_python
from ..resolver.version_resolver import resolve_versions
from ..utils.batching import fetch_all

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Vulnerability Timeline API")

allowed_origins = [origin.strip() for origin in os.getenv("ALLOWED_ORIGINS", "*").split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins or ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _safe_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _build_pypi_constraints(metadata: dict[str, dict[str, Any] | None]) -> dict[str, dict[str, str]]:
    package_constraints: dict[str, dict[str, str]] = {}

    for pkg_name, pkg_meta in metadata.items():
        constraints: dict[str, str] = {}
        if not isinstance(pkg_meta, dict):
            package_constraints[pkg_name] = constraints
            continue

        requires_dist = pkg_meta.get("requires_dist")
        if not isinstance(requires_dist, list):
            package_constraints[pkg_name] = constraints
            continue

        for dep_entry in requires_dist:
            if not isinstance(dep_entry, str):
                continue
            try:
                parsed = Requirement(dep_entry)
            except InvalidRequirement:
                logger.warning("Invalid requires_dist entry skipped for %s: %s", pkg_name, dep_entry)
                continue

            dep_name = parsed.name
            dep_specifier = str(parsed.specifier)
            if not dep_name or not dep_specifier:
                continue
            constraints[dep_name] = dep_specifier

        package_constraints[pkg_name] = constraints

    return package_constraints


def _build_npm_constraints(metadata: dict[str, dict[str, Any] | None], installed: dict[str, str]) -> dict[str, dict[str, str]]:
    package_constraints: dict[str, dict[str, str]] = {}

    for pkg_name, pkg_meta in metadata.items():
        constraints: dict[str, str] = {}
        if not isinstance(pkg_meta, dict):
            package_constraints[pkg_name] = constraints
            continue

        versions = _safe_dict(pkg_meta.get("versions"))
        installed_version = installed.get(pkg_name)
        if not installed_version:
            package_constraints[pkg_name] = constraints
            continue

        installed_meta = _safe_dict(versions.get(installed_version))
        dep_map = _safe_dict(installed_meta.get("dependencies"))
        peer_dep_map = _safe_dict(installed_meta.get("peerDependencies"))

        for dep_name, specifier in dep_map.items():
            if isinstance(dep_name, str) and isinstance(specifier, str) and specifier:
                constraints[dep_name] = specifier

        for dep_name, specifier in peer_dep_map.items():
            if isinstance(dep_name, str) and isinstance(specifier, str) and specifier:
                constraints[dep_name] = specifier

        package_constraints[pkg_name] = constraints

    return package_constraints


def _build_pypi_python_requires(metadata: dict[str, dict[str, Any] | None]) -> dict[str, str]:
    python_requires_map: dict[str, str] = {}
    for pkg_name, pkg_meta in metadata.items():
        if not isinstance(pkg_meta, dict):
            continue
        requires_python = pkg_meta.get("requires_python")
        if isinstance(requires_python, str) and requires_python:
            python_requires_map[pkg_name] = requires_python
    return python_requires_map


def _dedupe_conflicts(conflicts: list[ConflictRecord]) -> list[ConflictRecord]:
    deduped: list[ConflictRecord] = []
    seen: set[tuple[str, str]] = set()
    for conflict in conflicts:
        key = (conflict.package, conflict.required_by)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(conflict)
    return deduped


def _build_all_versions(
    metadata: dict[str, dict[str, Any] | None],
    ecosystem: str,
) -> dict[str, list[str]]:
    all_versions: dict[str, list[str]] = {}
    for package_name, package_meta in metadata.items():
        if not isinstance(package_meta, dict):
            all_versions[package_name] = []
            continue

        if ecosystem == "pypi":
            versions = package_meta.get("versions")
            if isinstance(versions, list):
                all_versions[package_name] = [value for value in versions if isinstance(value, str)]
            else:
                all_versions[package_name] = []
            continue

        versions_map = _safe_dict(package_meta.get("versions"))
        all_versions[package_name] = [key for key in versions_map.keys() if isinstance(key, str)]

    return all_versions


def _analyse_sync(filename: str, file_content: str) -> AnalysisResponse:
    if not file_content or not file_content.strip():
        raise HTTPException(status_code=422, detail="No packages found in file")

    lower_name = filename.lower()
    if lower_name.endswith("requirements.txt") or lower_name.endswith(".txt"):
        parsed_packages = parse_requirements_content(file_content)
        parse_mode = "requirements"
    elif lower_name.endswith(".json"):
        parse_mode = "json"
        parsed_packages = parse_package_json_content(file_content)
    else:
        raise HTTPException(
            status_code=400,
            detail="Only package.json and requirements.txt are supported",
        )

    if not parsed_packages:
        if parse_mode == "json":
            try:
                payload = json.loads(file_content)
                dependencies = payload.get("dependencies") if isinstance(payload, dict) else None
                dev_dependencies = payload.get("devDependencies") if isinstance(payload, dict) else None
                has_dependencies = bool(dependencies) or bool(dev_dependencies)
                if not has_dependencies:
                    raise HTTPException(status_code=422, detail="File parsed but no dependencies found")
            except json.JSONDecodeError:
                raise HTTPException(status_code=400, detail="File parsing failed")
        raise HTTPException(status_code=422, detail="No packages found in file")

    batched_result = asyncio.run(fetch_all(parsed_packages))
    if batched_result.get("upstream_unreachable"):
        raise HTTPException(status_code=502, detail="One or more upstream APIs are unreachable")

    installed = {pkg.name: pkg.resolved_version for pkg in parsed_packages}
    metadata = batched_result.get("metadata")
    metadata_map: dict[str, dict[str, Any] | None] = metadata if isinstance(metadata, dict) else {}

    ecosystem = batched_result["ecosystem"]
    if ecosystem == "pypi":
        package_dep_constraints = _build_pypi_constraints(metadata_map)
        python_requires_map = _build_pypi_python_requires(metadata_map)
    else:
        package_dep_constraints = _build_npm_constraints(metadata_map, installed)
        python_requires_map = {}

    python_target = recommend_python(list(python_requires_map.values()))
    version_conflicts = detect_version_conflicts(installed, package_dep_constraints)
    python_conflicts = detect_python_conflicts(installed, python_requires_map, python_target)
    conflicts = _dedupe_conflicts([*version_conflicts, *python_conflicts])
    package_reports = batched_result.get("package_reports")
    vuln_reports: list[PackageVulnerabilityReport] = (
        package_reports if isinstance(package_reports, list) else []
    )
    all_versions = _build_all_versions(metadata_map, ecosystem)
    resolver_dep_constraints = dict(package_dep_constraints)
    resolver_dep_constraints["__python_requires__"] = python_requires_map

    resolution = resolve_versions(
        packages=parsed_packages,
        vuln_reports=vuln_reports,
        conflicts=conflicts,
        all_versions=all_versions,
        dep_constraints=resolver_dep_constraints,
        target_python=python_target,
    )

    return AnalysisResponse(
        ecosystem=ecosystem,
        packages=vuln_reports,
        conflicts=conflicts,
        resolution=resolution,
        analysed_at=datetime.now(timezone.utc),
    )


def _extract_multipart_file(content_type: str, body: bytes) -> tuple[str, str]:
    if "multipart/form-data" not in content_type.lower():
        raise HTTPException(status_code=400, detail="Only package.json and requirements.txt are supported")

    raw_message = (
        f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("utf-8") + body
    )
    message = BytesParser(policy=default).parsebytes(raw_message)
    if not message.is_multipart():
        raise HTTPException(status_code=400, detail="Only package.json and requirements.txt are supported")

    for part in message.iter_parts():
        disposition = part.get("Content-Disposition", "")
        if "form-data" not in disposition:
            continue
        if part.get_param("name", header="content-disposition") != "file":
            continue

        filename = part.get_filename() or ""
        payload = part.get_payload(decode=True)
        if isinstance(payload, bytes):
            return filename, payload.decode("utf-8", errors="ignore")

        fallback_payload = part.get_payload()
        if isinstance(fallback_payload, str):
            return filename, fallback_payload

        return filename, ""

    raise HTTPException(status_code=400, detail="Only package.json and requirements.txt are supported")


@app.post("/analyse", response_model=AnalysisResponse)
async def analyse(request: Request) -> AnalysisResponse:
    try:
        body = await request.body()
        filename, content = _extract_multipart_file(
            request.headers.get("content-type", ""),
            body,
        )

        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None,
            _analyse_sync,
            filename,
            content,
        )
        return result
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Internal analysis crash: %s", exc)
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail="Internal analysis error")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.on_event("startup")
async def startup_validation() -> None:
    if not os.getenv("NVD_API_KEY"):
        logger.warning("NVD_API_KEY not set; NVD severity enrichment will remain UNKNOWN")

    try:
        _ = importlib.import_module("pip_requirements_parser")
    except Exception as exc:
        logger.warning("pip-requirements-parser import check failed: %s", exc)

    logger.info("Vulnerability Timeline API ready")
