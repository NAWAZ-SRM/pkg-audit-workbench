import asyncio
import logging
import os
from datetime import date, datetime
from typing import Any

import httpx

from ..models.types import CVEEvent, PackageVulnerabilityReport, ParsedPackage

logger = logging.getLogger(__name__)

OSV_BATCH_SIZE = 100


def _osv_batch_size(total_packages: int) -> int:
    try:
        configured = int(os.getenv("OSV_BATCH_SIZE", str(OSV_BATCH_SIZE)))
    except (TypeError, ValueError):
        configured = OSV_BATCH_SIZE

    if configured <= 0:
        configured = OSV_BATCH_SIZE

    if total_packages > 200:
        return 50

    return configured


def _parse_iso_date(value: str | None):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).date()
    except Exception:
        return None


async def _fetch_patch_release_date(
    client: httpx.AsyncClient,
    ecosystem: str,
    package_name: str,
    fixed_version: str,
) -> date | None:
    try:
        if ecosystem == "pypi":
            url = f"https://pypi.org/pypi/{package_name}/json"
            response = await client.get(url)
            if response.status_code != 200:
                return None
            payload = response.json()
            releases = payload.get("releases") or {}
            release_entries = releases.get(fixed_version) or []
            if not release_entries:
                return None
            upload_time = (release_entries[0] or {}).get("upload_time")
            return _parse_iso_date(upload_time)

        if ecosystem == "npm":
            url = f"https://registry.npmjs.org/{package_name}"
            response = await client.get(url)
            if response.status_code != 200:
                return None
            payload = response.json()
            time_map = payload.get("time") or {}
            published = time_map.get(fixed_version)
            return _parse_iso_date(published)
    except Exception:
        return None
    return None


def _build_query_chunk(packages: list[ParsedPackage]) -> dict[str, list[dict[str, Any]]]:
    queries: list[dict[str, Any]] = []
    for pkg in packages:
        ecosystem_name = "PyPI" if pkg.ecosystem == "pypi" else "npm"
        queries.append(
            {
                "package": {"name": pkg.name, "ecosystem": ecosystem_name},
                "version": pkg.resolved_version,
            }
        )
    return {"queries": queries}


async def _fetch_osv_chunk(
    client: httpx.AsyncClient,
    packages_chunk: list[ParsedPackage],
) -> list[PackageVulnerabilityReport]:
    payload = _build_query_chunk(packages_chunk)
    response = await client.post("https://api.osv.dev/v1/querybatch", json=payload)
    response.raise_for_status()
    body = response.json()
    results = body.get("results") or []

    reports: list[PackageVulnerabilityReport] = []
    for idx, pkg in enumerate(packages_chunk):
        entry = results[idx] if idx < len(results) else {}
        vulns = entry.get("vulns") or []
        cves: list[CVEEvent] = []

        for vuln in vulns:
            vuln_id = str(vuln.get("id") or "")
            aliases = vuln.get("aliases") or []
            cve_id = next((alias for alias in aliases if str(alias).startswith("CVE-")), vuln_id)
            summary = str(vuln.get("summary") or "")
            affected = vuln.get("affected") or []

            affected_range = ""
            patch_version = None
            patched_at = None
            for affected_item in affected:
                ranges = affected_item.get("ranges") or []
                for range_item in ranges:
                    events = range_item.get("events") or []
                    constraints = []
                    for event in events:
                        introduced = event.get("introduced")
                        fixed = event.get("fixed")
                        if introduced:
                            constraints.append(f">={introduced}")
                        if fixed and patch_version is None:
                            patch_version = str(fixed)
                    if constraints and not affected_range:
                        affected_range = ",".join(constraints)

            disclosed_at = _parse_iso_date(vuln.get("published"))
            if patch_version:
                patched_at = await _fetch_patch_release_date(
                    client=client,
                    ecosystem=pkg.ecosystem,
                    package_name=pkg.name,
                    fixed_version=patch_version,
                )

            if not disclosed_at:
                continue

            cves.append(
                CVEEvent(
                    cve_id=cve_id,
                    osv_id=vuln_id,
                    summary=summary,
                    disclosed_at=disclosed_at,
                    patched_at=patched_at,
                    patch_version=patch_version,
                    severity="UNKNOWN",
                    cvss_score=None,
                    affected_range=affected_range,
                )
            )

        reports.append(
            PackageVulnerabilityReport(
                package=pkg,
                vulnerabilities=cves,
                is_clean=len(cves) == 0,
            )
        )

    return reports


async def fetch_osv_reports(packages: list[ParsedPackage]) -> list[PackageVulnerabilityReport]:
    if not packages:
        return []

    batch_size = _osv_batch_size(len(packages))

    chunks: list[list[ParsedPackage]] = [
        packages[i : i + batch_size] for i in range(0, len(packages), batch_size)
    ]

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            chunk_tasks = [_fetch_osv_chunk(client, chunk) for chunk in chunks]
            chunk_results = await asyncio.gather(*chunk_tasks, return_exceptions=True)
    except Exception as exc:
        logger.error("OSV batch failed: %s", exc)
        return [PackageVulnerabilityReport(package=p, vulnerabilities=[], is_clean=True) for p in packages]

    flattened: list[PackageVulnerabilityReport] = []
    for index, chunk_result in enumerate(chunk_results):
        if isinstance(chunk_result, BaseException):
            logger.error("OSV chunk %s failed: %s", index, chunk_result)
            failed_chunk = chunks[index]
            flattened.extend(
                [PackageVulnerabilityReport(package=p, vulnerabilities=[], is_clean=True) for p in failed_chunk]
            )
            continue
        flattened.extend(chunk_result)
    return flattened
