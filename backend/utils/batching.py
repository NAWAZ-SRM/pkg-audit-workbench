import asyncio
import logging
from typing import Any

from ..api.npm_client import fetch_npm_metadata
from ..api.nvd_client import enrich_cve_severity
from ..api.osv_client import fetch_osv_reports
from ..api.pypi_client import fetch_pypi_metadata
from ..models.types import CVEEvent, PackageVulnerabilityReport, ParsedPackage

logger = logging.getLogger(__name__)


FetchAllResult = dict[str, Any]


async def fetch_all(packages: list[ParsedPackage]) -> FetchAllResult:
    ecosystem = packages[0].ecosystem if packages else "pypi"
    package_names = [pkg.name for pkg in packages]

    osv_task = fetch_osv_reports(packages)
    meta_task = (
        fetch_pypi_metadata(package_names)
        if ecosystem == "pypi"
        else fetch_npm_metadata(package_names)
    )

    osv_result, meta_result = await asyncio.gather(
        osv_task,
        meta_task,
        return_exceptions=True,
    )

    upstream_unreachable = False

    if isinstance(osv_result, BaseException):
        logger.error("OSV task failed: %s", osv_result)
        osv_reports: list[PackageVulnerabilityReport] = [
            PackageVulnerabilityReport(package=pkg, vulnerabilities=[], is_clean=True)
            for pkg in packages
        ]
        upstream_unreachable = True
    else:
        osv_reports = osv_result

    if isinstance(meta_result, BaseException):
        logger.error("Metadata task failed: %s", meta_result)
        metadata = {name: None for name in package_names}
        upstream_unreachable = True
    else:
        metadata = meta_result

    cve_events: list[CVEEvent] = []
    for report in osv_reports:
        cve_events.extend(report.vulnerabilities)

    try:
        await enrich_cve_severity(cve_events)
    except Exception as exc:
        logger.error("NVD enrichment failed: %s", exc)
        for event in cve_events:
            event.severity = "UNKNOWN"
            event.cvss_score = None

    return {
        "ecosystem": ecosystem,
        "package_reports": osv_reports,
        "metadata": metadata,
        "upstream_unreachable": upstream_unreachable,
    }
