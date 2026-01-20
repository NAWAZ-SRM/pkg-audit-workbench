import asyncio
import logging
import os
from typing import Literal

import httpx

from ..models.types import CVEEvent

logger = logging.getLogger(__name__)


def _score_to_severity(score: float) -> Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


async def _fetch_cvss_for_cve(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    cve_id: str,
    api_key: str | None,
) -> tuple[str, float | None, Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]]:
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cveId": cve_id}
    headers = {"apiKey": api_key} if api_key else {}

    async with semaphore:
        try:
            response = await client.get(url, params=params, headers=headers)
            retries = 0
            while response.status_code == 429 and retries < 3:
                retries += 1
                await asyncio.sleep(1)
                response = await client.get(url, params=params, headers=headers)
            response.raise_for_status()
            payload = response.json()
            vulnerabilities = payload.get("vulnerabilities") or []
            if not vulnerabilities:
                return cve_id, None, "UNKNOWN"

            cve = (vulnerabilities[0] or {}).get("cve") or {}
            metrics = cve.get("metrics") or {}
            cvss_v31 = metrics.get("cvssMetricV31") or []
            if not cvss_v31:
                return cve_id, None, "UNKNOWN"

            cvss_data = (cvss_v31[0] or {}).get("cvssData") or {}
            score = cvss_data.get("baseScore")
            if score is None:
                return cve_id, None, "UNKNOWN"

            numeric_score = float(score)
            return cve_id, numeric_score, _score_to_severity(numeric_score)
        except Exception as exc:
            logger.warning("NVD lookup failed for %s: %s", cve_id, exc)
            return cve_id, None, "UNKNOWN"


async def enrich_cve_severity(cve_events: list[CVEEvent]) -> None:
    api_key = os.getenv("NVD_API_KEY")
    if not api_key:
        for event in cve_events:
            event.severity = "UNKNOWN"
            event.cvss_score = None
        return

    rate_limit = 50 if api_key else 5
    try:
        configured = int(os.getenv("NVD_RATE_LIMIT", str(rate_limit)))
        if configured > 0:
            rate_limit = configured
    except (TypeError, ValueError):
        pass

    semaphore = asyncio.Semaphore(rate_limit)

    async with httpx.AsyncClient(timeout=15.0) as client:
        tasks = [
            _fetch_cvss_for_cve(
                client=client,
                semaphore=semaphore,
                cve_id=event.cve_id,
                api_key=api_key,
            )
            for event in cve_events
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    mapped: dict[str, tuple[float | None, Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]]] = {}
    for result in results:
        if isinstance(result, BaseException):
            continue
        cve_id, score, severity = result
        mapped[cve_id] = (score, severity)

    for event in cve_events:
        score, severity = mapped.get(event.cve_id, (None, "UNKNOWN"))
        event.cvss_score = score
        event.severity = severity
