import asyncio
import logging
import os
from typing import Any

import httpx

logger = logging.getLogger(__name__)
METADATA_BATCH_SIZE = 50


def _pypi_concurrency_limit() -> int:
    try:
        value = int(os.getenv("PYPI_CONCURRENCY_LIMIT", "20"))
        return value if value > 0 else 20
    except (TypeError, ValueError):
        return 20


async def _fetch_single_pypi(client: httpx.AsyncClient, name: str) -> dict[str, Any] | None:
    url = f"https://pypi.org/pypi/{name}/json"
    try:
        response = await client.get(url)
        if response.status_code == 404:
            logger.warning("PyPI package not found: %s", name)
            return None
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:
        logger.warning("PyPI fetch failed for %s: %s", name, exc)
        return None

    info = payload.get("info") or {}
    releases = payload.get("releases") or {}

    version_times: dict[str, str | None] = {}
    for version, release_entries in releases.items():
        upload_time = None
        if isinstance(release_entries, list) and release_entries:
            first = release_entries[0] or {}
            upload_time = first.get("upload_time")
        version_times[version] = upload_time

    return {
        "requires_python": info.get("requires_python"),
        "requires_dist": info.get("requires_dist"),
        "versions": list(releases.keys()),
        "version_times": version_times,
    }


async def fetch_pypi_metadata(package_names: list[str]) -> dict[str, dict[str, Any] | None]:
    if not package_names:
        return {}

    semaphore = asyncio.Semaphore(_pypi_concurrency_limit())
    output: dict[str, dict[str, Any] | None] = {}

    async def wrapped(client: httpx.AsyncClient, name: str) -> dict[str, Any] | None:
        async with semaphore:
            return await _fetch_single_pypi(client, name)

    async with httpx.AsyncClient(timeout=15.0) as client:
        batches = (
            [
                package_names[index : index + METADATA_BATCH_SIZE]
                for index in range(0, len(package_names), METADATA_BATCH_SIZE)
            ]
            if len(package_names) > 200
            else [package_names]
        )

        for batch in batches:
            tasks = [wrapped(client, name) for name in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for name, value in zip(batch, results, strict=False):
                if isinstance(value, BaseException):
                    logger.warning("PyPI metadata task exception for %s: %s", name, value)
                    output[name] = None
                    continue
                output[name] = value

    return output
