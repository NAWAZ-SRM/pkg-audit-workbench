import logging
import tempfile

import httpx
from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version
from pip_requirements_parser import RequirementsFile

from ..models.types import ParsedPackage

logger = logging.getLogger(__name__)


def _resolve_range_version(name: str, specifier_text: str, timeout: float = 10.0) -> str | None:
    try:
        specifier = SpecifierSet(specifier_text)
    except Exception:
        return None

    url = f"https://pypi.org/pypi/{name}/json"
    try:
        with httpx.Client(timeout=timeout) as client:
            response = client.get(url)
            if response.status_code != 200:
                return None
            payload = response.json()
    except Exception as exc:
        logger.warning("Failed resolving range for %s: %s", name, exc)
        return None

    releases = payload.get("releases") or {}
    versions = list(releases.keys())
    best: Version | None = None
    for version_text in versions:
        try:
            version_obj = Version(version_text)
        except InvalidVersion:
            continue
        if version_obj in specifier and (best is None or version_obj > best):
            best = version_obj
    return str(best) if best else None


def parse_requirements_content(file_content: str) -> list[ParsedPackage]:
    parse_errors: list[str] = []
    packages: list[ParsedPackage] = []
    seen: set[str] = set()

    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=True) as tmp_file:
            _ = tmp_file.write(file_content)
            tmp_file.flush()
            requirements_file = RequirementsFile.from_file(tmp_file.name)
    except Exception as exc:
        parse_errors.append(str(exc))
        logger.warning("requirements parse failed: %s", exc)
        return []

    for req in requirements_file.requirements:
        name = getattr(req, "name", None)
        if not name:
            continue

        normalized_name = name.strip()
        if not normalized_name:
            continue

        raw_line = str(getattr(req, "line", "") or "")
        editable_flag = bool(getattr(req, "editable", False))
        if editable_flag or raw_line.startswith("-e ") or raw_line.startswith("--editable"):
            continue

        link = str(getattr(req, "link", "") or "")
        uri = str(getattr(req, "uri", "") or "")
        source_text = " ".join([raw_line, link, uri]).lower()
        if "git+https://" in source_text or "http://" in source_text or "https://" in source_text:
            continue

        dedupe_key = normalized_name.lower()
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)

        specifier_obj = getattr(req, "specifier", None)
        raw_specifier = str(specifier_obj or "")
        resolved_version: str | None = None

        if raw_specifier.startswith("=="):
            resolved_version = raw_specifier[2:].strip()
        elif raw_specifier:
            resolved_version = _resolve_range_version(normalized_name, raw_specifier)

        if not resolved_version:
            logger.debug("Skipping unresolved requirement %s (%s)", normalized_name, raw_specifier)
            continue

        packages.append(
            ParsedPackage(
                name=normalized_name,
                raw_specifier=raw_specifier,
                resolved_version=resolved_version,
                ecosystem="pypi",
            )
        )

    if parse_errors:
        logger.debug("requirements parse_errors=%s", parse_errors)
    return packages
