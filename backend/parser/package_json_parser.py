import json
import re

from ..models.types import ParsedPackage

SEMVER_PREFIXES = ("^", "~", ">=", "<=", ">", "<", "=")


def _normalize_version(version_spec: str) -> str | None:
    cleaned = version_spec.strip()
    if not cleaned:
        return None

    if cleaned.startswith("workspace:") or cleaned.startswith("file:"):
        return None

    cleaned = cleaned.split("||")[0].strip()
    parts = cleaned.split()
    if len(parts) > 1:
        lower_bound = None
        for part in parts:
            segment = part.strip()
            if segment.startswith((">=", ">")):
                lower_bound = segment
                break
        candidate = lower_bound or parts[0]
    else:
        candidate = cleaned

    normalized = candidate
    for prefix in SEMVER_PREFIXES:
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix) :]
            break

    normalized = normalized.strip()
    if not normalized:
        return None
    if "x" in normalized.lower() or "*" in normalized:
        return None
    if not re.fullmatch(r"[0-9]+(?:\.[0-9A-Za-z-]+)*", normalized):
        return None
    return normalized or None


def parse_package_json_content(file_content: str) -> list[ParsedPackage]:
    try:
        payload = json.loads(file_content)
    except json.JSONDecodeError:
        return []

    dependencies = payload.get("dependencies") or {}
    dev_dependencies = payload.get("devDependencies") or {}
    merged: dict[str, str] = {}
    for source in (dependencies, dev_dependencies):
        for name, spec in source.items():
            if name not in merged:
                merged[name] = str(spec)

    result: list[ParsedPackage] = []
    seen: set[str] = set()
    for name, raw_specifier in merged.items():
        dedupe_key = name.lower()
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)

        resolved_version = _normalize_version(raw_specifier)
        if not resolved_version:
            continue

        result.append(
            ParsedPackage(
                name=name,
                raw_specifier=raw_specifier,
                resolved_version=resolved_version,
                ecosystem="npm",
            )
        )

    return result
