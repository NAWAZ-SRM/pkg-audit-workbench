import logging

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from ..models.types import ConflictRecord

logger = logging.getLogger(__name__)


def detect_version_conflicts(
    installed: dict[str, str],
    package_dep_constraints: dict[str, dict[str, str]],
) -> list[ConflictRecord]:
    conflicts: list[ConflictRecord] = []

    for pkg_name, dep_constraints in package_dep_constraints.items():
        for dep_name, required_specifier in dep_constraints.items():
            if dep_name not in installed:
                continue

            installed_version = installed[dep_name]
            try:
                specifier_set = SpecifierSet(required_specifier)
            except InvalidSpecifier:
                logger.warning(
                    "Invalid dependency specifier skipped: pkg=%s dep=%s spec=%s",
                    pkg_name,
                    dep_name,
                    required_specifier,
                )
                continue

            try:
                installed_version_obj = Version(installed_version)
            except InvalidVersion:
                logger.warning(
                    "Invalid installed version skipped: dep=%s version=%s",
                    dep_name,
                    installed_version,
                )
                continue

            if installed_version_obj not in specifier_set:
                conflicts.append(
                    ConflictRecord(
                        package=dep_name,
                        installed_version=installed_version,
                        required_by=pkg_name,
                        required_specifier=required_specifier,
                        conflict_type="version_conflict",
                    )
                )

    return conflicts


def detect_python_conflicts(
    installed: dict[str, str],
    python_requires_map: dict[str, str],
    candidate_python: str,
) -> list[ConflictRecord]:
    selected_python = candidate_python or "3.11.9"
    try:
        selected_python_version = Version(selected_python)
    except InvalidVersion:
        logger.warning("Invalid candidate_python provided: %s; using fallback 3.11.9", selected_python)
        selected_python_version = Version("3.11.9")

    conflicts: list[ConflictRecord] = []
    for pkg_name, requires_python in python_requires_map.items():
        if not requires_python:
            continue

        try:
            specifier_set = SpecifierSet(requires_python)
        except InvalidSpecifier:
            logger.warning(
                "Invalid python_requires specifier skipped: pkg=%s spec=%s",
                pkg_name,
                requires_python,
            )
            continue

        if selected_python_version not in specifier_set:
            conflicts.append(
                ConflictRecord(
                    package=pkg_name,
                    installed_version=installed.get(pkg_name, "unknown"),
                    required_by="python_runtime",
                    required_specifier=requires_python,
                    conflict_type="python_incompatible",
                )
            )

    return conflicts
