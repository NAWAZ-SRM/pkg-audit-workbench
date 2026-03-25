import os
from collections import defaultdict

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from ..models.types import (
    ConflictRecord,
    FullResolution,
    PackageResolution,
    PackageVulnerabilityReport,
    ParsedPackage,
)
from .conflict_detector import detect_version_conflicts, detect_python_conflicts


def _safe_sorted_versions(values: list[str]) -> list[str]:
    parsed: list[tuple[Version, str]] = []
    for value in values:
        try:
            parsed.append((Version(value), value))
        except InvalidVersion:
            continue
    parsed.sort(key=lambda item: item[0], reverse=True)
    return [raw for _, raw in parsed]


SEVERITY_WEIGHT = {
    "UNKNOWN": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def _candidate_vulnerability_stats(
    version: str,
    vulnerabilities: list[tuple[str | None, str]],
) -> tuple[int, int]:
    try:
        candidate = Version(version)
    except InvalidVersion:
        return (10**9, 10**9)

    unresolved_count = 0
    unresolved_severity = 0

    for patch, severity in vulnerabilities:
        unresolved = False
        if patch is None:
            unresolved = True
        else:
            try:
                patch_version = Version(patch)
                unresolved = candidate < patch_version
            except InvalidVersion:
                unresolved = True

        if unresolved:
            unresolved_count += 1
            unresolved_severity = max(unresolved_severity, SEVERITY_WEIGHT.get(severity, 0))

    return unresolved_count, unresolved_severity


def _can_be_cve_free(version: str, vulnerabilities: list[tuple[str | None, str]]) -> bool:
    unresolved_count, _ = _candidate_vulnerability_stats(version, vulnerabilities)
    return unresolved_count == 0


def _lowest_risk_candidate(
    candidates: list[str],
    vulnerabilities: list[tuple[str | None, str]],
) -> str | None:
    best: tuple[int, int, Version, str] | None = None
    for candidate in candidates:
        try:
            version_obj = Version(candidate)
        except InvalidVersion:
            continue

        unresolved_count, unresolved_severity = _candidate_vulnerability_stats(candidate, vulnerabilities)
        rank = (unresolved_severity, unresolved_count, version_obj, candidate)
        if best is None:
            best = rank
            continue
        if rank[0] < best[0]:
            best = rank
            continue
        if rank[0] == best[0] and rank[1] < best[1]:
            best = rank
            continue
        if rank[0] == best[0] and rank[1] == best[1] and rank[2] > best[2]:
            best = rank

    return best[3] if best else None


def _target_python_or_default(target_python: str) -> str:
    try:
        _ = Version(target_python)
        return target_python
    except InvalidVersion:
        return "3.11.9"


def _package_python_compatible(
    package_name: str,
    target_python: str,
    python_requires_map: dict[str, str],
) -> bool:
    required_specifier = python_requires_map.get(package_name)
    if not required_specifier:
        return True

    try:
        specifier_set = SpecifierSet(required_specifier)
        python_version = Version(target_python)
    except (InvalidSpecifier, InvalidVersion):
        return True

    return python_version in specifier_set


def _satisfies_external_constraints(
    candidate_version: str,
    package_name: str,
    dep_constraints: dict[str, dict[str, str]],
) -> bool:
    try:
        candidate_obj = Version(candidate_version)
    except InvalidVersion:
        return False

    for depender, constraints in dep_constraints.items():
        if depender == "__python_requires__":
            continue
        required_specifier = constraints.get(package_name)
        if not required_specifier:
            continue
        try:
            specifier_set = SpecifierSet(required_specifier)
        except InvalidSpecifier:
            continue
        if candidate_obj not in specifier_set:
            return False
    return True


def resolve_versions(
    packages: list[ParsedPackage],
    vuln_reports: list[PackageVulnerabilityReport],
    conflicts: list[ConflictRecord],
    all_versions: dict[str, list[str]],
    dep_constraints: dict[str, dict[str, str]],
    target_python: str,
) -> FullResolution:
    try:
        max_iterations = int(os.getenv("RESOLVER_MAX_ITERATIONS", "10"))
        if max_iterations <= 0:
            max_iterations = 10
    except (TypeError, ValueError):
        max_iterations = 10
    selected_python = _target_python_or_default(target_python)

    original = {pkg.name: pkg.resolved_version for pkg in packages}
    working_set = dict(original)
    python_requires_map = dep_constraints.get("__python_requires__", {})

    vulnerabilities_by_package: dict[str, list[tuple[str | None, str]]] = defaultdict(list)
    for report in vuln_reports:
        for vuln in report.vulnerabilities:
            vulnerabilities_by_package[report.package.name].append(
                (vuln.patch_version, vuln.severity)
            )

    cve_packages = {report.package.name for report in vuln_reports if not report.is_clean}
    current_conflicts = list(conflicts)
    conflict_packages = {item.package for item in conflicts} | {
        item.required_by for item in conflicts if item.required_by in original
    }

    changed_due_to_cve: set[str] = set()
    changed_due_to_conflict: set[str] = set()
    no_candidates_found: set[str] = set()
    lowest_risk_selected: set[str] = set()

    reached_fixpoint = False
    iterations = 0

    while iterations < max_iterations:
        iterations += 1
        packages_needing_resolution = cve_packages | conflict_packages
        if not packages_needing_resolution:
            reached_fixpoint = True
            break

        any_change = False
        next_working_set = dict(working_set)

        for package_name in packages_needing_resolution:
            available_candidates = _safe_sorted_versions(all_versions.get(package_name, []))
            if not available_candidates:
                no_candidates_found.add(package_name)
                continue

            package_vulns = vulnerabilities_by_package.get(package_name, [])
            constraint_compatible = [
                candidate
                for candidate in available_candidates
                if _package_python_compatible(package_name, selected_python, python_requires_map)
                and _satisfies_external_constraints(candidate, package_name, dep_constraints)
            ]

            if not constraint_compatible:
                no_candidates_found.add(package_name)
                continue

            filtered = [
                candidate
                for candidate in constraint_compatible
                if _can_be_cve_free(candidate, package_vulns)
            ]

            chosen = filtered[0] if filtered else None
            if not chosen:
                lowest_risk = _lowest_risk_candidate(constraint_compatible, package_vulns)
                chosen = lowest_risk
                if chosen:
                    lowest_risk_selected.add(package_name)

            if chosen and next_working_set.get(package_name) != chosen:
                next_working_set[package_name] = chosen
                any_change = True
                if package_name in cve_packages:
                    changed_due_to_cve.add(package_name)
                if package_name in conflict_packages:
                    changed_due_to_conflict.add(package_name)

        working_set = next_working_set

        updated_conflicts = detect_version_conflicts(working_set, dep_constraints)
        updated_conflicts.extend(detect_python_conflicts(working_set, python_requires_map, selected_python))
        current_conflicts = updated_conflicts

        if not updated_conflicts:
            reached_fixpoint = True
            break

        conflict_packages = {item.package for item in updated_conflicts} | {
            item.required_by for item in updated_conflicts if item.required_by in original
        }

        if not any_change:
            break

    package_resolutions: list[PackageResolution] = []
    for package in packages:
        name = package.name
        current_version = package.resolved_version
        recommended_version = working_set.get(name, current_version)
        changed = recommended_version != current_version

        if changed and name in changed_due_to_cve:
            reason = "CVE fix"
        elif changed and name in changed_due_to_conflict:
            reason = "conflict resolution"
        elif name in no_candidates_found:
            reason = "no candidates found"
        elif name in lowest_risk_selected:
            reason = "no clean version available - lowest risk chosen"
        else:
            reason = "unchanged"

        if not reached_fixpoint:
            reason = f"{reason}; partial resolution: fixpoint did not converge"

        package_resolutions.append(
            PackageResolution(
                name=name,
                current_version=current_version,
                recommended_version=recommended_version,
                changed=changed,
                reason=reason,
            )
        )

    all_cves_resolved = True
    for package_name, package_vulns in vulnerabilities_by_package.items():
        current = working_set.get(package_name)
        if not current:
            all_cves_resolved = False
            break
        if not _can_be_cve_free(current, package_vulns):
            all_cves_resolved = False
            break

    all_conflicts_resolved = len(current_conflicts) == 0
    if not reached_fixpoint:
        all_cves_resolved = False
        all_conflicts_resolved = False

    return FullResolution(
        python_version=selected_python,
        packages=package_resolutions,
        all_cves_resolved=all_cves_resolved,
        all_conflicts_resolved=all_conflicts_resolved,
    )
