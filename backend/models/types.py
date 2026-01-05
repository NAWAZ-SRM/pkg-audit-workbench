from datetime import date, datetime
from typing import Literal, Optional

from pydantic import BaseModel


class ParsedPackage(BaseModel):
    name: str
    raw_specifier: str
    resolved_version: str
    ecosystem: Literal["pypi", "npm"]

    class Config:
        orm_mode = True


class CVEEvent(BaseModel):
    cve_id: str
    osv_id: str
    summary: str
    disclosed_at: date
    patched_at: Optional[date] = None
    patch_version: Optional[str] = None
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    cvss_score: Optional[float] = None
    affected_range: str

    class Config:
        orm_mode = True


class PackageVulnerabilityReport(BaseModel):
    package: ParsedPackage
    vulnerabilities: list[CVEEvent]
    is_clean: bool

    class Config:
        orm_mode = True


class ConflictRecord(BaseModel):
    package: str
    installed_version: str
    required_by: str
    required_specifier: str
    conflict_type: Literal["version_conflict", "python_incompatible"]

    class Config:
        orm_mode = True


class PackageResolution(BaseModel):
    name: str
    current_version: str
    recommended_version: str
    changed: bool
    reason: str

    class Config:
        orm_mode = True


class FullResolution(BaseModel):
    python_version: str
    packages: list[PackageResolution]
    all_cves_resolved: bool
    all_conflicts_resolved: bool

    class Config:
        orm_mode = True


class AnalysisResponse(BaseModel):
    ecosystem: Literal["pypi", "npm"]
    packages: list[PackageVulnerabilityReport]
    conflicts: list[ConflictRecord]
    resolution: Optional[FullResolution] = None
    analysed_at: datetime

    class Config:
        orm_mode = True
