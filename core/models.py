"""Data models for findings and remediations."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def rank(cls, value: "Severity | str") -> int:
        order = {
            cls.CRITICAL: 5,
            cls.HIGH: 4,
            cls.MEDIUM: 3,
            cls.LOW: 2,
            cls.INFO: 1,
        }
        if isinstance(value, str):
            value = cls(value.lower())
        return order[value]

    def at_or_above(self, threshold: "Severity | str") -> bool:
        return self.rank(self) >= self.rank(threshold)


SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "blue",
}


@dataclass
class Finding:
    id: str
    module: str
    severity: Severity
    title: str
    detail: str
    current: str = ""
    recommended: str = ""
    remediation_id: Optional[str] = None
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        sev = data.get("severity", "info")
        if isinstance(sev, str):
            sev = Severity(sev.lower())
        return cls(
            id=data["id"],
            module=data["module"],
            severity=sev,
            title=data["title"],
            detail=data["detail"],
            current=data.get("current", ""),
            recommended=data.get("recommended", ""),
            remediation_id=data.get("remediation_id"),
            meta=data.get("meta") or {},
        )


@dataclass
class AuditResult:
    hostname: str
    os_name: str
    os_version: str
    findings: List[Finding] = field(default_factory=list)
    modules_run: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hostname": self.hostname,
            "os_name": self.os_name,
            "os_version": self.os_version,
            "modules_run": self.modules_run,
            "errors": self.errors,
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary(),
        }

    def summary(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        counts["total"] = len(self.findings)
        return counts

    def filter_severity(self, minimum: Severity | str) -> List[Finding]:
        return [f for f in self.findings if f.severity.at_or_above(minimum)]

    def with_remediations(self) -> List[Finding]:
        return [f for f in self.findings if f.remediation_id]


@dataclass
class Remediation:
    id: str
    title: str
    description: str
    script: str
    files_touched: List[str] = field(default_factory=list)
    restart_service: Optional[str] = None
    requires_root: bool = True
