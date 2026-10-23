from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any, Dict, Optional


def parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


@dataclass
class RiskCard:
    sample_id: str
    package: str
    raw_name: str
    type: str
    status: str
    severity: str
    confidence: float
    location: Dict[str, Any]
    generation_time: Optional[str]
    audit_time: Optional[str]
    time_view: str
    install_reachability: str
    evidence_level: str
    false_positive_filtered: bool
    evidence: Dict[str, Any]
    repair: Dict[str, Any]

    def to_dict(self):
        return asdict(self)


def classify_package_status(exists_now: bool, first_release_time: Optional[str], generation_time: Optional[str], error: Optional[str] = None) -> str:
    if error:
        return "registry_query_error"
    if not exists_now:
        return "nonexistent_now"
    first_dt = parse_iso(first_release_time)
    gen_dt = parse_iso(generation_time)
    if first_dt is not None and gen_dt is not None:
        if first_dt > gen_dt:
            return "created_after_tg"
        return "existed_at_tg"
    if exists_now:
        return "exists_now_time_unknown"
    return "registry_unknown"


def infer_reachability(source_type: str) -> str:
    if source_type == "manifest":
        return "manifest_declared"
    if source_type == "import":
        return "import_only"
    return "unknown"


def build_risk_card(
    sample_id: str,
    entity: Any,
    pypi_evidence: Any,
    generation_time: Optional[str],
    reachability_override: Optional[str] = None,
) -> Optional[RiskCard]:
    if entity.is_false_positive or entity.is_local_module:
        return None

    status = classify_package_status(
        exists_now=pypi_evidence.exists_now,
        first_release_time=pypi_evidence.first_release_time,
        generation_time=generation_time,
        error=getattr(pypi_evidence, "error", None),
    )

    if status in {"existed_at_tg", "exists_now_time_unknown", "registry_query_error"}:
        # Keep non-risk or query-error information in the result file elsewhere; no risk card emitted here.
        return None

    reachability = reachability_override or infer_reachability(entity.source_type)
    if status == "nonexistent_now":
        risk_type = "temporal_package_hallucination"
        severity = "high" if reachability == "manifest_declared" else "medium"
        confidence = 0.85
    elif status == "created_after_tg":
        risk_type = "temporal_package_hallucination"
        severity = "high" if reachability == "manifest_declared" else "medium"
        confidence = 0.90
    else:
        risk_type = "temporal_package_hallucination"
        severity = "low"
        confidence = 0.50

    return RiskCard(
        sample_id=sample_id,
        package=entity.mapped_name,
        raw_name=entity.raw_name,
        type=risk_type,
        status=status,
        severity=severity,
        confidence=confidence,
        location={"file": entity.file, "line": entity.line, "source_type": entity.source_type},
        generation_time=generation_time,
        audit_time=pypi_evidence.audit_time,
        time_view="as_of_audit_current_pypi",
        install_reachability=reachability,
        evidence_level="current_registry_evidence",
        false_positive_filtered=False,
        evidence={
            "query_url": pypi_evidence.query_url,
            "exists_now": pypi_evidence.exists_now,
            "first_release_time": pypi_evidence.first_release_time,
            "latest_version": pypi_evidence.latest_version,
            "original_text": entity.original_text,
        },
        repair={
            "action": "review" if status == "created_after_tg" else "remove_or_replace",
            "suggestion": "人工核对该依赖是否为真实需要的第三方包；如果不是，请删除或替换为可信官方包。",
            "verify": "重新运行依赖安装和项目测试。",
        },
    )
