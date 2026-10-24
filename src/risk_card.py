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
    subtype: str
    status: str
    severity: str
    confidence: Optional[float]
    channel: str
    formal_eligible: bool
    claim_strength: str
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


def classify_package_status(exists_now: Optional[bool], first_release_time: Optional[str], generation_time: Optional[str], error: Optional[str] = None) -> str:
    if error:
        return "registry_query_error"
    if exists_now is False:
        return "nonexistent_now"
    if exists_now is not True:
        return "registry_unknown"
    first_dt = parse_iso(first_release_time)
    gen_dt = parse_iso(generation_time)
    if first_dt is not None and gen_dt is not None:
        if first_dt > gen_dt:
            return "created_after_tg"
        return "existed_at_tg"
    return "exists_now_time_unknown"


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
        subtype = "audit_time_registry_absence"
        severity = "high" if reachability == "manifest_declared" else "medium"
        confidence = None
        channel = "auxiliary"
        formal_eligible = False
        claim_strength = "audit_time_absence_only"
        evidence_level = "audit_time_registry_observation"
    elif status == "created_after_tg":
        risk_type = "temporal_package_hallucination"
        is_install_reachable = reachability == "manifest_declared"
        subtype = (
            "install_reachable_temporal_hallucination"
            if is_install_reachable
            else "created_after_generation"
        )
        severity = "high" if is_install_reachable else "medium"
        confidence = 0.90
        channel = "formal"
        formal_eligible = True
        claim_strength = (
            "bounded_temporal_hallucination"
            if is_install_reachable
            else "created_after_generation_only"
        )
        evidence_level = "generation_and_release_time_evidence"
    else:
        risk_type = "temporal_package_hallucination"
        subtype = "temporal_status_review"
        severity = "low"
        confidence = None
        channel = "auxiliary"
        formal_eligible = False
        claim_strength = "insufficient_temporal_evidence"
        evidence_level = "current_registry_evidence"

    if status == "nonexistent_now":
        repair = {
            "action": "review_temporal_and_identity_evidence",
            "suggestion": (
                "核对生成时 registry/release 历史、后续删除或 yank、"
                "import-to-distribution 映射以及本地/私有包上下文；"
                "在完成复核前不要将当前 404 当作生成时包名幻觉。"
            ),
            "verify": "完成人工 adjudication 后再决定保留、删除或替换依赖。",
        }
    else:
        repair = {
            "action": "review",
            "suggestion": (
                "人工核对该依赖是否为真实需要的第三方包；"
                "如果不是，请删除或替换为可信官方包。"
            ),
            "verify": "重新运行依赖安装和项目测试。",
        }

    return RiskCard(
        sample_id=sample_id,
        package=entity.mapped_name,
        raw_name=entity.raw_name,
        type=risk_type,
        subtype=subtype,
        status=status,
        severity=severity,
        confidence=confidence,
        channel=channel,
        formal_eligible=formal_eligible,
        claim_strength=claim_strength,
        location={"file": entity.file, "line": entity.line, "source_type": entity.source_type},
        generation_time=generation_time,
        audit_time=pypi_evidence.audit_time,
        time_view="as_of_audit_current_pypi",
        install_reachability=reachability,
        evidence_level=evidence_level,
        false_positive_filtered=False,
        evidence={
            "query_url": pypi_evidence.query_url,
            "exists_now": pypi_evidence.exists_now,
            "first_release_time": pypi_evidence.first_release_time,
            "latest_version": pypi_evidence.latest_version,
            "original_text": entity.original_text,
        },
        repair=repair,
    )
