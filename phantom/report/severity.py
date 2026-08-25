"""Contextual severity calibration for demonstrated business impact."""

from __future__ import annotations

from typing import Any


_HIGH_IMPACT_TAGS = frozenset(
    {
        "account_takeover",
        "credential_compromise",
        "database_extraction",
        "financial_loss",
        "privilege_escalation",
        "remote_code_execution",
    }
)


def cvss_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def calibrate_severity(
    score: float,
    *,
    impact_tags: list[str],
    validation: dict[str, Any] | None,
) -> tuple[str, str]:
    """Return ``(severity, basis)`` with severity matching the CVSS score.

    Business-impact tags are retained as prioritization context, but they must
    not silently change the CVSS severity.  For example, a demonstrated
    limited-integrity transfer with CVSS 4.3 is still ``medium``; the report's
    impact tags and attack-path analysis carry the additional business context.
    Keeping the label and score aligned prevents reports such as ``HIGH / 4.3``.
    """
    base = cvss_severity(score)
    if not validation or validation.get("status") != "independently_validated":
        return base, "cvss_base_unverified_business_impact"

    high_tags = sorted(set(impact_tags) & _HIGH_IMPACT_TAGS)
    if high_tags:
        return base, "cvss_base_with_validated_impact:" + ",".join(high_tags)
    return base, "cvss_base"
