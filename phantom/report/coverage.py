"""Coverage-ledger helpers used by Phantom's orchestration quality gates."""

from __future__ import annotations

import hashlib
import re
from typing import Any


COVERAGE_STATUSES = frozenset(
    {"planned", "running", "confirmed", "ruled_out", "blocked", "not_tested"}
)
COVERAGE_TERMINAL_STATUSES = frozenset({"confirmed", "ruled_out", "blocked", "not_tested"})
COVERAGE_PRIORITIES = frozenset({"required", "recommended", "optional"})

_BROAD_TASK_MARKERS = (
    "recon",
    "reconnaissance",
    "attack surface",
    "map the",
    "map all",
    "enumerate",
    "discover",
    "systematic",
    "comprehensive",
    "all endpoints",
    "all vulnerabilities",
)


def _clean(value: Any) -> str:
    return " ".join(str(value or "").split()).strip()


def stable_coverage_id(*, title: str, surface: str, category: str) -> str:
    """Return a stable, non-target-specific id for a planned test item."""
    source = "|".join(_clean(value).casefold() for value in (title, surface, category))
    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()[:12]
    return f"cov-{digest}"


def normalize_coverage_item(raw: dict[str, Any], *, agent_id: str | None = None) -> dict[str, Any]:
    """Normalize one model-supplied coverage item without inventing evidence."""
    title = _clean(raw.get("title"))
    surface = _clean(raw.get("surface"))
    category = _clean(raw.get("category")).casefold()
    if not title:
        raise ValueError("coverage item title is required")
    if not surface:
        raise ValueError("coverage item surface is required")
    if not category:
        raise ValueError("coverage item category is required")

    status = _clean(raw.get("status") or "planned").casefold()
    if status not in COVERAGE_STATUSES:
        raise ValueError(f"invalid coverage status: {status}")
    priority = _clean(raw.get("priority") or "required").casefold()
    if priority not in COVERAGE_PRIORITIES:
        raise ValueError(f"invalid coverage priority: {priority}")

    coverage_id = _clean(raw.get("coverage_id")) or stable_coverage_id(
        title=title,
        surface=surface,
        category=category,
    )
    if not re.fullmatch(r"cov-[a-f0-9]{12}", coverage_id):
        raise ValueError("coverage_id must be a generated value such as cov-0123456789ab")

    families = raw.get("test_families") or []
    if not isinstance(families, list):
        raise ValueError("test_families must be an array")
    test_families = [_clean(item).casefold() for item in families if _clean(item)]
    if not test_families:
        raise ValueError("coverage item must declare at least one test family")

    item: dict[str, Any] = {
        "coverage_id": coverage_id,
        "title": title,
        "category": category,
        "surface": surface,
        "test_families": list(dict.fromkeys(test_families)),
        "priority": priority,
        "status": status,
    }
    for field in ("evidence", "notes"):
        value = _clean(raw.get(field))
        if value:
            item[field] = value
    if agent_id:
        item["updated_by"] = agent_id
    return item


def validate_agent_assignment(
    *,
    agent_type: str | None,
    task: str,
    coverage_ids: list[str],
    existing_items: list[dict[str, Any]],
) -> str | None:
    """Prevent specialized roles from being used as broad discovery agents."""
    if agent_type is None:
        return None

    known_ids = {
        str(item.get("coverage_id"))
        for item in existing_items
        if isinstance(item, dict) and item.get("coverage_id")
    }
    unknown = sorted(set(coverage_ids) - known_ids)
    if unknown:
        return f"Unknown coverage_id(s): {unknown}. Record the coverage item before assigning it."

    if agent_type in {"web_validator", "payload_crafter", "reporting_analyst"} and not coverage_ids:
        return (
            f"agent_type={agent_type} requires at least one concrete coverage_id; "
            "specialized agents cannot be used for unbounded discovery"
        )
    if agent_type == "web_validator" and len(coverage_ids) > 3:
        return "web_validator may cover at most three closely related coverage items"

    lowered_task = _clean(task).casefold()
    if agent_type in {"web_validator", "payload_crafter", "reporting_analyst"}:
        broad = [marker for marker in _BROAD_TASK_MARKERS if marker in lowered_task]
        if broad and agent_type != "reporting_analyst":
            return (
                f"agent_type={agent_type} is narrowly scoped, but the task is broad "
                f"({', '.join(broad[:3])}); use a default discovery agent first"
            )
    return None


def coverage_quality_errors(items: list[dict[str, Any]] | None = None) -> list[str]:
    """Return blocking gaps without requiring an exact vulnerability count."""
    if not items:
        return [
            "Coverage ledger is empty. Record the discovered attack-surface test "
            "obligations before finishing the scan."
        ]

    errors: list[str] = []
    unresolved = [
        item
        for item in items
        if str(item.get("priority", "required")).casefold() == "required"
        and str(item.get("status", "planned")).casefold() not in COVERAGE_TERMINAL_STATUSES
    ]
    if unresolved:
        preview = ", ".join(
            f"{item.get('coverage_id', 'unknown')} ({item.get('title', 'untitled')})"
            for item in unresolved[:8]
        )
        suffix = " ..." if len(unresolved) > 8 else ""
        errors.append(
            "Required coverage items are unresolved: "
            f"{preview}{suffix}. Finish, rule out, block with a reason, or explicitly "
            "mark the item not_tested before completing the scan."
        )
    missing_disposition = [
        item
        for item in items
        if str(item.get("status", "planned")).casefold() in COVERAGE_TERMINAL_STATUSES
        and not (_clean(item.get("evidence")) or _clean(item.get("notes")))
    ]
    if missing_disposition:
        preview = ", ".join(
            str(item.get("coverage_id", "unknown")) for item in missing_disposition[:8]
        )
        errors.append(
            "Terminal coverage items require evidence or a reason: "
            f"{preview}. Do not mark coverage complete without documenting the result."
        )
    return errors


def baseline_coverage_items(targets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return a small, target-agnostic baseline for the supported scan types."""
    baselines: dict[str, list[tuple[str, str, list[str], str]]] = {
        "web_application": [
            ("Surface mapping", "reconnaissance", ["recon"], "required"),
            (
                "Authentication and session controls",
                "authentication",
                ["authentication", "session"],
                "required",
            ),
            (
                "Authorization and object access",
                "authorization",
                ["idor", "broken_function_level_authorization"],
                "required",
            ),
            (
                "Input handling and injection",
                "input_validation",
                ["xss", "sql_injection"],
                "required",
            ),
            ("State-changing workflows", "business_logic", ["business_logic", "csrf"], "required"),
            (
                "Server-side integrations and file access",
                "server_side",
                ["ssrf", "path_traversal_lfi_rfi"],
                "required",
            ),
            ("Technology-specific surfaces", "technology", ["technology_detection"], "recommended"),
        ],
        "api_spec": [
            ("API surface and schema mapping", "reconnaissance", ["api_mapping"], "required"),
            (
                "API authentication and authorization",
                "authorization",
                ["authentication", "idor", "broken_function_level_authorization"],
                "required",
            ),
            (
                "API input validation",
                "input_validation",
                ["sql_injection", "xss", "api_abuse"],
                "required",
            ),
            (
                "API workflows and abuse controls",
                "business_logic",
                ["business_logic", "api_abuse"],
                "required",
            ),
        ],
        "repository": [
            (
                "Source and dependency security mapping",
                "source_review",
                ["source_aware_sast", "dependency_cve_scanning"],
                "required",
            ),
            (
                "Authentication and authorization code paths",
                "authorization",
                ["source_aware_sast"],
                "required",
            ),
            (
                "Input, output, and dangerous-sink review",
                "input_validation",
                ["source_aware_sast"],
                "required",
            ),
        ],
        "local_code": [
            ("Local source security mapping", "source_review", ["source_aware_sast"], "required"),
            (
                "Authentication and authorization code paths",
                "authorization",
                ["source_aware_sast"],
                "required",
            ),
            (
                "Input, output, and dangerous-sink review",
                "input_validation",
                ["source_aware_sast"],
                "required",
            ),
        ],
    }
    result: list[dict[str, Any]] = []
    for target in targets:
        if not isinstance(target, dict):
            continue
        target_type = _clean(target.get("type")) or "unknown"
        target_label = _clean(target.get("original")) or target_type
        for title, category, test_families, priority in baselines.get(
            target_type,
            [("Target surface mapping", "reconnaissance", ["recon"], "required")],
        ):
            result.append(
                {
                    "title": title,
                    "category": category,
                    "surface": target_label,
                    "test_families": test_families,
                    "priority": priority,
                    "status": "planned",
                }
            )
    return result
