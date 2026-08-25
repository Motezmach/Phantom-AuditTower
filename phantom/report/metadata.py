"""Normalization helpers for structured finding metadata."""

from __future__ import annotations

import re
from typing import Any


_VALID_VALIDATION_STATUSES = frozenset(
    {"independently_validated", "single_agent", "not_validated", "ruled_out"}
)
_VALID_CONFIDENCES = frozenset({"confirmed", "probable", "contextual"})
_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
_PLACEHOLDER_ATTACK_ACTIONS = frozenset(
    {
        "access",
        "check",
        "compromise",
        "confirm",
        "execute",
        "exploit",
        "inject",
        "login",
        "read",
        "submit",
        "test",
        "verify",
        "write",
    }
)

_IMPACT_TAGS = frozenset(
    {
        "account_takeover",
        "credential_compromise",
        "database_extraction",
        "financial_loss",
        "privilege_escalation",
        "remote_code_execution",
        "sensitive_data_disclosure",
        "service_disruption",
    }
)


def normalize_validation(raw: Any) -> tuple[dict[str, Any] | None, list[str]]:
    """Validate independent-validation provenance without trusting free text."""
    if raw is None:
        return None, []
    if not isinstance(raw, dict):
        return None, ["validation must be an object"]

    status = str(raw.get("status") or "").strip().lower()
    if status not in _VALID_VALIDATION_STATUSES:
        return None, [
            "validation.status must be one of: "
            + ", ".join(sorted(_VALID_VALIDATION_STATUSES)),
        ]

    normalized: dict[str, Any] = {"status": status}
    for field in ("validator", "evidence", "notes"):
        value = raw.get(field)
        if value is not None and str(value).strip():
            normalized[field] = str(value).strip()

    attempts = raw.get("reproduction_count")
    if attempts is not None:
        try:
            attempts_int = int(attempts)
        except (TypeError, ValueError):
            return None, ["validation.reproduction_count must be an integer"]
        if attempts_int < 1 or attempts_int > 100:
            return None, ["validation.reproduction_count must be between 1 and 100"]
        normalized["reproduction_count"] = attempts_int

    errors: list[str] = []
    if status == "independently_validated":
        if not normalized.get("validator"):
            errors.append("validation.validator is required for independent validation")
        if not normalized.get("evidence"):
            errors.append("validation.evidence is required for independent validation")
        if "reproduction_count" not in normalized:
            errors.append("validation.reproduction_count is required for independent validation")
    return (normalized if not errors else None), errors


def normalize_impact_tags(raw: Any) -> tuple[list[str], list[str]]:
    """Normalize explicit business-impact facts supplied by the reporter."""
    if raw is None:
        return [], []
    if not isinstance(raw, list):
        return [], ["impact_tags must be an array of strings"]
    tags: list[str] = []
    errors: list[str] = []
    for value in raw:
        tag = str(value or "").strip().lower()
        if tag not in _IMPACT_TAGS:
            errors.append(
                f"Unsupported impact tag {tag!r}; use one of: {', '.join(sorted(_IMPACT_TAGS))}"
            )
        elif tag not in tags:
            tags.append(tag)
    return tags, errors


def infer_impact_tags(*texts: str | None) -> list[str]:
    """Infer only strong, demonstrated impact phrases for legacy callers.

    Explicit ``impact_tags`` remain preferred. The fallback is deliberately
    conservative and does not treat hypothetical phrases such as "could lead
    to" or "can be chained to" as demonstrated impact.
    """
    text = " ".join(str(value or "") for value in texts).lower()
    if not text:
        return []

    tags: list[str] = []
    patterns: tuple[str, str] = (
        (
            "account_takeover",
            r"(?:account takeover|account was taken over|successfully authenticated as|"
            r"logged in as (?:the )?(?:admin|administrator)|password.{0,40}used successfully)",
        ),
        (
            "financial_loss",
            r"(?:fund theft|theft of funds|funds were moved|moved .* out of .* into|"
            r"transferred .* into .* account|unauthorized financial movement)",
        ),
        (
            "database_extraction",
            r"(?:full database extraction|database extraction|arbitrary read of .* database|"
            r"extracted .* from the .* table)",
        ),
        (
            "remote_code_execution",
            r"(?:confirmed remote code execution|arbitrary command execution confirmed|"
            r"executed .* on the server)",
        ),
        ("privilege_escalation", r"(?:confirmed privilege escalation|privileges were escalated)"),
        (
            "service_disruption",
            r"(?:service was unavailable|service interruption was observed|"
            r"confirmed denial of service)",
        ),
    )
    for tag, pattern in patterns:
        if re.search(pattern, text, flags=re.IGNORECASE):
            tags.append(tag)
    return tags


_IMPACT_EVIDENCE_PATTERNS: dict[str, str] = {
    "account_takeover": (
        r"(?:account takeover|account was taken over|gained control of (?:the )?account|"
        r"logged in as (?:the )?(?:admin|administrator|victim)|"
        r"authenticated as (?:the )?(?:admin|administrator|victim)|"
        r"credentials? (?:were|was) compromised|password(?: was)? used successfully)"
    ),
    "credential_compromise": (
        r"(?:credentials? (?:were|was) compromised|password (?:was|were) exposed|"
        r"usable credential|secret (?:was|were) disclosed)"
    ),
    "database_extraction": (
        r"(?:database extraction|extracted .*?(?:database|table)|"
        r"dumped .*?(?:database|table)|rows? returned from .*?(?:database|table))"
    ),
    "financial_loss": (
        r"(?:fund theft|theft of funds|funds? (?:were|was) (?:moved|transferred|stolen)|"
        r"(?:successfully )?transferred .*?(?:account|balance)|"
        r"unauthori[sz]ed (?:financial )?(?:movement|transfer|payment)|"
        r"balances? changed)"
    ),
    "privilege_escalation": (
        r"(?:privilege escalation|privileges? were escalated|"
        r"elevated privileges|administrator access|admin privilege)"
    ),
    "remote_code_execution": (
        r"(?:remote code execution|arbitrary command execution|"
        r"command execution confirmed|executed .*? on the server)"
    ),
    "sensitive_data_disclosure": (
        r"(?:data (?:was|were) disclosed|disclos(?:ed|ure)|expos(?:ed|ure)|"
        r"leak(?:ed|age)|read .*?(?:account|record|secret|file)|"
        r"returned .*?(?:data|record|balance|transaction))"
    ),
    "service_disruption": (
        r"(?:service was unavailable|service interruption was observed|"
        r"confirmed denial of service)"
    ),
}


def validate_impact_evidence(
    impact_tags: list[str], *texts: str | None
) -> list[str]:
    """Reject high-impact labels that the supplied evidence does not support.

    This is intentionally a small semantic guard, not an NLP classifier. It
    catches the most damaging reporting error: treating a prerequisite or a
    hypothetical follow-on as a demonstrated business outcome. Callers may
    still omit a tag when the wording is ambiguous and retain the underlying
    finding at its CVSS-supported severity.
    """
    text = " ".join(str(value or "") for value in texts).lower()
    errors: list[str] = []
    for tag in dict.fromkeys(impact_tags):
        pattern = _IMPACT_EVIDENCE_PATTERNS.get(tag)
        if pattern and not re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL):
            errors.append(
                f"impact_tags includes {tag!r}, but the report text does not "
                "demonstrate that outcome; remove the tag or add concrete evidence",
            )
    return errors


def validate_mitre_mappings(
    mappings: list[dict[str, Any]], *texts: str | None
) -> list[str]:
    """Catch a few high-confidence ATT&CK mapping/category mismatches.

    Phantom does not attempt to ship a complete ATT&CK database in the report
    tool. These checks only prevent mappings that are commonly confused in web
    testing; the analyst remains responsible for selecting the technique and
    recording behavior-specific evidence.
    """
    text = " ".join(str(value or "") for value in texts).lower()
    errors: list[str] = []
    for mapping in mappings:
        technique_id = str(mapping.get("technique_id") or "").upper()
        if technique_id == "T1563" and (
            "csrf" in text or "cross-site request forgery" in text
        ) and not re.search(
            r"(?:session hijack|hijack(?:ed|ing) .*?session|cookie theft|"
            r"stole .*?(?:cookie|session token)|session token .*?stolen)",
            text,
            flags=re.IGNORECASE | re.DOTALL,
        ):
            errors.append(
                "MITRE T1563 requires demonstrated session hijacking or cookie/token theft; "
                "CSRF alone is not sufficient",
            )
        elif technique_id == "T1592" and "session fixation" in text:
            errors.append(
                "MITRE T1592 is host-information discovery and does not describe session fixation",
            )
        elif technique_id == "T1557" and re.search(
            r"(?:missing|without)\s+secure|secure\s+flag",
            text,
            flags=re.IGNORECASE,
        ) and not re.search(
            r"(?:man[- ]in[- ]the[- ]middle|mitm|intercept(?:ed|ion)|"
            r"cleartext|downgrade|traffic interception)",
            text,
            flags=re.IGNORECASE,
        ):
            errors.append(
                "MITRE T1557 requires demonstrated adversary-in-the-middle or "
                "traffic interception; a missing Secure flag alone is insufficient",
            )
    return errors


def normalize_attack_path(raw: Any) -> tuple[list[dict[str, Any]], list[str]]:
    """Normalize a short, evidence-backed sequence of attack-path steps."""
    if raw is None:
        return [], []
    if not isinstance(raw, list):
        return [], ["attack_path must be an array of step objects"]
    if len(raw) > 12:
        return [], ["attack_path cannot contain more than 12 steps"]

    normalized: list[dict[str, Any]] = []
    errors: list[str] = []
    for index, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            errors.append(f"attack_path[{index - 1}] must be an object")
            continue
        action = str(item.get("action") or "").strip()
        if not action:
            errors.append(f"attack_path[{index - 1}].action is required")
            continue
        action_key = re.sub(r"[^a-z0-9]+", " ", action.casefold()).strip()
        if action_key in _PLACEHOLDER_ATTACK_ACTIONS:
            errors.append(
                f"attack_path[{index - 1}].action must describe the concrete request, "
                "actor, or state change; placeholder verbs are not sufficient",
            )
        step: dict[str, Any] = {"order": index, "action": action}
        for field in ("finding_id", "evidence", "preconditions", "result", "notes"):
            value = item.get(field)
            if value is not None and str(value).strip():
                step[field] = str(value).strip()
        confidence = str(item.get("confidence") or "").strip().lower()
        if confidence:
            if confidence not in _VALID_CONFIDENCES:
                errors.append(
                    f"attack_path[{index - 1}].confidence must be one of: "
                    + ", ".join(sorted(_VALID_CONFIDENCES))
                )
            else:
                step["confidence"] = confidence
        if not step.get("evidence"):
            errors.append(f"attack_path[{index - 1}].evidence is required")
        normalized.append(step)
    return normalized, errors


def normalize_mitre_techniques(raw: Any) -> tuple[list[dict[str, Any]], list[str]]:
    """Normalize evidence-backed ATT&CK mappings for a finding or chain."""
    if raw is None:
        return [], []
    if not isinstance(raw, list):
        return [], ["mitre_techniques must be an array of objects"]
    if len(raw) > 8:
        return [], ["mitre_techniques cannot contain more than 8 mappings"]

    normalized: list[dict[str, Any]] = []
    errors: list[str] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            errors.append(f"mitre_techniques[{index}] must be an object")
            continue
        technique_id = str(item.get("technique_id") or "").strip().upper()
        technique_name = str(item.get("technique_name") or "").strip()
        evidence = str(item.get("evidence") or "").strip()
        confidence = str(item.get("confidence") or "").strip().lower()
        if not _TECHNIQUE_ID_RE.fullmatch(technique_id):
            errors.append(f"mitre_techniques[{index}].technique_id is invalid")
        if not technique_name:
            errors.append(f"mitre_techniques[{index}].technique_name is required")
        if not evidence:
            errors.append(f"mitre_techniques[{index}].evidence is required")
        if confidence not in _VALID_CONFIDENCES:
            errors.append(
                f"mitre_techniques[{index}].confidence must be one of: "
                + ", ".join(sorted(_VALID_CONFIDENCES))
            )
        mapping: dict[str, Any] = {
            "technique_id": technique_id,
            "technique_name": technique_name,
            "evidence": evidence,
            "confidence": confidence,
        }
        tactic = str(item.get("tactic") or "").strip()
        if tactic:
            mapping["tactic"] = tactic
        normalized.append(mapping)
    return normalized, errors


def infer_mitre_mappings(
    *texts: str | None,
    independently_validated: bool = False,
) -> list[dict[str, Any]]:
    """Add only high-confidence web mappings omitted by a reporting agent.

    ATT&CK is a behavior taxonomy, not a CWE replacement.  This deliberately
    covers a small set of unambiguous cases so a report cannot lose the useful
    mapping merely because a model left the optional field empty.  It does not
    assign a generic technique to every web weakness.
    """
    text = " ".join(str(value or "") for value in texts)
    lowered = text.casefold()
    confidence = "confirmed" if independently_validated else "probable"
    mappings: list[dict[str, Any]] = []

    if re.search(
        r"(?:sql\s*injection|sqli|cwe[- ]?89|unsanitized\s+sql|injected\s+predicate)",
        lowered,
    ):
        mappings.append(
            {
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "evidence": (
                    "SQL injection was demonstrated against a remotely reachable application "
                    "endpoint."
                ),
                "confidence": confidence,
            }
        )

    if re.search(
        r"(?:logged\s+in\s+as\s+(?:the\s+)?(?:admin|administrator)|"
        r"admin(?:istrator)?[- ]?(?:level|privileged)\s+(?:session|access)|"
        r"admin(?:istrator)?\s+token|(?:obtained|gained|granted|usable|full)\s+"
        r"(?:an?\s+)?administrator\s+access|account\s+takeover|valid\s+account)",
        lowered,
    ):
        mappings.append(
            {
                "technique_id": "T1078",
                "technique_name": "Valid Accounts",
                "tactic": "Defense Evasion / Persistence / Privilege Escalation / Initial Access",
                "evidence": (
                    "The demonstrated path produced a usable authenticated session or "
                    "administrator access."
                ),
                "confidence": confidence,
            }
        )

    has_path_traversal = re.search(
        r"(?:path traversal|directory traversal|cwe[- ]?22)", lowered
    )
    has_restricted_read = re.search(
        r"(?:read .*?(?:file|web\.xml)|file contents? disclosed|"
        r"restricted file|sensitive file contents?)",
        lowered,
    )
    if has_path_traversal and has_restricted_read:
        mappings.append(
            {
                "technique_id": "T1005",
                "technique_name": "Data from Local System",
                "tactic": "Collection",
                "evidence": "The path traversal proof read restricted file contents from the target host.",
                "confidence": confidence,
            }
        )

    return mappings
