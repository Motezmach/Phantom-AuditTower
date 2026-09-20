"""ASVS 5.0 honest-coverage mapping.

Translates Phantom's *log-derived* evidence — the coverage ledger and the signed
findings — into an OWASP ASVS 5.0.0 coverage statement: every requirement is
marked ``failed`` / ``checked`` / ``not_tested``, and every ``not_tested`` carries
a reason. This is the README's "honest coverage" pillar.

Design invariants (do not break):
- Coverage is computed here from execution artefacts, never authored by the LLM
  (README Idea 4 / section 5.5). The only inputs are the coverage ledger and the
  signed findings.
- Black-box honesty: a requirement is ``checked`` only when its area was actually
  exercised with terminal evidence; otherwise it is ``not_tested`` with a reason.
  Absence of a finding is never silently reported as a pass.
- The ASVS text and CWE mappings are bundled offline under ``data/asvs`` (no
  network at runtime); section 5.1 data residency is preserved.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any


_DATA_DIR = Path(__file__).parent / "data" / "asvs"
ASVS_VERSION = "5.0.0"

STATUS_FAILED = "failed"
STATUS_CHECKED = "checked"
STATUS_NOT_TESTED = "not_tested"

# Coverage-ledger categories / discovery lanes -> ASVS 5.0 chapters they exercise.
# Curated, defensible, and the human-owned part of the mapping.
CATEGORY_TO_CHAPTERS: dict[str, tuple[str, ...]] = {
    "authentication": ("V6", "V7", "V9"),
    "session": ("V7",),
    "authorization": ("V8", "V4"),
    "injection": ("V1", "V2"),
    "input_validation": ("V1", "V2"),
    "input_surface": ("V1", "V2"),
    "business_logic": ("V2",),
    "state_change": ("V2", "V3"),
    "client_side": ("V3",),
    "api": ("V4",),
    "api_surface": ("V4",),
    "server_side": ("V5", "V15"),
    "server_side_fetch": ("V5", "V15"),
    "information_disclosure": ("V14", "V16"),
    "error_disclosure": ("V16",),
    "technology": ("V12",),
}

_SOURCE_REVIEW_REASON = (
    "Requires source-code or configuration review — outside the black-box dynamic scope."
)

# Chapters with no dynamic discovery lane: state honestly *why* they are untested.
NO_LANE_CHAPTER_REASONS: dict[str, str] = {
    "V10": "Not applicable — no OAuth 2.0 / OIDC flow was observed within the approved scope.",
    "V11": (
        "Requires source-code or configuration review — cryptographic implementation "
        "cannot be fully verified through black-box dynamic testing."
    ),
    "V13": (
        "Requires configuration and deployment review, which was outside the "
        "black-box dynamic scope."
    ),
    "V17": "Not applicable — no WebRTC surface was observed within the approved scope.",
}

# Fallback for finding CWEs the official ASVS index does not resolve: map to the
# specific representative requirement(s), never a whole chapter, to avoid inflating
# failures. Curated and defensible for the CWEs Phantom actually emits.
CWE_REQ_FALLBACK: dict[int, tuple[str, ...]] = {
    863: ("V8.2.1", "V8.3.1"),    # incorrect authorization -> function-level + trusted layer
    248: ("V16.5.3", "V16.5.4"),  # uncaught exception -> fail gracefully + last-resort handler
    404: ("V16.3.3",),            # unaudited destructive action -> log security events
}

_TERMINAL_EXERCISED = frozenset({"confirmed", "ruled_out"})
_ATTEMPTED_INCOMPLETE = frozenset({"blocked", "not_tested", "planned", "running"})

_STATUS_LABEL = {
    STATUS_FAILED: "Failed",
    STATUS_CHECKED: "Checked",
    STATUS_NOT_TESTED: "Not tested",
}


@lru_cache(maxsize=1)
def load_asvs() -> dict[str, Any]:
    """Load the bundled ASVS 5.0.0 requirement set."""
    return json.loads((_DATA_DIR / f"asvs-{ASVS_VERSION}.json").read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def load_cwe_index() -> dict[str, Any]:
    """Load the bundled CWE <-> ASVS 5.0.0 requirement index."""
    return json.loads((_DATA_DIR / f"asvs-{ASVS_VERSION}-cwe.json").read_text(encoding="utf-8"))


def _cwe_number(value: Any) -> int | None:
    """Extract an integer CWE id from 'CWE-639', '639', or 639."""
    if value is None:
        return None
    match = re.search(r"(\d+)", str(value))
    return int(match.group(1)) if match else None


def _mapped_chapters() -> set[str]:
    chapters: set[str] = set()
    for chs in CATEGORY_TO_CHAPTERS.values():
        chapters.update(chs)
    return chapters


def _exercised_and_attempted(
    coverage_items: list[dict[str, Any]],
) -> tuple[set[str], set[str]]:
    """Split coverage-ledger entries into exercised vs attempted-but-incomplete chapters."""
    exercised: set[str] = set()
    attempted: set[str] = set()
    for item in coverage_items:
        chapters = CATEGORY_TO_CHAPTERS.get(str(item.get("category", "")).strip().lower())
        if not chapters:
            continue
        status = str(item.get("status", "")).strip().lower()
        if status in _TERMINAL_EXERCISED:
            exercised.update(chapters)
        elif status in _ATTEMPTED_INCOMPLETE:
            attempted.update(chapters)
    return exercised, attempted


def _map_findings(
    findings: list[dict[str, Any]], by_cwe: dict[str, list[str]], valid_req_ids: set[str]
) -> tuple[dict[str, list[str]], list[dict[str, Any]]]:
    """Map signed findings to specific requirements by CWE (official index, then fallback)."""
    req_findings: dict[str, list[str]] = {}
    unmapped: list[dict[str, Any]] = []
    for finding in findings:
        label = str(finding.get("id") or finding.get("title") or "finding")
        cwe = _cwe_number(finding.get("cwe"))
        if cwe is None:
            unmapped.append({"finding": label, "reason": "no CWE on finding"})
            continue
        targets = by_cwe.get(str(cwe)) or CWE_REQ_FALLBACK.get(cwe)
        if not targets:
            unmapped.append({"finding": label, "reason": f"CWE-{cwe} has no ASVS 5.0 requirement"})
            continue
        for rid in targets:
            if rid in valid_req_ids:
                req_findings.setdefault(rid, []).append(label)
    return req_findings, unmapped


def _resolve_status(
    chapter: str,
    finding_ids: list[str],
    exercised: set[str],
    attempted: set[str],
    mapped_chapters: set[str],
) -> tuple[str, str]:
    """Decide a single requirement's status and reason from the evidence sets."""
    if finding_ids:
        return STATUS_FAILED, ""
    if chapter in exercised:
        return STATUS_CHECKED, ""
    if chapter not in mapped_chapters:
        return STATUS_NOT_TESTED, NO_LANE_CHAPTER_REASONS.get(chapter, _SOURCE_REVIEW_REASON)
    if chapter in attempted:
        return (
            STATUS_NOT_TESTED,
            "Testing of this area did not complete in this run (blocked or time-bounded).",
        )
    return STATUS_NOT_TESTED, "Not exercised — no in-scope dynamic test reached this requirement."


def build_asvs_coverage(
    findings: list[dict[str, Any]],
    coverage_items: list[dict[str, Any]] | None = None,
    *,
    scope_note: str | None = None,
) -> dict[str, Any]:
    """Compute an ASVS 5.0 coverage statement from findings + the coverage ledger.

    ``findings`` are the *signed* findings (each with a ``cwe`` and a display id).
    ``coverage_items`` are coverage-ledger entries (each with ``category`` and
    ``status``). Both are execution artefacts; nothing here is model-authored.
    """
    asvs = load_asvs()
    requirements: list[dict[str, Any]] = asvs["requirements"]
    valid_req_ids = {r["req_id"] for r in requirements}
    mapped_chapters = _mapped_chapters()

    exercised, attempted = _exercised_and_attempted(coverage_items or [])
    req_findings, unmapped = _map_findings(
        findings, load_cwe_index().get("by_cwe", {}), valid_req_ids
    )

    per_req: list[dict[str, Any]] = []
    for req in requirements:
        finding_ids = list(dict.fromkeys(req_findings.get(req["req_id"], [])))
        status, reason = _resolve_status(
            req["chapter_id"], finding_ids, exercised, attempted, mapped_chapters
        )
        if status == STATUS_NOT_TESTED and scope_note:
            reason = f"{reason} {scope_note}".strip()
        per_req.append({
            "req_id": req["req_id"], "chapter_id": req["chapter_id"],
            "chapter_name": req["chapter_name"], "section_id": req["section_id"],
            "level": req["level"], "description": req["description"],
            "status": status, "reason": reason, "findings": finding_ids,
        })

    by_chapter: list[dict[str, Any]] = []
    for ch in asvs["chapters"]:
        rows = [r for r in per_req if r["chapter_id"] == ch["id"]]
        by_chapter.append({
            "chapter_id": ch["id"], "name": ch["name"], "total": len(rows),
            "failed": sum(r["status"] == STATUS_FAILED for r in rows),
            "checked": sum(r["status"] == STATUS_CHECKED for r in rows),
            "not_tested": sum(r["status"] == STATUS_NOT_TESTED for r in rows),
        })
    summary = {
        "total": len(per_req),
        "failed": sum(r["status"] == STATUS_FAILED for r in per_req),
        "checked": sum(r["status"] == STATUS_CHECKED for r in per_req),
        "not_tested": sum(r["status"] == STATUS_NOT_TESTED for r in per_req),
    }
    return {
        "standard": "OWASP ASVS", "version": ASVS_VERSION, "summary": summary,
        "by_chapter": by_chapter, "requirements": per_req, "unmapped_findings": unmapped,
    }


def render_asvs_markdown(coverage: dict[str, Any]) -> str:
    """Render an ASVS coverage section (report-ready markdown)."""
    s = coverage["summary"]
    lines: list[str] = [
        f"## ASVS {coverage['version']} Coverage",
        "",
        (
            f"Assessed against the OWASP Application Security Verification Standard "
            f"{coverage['version']} ({s['total']} requirements). **{s['failed']} failed**, "
            f"**{s['checked']} checked** (actively tested, no issue observed in dynamic testing), "
            f"**{s['not_tested']} not tested**. Coverage is computed from the execution ledger "
            "and the signed findings, not authored by the testing engine. `Checked` reflects "
            "dynamic black-box testing; some requirements additionally warrant source-code or "
            "configuration review for full ASVS verification."
        ),
        "",
        "| Chapter | Failed | Checked | Not tested |",
        "|---|---:|---:|---:|",
    ]
    lines.extend(
        f"| {ch['chapter_id']} {ch['name']} | {ch['failed']} "
        f"| {ch['checked']} | {ch['not_tested']} |"
        for ch in coverage["by_chapter"]
    )
    lines.append("")

    failed = [r for r in coverage["requirements"] if r["status"] == STATUS_FAILED]
    if failed:
        lines.extend(["### Failed requirements", ""])
        for r in failed:
            evidence = f"  \n  _Evidence:_ {', '.join(r['findings'])}" if r["findings"] else ""
            lines.append(f"- **{r['req_id']}** (L{r['level']}) — {r['description']}{evidence}")
        lines.append("")

    # Not-tested, grouped by reason (the honest-coverage payoff).
    grouped: dict[str, list[str]] = {}
    for r in coverage["requirements"]:
        if r["status"] == STATUS_NOT_TESTED:
            grouped.setdefault(r["reason"], []).append(r["req_id"])
    if grouped:
        lines.extend(["### Not tested — and why", ""])
        for reason, rids in sorted(grouped.items(), key=lambda kv: (-len(kv[1]), kv[0])):
            extra = f" (+{len(rids) - 12} more)" if len(rids) > 12 else ""
            lines.append(f"- _{reason}_  \n  {', '.join(rids[:12])}{extra}")
        lines.append("")
    return "\n".join(lines)
