"""Per-run human review decisions used by Phantom's report boundary.

The scan engine intentionally records every candidate finding.  This module
keeps the separate, small ledger that answers a different question: which
candidate findings did an auditor sign or reject for this specific run?

Playbooks and rejections remain the durable cross-run libraries.  The run
ledger only stores the decision metadata, never a second copy of the finding.
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from phantom.core.paths import run_reviews_path
from phantom.core.playbooks import PlaybookStore, finding_fingerprint
from phantom.core.rejections import RejectionStore
from phantom.utils.atomic import atomic_write_text


logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from pathlib import Path

_DECISIONS = {"signed", "rejected"}


class ReviewValidationError(ValueError):
    """Raised when a per-run review decision cannot be stored."""

    def __init__(self, message: str, *, code: str = "invalid_review") -> None:
        super().__init__(message)
        self.code = code


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _text(value: object, *, field: str, maximum: int, required: bool = True) -> str:
    if not isinstance(value, str):
        value = "" if value is None else str(value)
    value = value.strip()
    if required and not value:
        raise ReviewValidationError(f"{field} is required.", code="invalid_review")
    if len(value) > maximum:
        raise ReviewValidationError(f"{field} is too long.", code="invalid_review")
    return value


def _finding_fingerprint(finding: dict[str, Any]) -> str:
    target = str(finding.get("target") or "").strip()
    return finding_fingerprint(target, finding) if target else ""


def _matches_decision(
    decision: dict[str, Any], finding: dict[str, Any], fingerprint: str
) -> bool:
    candidate_id = str(finding.get("id") or "")
    return bool(
        (candidate_id and decision.get("candidate_id") == candidate_id)
        or (fingerprint and decision.get("fingerprint") == fingerprint)
    )


class RunReviewStore:
    """Thread-safe JSON ledger for one run's signed/rejected candidates."""

    def __init__(self, run_dir: Path) -> None:
        self.run_dir = run_dir
        self.path = run_reviews_path(run_dir)
        self._lock = threading.RLock()

    def list(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self._read()]

    def record_signed(
        self,
        *,
        finding: dict[str, Any],
        replay_id: object,
        auditor_name: object,
    ) -> dict[str, Any]:
        return self._record(
            finding=finding,
            decision="signed",
            replay_id=replay_id,
            auditor_name=auditor_name,
            reason=None,
        )

    def record_rejected(
        self,
        *,
        finding: dict[str, Any],
        reason: object,
        auditor_name: object,
    ) -> dict[str, Any]:
        return self._record(
            finding=finding,
            decision="rejected",
            replay_id=None,
            auditor_name=auditor_name,
            reason=reason,
        )

    def remove(self, *, finding: dict[str, Any]) -> bool:
        fingerprint = _finding_fingerprint(finding)
        with self._lock:
            records = self._read()
            remaining = [
                item for item in records if not _matches_decision(item, finding, fingerprint)
            ]
            if len(remaining) == len(records):
                return False
            self._write(remaining)
            return True

    def _record(
        self,
        *,
        finding: dict[str, Any],
        decision: str,
        replay_id: object,
        auditor_name: object,
        reason: object,
    ) -> dict[str, Any]:
        if decision not in _DECISIONS:
            raise ReviewValidationError("Unknown review decision.")
        candidate_id = _text(finding.get("id"), field="Finding id", maximum=160)
        fingerprint = _finding_fingerprint(finding)
        if not fingerprint:
            raise ReviewValidationError(
                "A finding target is required for review.", code="invalid_review"
            )
        auditor = _text(
            auditor_name,
            field="Auditor name",
            maximum=200,
            required=False,
        ) or "Local auditor"
        clean_replay_id = (
            _text(replay_id, field="Confirming replay id", maximum=160)
            if decision == "signed"
            else None
        )
        clean_reason = (
            _text(reason, field="Rejection reason", maximum=2_000)
            if decision == "rejected"
            else None
        )
        record = {
            "candidate_id": candidate_id,
            "fingerprint": fingerprint,
            "decision": decision,
            "auditor_name": auditor,
            "reviewed_at": _now(),
            "replay_id": clean_replay_id,
            "reason": clean_reason,
        }
        with self._lock:
            records = self._read()
            replaced = False
            for index, existing in enumerate(records):
                if _matches_decision(existing, finding, fingerprint):
                    records[index] = record
                    replaced = True
                    break
            if not replaced:
                records.append(record)
            self._write(records)
        return dict(record)

    def _read(self) -> list[dict[str, Any]]:
        if not self.path.is_file():
            return []
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ReviewValidationError(
                "The run review ledger could not be read.", code="review_ledger_invalid"
            ) from exc
        records = raw.get("reviews") if isinstance(raw, dict) else None
        if not isinstance(records, list):
            raise ReviewValidationError(
                "The run review ledger has an invalid format.", code="review_ledger_invalid"
            )
        return [dict(item) for item in records if isinstance(item, dict)]

    def _write(self, records: list[dict[str, Any]]) -> None:
        atomic_write_text(
            self.path,
            json.dumps({"version": 1, "reviews": records}, indent=2, ensure_ascii=False) + "\n",
        )


def _safe_global_records(store: Any) -> list[Any]:
    try:
        return list(store.list())
    except Exception:  # noqa: BLE001 - a broken optional registry must not hide candidates
        logger.warning("Could not read the global review registry", exc_info=True)
        return []


def _matches_global_rejection(
    record: Any, *, run_name: str, finding: dict[str, Any], fingerprint: str
) -> bool:
    source_run = str(getattr(record, "source_run_name", ""))
    source_id = str(getattr(record, "source_finding_id", ""))
    candidate_id = str(finding.get("id") or "")
    return bool(
        (source_run == run_name and source_id == candidate_id)
        or (fingerprint and str(getattr(record, "fingerprint", "")) == fingerprint)
    )


def _matches_current_signed_playbook(
    record: Any, *, run_name: str, finding: dict[str, Any], fingerprint: str
) -> bool:
    if str(getattr(record, "source_run_name", "")) != run_name:
        return False
    if not str(getattr(record, "confirmed_by_replay_id", "") or ""):
        return False
    source_id = str(getattr(record, "source_finding_id", ""))
    candidate_id = str(finding.get("id") or "")
    return bool(
        source_id == candidate_id
        or (fingerprint and str(getattr(record, "fingerprint", "")) == fingerprint)
    )


def review_snapshot(
    run_dir: Path,
    findings: list[dict[str, Any]],
    *,
    include_global_libraries: bool = True,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Return signed findings and the current per-run review summary.

    A replay-confirmed Playbook regression is already backed by a prior human
    signature, so a current ``playbook.status == reproduced`` marker counts as
    signed. Explicit run decisions always take precedence, and any rejection
    wins over an accidental duplicate signal.
    """
    candidates = [item for item in findings if isinstance(item, dict)]
    run_name = run_dir.name
    store = RunReviewStore(run_dir)
    try:
        explicit = store.list()
    except ReviewValidationError:
        # A corrupt review ledger must fail closed (nothing is treated as
        # signed) without interrupting the scan engine's candidate writes.
        logger.warning("Could not read the run review ledger", exc_info=True)
        explicit = []
    playbooks = _safe_global_records(PlaybookStore()) if include_global_libraries else []
    rejections = _safe_global_records(RejectionStore()) if include_global_libraries else []
    decisions: dict[str, dict[str, Any]] = {}

    for finding in candidates:
        candidate_id = str(finding.get("id") or "")
        if not candidate_id:
            continue
        fingerprint = _finding_fingerprint(finding)
        decision: dict[str, Any] | None = next(
            (item for item in explicit if _matches_decision(item, finding, fingerprint)),
            None,
        )
        if decision is None or decision.get("decision") == "signed":
            rejection = next(
                (
                    item
                    for item in rejections
                    if _matches_global_rejection(
                        item,
                        run_name=run_name,
                        finding=finding,
                        fingerprint=fingerprint,
                    )
                ),
                None,
            )
            if rejection is not None:
                decision = {
                    "decision": "rejected",
                    "auditor_name": str(getattr(rejection, "auditor_name", "Local auditor")),
                    "reviewed_at": str(getattr(rejection, "rejected_at", "")),
                    "reason": str(getattr(rejection, "reason", "")),
                }

        if decision is None:
            marker = finding.get("playbook")
            if (
                isinstance(marker, dict)
                and marker.get("status") == "reproduced"
                and str(marker.get("replay_id") or "")
            ):
                decision = {
                    "decision": "signed",
                    "auditor_name": "Playbook gate",
                    "reviewed_at": str(marker.get("replayed_at") or ""),
                    "replay_id": str(marker.get("replay_id")),
                }

        if decision is None:
            playbook = next(
                (
                    item
                    for item in playbooks
                    if _matches_current_signed_playbook(
                        item,
                        run_name=run_name,
                        finding=finding,
                        fingerprint=fingerprint,
                    )
                ),
                None,
            )
            if playbook is not None:
                decision = {
                    "decision": "signed",
                    "auditor_name": str(getattr(playbook, "auditor_name", "Local auditor")),
                    "reviewed_at": str(getattr(playbook, "updated_at", "")),
                    "replay_id": str(getattr(playbook, "confirmed_by_replay_id", "")),
                }

        if decision is not None:
            decisions[candidate_id] = decision

    signed = [
        finding
        for finding in candidates
        if decisions.get(str(finding.get("id") or ""), {}).get("decision") == "signed"
    ]
    signed_count = len(signed)
    rejected_count = sum(
        decision.get("decision") == "rejected" for decision in decisions.values()
    )
    candidate_count = len(candidates)
    pending_count = max(0, candidate_count - signed_count - rejected_count)
    snapshot = {
        "candidate_count": candidate_count,
        "signed_count": signed_count,
        "rejected_count": rejected_count,
        "pending_count": pending_count,
        "decided_count": signed_count + rejected_count,
        # A clean run and a run where every candidate was rejected are still
        # legitimate reports. Findings require one human decision first.
        "report_ready": candidate_count == 0 or signed_count + rejected_count > 0,
    }
    return signed, snapshot


def build_reviewed_scan_results(
    record: dict[str, Any],
    signed_findings: list[dict[str, Any]],
    review: dict[str, Any],
) -> dict[str, Any]:
    """Build report sections that cannot leak pending candidate details."""
    signed_count = int(review.get("signed_count") or 0)
    rejected_count = int(review.get("rejected_count") or 0)
    pending_count = int(review.get("pending_count") or 0)
    raw_targets = record.get("targets_info")
    targets = raw_targets if isinstance(raw_targets, list) else []
    target = " and ".join(
        str(item.get("original") or "")
        for item in targets
        if isinstance(item, dict) and item.get("original")
    ) or "the selected target"
    if signed_count:
        signed_lines = "\n".join(
            f"- **{item.get('title', 'Untitled finding')}** ("
            f"{str(item.get('severity', 'unknown')).upper()})"
            for item in signed_findings
        )
        executive = (
            f"This reviewed Phantom assessment of {target} contains "
            f"{signed_count} signed finding(s). "
            f"{rejected_count} candidate(s) were rejected and {pending_count} remain pending; "
            "pending and rejected candidates are excluded from this report.\n\n"
            "Signed findings:\n\n"
            f"{signed_lines}"
        )
    else:
        executive = (
            f"This Phantom assessment of {target} has no signed findings yet. "
            f"{rejected_count} candidate(s) were rejected and {pending_count} remain pending. "
            "No unreviewed candidate is included in this report."
        )

    technical = (
        "Only findings confirmed through the Phantom review workflow are included below. "
        "The detailed evidence, validation, replay metadata, and remediation "
        "for each signed finding "
        "follow in the Findings section."
    )
    methodology = (
        "Phantom collected candidate findings through its normal agent workflow. The auditor then "
        "reviewed the evidence and signed each included finding through a confirmed replay. "
        "Rejected and pending candidates remain available in the local Issues view but are not "
        "part "
        "of this customer-facing report."
    )
    recommendations = (
        "Prioritize remediation of the signed findings below and use Phantom replay to retest each "
        "fix. Resolve the remaining pending candidates in the Issues view before treating the "
        "assessment as fully triaged."
    )
    return {
        "scan_completed": True,
        "executive_summary": executive,
        "methodology": methodology,
        "technical_analysis": technical,
        "recommendations": recommendations,
        "success": True,
        "reviewed": True,
        "review_summary": dict(review),
    }


__all__ = [
    "ReviewValidationError",
    "RunReviewStore",
    "build_reviewed_scan_results",
    "review_snapshot",
]
