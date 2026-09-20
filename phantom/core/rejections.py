"""Durable Rejection records — the analyst's "this is a false positive" decision.

Rejecting a finding is the negative half of the signing line: signing a finding
saves a Playbook, while rejecting one records *why* it is not real. Rejections are
keyed by the same stable fingerprint Playbooks use, so the same false positive is
recognised across rescans and never re-triaged from scratch.

Unlike a Playbook, a Rejection deliberately does **not** require a structured
replay recipe — an analyst often rejects a finding precisely because it is bogus
or unreproducible. Rejections never invoke an LLM or create an agent.
"""

from __future__ import annotations

import copy
import json
import threading
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from phantom.core.paths import rejections_path

# Reuse the Playbook identity/validation helpers so a finding's rejection
# fingerprint is identical to its Playbook fingerprint (same finding == same id).
from phantom.core.playbooks import (
    MAX_AUDITOR_LENGTH,
    PlaybookValidationError,
    _json_copy,
    _now,
    _text,
    finding_fingerprint,
)
from phantom.core.targets import Target, normalize_base_url, target_urls_match
from phantom.utils.atomic import atomic_write_text


if TYPE_CHECKING:
    from pathlib import Path


MAX_REASON_LENGTH = 2_000


class RejectionValidationError(ValueError):
    """Raised when a Rejection record cannot be safely stored."""

    def __init__(self, message: str, *, code: str = "invalid_rejection") -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Rejection:
    id: str
    target_id: str
    target_name: str
    target_url: str
    auditor_name: str
    reason: str
    rejected_at: str
    updated_at: str
    source_run_name: str
    source_finding_id: str
    finding_title: str
    fingerprint: str
    finding: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "target_id": self.target_id,
            "target_name": self.target_name,
            "target_url": self.target_url,
            "auditor_name": self.auditor_name,
            "reason": self.reason,
            "rejected_at": self.rejected_at,
            "updated_at": self.updated_at,
            "source_run_name": self.source_run_name,
            "source_finding_id": self.source_finding_id,
            "finding_title": self.finding_title,
            "fingerprint": self.fingerprint,
            "finding": copy.deepcopy(self.finding),
        }


def _decode(raw: object) -> Rejection:
    if not isinstance(raw, dict):
        raise RejectionValidationError(
            "The Rejection registry contains an invalid record.", code="registry_invalid"
        )
    finding = _json_copy(raw.get("finding"), field="finding")
    return Rejection(
        id=str(raw.get("id") or ""),
        target_id=str(raw.get("target_id") or ""),
        target_name=str(raw.get("target_name") or ""),
        target_url=str(raw.get("target_url") or ""),
        auditor_name=str(raw.get("auditor_name") or ""),
        reason=str(raw.get("reason") or ""),
        rejected_at=str(raw.get("rejected_at") or ""),
        updated_at=str(raw.get("updated_at") or ""),
        source_run_name=str(raw.get("source_run_name") or ""),
        source_finding_id=str(raw.get("source_finding_id") or ""),
        finding_title=str(raw.get("finding_title") or ""),
        fingerprint=str(raw.get("fingerprint") or ""),
        finding=finding,
    )


class RejectionStore:
    """Thread-safe JSON-backed Rejection registry."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or rejections_path()
        self._lock = threading.RLock()

    def list(self, *, target_id: str | None = None) -> list[Rejection]:
        with self._lock:
            records = self._read()
            if target_id:
                records = [record for record in records if record.target_id == target_id]
            return sorted(records, key=lambda item: item.updated_at, reverse=True)

    def get(self, rejection_id: str) -> Rejection | None:
        normalized = str(rejection_id or "").strip()
        if not normalized:
            return None
        with self._lock:
            return next((item for item in self._read() if item.id == normalized), None)

    def create_from_finding(
        self,
        *,
        target: Target,
        reason: object,
        auditor_name: object,
        source_run_name: object,
        finding: object,
    ) -> tuple[Rejection, bool]:
        # The shared Playbook validation helpers raise ``PlaybookValidationError``;
        # re-raise as our own type so callers of the Rejection store see a
        # consistent error contract.
        try:
            clean_reason = _text(reason, field="Rejection reason", maximum=MAX_REASON_LENGTH)
            clean_auditor = _text(
                auditor_name,
                field="Auditor name",
                maximum=MAX_AUDITOR_LENGTH,
                default="Local auditor",
            )
            clean_run = _text(source_run_name, field="Source run", maximum=200)
            finding_copy = _json_copy(finding, field="finding")
            finding_id = _text(finding_copy.get("id"), field="Finding id", maximum=160)
            title = _text(finding_copy.get("title"), field="Finding title", maximum=500)
        except PlaybookValidationError as exc:
            raise RejectionValidationError(str(exc), code="invalid_rejection") from exc
        finding_target = finding_copy.get("target") or target.base_url
        try:
            normalized_finding_target, _ = normalize_base_url(finding_target)
        except ValueError as exc:
            raise RejectionValidationError(
                "The finding target is not a valid HTTP(S) URL.", code="target_mismatch"
            ) from exc
        if not target_urls_match(normalized_finding_target, target.base_url):
            raise RejectionValidationError(
                "The finding does not belong to the selected registered target.",
                code="target_mismatch",
            )
        fingerprint = finding_fingerprint(target.base_url, {**finding_copy, "title": title})
        with self._lock:
            records = self._read()
            existing = next(
                (
                    item
                    for item in records
                    if item.target_id == target.id
                    and (
                        (item.source_run_name == clean_run and item.source_finding_id == finding_id)
                        or item.fingerprint == fingerprint
                    )
                ),
                None,
            )
            if existing is not None:
                return existing, False
            now = _now()
            record = Rejection(
                id=f"rej_{uuid.uuid4().hex[:12]}",
                target_id=target.id,
                target_name=target.name,
                target_url=target.base_url,
                auditor_name=clean_auditor,
                reason=clean_reason,
                rejected_at=now,
                updated_at=now,
                source_run_name=clean_run,
                source_finding_id=finding_id,
                finding_title=title,
                fingerprint=fingerprint,
                finding=finding_copy,
            )
            records.append(record)
            self._write(records)
            return record, True

    def delete(self, rejection_id: str) -> bool:
        normalized = str(rejection_id or "").strip()
        with self._lock:
            records = self._read()
            remaining = [item for item in records if item.id != normalized]
            if len(remaining) == len(records):
                return False
            self._write(remaining)
            return True

    def _read(self) -> list[Rejection]:
        if not self.path.is_file():
            return []
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RejectionValidationError(
                "The Phantom Rejection registry could not be read. Fix or remove its "
                "rejections.json file.",
                code="registry_invalid",
            ) from exc
        records = raw.get("rejections") if isinstance(raw, dict) else None
        if not isinstance(records, list):
            raise RejectionValidationError(
                "The Phantom Rejection registry has an invalid format.", code="registry_invalid"
            )
        return [_decode(record) for record in records]

    def _write(self, records: list[Rejection]) -> None:
        payload = {"version": 1, "rejections": [record.as_dict() for record in records]}
        atomic_write_text(self.path, json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
