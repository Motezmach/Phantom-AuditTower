"""Durable Playbook records for fast, repeatable finding validation.

Playbooks are deliberately separate from the scan engine.  Saving a finding
stores the approved finding snapshot and its structured HTTP replay recipe;
running that recipe later uses :class:`ReplayManager` and does not invoke an
LLM or create an agent.  This keeps the fast regression gate predictable while
leaving the existing scan path unchanged.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import threading
import uuid
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from phantom.core.paths import playbooks_path
from phantom.core.targets import Target, normalize_base_url, target_urls_match
from phantom.utils.atomic import atomic_write_text


if TYPE_CHECKING:
    from pathlib import Path


MAX_NAME_LENGTH = 160
MAX_AUDITOR_LENGTH = 120
MAX_HISTORY = 50
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


class PlaybookValidationError(ValueError):
    """Raised when a Playbook record cannot be safely stored."""

    def __init__(self, message: str, *, code: str = "invalid_playbook") -> None:
        super().__init__(message)
        self.code = code


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _text(value: object, *, field: str, maximum: int, default: str | None = None) -> str:
    if value is None and default is not None:
        value = default
    if not isinstance(value, str):
        raise PlaybookValidationError(f"{field} is required.")
    cleaned = value.strip()
    if not cleaned:
        raise PlaybookValidationError(f"{field} is required.")
    if len(cleaned) > maximum:
        raise PlaybookValidationError(f"{field} must be {maximum} characters or fewer.")
    if _CONTROL_CHARS.search(cleaned):
        raise PlaybookValidationError(f"{field} contains unsupported control characters.")
    return cleaned


def _json_copy(value: object, *, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PlaybookValidationError(f"{field} must be an object.")
    try:
        copied = copy.deepcopy(value)
        json.dumps(copied, ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise PlaybookValidationError(f"{field} contains values that cannot be stored.") from exc
    return copied


def finding_fingerprint(target_url: str, finding: dict[str, Any]) -> str:
    """Stable identity for the same finding across rescans with new IDs."""
    parts = [
        target_url.rstrip("/").casefold(),
        str(finding.get("title") or "").strip().casefold(),
        str(finding.get("method") or "").strip().casefold(),
        str(finding.get("endpoint") or "").strip().casefold(),
    ]
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Playbook:
    id: str
    name: str
    target_id: str
    target_name: str
    target_url: str
    auditor_name: str
    added_at: str
    updated_at: str
    source_run_name: str
    source_finding_id: str
    fingerprint: str
    finding: dict[str, Any]
    replay_spec: dict[str, Any]
    status: str = "active"
    replay_count: int = 0
    last_replay_at: str | None = None
    last_replay_status: str | None = None
    last_replay_reason: str | None = None
    replay_history: tuple[dict[str, Any], ...] = ()
    # Id of the confirmed replay the auditor watched reproduce before signing
    # this finding into the library. ``None`` for legacy records saved before
    # the signing line existed.
    confirmed_by_replay_id: str | None = None
    # Remediation lifecycle for this signed finding: "open" (still exploitable),
    # "fixed" (a retest could no longer reproduce it), or "reopened" (a later
    # retest reproduced it again -- a regression). Driven by retests in
    # ``record_replay``; owner/due_date are set by the analyst.
    remediation_status: str = "open"
    owner: str | None = None
    due_date: str | None = None
    fixed_at: str | None = None
    reopened_at: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "target_id": self.target_id,
            "target_name": self.target_name,
            "target_url": self.target_url,
            "auditor_name": self.auditor_name,
            "added_at": self.added_at,
            "updated_at": self.updated_at,
            "source_run_name": self.source_run_name,
            "source_finding_id": self.source_finding_id,
            "fingerprint": self.fingerprint,
            "finding": copy.deepcopy(self.finding),
            "replay_spec": copy.deepcopy(self.replay_spec),
            "status": self.status,
            "replay_count": self.replay_count,
            "last_replay_at": self.last_replay_at,
            "last_replay_status": self.last_replay_status,
            "last_replay_reason": self.last_replay_reason,
            "replay_history": [copy.deepcopy(item) for item in self.replay_history],
            "confirmed_by_replay_id": self.confirmed_by_replay_id,
            "remediation_status": self.remediation_status,
            "owner": self.owner,
            "due_date": self.due_date,
            "fixed_at": self.fixed_at,
            "reopened_at": self.reopened_at,
        }


def _decode(raw: object) -> Playbook:
    if not isinstance(raw, dict):
        raise PlaybookValidationError(
            "The Playbook registry contains an invalid record.", code="registry_invalid"
        )
    finding = _json_copy(raw.get("finding"), field="finding")
    replay_spec = _json_copy(raw.get("replay_spec"), field="replay_spec")
    history_raw = raw.get("replay_history", [])
    if not isinstance(history_raw, list) or not all(isinstance(item, dict) for item in history_raw):
        raise PlaybookValidationError(
            "The Playbook registry contains invalid replay history.", code="registry_invalid"
        )
    return Playbook(
        id=str(raw.get("id") or ""),
        name=str(raw.get("name") or ""),
        target_id=str(raw.get("target_id") or ""),
        target_name=str(raw.get("target_name") or ""),
        target_url=str(raw.get("target_url") or ""),
        auditor_name=str(raw.get("auditor_name") or ""),
        added_at=str(raw.get("added_at") or ""),
        updated_at=str(raw.get("updated_at") or ""),
        source_run_name=str(raw.get("source_run_name") or ""),
        source_finding_id=str(raw.get("source_finding_id") or ""),
        fingerprint=str(raw.get("fingerprint") or ""),
        finding=finding,
        replay_spec=replay_spec,
        status=str(raw.get("status") or "active"),
        replay_count=max(0, int(raw.get("replay_count") or 0)),
        last_replay_at=str(raw["last_replay_at"]) if raw.get("last_replay_at") else None,
        last_replay_status=(
            str(raw["last_replay_status"]) if raw.get("last_replay_status") else None
        ),
        last_replay_reason=(
            str(raw["last_replay_reason"]) if raw.get("last_replay_reason") else None
        ),
        replay_history=tuple(copy.deepcopy(item) for item in history_raw[-MAX_HISTORY:]),
        confirmed_by_replay_id=(
            str(raw["confirmed_by_replay_id"]) if raw.get("confirmed_by_replay_id") else None
        ),
        remediation_status=(
            str(raw["remediation_status"])
            if raw.get("remediation_status") in {"open", "fixed", "reopened"}
            else "open"
        ),
        owner=str(raw["owner"]) if raw.get("owner") else None,
        due_date=str(raw["due_date"]) if raw.get("due_date") else None,
        fixed_at=str(raw["fixed_at"]) if raw.get("fixed_at") else None,
        reopened_at=str(raw["reopened_at"]) if raw.get("reopened_at") else None,
    )


class PlaybookStore:
    """Thread-safe JSON-backed Playbook registry."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or playbooks_path()
        self._lock = threading.RLock()

    def list(self, *, target_id: str | None = None) -> list[Playbook]:
        with self._lock:
            records = self._read()
            if target_id:
                records = [record for record in records if record.target_id == target_id]
            return sorted(records, key=lambda item: item.updated_at, reverse=True)

    def get(self, playbook_id: str) -> Playbook | None:
        normalized = str(playbook_id or "").strip()
        if not normalized:
            return None
        with self._lock:
            return next((item for item in self._read() if item.id == normalized), None)

    def create_from_finding(
        self,
        *,
        target: Target,
        name: object,
        auditor_name: object,
        source_run_name: object,
        finding: object,
        confirmed_by_replay_id: object = None,
    ) -> tuple[Playbook, bool]:
        clean_name = _text(name, field="Playbook name", maximum=MAX_NAME_LENGTH)
        clean_auditor = _text(
            auditor_name,
            field="Auditor name",
            maximum=MAX_AUDITOR_LENGTH,
            default="Local auditor",
        )
        clean_run = _text(source_run_name, field="Source run", maximum=200)
        # The confirming replay id is optional (older callers and legacy
        # records omit it) but, when present, records which replay the auditor
        # watched reproduce before signing.
        clean_replay_id = (
            _text(confirmed_by_replay_id, field="Confirming replay id", maximum=120)
            if confirmed_by_replay_id not in (None, "")
            else None
        )
        finding_copy = _json_copy(finding, field="finding")
        finding_id = _text(finding_copy.get("id"), field="Finding id", maximum=160)
        title = _text(finding_copy.get("title"), field="Finding title", maximum=500)
        finding_target = finding_copy.get("target") or target.base_url
        try:
            normalized_finding_target, _ = normalize_base_url(finding_target)
        except ValueError as exc:
            raise PlaybookValidationError(
                "The finding target is not a valid HTTP(S) URL.", code="target_mismatch"
            ) from exc
        if not target_urls_match(normalized_finding_target, target.base_url):
            raise PlaybookValidationError(
                "The finding does not belong to the selected registered target.",
                code="target_mismatch",
            )

        raw_spec = finding_copy.get("replay_spec")
        # Keep the registry usable for dashboard metadata and migrations even
        # when replay/LLM dependencies are not imported yet.
        from phantom.core.replay import normalize_replay_spec  # noqa: PLC0415

        normalized_spec, errors = normalize_replay_spec(
            raw_spec,
            finding_target=target.base_url,
        )
        if normalized_spec is None or errors:
            raise PlaybookValidationError(
                "; ".join(errors) or "This finding has no valid structured replay recipe.",
                code="replay_unavailable",
            )
        finding_copy["replay_spec"] = normalized_spec
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
                # Legacy Playbooks predate replay-backed signing. A newly
                # confirmed replay upgrades that record in place so its
                # history and stable identity are preserved.
                if clean_replay_id and not existing.confirmed_by_replay_id:
                    now = _now()
                    upgraded = replace(
                        existing,
                        name=clean_name,
                        target_name=target.name,
                        target_url=target.base_url,
                        auditor_name=clean_auditor,
                        updated_at=now,
                        source_run_name=clean_run,
                        source_finding_id=finding_id,
                        fingerprint=fingerprint,
                        finding=finding_copy,
                        replay_spec=normalized_spec,
                        confirmed_by_replay_id=clean_replay_id,
                    )
                    records = [upgraded if item.id == existing.id else item for item in records]
                    self._write(records)
                    return upgraded, True
                return existing, False
            now = _now()
            record = Playbook(
                id=f"pb_{uuid.uuid4().hex[:12]}",
                name=clean_name,
                target_id=target.id,
                target_name=target.name,
                target_url=target.base_url,
                auditor_name=clean_auditor,
                added_at=now,
                updated_at=now,
                source_run_name=clean_run,
                source_finding_id=finding_id,
                fingerprint=fingerprint,
                finding=finding_copy,
                replay_spec=normalized_spec,
                confirmed_by_replay_id=clean_replay_id,
            )
            records.append(record)
            self._write(records)
            return record, True

    def delete(self, playbook_id: str) -> bool:
        normalized = str(playbook_id or "").strip()
        with self._lock:
            records = self._read()
            remaining = [item for item in records if item.id != normalized]
            if len(remaining) == len(records):
                return False
            self._write(remaining)
            return True

    def record_replay(
        self,
        playbook_id: str,
        *,
        status: str,
        reason: str | None = None,
        replay_id: str | None = None,
        run_name: str | None = None,
        completed_steps: int | None = None,
        artifact_path: str | None = None,
    ) -> Playbook | None:
        if status not in {"confirmed", "not_reproduced", "inconclusive", "blocked", "failed"}:
            raise PlaybookValidationError(
                "Invalid Playbook replay status.", code="invalid_replay_status"
            )
        with self._lock:
            records = self._read()
            now = _now()
            updated: Playbook | None = None
            output: list[Playbook] = []
            for item in records:
                if item.id != playbook_id:
                    output.append(item)
                    continue
                history_item: dict[str, Any] = {
                    "replayed_at": now,
                    "status": status,
                    "reason": reason,
                }
                if replay_id:
                    history_item["replay_id"] = replay_id
                if run_name:
                    history_item["run_name"] = run_name
                if completed_steps is not None:
                    history_item["completed_steps"] = completed_steps
                if artifact_path:
                    history_item["artifact_path"] = artifact_path
                # Proof of fixes: a retest that no longer reproduces the saved
                # attack marks it fixed; one that reproduces it again after it
                # was fixed reopens it (a regression). Inconclusive/blocked/
                # failed retests can't conclude anything, so they leave it be.
                remediation = item.remediation_status
                fixed_at = item.fixed_at
                reopened_at = item.reopened_at
                if status == "not_reproduced" and remediation != "fixed":
                    remediation, fixed_at = "fixed", now
                elif status == "confirmed" and remediation == "fixed":
                    remediation, reopened_at = "reopened", now
                updated = replace(
                    item,
                    updated_at=now,
                    replay_count=item.replay_count + 1,
                    last_replay_at=now,
                    last_replay_status=status,
                    last_replay_reason=reason,
                    replay_history=(*item.replay_history, history_item)[-MAX_HISTORY:],
                    remediation_status=remediation,
                    fixed_at=fixed_at,
                    reopened_at=reopened_at,
                )
                output.append(updated)
            if updated is None:
                return None
            self._write(output)
            return updated

    def set_remediation(
        self,
        playbook_id: str,
        *,
        owner: object = None,
        due_date: object = None,
    ) -> Playbook | None:
        """Set the analyst-owned remediation metadata (owner and due date).

        The lifecycle status itself (open/fixed/reopened) is driven by retests in
        :meth:`record_replay`, not set here. Empty values clear the field.
        """

        def _opt(value: object, *, field: str, maximum: int) -> str | None:
            if value is None:
                return None
            text = str(value).strip()
            if not text:
                return None
            if len(text) > maximum:
                raise PlaybookValidationError(f"{field} is too long.", code="invalid_remediation")
            if _CONTROL_CHARS.search(text):
                raise PlaybookValidationError(
                    f"{field} contains unsupported control characters.", code="invalid_remediation"
                )
            return text

        clean_owner = _opt(owner, field="Owner", maximum=200)
        clean_due = _opt(due_date, field="Due date", maximum=40)
        with self._lock:
            records = self._read()
            updated: Playbook | None = None
            output: list[Playbook] = []
            for item in records:
                if item.id != playbook_id:
                    output.append(item)
                    continue
                updated = replace(item, updated_at=_now(), owner=clean_owner, due_date=clean_due)
                output.append(updated)
            if updated is None:
                return None
            self._write(output)
            return updated

    def _read(self) -> list[Playbook]:
        if not self.path.is_file():
            return []
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PlaybookValidationError(
                "The Phantom Playbook registry could not be read. Fix or remove its "
                "playbooks.json file.",
                code="registry_invalid",
            ) from exc
        records = raw.get("playbooks") if isinstance(raw, dict) else None
        if not isinstance(records, list):
            raise PlaybookValidationError(
                "The Phantom Playbook registry has an invalid format.", code="registry_invalid"
            )
        return [_decode(record) for record in records]

    def _write(self, records: list[Playbook]) -> None:
        payload = {"version": 1, "playbooks": [record.as_dict() for record in records]}
        atomic_write_text(self.path, json.dumps(payload, indent=2, ensure_ascii=False) + "\n")


__all__ = [
    "Playbook",
    "PlaybookStore",
    "PlaybookValidationError",
    "finding_fingerprint",
]
