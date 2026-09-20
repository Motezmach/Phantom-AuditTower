"""Tests for Phantom's durable Rejection registry (the negative half of the signing line)."""

from __future__ import annotations

from phantom.core.rejections import RejectionStore, RejectionValidationError
from phantom.core.targets import TargetStore


def _finding(
    *, finding_id: str = "vuln-0001", title: str = "Reflected XSS on /search"
) -> dict[str, object]:
    return {
        "id": finding_id,
        "title": title,
        "target": "http://demo.test",
        "endpoint": "/search",
        "method": "GET",
        "severity": "medium",
        "description": "A finding the analyst judged to be a false positive.",
    }


def test_rejection_is_durable_and_deduplicated_across_rescans(tmp_path) -> None:
    targets = TargetStore(tmp_path / "targets.json")
    target = targets.create(name="Demo", base_url="http://demo.test")
    store = RejectionStore(tmp_path / "rejections.json")

    entry, created = store.create_from_finding(
        target=target,
        reason="Reflection is HTML-encoded; not exploitable.",
        auditor_name="Auditor",
        source_run_name="demo_0001",
        finding=_finding(),
    )

    assert created is True
    assert entry.id.startswith("rej_")
    assert entry.reason.startswith("Reflection is HTML-encoded")
    assert entry.finding_title == "Reflected XSS on /search"

    # The same finding re-discovered in a later scan (new id) must not re-open.
    duplicate, created_again = store.create_from_finding(
        target=target,
        reason="Still a false positive.",
        auditor_name="Auditor",
        source_run_name="demo_0002",
        finding=_finding(finding_id="vuln-0099"),
    )
    assert created_again is False
    assert duplicate.id == entry.id
    assert len(store.list()) == 1


def test_rejection_requires_a_reason(tmp_path) -> None:
    targets = TargetStore(tmp_path / "targets.json")
    target = targets.create(name="Demo", base_url="http://demo.test")
    store = RejectionStore(tmp_path / "rejections.json")

    try:
        store.create_from_finding(
            target=target,
            reason="   ",
            auditor_name="Auditor",
            source_run_name="demo_0001",
            finding=_finding(),
        )
    except RejectionValidationError as exc:
        assert "reason" in str(exc).lower()
    else:  # pragma: no cover - the call above must raise
        raise AssertionError("A blank reason must be rejected.")


def test_rejection_does_not_require_a_replay_recipe_and_deletes(tmp_path) -> None:
    targets = TargetStore(tmp_path / "targets.json")
    target = targets.create(name="Demo", base_url="http://demo.test")
    store = RejectionStore(tmp_path / "rejections.json")

    # No ``replay_spec`` on the finding: rejecting must still work.
    entry, created = store.create_from_finding(
        target=target,
        reason="Endpoint is out of the agreed scope.",
        auditor_name="Auditor",
        source_run_name="demo_0001",
        finding=_finding(),
    )
    assert created is True
    assert store.delete(entry.id) is True
    assert store.get(entry.id) is None
    assert store.list() == []
