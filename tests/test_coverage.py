"""Tests for Phantom's target-agnostic coverage control plane."""

from __future__ import annotations

from phantom.report.coverage import (
    coverage_quality_errors,
    normalize_coverage_item,
    validate_agent_assignment,
)


def _login_item() -> dict[str, object]:
    return normalize_coverage_item(
        {
            "title": "Authentication entry point",
            "category": "authentication",
            "surface": "POST /login",
            "test_families": ["authentication", "injection"],
        }
    )


def test_coverage_id_is_stable_and_assignment_requires_existing_item() -> None:
    item = _login_item()
    assert item["coverage_id"] == _login_item()["coverage_id"]
    assert validate_agent_assignment(
        agent_type="web_validator",
        task="Reproduce the authentication hypothesis",
        coverage_ids=[],
        existing_items=[item],
    )
    assert validate_agent_assignment(
        agent_type="web_validator",
        task="Reproduce the authentication hypothesis",
        coverage_ids=[str(item["coverage_id"])],
        existing_items=[item],
    ) is None


def test_specialized_agent_cannot_be_used_for_broad_discovery() -> None:
    item = _login_item()
    error = validate_agent_assignment(
        agent_type="web_validator",
        task="Perform comprehensive reconnaissance and map all endpoints",
        coverage_ids=[str(item["coverage_id"])],
        existing_items=[item],
    )
    assert error is not None
    assert "default discovery agent" in error


def test_required_unresolved_coverage_blocks_completion() -> None:
    item = _login_item()
    errors = coverage_quality_errors([item])
    assert errors
    assert str(item["coverage_id"]) in errors[0]

    item["status"] = "ruled_out"
    item["notes"] = "No matching behavior was observed during the bounded test."
    assert coverage_quality_errors([item]) == []


def test_empty_coverage_is_a_quality_error() -> None:
    assert coverage_quality_errors()
