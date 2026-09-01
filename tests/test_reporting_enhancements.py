"""Tests for validation provenance, contextual severity, paths, and mappings."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest


if TYPE_CHECKING:
    from pathlib import Path

from phantom.report.metadata import (
    normalize_attack_path,
    normalize_mitre_techniques,
    validate_impact_evidence,
    validate_mitre_mappings,
)
from phantom.report.severity import calibrate_severity
from phantom.report.state import ReportState, set_global_report_state
from phantom.report.writer import render_vulnerability_md, write_executive_report
from phantom.tools.reporting.tool import _do_create
from phantom.utils.atomic import atomic_write_text, cleanup_atomic_temps


_CVSS_MEDIUM = {
    "attack_vector": "N",
    "attack_complexity": "L",
    "privileges_required": "L",
    "user_interaction": "N",
    "scope": "U",
    "confidentiality": "N",
    "integrity": "H",
    "availability": "N",
}


def test_business_impact_does_not_override_cvss_severity() -> None:
    severity, basis = calibrate_severity(
        6.5,
        impact_tags=["financial_loss"],
        validation={
            "status": "independently_validated",
            "validator": "validator-1",
            "evidence": "Two clean reproductions",
            "reproduction_count": 2,
        },
    )
    assert severity == "medium"
    assert "financial_loss" in basis

    severity, basis = calibrate_severity(6.5, impact_tags=["financial_loss"], validation=None)
    assert severity == "medium"
    assert "unverified" in basis


def test_structured_path_and_mitre_metadata_is_normalized() -> None:
    path, path_errors = normalize_attack_path(
        [{"action": "Read another account", "evidence": "Response contained balance"}]
    )
    mappings, mapping_errors = normalize_mitre_techniques(
        [
            {
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "evidence": "Confirmed request and impact",
                "confidence": "confirmed",
            }
        ]
    )
    assert not path_errors and path[0]["order"] == 1
    assert not mapping_errors and mappings[0]["technique_id"] == "T1190"


def test_attack_path_rejects_placeholder_steps() -> None:
    path, errors = normalize_attack_path(
        [{"action": "inject", "evidence": "The server returned a changed response."}]
    )
    assert path
    assert any("placeholder" in error for error in errors)


def test_impact_and_mitre_guards_reject_semantic_overclaiming() -> None:
    assert not validate_impact_evidence(
        ["financial_loss"],
        "Two unauthorized funds were transferred and the destination balance changed.",
    )
    impact_errors = validate_impact_evidence(
        ["account_takeover"],
        "The victim's authenticated session was used to submit a transfer.",
    )
    assert any("account_takeover" in error for error in impact_errors)

    mitre_errors = validate_mitre_mappings(
        [
            {
                "technique_id": "T1563",
                "technique_name": "Remote Service Session Hijacking",
            }
        ],
        "CSRF forced a transfer from the victim's authenticated session.",
    )
    assert any("T1563" in error for error in mitre_errors)


@pytest.mark.asyncio
async def test_every_dynamic_report_requires_independent_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    state = ReportState(run_name="validation-gate-test")
    set_global_report_state(state)

    result = await _do_create(
        title="Authorization bypass",
        description="A protected action is reachable.",
        impact="The action completed for an unauthorized principal.",
        target="https://app.example.test",
        technical_analysis="The server does not enforce the role check.",
        poc_description="1. Send the request as a low-privilege user.",
        poc_script_code="GET /admin/action",
        remediation_steps="Enforce authorization server-side.",
        evidence="The protected response was returned.",
        assumptions="Assumes a low-privilege account.",
        fix_effort="medium",
        cvss_breakdown=_CVSS_MEDIUM,
        endpoint="/admin/action",
        method="GET",
        cve=None,
        cwe="CWE-863",
        code_locations=None,
    )
    assert result["success"] is False
    assert any("every dynamic vulnerability" in error for error in result["errors"])
    assert not state.vulnerability_reports


@pytest.mark.asyncio
async def test_high_business_impact_report_requires_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    state = ReportState(run_name="severity-test")
    set_global_report_state(state)

    result = await _do_create(
        title="Cross-account fund theft",
        description="A user can move funds from another account.",
        impact="Demonstrated funds were moved from another account into the attacker account.",
        target="https://app.example.test",
        technical_analysis="Ownership is not checked.",
        poc_description="1. Submit the transfer request.",
        poc_script_code="POST /api/transfer",
        remediation_steps="Enforce server-side ownership.",
        evidence="Two account balances changed after the request.",
        assumptions="Assumes a low-privilege authenticated account.",
        fix_effort="medium",
        cvss_breakdown=_CVSS_MEDIUM,
        endpoint="/api/transfer",
        method="POST",
        cve=None,
        cwe="CWE-639",
        code_locations=None,
        impact_tags=["financial_loss"],
    )
    assert result["success"] is False
    assert any("Independent validation" in error for error in result["errors"])

    result = await _do_create(
        title="Cross-account fund theft",
        description="A user can move funds from another account.",
        impact="Demonstrated funds were moved from another account into the attacker account.",
        target="https://app.example.test",
        technical_analysis="Ownership is not checked.",
        poc_description="1. Submit the transfer request.",
        poc_script_code="POST /api/transfer",
        remediation_steps="Enforce server-side ownership.",
        evidence="Two account balances changed after the request.",
        assumptions="Assumes a low-privilege authenticated account.",
        fix_effort="medium",
        cvss_breakdown=_CVSS_MEDIUM,
        endpoint="/api/transfer",
        method="POST",
        cve=None,
        cwe="CWE-639",
        code_locations=None,
        impact_tags=["financial_loss"],
        validation={
            "status": "independently_validated",
            "validator": "Web Validator",
            "evidence": "Reproduced with two clean balance checks.",
            "reproduction_count": 2,
        },
        attack_path=[
            {"action": "Submit cross-account transfer", "evidence": "Destination balance increased"}
        ],
        mitre_techniques=[
            {
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "evidence": "The authorized request produced the transfer.",
                "confidence": "confirmed",
            }
        ],
        replay_spec={
            "version": 1,
            "executor": "http",
            "target": "https://app.example.test",
            "steps": [
                {
                    "method": "POST",
                    "path": "/api/transfer",
                    "body_type": "json",
                    "body": {"fromAccount": "800002", "toAccount": "800005", "amount": 1},
                    "assertions": [
                        {"type": "status_equals", "value": 200},
                        {"type": "body_contains", "value": "transferred"},
                    ],
                    "side_effect": "mutating",
                }
            ],
            "side_effect": "mutating",
        },
    )
    assert result["success"] is True
    assert result["severity"] == "medium"
    assert state.vulnerability_reports[0]["severity_basis"].startswith(
        "cvss_base_with_validated_impact"
    )


def test_report_rendering_includes_structured_sections_and_no_duplicate_headings(
    tmp_path: Path,
) -> None:
    report = {
        "id": "vuln-0001",
        "title": "Validated SQL injection",
        "severity": "high",
        "severity_basis": "independently_validated_business_impact:database_extraction",
        "timestamp": "2026-08-23 00:00:00 UTC",
        "description": "Database extraction was demonstrated.",
        "impact": "Sensitive records were returned.",
        "validation": {
            "status": "independently_validated",
            "validator": "Web Validator",
            "evidence": "Reproduced twice.",
            "reproduction_count": 2,
        },
        "attack_path": [
            {
                "order": 1,
                "action": "Submit the bounded request",
                "evidence": "Rows returned",
                "result": "Two records were returned",
            }
        ],
        "mitre_techniques": [
            {
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "confidence": "confirmed",
                "evidence": "The request produced the demonstrated result.",
            }
        ],
    }
    markdown = render_vulnerability_md(report)
    assert "## Validation" in markdown
    assert "## Attack Path" in markdown
    assert "## MITRE ATT&CK" in markdown
    assert "Severity Basis" in markdown
    assert "**Result:** Two records were returned" in markdown

    no_mapping = render_vulnerability_md(
        {
            "title": "Informational disclosure",
            "severity": "low",
            "description": "A verbose error is exposed.",
            "mitre_mapping_status": "not_mapped",
            "mitre_techniques": [],
        }
    )
    assert "## MITRE ATT&CK" in no_mapping
    assert "No direct ATT&CK technique was recorded" in no_mapping

    write_executive_report(
        tmp_path,
        "# Executive Summary\nSummary\n# Methodology\nMethod\n",
        [report],
    )
    content = (tmp_path / "penetration_test_report.md").read_text(encoding="utf-8")
    assert content.count("# Executive Summary") == 1
    assert "## Attack Path Analysis" in content


def test_atomic_writes_remove_temps(tmp_path: Path) -> None:
    atomic_write_text(tmp_path / "run.json", json.dumps({"ok": True}))
    assert json.loads((tmp_path / "run.json").read_text(encoding="utf-8"))["ok"] is True
    stale = tmp_path / ".run.json.stale.tmp"
    stale.write_text("stale", encoding="utf-8")
    assert cleanup_atomic_temps(tmp_path) == 1
    assert not stale.exists()
