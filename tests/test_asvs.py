"""Tests for the ASVS 5.0 honest-coverage mapping (phantom.report.asvs)."""

from __future__ import annotations

import json

from phantom.report import asvs
from phantom.report.writer import render_executive_report, write_asvs


def test_asvs_data_loads() -> None:
    data = asvs.load_asvs()
    assert data["version"] == "5.0.0"
    assert data["requirement_count"] == 345
    assert len(data["requirements"]) == 345
    assert len(data["chapters"]) == 17
    # every requirement carries the fields the mapper relies on
    sample = data["requirements"][0]
    for key in ("req_id", "chapter_id", "chapter_name", "section_id", "level", "description"):
        assert sample[key]


def test_cwe_index_loads() -> None:
    idx = asvs.load_cwe_index()
    by_cwe = idx["by_cwe"]
    # CWE-639 (IDOR / BOLA) resolves to the object-level authorization requirement
    assert "V8.2.2" in by_cwe["639"]


def test_failed_via_official_cwe() -> None:
    result = asvs.build_asvs_coverage([{"id": "F1", "cwe": "CWE-639"}], [])
    failed = {r["req_id"] for r in result["requirements"] if r["status"] == asvs.STATUS_FAILED}
    assert "V8.2.2" in failed
    assert not result["unmapped_findings"]


def test_fallback_maps_to_specific_reqs_not_whole_chapter() -> None:
    # CWE-863 has no official ASVS index entry; the curated fallback must hit exactly
    # V8.2.1 + V8.3.1 and NOT flip the entire V8 chapter to failed.
    result = asvs.build_asvs_coverage([{"id": "F1", "cwe": "CWE-863"}], [])
    v8 = [r for r in result["requirements"] if r["chapter_id"] == "V8"]
    failed = {r["req_id"] for r in v8 if r["status"] == asvs.STATUS_FAILED}
    assert failed == {"V8.2.1", "V8.3.1"}
    assert sum(r["status"] == asvs.STATUS_FAILED for r in v8) == 2  # not all 13
    assert not result["unmapped_findings"]


def test_checked_comes_from_coverage_ledger() -> None:
    # An exercised authorization lane marks V8 requirements checked (except any failed).
    result = asvs.build_asvs_coverage(
        [{"id": "F1", "cwe": "CWE-639"}],
        [{"category": "authorization", "status": "confirmed"}],
    )
    v8 = {r["req_id"]: r["status"] for r in result["requirements"] if r["chapter_id"] == "V8"}
    assert v8["V8.2.2"] == asvs.STATUS_FAILED  # the finding
    assert v8["V8.1.1"] == asvs.STATUS_CHECKED  # exercised, no finding


def test_not_tested_reason_for_source_only_chapter() -> None:
    # With no coverage at all, cryptography (no dynamic lane) is not-tested with a reason.
    result = asvs.build_asvs_coverage([], [])
    crypto = [r for r in result["requirements"] if r["chapter_id"] == "V11"]
    assert crypto and all(r["status"] == asvs.STATUS_NOT_TESTED for r in crypto)
    assert all("source" in r["reason"].lower() for r in crypto)


def test_unmapped_finding_is_reported_honestly() -> None:
    result = asvs.build_asvs_coverage([{"id": "F1", "title": "weird", "cwe": None}], [])
    assert result["unmapped_findings"] and result["unmapped_findings"][0]["finding"] == "F1"


def test_summary_counts_are_exhaustive() -> None:
    result = asvs.build_asvs_coverage([{"id": "F1", "cwe": "CWE-639"}], [])
    s = result["summary"]
    assert s["total"] == 345
    assert s["failed"] + s["checked"] + s["not_tested"] == 345


def test_scope_note_appended_to_not_tested() -> None:
    result = asvs.build_asvs_coverage([], [], scope_note="(pre-prod scope.)")
    nt = [r for r in result["requirements"] if r["status"] == asvs.STATUS_NOT_TESTED]
    assert nt and all(r["reason"].endswith("(pre-prod scope.)") for r in nt)


def test_render_markdown_has_key_sections() -> None:
    result = asvs.build_asvs_coverage([{"id": "F1", "cwe": "CWE-639"}], [])
    md = asvs.render_asvs_markdown(result)
    assert "ASVS 5.0.0 Coverage" in md
    assert "Not tested" in md
    assert "V8.2.2" in md  # failed requirement listed


def test_write_asvs_creates_both_artifacts(tmp_path) -> None:  # type: ignore[no-untyped-def]
    coverage = asvs.build_asvs_coverage([{"id": "F1", "cwe": "CWE-639"}], [])
    write_asvs(tmp_path, coverage)
    data = json.loads((tmp_path / "asvs.json").read_text(encoding="utf-8"))
    assert data["version"] == "5.0.0"
    assert data["summary"]["total"] == 345
    assert "ASVS 5.0.0 Coverage" in (tmp_path / "asvs.md").read_text(encoding="utf-8")


def test_executive_report_includes_asvs_section() -> None:
    coverage = asvs.build_asvs_coverage([{"id": "F1", "cwe": "CWE-639"}], [])
    report = render_executive_report("# Executive Summary\n\nAll good.", [], coverage)
    assert "## ASVS 5.0.0 Coverage" in report
    # and it stays absent when not supplied (back-compat)
    assert "ASVS" not in render_executive_report("# Executive Summary\n\nAll good.", [])
