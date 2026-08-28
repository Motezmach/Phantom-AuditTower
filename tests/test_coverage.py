"""Tests for Phantom's target-agnostic coverage control plane."""

from __future__ import annotations

from phantom.report.coverage import (
    DISCOVERY_LANE_SPECS,
    build_surface_coverage_plan,
    coverage_quality_errors,
    discovery_lane_quality_errors,
    normalize_coverage_item,
    payload_crafter_quality_errors,
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


def test_surface_planner_creates_concrete_lanes_and_payload_handoff() -> None:
    plan = build_surface_coverage_plan(
        {
            "base_url": "http://example.test",
            "endpoints": [
                {
                    "method": "POST",
                    "path": "/api/login",
                    "kind": "api",
                    "parameters": [{"name": "username"}, {"name": "password"}],
                    "auth_context": "anonymous",
                }
            ],
            "observations": ["The error path returned a stack trace"],
            "technologies": ["Tomcat"],
        }
    )

    assert any(item["discovery_lane"] == "authentication" for item in plan)
    assert any(item["discovery_lane"] == "injection" for item in plan)
    assert any(item["requires_payload_crafter"] for item in plan)
    assert any(item["discovery_lane"] == "error_disclosure" for item in plan)


def test_surface_planner_recovers_generic_routes_from_recon_notes() -> None:
    plan = build_surface_coverage_plan(
        {
            "base_url": "http://example.test",
            "recon_notes": [
                {
                    "title": "Endpoint inventory",
                    "content": (
                        "- POST /api/login (username, password)\n"
                        "- /search.jsp?query= - reflects the query into HTML\n"
                        "- /util/check?url= - server-side URL check candidate\n"
                        "- POST /api/transfer ({toAccount, fromAccount, transferAmount})"
                    ),
                }
            ],
        }
    )

    assert any(item.get("route") == "/api/login" for item in plan)
    assert any(item.get("parameter") == "username, password" for item in plan)
    assert any(
        item.get("route") == "/api/transfer"
        and item.get("parameter") == "toAccount, fromAccount, transferAmount"
        for item in plan
    )
    assert any(item["requires_payload_crafter"] for item in plan)


def test_unscoped_parameters_do_not_spread_across_multiple_routes() -> None:
    plan = build_surface_coverage_plan(
        {
            "parameters": ["query", "content", "HostName"],
            "endpoints": [
                {"path": "/index.jsp", "method": "GET"},
                {"path": "/style.css", "method": "GET"},
            ],
        }
    )

    assert not any(
        item.get("parameter") == "query, content, HostName" for item in plan
    )
    assert not any(item.get("requires_payload_crafter") for item in plan)


def test_unscoped_parameters_remain_a_single_route_fallback() -> None:
    plan = build_surface_coverage_plan(
        {
            "parameters": ["query", "content"],
            "endpoints": [{"path": "/search.jsp", "method": "GET"}],
        }
    )

    assert any(item.get("parameter") == "query, content" for item in plan)


def test_authorization_lane_requires_post_auth_privilege_recheck() -> None:
    spec = DISCOVERY_LANE_SPECS["authorization"]
    guidance = spec["task_guidance"]

    assert "post-authentication recheck" in guidance
    assert "parent 404" in guidance
    assert "ordinary low-privilege principal" in guidance


def test_api_state_changes_and_object_references_get_authorization_coverage() -> None:
    plan = build_surface_coverage_plan(
        {
            "base_url": "https://example.test",
            "endpoints": [
                {
                    "path": "/v1/submit",
                    "method": "POST",
                    "kind": "api",
                    "parameters": ["payload"],
                },
                {
                    "path": "/v1/widgets/{id}",
                    "method": "GET",
                    "kind": "api",
                },
            ],
        }
    )

    assert any(
        item.get("route") == "/v1/submit"
        and item.get("discovery_lane") == "authorization"
        for item in plan
    )
    assert any(
        item.get("route") == "/v1/submit"
        and item.get("discovery_lane") == "state_change"
        for item in plan
    )
    assert any(
        item.get("route") == "/v1/widgets/{id}"
        and item.get("discovery_lane") == "authorization"
        for item in plan
    )


def test_text_inventory_normalizes_compact_api_method_notation() -> None:
    plan = build_surface_coverage_plan(
        {
            "base_url": "https://example.test",
            "recon_notes": [
                {
                    "title": "API inventory",
                    "content": (
                        "- /api/login(Get/Post) (username, password)\n"
                        "- /api/transfer(Post) (fromAccount, toAccount, amount)"
                    ),
                }
            ],
        }
    )

    assert any(item.get("route") == "/api/login" for item in plan)
    assert any(
        item.get("route") == "/api/transfer"
        and item.get("discovery_lane") == "authorization"
        for item in plan
    )


def test_text_inventory_ignores_explicitly_unavailable_paths() -> None:
    plan = build_surface_coverage_plan(
        {
            "base_url": "https://example.test",
            "recon_notes": [
                {
                    "content": (
                        "**Ruled out:**\n"
                        "- /POST (404 artifact), /from (404), /api/login (200)"
                    )
                }
            ],
        }
    )

    routes = {item.get("route") for item in plan}
    assert "/POST" not in routes
    assert "/from" not in routes
    assert "/api/login" in routes


def test_lane_and_payload_quality_require_matching_handoffs() -> None:
    item = normalize_coverage_item(
        {
            "title": "POST /api/login input",
            "category": "input_validation",
            "surface": "POST /api/login [username]",
            "test_families": ["sql_injection"],
            "discovery_lane": "injection",
            "requires_payload_crafter": True,
            "status": "confirmed",
            "evidence": "Bounded differential reproduced.",
        }
    )
    item["assigned_agent_id"] = "injector"
    metadata = {
        "injector": {
            "task": "Run the bounded injection discovery lane",
            "skills": ["vulnerabilities/sql_injection"],
            "coverage_ids": [item["coverage_id"]],
            "agent_type": None,
        }
    }
    statuses = {"injector": "completed"}
    assert discovery_lane_quality_errors([item], metadata, statuses) == []
    assert payload_crafter_quality_errors([item], metadata, statuses)

    metadata["crafter"] = {
        "task": "Prepare bounded web payload mutations",
        "skills": ["vulnerabilities/web_payload_crafting"],
        "coverage_ids": [item["coverage_id"]],
        "agent_type": "payload_crafter",
    }
    statuses["crafter"] = "completed"
    assert payload_crafter_quality_errors([item], metadata, statuses) == []
