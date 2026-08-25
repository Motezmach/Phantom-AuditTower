"""Tests for specialized agent-type registration and persistence metadata."""

from __future__ import annotations

import pytest

from phantom.agents.factory import _load_agent_type_instructions, get_available_agent_types
from phantom.core.agents import AgentCoordinator


def test_payload_crafter_is_explicitly_registered() -> None:
    assert get_available_agent_types() == [
        "attack_path_analyst",
        "payload_crafter",
        "reporting_analyst",
        "web_validator",
    ]
    instructions = _load_agent_type_instructions("payload_crafter")
    assert instructions is not None
    assert "Authorization Gate" in instructions
    assert "Detection Pairing" in instructions
    assert "MITRE ATT&CK Mapping" in instructions


def test_validation_and_reporting_agent_prompts_are_registered() -> None:
    assert "Independent Validation Handoff" in _load_agent_type_instructions("web_validator")
    assert "Attack Path Analysis Handoff" in _load_agent_type_instructions("attack_path_analyst")
    assert "impact_tags" in _load_agent_type_instructions("reporting_analyst")


def test_unknown_agent_type_is_rejected() -> None:
    with pytest.raises(ValueError, match="Unknown agent_type"):
        _load_agent_type_instructions("../outside")


@pytest.mark.asyncio
async def test_agent_type_is_kept_in_graph_metadata() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register(
        "child",
        "Web Payload Crafter",
        "root",
        skills=["web_payload_crafting"],
        agent_type="payload_crafter",
    )

    snapshot = await coordinator.snapshot()
    assert snapshot["metadata"]["child"]["agent_type"] == "payload_crafter"
