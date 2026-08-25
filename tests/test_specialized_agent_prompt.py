"""Tests for scoped specialized-agent prompt composition."""

from __future__ import annotations

import pytest

import phantom.agents.prompt as prompt_module
from phantom.agents.prompt import render_specialized_prompt


def test_specialized_prompt_keeps_scope_and_requested_skills() -> None:
    prompt = render_specialized_prompt(
        specialized_instructions="SPECIALIZED PAYLOAD ROLE",
        skills=["web_payload_crafting"],
        scan_mode="quick",
        system_prompt_context={
            "scope_source": "test_scope",
            "authorization_source": "test_authorization",
            "authorized_targets": [
                {"type": "web_application", "value": "http://app.test"}
            ],
        },
    )

    assert "SPECIALIZED PAYLOAD ROLE" in prompt
    assert "http://app.test" in prompt
    assert "test_scope" in prompt
    assert "Scan mode: quick" in prompt
    assert "Web Payload Handoff" in prompt
    assert "<loaded_skills>" in prompt


def test_specialized_prompt_without_verified_scope_is_lab_only() -> None:
    prompt = render_specialized_prompt(
        specialized_instructions="SPECIALIZED PAYLOAD ROLE",
        system_prompt_context={},
    )

    assert "No platform-verified target was provided" in prompt
    assert "lab-only placeholder" in prompt


def test_specialized_prompt_fails_closed_when_skill_rendering_breaks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken_load_skills(_skills: list[str]) -> dict[str, str]:
        raise OSError("test skill loader failure")

    monkeypatch.setattr(prompt_module, "load_skills", broken_load_skills)

    with pytest.raises(RuntimeError, match="verified scope and skills"):
        render_specialized_prompt(
            specialized_instructions="SPECIALIZED PAYLOAD ROLE",
            system_prompt_context={
                "authorized_targets": ["http://app.test"],
            },
        )
