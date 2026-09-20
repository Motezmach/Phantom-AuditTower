from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

import litellm
from agents.usage import Usage

from phantom.report.pricing import resolve_litellm_model
from phantom.report.usage import LLMUsageLedger


if TYPE_CHECKING:
    import pytest


def test_resolver_contract_with_controlled_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    """Resolver contract, decoupled from litellm's live (and drifting) registry.

    Uses a fixed model_cost so the test asserts *behaviour*, not whichever
    providers litellm happens to ship for a given model this month.
    """
    fake_cost = {
        "deepseek-v4-flash": {
            "litellm_provider": "deepseek",
            "input_cost_per_token": 1e-7,
            "output_cost_per_token": 2e-7,
        },
        # same model, two providers, identical price -> prefer the most direct one
        "xai/grok-4.5": {"input_cost_per_token": 1e-6, "output_cost_per_token": 2e-6},
        "openrouter/x-ai/grok-4.5": {"input_cost_per_token": 1e-6, "output_cost_per_token": 2e-6},
        # same model, two providers, DIFFERENT price -> ambiguous, decline to guess
        "minimax/MiniMax-M3": {"input_cost_per_token": 3e-7, "output_cost_per_token": 6e-7},
        "deepinfra/MiniMaxAI/MiniMax-M3": {
            "input_cost_per_token": 9e-7,
            "output_cost_per_token": 9e-7,
        },
    }
    monkeypatch.setattr(litellm, "model_cost", fake_cost)
    resolve_litellm_model.cache_clear()
    try:
        # a bare name that carries its own provider -> provider/name
        assert resolve_litellm_model("deepseek-v4-flash") == "deepseek/deepseek-v4-flash"
        assert resolve_litellm_model("openai/deepseek-v4-flash") == "deepseek/deepseek-v4-flash"
        # several providers at the same price -> the most direct (fewest path segments)
        assert resolve_litellm_model("grok-4.5") == "xai/grok-4.5"
        # providers disagree on price -> not safely resolvable
        assert resolve_litellm_model("MiniMax-M3") is None
    finally:
        resolve_litellm_model.cache_clear()


def test_resolver_returns_none_for_unresolvable_model() -> None:
    resolve_litellm_model.cache_clear()
    assert resolve_litellm_model("provider/not-a-real-model") is None


def test_ledger_uses_estimate_when_routed_provider_reports_no_cost() -> None:
    usage = Usage()
    usage.requests = 1
    usage.input_tokens = 1000
    usage.output_tokens = 200
    usage.total_tokens = 1200
    ledger = LLMUsageLedger()

    with patch("litellm.completion_cost", return_value=0.42):
        ledger.record(agent_id="a", usage=usage, model="openai/deepseek-v4-flash")

    assert ledger.total_cost == 0.42


def test_ledger_prefers_observed_cost_over_estimate() -> None:
    usage = Usage()
    usage.requests = 1
    usage.input_tokens = 1000
    usage.output_tokens = 200
    usage.total_tokens = 1200
    ledger = LLMUsageLedger()

    with patch("litellm.completion_cost", return_value=0.42):
        ledger.record(agent_id="a", usage=usage, model="openai/deepseek-v4-flash")
    ledger.record_observed_cost(0.17)

    assert ledger.total_cost == 0.17


def test_hydrated_estimate_continues_accumulating_new_estimates() -> None:
    usage = Usage()
    usage.requests = 1
    usage.input_tokens = 1000
    usage.output_tokens = 200
    usage.total_tokens = 1200
    ledger = LLMUsageLedger()
    ledger.hydrate({"cost": 0.42})

    with patch("litellm.completion_cost", return_value=0.17):
        ledger.record(agent_id="a", usage=usage, model="openai/deepseek-v4-flash")

    assert ledger.total_cost == 0.59


def test_zero_cost_disables_both_observed_and_estimated_costs() -> None:
    usage = Usage()
    usage.requests = 1
    usage.input_tokens = 1000
    usage.output_tokens = 200
    usage.total_tokens = 1200
    ledger = LLMUsageLedger()
    ledger.zero_cost = True

    with patch("litellm.completion_cost", return_value=0.42) as estimate:
        ledger.record(agent_id="a", usage=usage, model="deepseek-v4-flash")
        ledger.record_observed_cost(1.0)

    estimate.assert_not_called()
    assert ledger.total_cost == 0.0


def test_resolver_uses_provider_when_bare_entry_has_one() -> None:
    original = litellm.model_cost
    litellm.model_cost = {
        "example": {
            "litellm_provider": "example-provider",
            "input_cost_per_token": 1.0,
            "output_cost_per_token": 2.0,
        }
    }
    try:
        resolve_litellm_model.cache_clear()
        assert resolve_litellm_model("example") == "example-provider/example"
    finally:
        litellm.model_cost = original
        resolve_litellm_model.cache_clear()


def test_resolver_does_not_guess_between_differently_priced_providers() -> None:
    original = litellm.model_cost
    litellm.model_cost = {
        "provider-a/example": {
            "input_cost_per_token": 1.0,
            "output_cost_per_token": 2.0,
        },
        "provider-b/example": {
            "input_cost_per_token": 3.0,
            "output_cost_per_token": 4.0,
        },
    }
    try:
        resolve_litellm_model.cache_clear()
        assert resolve_litellm_model("example") is None
    finally:
        litellm.model_cost = original
        resolve_litellm_model.cache_clear()
