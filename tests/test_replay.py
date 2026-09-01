"""Tests for Phantom's structured finding replay contract."""

from __future__ import annotations

from phantom.core.replay import (
    _SANDBOX_REPLAY_RUNNER,
    _evaluate_assertions,
    normalize_replay_spec,
    render_replay_script,
)


def _spec() -> dict[str, object]:
    return {
        "version": 1,
        "executor": "http",
        "target": "http://demo.testfire.net",
        "steps": [
            {
                "name": "Submit proof request",
                "method": "POST",
                "path": "/doLogin",
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body_type": "form",
                "body": {"uid": "' OR '1'='1'--", "passw": "x"},
                "assertions": [
                    {"type": "status_equals", "value": 302},
                    {"type": "body_contains", "value": "Hello Admin"},
                ],
            }
        ],
    }


def test_replay_spec_is_normalized_and_gets_a_preview_script() -> None:
    normalized, errors = normalize_replay_spec(_spec(), finding_target="http://demo.testfire.net/")

    assert errors == []
    assert normalized is not None
    assert normalized["executor"] == "http"
    assert "curl -i -X POST" in str(normalized["script"])
    assert "doLogin" in str(normalized["script"])


def test_replay_spec_rejects_cross_origin_steps() -> None:
    spec = _spec()
    spec["steps"] = [{"method": "GET", "path": "//attacker.test/collect", "assertions": []}]

    normalized, errors = normalize_replay_spec(spec, finding_target="http://demo.testfire.net")

    assert normalized is None
    assert errors


def test_replay_spec_requires_an_objective_assertion() -> None:
    spec = _spec()
    step = spec["steps"][0]
    assert isinstance(step, dict)
    step["assertions"] = []

    normalized, errors = normalize_replay_spec(spec)

    assert normalized is None
    assert "at least one assertion" in errors[0]


def test_replay_spec_rejects_a_capture_that_was_not_defined() -> None:
    spec = _spec()
    spec["steps"] = [
        {
            "method": "POST",
            "path": "/login",
            "assertions": [{"type": "status_equals", "value": 200}],
        },
        {
            "method": "GET",
            "path": "/account",
            "headers": {"Authorization": "Bearer {{token}}"},
            "assertions": [{"type": "status_equals", "value": 200}],
        },
    ]

    normalized, errors = normalize_replay_spec(spec)

    assert normalized is None
    assert "token" in errors[0]
    assert "earlier step" in errors[0]


def test_assertions_report_success_and_failure() -> None:
    assertions = [
        {"type": "status_equals", "value": 200},
        {"type": "body_contains", "value": "proof"},
    ]

    passed, failures = _evaluate_assertions(
        assertions,
        status=200,
        headers={},
        body="proof response",
    )
    assert passed is True
    assert failures == []

    passed, failures = _evaluate_assertions(
        assertions,
        status=403,
        headers={},
        body="denied",
    )
    assert passed is False
    assert len(failures) == 2


def test_regex_assertions_can_validate_response_headers() -> None:
    passed, failures = _evaluate_assertions(
        [{"type": "regex", "value": r"Location:\s*/bank/main\.jsp"}],
        status=302,
        headers={"Location": "/bank/main.jsp"},
        body="",
    )

    assert passed is True
    assert failures == []


def test_render_preview_is_readable_and_non_empty() -> None:
    normalized, errors = normalize_replay_spec(_spec())

    assert errors == []
    assert normalized is not None
    preview = render_replay_script(normalized)
    assert preview.startswith("# Step 1:")
    assert "Content-Type" in preview


def test_sandbox_runner_preserves_cookies_between_replay_steps() -> None:
    compile(_SANDBOX_REPLAY_RUNNER, "<phantom-replay-runner>", "exec")
    assert "MozillaCookieJar" in _SANDBOX_REPLAY_RUNNER
    assert "HTTPCookieProcessor" in _SANDBOX_REPLAY_RUNNER
    assert '"cookie_file"' in _SANDBOX_REPLAY_RUNNER
