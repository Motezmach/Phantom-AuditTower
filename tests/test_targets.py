"""Tests for Phantom's local dashboard target registry."""

from __future__ import annotations

import json

import pytest

from phantom.core.targets import TargetStore, TargetValidationError, normalize_base_url


def test_normalize_base_url_keeps_path_and_derives_scope() -> None:
    url, host = normalize_base_url(" HTTPS://Example.test/app/ ")
    assert url == "https://example.test/app"
    assert host == "example.test"


@pytest.mark.parametrize(
    "value",
    [
        "example.test",
        "ftp://example.test",
        "https://user:password@example.test",
        "https://example.test/?token=secret",
        "https://example.test/#fragment",
    ],
)
def test_normalize_base_url_rejects_unsafe_or_ambiguous_values(value: str) -> None:
    with pytest.raises(TargetValidationError):
        normalize_base_url(value)


def test_target_store_creates_and_persists_target(tmp_path) -> None:
    path = tmp_path / "targets.json"
    store = TargetStore(path)

    target = store.create(name="Demo app", base_url="http://Demo.test/")

    assert target.id.startswith("tgt_")
    assert target.base_url == "http://demo.test"
    assert target.scope_hosts == ("demo.test",)
    assert store.list()[0] == target
    assert json.loads(path.read_text(encoding="utf-8"))["version"] == 1


def test_target_store_rejects_duplicate_name_and_url(tmp_path) -> None:
    store = TargetStore(tmp_path / "targets.json")
    store.create(name="Demo app", base_url="http://demo.test")

    with pytest.raises(TargetValidationError, match="name already exists"):
        store.create(name="demo APP", base_url="http://other.test")
    with pytest.raises(TargetValidationError, match="already registered"):
        store.create(name="Other app", base_url="http://DEMO.test/")
