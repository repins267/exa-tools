"""Tests for exa update self repo root detection."""

from exa.cli.update import _find_repo_root


def test_find_repo_root_returns_path() -> None:
    result = _find_repo_root()
    assert result is not None
    assert (result / ".git").exists()


def test_find_repo_root_contains_pyproject() -> None:
    result = _find_repo_root()
    assert result is not None
    assert (result / "pyproject.toml").exists()
