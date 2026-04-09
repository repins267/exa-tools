"""Tests for SigmaHQ index building and browse filtering."""

import json
from pathlib import Path

import pytest

from exa.update import _build_sigma_index


def _make_sigma_rule(
    title: str = "Test Rule",
    category: str = "process_creation",
    product: str = "windows",
    level: str = "high",
    tags: list[str] | None = None,
) -> str:
    """Generate a minimal Sigma YAML string."""
    tag_lines = ""
    if tags:
        tag_lines = "\ntags:\n" + "\n".join(f"    - {t}" for t in tags)
    return f"""title: {title}
logsource:
    category: {category}
    product: {product}
level: {level}{tag_lines}
detection:
    selection:
        CommandLine|contains: test
    condition: selection
"""


@pytest.fixture()
def sigma_dir(tmp_path: Path) -> Path:
    """Create a fake sigma repo with test rules."""
    rules = tmp_path / "rules" / "windows" / "process_creation"
    rules.mkdir(parents=True)

    (rules / "rule_high.yml").write_text(
        _make_sigma_rule(
            title="Suspicious PowerShell",
            level="high",
            tags=["attack.t1059.001"],
        ),
        encoding="utf-8",
    )
    (rules / "rule_medium.yml").write_text(
        _make_sigma_rule(
            title="Generic Process",
            level="medium",
            tags=["attack.t1059"],
        ),
        encoding="utf-8",
    )

    linux_rules = tmp_path / "rules" / "linux" / "network_connection"
    linux_rules.mkdir(parents=True)
    (linux_rules / "rule_linux.yml").write_text(
        _make_sigma_rule(
            title="Linux Network Event",
            category="network_connection",
            product="linux",
            level="low",
        ),
        encoding="utf-8",
    )

    return tmp_path


class TestSigmaIndexParsed:
    def test_index_built(self, sigma_dir: Path) -> None:
        """Index JSON is created with correct rule count."""
        cache = sigma_dir / "cache"
        result = _build_sigma_index(sigma_dir, cache)
        assert result.records == 3
        assert result.error == ""
        assert (cache / "sigma_index.json").exists()

    def test_index_structure(self, sigma_dir: Path) -> None:
        """Each index entry has the required fields."""
        cache = sigma_dir / "cache"
        _build_sigma_index(sigma_dir, cache)
        data = json.loads(
            (cache / "sigma_index.json").read_text(encoding="utf-8"),
        )
        for entry in data:
            assert "path" in entry
            assert "title" in entry
            assert "tags" in entry
            assert "level" in entry
            assert "category" in entry
            assert "product" in entry

    def test_index_content(self, sigma_dir: Path) -> None:
        """Index contains expected rule data."""
        cache = sigma_dir / "cache"
        _build_sigma_index(sigma_dir, cache)
        data = json.loads(
            (cache / "sigma_index.json").read_text(encoding="utf-8"),
        )
        titles = [e["title"] for e in data]
        assert "Suspicious PowerShell" in titles
        assert "Linux Network Event" in titles


class TestBrowseFilterCategory:
    def test_filter_by_category(self, sigma_dir: Path) -> None:
        """Filter rules by logsource category."""
        cache = sigma_dir / "cache"
        _build_sigma_index(sigma_dir, cache)
        data = json.loads(
            (cache / "sigma_index.json").read_text(encoding="utf-8"),
        )
        filtered = [
            r for r in data
            if "process_creation" in r.get("category", "").lower()
        ]
        assert len(filtered) == 2
        assert all(
            r["category"] == "process_creation" for r in filtered
        )

    def test_filter_excludes_other(self, sigma_dir: Path) -> None:
        """Category filter excludes non-matching rules."""
        cache = sigma_dir / "cache"
        _build_sigma_index(sigma_dir, cache)
        data = json.loads(
            (cache / "sigma_index.json").read_text(encoding="utf-8"),
        )
        filtered = [
            r for r in data
            if "network_connection" in r.get("category", "").lower()
        ]
        assert len(filtered) == 1
        assert filtered[0]["product"] == "linux"


class TestBrowseFilterLevel:
    def test_filter_high(self, sigma_dir: Path) -> None:
        """Filter by level=high returns only high-level rules."""
        cache = sigma_dir / "cache"
        _build_sigma_index(sigma_dir, cache)
        data = json.loads(
            (cache / "sigma_index.json").read_text(encoding="utf-8"),
        )
        filtered = [
            r for r in data if r.get("level", "") == "high"
        ]
        assert len(filtered) == 1
        assert filtered[0]["title"] == "Suspicious PowerShell"

    def test_filter_low(self, sigma_dir: Path) -> None:
        """Filter by level=low returns only low-level rules."""
        cache = sigma_dir / "cache"
        _build_sigma_index(sigma_dir, cache)
        data = json.loads(
            (cache / "sigma_index.json").read_text(encoding="utf-8"),
        )
        filtered = [
            r for r in data if r.get("level", "") == "low"
        ]
        assert len(filtered) == 1
        assert filtered[0]["title"] == "Linux Network Event"
