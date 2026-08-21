"""AI/LLM report output formats: html / json / csv / pdf."""

from __future__ import annotations

import json

import pytest

from exa.aillm.report import (
    AILLMReport,
    DriftItem,
    TableChange,
    TableState,
    report_to_csv,
    save_csv_report,
    save_html_report,
    save_json_report,
    save_pdf_report,
)
from exa.report import pdf as pdf_mod
from exa.report.pdf import PdfUnavailableError, html_to_pdf


def _report() -> AILLMReport:
    return AILLMReport(
        tenant="sademodev22",
        collected_at="2026-08-21T01:00:00",
        lookback_days=30,
        tables=[
            TableState(
                name="AI/LLM Web Domains",
                table_id="abc",
                key_attr="web_domain",
                records=221,
                present=True,
                consumers=["rules"],
            ),
            TableState(
                name="AI Agent Process Names",
                table_id=None,
                key_attr="process_name",
                records=0,
                present=False,
                consumers=["rules"],
            ),
        ],
        changes=[TableChange(name="AI/LLM Web Domains", before=200, after=221)],
        drift=[DriftItem(field_name="app", value="M365 MCP Client for Claude")],
        baseline_at="2026-08-20T01:00:00",
        reference_summary="bundled 2026-08",
    )


def test_json_report_writes_parseable_file(tmp_path):
    out = tmp_path / "r.json"
    save_json_report(_report(), out)
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["tenant"] == "sademodev22"
    assert len(data["tables"]) == 2
    # A moved change is included; missing table surfaces.
    assert data["missing_tables"] == ["AI Agent Process Names"]


def test_csv_report_one_row_per_table(tmp_path):
    text = report_to_csv(_report())
    lines = [ln for ln in text.splitlines() if ln.strip()]
    assert lines[0] == "table,key_attr,records,read_by,present,status"
    assert len(lines) == 3  # header + 2 tables
    assert "AI/LLM Web Domains" in lines[1] and "populated" in lines[1]
    assert "AI Agent Process Names" in lines[2] and "not on tenant" in lines[2]
    out = tmp_path / "r.csv"
    save_csv_report(_report(), out)
    assert out.read_text(encoding="utf-8").startswith("table,key_attr")


def test_html_report_is_self_contained(tmp_path):
    out = tmp_path / "r.html"
    save_html_report(_report(), out)
    html = out.read_text(encoding="utf-8")
    assert "AI/LLM Web Domains" in html
    assert "<html" in html.lower() and "<style" in html.lower()


def test_pdf_unavailable_raises_when_no_edge(tmp_path, monkeypatch):
    monkeypatch.setattr(pdf_mod, "find_edge", lambda: None)
    with pytest.raises(PdfUnavailableError):
        save_pdf_report(_report(), tmp_path / "r.pdf")


def test_pdf_invokes_edge_and_returns_path(tmp_path, monkeypatch):
    monkeypatch.setattr(pdf_mod, "find_edge", lambda: "fake-edge.exe")

    def fake_run(argv, **kwargs):
        # Extract the --print-to-pdf=<path> target and write a non-empty file,
        # mimicking Edge producing the PDF.
        target = next(
            a.split("=", 1)[1] for a in argv if a.startswith("--print-to-pdf=")
        )
        from pathlib import Path

        Path(target).write_bytes(b"%PDF-1.4 fake")

        class R:
            returncode = 0

        return R()

    monkeypatch.setattr(pdf_mod.subprocess, "run", fake_run)
    out = save_pdf_report(_report(), tmp_path / "r.pdf")
    assert out.exists() and out.stat().st_size > 0


def test_html_to_pdf_errors_when_edge_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(pdf_mod, "find_edge", lambda: "fake-edge.exe")
    monkeypatch.setattr(pdf_mod.subprocess, "run", lambda *a, **k: None)
    src = tmp_path / "in.html"
    src.write_text("<html><body>hi</body></html>", encoding="utf-8")
    with pytest.raises(RuntimeError, match="no PDF was written"):
        html_to_pdf(src, tmp_path / "out.pdf")
