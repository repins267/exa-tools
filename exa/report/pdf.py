"""Shared HTML->PDF conversion via headless Microsoft Edge (Windows).

Compliance and AI/LLM reports both print their self-contained HTML to PDF the
same way: locate ``msedge.exe`` and run ``--headless --print-to-pdf``. Factored
here so there is one Edge-invocation path, not two subtly different copies.

Edge is the only supported engine on purpose: it ships with Windows (the work
laptops this runs on), needs no Python PDF dependency, and renders the reports'
inline CSS faithfully. When Edge is absent we raise ``PdfUnavailableError`` rather
than silently writing HTML under a ``.pdf`` name.
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

# Standard install locations; 64-bit Edge lives under Program Files (x86).
_EDGE_CANDIDATES = (
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
)


class PdfUnavailableError(RuntimeError):
    """No headless browser is available to render a PDF."""


def find_edge() -> str | None:
    """Return the first existing msedge.exe path, or None if Edge is absent."""
    return next((p for p in _EDGE_CANDIDATES if Path(p).exists()), None)


def html_to_pdf(
    html_path: str | Path, pdf_path: str | Path, *, timeout: int = 60
) -> Path:
    """Print an existing HTML file to PDF with headless Edge.

    Returns the PDF path on success. Raises ``PdfUnavailableError`` when Edge is not
    installed; ``subprocess`` errors (non-zero exit, timeout) propagate so the
    caller can report them.
    """
    edge = find_edge()
    if not edge:
        raise PdfUnavailableError(
            "Microsoft Edge not found. Install Edge, or open the HTML report "
            "and use File -> Print -> Save as PDF."
        )
    src = Path(html_path)
    out = Path(pdf_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            edge,
            "--headless",
            "--disable-gpu",
            "--print-to-pdf-no-header",
            f"--print-to-pdf={out.resolve()}",
            str(src.resolve()),
        ],
        capture_output=True,
        timeout=timeout,
        check=True,
    )
    if not (out.exists() and out.stat().st_size > 0):
        raise RuntimeError("Edge ran but no PDF was written")
    return out


def html_str_to_pdf(
    html: str, pdf_path: str | Path, *, timeout: int = 60
) -> Path:
    """Render an HTML string to PDF via a temporary file."""
    tmp = tempfile.NamedTemporaryFile(suffix=".html", delete=False)
    tmp_path = Path(tmp.name)
    tmp.close()
    try:
        tmp_path.write_text(html, encoding="utf-8")
        return html_to_pdf(tmp_path, pdf_path, timeout=timeout)
    finally:
        tmp_path.unlink(missing_ok=True)
