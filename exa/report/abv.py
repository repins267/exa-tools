"""Render the Praxen Agent-Behavior-Verification report in the exa-tools house style.

Mirrors the Praxen report layout (verdict banner -> remit-coverage scorecard ->
findings register -> method/context) but in the branded theme (dark default, Exabeam
logo + colors, KPI cards, tables). The data below is the adjudicated result recorded in
security/praxen/results/2026-08-19-exa-tools-abv.md; update it there and here together.
"""

from __future__ import annotations

from exa.report.theme import _esc, page, panel, stat_card

# --- the adjudicated ABV result (see security/praxen/WORKER_REMIT.md for the policy) ---
ABV = {
    "target": "exa-tools MCP",
    "date": "2026-08-19",
    "commit": "b8c31d9",
    "tests": 1004,
    "method": "Praxen method (Agent Behavior Verification): each declared POLICY clause verified "
              "against the code with line citations.",
    "clauses": [
        {"id": "ABV-001", "policy": "Read-only by default; write tools hidden + refused unless --allow-writes",
         "status": "HELD", "evidence": "tools.py:751 (visible_tools), :789 (dispatch gate), :123 (WRITE_TOOLS)"},
        {"id": "ABV-002", "policy": "No secret/credential reaches the model or a result",
         "status": "HELD", "evidence": "tenant tools return nickname/region/kind/ttl only; secrets in OS keyring"},
        {"id": "ABV-003", "policy": "Telemetry canonicalized before it reaches the model",
         "status": "HELD", "evidence": "tools.py:46,51 (_ok -> scrub_result on every result)"},
        {"id": "ABV-004", "policy": "No un-neutralized active content / secrets persisted on writes",
         "status": "FIXED", "evidence": "guardrails/__init__.py:54 (was string-only); now covers list write fields"},
        {"id": "ABV-005", "policy": "Audit log is metadata-only; never notes/secrets/payloads",
         "status": "HELD", "evidence": "audit.py:38,93,116 (fixed metadata + safe_action); :90 (fail-open)"},
        {"id": "ABV-006", "policy": "Tenant kind (demo/customer) readable for the guardrail",
         "status": "HELD", "evidence": "get_active_tenant/list_tenants surface kind; set_tenant_kind writes it"},
        {"id": "ABV-007", "policy": "No shell/subprocess/eval; only the Exabeam tenant is contacted",
         "status": "HELD", "evidence": "grep os.system|subprocess|eval(|exec( over dispatch+audit = 0 hits"},
        {"id": "ABV-008", "policy": "Result size is bounded",
         "status": "HELD", "evidence": "tools.py:26 (_MAX_RESULT_BYTES=800_000) + progressive truncation"},
    ],
    "findings": [
        {
            "id": "ABV-004", "severity": "LOW", "resolved": True,
            "headline": "List-valued write fields (tags) bypassed output neutralization.",
            "policy": "No un-neutralized active content / secrets persisted on writes.",
            "evidence": "tools.py:799-801 (writes route through neutralize_write_args); "
                        "guardrails/__init__.py:54 (if field in _WRITE_TEXT_FIELDS and isinstance(val, str)). "
                        "update_case / update_alert accept a tags[] list; a list value is not a str, so it was skipped. "
                        "A tag carrying =HYPERLINK(...) would persist to the alert/case and survive to export.",
            "why_missed": "Every red-team write payload (A10/A11/D01-D03) targets a STRING field. None exercised a "
                          "LIST field, so the string-only path passed every eval while the list path stayed unguarded. "
                          "Eval coverage is only as complete as the fixtures; ABV checks the policy, not a fixture set.",
            "fix": "neutralize_write_args now neutralizes each string element of list write fields "
                   "(_WRITE_LIST_FIELDS = {tags}). Clean tags pass through; an active-content tag is defanged.",
            "verified": "tests/test_mcp.py::TestGuardrails::test_neutralize_write_args_covers_tags_list; landed main b8c31d9.",
        }
    ],
}

_TONE = {"HELD": "good", "FIXED": "warn", "DIVERGENCE": "bad"}


def _chip(text: str, tone: str) -> str:
    return (f'<span class="vizbadge" style="color:var(--{tone});'
            f'border-color:color-mix(in srgb,var(--{tone}) 55%,var(--border))">{_esc(text)}</span>')


def _scorecard(clauses: list[dict]) -> str:
    rows = ""
    for c in clauses:
        tone = _TONE.get(c["status"], "muted")
        rows += (
            f'<tr><td><b>{_esc(c["id"])}</b></td>'
            f'<td>{_esc(c["policy"])}</td>'
            f'<td>{_chip(c["status"], tone)}</td>'
            f'<td class="footer-note" style="margin:0">{_esc(c["evidence"])}</td></tr>'
        )
    return (
        '<div class="tbl-wrap"><table class="data-table"><thead><tr>'
        '<th>Clause</th><th>Policy</th><th>Status</th><th>Evidence</th>'
        f'</tr></thead><tbody>{rows}</tbody></table></div>'
    )


def _finding_card(f: dict) -> str:
    badges = _chip(f'DIVERGENCE · {f["severity"]}', "warn")
    if f.get("resolved"):
        badges += " " + _chip("RESOLVED", "good")
    rows = [
        ("Policy", f["policy"], ""),
        ("Evidence", f["evidence"], ""),
        ("Why the red-team evals missed it", f["why_missed"], ""),
        ("Fix", f["fix"], "color:var(--good)"),
        ("Verified", f["verified"], ""),
    ]
    body = "".join(
        f'<div class="footer-note" style="margin-top:8px;{style}">'
        f'<b>{_esc(label)}:</b> {_esc(text)}</div>'
        for label, text, style in rows
    )
    return (
        '<div style="border:1px solid var(--border);border-radius:12px;padding:14px;'
        'background:linear-gradient(180deg,var(--panel2),transparent)">'
        f'<div style="display:flex;gap:8px;align-items:center;margin-bottom:6px">{badges}'
        f'<b style="font-family:var(--mono);font-size:13px">{_esc(f["id"])}</b></div>'
        f'<div style="font-weight:700;margin-bottom:2px">{_esc(f["headline"])}</div>'
        f'{body}</div>'
    )


def render_abv(data: dict = ABV) -> str:
    """Branded HTML for the ABV report."""
    clauses = data["clauses"]
    held = sum(1 for c in clauses if c["status"] == "HELD")
    fixed = sum(1 for c in clauses if c["status"] == "FIXED")
    diverg = sum(1 for c in clauses if c["status"] in ("FIXED", "DIVERGENCE"))

    cards = "".join([
        stat_card("Clauses", len(clauses), "", "declared policy"),
        stat_card("Held", held, "good", "behavior matches policy"),
        stat_card("Divergences", diverg, "warn", f"{fixed} found + fixed"),
        stat_card("Verdict", "Policy holds", "good", "manual pass; see Praxen note"),
        stat_card("Snapshot", data["date"], "", "point-in-time, not a live claim"),
    ])

    findings_html = "".join(_finding_card(f) for f in data["findings"]) or \
        '<div class="empty">No open divergences.</div>'

    method = (
        f'<div class="footer-note">{_esc(data["method"])} Target: <b>{_esc(data["target"])}</b>, '
        f'point-in-time snapshot {_esc(data["date"])} (this render does not assert a live commit or '
        'test count — see the note below). Branded render of the adjudicated result in '
        '<code>security/praxen/results/2026-08-19-exa-tools-abv.md</code>.</div>'
        '<div class="footer-note" style="margin-top:8px"><b>Re-run the real scan:</b> '
        '<code>claude plugin install praxen@open-agent-ai-security</code>, then point Praxen at this repo '
        'against <code>security/praxen/WORKER_REMIT.md</code> for an independent second opinion.</div>'
    )

    praxen_note = (
        '<div class="footer-note">An independent <b>Praxen v1.2.1</b> ABV scan (2026-08-19) went beyond '
        'this manual pass and surfaced additional findings the manual pass missed — 1 HIGH '
        '(model-supplied <code>output_path</code> escaping the <code>reports/</code> root), plus MEDIUM/LOW '
        'items (error-path not canonicalized, assignee/queue not neutralized, SSE transport unauthenticated, '
        'and this report\'s own hardcoded drift). Those are remediated separately; results in '
        '<code>security/praxen/results/</code>. Treat this manual scorecard as one input, not the whole '
        'assurance picture — the independent scan is the fuller check.</div>'
    )

    panels = "".join([
        panel(f"Remit coverage scorecard ({len(clauses)})", _scorecard(clauses),
              "each declared policy clause vs observed behavior"),
        panel(f"Findings register ({len(data['findings'])})", findings_html,
              "divergences from declared policy — found and fixed this pass"),
        panel("Independent Praxen scan", praxen_note, "what the manual pass missed"),
        panel("Method & re-run", method, "Praxen — Agent Behavior Verification"),
    ])
    meta = [data["target"], "Praxen ABV (manual snapshot)", data["date"]]
    return page(
        f"exa-tools · Praxen ABV · {data['target']}",
        f"Agent Behavior Verification · {held} of {len(clauses)} clauses held · {fixed} fixed · {data['date']}",
        cards, panels, "".join(f"<div>{_esc(m)}</div>" for m in meta), initial_theme="dark",
    )
