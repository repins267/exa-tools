"""Self-contained report theme: light/dark, embedded logo, cards, panels, tables.

Every report type (compliance, MITRE coverage, tenant config, AI-posture) renders
through `page()` so they share one look. The output is a single HTML file with no
external assets: the logo is embedded as base64 and the light/dark toggle is inline
JS. Palette adapted from the ExabeamLabs MITRE Coverage Report.

Theme model (theme-aware, three states):
  - bare :root                             -> light (default)
  - @media prefers-color-scheme: dark      -> dark, unless the reader forced light
  - :root[data-theme="dark"|"light"]       -> the reader's explicit toggle wins

For PDF export pass initial_theme="light" (print wants light); the interactive
toggle still works in the browser and persists via localStorage.
"""

from __future__ import annotations

import html as _htmllib
from pathlib import Path

# --- palettes ---------------------------------------------------------------

_LIGHT = (
    "--bg:#f6f8fb;--panel:#ffffff;--panel2:#f1f5fa;--border:#dbe3ec;"
    "--text:#0e1a2b;--muted:#5b6b80;--good:#106D00;--warn:#b45309;--bad:#be123c;"
    "--shadow:rgba(20,40,70,0.10);--header1:#eef3f9;--header2:#e4ecf5;"
    "--logobd:#1a2230;--inputbg:#f4f7fb;--thead:#eef3f9;--hover:rgba(0,107,255,0.06);"
    "--acc1:#009D00;--acc2:#006BFF;--purple:#8300D8;--brandbg:#0a0e14;"
)
_DARK = (
    "--bg:#0b0f14;--panel:#0f1720;--panel2:#111b26;--border:#223042;"
    "--text:#e7eef8;--muted:#9fb1c6;--good:#4CDB00;--warn:#fbbf24;--bad:#fb7185;"
    "--shadow:rgba(0,0,0,0.35);--header1:#1a2a3a;--header2:#0e1620;"
    "--logobd:#2b3c52;--inputbg:#0b121a;--thead:#0b121a;--hover:rgba(39,178,255,0.08);"
    "--acc1:#4CDB00;--acc2:#27B2FF;--purple:#B383FF;--brandbg:#0a0e14;"
)

_CSS_VARS = (
    ":root{" + _LIGHT + "--radius:16px;"
    "--mono:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono','Courier New',monospace;"
    "--sans:ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial;}\n"
    ':root[data-theme="dark"]{' + _DARK + "}\n"
    "@media (prefers-color-scheme: dark){:root:not([data-theme=\"light\"]){" + _DARK + "}}\n"
)

# Layout CSS uses var(...) only, so it works in both themes. No f-string here —
# the braces are literal.
_CSS_LAYOUT = """
*{box-sizing:border-box}
html,body{background:var(--bg)}
body{margin:0;font-family:var(--sans);color:var(--text);
  background:radial-gradient(1200px 600px at 15% 10%, color-mix(in srgb, var(--panel2) 60%, transparent), transparent 60%),
             radial-gradient(900px 500px at 85% 0%, color-mix(in srgb, var(--panel) 50%, transparent), transparent 55%),
             var(--bg);}
.wrap{max-width:1320px;margin:0 auto;padding:20px 18px 60px}
.topbar{display:flex;align-items:center;justify-content:space-between;gap:14px;padding:14px 16px;
  border:1px solid var(--border);background:linear-gradient(180deg,var(--panel),color-mix(in srgb,var(--panel) 65%,transparent));
  box-shadow:0 10px 28px var(--shadow);border-radius:var(--radius)}
.brand{display:flex;align-items:center;gap:12px;min-width:260px}
.logo{height:48px;display:flex;align-items:center}
.logo img{height:100%;width:auto;max-width:300px;object-fit:contain;display:block}
.logo .logo-light{display:none}
:root[data-theme="light"] .logo .logo-dark{display:none}
:root[data-theme="light"] .logo .logo-light{display:block}
@media (prefers-color-scheme: light){:root:not([data-theme="dark"]) .logo .logo-dark{display:none}
  :root:not([data-theme="dark"]) .logo .logo-light{display:block}}
.title h1{margin:0;font-size:19px;font-weight:800;letter-spacing:.2px}
.title .sub{margin-top:4px;font-size:12px;color:var(--muted);font-family:var(--mono)}
.right{display:flex;align-items:center;gap:12px}
.meta{text-align:right;color:var(--muted);font-size:12px;font-family:var(--mono)}
.toggle{cursor:pointer;border:1px solid var(--border);background:var(--panel2);color:var(--text);
  border-radius:999px;padding:8px 12px;font-family:var(--mono);font-size:12px;line-height:1}
.toggle:hover{border-color:var(--muted)}
.grid{margin-top:18px;display:grid;grid-template-columns:repeat(12,1fr);gap:14px}
.card{grid-column:span 3;padding:14px;border:1px solid var(--border);
  background:linear-gradient(180deg,var(--panel2),color-mix(in srgb,var(--panel2) 75%,transparent));
  border-radius:var(--radius);box-shadow:0 10px 24px var(--shadow)}
.card .label{color:var(--muted);font-size:12px;margin-bottom:8px}
.card .value{font-size:28px;font-weight:800;letter-spacing:.2px}
.card .hint{margin-top:10px;font-size:12px;color:var(--muted)}
.value.good{color:var(--good)}.value.warn{color:var(--warn)}.value.bad{color:var(--bad)}
.panel{grid-column:span 12;padding:14px 14px 6px;border:1px solid var(--border);
  background:linear-gradient(180deg,var(--panel),color-mix(in srgb,var(--panel) 70%,transparent));
  border-radius:var(--radius);box-shadow:0 10px 24px var(--shadow)}
.panel h2{margin:2px 0 8px;font-size:15px;font-weight:800;letter-spacing:.2px}
.panel .sub{margin:0 0 10px;color:var(--muted);font-size:12px}
.bar{height:10px;border-radius:999px;background:var(--panel2);border:1px solid var(--border);overflow:hidden;margin:6px 0}
.bar>span{display:block;height:100%;background:linear-gradient(90deg,var(--acc1),var(--acc2))}
.tbl-wrap{overflow-x:auto}
table.data-table{width:100%;border-collapse:collapse;font-family:var(--mono);font-size:12px;margin:10px 0 16px}
table.data-table thead th{text-align:left;background:var(--thead);color:var(--muted);
  border-bottom:1px solid var(--border);padding:10px;position:sticky;top:0;z-index:2}
table.data-table tbody td{padding:9px 10px;border-bottom:1px solid color-mix(in srgb,var(--border) 60%,transparent);vertical-align:top}
table.data-table tbody tr:hover{background:var(--hover)}
.footer-note{margin-top:8px;color:var(--muted);font-size:12px;font-family:var(--mono)}
.panel.half{grid-column:span 6}
@media (max-width:900px){.panel.half{grid-column:span 12}}
.chart{margin:8px 0}
.chart .row{display:flex;align-items:center;gap:8px;margin:5px 0;font-family:var(--mono);font-size:11px}
.chart .lbl{width:40%;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.chart .track{flex:1;background:var(--panel2);border:1px solid var(--border);border-radius:6px;overflow:hidden;height:14px}
.chart .fill{height:100%;background:linear-gradient(90deg,var(--acc1),var(--acc2))}
.chart .val{width:78px;text-align:right;color:var(--text)}
.pie{display:flex;align-items:center;gap:16px;flex-wrap:wrap}
.pie .disc{width:130px;height:130px;border-radius:50%;flex:none;border:1px solid var(--border)}
.pie .legend{font-family:var(--mono);font-size:11px}
.pie .legend .r{display:flex;align-items:center;gap:7px;margin:3px 0}
.pie .sw{width:11px;height:11px;border-radius:2px;flex:none}
.empty{font-family:var(--mono);font-size:11px;color:var(--muted);padding:14px;border:1px dashed var(--border);border-radius:10px;text-align:center}
.vizbadge{display:inline-block;font-family:var(--mono);font-size:10px;color:var(--muted);border:1px solid var(--border);border-radius:999px;padding:2px 8px;margin-left:8px}

@media (max-width:980px){.card{grid-column:span 6}.meta{display:none}}
@media (max-width:560px){.card{grid-column:span 12}}
@media print{.toggle{display:none}body{background:#fff}}
"""

_TOGGLE_JS = """
<script>
(function(){
  var root=document.documentElement, KEY="exa-report-theme";
  try{var s=localStorage.getItem(KEY); if(s){root.setAttribute("data-theme",s);}}catch(e){}
  function cur(){var a=root.getAttribute("data-theme");
    if(a) return a;
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark":"light";}
  window.__toggleTheme=function(){var n=cur()==="dark"?"light":"dark";
    root.setAttribute("data-theme",n); try{localStorage.setItem(KEY,n);}catch(e){}
    var b=document.getElementById("themeBtn"); if(b) b.textContent=(n==="dark"?"☀ Light":"☾ Dark");};
  document.addEventListener("DOMContentLoaded",function(){
    var b=document.getElementById("themeBtn"); if(b) b.textContent=(cur()==="dark"?"☀ Light":"☾ Dark");});
})();
</script>
"""


def _esc(v) -> str:
    return _htmllib.escape("" if v is None else str(v))


def _load_b64(name: str) -> str:
    """Load a base64 asset shipped in this package (empty string if missing)."""
    p = Path(__file__).resolve().parent / name
    return p.read_text(encoding="utf-8").strip() if p.exists() else ""


# --- component helpers ------------------------------------------------------


def stat_card(label: str, value, status: str = "", hint: str = "") -> str:
    """A KPI card. status in {'', 'good', 'warn', 'bad'} colors the value."""
    cls = f"value {status}".strip()
    hint_html = f'<div class="hint">{_esc(hint)}</div>' if hint else ""
    return (
        f'<div class="card"><div class="label">{_esc(label)}</div>'
        f'<div class="{cls}">{_esc(value)}</div>{hint_html}</div>'
    )


def coverage_bar(pct: float) -> str:
    """A 0-100 progress bar."""
    p = max(0, min(100, round(float(pct))))
    return f'<div class="bar"><span style="width:{p}%"></span></div>'


def data_table(rows: list[dict], table_id: str = "tbl", max_rows: int = 1000) -> str:
    """Render a list of uniform dicts as a sortable-looking data table."""
    if not rows:
        return '<div class="footer-note">No rows.</div>'
    headers = list(rows[0].keys())
    head = "".join(f"<th>{_esc(h)}</th>" for h in headers)
    body_rows = []
    for r in rows[:max_rows]:
        cells = "".join(f"<td>{_esc(r.get(h, ''))}</td>" for h in headers)
        body_rows.append(f"<tr>{cells}</tr>")
    more = ""
    if len(rows) > max_rows:
        more = f'<div class="footer-note">Showing {max_rows} of {len(rows)} rows.</div>'
    return (
        f'<div class="tbl-wrap"><table class="data-table" id="{_esc(table_id)}">'
        f"<thead><tr>{head}</tr></thead><tbody>{''.join(body_rows)}</tbody></table></div>{more}"
    )


def panel(title: str, body_html: str, subtitle: str = "", half: bool = False) -> str:
    """A section panel. half=True makes it span 6 columns (two per row)."""
    sub = f'<div class="sub">{_esc(subtitle)}</div>' if subtitle else ""
    cls = "panel half" if half else "panel"
    return f'<div class="{cls}"><h2>{_esc(title)}</h2>{sub}{body_html}</div>'


def page(
    title: str,
    subtitle: str = "",
    cards_html: str = "",
    panels_html: str = "",
    meta_html: str = "",
    initial_theme: str = "dark",
) -> str:
    """Assemble a complete self-contained HTML report.

    initial_theme: 'auto' (follow the OS), 'light', or 'dark'. Use 'light' when
    the HTML will be rendered to PDF.
    """
    ld = _load_b64("_logo_dark_b64.txt")
    ll = _load_b64("_logo_light_b64.txt")
    logo_html = (
        f'<img class="logo-dark" src="data:image/svg+xml;base64,{ld}" alt="Exabeam" />'
        f'<img class="logo-light" src="data:image/svg+xml;base64,{ll}" alt="Exabeam" />'
    )
    theme_attr = f' data-theme="{initial_theme}"' if initial_theme in ("light", "dark") else ""
    return f"""<!DOCTYPE html>
<html lang="en"{theme_attr}>
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{_esc(title)}</title>
<style>
{_CSS_VARS}{_CSS_LAYOUT}
</style>
</head>
<body>
<div class="wrap">
  <div class="topbar">
    <div class="brand">
      <div class="logo">{logo_html}</div>
      <div class="title"><h1>{_esc(title)}</h1><div class="sub">{_esc(subtitle)}</div></div>
    </div>
    <div class="right">
      <div class="meta">{meta_html}</div>
      <button id="themeBtn" class="toggle" onclick="__toggleTheme()">Theme</button>
    </div>
  </div>
  <div class="grid">
    {cards_html}
    {panels_html}
  </div>
</div>
{_TOGGLE_JS}
</body>
</html>"""
