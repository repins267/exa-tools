"""End-to-end detection timing (MTTD) for a simulate run.

Given a recorded :class:`~exa.simulate.ledger.SimRun` (what was sent, when, and
which named rules it should fire), this measures how long each expected rule
took to surface as an alert and a case in Threat Center -- the inject->detect
latency a SOC cares about.

The math is a pure function (:func:`compute_timing`) over already-fetched alert
and case rows, so it is fully unit-testable; :func:`poll_detections` is the thin
live loop that fetches on an interval until every expected rule is detected or a
deadline passes. Live alert/case field names vary by deployment, so extraction
tries several candidate keys and is validated against a real tenant in WS6.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from exa.simulate.ledger import SimRun

# Candidate keys for an alert/case rule label and creation time, most specific
# first. Deployments differ; we probe rather than assume one schema.
_RULE_KEYS = ("ruleName", "rule_name", "name", "displayName", "ruleId", "rule_id")
_TIME_KEYS = (
    "alertCreationTimestamp", "caseCreationTimestamp", "creationTimestamp",
    "detectionTimestamp", "startTime", "timestamp", "createdAt",
)
_HOST_KEYS = ("host", "hostName", "entityName", "asset", "src_host", "dest_host")


def _first(d: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for k in keys:
        v = d.get(k)
        if v not in (None, ""):
            return v
    return None


def _parse_time(value: Any) -> datetime | None:
    """Parse an epoch (s or ms) or ISO-8601 string to an aware UTC datetime."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        ts = float(value)
        if ts > 1_000_000_000_000:  # milliseconds
            ts /= 1000.0
        try:
            return datetime.fromtimestamp(ts, tz=UTC)
        except (ValueError, OSError):
            return None
    try:
        s = str(value).replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    except ValueError:
        return None


def _norm_rule(name: str) -> str:
    return (name or "").replace("[Sigma]", "").strip().lower()


def _rule_matches(row: dict[str, Any], expected_rule: str) -> bool:
    label = _norm_rule(str(_first(row, _RULE_KEYS) or ""))
    want = _norm_rule(expected_rule)
    return bool(want) and (want in label or label in want) and label != ""


def _host_matches(row: dict[str, Any], host: str) -> bool:
    if not host:
        return True
    got = str(_first(row, _HOST_KEYS) or "").lower()
    return host.lower() in got if got else True


@dataclass
class DetectionOutcome:
    behavior: str
    rule_name: str
    detected: bool = False
    first_alert_at: str | None = None
    first_case_at: str | None = None
    mttd_alert_seconds: float | None = None
    mttd_case_seconds: float | None = None


@dataclass
class TimingReport:
    run: SimRun
    started_at: str
    finished_at: str
    deadline_seconds: int
    outcomes: list[DetectionOutcome] = field(default_factory=list)

    @property
    def detected_count(self) -> int:
        return sum(1 for o in self.outcomes if o.detected)

    @property
    def total_expected(self) -> int:
        return len(self.outcomes)

    @property
    def all_detected(self) -> bool:
        return self.total_expected > 0 and self.detected_count == self.total_expected

    def _mean(self, attr: str) -> float | None:
        vals = [getattr(o, attr) for o in self.outcomes if getattr(o, attr) is not None]
        return round(sum(vals) / len(vals), 1) if vals else None

    @property
    def mean_mttd_alert(self) -> float | None:
        return self._mean("mttd_alert_seconds")

    @property
    def mean_mttd_case(self) -> float | None:
        return self._mean("mttd_case_seconds")

    def to_dict(self) -> dict[str, Any]:
        return {
            "run": self.run.to_dict(),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "deadline_seconds": self.deadline_seconds,
            "detected": self.detected_count,
            "total_expected": self.total_expected,
            "all_detected": self.all_detected,
            "mean_mttd_alert_seconds": self.mean_mttd_alert,
            "mean_mttd_case_seconds": self.mean_mttd_case,
            "outcomes": [asdict(o) for o in self.outcomes],
        }


def compute_timing(
    run: SimRun,
    alerts: list[dict[str, Any]],
    cases: list[dict[str, Any]],
) -> list[DetectionOutcome]:
    """Match alerts/cases to the run's expected rules and compute MTTD per rule.

    Pure: no I/O. MTTD is measured from ``run.sent_at`` to the earliest matching
    alert/case creation time, scoped to the run's host when one is set.
    """
    sent = _parse_time(run.sent_at)
    outcomes: list[DetectionOutcome] = []
    for exp in run.expected:
        if not exp.rule_name:
            continue  # table-feeding behaviors have no rule to time
        out = DetectionOutcome(behavior=exp.behavior, rule_name=exp.rule_name)

        def _earliest(rows: list[dict[str, Any]]) -> datetime | None:
            times = [
                t for r in rows
                if _rule_matches(r, exp.rule_name) and _host_matches(r, run.host)
                for t in [_parse_time(_first(r, _TIME_KEYS))]
                if t is not None
            ]
            return min(times) if times else None

        a = _earliest(alerts)
        c = _earliest(cases)
        if a is not None:
            out.detected = True
            out.first_alert_at = a.isoformat()
            if sent is not None:
                out.mttd_alert_seconds = round((a - sent).total_seconds(), 1)
        if c is not None:
            out.first_case_at = c.isoformat()
            if sent is not None:
                out.mttd_case_seconds = round((c - sent).total_seconds(), 1)
        outcomes.append(out)
    return outcomes


def poll_detections(
    client: Any,
    run: SimRun,
    *,
    deadline_seconds: int = 900,
    interval_seconds: int = 30,
    lookback_days: int = 1,
    alerts_fn: Callable[..., Any] | None = None,
    cases_fn: Callable[..., Any] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    on_poll: Callable[[TimingReport], None] | None = None,
) -> TimingReport:
    """Poll alerts+cases until every expected rule is detected or the deadline.

    ``alerts_fn``/``cases_fn`` default to the Threat Center searches; they are
    injectable for testing. Returns the final TimingReport.
    """
    if alerts_fn is None:
        from exa.case.alerts import search_alerts as alerts_fn  # type: ignore
    if cases_fn is None:
        from exa.case.cases import search_cases as cases_fn  # type: ignore

    started = datetime.now(UTC).isoformat(timespec="seconds")
    start = clock()
    report = TimingReport(
        run=run,
        started_at=started,
        finished_at=started,
        deadline_seconds=deadline_seconds,
        outcomes=[],
    )
    while True:
        alerts = alerts_fn(client, lookback_days=lookback_days, limit=500)
        cases = cases_fn(client, lookback_days=lookback_days, limit=500)
        alerts = alerts if isinstance(alerts, list) else []
        cases = cases if isinstance(cases, list) else []
        report.outcomes = compute_timing(run, alerts, cases)
        report.finished_at = datetime.now(UTC).isoformat(timespec="seconds")
        if on_poll is not None:
            on_poll(report)
        if report.all_detected or (clock() - start) >= deadline_seconds:
            break
        sleep(interval_seconds)
    return report


def _fmt_secs(v: float | None) -> str:
    if v is None:
        return "&mdash;"
    if v < 90:
        return f"{v:.0f}s"
    return f"{v / 60:.1f}m"


def render_timing_html(report: TimingReport) -> str:
    """A self-contained internal MTTD report (dark/light, no external assets)."""
    r = report
    rows = "".join(
        "<tr>"
        f"<td>{o.behavior}</td>"
        f"<td>{o.rule_name.replace('[Sigma] ', '')}</td>"
        f"<td>{'&#10003;' if o.detected else '&#10007;'}</td>"
        f"<td class='n'>{_fmt_secs(o.mttd_alert_seconds)}</td>"
        f"<td class='n'>{_fmt_secs(o.mttd_case_seconds)}</td>"
        "</tr>"
        for o in r.outcomes
    )
    css = (
        "body{margin:0;padding:32px;background:#15181c;color:#e8eaed;"
        "font:15px/1.5 Segoe UI,Roboto,Arial,sans-serif}"
        "@media(prefers-color-scheme:light){body{background:#fff;color:#1a1d21}}"
        ".wrap{max-width:900px;margin:0 auto}h1{font-size:23px;margin:0 0 4px}"
        ".sub{color:#9aa3ad;font-size:13px;margin-bottom:20px}"
        "table{border-collapse:collapse;width:100%;font-size:14px}"
        "th,td{text-align:left;padding:7px 10px;border-bottom:1px solid #2a2f36}"
        "td.n{text-align:right;font-variant-numeric:tabular-nums}"
        ".cards{display:flex;gap:12px;margin:16px 0}"
        ".card{background:#1c2026;border:1px solid #2a2f36;border-radius:8px;padding:12px 16px}"
        "@media(prefers-color-scheme:light){.card{background:#f7f8fa;border-color:#e3e6ea}"
        "th,td{border-color:#e3e6ea}}"
        ".v{font-size:24px;font-weight:600}.l{color:#9aa3ad;font-size:12px}"
    )
    return (
        f"<!doctype html><html><head><meta charset='utf-8'>"
        f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>AI/LLM Detection Timing</title><style>{css}</style></head><body><div class='wrap'>"
        f"<h1>Detection timing &mdash; {r.run.scenario or r.run.kind}</h1>"
        f"<div class='sub'>Tenant {r.run.tenant} &middot; run {r.run.run_id} &middot; "
        f"marker {r.run.marker} &middot; sent {r.run.sent_at}</div>"
        f"<div class='cards'>"
        f"<div class='card'><div class='v'>{r.detected_count}/{r.total_expected}</div>"
        f"<div class='l'>Rules detected</div></div>"
        f"<div class='card'><div class='v'>{_fmt_secs(r.mean_mttd_alert)}</div>"
        f"<div class='l'>Mean MTTD (alert)</div></div>"
        f"<div class='card'><div class='v'>{_fmt_secs(r.mean_mttd_case)}</div>"
        f"<div class='l'>Mean MTTD (case)</div></div></div>"
        f"<table><thead><tr><th>Behavior</th><th>Expected rule</th><th>Det.</th>"
        f"<th>MTTD alert</th><th>MTTD case</th></tr></thead><tbody>{rows}</tbody></table>"
        f"</div></body></html>"
    )
