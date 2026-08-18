"""Tests for the search verification battery (`exa verify search`).

The probes themselves cannot be unit tested -- they measure a live tenant. What CAN
and must be tested is the **verdict logic**, because that is where a wrong answer
would be most damaging: a probe that reports CONFIRMED when its precondition failed
would put a false "verified live" row into the vault, and a documented-not-verified
claim would become a verified-wrong one.

So every test here drives a probe with a scripted fake endpoint and asserts the
verdict, especially the INCONCLUSIVE cases.

Nothing here touches the network or `~/.exa` -- `_VERIFY_DIR` is pinned per-test.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from typer.testing import CliRunner

from exa.cli.app import app
from exa.exceptions import ExaAPIError
from exa.search import verify as sv

runner = CliRunner()


# ---------------------------------------------------------------------------
# Fixtures -- never read the developer's real cached state
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _pin_verify_dir(tmp_path, monkeypatch):
    """Pin the artifact directory.

    Without this, load_last_verification() would find a real run against a real
    tenant in ~/.exa/search-verify and the assertions would pass against live
    customer data instead of the fixture.
    """
    monkeypatch.setattr(sv, "_VERIFY_DIR", tmp_path / "search-verify")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    return tmp_path


class FakeClient:
    """Scripted stand-in for ExaClient.

    `post_handler(body, index)` returns a response dict or raises ExaAPIError.
    Every request body is recorded so tests can assert on what was SENT, which is
    how the EXA-SEARCH-QUERY-VS-FILTER and EXA-SEARCH-FILTER-400 contracts are
    checked.
    """

    def __init__(self, post_handler=None, get_handler=None, tenant: str = "faketenant"):
        self.tenant = tenant
        self.base_url = "https://api.us-west.exabeam.cloud"
        self._post_handler = post_handler
        self._get_handler = get_handler
        self.posts: list[dict[str, Any]] = []
        self.gets: list[str] = []

    def post(self, path: str, *, json: Any = None, params: Any = None) -> Any:
        self.posts.append(json)
        if self._post_handler is None:
            return {"rows": []}
        return self._post_handler(json, len(self.posts) - 1)

    def get(self, path: str, *, params: Any = None) -> Any:
        self.gets.append(path)
        if self._get_handler is None:
            raise ExaAPIError(404, "no get handler")
        return self._get_handler(path, params)

    def close(self) -> None:
        pass


def _rows(values: list[str], field: str = "activity_type") -> dict[str, Any]:
    return {"rows": [{field: v} for v in values]}


def _n_rows(count: int, field: str = "activity_type", value: str = "authentication"):
    return {"rows": [{field: value} for _ in range(count)]}


def _days_of(body: dict[str, Any]) -> int:
    """Window width in days, from the body itself.

    Handlers key off this rather than off call index: the probes now issue a
    variable number of preliminary calls (spelling probes, shape probes) before the
    measurement sweep, and an index-keyed fixture silently mis-attributes every
    response the moment a probe gains a call.
    """
    fmt = "%Y-%m-%dT%H:%M:%S.000Z"
    start = sv.datetime.strptime(body["startTime"], fmt)
    end = sv.datetime.strptime(body["endTime"], fmt)
    return round((end - start).total_seconds() / 86400)


def _api_error(status: int, code: str, message: str) -> ExaAPIError:
    """An ExaAPIError carrying a real Exabeam error body.

    The live battery's whole diagnosis came out of these bodies, so the fixtures
    have to have the same shape -- a thinner fixture passes while the real call
    tells you something the code cannot read.
    """
    return ExaAPIError(status, json.dumps({"errors": [{"id": code, "message": message}]}))


_RANGE_ERROR = (
    "Invalid query time range. Context Table does not support time range queries "
    "90 days or more."
)
_NON_KEY_ERROR = "Context table non-key field : aillm_domain not found"
_TYPE_ERROR = 'Field src_ip has value "null", incompatible for type ipv4/ipv6'


# ---------------------------------------------------------------------------
# Error-body parsing -- the status code alone is not a diagnosis
# ---------------------------------------------------------------------------


def test_parse_error_extracts_the_exabeam_code_and_message():
    parsed = sv._parse_error(json.dumps({"errors": [{"id": "AAA_ESA_1006_400",
                                                    "message": _RANGE_ERROR}]}))
    assert parsed["error_code"] == "AAA_ESA_1006_400"
    assert "90 days or more" in parsed["error_message"]


def test_parse_error_handles_a_flat_body_and_a_non_json_string():
    flat = sv._parse_error({"code": "AAA_ESA_1000_400", "message": "bad value"})
    assert flat["error_code"] == "AAA_ESA_1000_400"
    plain = sv._parse_error("upstream connect error")
    assert plain["error_code"] is None
    assert "upstream" in plain["error_message"]


def test_call_records_the_error_code_so_probes_can_branch_on_it():
    client = FakeClient(
        lambda body, index: (_ for _ in ()).throw(
            _api_error(400, "AAA_ESA_1006_400", _RANGE_ERROR)
        )
    )
    probe = sv.Probe(probe="t", claim="c", source="s")
    now = sv.datetime.now(sv.UTC)
    outcome = sv._call(client, probe, "x", sv._build_body("", now, now))
    assert outcome["error_code"] == "AAA_ESA_1006_400"
    assert "90 days or more" in outcome["error_message"]


# ---------------------------------------------------------------------------
# Body construction contracts
# ---------------------------------------------------------------------------


def test_build_body_always_sends_filter_key():
    """EXA-SEARCH-FILTER-400: omitting `filter` returns 400 and masks the probe."""
    body = sv._build_body("", sv.datetime.now(sv.UTC), sv.datetime.now(sv.UTC))
    assert "filter" in body


def test_build_body_sends_eql_in_both_query_and_filter_by_default():
    """EXA-SEARCH-QUERY-VS-FILTER: the default shape must be the safe one."""
    eql = 'activity_type:"authentication"'
    body = sv._build_body(eql, sv.datetime.now(sv.UTC), sv.datetime.now(sv.UTC))
    assert body["query"] == eql
    assert body["filter"] == eql


def test_build_body_can_omit_the_limit_key_entirely():
    """Probe 1 needs 'no limit key at all', which is different from limit=3000."""
    now = sv.datetime.now(sv.UTC)
    assert "limit" not in sv._build_body("", now, now, omit_limit=True)
    assert sv._build_body("", now, now, limit=17)["limit"] == 17


# ---------------------------------------------------------------------------
# P0 -- query vs filter regression
# ---------------------------------------------------------------------------


def _p0_handler(*, query_only_distinct: int, both_distinct: int = 1, unfiltered: int = 3):
    """Script the four P0 calls: sample, both, query-only, neither."""

    def handler(body, index):
        if index == 0:  # unfiltered sample -- mixed values, 'rare' least common
            return _rows(["authentication"] * 10 + ["file-write"] * 3 + ["rare"])
        if index == 1:  # a: both fields
            return _rows(["rare"] * 5 if both_distinct == 1 else ["rare", "other"])
        if index == 2:  # b: query only
            return _rows(["rare"] * 5 if query_only_distinct == 1 else ["rare", "other", "x"])
        return _rows(["authentication", "file-write", "rare"][:unfiltered])

    return handler


def test_p0_confirmed_when_query_only_returns_multiple_values():
    client = FakeClient(_p0_handler(query_only_distinct=3))
    probe = sv.probe_query_vs_filter(client, now=sv.datetime.now(sv.UTC))
    assert probe.verdict == sv.CONFIRMED
    assert probe.precondition_met is True
    assert "double-send" in probe.reason


def test_p0_refuted_when_query_only_filters_correctly():
    client = FakeClient(_p0_handler(query_only_distinct=1))
    probe = sv.probe_query_vs_filter(client, now=sv.datetime.now(sv.UTC))
    assert probe.verdict == sv.REFUTED
    # A REFUTED here would let someone simplify events.py. The reason must say
    # not to, on one region's evidence.
    assert "other region" in probe.reason


def test_p0_inconclusive_when_only_one_activity_type_exists():
    """A tenant with one activity_type cannot show filtering. Must not guess."""
    client = FakeClient(lambda body, index: _rows(["authentication"] * 10))
    probe = sv.probe_query_vs_filter(client, now=sv.datetime.now(sv.UTC))
    assert probe.verdict == sv.INCONCLUSIVE
    assert probe.precondition_met is False


def test_p0_flags_a_new_finding_when_filter_itself_does_not_narrow():
    """If `filter` stops filtering, that is worse than the known defect."""
    client = FakeClient(_p0_handler(query_only_distinct=3, both_distinct=2))
    probe = sv.probe_query_vs_filter(client, now=sv.datetime.now(sv.UTC))
    assert probe.verdict == sv.INCONCLUSIVE
    assert "NEW FINDING" in probe.reason


# ---------------------------------------------------------------------------
# P1 -- 3,000 is a default, not a cap
# ---------------------------------------------------------------------------


def _p1_handler(*, half: int, no_limit: int, at_10000: int):
    def handler(body, index):
        if index in (0, 1):
            return _n_rows(half)
        if index == 2:
            return _n_rows(no_limit)
        if index == 3:
            return _n_rows(3000)
        if index == 4:
            return _n_rows(min(5000, at_10000))
        return _n_rows(at_10000)

    return handler


def test_p1_confirmed_when_a_higher_limit_returns_more_than_3000():
    client = FakeClient(_p1_handler(half=4000, no_limit=3000, at_10000=7500))
    probe = sv.probe_limit_default(client, now=sv.datetime.now(sv.UTC))
    assert probe.verdict == sv.CONFIRMED
    assert probe.observed["default_matches_3000"] is True


def test_p1_refuted_when_3000_behaves_as_a_hard_cap():
    """Halves sum above 3,000 but the whole window stops at 3,000 -- a real cap."""
    client = FakeClient(_p1_handler(half=4000, no_limit=3000, at_10000=3000))
    probe = sv.probe_limit_default(client, now=sv.datetime.now(sv.UTC))
    assert probe.verdict == sv.REFUTED
    assert "HARD" in probe.reason


def test_p1_inconclusive_when_the_tenant_has_fewer_than_3000_events():
    """The dangerous case: 3,000 rows back because only 3,000 exist."""
    client = FakeClient(_p1_handler(half=500, no_limit=1000, at_10000=1000))
    probe = sv.probe_limit_default(client, now=sv.datetime.now(sv.UTC))
    assert probe.verdict == sv.INCONCLUSIVE
    assert probe.precondition_met is False
    assert "proves nothing" in probe.reason


def test_p1_notes_when_the_default_is_not_3000():
    client = FakeClient(_p1_handler(half=4000, no_limit=1234, at_10000=7500))
    probe = sv.probe_limit_default(client, now=sv.datetime.now(sv.UTC))
    assert probe.observed["default_matches_3000"] is False
    assert "NOT the documented default" in probe.reason


# ---------------------------------------------------------------------------
# P2 -- context-table window
# ---------------------------------------------------------------------------


_TABLE = {
    "id": "pg5mmUzim3",
    "name": "Public AI Domains and Risk",
    "displayName": None,
    "attributes": [
        {"id": "aillm_domain", "displayName": "Domain", "isKey": True},
        {"id": "risk_level", "displayName": "Risk", "isKey": False},
    ],
}


def _table_get_handler(records: list[dict[str, Any]], tables=None):
    def handler(path: str, params):
        if path.endswith("/records"):
            return {"records": records, "totalItems": len(records)}
        if path == "/context-management/v1/tables":
            return tables if tables is not None else [_TABLE]
        return _TABLE

    return handler


def _p2_post_handler(
    table_rows: dict[int, int],
    control_rows: dict[int, int],
    *,
    qualified_ok: bool = True,
    range_error_at: tuple[int, ...] = (),
):
    """Rows keyed by window width, read from the request body.

    `qualified_ok=False` reproduces the live 404 where the qualified
    `table."column"` form is refused on the table's own key attribute.
    `range_error_at` reproduces the 400 that names the 90-day boundary verbatim.
    """

    def handler(body, index):
        days = _days_of(body)
        eql = body.get("filter", "")
        if " IN " in eql:
            if '"."' in eql and not qualified_ok:
                raise _api_error(404, "AAA_ESA_2003_404", _NON_KEY_ERROR)
            if days in range_error_at:
                raise _api_error(400, "AAA_ESA_1006_400", _RANGE_ERROR)
            count = table_rows.get(days, 0)
        else:
            count = control_rows.get(days, 0)
        return _n_rows(count, field="web_domain", value="openai.com")

    return handler


def test_p2_confirmed_when_the_table_form_dies_at_90_days_and_the_control_does_not():
    table_rows = {7: 10, 29: 20, 31: 25, 60: 40, 89: 50, 91: 0, 120: 0}
    control_rows = {d: 60 for d in sv._WINDOW_LOOKBACKS}
    client = FakeClient(
        _p2_post_handler(table_rows, control_rows),
        _table_get_handler([{"aillm_domain": "openai.com", "risk_level": "High"}]),
    )
    probe = sv.probe_context_table_window(client, now=sv.datetime.now(sv.UTC))
    assert probe.verdict == sv.CONFIRMED
    assert probe.observed["key_attribute"] == "aillm_domain"  # EXA-TABLE-KEY-ATTR
    assert probe.observed["column_used"] == "aillm_domain"


def test_p2_confirmed_from_the_rejection_message_when_the_api_states_the_limit():
    """The endpoint naming its own boundary beats any row count this can compute.

    Measured on sademodev22 2026-08-17: 91d and 120d returned 400 AAA_ESA_1006_400
    "Context Table does not support time range queries 90 days or more". The first
    version of this probe only compared row counts, so it read a decisive result as
    INCONCLUSIVE.
    """
    client = FakeClient(
        _p2_post_handler(
            {d: 10 for d in sv._WINDOW_LOOKBACKS},
            {d: 60 for d in sv._WINDOW_LOOKBACKS},
            range_error_at=(91, 120),
        ),
        _table_get_handler([{"aillm_domain": "openai.com"}]),
    )
    probe = sv.probe_context_table_window(client, now=sv.datetime.now(sv.UTC))
    assert probe.verdict == sv.CONFIRMED
    assert probe.observed["range_rejected_at"] == [91, 120]
    assert 89 in probe.observed["range_not_rejected_at"]
    assert "90 days or more" in probe.observed["range_error_message"]
    # The wording makes the boundary exclusive -- 89d is the widest accepted span.
    assert "EXCLUSIVE" in probe.reason


def test_p2_falls_back_to_the_unqualified_spelling_when_the_qualified_form_404s():
    """EQL called the table's own key attribute a "non-key field" on the live run."""
    client = FakeClient(
        _p2_post_handler(
            {7: 10, 29: 20, 31: 25, 60: 40, 89: 50, 91: 0, 120: 0},
            {d: 60 for d in sv._WINDOW_LOOKBACKS},
            qualified_ok=False,
        ),
        _table_get_handler([{"aillm_domain": "openai.com"}]),
    )
    probe = sv.probe_context_table_window(client, now=sv.datetime.now(sv.UTC))
    assert probe.observed["spelling_used"] == "unqualified"
    assert probe.observed["qualified_status_7d"] == 404
    assert probe.verdict == sv.CONFIRMED


def test_p2_distinguishes_a_failed_call_from_a_genuinely_empty_result():
    """None (the call failed) must never be reported as "returned no rows"."""
    # Both spellings fail, which is what the live run hit for the qualified form.
    def both_fail(body, index):
        if " IN " in body.get("filter", ""):
            raise _api_error(404, "AAA_ESA_2003_404", _NON_KEY_ERROR)
        return _n_rows(60, field="web_domain", value="openai.com")

    client = FakeClient(both_fail, _table_get_handler([{"aillm_domain": "openai.com"}]))
    probe = sv.probe_context_table_window(client, now=sv.datetime.now(sv.UTC))
    assert probe.verdict == sv.INCONCLUSIVE
    assert probe.precondition_met is False
    assert "the CALL FAILED" in probe.reason
    assert "AAA_ESA_2003_404" in probe.reason
    assert "returned 200 but zero rows" not in probe.reason


def test_p2_refuted_when_the_table_form_still_matches_at_120_days():
    table_rows = {d: 10 for d in sv._WINDOW_LOOKBACKS}
    control_rows = {d: 60 for d in sv._WINDOW_LOOKBACKS}
    client = FakeClient(
        _p2_post_handler(table_rows, control_rows),
        _table_get_handler([{"aillm_domain": "openai.com"}]),
    )
    probe = sv.probe_context_table_window(client, now=sv.datetime.now(sv.UTC))
    assert probe.verdict == sv.REFUTED


def test_p2_inconclusive_when_no_matchable_events_exist_beyond_the_window():
    """Zero past 90d proves nothing if the control is also zero out there."""
    table_rows = {7: 10, 29: 20, 31: 20, 60: 20, 89: 20, 91: 0, 120: 0}
    control_rows = {7: 30, 29: 30, 31: 30, 60: 30, 89: 30, 91: 0, 120: 0}
    client = FakeClient(
        _p2_post_handler(table_rows, control_rows),
        _table_get_handler([{"aillm_domain": "openai.com"}]),
    )
    probe = sv.probe_context_table_window(client, now=sv.datetime.now(sv.UTC))
    assert probe.verdict == sv.INCONCLUSIVE
    assert probe.precondition_met is False


def test_p2_refuses_to_guess_between_two_similarly_named_tables():
    """sademodev22 has both 'Public AI Domains and Risk' and '...Risks'."""
    twin = dict(_TABLE, id="other123")
    client = FakeClient(None, _table_get_handler([], tables=[_TABLE, twin]))
    probe = sv.probe_context_table_window(client, now=sv.datetime.now(sv.UTC))
    assert probe.verdict == sv.INCONCLUSIVE
    assert "--table-id" in probe.reason


def test_p2_inconclusive_when_the_table_is_empty():
    client = FakeClient(None, _table_get_handler([]))
    probe = sv.probe_context_table_window(client, now=sv.datetime.now(sv.UTC))
    assert probe.verdict == sv.INCONCLUSIVE
    assert probe.precondition_met is False


# ---------------------------------------------------------------------------
# P3 -- aggregation window
# ---------------------------------------------------------------------------


def _agg_rows(groups: list[tuple[str, int]], column: str = "f0_") -> dict[str, Any]:
    return {"rows": [{"activity_type": name, column: count} for name, count in groups]}


def _p3_handler(
    totals_by_days: dict[int, int],
    *,
    reject_days: tuple[int, ...] = (),
    count_column: str = "f0_",
    eql_accepted: bool = True,
):
    """Aggregation totals keyed by window width, read from the request body.

    The body's `groupBy` key deliberately returns the grouped column and NO count,
    which is what the live endpoint does -- so a probe that relies on groupBy for a
    total has to fail here rather than quietly pass on a fixture that is friendlier
    than reality.
    """

    def handler(body, index):
        days = _days_of(body)
        eql = body.get("filter", "")
        if body.get("groupBy"):
            return _rows(["authentication", "file-write"])
        if "COUNT" not in eql.upper():
            return _rows(["authentication"])
        if not eql_accepted:
            raise _api_error(400, "AAA_ESA_1000_400", "Invalid filter value")
        if days in reject_days:
            raise _api_error(400, "AAA_ESA_1006_400", "aggregation range exceeds 7 days")
        return _agg_rows(
            [("authentication", totals_by_days.get(days, 0))], column=count_column
        )

    return handler


def test_p3_confirmed_when_the_8_day_total_is_short_of_its_two_4_day_slices():
    """The dangerous form: 200 OK with a silently smaller number."""
    client = FakeClient(_p3_handler({6: 600, 8: 400, 30: 900, 4: 500}))
    probe = sv.probe_aggregation_window(client, now=sv.datetime.now(sv.UTC))
    assert probe.verdict == sv.CONFIRMED
    assert "truncating silently" in probe.reason


def test_p3_refuted_when_the_8_day_total_reconciles():
    client = FakeClient(_p3_handler({6: 600, 8: 1000, 30: 3000, 4: 500}))
    probe = sv.probe_aggregation_window(client, now=sv.datetime.now(sv.UTC))
    assert probe.verdict == sv.REFUTED


def test_p3_confirmed_when_the_8_day_aggregation_is_rejected():
    client = FakeClient(_p3_handler({6: 100, 30: 100, 4: 50}, reject_days=(8,)))
    probe = sv.probe_aggregation_window(client, now=sv.datetime.now(sv.UTC))
    assert probe.verdict == sv.CONFIRMED
    assert "enforced loudly" in probe.reason


def test_p3_uses_an_eql_count_because_body_groupby_returns_no_count_column():
    """Measured 2026-08-17: groupBy returns ['activity_type'] and nothing else.

    So the 7-day window cannot be measured through groupBy at all -- there is no
    total to compare. The probe has to find a working EQL COUNT() spelling, and it
    must record which one the endpoint accepted rather than assuming a syntax.
    """
    client = FakeClient(_p3_handler({6: 600, 8: 400, 30: 900, 4: 500}))
    probe = sv.probe_aggregation_window(client, now=sv.datetime.now(sv.UTC))
    assert probe.observed["body_groupby_has_count_column"] is False
    assert "COUNT" in probe.observed["eql_aggregation_used"]
    assert probe.observed["total_6d"] == 600


def test_p3_inconclusive_when_no_eql_aggregation_spelling_is_accepted():
    """Never invent a total. If no syntax works, the claim is UNTESTED, not refuted."""
    client = FakeClient(_p3_handler({}, eql_accepted=False))
    probe = sv.probe_aggregation_window(client, now=sv.datetime.now(sv.UTC))
    assert probe.verdict == sv.INCONCLUSIVE
    assert probe.precondition_met is False
    assert "UNTESTED" in probe.reason
    # Every spelling it tried is recorded, so the next run can start from the data.
    assert len(probe.observed["eql_aggregation_spellings"]) == 4


def test_p3_sums_every_group_row_not_just_a_retained_sample():
    """The total must come from all rows -- a partial sum would fake truncation."""

    def handler(body, index):
        if body.get("groupBy"):
            return _rows(["a", "b", "c"])
        if "COUNT" not in body.get("filter", "").upper():
            return _rows(["a"])
        return _agg_rows([("a", 10), ("b", 20), ("c", 30)])

    client = FakeClient(handler)
    probe = sv.probe_aggregation_window(client, now=sv.datetime.now(sv.UTC))
    assert probe.observed["total_6d"] == 60


# ---------------------------------------------------------------------------
# P4 -- query time range limit
# ---------------------------------------------------------------------------


def test_p4_confirmed_records_the_boundary_and_the_rejection_shape():
    def handler(body, index):
        if index >= 3:  # 7, 30, 90 pass; 180 fails
            raise ExaAPIError(400, "query time range exceeds license limit")
        return _n_rows(1)

    client = FakeClient(handler)
    probe = sv.probe_time_range_limit(client, now=sv.datetime.now(sv.UTC))
    assert probe.verdict == sv.CONFIRMED
    assert probe.observed["status_by_lookback"][180] == 400
    # The number is license-specific; only the rejection shape transfers.
    assert "never hard-code" in probe.reason


def test_p4_refuted_when_every_window_is_accepted():
    client = FakeClient(lambda body, index: _n_rows(1))
    probe = sv.probe_time_range_limit(client, now=sv.datetime.now(sv.UTC))
    assert probe.verdict == sv.REFUTED
    assert "does NOT mean a customer's license has none" in probe.reason


def test_p4_inconclusive_when_even_the_7_day_control_fails():
    def handler(body, index):
        raise ExaAPIError(500, "boom")

    client = FakeClient(handler)
    probe = sv.probe_time_range_limit(client, now=sv.datetime.now(sv.UTC))
    assert probe.verdict == sv.INCONCLUSIVE
    assert probe.precondition_met is False


# ---------------------------------------------------------------------------
# P5 -- result shape and f0_ naming
# ---------------------------------------------------------------------------


def _p5_handler(*, agg_column: str | None = "f0_", eql_accepted: bool = True):
    """Projection-aware fake: column set depends on the `fields` key.

    Reproduces the live shape measured 2026-08-17 -- omitting `fields` returns
    metadata-only columns with no CIM fields, while `['*']` returns them.
    """
    metadata_only = {"id": 1, "time": "t", "product": "p", "vendor": "v"}

    def handler(body, index):
        eql = body.get("filter", "")
        if "COUNT" in eql.upper():
            if not eql_accepted:
                raise _api_error(400, "AAA_ESA_1000_400", "Invalid filter value")
            if agg_column is None:
                return _rows(["authentication"])
            return _agg_rows([("authentication", 5)], column=agg_column)
        if body.get("groupBy"):
            # No count column, exactly as the live endpoint behaves.
            return _rows(["authentication", "file-write"])
        fields = body.get("fields")
        if fields is None:
            return {"rows": [dict(metadata_only)]}
        if fields == ["*"]:
            return {"rows": [dict(metadata_only, activity_type="authentication",
                                  src_ip="10.0.0.1", user="u")]}
        return {"rows": [{f: "x" for f in fields}]}

    return handler


def test_p5_confirmed_when_the_aggregation_column_is_f0():
    client = FakeClient(_p5_handler())
    probe = sv.probe_result_shape(client, now=sv.datetime.now(sv.UTC))
    assert probe.verdict == sv.CONFIRMED
    assert probe.observed["f_pattern_columns"] == ["f0_"]


def test_p5_refuted_when_the_aggregation_column_has_a_readable_name():
    client = FakeClient(_p5_handler(agg_column="count"))
    probe = sv.probe_result_shape(client, now=sv.datetime.now(sv.UTC))
    assert probe.verdict == sv.REFUTED
    assert "count" in str(probe.observed["columns_eql_aggregation"])


def test_p5_inconclusive_not_refuted_when_no_eql_aggregation_is_available():
    """The `f0_` claim is about an EQL aggregation column.

    The body `groupBy` key produces no aggregation column at all, so it cannot
    refute the naming -- there was never a column to inspect. The first live run
    reported REFUTED for a claim it had not tested.
    """
    client = FakeClient(_p5_handler(eql_accepted=False))
    probe = sv.probe_result_shape(client, now=sv.datetime.now(sv.UTC))
    assert probe.verdict == sv.INCONCLUSIVE
    assert "UNTESTED" in probe.reason
    assert probe.observed["body_groupby_count_columns"] == []


def test_p5_records_that_omitting_fields_is_not_the_same_as_star():
    """Omitting `fields` returned metadata only -- no CIM fields -- on the live run."""
    client = FakeClient(_p5_handler())
    probe = sv.probe_result_shape(client, now=sv.datetime.now(sv.UTC))
    assert probe.observed["omitted_is_metadata_only"] is True
    assert probe.observed["star_widens_projection"] is True
    assert "activity_type" in probe.observed["fields_only_in_star"]
    assert "NOT equivalent to '*'" in probe.reason


def test_p5_inconclusive_when_the_aggregation_returns_nothing():
    client = FakeClient(lambda body, index: {"rows": []})
    probe = sv.probe_result_shape(client, now=sv.datetime.now(sv.UTC))
    assert probe.verdict == sv.INCONCLUSIVE


# ---------------------------------------------------------------------------
# P6 -- limit: -1
# ---------------------------------------------------------------------------


def test_p6_confirmed_when_negative_one_is_rejected():
    def handler(body, index):
        if body.get("limit") == -1:
            raise ExaAPIError(400, "limit must be a positive integer")
        return _n_rows(1)

    client = FakeClient(handler)
    probe = sv.probe_limit_negative(client, now=sv.datetime.now(sv.UTC))
    assert probe.verdict == sv.CONFIRMED
    assert probe.observed["status_limit_negative_1"] == 400


def test_p6_refuted_and_flags_silent_coercion_to_the_3000_default():
    """A 200 that quietly truncates is worse than the documented rejection."""

    def handler(body, index):
        if body.get("limit") == -1:
            return _n_rows(3000)
        return _n_rows(1)

    client = FakeClient(handler)
    probe = sv.probe_limit_negative(client, now=sv.datetime.now(sv.UTC))
    assert probe.verdict == sv.REFUTED
    assert "silently coerced" in probe.reason


def test_p6_flags_a_200_with_zero_rows_as_worse_than_the_documented_rejection():
    """Measured on sademodev22 2026-08-17 -- the signature failure of this API.

    limit: -1 and limit: 0 both returned HTTP 200 with 0 rows while limit: 10
    returned rows over the identical window. Not rejected, not coerced to the
    default: an empty result set indistinguishable from "no matching events".
    """

    def handler(body, index):
        if body.get("limit", 1) <= 0:
            return _n_rows(0)
        return _n_rows(min(body["limit"], 10))

    client = FakeClient(handler)
    probe = sv.probe_limit_negative(client, now=sv.datetime.now(sv.UTC))
    assert probe.verdict == sv.REFUTED
    assert probe.observed["rows_limit_negative_1"] == 0
    assert "WORSE THAN DOCUMENTED" in probe.reason
    assert "ZERO rows" in probe.reason
    # It must not be mistaken for the silent-coercion case, which is a different bug.
    assert "silently coerced" not in probe.reason


def test_p6_inconclusive_when_the_window_has_no_events_to_return():
    """Zero rows for limit -1 means nothing if limit 10 also returns zero."""
    client = FakeClient(lambda body, index: _n_rows(0))
    probe = sv.probe_limit_negative(client, now=sv.datetime.now(sv.UTC))
    assert probe.verdict == sv.INCONCLUSIVE
    assert probe.precondition_met is False


def test_p6_inconclusive_when_the_limit_1_control_fails():
    def handler(body, index):
        raise ExaAPIError(500, "boom")

    client = FakeClient(handler)
    probe = sv.probe_limit_negative(client, now=sv.datetime.now(sv.UTC))
    assert probe.verdict == sv.INCONCLUSIVE
    assert probe.precondition_met is False


# ---------------------------------------------------------------------------
# P7 -- null vs "null"
# ---------------------------------------------------------------------------


def test_p7_confirmed_when_quoting_changes_the_result():
    def handler(body, index):
        eql = body.get("filter", "")
        if not eql:  # sample + per-candidate null-ness passes
            return {"rows": [{"user": "u1"}, {"user": None}, {"user": "u2"}]}
        if eql.endswith(':"null"'):
            return _n_rows(0, field="user")
        return _n_rows(12, field="user", value="")

    client = FakeClient(handler)
    probe = sv.probe_null_quoting(client, now=sv.datetime.now(sv.UTC))
    assert probe.verdict == sv.CONFIRMED
    assert probe.observed["field_used"] == "user"


def test_p7_refuted_when_both_forms_agree():
    def handler(body, index):
        eql = body.get("filter", "")
        if not eql:
            return {"rows": [{"user": "u1"}, {"user": None}]}
        return _n_rows(7, field="user")

    client = FakeClient(handler)
    probe = sv.probe_null_quoting(client, now=sv.datetime.now(sv.UTC))
    assert probe.verdict == sv.REFUTED


def test_p7_inconclusive_when_no_field_is_both_null_and_populated():
    """Without a mixed field, emptiness and string-match cannot be told apart."""
    client = FakeClient(lambda body, index: {"rows": [{"user": "u1"}, {"user": "u2"}]})
    probe = sv.probe_null_quoting(client, now=sv.datetime.now(sv.UTC))
    assert probe.verdict == sv.INCONCLUSIVE
    assert probe.precondition_met is False


def test_p7_prefers_string_typed_fields_over_ip_typed_ones():
    """A type rejection cannot settle a claim about matching semantics.

    Measured 2026-08-17: `src_ip:"null"` returns 400 'incompatible for type
    ipv4/ipv6'. That proves src_ip is typed, not that quoting changes matching --
    so typed fields are probed last and only as evidence of the type behavior.
    """
    assert sv._NULLABLE_CANDIDATES.index("user") < sv._NULLABLE_CANDIDATES.index("src_ip")
    assert sv._NULLABLE_CANDIDATES.index("host") < sv._NULLABLE_CANDIDATES.index("src_ip")
    assert sv._TYPED_CANDIDATES == {"src_ip", "dest_ip"}


def test_p7_skips_a_type_rejected_field_and_tries_the_next_one():
    """A 400 'incompatible for type' is a dead end, not a verdict."""

    def handler(body, index):
        eql = body.get("filter", "")
        fields = body.get("fields") or []
        if not eql:  # sampling passes: make src_ip and host both mixed
            return {"rows": [{f: "x" for f in fields}, {f: None for f in fields}]}
        if eql.startswith("src_ip:") and eql.endswith(':"null"'):
            raise _api_error(400, "AAA_ESA_1000_400", _TYPE_ERROR)
        if eql.endswith(':"null"'):
            return _n_rows(3, field=fields[0])
        return _n_rows(40, field=fields[0])

    client = FakeClient(handler)
    probe = sv.probe_null_quoting(client, now=sv.datetime.now(sv.UTC))
    assert probe.verdict == sv.CONFIRMED
    # It settled on a string-typed field, not on the type rejection.
    assert probe.observed["field_used"] not in sv._TYPED_CANDIDATES
    assert probe.observed["field_used_is_typed"] is False


def test_p7_confirmed_with_a_mechanism_note_when_one_spelling_is_rejected():
    """400-vs-200 IS a difference in meaning, but say what the mechanism was.

    The first live run reported INCONCLUSIVE for the strongest possible result --
    one spelling being invalid outright. It is CONFIRMED, with the caveat that a
    rejection is not the documented "matches the literal string" behavior.
    """

    def handler(body, index):
        eql = body.get("filter", "")
        fields = body.get("fields") or []
        if not eql:
            return {"rows": [{f: "x" for f in fields}, {f: None for f in fields}]}
        if eql.endswith(':"null"'):
            raise _api_error(400, "AAA_ESA_1000_400", "Unsupported quoted null literal")
        return _n_rows(9, field=fields[0])

    client = FakeClient(handler)
    probe = sv.probe_null_quoting(client, now=sv.datetime.now(sv.UTC))
    assert probe.verdict == sv.CONFIRMED
    assert "MECHANISM is a rejection" in probe.reason


def test_p7_inconclusive_when_every_usable_field_is_type_rejected():
    """No string-typed field available -> the claim is untested, not settled."""

    def handler(body, index):
        eql = body.get("filter", "")
        fields = body.get("fields") or []
        if not eql:
            if fields and fields[0] in sv._TYPED_CANDIDATES:
                return {"rows": [{fields[0]: "10.0.0.1"}, {fields[0]: None}]}
            return {"rows": [{f: "x" for f in fields}]}  # not mixed -> unusable
        if eql.endswith(':"null"'):
            raise _api_error(400, "AAA_ESA_1000_400", _TYPE_ERROR)
        return _n_rows(5, field=fields[0])

    client = FakeClient(handler)
    probe = sv.probe_null_quoting(client, now=sv.datetime.now(sv.UTC))
    assert probe.verdict == sv.INCONCLUSIVE
    assert probe.precondition_met is False
    assert "type-rejected" in probe.reason
    assert probe.observed["type_rejections"]


# ---------------------------------------------------------------------------
# P1 -- the EQL LIMIT sub-call must be a valid query
# ---------------------------------------------------------------------------


def test_p1_sends_a_well_formed_eql_limit_clause_with_select_or_where():
    """A bare `LIMIT 10000` is invalid by the guide's own clause rule.

    The first live run sent it bare, got a 400, and that would have been recorded as
    "EQL LIMIT is rejected" when the request was simply malformed -- the guide
    requires at least one SELECT or one WHERE alongside an advanced operator.
    """
    client = FakeClient(lambda body, index: _n_rows(4000))
    probe = sv.probe_limit_default(client, now=sv.datetime.now(sv.UTC))
    sent = [b.get("filter", "") for b in client.posts]
    limit_queries = [f for f in sent if "LIMIT 10000" in f]
    assert limit_queries, "the probe must still test an EQL LIMIT clause"
    for query in limit_queries:
        assert "SELECT" in query or "WHERE" in query
    # And a control without LIMIT, so a rejection can be attributed to LIMIT itself.
    assert probe.observed["eql_control_status"] == 200
    assert probe.observed["eql_limit_clause_is_the_cause"] is False


# ---------------------------------------------------------------------------
# P8 -- the pipe probe must never run by accident
# ---------------------------------------------------------------------------


def test_pipe_probe_is_excluded_by_default():
    """It spends a shared, deployment-wide, monthly quota. Opt-in only."""
    client = FakeClient(lambda body, index: {"rows": []})
    artifact = sv.run_verification(client, only=["result-shape"])
    assert all(p["probe"] != "P8-pipe-quota-and-range" for p in artifact["probes"])
    assert artifact["include_pipe_probes"] is False


def test_pipe_probe_runs_only_when_explicitly_included():
    def handler(body, index):
        if "|" in body.get("filter", ""):
            return {"rows": [{"activity_type": "authentication"}]}
        return {"rows": []}

    client = FakeClient(handler)
    artifact = sv.run_verification(
        client, only=["pipe-quota"], include_pipe_probes=True
    )
    names = [p["probe"] for p in artifact["probes"]]
    assert names == ["P8-pipe-quota-and-range"]


def test_pipe_probe_inconclusive_when_the_syntax_is_rejected():
    """Do not spend more quota chasing a syntax error."""

    def handler(body, index):
        raise ExaAPIError(400, "invalid query syntax near '|'")

    client = FakeClient(handler)
    probe = sv.probe_pipe_quota(client, now=sv.datetime.now(sv.UTC))
    assert probe.verdict == sv.INCONCLUSIVE
    assert "before spending more quota" in probe.reason


# ---------------------------------------------------------------------------
# Battery, artifact and vault rendering
# ---------------------------------------------------------------------------


def test_run_verification_pins_now_once_for_every_probe():
    """P3 compares an 8d window against two 4d slices -- they must tile exactly."""
    client = FakeClient(lambda body, index: {"rows": []})
    artifact = sv.run_verification(client, only=["time-range"])
    starts_and_ends = [(b["startTime"], b["endTime"]) for b in client.posts]
    assert len({end for _, end in starts_and_ends}) == 1, "endTime drifted between calls"
    assert artifact["now_pinned"].endswith("Z")


def test_a_raising_probe_does_not_lose_the_rest_of_the_battery(monkeypatch):
    def explode(*args, **kwargs):
        raise RuntimeError("probe bug")

    monkeypatch.setattr(sv, "probe_limit_negative", explode)
    client = FakeClient(lambda body, index: {"rows": []})
    artifact = sv.run_verification(client, only=["limit-negative", "result-shape"])
    assert len(artifact["probes"]) == 2
    broken = next(p for p in artifact["probes"] if p["probe"] == "limit-negative")
    assert broken["verdict"] == sv.INCONCLUSIVE
    assert "RuntimeError" in broken["reason"]


def test_summarize_counts_all_three_verdicts():
    probes = [
        {"verdict": sv.CONFIRMED},
        {"verdict": sv.CONFIRMED},
        {"verdict": sv.REFUTED},
        {"verdict": sv.INCONCLUSIVE},
    ]
    assert sv.summarize(probes) == {
        "confirmed": 2, "refuted": 1, "inconclusive": 1, "total": 4,
    }


def test_save_and_load_round_trip(_pin_verify_dir):
    artifact = {"tenant": "faketenant", "run_at": "2026-08-17T00:00:00+00:00", "probes": []}
    path = sv.save_verification(artifact, "faketenant")
    assert path.exists()
    assert sv.load_last_verification("faketenant")["tenant"] == "faketenant"


def test_load_returns_none_for_an_unknown_tenant():
    assert sv.load_last_verification("never-run-here") is None


def test_artifact_does_not_retain_event_rows_by_default():
    """The artifact records behavior, not a copy of tenant event data."""

    def handler(body, index):
        return {"rows": [{"user": "alice", "src_ip": "10.0.0.1"} for _ in range(5)]}

    client = FakeClient(handler)
    artifact = sv.run_verification(client, only=["time-range", "limit-negative"])
    blob = str(artifact)
    assert "10.0.0.1" not in blob
    assert "alice" not in blob


def test_vault_rows_renders_a_markdown_table():
    artifact = {
        "tenant": "sademodev22",
        "run_at": "2026-08-17T12:00:00+00:00",
        "probes": [
            {
                "probe": "P1-limit-default-3000",
                "claim": "3,000 is the API's DEFAULT when no limit is set",
                "verdict": "CONFIRMED",
                "reason": "limit=10000 returned 7500 rows",
            }
        ],
    }
    out = sv.vault_rows(artifact)
    assert out.startswith("| Probe | Claim | Verdict | Tenant | Date | Why |")
    assert "`P1-limit-default-3000`" in out
    assert "**CONFIRMED**" in out
    assert "2026-08-17" in out


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


def test_verify_group_help_lists_the_commands():
    result = runner.invoke(app, ["verify", "--help"])
    assert result.exit_code == 0
    assert "search" in result.output
    assert "results" in result.output
    assert "vault" in result.output


def test_verify_search_help_shows_the_pipe_flag_and_its_default(monkeypatch):
    # rich elides option names at narrow widths, so pin the width rather than
    # asserting against whatever the test runner's terminal happens to be.
    monkeypatch.setenv("COLUMNS", "200")
    result = runner.invoke(app, ["verify", "search", "--help"])
    assert result.exit_code == 0
    assert "--include-pipe-probes" in result.output
    assert "--no-include-pipe-probes" in result.output
    assert "--table-id" in result.output


def test_verify_search_rejects_an_unknown_probe_name_before_authenticating():
    result = runner.invoke(app, ["verify", "search", "--probe", "not-a-probe"])
    assert result.exit_code == 1
    assert "Unknown probe" in result.output


def test_verify_search_refuses_pipe_probe_without_the_opt_in_flag():
    """Otherwise it runs nothing and reports a clean, empty, meaningless pass."""
    result = runner.invoke(app, ["verify", "search", "--probe", "pipe-quota"])
    assert result.exit_code == 1
    assert "--include-pipe-probes" in result.output


def test_verify_results_exits_cleanly_with_no_saved_run():
    result = runner.invoke(app, ["verify", "results", "--tenant", "never-run-here"])
    assert result.exit_code == 1
    assert "No verification run found" in result.output


def test_verify_vault_drops_inconclusive_rows_by_default(_pin_verify_dir):
    sv.save_verification(
        {
            "tenant": "faketenant",
            "run_at": "2026-08-17T00:00:00+00:00",
            "probes": [
                {"probe": "P1", "claim": "c", "verdict": "CONFIRMED", "reason": "r"},
                {"probe": "P2", "claim": "c", "verdict": "INCONCLUSIVE", "reason": "r"},
            ],
        },
        "faketenant",
    )
    result = runner.invoke(app, ["verify", "vault", "--tenant", "faketenant"])
    assert result.exit_code == 0
    assert "`P1`" in result.output
    assert "`P2`" not in result.output

    both = runner.invoke(
        app, ["verify", "vault", "--tenant", "faketenant", "--no-settled-only"]
    )
    assert "`P2`" in both.output
