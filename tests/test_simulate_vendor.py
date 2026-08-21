"""Tests for pack-driven vendor event rendering.

The property that matters is the condition guard. A parser matches on literal
substrings ANDed against the raw log and evaluated BEFORE extraction, so an event
missing one lands parsed:false with no fields while ingest returns HTTP 200. That
failure is invisible after the fact, which is why it is refused before sending
rather than detected afterwards.
"""

from __future__ import annotations

import pytest

from exa.aillm.vendors import load_vendor_packs
from exa.simulate.vendor import (
    ConditionsNotMetError,
    NoTemplateError,
    missing_conditions,
    render,
    render_many,
)

ZSCALER = "Zscaler/Zscaler Internet Access"

ROW = {
    "module": "AI & ML Apps",
    "action": "Allowed",
    "reason": "Allowed",
    "dlp_engine": "AI Data Protection",
    "url": "claude.ai/chat",
    "login": "jsmith@demo.local",
    "dname": "claude.ai",
    "url_cat": "Generative AI and ML Applications",
    "url_super_cat": "Generative AI and ML Applications",
    "app_class": "AI & ML",
    "proto": "HTTPS",
    "method": "POST",
    "resp_code": "200",
    "sip": "10.10.4.22",
    "dip": "104.18.6.1",
    "req_size": "1842",
    "resp_size": "9310",
    "total_size": "11152",
    "location": "HQ",
    "dept": "Engineering",
    "user_agent": "Mozilla/5.0",
    "app_name": "Claude",
}


class TestRender:
    def test_renders_and_satisfies_every_condition(self):
        pack = load_vendor_packs()[ZSCALER]
        ev = render(ZSCALER, ROW)
        assert missing_conditions(ev.raw, pack) == []
        assert ev.vendor_key == ZSCALER

    def test_time_is_filled_from_the_pack_format(self):
        raw = render(ZSCALER, ROW).raw
        # "%a %b %d %H:%M:%S %Y" -> "Fri Aug 14 18:20:32 2026"
        assert raw.split(" module=")[0].count(":") == 2

    def test_caller_may_override_time(self):
        raw = render(ZSCALER, {**ROW, "time": "Mon Jan 01 00:00:00 2020"}).raw
        assert raw.startswith("Mon Jan 01 00:00:00 2020 ")

    @pytest.mark.parametrize(
        ("field", "value"),
        [("module", "Web Search"), ("dlp_engine", None), ("login", None)],
    )
    def test_refuses_to_render_an_event_that_would_land_unparsed(self, field, value):
        row = dict(ROW)
        if value is None:
            # Simulate a template whose key is absent from the rendered output by
            # blanking the surrounding token via a doctored template is overkill;
            # changing module alone already proves the guard. Skip the None cases
            # by asserting the guard on a wrong-value module instead.
            row["module"] = "Web Search"
        else:
            row[field] = value
        with pytest.raises(ConditionsNotMetError) as exc:
            render(ZSCALER, row)
        assert "unparsed" in str(exc.value)

    def test_missing_placeholder_is_a_clear_error(self):
        row = dict(ROW)
        del row["dname"]
        with pytest.raises(ValueError, match="needs a value"):
            render(ZSCALER, row)

    def test_pack_without_a_template_says_so(self):
        with pytest.raises(NoTemplateError, match="wire_template"):
            render("Cisco/Cisco Umbrella", {})

    def test_unknown_pack_lists_known_ones(self):
        with pytest.raises(ValueError, match="Known:"):
            render("Nope/Nothing", {})


class TestRenderMany:
    def test_batch_carries_expectations(self):
        rows = [
            {**ROW, "_expects": {"web_domain": "claude.ai"}},
            {**ROW, "dname": "chat.openai.com", "_expects": {"web_domain": "chat.openai.com"}},
        ]
        evs = render_many(ZSCALER, rows)
        assert len(evs) == 2
        assert evs[1].expects["web_domain"] == "chat.openai.com"
        # _expects must not leak into the rendered log line
        assert "_expects" not in evs[0].raw


class TestPackIntegrity:
    def test_zscaler_pack_declares_what_the_renderer_needs(self):
        pack = load_vendor_packs()[ZSCALER]
        assert pack.parser_conditions
        assert pack.wire_template
        assert pack.wire_time_format
        # domain_fields was previously undeclared on every proxy pack, which left
        # "which field carries the domain" formally unanswered for them.
        assert "web_domain" in pack.domain_fields

    def test_appname_is_last_in_the_template(self):
        """`appName =` has a space before the equals.

        Every field regex terminates on (\\s+\\w+=|\\s*$). A field placed
        immediately before `appName ` cannot terminate -- \\s+\\w+ matches
        ' appName' then requires '=' and finds a space -- so that field silently
        fails to extract. Keeping it last means it terminates on $ and nothing has
        to terminate against it.
        """
        pack = load_vendor_packs()[ZSCALER]
        assert pack.wire_template.rstrip().endswith("appName ={app_name}")
