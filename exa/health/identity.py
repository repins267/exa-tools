"""Detect AD/identity-resolution problems: merged user entities and GUID ghost users.

Two independent signals for the "two users collapsed into one" class of issue:

1. **Merged identifiers (the smoking gun).** In the identity/User context tables, an
   identifier value (email / UPN / SAMAccountName) that maps to TWO OR MORE distinct
   user keys means Exabeam is stitching two real people into one entity — usually a
   recycled email (a former employee's address handed to a new hire/manager), since
   email is a primary linking key. Schema-agnostic: it reads each identity table's real
   key attribute and inverts every other attribute value -> set of user keys.

2. **GUID ghost users.** A login whose username is a bare AD objectGUID
   (8-4-4-4-12 hex) is Windows failing to resolve a SID to a SAMAccountName — a deleted,
   orphaned, or mid-deprovisioning account. Grouped by host: many GUIDs on one host is a
   single machine cycling orphaned accounts.

Read-only. The FIX (removing the shared identifier + re-enriching) is a gated, human-
confirmed remediation, never run from here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from exa.client import ExaClient

_GUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
# Table names / context types that hold identity links worth scanning for merges.
_IDENTITY_HINTS = ("user", "entity", "identity", "link", "account")


def is_guid_username(name) -> bool:
    """True if the username is a bare AD objectGUID — an unresolved identity."""
    return bool(_GUID_RE.match(str(name or "").strip()))


@dataclass
class MergedIdentifier:
    table: str = ""
    attribute: str = ""
    value: str = ""
    users: list[str] = field(default_factory=list)


@dataclass
class GuidUser:
    username: str = ""
    host: str = ""
    count: int = 0


@dataclass
class IdentityHealth:
    tenant: str | None = None
    lookback_days: int = 7
    merged: list[MergedIdentifier] = field(default_factory=list)
    guid_users: list[GuidUser] = field(default_factory=list)
    tables_scanned: list[str] = field(default_factory=list)
    note: str = ""

    @property
    def hosts_with_guids(self) -> list[tuple[str, int]]:
        from collections import Counter
        c: Counter = Counter()
        for g in self.guid_users:
            c[g.host or "?"] += 1
        return c.most_common()


def find_merged_identifiers(client: "ExaClient", *, table: str | None = None, max_records: int = 200_000):
    """Scan identity context tables for any identifier mapped to 2+ distinct users."""
    from exa.context.tables import get_all_records, get_tables, resolve_table_schema

    tables = get_tables(client)
    if table:
        t_l = table.lower()
        cands = [t for t in tables if t_l in str(t.get("name", "")).lower() or t_l == str(t.get("id", ""))]
    else:
        cands = [
            t for t in tables
            if str(t.get("contextType", "")) == "User"
            or any(h in str(t.get("name", "")).lower() for h in _IDENTITY_HINTS)
        ]

    merged: list[MergedIdentifier] = []
    scanned: list[str] = []
    notes: list[str] = []
    for t in cands:
        name = str(t.get("name") or t.get("id") or "?")
        try:
            key_attr, others = resolve_table_schema(client, t)
            records = get_all_records(client, t["id"])[:max_records]
        except Exception as exc:
            notes.append(f"{name}: {exc}")
            continue
        scanned.append(name)
        attr_display = {v: k for k, v in others.items()}
        inv: dict[tuple[str, str], set[str]] = {}
        for r in records:
            user = str(r.get(key_attr) or "").strip()
            if not user:
                continue
            for attr_id in others.values():
                raw = r.get(attr_id)
                if raw in (None, ""):
                    continue
                for v in (raw if isinstance(raw, list) else [raw]):
                    vs = str(v).strip().lower()
                    if len(vs) < 3:
                        continue
                    inv.setdefault((attr_id, vs), set()).add(user)
        for (attr_id, vs), users in inv.items():
            if len(users) >= 2:
                merged.append(MergedIdentifier(
                    table=name, attribute=attr_display.get(attr_id, attr_id),
                    value=vs, users=sorted(users),
                ))
    merged.sort(key=lambda m: -len(m.users))
    return merged, scanned, " | ".join(notes)


def find_guid_users(client: "ExaClient", *, lookback_days: int = 7,
                    login_filter: str = 'activity_type:"user-login"', limit: int = 5000) -> list[GuidUser]:
    """Login events whose username is a bare objectGUID, grouped by host."""
    from exa.search.events import search_events

    rows = None
    for host_field in ("dest_host", "host", "src_host"):
        try:
            rows = search_events(
                client, login_filter, fields=["user", host_field, "count(id)"],
                group_by=["user", host_field], lookback_days=lookback_days, limit=limit,
            )
            break
        except Exception:
            continue
    out: list[GuidUser] = []
    for r in rows or []:
        u = r.get("user")
        if is_guid_username(u):
            host = r.get("dest_host") or r.get("host") or r.get("src_host") or ""
            out.append(GuidUser(username=str(u), host=str(host), count=int(r.get("f0_") or 0)))
    out.sort(key=lambda g: (g.host, -g.count))
    return out


def collect_identity_health(client: "ExaClient", *, lookback_days: int = 7, table: str | None = None) -> IdentityHealth:
    """Read-only sweep for merged entities + GUID ghost users."""
    ih = IdentityHealth(tenant=getattr(client, "tenant", None), lookback_days=lookback_days)
    notes: list[str] = []
    try:
        ih.merged, ih.tables_scanned, n = find_merged_identifiers(client, table=table)
        if n:
            notes.append(n)
    except Exception as exc:
        notes.append(f"context-table scan failed: {exc}")
    try:
        ih.guid_users = find_guid_users(client, lookback_days=lookback_days)
    except Exception as exc:
        notes.append(f"guid-user scan failed: {exc}")
    if not ih.tables_scanned:
        notes.append("no identity/User context table found to scan for merges")
    ih.note = " | ".join(notes)
    return ih


def identity_summary(ih: IdentityHealth) -> dict:
    return {
        "tenant": ih.tenant,
        "lookback_days": ih.lookback_days,
        "merged_entities": len(ih.merged),
        "guid_ghost_users": len(ih.guid_users),
        "tables_scanned": ih.tables_scanned,
        "merged": [
            {"table": m.table, "attribute": m.attribute, "shared_value": m.value, "users": m.users}
            for m in ih.merged[:50]
        ],
        "guid_users_by_host": [{"host": h, "guid_users": n} for h, n in ih.hosts_with_guids],
        "note": ih.note or None,
    }


def render_identity(ih: IdentityHealth) -> str:
    """Branded identity-health report."""
    from exa.report import data_table, page, panel, stat_card

    cards = "".join([
        stat_card("Tenant", ih.tenant or "—", "", f"last {ih.lookback_days}d"),
        stat_card("Merged entities", len(ih.merged), "bad" if ih.merged else "good",
                  "shared identifier → 2+ users"),
        stat_card("GUID ghost users", len(ih.guid_users), "warn" if ih.guid_users else "good",
                  "unresolved AD identities"),
        stat_card("Identity tables", len(ih.tables_scanned), "" if ih.tables_scanned else "warn",
                  "scanned for merges"),
    ])

    if ih.merged:
        rows = [{
            "Table": m.table, "Shared attribute": m.attribute, "Value": m.value,
            "Merged users": ", ".join(m.users), "# users": len(m.users),
        } for m in ih.merged[:50]]
        merged_html = data_table(rows, "tblMerge")
    else:
        merged_html = ('<div class="empty">No identifier maps to more than one user in the scanned '
                       'identity tables — no merged entities found.</div>')

    guid_html = (
        data_table([{"Host": h, "GUID users": n} for h, n in ih.hosts_with_guids], "tblGuid")
        if ih.guid_users else '<div class="empty">No GUID-format usernames in login events.</div>'
    )

    note = (
        "A shared value under one attribute mapped to 2+ users is the merge smoking gun — most often a "
        "recycled email/UPN (a former employee's address reassigned). FIX (gated, human-confirmed): remove "
        "the stale identifier from the identity table for the wrong user, then force re-enrichment on both "
        "accounts. Cross-check Entra proxyAddresses/mail change history for the shared value."
    )
    panels = "".join([
        panel(f"Merged entities ({len(ih.merged)})", merged_html, note),
        panel("GUID ghost users by host", guid_html,
              "objectGUID logins = Windows failing to resolve a SID; a host with many is cycling orphaned accounts"),
        panel("Scanned & caveats",
              f'<div class="footer-note">Tables scanned: {", ".join(ih.tables_scanned) or "none"}. '
              + (f'Note: {ih.note}. ' if ih.note else "")
              + 'Read-only detection. Confirm each merge in Settings → Context Management before any '
              'remediation; a bad context-table delete has real blast radius.</div>'),
    ])
    meta = [ih.tenant or "—", f"last {ih.lookback_days}d", "identity health · read-only"]
    return page(
        f"exa-tools · {ih.tenant or ''} · Identity Health",
        f"Merged entities & GUID ghost users · last {ih.lookback_days}d",
        cards, panels, "".join(f"<div>{m}</div>" for m in meta), initial_theme="dark",
    )
