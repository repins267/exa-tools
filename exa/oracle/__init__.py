"""Field Oracle sourced from a tenant's live parser export.

Historically the Field Oracle was built by cloning ExabeamLabs/Content-Library-CIM2
(~500 MB) and parsing its `pC_*.md` files. That clone goes stale — measured 7.5
months behind a live tenant — and it is not what any given tenant actually runs.

A tenant's own parser export (`parsers.conf` + `event_builder.conf`, downloaded
from the tenant and referenced by path in its config) is the live truth. Building
the Oracle from it gives equal-or-better vendor / activity-type / CIM2-field
coverage — including the AI activity family the stale clone lacks entirely — with
no repo to keep fresh and no customer data stored by exa-tools (only the path is
saved, exactly like a credential handle).

This package builds a `field_oracle.json` (identical schema to the pC-based build)
from an export, and resolves which Oracle a given tenant should use.
"""

from __future__ import annotations

from exa.oracle.api_source import build_oracle_from_api
from exa.oracle.export_builder import (
    build_oracle_from_export,
    build_oracle_from_records,
    build_oracle_from_zip,
    write_oracle,
)
from exa.oracle.paths import oracle_path

__all__ = [
    "build_oracle_from_api",
    "build_oracle_from_export",
    "build_oracle_from_records",
    "build_oracle_from_zip",
    "write_oracle",
    "oracle_path",
]
