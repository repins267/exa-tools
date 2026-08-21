"""Health, licence and consumption API functions.

Every path here was probed live against a tenant on 2026-08-13. Two of them were
wrong and had been returning HTTP 404 since they were written:

    /health-consumption/v2/license-details              404  <- was in get_license_details
    /health-consumption/v2/consumption/licenseDetails   200  <- correct

    /health-consumption/v1/consumption/correlation-rules  404  <- was in get_correlation_rule_count
    /health-consumption/v1/consumption/correlationRule    200  <- correct

Both wrong forms are the plausible-looking ones: kebab-case where the API uses
camelCase, and a shorter path where the API nests under `consumption/`. Neither
function had a caller or a test, so nothing surfaced it.

The API is inconsistent about this by design, not by accident -- `licenseDetails`
and `correlationRule` are camelCase while `appStatus` and `lts` are not, and
`consumption/` appears in some paths and not others. Do not infer a path here;
probe it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from exa.client import ExaClient


def get_license_details(client: ExaClient) -> dict[str, Any]:
    """Entitled vs consumed log ingestion, with daily history.

    API: GET /health-consumption/v2/consumption/licenseDetails

    Returns `logIngestionDetails` carrying `entitledIngestGbPerDay`,
    `consumedIngestGbForToday`, and `historicalLogIngestionInGb` as a list of
    {date, ingestGb}. The v1 path returns the same fields unwrapped.

    Consumption OVER entitlement is reported plainly rather than flagged -- the
    API does not mark it, so nothing errors when a tenant is over. Compare the
    two numbers yourself.
    """
    return client.get("/health-consumption/v2/consumption/licenseDetails")


def get_lts_consumption(client: ExaClient) -> dict[str, Any]:
    """Long-term search and storage volume, used vs licensed.

    API: GET /health-consumption/v1/consumption/lts

    Returns `totalLTSearchVolumeUsed` / `totalLTSearchVolumeLicensed` and the
    storage equivalents, plus `unitOfMeasure` (GB). Storage figures read 0/0 on
    tenants without the entitlement -- that is "not licensed", not "unused".
    """
    return client.get("/health-consumption/v1/consumption/lts")


def get_correlation_rule_count(client: ExaClient) -> dict[str, Any]:
    """Correlation rules used vs licensed.

    API: GET /health-consumption/v1/consumption/correlationRule

    Note the singular camelCase resource. Returns `totalRuleUsed` and
    `totalRuleLicensed`.
    """
    return client.get("/health-consumption/v1/consumption/correlationRule")


def get_app_status(client: ExaClient) -> list[dict[str, Any]]:
    """Per-application uptime history.

    API: GET /health-consumption/v1/health/appStatus

    Returns one row per application per day with `uptimeValue`,
    `majorOutageInSeconds` and `partialOutageInSeconds`.
    """
    resp = client.get("/health-consumption/v1/health/appStatus")
    return resp if isinstance(resp, list) else resp.get("items", [])
