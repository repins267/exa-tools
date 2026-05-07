"""Compliance source mapping: discovery, DirectMap key extraction, and FilterMode classification.

DirectMap key priority:
  u_account > u_user > username > samaccountname >
  hostname > host > ip > key > first non-empty string value
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from fnmatch import fnmatch
from typing import TYPE_CHECKING, Any

from exa.context.tables import get_tables

if TYPE_CHECKING:
    from exa.client import ExaClient

# DirectMap key column priority order
_KEY_PRIORITY = [
    "u_account", "u_user", "username", "samaccountname",
    "hostname", "host", "ip", "key",
]

# Discovery: target patterns for scoring
_TARGET_PATTERNS: dict[str, list[str]] = {
    "privileged_users": ["privileged", "admin", "priv user", "elevated"],
    "service_accounts": [
        "service account", "service acct", "svc account", "system account", "managed identity",
    ],
    "shared_accounts": ["shared account", "shared acct", "generic account", "shared"],
    "third_party_users": [
        "third party", "third-party", "vendor", "contractor", "external user", "guest",
    ],
    "in_scope_systems": [
        "critical device", "critical asset", "in-scope",
        "data system", "database server", "file server",
    ],
    "network_systems": [
        "domain controller", "network security", "firewall", "network device", "infrastructure",
    ],
}

# Default patterns for FilterMode
DEFAULT_PRIVILEGED_PATTERNS = ["*admin*", "*privileged*", "*Domain Admins*", "*Enterprise Admins*"]
DEFAULT_SERVICE_PATTERNS = ["svc-*", "sa-*", "*-svc", "*$"]
DEFAULT_SHARED_PATTERNS = ["shared-*", "*-shared", "shared_*", "*_shared"]


@dataclass
class DiscoverySuggestion:
    compliance_target: str
    suggested_source: str
    source_id: str = ""
    source_records: int = 0
    confidence: str = "None"  # High, Low, None
    score: int = 0


@dataclass
class ClassificationResult:
    privileged_users: list[str] = field(default_factory=list)
    service_accounts: list[str] = field(default_factory=list)
    shared_accounts: list[str] = field(default_factory=list)
    third_party_users: list[str] = field(default_factory=list)
    unclassified: int = 0


def extract_keys(records: list[dict[str, Any]]) -> list[str]:
    """Extract key values from records using the DirectMap priority order."""
    keys: list[str] = []
    for r in records:
        key = None
        for col in _KEY_PRIORITY:
            val = r.get(col)
            if val and str(val).strip():
                key = str(val).strip()
                break
        if key is None:
            # Last resort: first non-empty string value
            for v in r.values():
                if isinstance(v, str) and v.strip():
                    key = v.strip()
                    break
        if key:
            keys.append(key)
    return keys


def discover_source_mappings(
    client: ExaClient,
    all_tables: list[dict[str, Any]] | None = None,
) -> list[DiscoverySuggestion]:
    """Score tenant context tables against compliance target patterns."""
    if all_tables is None:
        all_tables = get_tables(client)

    suggestions: list[DiscoverySuggestion] = []
    for target, patterns in _TARGET_PATTERNS.items():
        best_match: dict[str, Any] | None = None
        best_score = 0

        for table in all_tables:
            name = table.get("name", "")
            if not name or name.lower().startswith("compliance -"):
                continue
            name_lower = name.lower()
            score = 0
            for pattern in patterns:
                if pattern.lower() in name_lower:
                    score += 10
                for word in pattern.split():
                    if len(word) >= 4 and word.lower() in name_lower:
                        score += 3
            if score > best_score:
                best_score = score
                best_match = table

        confidence = "High" if best_score >= 10 else ("Low" if best_score >= 3 else "None")
        suggestions.append(DiscoverySuggestion(
            compliance_target=target,
            suggested_source=best_match["name"] if best_match else "(none found)",
            source_id=best_match.get("id", "") if best_match else "",
            source_records=int(best_match.get("numRecords", 0)) if best_match else 0,
            confidence=confidence,
            score=best_score,
        ))

    return suggestions


def _get_prop(record: dict[str, Any], names: list[str]) -> str | None:
    """Get first matching property value from record."""
    for n in names:
        val = record.get(n)
        if val and str(val).strip():
            return str(val).strip()
    return None


def classify_records(
    records: list[dict[str, Any]],
    *,
    privileged_patterns: list[str] | None = None,
    service_patterns: list[str] | None = None,
    shared_patterns: list[str] | None = None,
    internal_domains: list[str] | None = None,
) -> ClassificationResult:
    """Classify records into compliance categories using field-based filters."""
    priv_pats = privileged_patterns or DEFAULT_PRIVILEGED_PATTERNS
    svc_pats = service_patterns or DEFAULT_SERVICE_PATTERNS
    shd_pats = shared_patterns or DEFAULT_SHARED_PATTERNS

    result = ClassificationResult()

    for rec in records:
        key = rec.get("key")
        if not key:
            result.unclassified += 1
            continue
        key = str(key)

        acct_type = _get_prop(rec, ["accountType", "account_type", "AccountType"])
        is_priv = _get_prop(rec, ["isPrivileged", "is_privileged", "IsPrivileged"])
        admin_count = _get_prop(rec, ["adminCount", "admin_count", "AdminCount"])
        user_type = _get_prop(rec, ["userType", "user_type", "UserType"])
        emp_type = _get_prop(rec, ["employeeType", "employee_type", "EmployeeType"])
        member_of = _get_prop(rec, ["memberOf", "member_of", "MemberOf", "groups"])
        email = _get_prop(rec, ["email", "mail", "emailAddress", "userPrincipalName", "upn"])

        classified = False

        # Priority 1: Service Accounts
        if not classified:
            if acct_type and re.match(r"^(service|system|managed)$", acct_type, re.I):
                result.service_accounts.append(key)
                classified = True
            if not classified:
                for p in svc_pats:
                    if fnmatch(key, p):
                        result.service_accounts.append(key)
                        classified = True
                        break

        # Priority 2: Privileged Users
        if not classified:
            if is_priv and re.match(r"^(true|yes|1)$", is_priv, re.I):
                result.privileged_users.append(key)
                classified = True
            if not classified and admin_count:
                try:
                    if int(admin_count) > 0:
                        result.privileged_users.append(key)
                        classified = True
                except ValueError:
                    pass
            if not classified and member_of:
                for p in priv_pats:
                    if fnmatch(member_of, p):
                        result.privileged_users.append(key)
                        classified = True
                        break

        # Priority 3: Shared Accounts
        if not classified:
            if acct_type and re.match(r"^shared$", acct_type, re.I):
                result.shared_accounts.append(key)
                classified = True
            if not classified:
                for p in shd_pats:
                    if fnmatch(key, p):
                        result.shared_accounts.append(key)
                        classified = True
                        break

        # Priority 4: Third-Party Users
        if not classified:
            if user_type and re.match(r"^(guest|external)$", user_type, re.I):
                result.third_party_users.append(key)
                classified = True
            if not classified and emp_type and re.search(
                r"contractor|vendor|consultant|extern|temp", emp_type, re.I
            ):
                result.third_party_users.append(key)
                classified = True
            if not classified and email and internal_domains:
                parts = email.split("@")
                if len(parts) == 2 and "." in parts[1]:
                    email_domain = parts[1].lower()
                    if email_domain not in {d.lower() for d in internal_domains}:
                        result.third_party_users.append(key)
                        classified = True

        if not classified:
            result.unclassified += 1

    return result
