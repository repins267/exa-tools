"""Generate ControlQueries JSON files for all 10 non-NIST_CSF compliance frameworks."""

from __future__ import annotations

import json
import re
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent / "exa" / "compliance" / "data"
QUERIES_DIR = DATA_DIR / "ControlQueries"
QUERIES_DIR.mkdir(exist_ok=True)

# Full concept → activity_type map (mirrors concepts.py)
CONCEPT_ACTIVITY_MAP: dict[str, list[str]] = {
    "GROUP_MANAGEMENT":    ["group-modify"],
    "PERMISSION_CHANGE":   ["file-permission-modify", "ds_object-modify", "audit_policy-modify"],
    "AUTH_SUCCESS":        ["authentication", "endpoint-authentication"],
    "AUTH_FAILURE":        ["authentication", "endpoint-authentication"],
    "ACCOUNT_MANAGEMENT":  ["account-creation", "account-modification", "user-modify"],
    "NETWORK_TRAFFIC":     ["network-session", "http-session", "http-traffic", "dns-query", "dns-response"],
    "FILE_ACTIVITY":       ["file-read", "file-write", "file-delete", "file-create"],
    "PROCESS_EXECUTION":   ["process-create"],
    "PRIVILEGED_ACCESS":   ["authentication", "endpoint-authentication"],
    "AUDIT_LOG":           ["audit_policy-modify"],
    "PHYSICAL_ACCESS":     ["physical_location-access"],
    "EMAIL_ACTIVITY":      ["email-send"],
    "CLOUD_ACTIVITY":      ["app-activity", "cloud-activity"],
    "ENDPOINT_ACTIVITY":   ["process-create", "dll-load", "driver-load"],
    "VULNERABILITY_EVENT": ["alert-trigger"],
    "INCIDENT_RESPONSE":   ["rule-trigger", "alert-trigger"],
    "DATA_EXFILTRATION":   ["file-write", "network-session", "alert-trigger"],
    "CONFIG_CHANGE":       ["registry-modify", "registry-create", "ds_object-modify", "audit_policy-modify"],
}


def fallback_filter(concepts: list[str]) -> str:
    """Build a static OR-filter from concept activity_types."""
    seen: set[str] = set()
    types: list[str] = []
    for c in concepts:
        for at in CONCEPT_ACTIVITY_MAP.get(c, []):
            if at not in seen:
                seen.add(at)
                types.append(at)
    types.sort()
    return " OR ".join(f'activity_type:"{t}"' for t in types)


def shared_key(concepts: list[str]) -> str:
    return "_".join(sorted(concepts)).lower()


def make_entry(
    name: str,
    concepts: list[str],
    fields: list[str] | None = None,
    min_evidence: int = 10,
    shared: str | None = None,
) -> dict:
    if fields is None:
        fields = ["user", "host", "src_ip", "activity_type", "action", "result"]
    ffilter = fallback_filter(concepts)
    key = shared if shared is not None else shared_key(concepts)
    return {
        "name": name,
        "concepts": concepts,
        "queries": [{"name": name, "filter": ffilter, "fields": fields, "evidenceDescription": ""}],
        "contextTables": [],
        "minimumEvidence": min_evidence,
        "sharedQueryGroup": key,
    }


# ── CIS_V8 ────────────────────────────────────────────────────────────────────

FAMILY_CONCEPTS_CIS: dict[str, list[str]] = {
    "Access Control":            ["AUTH_SUCCESS", "AUTH_FAILURE", "PRIVILEGED_ACCESS"],
    "Account Management":        ["ACCOUNT_MANAGEMENT", "AUTH_SUCCESS"],
    "Application Security":      ["PROCESS_EXECUTION", "ENDPOINT_ACTIVITY"],
    "Asset Management":          ["NETWORK_TRAFFIC", "AUDIT_LOG"],
    "Audit Log Management":      ["AUDIT_LOG"],
    "Continuous Vulnerability Management": ["VULNERABILITY_EVENT"],
    "Data Protection":           ["FILE_ACTIVITY", "DATA_EXFILTRATION"],
    "Data Recovery":             ["FILE_ACTIVITY", "AUDIT_LOG"],
    "Email and Web Browser Protections": ["EMAIL_ACTIVITY", "NETWORK_TRAFFIC"],
    "Incident Response Management": ["INCIDENT_RESPONSE", "AUDIT_LOG"],
    "Malware Defenses":          ["ENDPOINT_ACTIVITY", "PROCESS_EXECUTION", "VULNERABILITY_EVENT"],
    "Network Infrastructure Management": ["NETWORK_TRAFFIC", "CONFIG_CHANGE"],
    "Network Monitoring and Defense": ["NETWORK_TRAFFIC", "INCIDENT_RESPONSE"],
    "Penetration Testing":       ["VULNERABILITY_EVENT"],
    "Secure Configuration":      ["CONFIG_CHANGE"],
    "Security Awareness and Skills Training": ["AUTH_SUCCESS", "ACCOUNT_MANAGEMENT"],
    "Service Provider Management": ["CLOUD_ACTIVITY", "AUDIT_LOG"],
    "Software Management":       ["PROCESS_EXECUTION", "CONFIG_CHANGE"],
}

# Default fallback for any unmapped CIS family
DEFAULT_CIS = ["AUTH_SUCCESS", "AUDIT_LOG"]


def gen_cis_v8() -> None:
    raw = json.loads((DATA_DIR / "CIS_V8.json").read_text(encoding="utf-8-sig"))
    queries: dict[str, dict] = {}
    for c in raw["Controls"]:
        if not c.get("SiemValidatable", False):
            continue
        cid = c["ControlId"]
        family = c["Family"]
        desc = c.get("Description", "")
        concepts = FAMILY_CONCEPTS_CIS.get(family, DEFAULT_CIS)
        queries[cid] = make_entry(desc[:80], concepts)
    write_file("CIS_V8", queries)


# ── CJIS ─────────────────────────────────────────────────────────────────────

FAMILY_CONCEPTS_CJIS: dict[str, list[str]] = {
    "Access Control":  ["AUTH_SUCCESS", "AUTH_FAILURE", "ACCOUNT_MANAGEMENT"],
    "Auditing":        ["AUDIT_LOG"],
    "Configuration":   ["CONFIG_CHANGE"],
    "Formal Audits":   ["AUDIT_LOG"],
    "Identification":  ["AUTH_SUCCESS", "AUTH_FAILURE"],
    "Incidents":       ["INCIDENT_RESPONSE", "AUDIT_LOG"],
    "Mobile":          ["ENDPOINT_ACTIVITY", "AUTH_SUCCESS"],
    "Personnel":       ["ACCOUNT_MANAGEMENT"],
    "System Protection": ["ENDPOINT_ACTIVITY", "VULNERABILITY_EVENT", "NETWORK_TRAFFIC"],
}

DEFAULT_CJIS = ["AUDIT_LOG"]


def gen_cjis() -> None:
    raw = json.loads((DATA_DIR / "CJIS.json").read_text(encoding="utf-8-sig"))
    queries: dict[str, dict] = {}
    for c in raw["Controls"]:
        if not c.get("SiemValidatable", False):
            continue
        cid = c["ControlId"]
        family = c["Family"]
        desc = c.get("Description", "")
        concepts = FAMILY_CONCEPTS_CJIS.get(family, DEFAULT_CJIS)
        queries[cid] = make_entry(desc[:80], concepts)
    write_file("CJIS", queries)


# ── FedRAMP_Moderate ──────────────────────────────────────────────────────────

FAMILY_CONCEPTS_FEDRAMP: dict[str, list[str]] = {
    "Access Control (AC)":                   ["AUTH_SUCCESS", "AUTH_FAILURE", "ACCOUNT_MANAGEMENT"],
    "Audit & Accountability (AU)":           ["AUDIT_LOG"],
    "Configuration Management (CM)":         ["CONFIG_CHANGE"],
    "Contingency Planning (CP)":             ["AUDIT_LOG", "INCIDENT_RESPONSE"],
    "Identification & Authentication (IA)":  ["AUTH_SUCCESS", "AUTH_FAILURE"],
    "Incident Response (IR)":                ["INCIDENT_RESPONSE", "AUDIT_LOG"],
    "Maintenance (MA)":                      ["AUDIT_LOG", "CONFIG_CHANGE"],
    "Media Protection (MP)":                 ["FILE_ACTIVITY"],
    "Personnel Security (PS)":               ["ACCOUNT_MANAGEMENT"],
    "Physical Protection (PE)":              ["PHYSICAL_ACCESS"],
    "Planning (PL)":                         ["AUDIT_LOG"],
    "Program Management (PM)":               ["AUDIT_LOG"],
    "Risk Assessment (RA)":                  ["VULNERABILITY_EVENT"],
    "System & Communications Protection (SC)": ["NETWORK_TRAFFIC", "CONFIG_CHANGE"],
    "System & Information Integrity (SI)":   ["ENDPOINT_ACTIVITY", "VULNERABILITY_EVENT", "AUDIT_LOG"],
    "Supply Chain Risk Management (SR)":     ["CLOUD_ACTIVITY", "AUDIT_LOG"],
    "Awareness & Training (AT)":             ["AUTH_SUCCESS", "ACCOUNT_MANAGEMENT"],
}

DEFAULT_FEDRAMP = ["AUDIT_LOG"]


def gen_fedramp() -> None:
    raw = json.loads((DATA_DIR / "FedRAMP_Moderate.json").read_text(encoding="utf-8-sig"))
    queries: dict[str, dict] = {}
    for c in raw["Controls"]:
        if not c.get("SiemValidatable", False):
            continue
        cid = c["ControlId"]
        family = c.get("Family", "")
        name = c.get("ControlName", c.get("Description", ""))
        concepts = FAMILY_CONCEPTS_FEDRAMP.get(family, DEFAULT_FEDRAMP)
        queries[cid] = make_entry(name[:80], concepts)
    write_file("FedRAMP_Moderate", queries)


# ── HIPAA ─────────────────────────────────────────────────────────────────────

FAMILY_CONCEPTS_HIPAA: dict[str, list[str]] = {
    "Physical":           ["PHYSICAL_ACCESS"],
    "Breach Notification": ["INCIDENT_RESPONSE", "AUDIT_LOG"],
    "Documentation":      ["AUDIT_LOG"],
    "Organizational":     ["ACCOUNT_MANAGEMENT", "AUDIT_LOG"],
}

HIPAA_KEYWORD_MAP = [
    (["log", "audit", "monitor", "review record"], ["AUDIT_LOG"]),
    (["access", "authenticat", "password", "log-in", "login"], ["AUTH_SUCCESS", "AUTH_FAILURE"]),
    (["account", "user", "workforce", "termination", "clearance"], ["ACCOUNT_MANAGEMENT"]),
    (["network", "firewall", "transmission", "encrypt"], ["NETWORK_TRAFFIC"]),
    (["file", "data", "backup"], ["FILE_ACTIVITY"]),
    (["incident", "response", "report"], ["INCIDENT_RESPONSE"]),
    (["malware", "virus", "software"], ["PROCESS_EXECUTION", "ENDPOINT_ACTIVITY"]),
    (["physical", "facility"], ["PHYSICAL_ACCESS"]),
    (["privilege", "admin", "emergency"], ["PRIVILEGED_ACCESS"]),
]

DEFAULT_HIPAA = ["AUTH_SUCCESS", "AUDIT_LOG"]


def hipaa_concepts(family: str, desc: str) -> list[str]:
    if family in FAMILY_CONCEPTS_HIPAA:
        return FAMILY_CONCEPTS_HIPAA[family]
    lower = desc.lower()
    for keywords, concepts in HIPAA_KEYWORD_MAP:
        if any(kw in lower for kw in keywords):
            return concepts
    return DEFAULT_HIPAA


def gen_hipaa() -> None:
    raw = json.loads((DATA_DIR / "HIPAA.json").read_text(encoding="utf-8-sig"))
    queries: dict[str, dict] = {}
    for c in raw["Controls"]:
        if not c.get("SiemValidatable", False):
            continue
        cid = c["ControlId"]
        desc = c.get("Description", "")
        family = c.get("Family", "")
        concepts = hipaa_concepts(family, desc)
        queries[cid] = make_entry(desc[:80], concepts)
    write_file("HIPAA", queries)


# ── ISO_27001 ─────────────────────────────────────────────────────────────────

ISO_KEYWORD_MAP = [
    (["log", "audit", "monitor", "record"], ["AUDIT_LOG"]),
    (["access control", "authenticat", "password", "account"], ["AUTH_SUCCESS", "AUTH_FAILURE", "ACCOUNT_MANAGEMENT"]),
    (["network", "firewall", "communicat"], ["NETWORK_TRAFFIC"]),
    (["physical", "facility", "entry"], ["PHYSICAL_ACCESS"]),
    (["malware", "virus", "endpoint", "process"], ["ENDPOINT_ACTIVITY", "PROCESS_EXECUTION"]),
    (["incident", "response", "detection"], ["INCIDENT_RESPONSE"]),
    (["vulnerability", "patch", "pentest"], ["VULNERABILITY_EVENT"]),
    (["file", "data", "backup", "storage"], ["FILE_ACTIVITY"]),
    (["config", "change", "registry", "baseline"], ["CONFIG_CHANGE"]),
    (["cloud", "supplier", "service provider"], ["CLOUD_ACTIVITY"]),
    (["email", "phishing"], ["EMAIL_ACTIVITY"]),
    (["user", "identity", "workforce"], ["ACCOUNT_MANAGEMENT"]),
    (["privilege", "admin", "role", "segregat"], ["PRIVILEGED_ACCESS", "GROUP_MANAGEMENT"]),
]

DEFAULT_ISO = ["AUDIT_LOG", "AUTH_SUCCESS"]

FAMILY_CONCEPTS_ISO: dict[str, list[str]] = {
    "Physical": ["PHYSICAL_ACCESS"],
    "People":   ["ACCOUNT_MANAGEMENT", "AUTH_SUCCESS"],
}


def iso_concepts(family: str, desc: str) -> list[str]:
    if family in FAMILY_CONCEPTS_ISO:
        return FAMILY_CONCEPTS_ISO[family]
    lower = desc.lower()
    for keywords, concepts in ISO_KEYWORD_MAP:
        if any(kw in lower for kw in keywords):
            return concepts
    return DEFAULT_ISO


def gen_iso27001() -> None:
    raw = json.loads((DATA_DIR / "ISO_27001.json").read_text(encoding="utf-8-sig"))
    queries: dict[str, dict] = {}
    for c in raw["Controls"]:
        if not c.get("SiemValidatable", False):
            continue
        cid = c["ControlId"]
        desc = c.get("Description", "")
        family = c.get("Family", "")
        concepts = iso_concepts(family, desc)
        queries[cid] = make_entry(desc[:80], concepts)
    write_file("ISO_27001", queries)


# ── PCI_DSS ───────────────────────────────────────────────────────────────────

FAMILY_CONCEPTS_PCI: dict[str, list[str]] = {
    "Access Control":       ["AUTH_SUCCESS", "AUTH_FAILURE", "ACCOUNT_MANAGEMENT"],
    "Account Data Protection": ["FILE_ACTIVITY", "DATA_EXFILTRATION"],
    "Encryption":           ["NETWORK_TRAFFIC", "FILE_ACTIVITY"],
    "Logging and Monitoring": ["AUDIT_LOG", "NETWORK_TRAFFIC"],
    "Malware Protection":   ["ENDPOINT_ACTIVITY", "VULNERABILITY_EVENT"],
    "Network Security":     ["NETWORK_TRAFFIC", "CONFIG_CHANGE"],
    "Physical Security":    ["PHYSICAL_ACCESS"],
    "Secure Configuration": ["CONFIG_CHANGE"],
    "Security Awareness and Training": ["AUTH_SUCCESS", "ACCOUNT_MANAGEMENT"],
    "Testing":              ["VULNERABILITY_EVENT"],
    "Vulnerability Management": ["VULNERABILITY_EVENT"],
    "Identification and Authentication": ["AUTH_SUCCESS", "AUTH_FAILURE"],
}

DEFAULT_PCI = ["AUDIT_LOG", "NETWORK_TRAFFIC"]


def gen_pci_dss() -> None:
    raw = json.loads((DATA_DIR / "PCI_DSS.json").read_text(encoding="utf-8-sig"))
    queries: dict[str, dict] = {}
    for c in raw["Controls"]:
        if not c.get("SiemValidatable", False):
            continue
        cid = c["ControlId"]
        family = c.get("Family", "")
        desc = c.get("Description", "")
        concepts = FAMILY_CONCEPTS_PCI.get(family, DEFAULT_PCI)
        queries[cid] = make_entry(desc[:80], concepts)
    write_file("PCI_DSS", queries)


# ── Empty stubs (0 SIEM-testable controls) ───────────────────────────────────

def gen_empty(fw_id: str) -> None:
    write_file(fw_id, {})


# ── Writer ────────────────────────────────────────────────────────────────────

def write_file(fw_id: str, queries: dict) -> None:
    out = {"queries": queries}
    path = QUERIES_DIR / f"{fw_id}.json"
    path.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"  Wrote {fw_id}.json ({len(queries)} controls)")


# ── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Generating ControlQueries JSON files...")
    gen_cis_v8()
    gen_cjis()
    gen_fedramp()
    gen_hipaa()
    gen_iso27001()
    gen_pci_dss()
    # Zero testable controls — write empty stubs
    gen_empty("CMMC_L2")
    gen_empty("CMMC_L3")
    gen_empty("GDPR")
    gen_empty("SOX")
    print("Done.")
