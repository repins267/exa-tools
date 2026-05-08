"""IP address classification for display annotation in case triage.

Classifies public IPs as residential, datacenter, cdn, private, or loopback.
Uses stdlib ipaddress only — no external APIs or dependencies.

Classification is display-only and does not drive verdict logic.
"""

from __future__ import annotations

import ipaddress

_CDN_RANGES: list[tuple[str, str]] = [
    ("104.16.0.0/12", "Cloudflare"),
    ("172.64.0.0/13", "Cloudflare"),
    ("13.224.0.0/14", "AWS CloudFront"),
    ("54.230.0.0/16", "AWS CloudFront"),
    ("13.32.0.0/15", "AWS CloudFront"),
    ("23.235.32.0/20", "Fastly"),
    ("151.101.0.0/16", "Fastly"),
    ("199.232.0.0/16", "Fastly"),
    ("2.16.0.0/13", "Akamai"),
    ("23.0.0.0/12", "Akamai"),
]

_DATACENTER_PREFIXES: list[str] = [
    "52.", "54.", "18.1", "18.2", "18.3",   # AWS EC2
    "35.1", "35.2", "34.8", "34.9",          # GCP
    "40.7", "40.8", "40.9", "20.3",          # Azure
    "104.41", "104.42", "104.43",             # Azure
]


def classify_ip(ip: str) -> str:
    """Classify an IP as: private, loopback, cdn, datacenter, residential, or unknown.

    Args:
        ip: IPv4 or IPv6 address string.

    Returns:
        Classification string. Never raises — returns "unknown" on parse failure.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"

    if addr.is_loopback or addr.is_link_local:
        return "loopback"
    if addr.is_private or addr.is_reserved:
        return "private"

    for cidr, _provider in _CDN_RANGES:
        if addr in ipaddress.ip_network(cidr, strict=False):
            return "cdn"

    for prefix in _DATACENTER_PREFIXES:
        if ip.startswith(prefix):
            return "datacenter"

    return "residential"


def classify_ip_with_label(ip: str) -> tuple[str, str]:
    """Return (classification, label) for display.

    Label adds provider name for cdn ranges, otherwise matches classification.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown", "unknown"

    if addr.is_loopback or addr.is_link_local:
        return "loopback", "loopback"
    if addr.is_private or addr.is_reserved:
        return "private", "private"

    for cidr, provider in _CDN_RANGES:
        if addr in ipaddress.ip_network(cidr, strict=False):
            return "cdn", f"cdn ({provider})"

    for prefix in _DATACENTER_PREFIXES:
        if ip.startswith(prefix):
            return "datacenter", "datacenter"

    return "residential", "residential"
