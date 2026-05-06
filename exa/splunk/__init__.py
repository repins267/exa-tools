"""Splunk SPL → Exabeam EQL correlation rule converter."""

from exa.splunk.batch import convert_excel, export_api_payloads
from exa.splunk.converter import convert_spl_to_exa_rule, to_api_payload

__all__ = [
    "convert_spl_to_exa_rule",
    "to_api_payload",
    "convert_excel",
    "export_api_payloads",
]
