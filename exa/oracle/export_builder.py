"""Build a Field Oracle from a tenant parser export (parsers.conf + event_builder.conf).

The output schema is byte-compatible with `exa.update.build_field_oracle` (the
pC-based build), so every consumer — the SPL→Sigma→EQL converter and compliance
concept resolution — reads it unchanged:

    by_activity_type: {activity_type -> {cim2_field -> [vendor/product, ...]}}
    by_vendor:        {vendor -> {activity_type -> [cim2_field, ...]}}
    raw_to_cim2:      {raw_key -> cim2_field}
    built_at:         ISO timestamp
    stats:            {parsers_processed, parsers_failed, source, raw_to_cim2_note}

Parity is guaranteed by reusing the pC build's own helpers for activity-type and
CIM2-field extraction. The one dimension that differs is `raw_to_cim2`: the pC
files carry explicit `exa_json_path=…,exa_field_name=…` mappings, whereas an
export encodes them only implicitly in the extraction regexes. We recover them
from JSON parsers reliably (the raw key sits immediately before the capture) and
best-effort from key=value / CEF parsers; the note in `stats` records this.
"""

from __future__ import annotations

import json
import re
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Reuse the pC build's helpers so activity-type and field extraction match exactly.
from exa.update import _CAPTURE_GROUP_RE, _extract_activity_type

# A parser block in parsers.conf: """Name""" = """...""" ... up to the next Name.
_NAME_RE = re.compile(r'"""Name"""\s*=\s*"""([^"]+)"""')
_VENDOR_RE = re.compile(r'"""Vendor"""\s*=\s*"""([^"]+)"""')
_PRODUCT_RE = re.compile(r'"""Product"""\s*=\s*"""([^"]+)"""')

# raw -> CIM2 from the extraction regexes. JSON: the raw key precedes the capture,
#   e.g.  "username":"...({user}...   -> username -> user
# key=value / CEF:  \Wsuser=(...({user}...  -> suser -> user
_RAW_JSON_RE = re.compile(r'"([A-Za-z0-9_.\-]+)"\s*:\s*\\?"?[^"]*?\(\{([a-z][a-z0-9_]*)\}')
_RAW_KV_RE = re.compile(r'\\W([A-Za-z0-9_]+)=\(?\{?[^)]*?\(\{([a-z][a-z0-9_]*)\}')


def _iter_parser_blocks(parsers_conf: str):
    """Yield (name, vendor, product, block_text) for each parser in parsers.conf."""
    # Split at each Name so a block holds exactly one parser's fields.
    parts = re.split(r'(?="""Name"""\s*=)', parsers_conf)
    for block in parts:
        nm = _NAME_RE.search(block)
        if not nm:
            continue
        ven = _VENDOR_RE.search(block)
        prod = _PRODUCT_RE.search(block)
        yield nm.group(1), (ven.group(1) if ven else ""), (prod.group(1) if prod else ""), block


def _raw_to_cim2_from_block(block: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in _RAW_JSON_RE.finditer(block):
        out.setdefault(m.group(1), m.group(2))
    for m in _RAW_KV_RE.finditer(block):
        out.setdefault(m.group(1), m.group(2))
    return out


def build_oracle_from_export(
    parsers_conf: str, event_builder_conf: str | None = None
) -> dict[str, Any]:
    """Build the Oracle dict from parser-export text. Same schema as the pC build.

    ``event_builder_conf`` is accepted for future activity-type enrichment but is
    not required: activity_type is derived from the parser name via the same
    helper the pC build uses, so the two Oracles stay drop-in compatible.
    """
    by_activity_type: dict[str, dict[str, list[str]]] = {}
    by_vendor: dict[str, dict[str, list[str]]] = {}
    raw_to_cim2: dict[str, str] = {}
    parser_count = 0
    error_count = 0

    for name, vendor, product, block in _iter_parser_blocks(parsers_conf):
        try:
            activity_type = _extract_activity_type(name)
            cim2_fields = sorted(set(_CAPTURE_GROUP_RE.findall(block)))
            vendor_product = f"{vendor}/{product}" if vendor and product else vendor
            parser_count += 1

            if activity_type:
                at_entry = by_activity_type.setdefault(activity_type, {})
                for fld in cim2_fields:
                    sources = at_entry.setdefault(fld, [])
                    if vendor_product and vendor_product not in sources:
                        sources.append(vendor_product)

            if vendor:
                vendor_entry = by_vendor.setdefault(vendor, {})
                if activity_type:
                    at_fields = vendor_entry.setdefault(activity_type, [])
                    for fld in cim2_fields:
                        if fld not in at_fields:
                            at_fields.append(fld)

            for raw_key, cim2_field in _raw_to_cim2_from_block(block).items():
                raw_to_cim2.setdefault(raw_key, cim2_field)
        except Exception:  # noqa: BLE001 - one bad block never kills the build
            error_count += 1
            continue

    return {
        "by_activity_type": by_activity_type,
        "by_vendor": by_vendor,
        "raw_to_cim2": raw_to_cim2,
        "built_at": datetime.now(UTC).isoformat(),
        "stats": {
            "parsers_processed": parser_count,
            "parsers_failed": error_count,
            "source": "tenant-export",
            "raw_to_cim2_note": "regex-derived (JSON reliable, key=value/CEF best-effort)",
        },
    }


def _read_export(source: Path) -> tuple[str, str | None]:
    """Return (parsers_conf_text, event_builder_text_or_None) from a zip or a dir."""
    source = Path(source).expanduser()
    if source.is_dir():
        pconf = next(source.rglob("parsers.conf"), None)
        if pconf is None:
            raise FileNotFoundError(f"no parsers.conf under {source}")
        econf = next(source.rglob("event_builder.conf"), None)
        return (
            pconf.read_text(encoding="utf-8", errors="replace"),
            econf.read_text(encoding="utf-8", errors="replace") if econf else None,
        )
    if source.suffix.lower() == ".zip":
        with zipfile.ZipFile(source) as zf:
            names = zf.namelist()
            pname = next((n for n in names if n.endswith("parsers.conf")), None)
            if pname is None:
                raise FileNotFoundError(f"no parsers.conf in {source}")
            ename = next((n for n in names if n.endswith("event_builder.conf")), None)
            pconf = zf.read(pname).decode("utf-8", errors="replace")
            econf = zf.read(ename).decode("utf-8", errors="replace") if ename else None
            return pconf, econf
    if source.name.endswith("parsers.conf"):
        return source.read_text(encoding="utf-8", errors="replace"), None
    raise ValueError(f"unsupported export {source}: expected a .zip, a dir, or parsers.conf")


def build_oracle_from_zip(source: str | Path) -> dict[str, Any]:
    """Build the Oracle from a parser export .zip, an extracted dir, or a parsers.conf."""
    parsers_conf, event_builder = _read_export(Path(source))
    return build_oracle_from_export(parsers_conf, event_builder)


def write_oracle(oracle: dict[str, Any], path: str | Path) -> Path:
    """Write an Oracle dict to disk (creating parent dirs). Returns the path."""
    p = Path(path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(oracle, indent=2), encoding="utf-8")
    return p
