"""Report branding: resolve which logo goes in the header, keep reports self-contained.

The renderer (`exa.report.theme.page`) has one header logo slot. `brand` selects
what fills it:

- ``"exabeam"`` (default) -- the Exabeam house style, for customer-facing reports
  delivered through official Exabeam communications. Unchanged.
- ``"exa-tools"`` -- the exa-tools lockup, so an internal reader sees at a glance
  that exa-tools produced the report.
- a **registered name** -- a customer logo added once with ``exa brand add <name>
  <file>`` and stored under ``~/.exa/brand/``. Select it per render with
  ``brand="<name>"``.
- a **file path** -- an ad-hoc logo embedded for a single render.

Whatever is selected is base64-embedded into the header, so every report stays
fully self-contained (offline, PDF, email-safe) -- no external asset is ever
linked. Customer logos live only in the local ``~/.exa/brand/`` registry and are
embedded per render; they are never committed or promoted into shipped assets.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from pathlib import Path

# Presets ship as base64 assets alongside this module. Keys map to
# (dark-theme logo, light-theme logo) -- the dark slot needs the light-coloured
# artwork and vice-versa (see theme.py's .logo-dark / .logo-light swap).
_PRESET_ASSETS: dict[str, tuple[str, str, str]] = {
    # name: (dark-theme b64 file, light-theme b64 file, alt text)
    "exabeam": ("_logo_dark_b64.txt", "_logo_light_b64.txt", "Exabeam"),
    "exa-tools": ("_logo_exatools_dark_b64.txt", "_logo_exatools_light_b64.txt", "exa-tools"),
}

DEFAULT_BRAND = "exabeam"

_BRAND_DIR = Path.home() / ".exa" / "brand"

# Image types allowed for a custom logo, mapped to the data-URI media type.
_MIME_BY_EXT = {
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
}
_MAX_LOGO_BYTES = 2 * 1024 * 1024  # 2 MiB: a header logo, not an attachment


class BrandError(ValueError):
    """A brand could not be resolved (unknown name, missing/oversized/bad file)."""


@dataclass(frozen=True)
class ResolvedLogo:
    """A header logo ready to embed: full ``data:`` src for each theme + alt text."""

    dark_src: str
    light_src: str
    alt: str


def _file_to_data_uri(path: Path) -> str:
    ext = path.suffix.lower()
    mime = _MIME_BY_EXT.get(ext)
    if mime is None:
        raise BrandError(
            f"unsupported logo type {ext!r} ({path}); use one of {sorted(_MIME_BY_EXT)}"
        )
    data = path.read_bytes()
    if len(data) > _MAX_LOGO_BYTES:
        raise BrandError(
            f"logo {path} is {len(data)} bytes; max is {_MAX_LOGO_BYTES} (keep header logos small)"
        )
    return f"data:{mime};base64,{base64.b64encode(data).decode('ascii')}"


def _preset_data_uri(b64_file: str) -> str:
    p = Path(__file__).resolve().parent / b64_file
    if not p.exists():
        raise BrandError(f"preset asset missing: {b64_file}")
    return f"data:image/svg+xml;base64,{p.read_text(encoding='utf-8').strip()}"


def _registered_variants(name: str) -> tuple[Path, Path] | None:
    """(dark-theme file, light-theme file) for a registered brand, or None.

    A brand may register one logo (used for both themes) or a ``<name>`` plus a
    ``<name>-light`` variant for light backgrounds.
    """
    if not _BRAND_DIR.exists():
        return None
    dark: Path | None = None
    light: Path | None = None
    for ext in _MIME_BY_EXT:
        if dark is None and (_BRAND_DIR / f"{name}{ext}").exists():
            dark = _BRAND_DIR / f"{name}{ext}"
        if light is None and (_BRAND_DIR / f"{name}-light{ext}").exists():
            light = _BRAND_DIR / f"{name}-light{ext}"
    if dark is None:
        return None
    return dark, (light or dark)


def resolve_logo(brand: str | None = None) -> ResolvedLogo:
    """Resolve ``brand`` to an embeddable header logo.

    Order: preset name -> registered name (~/.exa/brand/) -> file path. Raises
    ``BrandError`` on an unknown name or unreadable file rather than silently
    rendering without a logo.
    """
    name = (brand or DEFAULT_BRAND).strip()
    if not name:
        name = DEFAULT_BRAND

    preset = _PRESET_ASSETS.get(name)
    if preset:
        dark_file, light_file, alt = preset
        return ResolvedLogo(_preset_data_uri(dark_file), _preset_data_uri(light_file), alt)

    variants = _registered_variants(name)
    if variants:
        dark, light = variants
        return ResolvedLogo(_file_to_data_uri(dark), _file_to_data_uri(light), name)

    # A file path for a one-off logo.
    p = Path(name).expanduser()
    if p.is_file():
        uri = _file_to_data_uri(p)
        return ResolvedLogo(uri, uri, p.stem)

    raise BrandError(
        f"unknown brand {name!r}: not a preset ({sorted(_PRESET_ASSETS)}), "
        f"a registered brand ({', '.join(list_brands()) or 'none'}), or a file path"
    )


# --- registry management (backs `exa brand add/list/remove`) ----------------


def list_brands() -> list[str]:
    """Registered custom brand names (excludes presets), sorted."""
    if not _BRAND_DIR.exists():
        return []
    names = set()
    for f in _BRAND_DIR.iterdir():
        if f.is_file() and f.suffix.lower() in _MIME_BY_EXT:
            stem = f.stem
            if stem.endswith("-light"):
                stem = stem[: -len("-light")]
            names.add(stem)
    return sorted(names)


def add_brand(name: str, logo_path: str | Path, light_path: str | Path | None = None) -> Path:
    """Register a custom logo under ``~/.exa/brand/``. Returns the stored dark file.

    ``light_path`` is an optional variant for light backgrounds. Reserved preset
    names cannot be shadowed.
    """
    name = name.strip()
    if not name or "/" in name or "\\" in name or name != name.replace("..", ""):
        raise BrandError(f"invalid brand name {name!r}")
    if name in _PRESET_ASSETS:
        raise BrandError(f"{name!r} is a built-in preset and cannot be overridden")

    src = Path(logo_path).expanduser()
    if not src.is_file():
        raise BrandError(f"logo file not found: {src}")
    _file_to_data_uri(src)  # validate type + size before writing anything

    _BRAND_DIR.mkdir(parents=True, exist_ok=True)
    # Remove any prior files for this name so a re-register replaces cleanly.
    remove_brand(name, quiet=True)
    dark_dest = _BRAND_DIR / f"{name}{src.suffix.lower()}"
    dark_dest.write_bytes(src.read_bytes())
    if light_path:
        lsrc = Path(light_path).expanduser()
        if not lsrc.is_file():
            raise BrandError(f"light logo file not found: {lsrc}")
        _file_to_data_uri(lsrc)
        (_BRAND_DIR / f"{name}-light{lsrc.suffix.lower()}").write_bytes(lsrc.read_bytes())
    return dark_dest


def remove_brand(name: str, *, quiet: bool = False) -> int:
    """Delete a registered brand's files. Returns how many files were removed."""
    name = name.strip()
    if name in _PRESET_ASSETS:
        raise BrandError(f"{name!r} is a built-in preset and cannot be removed")
    if not _BRAND_DIR.exists():
        if quiet:
            return 0
        raise BrandError(f"no such registered brand: {name!r}")
    removed = 0
    for ext in _MIME_BY_EXT:
        for cand in (_BRAND_DIR / f"{name}{ext}", _BRAND_DIR / f"{name}-light{ext}"):
            if cand.exists():
                cand.unlink()
                removed += 1
    if removed == 0 and not quiet:
        raise BrandError(f"no such registered brand: {name!r}")
    return removed
