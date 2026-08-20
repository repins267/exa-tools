"""Bridge the ExaVault (local Obsidian) to a Google Drive folder for a Gemini agent.

Gemini / Agentspace can't read local files, so the vault has to live in a Drive folder
it can ground on. Layering Google Drive sync directly on the Obsidian-synced vault causes
two-sync-engine conflicts, so this keeps the vault as the source of truth and runs a
one-way mirror + an inbox instead:

  READ side  — mirror the TAM folders (10-Customers, 20-Defects, 30-Runbooks, 40-Reference)
               from the vault INTO the Drive mirror folder, so an Agentspace/Gemini data
               store can ground on current notes. Excludes Personal/ and wiki/ (off-limits
               per the exa-vault method) and .obsidian/.
  WRITE side — move Gemini's output out of the Drive inbox (90-Inbox) into the vault's own
               90-Inbox for triage (by a human or the exa-vault skill), then clear the Drive
               inbox. Deliberately does NOT auto-append to customer notes: appending to an
               Obsidian-synced file from a script races Obsidian Sync, so triage stays a
               separate, safe step.

Run on a schedule (Windows Task Scheduler). Read-only by default until you pass --apply.

Config via env (or edit the defaults):
    EXAVAULT_DIR       default C:\\Users\\cyrus.field\\ExaVault
    VAULT_DRIVE_MIRROR the Drive-synced folder, e.g. G:\\My Drive\\ExaVault-Gemini

Usage:
    python scripts/vault_gemini_sync.py            # dry run — shows what it would do
    python scripts/vault_gemini_sync.py --apply    # actually mirror + drain the inbox
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import sys
from pathlib import Path

# Folders the agent may GROUND on (read). Never mirror Personal/ or wiki/.
READ_FOLDERS = ("10-Customers", "20-Defects", "30-Runbooks", "40-Reference")
INBOX = "90-Inbox"  # Gemini writes here (in Drive); we drain it into the vault's 90-Inbox
_OFF_LIMITS = {"Personal", "wiki", ".obsidian", ".git", INBOX}


def _vault() -> Path:
    return Path(os.environ.get("EXAVAULT_DIR", r"C:\Users\cyrus.field\ExaVault"))


def _mirror() -> Path:
    m = os.environ.get("VAULT_DRIVE_MIRROR", "").strip()
    if not m:
        sys.exit("Set VAULT_DRIVE_MIRROR to your Google Drive mirror folder "
                 "(e.g. G:\\My Drive\\ExaVault-Gemini).")
    return Path(m)


def _digest(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _changed(src: Path, dst: Path) -> bool:
    if not dst.exists():
        return True
    if src.stat().st_size != dst.stat().st_size:
        return True
    return _digest(src) != _digest(dst)


def mirror_read(vault: Path, mirror: Path, apply: bool) -> tuple[int, int]:
    """One-way vault -> mirror for the READ_FOLDERS. Returns (copied, removed)."""
    copied = removed = 0
    for folder in READ_FOLDERS:
        src_root = vault / folder
        if not src_root.is_dir():
            continue
        dst_root = mirror / folder
        want: set[Path] = set()
        for src in src_root.rglob("*.md"):
            rel = src.relative_to(src_root)
            if any(part in _OFF_LIMITS for part in rel.parts):
                continue
            dst = dst_root / rel
            want.add(dst)
            if _changed(src, dst):
                copied += 1
                print(f"  copy   {folder}/{rel}")
                if apply:
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src, dst)
        # remove mirror files that no longer exist in the vault (these folders are vault-owned)
        if dst_root.is_dir():
            for stale in dst_root.rglob("*.md"):
                if stale not in want:
                    removed += 1
                    print(f"  remove {folder}/{stale.relative_to(dst_root)} (gone from vault)")
                    if apply:
                        stale.unlink()
    return copied, removed


def drain_inbox(vault: Path, mirror: Path, apply: bool) -> int:
    """Move Gemini's Drive-inbox notes into the vault's 90-Inbox for triage. Returns count."""
    src_inbox = mirror / INBOX
    if not src_inbox.is_dir():
        return 0
    dst_inbox = vault / INBOX
    moved = 0
    for f in src_inbox.rglob("*.md"):
        rel = f.relative_to(src_inbox)
        dst = dst_inbox / rel
        # never overwrite an existing triage file; disambiguate by suffix
        n = 1
        while dst.exists():
            dst = dst_inbox / rel.with_stem(f"{rel.stem}-{n}")
            n += 1
        moved += 1
        print(f"  ingest {INBOX}/{rel} -> vault/{INBOX}/{dst.name}")
        if apply:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(f), str(dst))
    return moved


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Mirror ExaVault <-> a Google Drive folder for Gemini.")
    ap.add_argument("--apply", action="store_true", help="actually copy/move (default: dry run)")
    args = ap.parse_args(argv)

    vault, mirror = _vault(), _mirror()
    if not vault.is_dir():
        sys.exit(f"Vault not found: {vault} (set EXAVAULT_DIR).")
    mode = "APPLY" if args.apply else "DRY-RUN"
    print(f"[{mode}] vault={vault}  mirror={mirror}")
    if args.apply:
        mirror.mkdir(parents=True, exist_ok=True)

    print("READ  (vault -> Drive mirror):")
    copied, removed = mirror_read(vault, mirror, args.apply)
    print("WRITE (Drive inbox -> vault 90-Inbox):")
    ingested = drain_inbox(vault, mirror, args.apply)

    print(f"Summary: {copied} copied, {removed} removed, {ingested} inbox notes ingested.")
    if not args.apply and (copied or removed or ingested):
        print("Dry run only — re-run with --apply to make these changes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
