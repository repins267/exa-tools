---
name: exa-identity
description: >-
  Investigate AD/identity-resolution problems on a New-Scale tenant — two users merged
  into one entity, EXA-INTERNAL-ERROR on a user, or GUID "ghost" usernames. Use when asked
  "why are these two users merged", "identity merge", "recycled email", "user entity
  links", "GUID users", or "EXA-INTERNAL-ERROR on an entity". Detects the shared-identifier
  smoking gun (read-only) and walks the gated remediation. Requires the exa-tools MCP.
---

# exa-identity — merged entities & identity resolution

Exabeam stitches user identity from several keys (email, UPN, SAMAccountName). When one
identifier is **shared by two real people** — almost always a **recycled email** (a former
employee's address reassigned to a new hire/manager) — the two entities collapse into one,
and the platform throws EXA-INTERNAL-ERROR trying to build one timeline from two
contradictory AD objects. This skill finds that shared identifier and confirms it.

## Preflight

Call `get_active_tenant`; state the tenant + kind. Detection is read-only and safe on a
customer tenant. Remediation (deleting a context-table record) is a **write** — never do it
without `--allow-writes` AND an explicit human confirmation of the exact record.

## Detect (read-only)

1. **`identity_health`** — the sweep. Two signals:
   - **Merged entities** — any identifier in an identity/User context table mapped to **2+
     distinct users**. This is the smoking gun: `email areckamp@acme.com → adam.reckamp,
     ryan.siebel` means those two people are one entity to Exabeam.
   - **GUID ghost users** — logins whose username is a bare AD objectGUID (unresolved SID),
     grouped by host. Many on one host = a machine cycling deleted/orphaned accounts. This
     is a *related but different* problem (Windows-side resolution failure), not a merge.
   Add `render=true` for a branded report.
2. **`context_table`** — the direct lookup that used to be "UI-only". With no args it lists
   every context table; `table="User Entity Links" contains="adam.reckamp"` returns every
   record (and identifier) mapped to that user. Run it for **both** users and eyeball the
   overlapping value — that is the proof, straight from the table the UI shows.

## Confirm in Entra/AD (the human step)

Take the shared value and check both accounts in Entra: `proxyAddresses`, `mail`,
`userPrincipalName`, and their **change history**. If the value was on a deprovisioned
account and reassigned, the change log shows it — that closes the case.

## Remediate (gated — human-confirmed, write)

Only after the shared identifier is confirmed, and only on `--allow-writes`:

1. Identify the **stale/wrong** owner (the former employee, or the entry that shouldn't hold
   the value).
2. Remove that identifier from the identity table for the wrong user (`exa tables records`
   delete, or the Context Management API `deleteRecords`), then re-add the corrected mapping.
3. Force re-enrichment on both accounts.
4. Re-run `identity_health` to confirm the merge is gone.

**Never auto-delete.** A wrong context-table delete has real blast radius (it can blind
detections for a user). State the exact record, get a yes, then act on that one record.

## How to read it

- **A merge is 2+ users on one value; a GUID ghost is one unresolved login.** Different root
  causes, different fixes — say which you found. Don't conflate them.
- **Lead with the shared value and the two users** — that is what the TAM takes to Entra.
- **No merge found ≠ no problem** — the identity table may not be the one Exabeam links on,
  or the merge may be on an attribute not in the scanned tables. Say what you scanned.

## Traps

- The identity table's key attribute is **not** always named `key` — the tool resolves the
  real key; don't assume.
- GUID users are noise, not a merge — don't send them down the recycled-email path.
- Reading a huge context table is heavy; if a scan is slow, scope it with `table=`.
- Detection proves *what* is shared; the *why* (reassignment) is confirmed in Entra, not here.
