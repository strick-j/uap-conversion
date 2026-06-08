# DPA/SIA → UAP policy migration

Four-stage pipeline, pure Python 3.9+ (stdlib only at runtime):

```bash
# 1. INVENTORY — pull legacy SIA policies into old-policies/
python3 -m converter.pull    --tenant <tenant> --token token

# 2. CONVERT  — old-policies/ -> new-policies/ (UAP format), resolving principals
python3 -m converter.convert --resolve --drop-unresolved \
        --identity-tenant <identity-tenant>

# 3. DELETE   — remove the legacy SIA policies (dry run first, then --confirm)
python3 -m converter.delete  --tenant <tenant> --token token --confirm

# ===> Switch the tenant to UAP (Access Control Policies) mode before step 4 <===
#      UAP policies cannot be created until the tenant has been migrated.

# 4. CREATE   — POST every converted policy to the UAP API
python3 -m converter.post    --tenant <tenant> --token token
```

Two tenant identifiers, which may differ:

- **`<tenant>`** — your service subdomain, used in `<tenant>.uap.cyberark.cloud`
  (UAP) and `<tenant>-jit.cyberark.cloud` (SIA).
- **`<identity-tenant>`** — your Identity login tenant, used in
  `<identity-tenant>.id.cyberark.cloud` (principal resolution).

Each tool also accepts an explicit URL override (`--base-url` / `--identity-url`)
if your endpoints don't follow the standard pattern.

## Stage 1 — pull (inventory + retrieval)

`pull.py` lists policies from the SIA JIT API and fetches each one in full,
writing the raw old-format JSON to `old-policies/` (the shape stage 2 consumes):

- `GET /api/access-policies` → `{ items, totalCount }`
- `GET /api/access-policies/{id}?extended=true` → full policy

Base URL is `https://<tenant>-jit.cyberark.cloud` (override with `--base-url`).
Files are named from a sanitized `policyName` (`--name-by id` to use the id).
Per-policy fetch failures are non-fatal and reported; a `listed != totalCount`
mismatch warns about possible pagination.

## Stage 2 — convert

```bash
python3 -m converter.convert --old-dir old-policies --new-dir new-policies
```

Add `--resolve` for live principal-id lookups and `--drop-unresolved` to omit
principals that can't be resolved (see "Principal id resolution" below).

## What it does

- **Drops `Draft` policies** (status is server-managed in UAP, so it's omitted).
- **Splits multi-rule policies** — each old `userAccessRule` becomes its own
  single-rule UAP policy (`<name>-<n>-<ruleName>.json`). Only `policy27` splits.
- **Maps every field** per the locked rules below.
- Writes `principals-manifest.json`: every unique principal needing an id.

## Conversion rules

| Old | New | Notes |
|-----|-----|-------|
| `policyName` / `description` | `metadata.name` / `metadata.description` | |
| `status` | `metadata.status` = `{"status":"Active"}` | required on create (live 400 confirms); `Draft` dropped |
| `activationType` | `metadata.policyEntitlement.policyType` | `RECURRING`→`Recurring` |
| provider key (`AWS`/`Azure`/`GCP`/`OnPrem`) | `locationType` (`AWS`/`Azure`/`GCP`/`FQDN/IP`) | `targetCategory` always `VM` |
| `providersData.<p>` | `targets.<locationType>` | tags `Key/Value`→`key/value` |
| `daysOfWeek` (names) | `accessWindow.daysOfTheWeek` (ints) | **Sun=0** |
| `fullDays:true` | omit `fromHour`/`toHour` | else `HH:MM`→`HH:MM:SS` |
| `timeZone` | `metadata.timeZone` | moved off the rule |
| `idleTime` | `conditions.idleTime` | |
| *(none)* | `conditions.maxSessionDuration` | default **2** |
| `grantAccess` | *(dropped)* | no UAP equivalent; was uniform `2` |
| `connectAs.<p>.ssh` (str) | `behavior.connectAs.ssh.username` | tokens preserved |
| `connectAs.<p>.rdp.*` | `behavior.connectAs.rdp.*` | local/domain ephemeral kept as-is |
| roles/groups/users | flat `principals[]` | `type` UPPERCASE; ids resolved |

## Principal id resolution

The UAP schema requires `id` (and `sourceDirectoryId` for users/groups). The
old exports only carry name + source, so ids are looked up via the Identity API.

```bash
python3 -m converter.convert --resolve --token token \
    --identity-tenant <identity-tenant>
```

- **`--resolve`** uses `IdentityResolver`, validated live against the tenant:
  - **ROLE**  → Redrock `SELECT ID, Name FROM Role`
  - **USER**  → `DirectoryServiceQuery` (user filter on `SystemName`) — federates
    to AD live, so AD users absent from the Redrock cache still resolve.
  - **GROUP** → `DirectoryServiceQuery` (group filter on `DisplayName`).
  - Directory disambiguation: exact name → cloud-dir (`CDS`) → AD domain.
  - Failures degrade to a `<lookup:…>` placeholder + warning (non-fatal).
- **Default (no `--resolve`):** `PlaceholderResolver` emits tokens, no network.

Principals whose source directory is inactive or not connected in the tenant
won't resolve; with `--drop-unresolved` they're omitted (and reported) so the
rest of the policy still converts. Review those policies and add the correct
principal manually. Duplicate principals (same identity listed under two source
directories in the old data) are de-duplicated automatically.

## Stage 3 — delete (decommission legacy SIA)

```bash
python3 -m converter.delete --tenant <tenant> --token token            # dry run
python3 -m converter.delete --tenant <tenant> --token token --confirm  # delete
```

Removes the legacy SIA policies via `DELETE /api/access-policies/{id}` so the
tenant can be switched to UAP. Safeguards:

- **Dry-run by default** — prints exactly what would be deleted; `--confirm`
  required to act.
- Deletes **only** policies present in `old-policies/` (ones you've inventoried),
  read straight from those files' `policyId`.
- Per-policy failures are non-fatal; deleted ids are logged to
  `old-policies/deleted-policies.json`.

The tenant must then be migrated to UAP **before** stage 4 — UAP policies cannot
be created until it is.

## Files

- `pull.py` — stage 1: list + fetch legacy SIA policies to `old-policies/`.
- `mappings.py` — static lookup tables (day map, provider map, defaults).
- `transform.py` — pure old→new transform (no I/O).
- `principals.py` — resolver interface + placeholder + Identity implementations.
- `convert.py` — stage 2 CLI: read dir, drop/split, write files + manifest.
- `delete.py` — stage 3: delete inventoried SIA policies (dry-run by default).
- `post.py` — stage 4: bulk/targeted create with merge-safe id logging.

## Tests

```bash
python3 -m pytest tests/ -q          # uses fake sessions; no tenant needed
```

## Validation status

- **VM `targets`/`principals`/`behavior` shapes**: validated against a live VM
  policy and confirmed by POSTing converted policies and reading them back.
- Confirmed live on create: `status` required; hours are `HH:MM` (not
  `HH:MM:SS`); each policy needs ≥1 principal; role principals null their source
  fields, users/groups populate them; RDP keeps both ephemeral keys (unused =
  null); full-day windows use explicit null `fromHour`/`toHour`.
- `pull.py` is unit-tested against the documented SIA response shapes but has
  **not** been run against a live SIA tenant yet — verify auth/pagination there.

## Things to verify before bulk go-live

1. **`pull.py`** against a live SIA tenant (auth header + list pagination).
2. **Identity queries** in `IdentityResolver` for your tenant/version.
3. The empty-IP `WILDCARD` rule in `policy3` and any flagged warnings.
