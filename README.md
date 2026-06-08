# uap-conversion

Migrate legacy **CyberArk SIA / DPA access policies** to the new
**UAP (Access Control Policies)** format — inventory, convert, and create them
on your tenant.

The older SIA "access policies" use a deprecated schema (provider-keyed
`providersData`, multiple `userAccessRules` per policy, principals identified by
name only). UAP uses a single flat policy shape (`metadata` / `policyEntitlement`
/ `conditions` / `targets` / `principals` / `behavior`) with principals
identified by directory id. This tool automates the gap.

> Not affiliated with or endorsed by CyberArk. Use at your own risk; review the
> output before creating policies on a production tenant.

## Pipeline

Three independent stages — run them in order, or stop after `convert` to review:

```bash
# 1. INVENTORY — pull legacy SIA policies into old-policies/
python3 -m converter.pull    --tenant <tenant> --token token

# 2. CONVERT  — old-policies/ -> new-policies/ (UAP format), resolving principals
python3 -m converter.convert --resolve --drop-unresolved \
        --identity-tenant <identity-tenant>

# 3. CREATE   — POST every converted policy to the UAP API
python3 -m converter.post    --tenant <tenant> --token token
```

| Stage | Module | Reads | Writes |
|-------|--------|-------|--------|
| Inventory | `converter.pull` | SIA JIT API | `old-policies/*.json` |
| Convert | `converter.convert` | `old-policies/` (+ Identity API) | `new-policies/*.json` |
| Create | `converter.post` | `new-policies/` | UAP API (+ `created-policies.json` log) |

## What the conversion handles

- Provider → `locationType` (`AWS` / `Azure` / `GCP`, on-prem → `FQDN/IP`);
  `targetCategory` stays `VM`.
- Multi-rule policies are **split** into one UAP policy per rule.
- Days-of-week names → ints (Sun=0); `fullDays` → explicit null hours; hours
  normalized to `HH:MM`.
- Tags `Key/Value` → `key/value`; `grantAccess` dropped; `maxSessionDuration`
  defaulted; `Draft` policies dropped.
- Principals resolved to directory ids via the Identity API
  (roles → Redrock, users/groups → DirectoryServiceQuery), de-duplicated, with
  unresolved ones optionally omitted (`--drop-unresolved`).

See [converter/README.md](converter/README.md) for the full field-mapping table
and live-validated schema notes.

## Requirements

- Python 3.9+ (standard library only at runtime — no install needed).
- A bearer token for your tenant in a file named `token` (gitignored).
- `pytest` only if you want to run the tests.

## Tenant identifiers

Two values, which may differ:

- **`<tenant>`** — service subdomain, used in `<tenant>.uap.cyberark.cloud`
  (UAP) and `<tenant>-jit.cyberark.cloud` (SIA).
- **`<identity-tenant>`** — Identity login tenant, used in
  `<identity-tenant>.id.cyberark.cloud` (principal resolution).

Each stage also accepts an explicit URL override (`--base-url` /
`--identity-url`) if your endpoints differ from the standard pattern.

## Safety

- `token` and the tenant policy folders (`old-policies/`, `new-policies/`) are
  **gitignored** — your secrets and policy data never get committed.
- `convert` runs offline by default (placeholder principal ids) so you can
  review output before any network calls.
- `post` logs every created policy id to `new-policies/created-policies.json`
  for traceability / rollback.

## Tests

```bash
python3 -m pytest tests/ -q
```

## License

[MIT](LICENSE)
