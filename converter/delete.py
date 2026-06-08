"""Decommission stage: delete legacy SIA policies after they're inventoried.

DESTRUCTIVE. Run this only once `old-policies/` holds the full inventory (from
`converter.pull`) and you're ready to switch the tenant to UAP. To stay safe it
deletes ONLY the policies present in old-policies/ — i.e. ones you've already
backed up locally — via DELETE /api/access-policies/{id} on the SIA JIT API.

Dry-run by default; pass --confirm to actually delete.

  python3 -m converter.delete --tenant <tenant> --token token            # dry run
  python3 -m converter.delete --tenant <tenant> --token token --confirm  # delete

The HTTP layer is injectable (see Session) so the logic is testable offline.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from .pull import SiaSession, _base_url

# Sidecar logs that may live alongside the pulled policies — never delete these.
SKIP_FILES = {
    "created-policies.json",
    "principals-manifest.json",
    "deleted-policies.json",
}
_DELETE_OK = {200, 202, 204}


class Session(Protocol):
    def delete(self, path: str) -> int: ...


@dataclass(frozen=True)
class DeleteReport:
    deleted: list[dict] = field(default_factory=list)
    failed: list[dict] = field(default_factory=list)


def collect_targets(old_dir: Path) -> list[dict]:
    """Read pulled policy files and return their {policyId, name, file}."""
    targets: list[dict] = []
    for path in sorted(old_dir.glob("*.json")):
        if path.name in SKIP_FILES:
            continue
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue
        policy_id = data.get("policyId")
        if policy_id:
            targets.append(
                {"policyId": policy_id, "name": data.get("policyName"), "file": path.name}
            )
    return targets


def delete_policies(session: Session, targets: list[dict]) -> DeleteReport:
    """DELETE each target; collect successes and failures (never raises)."""
    deleted: list[dict] = []
    failed: list[dict] = []
    for target in targets:
        status = session.delete(f"/api/access-policies/{target['policyId']}")
        if status in _DELETE_OK:
            deleted.append(target)
        else:
            failed.append({**target, "status": status})
    return DeleteReport(deleted=deleted, failed=failed)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    base = _base_url(args)
    if not base:
        print("error: provide --tenant or --base-url", file=sys.stderr)
        return 2

    old_dir = Path(args.old_dir)
    if not old_dir.is_dir():
        print(f"error: old-dir not found: {old_dir}", file=sys.stderr)
        return 2

    targets = collect_targets(old_dir)
    if not targets:
        print(f"no inventoried policies with a policyId in {old_dir}; nothing to delete.")
        return 0

    print(f"found {len(targets)} inventoried policies in {old_dir}/:")
    for target in targets:
        print(f"  - {target['policyId']}  {target.get('name') or ''}")

    if not args.confirm:
        print(
            f"\nDRY RUN — nothing deleted. Re-run with --confirm to DELETE these "
            f"{len(targets)} policies from {base}."
        )
        return 0

    token_path = Path(args.token)
    if not token_path.is_file():
        print(f"error: token file not found: {token_path}", file=sys.stderr)
        return 2

    session = SiaSession(base, token_path.read_text().strip())
    print(f"\ndeleting {len(targets)} policies from {base} ...")
    report = delete_policies(session, targets)

    log_path = old_dir / "deleted-policies.json"
    log_path.write_text(json.dumps(report.deleted, indent=2) + "\n")

    print(f"\n=== deleted {len(report.deleted)}/{len(targets)}; failed {len(report.failed)} ===")
    print(f"deleted ids logged to {log_path}")
    for item in report.failed:
        print(f"  FAIL {item['policyId']} ({item.get('name')}) -> HTTP {item['status']}")
    return 0 if not report.failed else 1


def _parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Delete legacy SIA policies after they have been inventoried."
    )
    parser.add_argument("--old-dir", default="old-policies")
    parser.add_argument("--token", default="token")
    parser.add_argument(
        "--tenant",
        help="service subdomain; builds https://<tenant>-jit.cyberark.cloud",
    )
    parser.add_argument(
        "--base-url",
        help="explicit SIA JIT base URL (overrides --tenant)",
    )
    parser.add_argument(
        "--confirm",
        action="store_true",
        help="actually delete (default: dry run, no changes)",
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    raise SystemExit(main())
