"""Inventory + retrieval: pull legacy SIA access policies into old-policies/.

Step 1 of the migration. Lists policies from SIA, then fetches each one in full
(extended) and writes the raw old-format JSON to disk - exactly the shape the
converter (convert.py) consumes.

  python3 -m converter.pull --tenant <tenant> --token token --out-dir old-policies

Endpoints (SIA / DPA JIT API):
  GET /api/access-policies                       -> { items: [...], totalCount }
  GET /api/access-policies/{id}?extended=true    -> full policy (old format)

The HTTP layer is injectable (see SiaSession) so the orchestration is testable
without a live tenant.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol


class Session(Protocol):
    def get(self, path: str) -> dict: ...


@dataclass(frozen=True)
class PullReport:
    total_count: int
    listed: int
    written: list[str] = field(default_factory=list)
    failed: list[dict] = field(default_factory=list)


def fetch_policy_list(session: Session) -> tuple[list[dict], int]:
    """Return (items, totalCount) from the access-policies list endpoint."""
    payload = session.get("/api/access-policies") or {}
    items = payload.get("items") or []
    total = payload.get("totalCount", len(items))
    return items, total


def fetch_policy(session: Session, policy_id: str) -> dict:
    """Return one policy in full (extended) old format."""
    return session.get(f"/api/access-policies/{policy_id}?extended=true")


def pull(session: Session, out_dir: Path, name_by: str = "name") -> PullReport:
    """Fetch every policy and write it to out_dir as raw old-format JSON."""
    items, total = fetch_policy_list(session)
    out_dir.mkdir(parents=True, exist_ok=True)

    written: list[str] = []
    failed: list[dict] = []
    used_names: set[str] = set()

    for item in items:
        policy_id = item.get("policyId")
        if not policy_id:
            failed.append({"policyId": None, "error": "list item missing policyId"})
            continue
        try:
            policy = fetch_policy(session, policy_id)
        except Exception as exc:  # one bad policy must not abort the inventory
            failed.append({"policyId": policy_id, "error": str(exc)})
            continue

        filename = _filename(item, policy, name_by, used_names)
        (out_dir / filename).write_text(json.dumps(policy, indent=2) + "\n")
        written.append(filename)

    return PullReport(total_count=total, listed=len(items), written=written, failed=failed)


def _filename(item: dict, policy: dict, name_by: str, used: set[str]) -> str:
    """Build a unique, filesystem-safe filename for a policy."""
    policy_id = item.get("policyId") or policy.get("policyId") or "policy"
    if name_by == "id":
        stem = policy_id
    else:
        raw = item.get("policyName") or policy.get("policyName") or policy_id
        stem = _slug(raw)

    candidate = f"{stem}.json"
    if candidate in used:  # disambiguate collisions with a short id fragment
        candidate = f"{stem}-{str(policy_id)[:8]}.json"
    used.add(candidate)
    return candidate


def _slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-.")
    return slug or "policy"


# --- live HTTP session -----------------------------------------------------


class SiaSession:
    """Authenticated GET client for the SIA JIT API (stdlib only)."""

    def __init__(self, base_url: str, token: str) -> None:
        self._base = base_url.rstrip("/")
        self._token = token

    def get(self, path: str) -> dict:
        request = urllib.request.Request(
            self._base + path,
            method="GET",
            headers={
                "Authorization": f"Bearer {self._token}",
                "Accept": "application/json",
            },
        )
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
            body = response.read().decode("utf-8")
            return json.loads(body) if body else {}


def _base_url(args) -> str:
    if args.base_url:
        return args.base_url
    return f"https://{args.tenant}-jit.cyberark.cloud"


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if not args.tenant and not args.base_url:
        print("error: provide --tenant or --base-url", file=sys.stderr)
        return 2

    token_path = Path(args.token)
    if not token_path.is_file():
        print(f"error: token file not found: {token_path}", file=sys.stderr)
        return 2

    session = SiaSession(_base_url(args), token_path.read_text().strip())
    print(f"pulling policies from {_base_url(args)}/api/access-policies")

    try:
        report = pull(session, Path(args.out_dir), name_by=args.name_by)
    except urllib.error.HTTPError as exc:
        print(f"error: list request failed: HTTP {exc.code}", file=sys.stderr)
        return 1

    print(f"\n=== pulled {len(report.written)}/{report.total_count} policies ===")
    print(f"listed: {report.listed} | totalCount: {report.total_count}")
    if report.listed != report.total_count:
        print(
            f"  ! listed ({report.listed}) != totalCount ({report.total_count}); "
            "the list may be paginated - check the API for paging params.",
            file=sys.stderr,
        )
    print(f"written to {args.out_dir}: {len(report.written)}")
    if report.failed:
        print(f"failed: {len(report.failed)}")
        for item in report.failed:
            print(f"  - {item['policyId']}: {item['error']}")
    return 0 if not report.failed else 1


def _parse_args(argv):
    parser = argparse.ArgumentParser(description="Pull legacy SIA policies to disk.")
    parser.add_argument(
        "--tenant",
        help="service subdomain; builds https://<tenant>-jit.cyberark.cloud",
    )
    parser.add_argument("--base-url", help="override full base URL")
    parser.add_argument("--token", default="token", help="bearer token file")
    parser.add_argument("--out-dir", default="old-policies")
    parser.add_argument(
        "--name-by",
        choices=["name", "id"],
        default="name",
        help="filename source: sanitized policyName (default) or policyId",
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    raise SystemExit(main())
