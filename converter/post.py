"""Bulk-create converted UAP policies on the tenant.

  python3 -m converter.post --new-dir new-policies --token token \
      --tenant <tenant> --delete-id <id> ...

POSTs every new-policies/policy*.json, records each new policyId to
created-policies.json (for traceability / rollback), and prints a per-file
result. Optionally deletes ids first (used to clear earlier test policies so
re-running doesn't create duplicates). stdlib only.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path


def _request(method: str, url: str, token: str, payload: dict | None = None):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
            body = response.read().decode("utf-8")
            return response.status, (json.loads(body) if body else {})
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8")
        try:
            return error.code, json.loads(body)
        except json.JSONDecodeError:
            return error.code, {"raw": body}


def _base_url(args) -> str | None:
    """UAP API base, from explicit --base-url or the service subdomain."""
    if args.base_url:
        return args.base_url
    if args.tenant:
        return f"https://{args.tenant}.uap.cyberark.cloud"
    return None


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    base_url = _base_url(args)
    if not base_url:
        print("error: provide --tenant or --base-url", file=sys.stderr)
        return 2
    token = Path(args.token).read_text().strip()
    base = base_url.rstrip("/") + "/api/policies"

    for policy_id in args.delete_id:
        status, _ = _request("DELETE", f"{base}/{policy_id}", token)
        print(f"delete {policy_id}: HTTP {status}")

    if args.files:
        files = [Path(f) for f in args.files]
    else:
        skip = {"principals-manifest.json", "created-policies.json"}
        files = sorted(
            p for p in Path(args.new_dir).glob("*.json") if p.name not in skip
        )
    created: list[dict] = []
    failed: list[dict] = []
    for path in files:
        policy = json.loads(path.read_text())
        status, resp = _request("POST", base, token, policy)
        policy_id = resp.get("policyId") if isinstance(resp, dict) else None
        if status == 200 and policy_id:
            created.append({"file": path.name, "policyId": policy_id})
            print(f"OK   {path.name} -> {policy_id}")
        else:
            detail = resp.get("description") or resp.get("message") or resp
            failed.append({"file": path.name, "status": status, "error": detail})
            print(f"FAIL {path.name} -> HTTP {status}: {detail}")

    # Merge into the log (keyed by file) so partial/targeted runs don't clobber
    # ids from earlier runs.
    log_path = Path(args.new_dir) / "created-policies.json"
    merged = {}
    if log_path.is_file():
        for entry in json.loads(log_path.read_text()):
            merged[entry["file"]] = entry
    for entry in created:
        merged[entry["file"]] = entry
    log_path.write_text(
        json.dumps(sorted(merged.values(), key=lambda e: e["file"]), indent=2) + "\n"
    )

    print(f"\n=== {len(created)}/{len(files)} created; {len(failed)} failed ===")
    print(f"created ids logged to {log_path}")
    if failed:
        print("failures:")
        for item in failed:
            print(f"  - {item['file']}: HTTP {item['status']} {item['error']}")
    return 0 if not failed else 1


def _parse_args(argv):
    parser = argparse.ArgumentParser(description="Bulk-create UAP policies.")
    parser.add_argument(
        "files",
        nargs="*",
        help="specific policy files to post (default: all in --new-dir)",
    )
    parser.add_argument("--new-dir", default="new-policies")
    parser.add_argument("--token", default="token")
    parser.add_argument(
        "--tenant",
        help="service subdomain; builds https://<tenant>.uap.cyberark.cloud",
    )
    parser.add_argument(
        "--base-url",
        help="explicit UAP API base URL (overrides --tenant)",
    )
    parser.add_argument(
        "--delete-id",
        action="append",
        default=[],
        help="policy id to delete before posting (repeatable)",
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    raise SystemExit(main())
