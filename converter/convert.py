"""CLI: convert every old policy in a directory into UAP policy files.

  python -m converter.convert \
      --old-dir old-policies --new-dir new-policies

By default principal ids are emitted as <lookup:...> placeholders. The
Identity-API-backed resolver is wired in IdentityResolver (principals.py);
pass --resolve once you have a session to enable it.

Drops Draft policies, splits multi-rule policies, and writes a
principals-manifest.json listing every unique principal that needs an id.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .mappings import STATUS_DROP
from .principals import IdentityResolver, IdentitySession, PlaceholderResolver
from .transform import ConversionError, convert_policy


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    old_dir = Path(args.old_dir)
    new_dir = Path(args.new_dir)
    if not old_dir.is_dir():
        print(f"error: old-dir not found: {old_dir}", file=sys.stderr)
        return 2
    new_dir.mkdir(parents=True, exist_ok=True)

    resolver = _build_resolver(args)

    written = 0
    skipped: list[str] = []
    all_warnings: list[str] = []
    manifest: dict[str, dict] = {}

    for path in sorted(old_dir.glob("*.json")):
        try:
            old = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            print(f"skip {path.name}: invalid JSON ({exc})", file=sys.stderr)
            skipped.append(f"{path.name} (invalid JSON)")
            continue

        if (old.get("status") or "") == STATUS_DROP:
            print(f"drop {path.name}: status={STATUS_DROP}")
            skipped.append(f"{path.name} (Draft)")
            continue

        try:
            results = convert_policy(
                old, resolver, path.stem, drop_unresolved=args.drop_unresolved
            )
        except ConversionError as exc:
            print(f"skip {path.name}: {exc}", file=sys.stderr)
            skipped.append(f"{path.name} ({exc})")
            continue

        _collect_manifest(manifest, old)

        for result in results:
            out_path = new_dir / f"{result.suggested_filename_stem}.json"
            out_path.write_text(json.dumps(result.policy, indent=2) + "\n")
            written += 1
            label = (
                path.name
                if len(results) == 1
                else f"{path.name} -> {out_path.name}"
            )
            for warning in result.warnings:
                all_warnings.append(f"{label}: {warning}")

    manifest_path = new_dir / "principals-manifest.json"
    manifest_path.write_text(
        json.dumps(sorted(manifest.values(), key=lambda p: (p["type"], p["name"])), indent=2)
        + "\n"
    )

    _print_summary(written, skipped, all_warnings, manifest, manifest_path)
    return 0


def _identity_url(args) -> str | None:
    """Identity API base URL, from explicit --identity-url or --identity-tenant.

    Note: the Identity login tenant (e.g. used in <tenant>.id.cyberark.cloud)
    can differ from the service subdomain, so it is its own option.
    """
    if args.identity_url:
        return args.identity_url
    if args.identity_tenant:
        return f"https://{args.identity_tenant}.id.cyberark.cloud"
    return None


def _build_resolver(args):
    if not args.resolve:
        return PlaceholderResolver()
    identity_url = _identity_url(args)
    if not identity_url:
        print(
            "error: --resolve requires --identity-tenant or --identity-url",
            file=sys.stderr,
        )
        raise SystemExit(2)
    token_path = Path(args.token)
    if not token_path.is_file():
        print(f"error: token file not found: {token_path}", file=sys.stderr)
        raise SystemExit(2)
    token = token_path.read_text().strip()
    print(f"resolving principals via {identity_url}")
    return IdentityResolver(IdentitySession(identity_url, token))


def _collect_manifest(manifest: dict, old: dict) -> None:
    for rule in old.get("userAccessRules") or []:
        data = rule.get("userData") or {}
        for role in data.get("roles") or []:
            name = role.get("name") if isinstance(role, dict) else role
            manifest.setdefault(("ROLE", name, None), {"type": "ROLE", "name": name, "source": None})
        for group in data.get("groups") or []:
            key = ("GROUP", group.get("name"), group.get("source"))
            manifest.setdefault(key, {"type": "GROUP", "name": group.get("name"), "source": group.get("source")})
        for user in data.get("users") or []:
            key = ("USER", user.get("name"), user.get("source"))
            manifest.setdefault(key, {"type": "USER", "name": user.get("name"), "source": user.get("source")})


def _print_summary(written, skipped, warnings, manifest, manifest_path) -> None:
    print("\n=== conversion summary ===")
    print(f"policies written : {written}")
    print(f"sources skipped  : {len(skipped)}")
    for item in skipped:
        print(f"  - {item}")
    print(f"unique principals: {len(manifest)}  (-> {manifest_path.name})")
    if warnings:
        print(f"warnings         : {len(warnings)}")
        for warning in warnings:
            print(f"  ! {warning}")


def _parse_args(argv):
    parser = argparse.ArgumentParser(description="Convert old DPA/SIA policies to UAP.")
    parser.add_argument("--old-dir", default="old-policies")
    parser.add_argument("--new-dir", default="new-policies")
    parser.add_argument(
        "--resolve",
        action="store_true",
        help="resolve principal ids via the Identity API",
    )
    parser.add_argument(
        "--token",
        default="token",
        help="path to a file containing the bearer token (default: token)",
    )
    parser.add_argument(
        "--identity-tenant",
        help="Identity login tenant; builds https://<tenant>.id.cyberark.cloud",
    )
    parser.add_argument(
        "--identity-url",
        help="explicit Identity API base URL (overrides --identity-tenant)",
    )
    parser.add_argument(
        "--drop-unresolved",
        action="store_true",
        help="omit principals whose id could not be resolved (instead of placeholders)",
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    raise SystemExit(main())
