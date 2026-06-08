"""Pure old DPA/SIA -> new UAP transform. No I/O, no network, no mutation.

convert_policy() takes one parsed old-format policy and returns a list of new
UAP policy dicts: one per old userAccessRule (multi-rule policies fan out into
several single-rule UAP policies). Draft policies must be filtered out by the
caller before calling this.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from .mappings import (
    ACTIVATION_TO_POLICY_TYPE,
    DAY_NAME_TO_INT,
    DEFAULT_MAX_SESSION_DURATION_HOURS,
    DELEGATION_DEFAULT,
    PRINCIPAL_TYPE_GROUP,
    PRINCIPAL_TYPE_ROLE,
    PRINCIPAL_TYPE_USER,
    PROVIDER_TO_LOCATION_TYPE,
    TARGET_CATEGORY_VM,
)
from .principals import PrincipalRef, Resolver


@dataclass(frozen=True)
class ConversionResult:
    """One produced UAP policy plus the source rule it came from."""

    suggested_filename_stem: str
    policy: dict
    warnings: tuple[str, ...]


class ConversionError(ValueError):
    """Raised when an old policy cannot be faithfully represented in UAP."""


def convert_policy(
    old: dict,
    resolver: Resolver,
    source_stem: str,
    drop_unresolved: bool = False,
) -> list[ConversionResult]:
    """Convert one old policy into one UAP policy per access rule.

    When drop_unresolved is True, principals whose id could not be resolved are
    omitted (with a warning) instead of emitted as placeholders.
    """
    provider_key, providers = _single_provider(old)
    location_type = PROVIDER_TO_LOCATION_TYPE[provider_key]
    targets, target_warnings = _build_targets(provider_key, providers)

    rules = old.get("userAccessRules") or []
    if not rules:
        raise ConversionError(f"{source_stem}: policy has no userAccessRules")

    multi = len(rules) > 1
    results: list[ConversionResult] = []
    for index, rule in enumerate(rules):
        warnings: list[str] = list(target_warnings)
        conn = rule.get("connectionInformation") or {}

        metadata = _build_metadata(old, location_type, conn, rule, multi)
        conditions = _build_conditions(conn)
        principals, p_warnings = _build_principals(
            rule.get("userData") or {}, resolver, drop_unresolved
        )
        warnings.extend(p_warnings)
        behavior = _build_behavior(conn.get("connectAs") or {})

        policy = {
            "metadata": metadata,
            "conditions": conditions,
            "targets": targets,
            "principals": principals,
            "delegationClassification": DELEGATION_DEFAULT,
        }
        if behavior is not None:
            policy["behavior"] = behavior

        stem = source_stem
        if multi:
            stem = f"{source_stem}-{index + 1}-{_slug(rule.get('ruleName', f'rule{index + 1}'))}"
        results.append(ConversionResult(stem, policy, tuple(warnings)))

    return results


# --- metadata --------------------------------------------------------------

def _build_metadata(
    old: dict, location_type: str, conn: dict, rule: dict, multi: bool
) -> dict:
    name = old.get("policyName") or "Unnamed policy"
    if multi:
        rule_name = rule.get("ruleName")
        if rule_name:
            name = f"{name} - {rule_name}"

    return {
        "name": name,
        "description": old.get("description") or "",
        # status is REQUIRED on create (confirmed by a live 400). Old Enabled
        # policies map to Active; Draft policies are dropped before conversion.
        "status": {"status": "Active"},
        "timeFrame": {
            "fromTime": old.get("startDate"),
            "toTime": old.get("endDate"),
        },
        "policyEntitlement": {
            "targetCategory": TARGET_CATEGORY_VM,
            "locationType": location_type,
            "policyType": ACTIVATION_TO_POLICY_TYPE.get(
                old.get("activationType", "RECURRING"), "Recurring"
            ),
        },
        "policyTags": [],
        # Old timeZone lived per-rule; UAP keeps one on metadata. With the
        # multi-rule split each produced policy carries its own rule's zone.
        "timeZone": conn.get("timeZone") or "GMT",
    }


# --- conditions ------------------------------------------------------------

def _build_conditions(conn: dict) -> dict:
    # fullDays -> hours are explicit null (matches the live API's stored form).
    if conn.get("fullDays"):
        from_hour, to_hour = None, None
    else:
        from_hour = _hms(conn.get("hoursFrom"))
        to_hour = _hms(conn.get("hoursTo"))
    access_window = {
        "daysOfTheWeek": _days(conn.get("daysOfWeek") or []),
        "fromHour": from_hour,
        "toHour": to_hour,
    }

    conditions = {
        "accessWindow": access_window,
        "maxSessionDuration": DEFAULT_MAX_SESSION_DURATION_HOURS,
    }
    idle = conn.get("idleTime")
    if idle is not None:
        conditions["idleTime"] = idle
    return conditions


def _days(names: list[str]) -> list[int]:
    return sorted({DAY_NAME_TO_INT[n] for n in names if n in DAY_NAME_TO_INT})


def _hms(value: Optional[str]) -> Optional[str]:
    # VM create expects HH:MM ("4 digits", no seconds); old data is already
    # HH:MM, so just normalize away any seconds if present.
    if not value:
        return None
    parts = value.split(":")
    if len(parts) >= 2:
        return f"{parts[0]}:{parts[1]}"
    return value


# --- targets ---------------------------------------------------------------

def _single_provider(old: dict) -> tuple[str, dict]:
    providers = old.get("providersData") or {}
    keys = list(providers.keys())
    if len(keys) != 1:
        raise ConversionError(
            f"expected exactly one provider, found {keys or 'none'}"
        )
    key = keys[0]
    if key not in PROVIDER_TO_LOCATION_TYPE:
        raise ConversionError(f"unsupported provider '{key}'")
    return key, providers[key]


def _build_targets(provider_key: str, data: dict) -> tuple[dict, list[str]]:
    warnings: list[str] = []
    if provider_key == "AWS":
        block = {
            "regions": data.get("regions") or [],
            "tags": _tags(data.get("tags") or []),
            "vpcIds": data.get("vpcIds") or [],
            "accountIds": data.get("accountIds") or [],
        }
        return {"AWS": block}, warnings
    if provider_key == "Azure":
        block = {
            "regions": data.get("regions") or [],
            "tags": _tags(data.get("tags") or []),
            "resourceGroups": data.get("resourceGroups") or [],
            "vnetIds": data.get("vnetIds") or [],
            "subscriptions": data.get("subscriptions") or [],
        }
        return {"Azure": block}, warnings
    if provider_key == "GCP":
        block = {
            "regions": data.get("regions") or [],
            "labels": _tags(data.get("labels") or []),
            "vpcIds": data.get("vpcIds") or [],
            "projects": data.get("projects") or [],
        }
        return {"GCP": block}, warnings
    # OnPrem -> FQDN/IP
    if data.get("logicalNames"):
        warnings.append(
            "OnPrem.logicalNames was non-null; UAP folds logical names into "
            "ipRules[].logicalName - verify these are represented."
        )
    fqdn_rules = [
        {
            "operator": r.get("operator"),
            "computernamePattern": r.get("computernamePattern"),
            "domain": r.get("domain"),
        }
        for r in (data.get("fqdnRules") or [])
    ]
    ip_rules = []
    for r in data.get("ipRules") or []:
        if r.get("operator") == "EXACTLY" and not (r.get("ipAddresses") or []):
            warnings.append(
                f"ipRule '{r.get('logicalName')}' is EXACTLY with no IPs; "
                "UAP requires >=1 IP for EXACTLY - check this rule."
            )
        ip_rules.append(
            {
                "operator": r.get("operator"),
                "ipAddresses": r.get("ipAddresses") or [],
                "logicalName": r.get("logicalName"),
            }
        )
    return {"FQDN/IP": {"fqdnRules": fqdn_rules, "ipRules": ip_rules}}, warnings


def _tags(tags: list[dict]) -> list[dict]:
    """Old tags use Key/Value (capitalized); UAP uses key/value."""
    out = []
    for tag in tags:
        out.append(
            {
                "key": tag.get("Key", tag.get("key")),
                "value": tag.get("Value", tag.get("value")) or [],
            }
        )
    return out


# --- principals ------------------------------------------------------------

def _build_principals(
    user_data: dict, resolver: Resolver, drop_unresolved: bool = False
) -> tuple[list[dict], list[str]]:
    warnings: list[str] = []
    refs: list[PrincipalRef] = []

    for role in user_data.get("roles") or []:
        name = role.get("name") if isinstance(role, dict) else role
        if not isinstance(role, dict):
            warnings.append(f"role '{name}' was a bare string, not an object")
        refs.append(PrincipalRef(name=name, type=PRINCIPAL_TYPE_ROLE, source=None))

    for group in user_data.get("groups") or []:
        refs.append(
            PrincipalRef(
                name=group.get("name"),
                type=PRINCIPAL_TYPE_GROUP,
                source=group.get("source"),
            )
        )

    for user in user_data.get("users") or []:
        refs.append(
            PrincipalRef(
                name=user.get("name"),
                type=PRINCIPAL_TYPE_USER,
                source=user.get("source"),
            )
        )

    principals = []
    seen: set[tuple] = set()
    for ref in refs:
        resolved = resolver.resolve(ref)
        if not resolved.resolved:
            if drop_unresolved:
                warnings.append(f"dropped unresolved {ref.type} '{ref.name}'")
                continue
            warnings.append(f"unresolved principal id for {ref.type} '{ref.name}'")
        entry = resolved.to_uap()
        # The old format could list the same identity twice (e.g. once per
        # source directory); UAP wants each principal once.
        dedupe_key = (entry["type"], entry["id"], entry.get("sourceDirectoryId"))
        if dedupe_key in seen:
            warnings.append(f"dropped duplicate {ref.type} '{ref.name}'")
            continue
        seen.add(dedupe_key)
        principals.append(entry)
    return principals, warnings


# --- behavior / connectAs --------------------------------------------------

def _build_behavior(connect_as: dict) -> Optional[dict]:
    if not connect_as:
        return None
    # Old connectAs is keyed by provider; exactly one key, unwrap it.
    inner = next(iter(connect_as.values()), {}) or {}

    connect = {}
    ssh = inner.get("ssh")
    if isinstance(ssh, str) and ssh:
        connect["ssh"] = {"username": ssh}

    rdp = inner.get("rdp")
    if isinstance(rdp, dict):
        rdp_out = _build_rdp(rdp)
        if rdp_out is not None:
            connect["rdp"] = rdp_out

    if not connect:
        return None
    return {"connectAs": connect}


def _build_rdp(rdp: dict) -> Optional[dict]:
    # The live API stores both keys, with the unused one explicitly null.
    local = rdp.get("localEphemeralUser")
    domain = rdp.get("domainEphemeralUser")
    out = {"localEphemeralUser": None, "domainEphemeralUser": None}
    if local:
        out["localEphemeralUser"] = {
            "assignGroups": local.get("assignGroups") or [],
            "enableEphemeralUserReconnect": bool(
                local.get("enableEphemeralUserReconnect", False)
            ),
        }
    if domain:
        out["domainEphemeralUser"] = {
            "assignGroups": domain.get("assignGroups") or [],
            "enableEphemeralUserReconnect": bool(
                domain.get("enableEphemeralUserReconnect", False)
            ),
            "assignDomainGroups": domain.get("assignDomainGroups") or [],
        }
    if out["localEphemeralUser"] is None and out["domainEphemeralUser"] is None:
        return None
    return out


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", value.strip().lower()).strip("-")
    return slug or "rule"
