"""Static lookup tables for the old DPA/SIA -> new UAP policy conversion.

All values are confirmed against a real tenant sample and the Idira
ark-sdk-python UAP models. Kept in one place so the transform stays a pure
data mapping with no magic strings scattered around.
"""

# Day-of-week: old policies use 3-letter names; UAP uses ints 0-6 with
# Sunday = 0 (confirmed by the tenant owner).
DAY_NAME_TO_INT = {
    "Sun": 0,
    "Mon": 1,
    "Tue": 2,
    "Wed": 3,
    "Thu": 4,
    "Fri": 5,
    "Sat": 6,
}

# Old providersData key -> new metadata.policyEntitlement.locationType.
# targetCategory stays "VM" for every one of these (cloud or on-prem); the
# platform distinction lives entirely in locationType.
PROVIDER_TO_LOCATION_TYPE = {
    "AWS": "AWS",
    "Azure": "Azure",
    "GCP": "GCP",
    "OnPrem": "FQDN/IP",
}

# Old activationType -> new metadata.policyEntitlement.policyType.
ACTIVATION_TO_POLICY_TYPE = {
    "RECURRING": "Recurring",
    "ONDEMAND": "OnDemand",
    "ON_DEMAND": "OnDemand",
}

# Old flat status -> decision: UAP create requests omit status entirely
# (server-managed). "Draft" policies are dropped before conversion.
STATUS_DROP = "Draft"

# UAP principal type tokens are UPPERCASE (confirmed by tenant sample).
PRINCIPAL_TYPE_USER = "USER"
PRINCIPAL_TYPE_GROUP = "GROUP"
PRINCIPAL_TYPE_ROLE = "ROLE"

TARGET_CATEGORY_VM = "VM"
DELEGATION_DEFAULT = "Unrestricted"

# No old equivalent; tenant owner chose 2 hours as the default.
DEFAULT_MAX_SESSION_DURATION_HOURS = 2

# Placeholder tokens emitted when running without live Identity resolution.
def lookup_token(kind: str, value: str) -> str:
    """Return a stable, human-readable placeholder for an unresolved id."""
    return f"<lookup:{kind}:{value}>"
