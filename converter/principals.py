"""Principal resolution: turn an old (name, type, source) reference into the
(id, sourceDirectoryId) pair the UAP schema requires.

Two implementations:
  * PlaceholderResolver - no network; emits <lookup:...> tokens. Default, so
    the converter always runs and produces reviewable output.
  * IdentityResolver - queries the Idira Identity API. Wire in once you
    have a service-user token. Endpoints are tenant/version specific, so the
    queries are isolated here and easy to adjust.

Both return an immutable ResolvedPrincipal; neither mutates its input.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Protocol

from .mappings import lookup_token


@dataclass(frozen=True)
class PrincipalRef:
    """An old-format principal reference, normalized."""

    name: str
    type: str  # USER | GROUP | ROLE
    source: Optional[str]  # directory display name, None for roles


@dataclass(frozen=True)
class ResolvedPrincipal:
    """A principal ready to drop into UAP principals[]."""

    id: str
    name: str
    type: str
    source_directory_name: Optional[str]
    source_directory_id: Optional[str]
    resolved: bool  # False when ids are still placeholders

    def to_uap(self) -> dict:
        """Render the UAP principals[] entry.

        Source fields are always emitted (null for roles) to match the exact
        shape the live API stores/returns for a VM policy.
        """
        return {
            "id": self.id,
            "name": self.name,
            "sourceDirectoryName": self.source_directory_name,
            "sourceDirectoryId": self.source_directory_id,
            "type": self.type,
        }


class Resolver(Protocol):
    def resolve(self, ref: PrincipalRef) -> ResolvedPrincipal: ...


class PlaceholderResolver:
    """Emits deterministic placeholder ids; never touches the network."""

    def resolve(self, ref: PrincipalRef) -> ResolvedPrincipal:
        is_role = ref.type == "ROLE"
        return ResolvedPrincipal(
            id=lookup_token(ref.type.lower(), ref.name),
            name=ref.name,
            type=ref.type,
            source_directory_name=None if is_role else ref.source,
            source_directory_id=(
                None if is_role else lookup_token("dir", ref.source or "unknown")
            ),
            resolved=False,
        )


@dataclass(frozen=True)
class _Candidate:
    """A directory match for a user/group, from DirectoryServiceQuery."""

    id: str
    dir_id: Optional[str]
    dir_name: Optional[str]
    ds_type: Optional[str]  # "CDS" for cloud directory, "AdProxy" for AD


class IdentityResolver:
    """Resolves principal ids via the Idira Identity API.

    Validated against a live tenant:
      * ROLE  -> Redrock: SELECT ID, Name FROM Role
      * USER  -> DirectoryServiceQuery (user filter on SystemName); federates
                 to AD live, so AD users absent from the Redrock cache resolve.
      * GROUP -> DirectoryServiceQuery (group filter on DisplayName).

    Resolution failures are non-fatal: an unresolved principal degrades to a
    placeholder (resolved=False) so the run continues and the gap is reported.
    """

    def __init__(self, session, cache: Optional[dict] = None) -> None:
        self._session = session
        self._cache = cache if cache is not None else {}
        self._placeholder = PlaceholderResolver()

    def resolve(self, ref: PrincipalRef) -> ResolvedPrincipal:
        key = (ref.type, ref.name, ref.source)
        if key in self._cache:
            return self._cache[key]

        try:
            resolved = self._resolve(ref)
        except Exception:  # network/schema hiccup -> degrade, don't abort
            resolved = None

        result = resolved or self._placeholder.resolve(ref)
        self._cache[key] = result
        return result

    def _resolve(self, ref: PrincipalRef) -> Optional[ResolvedPrincipal]:
        if ref.type == "ROLE":
            rows = self._redrock(
                f"SELECT ID, Name FROM Role WHERE Name = '{_sql_escape(ref.name)}'"
            )
            if not rows:
                return None
            return ResolvedPrincipal(
                id=rows[0]["ID"],
                name=ref.name,
                type=ref.type,
                source_directory_name=None,
                source_directory_id=None,
                resolved=True,
            )

        if ref.type == "USER":
            candidates = self._dsq("user", {"_or": [{"SystemName": ref.name}]})
        else:
            candidates = self._dsq("group", {"_or": [{"DisplayName": ref.name}]})

        pick = _pick_directory(ref.source, candidates)
        if pick is None:
            return None
        return ResolvedPrincipal(
            id=pick.id,
            name=ref.name,
            type=ref.type,
            source_directory_name=pick.dir_name,
            source_directory_id=pick.dir_id,
            resolved=True,
        )

    # --- Identity API wire details (the only tenant-aware code) ------------

    def _dsq(self, kind: str, filt: dict) -> list[_Candidate]:
        import json

        payload = {
            kind: json.dumps(filt),
            "directoryServices": [],
            "Args": {"PageNumber": 1, "PageSize": 10000, "Caching": -1},
        }
        result = (self._session.post("/UserMgmt/DirectoryServiceQuery", payload) or {})
        table = (result.get("Result") or {}).get(kind.capitalize()) or {}
        candidates = []
        for entry in table.get("Results", []):
            row = entry.get("Row", {})
            if row.get("InternalName"):
                candidates.append(
                    _Candidate(
                        id=row["InternalName"],
                        dir_id=row.get("DirectoryServiceUuid"),
                        dir_name=row.get("ServiceInstanceLocalized"),
                        ds_type=row.get("ServiceType"),
                    )
                )
        return candidates

    def _redrock(self, script: str) -> list[dict]:
        result = (self._session.post("/Redrock/query", {"Script": script}) or {})
        rows = (result.get("Result") or {}).get("Results", [])
        return [row.get("Row", row) for row in rows]


def _pick_directory(
    source: Optional[str], candidates: list[_Candidate]
) -> Optional[_Candidate]:
    """Choose the candidate matching the old policy's source directory.

    Old source strings don't always equal live directory names (e.g. a cloud
    alias "CyberArk Cloud Directory" maps to "Idira Cloud Directory"), so match
    by: exact name, then cloud-directory type, then AD domain.
    """
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]

    src = (source or "").strip().lower()
    for cand in candidates:
        if (cand.dir_name or "").strip().lower() == src:
            return cand
    if "cloud directory" in src:
        cloud = [c for c in candidates if c.ds_type == "CDS"]
        if cloud:
            return cloud[0]
    domain = re.search(r"\(([^)]+)\)", source or "")
    if domain:
        needle = domain.group(1).strip().lower()
        for cand in candidates:
            if needle in (cand.dir_name or "").lower():
                return cand
    return candidates[0]  # ambiguous; caller still gets an id


class IdentitySession:
    """Minimal authenticated POST client for the Identity API (stdlib only)."""

    def __init__(self, base_url: str, token: str) -> None:
        self._base = base_url.rstrip("/")
        self._token = token

    def post(self, path: str, payload: dict) -> dict:
        import json
        import urllib.request

        request = urllib.request.Request(
            self._base + path,
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
                "X-IDAP-NATIVE-CLIENT": "true",
            },
        )
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
            return json.loads(response.read())


def _sql_escape(value: str) -> str:
    return value.replace("'", "''")
