"""Tests for converter.pull using fake sessions (no live tenant needed).

Sample payloads mirror the real SIA list/detail responses provided by the API.
"""

import json

import pytest

from converter.pull import PullReport, _slug, fetch_policy_list, pull

LIST_PAYLOAD = {
    "items": [
        {
            "policyId": "ffd2a745-3a90-40d9-bbc5-220ac00129da",
            "policyName": "Vandelay Server SSH UPN Access",
            "status": "Enabled",
            "platforms": ["OnPrem"],
            "ruleNames": ["George - Domain Access"],
        },
        {
            "policyId": "c50f982a-cb3a-47b6-8ad0-f551bb31836b",
            "policyName": "735280068473 - Infamous DevOps",
            "status": "Enabled",
            "platforms": ["AWS"],
            "ruleNames": ["EL EC2", "Ubuntu EC2", "Windows EC2"],
        },
    ],
    "totalCount": 2,
}

DETAIL = {
    "ffd2a745-3a90-40d9-bbc5-220ac00129da": {
        "policyId": "ffd2a745-3a90-40d9-bbc5-220ac00129da",
        "policyName": "Vandelay Server SSH UPN Access",
        "status": "Enabled",
        "policyType": "VM",
        "providersData": {"OnPrem": {"fqdnRules": [], "ipRules": []}},
        "userAccessRules": [{"ruleName": "George - Domain Access"}],
        "activationType": "RECURRING",
    },
    "c50f982a-cb3a-47b6-8ad0-f551bb31836b": {
        "policyId": "c50f982a-cb3a-47b6-8ad0-f551bb31836b",
        "policyName": "735280068473 - Infamous DevOps",
        "status": "Enabled",
        "policyType": "VM",
        "providersData": {"AWS": {"accountIds": ["735280068473"]}},
        "userAccessRules": [{"ruleName": "EL EC2"}, {"ruleName": "Ubuntu EC2"}],
        "activationType": "RECURRING",
    },
}


class FakeSession:
    def __init__(self, list_payload, detail, fail_ids=()):
        self._list = list_payload
        self._detail = detail
        self._fail = set(fail_ids)
        self.calls = []

    def get(self, path):
        self.calls.append(path)
        if path == "/api/access-policies":
            return self._list
        # /api/access-policies/{id}?extended=true
        policy_id = path.split("/api/access-policies/")[1].split("?")[0]
        if policy_id in self._fail:
            raise RuntimeError("boom")
        assert path.endswith("?extended=true"), "detail must request extended=true"
        return self._detail[policy_id]


@pytest.mark.unit
def test_fetch_policy_list_returns_items_and_total():
    items, total = fetch_policy_list(FakeSession(LIST_PAYLOAD, DETAIL))
    assert total == 2
    assert [i["policyId"] for i in items] == [
        "ffd2a745-3a90-40d9-bbc5-220ac00129da",
        "c50f982a-cb3a-47b6-8ad0-f551bb31836b",
    ]


@pytest.mark.unit
def test_pull_writes_extended_detail_to_disk(tmp_path):
    session = FakeSession(LIST_PAYLOAD, DETAIL)
    report = pull(session, tmp_path, name_by="name")

    assert isinstance(report, PullReport)
    assert len(report.written) == 2
    assert not report.failed

    # detail endpoints were called with extended=true
    assert any("?extended=true" in c for c in session.calls)

    # files contain the raw old-format detail, not the list summary
    written = sorted(p.name for p in tmp_path.glob("*.json"))
    assert written == [
        "735280068473---Infamous-DevOps.json",
        "Vandelay-Server-SSH-UPN-Access.json",
    ]
    saved = json.loads((tmp_path / "Vandelay-Server-SSH-UPN-Access.json").read_text())
    assert saved["providersData"]["OnPrem"]["fqdnRules"] == []
    assert saved["activationType"] == "RECURRING"


@pytest.mark.unit
def test_pull_name_by_id_uses_policy_id(tmp_path):
    pull(FakeSession(LIST_PAYLOAD, DETAIL), tmp_path, name_by="id")
    assert (tmp_path / "ffd2a745-3a90-40d9-bbc5-220ac00129da.json").exists()


@pytest.mark.unit
def test_pull_continues_when_one_policy_fails(tmp_path):
    session = FakeSession(
        LIST_PAYLOAD, DETAIL, fail_ids={"c50f982a-cb3a-47b6-8ad0-f551bb31836b"}
    )
    report = pull(session, tmp_path, name_by="name")
    assert len(report.written) == 1
    assert len(report.failed) == 1
    assert report.failed[0]["policyId"] == "c50f982a-cb3a-47b6-8ad0-f551bb31836b"


@pytest.mark.unit
def test_pull_deduplicates_colliding_names(tmp_path):
    dupe_list = {
        "items": [
            {"policyId": "id-aaaaaaaa-1", "policyName": "Same Name"},
            {"policyId": "id-bbbbbbbb-2", "policyName": "Same Name"},
        ],
        "totalCount": 2,
    }
    detail = {
        "id-aaaaaaaa-1": {"policyId": "id-aaaaaaaa-1", "policyName": "Same Name"},
        "id-bbbbbbbb-2": {"policyId": "id-bbbbbbbb-2", "policyName": "Same Name"},
    }
    pull(FakeSession(dupe_list, detail), tmp_path, name_by="name")
    names = sorted(p.name for p in tmp_path.glob("*.json"))
    assert names == ["Same-Name-id-bbbbb.json", "Same-Name.json"]


@pytest.mark.unit
def test_slug_sanitizes():
    assert _slug("475601244925 - Corp / Linux!") == "475601244925---Corp-Linux"
    assert _slug("   ") == "policy"


# --- CLI / session boilerplate --------------------------------------------

import converter.pull as pull_mod  # noqa: E402


@pytest.mark.unit
def test_base_url_prefers_explicit_then_tenant():
    ns = pull_mod._parse_args(["--tenant", "acme"])
    assert pull_mod._base_url(ns) == "https://acme-jit.cyberark.cloud"
    ns = pull_mod._parse_args(["--base-url", "https://x.example"])
    assert pull_mod._base_url(ns) == "https://x.example"


@pytest.mark.unit
def test_main_requires_target():
    assert pull_mod.main([]) == 2


@pytest.mark.unit
def test_main_errors_when_token_missing(tmp_path):
    missing = tmp_path / "nope"
    assert pull_mod.main(["--tenant", "x", "--token", str(missing)]) == 2


@pytest.mark.unit
def test_main_happy_path(tmp_path, monkeypatch, capsys):
    token = tmp_path / "token"
    token.write_text("tok")
    monkeypatch.setattr(
        pull_mod, "SiaSession", lambda base, tok: FakeSession(LIST_PAYLOAD, DETAIL)
    )
    rc = pull_mod.main(
        ["--tenant", "acme", "--token", str(token), "--out-dir", str(tmp_path)]
    )
    assert rc == 0
    assert (tmp_path / "Vandelay-Server-SSH-UPN-Access.json").exists()


@pytest.mark.unit
def test_main_warns_on_count_mismatch(tmp_path, monkeypatch, capsys):
    token = tmp_path / "token"
    token.write_text("tok")
    partial = {"items": LIST_PAYLOAD["items"], "totalCount": 99}
    monkeypatch.setattr(
        pull_mod, "SiaSession", lambda base, tok: FakeSession(partial, DETAIL)
    )
    pull_mod.main(
        ["--tenant", "x", "--token", str(token), "--out-dir", str(tmp_path)]
    )
    assert "totalCount" in capsys.readouterr().err


@pytest.mark.unit
def test_sia_session_get_parses_json(monkeypatch):
    class FakeResp:
        status = 200

        def read(self):
            return b'{"items": [], "totalCount": 0}'

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(
        pull_mod.urllib.request, "urlopen", lambda req, timeout=30: FakeResp()
    )
    session = pull_mod.SiaSession("https://x-jit.cyberark.cloud", "tok")
    assert session.get("/api/access-policies") == {"items": [], "totalCount": 0}
