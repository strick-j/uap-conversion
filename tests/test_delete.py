"""Tests for converter.delete using a fake session (no live tenant needed)."""

import json

import pytest

import converter.delete as delete_mod
from converter.delete import collect_targets, delete_policies


def _write_policy(directory, filename, policy_id, name="P"):
    body = {"policyId": policy_id, "policyName": name}
    (directory / filename).write_text(json.dumps(body))


class FakeSession:
    def __init__(self, fail_ids=()):
        self._fail = set(fail_ids)
        self.deleted_paths = []

    def delete(self, path):
        self.deleted_paths.append(path)
        policy_id = path.rsplit("/", 1)[1]
        return 500 if policy_id in self._fail else 204


@pytest.mark.unit
def test_collect_targets_reads_ids_and_skips_logs(tmp_path):
    _write_policy(tmp_path, "a.json", "id-a", "Alpha")
    _write_policy(tmp_path, "b.json", "id-b", "Beta")
    (tmp_path / "created-policies.json").write_text("[]")  # sidecar, must be skipped
    (tmp_path / "bad.json").write_text("{not json")  # unparseable, skipped

    targets = collect_targets(tmp_path)
    ids = sorted(t["policyId"] for t in targets)
    assert ids == ["id-a", "id-b"]


@pytest.mark.unit
def test_delete_policies_calls_endpoint_per_target(tmp_path):
    session = FakeSession()
    targets = [{"policyId": "id-a", "name": "Alpha", "file": "a.json"}]
    report = delete_policies(session, targets)
    assert session.deleted_paths == ["/api/access-policies/id-a"]
    assert len(report.deleted) == 1
    assert not report.failed


@pytest.mark.unit
def test_delete_policies_records_failures(tmp_path):
    session = FakeSession(fail_ids={"id-b"})
    targets = [
        {"policyId": "id-a", "name": "A", "file": "a.json"},
        {"policyId": "id-b", "name": "B", "file": "b.json"},
    ]
    report = delete_policies(session, targets)
    assert [d["policyId"] for d in report.deleted] == ["id-a"]
    assert report.failed[0]["policyId"] == "id-b"
    assert report.failed[0]["status"] == 500


@pytest.mark.unit
def test_main_dry_run_does_not_delete(tmp_path, monkeypatch, capsys):
    _write_policy(tmp_path, "a.json", "id-a")
    called = {"n": 0}

    def boom(*_a, **_k):  # SiaSession must never be constructed in a dry run
        called["n"] += 1
        raise AssertionError("network in dry run")

    monkeypatch.setattr(delete_mod, "SiaSession", boom)
    rc = delete_mod.main(["--tenant", "acme", "--old-dir", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "DRY RUN" in out
    assert called["n"] == 0
    assert not (tmp_path / "deleted-policies.json").exists()


@pytest.mark.unit
def test_main_confirm_deletes_and_logs(tmp_path, monkeypatch):
    _write_policy(tmp_path, "a.json", "id-a", "Alpha")
    _write_policy(tmp_path, "b.json", "id-b", "Beta")
    token = tmp_path / "token"
    token.write_text("tok")
    monkeypatch.setattr(delete_mod, "SiaSession", lambda base, tok: FakeSession())

    rc = delete_mod.main(
        ["--tenant", "acme", "--old-dir", str(tmp_path), "--token", str(token), "--confirm"]
    )
    assert rc == 0
    logged = json.loads((tmp_path / "deleted-policies.json").read_text())
    assert sorted(e["policyId"] for e in logged) == ["id-a", "id-b"]


@pytest.mark.unit
def test_main_requires_target(tmp_path):
    assert delete_mod.main(["--old-dir", str(tmp_path)]) == 2


@pytest.mark.unit
def test_main_nothing_to_delete(tmp_path, capsys):
    rc = delete_mod.main(["--tenant", "acme", "--old-dir", str(tmp_path)])
    assert rc == 0
    assert "nothing to delete" in capsys.readouterr().out
