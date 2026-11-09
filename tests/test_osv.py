import json
from pathlib import Path

import osv
from osv import extract_cwes, extract_ids, fetch_osv, fetch_vuln, records_by_id, resolve_cwes

FIXTURE = Path(__file__).parent / "fixtures" / "osv_django_3.2.0.json"
VULN_FIXTURE = Path(__file__).parent / "fixtures" / "osv_vuln_GHSA-2gwj-7jmv-h26r.json"


def load_fixture():
    with open(FIXTURE, encoding="utf-8") as f:
        return json.load(f)


def load_vuln_fixture():
    with open(VULN_FIXTURE, encoding="utf-8") as f:
        return json.load(f)


def pysec_record():
    """PYSEC-2022-190 has no CWE of its own; its alias GHSA-2gwj-7jmv-h26r does."""
    return records_by_id(load_fixture())["PYSEC-2022-190"]


def no_network(vuln_id):
    raise AssertionError(f"unexpected network lookup for {vuln_id}")


# --- 2.2 / 2.4 ---

def test_extract_ids_from_django_fixture():
    ids = extract_ids(load_fixture())
    assert "GHSA-2gwj-7jmv-h26r" in ids
    assert "PYSEC-2022-190" in ids
    assert len(ids) == 66


def test_extract_ids_no_vulnerabilities():
    assert extract_ids({}) == []


def test_extract_cwes_from_ghsa_record():
    assert extract_cwes(load_vuln_fixture()) == ["CWE-89"]


def test_extract_cwes_missing():
    assert extract_cwes({}) == []


# --- 2.5 alias fallback ---

def test_resolve_cwes_uses_own_cwes_first():
    assert resolve_cwes(load_vuln_fixture(), fetch=no_network) == ["CWE-89"]


def test_resolve_cwes_through_alias_fetch():
    looked_up = []

    def fake_fetch(vuln_id):
        looked_up.append(vuln_id)
        return load_vuln_fixture()

    assert resolve_cwes(pysec_record(), fetch=fake_fetch) == ["CWE-89"]
    assert looked_up == ["GHSA-2gwj-7jmv-h26r"]


def test_resolve_cwes_through_alias_already_known():
    known = records_by_id(load_fixture())
    assert resolve_cwes(pysec_record(), known=known, fetch=no_network) == ["CWE-89"]


def test_resolve_cwes_alias_not_found():
    assert resolve_cwes(pysec_record(), fetch=lambda vuln_id: None) == []


def test_resolve_cwes_no_ghsa_alias():
    record = {"id": "PYSEC-0000-0", "aliases": ["CVE-0000-0000"]}
    assert resolve_cwes(record, fetch=no_network) == []


# --- 2.6 cache ---

def test_fetch_osv_second_call_uses_cache(tmp_path, monkeypatch):
    calls = []

    def fake_post(name, version):
        calls.append((name, version))
        return load_fixture()

    monkeypatch.setattr(osv, "_post_query", fake_post)

    first = fetch_osv("django", "3.2.0", cache_dir=tmp_path)
    second = fetch_osv("django", "3.2.0", cache_dir=tmp_path)

    assert calls == [("django", "3.2.0")]  # only the first call hit the "network"
    assert first == second


def test_fetch_vuln_caches_not_found(tmp_path, monkeypatch):
    calls = []

    def fake_get(vuln_id):
        calls.append(vuln_id)
        return None

    monkeypatch.setattr(osv, "_get_vuln", fake_get)

    assert fetch_vuln("GHSA-xxxx-xxxx-xxxx", cache_dir=tmp_path) is None
    assert fetch_vuln("GHSA-xxxx-xxxx-xxxx", cache_dir=tmp_path) is None
    assert calls == ["GHSA-xxxx-xxxx-xxxx"]
