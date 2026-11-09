import json
from pathlib import Path

from osv import extract_ids

FIXTURE = Path(__file__).parent / "fixtures" / "osv_django_3.2.0.json"


def load_fixture():
    with open(FIXTURE, encoding="utf-8") as f:
        return json.load(f)


def test_extract_ids_from_django_fixture():
    ids = extract_ids(load_fixture())
    assert "GHSA-2gwj-7jmv-h26r" in ids
    assert "PYSEC-2022-190" in ids
    assert len(ids) == 66

def test_extract_ids_no_vulnerabilities():
    assert extract_ids({}) == []
