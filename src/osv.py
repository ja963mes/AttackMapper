import json
import urllib.error
import urllib.request
from pathlib import Path

# Saved API responses live here, relative to the folder you run the tool from.
# Delete this folder to force fresh data from OSV.
CACHE_DIR = Path(".cache") / "osv"


def extract_ids(response):
    id_list = []
    for vuln in response.get("vulns", []):
        id_list.append(vuln["id"])
    return id_list


def extract_cwes(record):
    return record.get("database_specific", {}).get("cwe_ids", [])


def records_by_id(response):
    """Map each record's ID to the record, so aliases can be looked up without the network."""
    return {vuln["id"]: vuln for vuln in response.get("vulns", [])}


def resolve_cwes(record, known=None, fetch=None):
    """Return the record's CWE IDs, borrowing them from a GHSA alias when it has none.

    known: records already in hand (from records_by_id), checked before the network.
    fetch: function that gets a record by ID; defaults to fetch_vuln.
    """
    cwes = extract_cwes(record)
    if cwes:
        return cwes

    known = known or {}
    fetch = fetch or fetch_vuln
    for alias in record.get("aliases", []):
        if not alias.startswith("GHSA-"):
            continue
        alias_record = known.get(alias) or fetch(alias)
        if alias_record:
            cwes = extract_cwes(alias_record)
            if cwes:
                return cwes
    return []


def fetch_osv(name, version, cache_dir=None):
    cache_dir = cache_dir or CACHE_DIR
    cache_file = cache_dir / "query" / f"{name}_{version}.json"
    return _cached(cache_file, lambda: _post_query(name, version))


def fetch_vuln(vuln_id, cache_dir=None):
    """Get one record by ID. Returns None if OSV has no record with that ID."""
    cache_dir = cache_dir or CACHE_DIR
    cache_file = cache_dir / "vulns" / f"{vuln_id}.json"
    return _cached(cache_file, lambda: _get_vuln(vuln_id))


def query_osv(name, version):
    return extract_ids(fetch_osv(name, version))


def _cached(cache_file, fetch):
    """Return the response saved in cache_file, or call fetch() and save what it returns."""
    if cache_file.exists():
        with open(cache_file, encoding="utf-8") as f:
            return json.load(f)

    data = fetch()

    # Write to a temporary file first, then rename it, so a crash halfway
    # through never leaves a broken cache file behind.
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    tmp_file = cache_file.with_suffix(".tmp")
    with open(tmp_file, "w", encoding="utf-8") as f:
        json.dump(data, f)
    tmp_file.replace(cache_file)
    return data


def _post_query(name, version):
    body = {
        "package": {"name": name, "ecosystem": "PyPI"},
        "version": version,
    }
    data = json.dumps(body).encode("utf-8")
    request = urllib.request.Request(
        "https://api.osv.dev/v1/query",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def _get_vuln(vuln_id):
    url = "https://api.osv.dev/v1/vulns/" + vuln_id
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise
