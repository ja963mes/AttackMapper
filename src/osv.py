import json
import urllib.request
import urllib.error

def extract_ids(response):
    id_list = []


    for vuln in response.get("vulns",  []):
        id_list.append(vuln["id"])

    return id_list

def fetch_osv(name, version):
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

def fetch_vuln(vuln_id):
    url = "https://api.osv.dev/v1/vulns/"+vuln_id
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise                

def query_osv(name, version):
    return extract_ids(fetch_osv(name, version))

def extract_cwes(record):
    return record.get("database_specific", {}).get("cwe_ids", [])