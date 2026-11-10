import json
import csv

def parse_related_weaknesses(text):
    ele = text.split("::")
    filtered_ele = [item for item in ele if item != ""]
    for i in range(len(filtered_ele)):
        filtered_ele[i] = "CWE-"+ filtered_ele[i]
    return filtered_ele    


def build_cwe_to_capec(csv_path):
    mapping = {}
    with open(csv_path, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            capec_id = "CAPEC-"+row["'ID"]
            for cwe in parse_related_weaknesses(row["Related Weaknesses"]):
                mapping.setdefault(cwe, []).append(capec_id)
    return mapping

def save_json(data, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
