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

def parse_attack_ids(text):
    ids = []
    elements = text.split("::")
    for ele in elements:
        parts = ele.split(":")
        if len(parts) > 3 and parts[1] == "ATTACK" and parts[2] == "ENTRY ID":
            ids.append("T"+parts[3])
    return ids

def build_capec_to_attack(csv_path):
    mapping = {}
    with open(csv_path, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            ids = parse_attack_ids(row["Taxonomy Mappings"])
            if ids:
                mapping["CAPEC-" + row["'ID"]] = ids
    return mapping
