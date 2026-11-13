def technique_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None

def build_technique_lookup(strix):
    lookup = {}
    for obj in strix["objects"]:
        if obj["type"] != 'attack-pattern':
            continue
        tid = technique_id(obj)
        if tid is None:
            continue
        tactics =[]
        for phase in obj.get("kill_chain_phases", []):
            tactics.append(phase["phase_name"])
        lookup[tid] = {"name": obj["name"], "tactics": tactics}
    return lookup