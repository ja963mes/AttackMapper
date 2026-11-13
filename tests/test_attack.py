from attack import build_technique_lookup


def test_build_technique_lookup():
    stix = {
        "objects": [
            {
                "type": "attack-pattern",
                "name": "Brute Force",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1110"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}
                ],
            },
            {"type": "malware", "name": "Not a technique"},
        ]
    }
    assert build_technique_lookup(stix) == {
        "T1110": {"name": "Brute Force", "tactics": ["credential-access"]}
    }
