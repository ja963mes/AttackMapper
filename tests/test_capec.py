from capec import build_cwe_to_capec, parse_attack_ids, parse_related_weaknesses, build_capec_to_attack

def test_parse_related_weaknesses_capec_49():
    text = "::521::262::263::257::654::307::308::309::"
    assert parse_related_weaknesses(text) == [
        "CWE-521", "CWE-262", "CWE-263", "CWE-257",
        "CWE-654", "CWE-307", "CWE-308", "CWE-309",
    ]


def test_parse_related_weaknesses_empty():
    assert parse_related_weaknesses("") == []

def test_build_cwe_to_capec_inverts_the_mapping(tmp_path):
    sample = tmp_path / "capec.csv"
    sample.write_text(
        "'ID,Name,Related Weaknesses\n"
        "49,Password Brute Forcing,::307::521::\n"
        "16,Dictionary-based Password Attack,::307::\n",
        encoding="utf-8",
    )
    assert build_cwe_to_capec(sample) == {
        "CWE-307": ["CAPEC-49", "CAPEC-16"],
        "CWE-521": ["CAPEC-49"],
    }

def test_parse_attack_ids_capec_49():
    text = "TAXONOMY NAME:ATTACK:ENTRY ID:1110.001:ENTRY NAME:Brute Force:Password Guessing::"
    assert parse_attack_ids(text) == ["T1110.001"]


def test_parse_attack_ids_two_entries():
    text = ("TAXONOMY NAME:ATTACK:ENTRY ID:1036.001:ENTRY NAME:Masquerading: Invalid Code Signature::"
            "::TAXONOMY NAME:ATTACK:ENTRY ID:1553.002:ENTRY NAME:Subvert Trust Controls: Code Signing::")
    assert parse_attack_ids(text) == ["T1036.001", "T1553.002"]


def test_parse_attack_ids_ignores_other_taxonomies():
    text = ("TAXONOMY NAME:WASC:ENTRY ID:28:ENTRY NAME:Null Byte Injection::"
            "::TAXONOMY NAME:OWASP Attacks:ENTRY NAME:Embedding Null Code::")
    assert parse_attack_ids(text) == []


def test_parse_attack_ids_empty():
    assert parse_attack_ids("") == []

def test_build_capec_to_attack_skips_unmapped(tmp_path):
    sample = tmp_path / "capec.csv"
    sample.write_text(
        "'ID,Name,Taxonomy Mappings\n"
        "49,Password Brute Forcing,TAXONOMY NAME:ATTACK:ENTRY ID:1110.001:ENTRY NAME:Brute Force::\n"
        "999,No Mapping,TAXONOMY NAME:WASC:ENTRY ID:28:ENTRY NAME:Null Byte Injection::\n",
        encoding="utf-8",
    )
    assert build_capec_to_attack(sample) == {"CAPEC-49": ["T1110.001"]}
