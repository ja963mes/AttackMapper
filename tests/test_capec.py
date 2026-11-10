from capec import build_cwe_to_capec, parse_related_weaknesses

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
