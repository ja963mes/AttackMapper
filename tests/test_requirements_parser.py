from requirements_parser import Pinned, Skipped, parse_requirements


def test_parses_pinned_lines(tmp_path):
    sample = tmp_path / "requirements.txt"
    sample.write_text(
        "django==3.2.0\n"
        "Python_Dateutil==2.8.2\n"
        "requests == 2.31.0\n"
        "flask==2.0.1  # pinned for an old plugin\n"
        "      \n"
        "# dev tools\n",
        encoding="utf-8",
    )
    kept, skipped = parse_requirements(sample)
    assert kept == [
        Pinned("django", "3.2.0"),
        Pinned("python-dateutil", "2.8.2"),
        Pinned("requests", "2.31.0"),
        Pinned("flask", "2.0.1"),
    ]
    assert skipped == []


def test_unpinned_line_is_skipped(tmp_path):
    sample = tmp_path / "requirements.txt"
    sample.write_text("numpy>=1.20\n", encoding="utf-8")
    kept, skipped = parse_requirements(sample)
    assert kept == []
    assert skipped == [Skipped("numpy>=1.20", "not pinned to an exact version")]
