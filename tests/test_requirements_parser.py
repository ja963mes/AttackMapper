import pytest

from requirements_parser import Requirement, parse_requirements


def test_parses_pinned_lines(tmp_path):
    sample = tmp_path / "requirements.txt"
    sample.write_text(
        "django==3.2.0\n"
        "python-dateutil==2.8.2\n"
        "requests == 2.31.0\n"
        "flask==2.0.1  # pinned for an old plugin\n"
        "      \n"
        "# dev tools\n",
        encoding="utf-8",
    )
    assert parse_requirements(sample) == [
        Requirement("django", "3.2.0"),
        Requirement("python-dateutil", "2.8.2"),
        Requirement("requests", "2.31.0"),
        Requirement("flask", "2.0.1"),
    ]

def test_unpinned_line_raises(tmp_path):
    sample = tmp_path / "requirements.txt"
    sample.write_text("numpy>=1.20\n", encoding="utf-8")
    with pytest.raises(ValueError):
        parse_requirements(sample)

