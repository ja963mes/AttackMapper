import re
from dataclasses import dataclass


@dataclass
class Requirement:
    name: str
    val: str


def parse_requirements(path):
    requirements_list = []
    with open(path, "r", encoding="utf-8") as file:
        for line in file:
            clean_text = re.sub(r'#.*', '', line)
            clean_text = clean_text.strip()
            if clean_text == "":
                continue
            try:
                name, val = clean_text.split("==")
            except ValueError:
                raise ValueError(f"Separator must be ==: {clean_text!r}") from None
            name = name.strip()
            val = val.strip()
            if name == "" or val == "":
                raise ValueError(f"Missing name or version: {clean_text!r}")
            requirements_list.append(Requirement(name=name, val=val))
    return requirements_list
