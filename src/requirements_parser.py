import re
from dataclasses import dataclass
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


@dataclass
class Pinned:
    name: str
    val: str

@dataclass
class Skipped:
    line: str
    reason: str

def parse_requirements(path):
    requirements_list = []
    skipped = []
    with open(path, "r", encoding="utf-8") as file:
        for line in file:
            clean_text = re.sub(r'#.*', '', line)
            clean_text = clean_text.strip()
            if clean_text == "":
                continue
            if clean_text.startswith("-"):
                skipped.append(Skipped(clean_text, "pip option, not supported"))
                continue
            operator = ""
            version = ""
            try:
                req = Requirement(clean_text)
                for spec in req.specifier:
                    operator = spec.operator
                    version = spec.version
                if operator != '==' or '*' in version:
                    skipped.append(Skipped(clean_text, "not pinned to an exact version"))
                    continue
                name, val = clean_text.split("==")
            except ValueError:
                raise ValueError(f"Separator must be ==: {clean_text!r}") from None
            name = canonicalize_name(name.strip())
            val = val.strip()
            if name == "" or val == "":
                raise ValueError(f"Missing name or version: {clean_text!r}")
            requirements_list.append(Pinned(name=name, val=val))
    return requirements_list, skipped
