from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import Version

KNOWN_PYTHON_VERSIONS = [
    "3.8.20",
    "3.9.21",
    "3.10.16",
    "3.11.9",
    "3.12.8",
    "3.13.1",
]


def recommend_python(all_requires_python: list[str]) -> str:
    filtered = [value for value in all_requires_python if isinstance(value, str) and value.strip()]
    if not filtered:
        return "3.11.9"

    specifiers: list[SpecifierSet] = []
    for value in filtered:
        try:
            specifiers.append(SpecifierSet(value))
        except InvalidSpecifier:
            continue

    if not specifiers:
        return "3.11.9"

    for candidate in reversed(KNOWN_PYTHON_VERSIONS):
        version = Version(candidate)
        if all(version in specifier for specifier in specifiers):
            return candidate

    return "3.11.9"
