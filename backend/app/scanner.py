"""Local, dependency-free static checks used by AegisReview."""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Iterator

MAX_FILE_SIZE_BYTES = 1_000_000
IGNORED_DIRECTORIES = {".git", "node_modules", ".venv", "venv", "dist", "build"}
TEST_PATH_MARKERS = {"test", "tests", "spec", "specs", "__tests__", "__mocks__", "fixture", "fixtures", "mock", "mocks"}
# Deliberately broad: catches the AWS docs' own sample key (AKIAIOSFODNN7EXAMPLE) and
# common seed/fixture values. Trade-off is a rare false negative over a common false alarm.
PLACEHOLDER_MARKERS = ("example", "sample", "dummy", "fake", "changeme", "placeholder", "yourkey", "your_key", "insert_", "replace_me", "xxxxxxxx", "00000000", "test", "mock")


class Finding(dict):
    """Typed-at-use dictionary shape returned by the API."""


SECRET_ASSIGNMENT = re.compile(
    r"(?i)(?:api[_-]?key|secret|token|password|access[_-]?key)\s*[:=]\s*['\"]([^'\"\s]{16,})['\"]"
)
AWS_ACCESS_KEY = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
SQL_INTERPOLATION = re.compile(
    r"(?i)(?:execute|executemany|cursor\.execute)\s*\(\s*(?:f['\"]|['\"].*(?:\.format\(|\s%\s|\+))"
)
XSS_PATTERNS = (
    (re.compile(r"\bdangerouslySetInnerHTML\b"), "React dangerouslySetInnerHTML usage"),
    (re.compile(r"\|\s*safe\b"), "Template safe filter usage"),
    (re.compile(r"\b(?:Markup|mark_safe)\s*\("), "Unescaped HTML markup usage"),
)
EVAL_EXEC = re.compile(r"\b(?:eval|exec)\s*\(")

# This is intentionally a small offline list: it remains deterministic and is easy to
# replace with an OSV/NVD-backed source later without changing the API contract.
KNOWN_BAD_DEPENDENCIES: dict[str, tuple[str, str, str]] = {
    "lodash": ("4.17.21", "high", "Known vulnerable lodash version"),
    "minimist": ("1.2.6", "critical", "Known vulnerable minimist version"),
    "axios": ("1.6.0", "high", "Known vulnerable axios version"),
    "django": ("4.2.11", "high", "Known vulnerable Django version"),
    "flask": ("2.2.5", "high", "Known vulnerable Flask version"),
    "pyyaml": ("6.0", "high", "Known vulnerable PyYAML version"),
    "urllib3": ("1.26.18", "high", "Known vulnerable urllib3 version"),
}


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    frequencies = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in frequencies.values())


def make_finding(file_path: Path, root: Path, line: int, rule: str, severity: str, context: str = "") -> Finding:
    return Finding(file=str(file_path.relative_to(root)), line_number=line, rule=rule, severity=severity, context=context)


def redact_secrets(text: str) -> str:
    text = SECRET_ASSIGNMENT.sub(lambda match: match.group(0).replace(match.group(1), "<REDACTED_SECRET>"), text)
    return AWS_ACCESS_KEY.sub("<REDACTED_AWS_ACCESS_KEY>", text)


def snippet_around(lines: list[str], line_number: int) -> str:
    start = max(0, line_number - 3)
    end = min(len(lines), line_number + 2)
    numbered = "\n".join(f"{index + 1}: {lines[index]}" for index in range(start, end))
    return redact_secrets(numbered)


def is_test_path(file_path: Path, root: Path) -> bool:
    relative = file_path.relative_to(root)
    if any(part.lower() in TEST_PATH_MARKERS for part in relative.parts[:-1]):
        return True
    name = relative.name.lower()
    return ".test." in name or ".spec." in name or name.startswith("test_") or name.startswith("mock_")


def looks_like_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in PLACEHOLDER_MARKERS)


def iter_scannable_files(root: Path) -> Iterator[Path]:
    for path in root.rglob("*"):
        if not path.is_file() or any(part in IGNORED_DIRECTORIES for part in path.relative_to(root).parts):
            continue
        if path.stat().st_size <= MAX_FILE_SIZE_BYTES:
            yield path


def scan_source_file(file_path: Path, root: Path) -> list[Finding]:
    try:
        content = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []

    lines = content.splitlines()
    test_path = is_test_path(file_path, root)
    findings: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        for match in SECRET_ASSIGNMENT.finditer(line):
            if shannon_entropy(match.group(1)) >= 3.5 and not looks_like_placeholder(match.group(1)):
                severity = "medium" if test_path else "critical"
                findings.append(make_finding(file_path, root, line_number, "Hardcoded high-entropy secret", severity, snippet_around(lines, line_number)))
        aws_match = AWS_ACCESS_KEY.search(line)
        if aws_match and not looks_like_placeholder(aws_match.group(0)):
            severity = "medium" if test_path else "critical"
            findings.append(make_finding(file_path, root, line_number, "Hardcoded AWS access key", severity, snippet_around(lines, line_number)))
        if SQL_INTERPOLATION.search(line):
            findings.append(make_finding(file_path, root, line_number, "SQL query built with string interpolation", "high", snippet_around(lines, line_number)))
        for pattern, rule in XSS_PATTERNS:
            if pattern.search(line):
                findings.append(make_finding(file_path, root, line_number, rule, "high", snippet_around(lines, line_number)))
        if EVAL_EXEC.search(line):
            findings.append(make_finding(file_path, root, line_number, "Dynamic eval/exec usage", "critical", snippet_around(lines, line_number)))
    return findings


def version_tuple(version: str) -> tuple[int, ...] | None:
    match = re.match(r"^(\d+(?:\.\d+)*)", version.strip().lstrip("^~<>=v"))
    return tuple(int(part) for part in match.group(1).split(".")) if match else None


def is_version_older(version: str, safe_version: str) -> bool:
    parsed, safe = version_tuple(version), version_tuple(safe_version)
    if not parsed or not safe:
        return False
    length = max(len(parsed), len(safe))
    return parsed + (0,) * (length - len(parsed)) < safe + (0,) * (length - len(safe))


def dependency_finding(file_path: Path, root: Path, line: int, name: str, version: str, lines: list[str]) -> Finding | None:
    known_bad = KNOWN_BAD_DEPENDENCIES.get(name.lower())
    if known_bad and is_version_older(version, known_bad[0]):
        safe_version, severity, description = known_bad
        return make_finding(file_path, root, line, f"{description}; upgrade to {safe_version}+", severity, snippet_around(lines, line))
    return None


def scan_package_json(file_path: Path, root: Path) -> list[Finding]:
    try:
        package = json.loads(file_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return []

    findings: list[Finding] = []
    lines = file_path.read_text(encoding="utf-8").splitlines()
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, version in package.get(section, {}).items():
            line = next((index + 1 for index, value in enumerate(lines) if f'"{name}"' in value), 1)
            finding = dependency_finding(file_path, root, line, name, str(version), lines)
            if finding:
                findings.append(finding)
    return findings


def scan_requirements(file_path: Path, root: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        lines = file_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return findings

    for line_number, line in enumerate(lines, start=1):
        match = re.match(r"^\s*([A-Za-z0-9_.-]+)\s*==\s*([^\s;#]+)", line)
        if match:
            finding = dependency_finding(file_path, root, line_number, match.group(1), match.group(2), lines)
            if finding:
                findings.append(finding)
    return findings


def scan_repository(root: Path) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    scanned_files = 0
    for file_path in iter_scannable_files(root):
        scanned_files += 1
        findings.extend(scan_source_file(file_path, root))
        if file_path.name == "package.json":
            findings.extend(scan_package_json(file_path, root))
        elif file_path.name == "requirements.txt":
            findings.extend(scan_requirements(file_path, root))
    return findings, scanned_files
