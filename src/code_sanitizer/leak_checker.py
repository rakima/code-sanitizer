"""Local, heuristic checks for information that may remain in sanitized text."""

from collections import Counter, defaultdict
from dataclasses import dataclass
from functools import lru_cache
import ipaddress
from pathlib import Path
import re
from typing import Iterable


@dataclass(frozen=True)
class LeakCandidate:
    category: str
    value: str
    count: int
    lines: tuple[int, ...]
    risk: str


@dataclass(frozen=True)
class PatternCheck:
    category: str
    label: str
    count: int


@dataclass(frozen=True)
class LeakCheckResult:
    pattern_candidates: tuple[LeakCandidate, ...]
    identifier_candidates: tuple[LeakCandidate, ...]
    pattern_checks: tuple[PatternCheck, ...]


_PATTERN_SPECS = (
    (
        "email",
        "Email",
        "high",
        re.compile(r"(?i)(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+"),
    ),
    (
        "ipv4",
        "IPv4",
        "high",
        re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"),
    ),
    (
        "url",
        "URL",
        "high",
        re.compile(r"(?i)\b(?:https?|ftp)://[^\s<>\"']+"),
    ),
    (
        "windows_path",
        "Windowsパス",
        "medium",
        re.compile(r"(?<![\w])(?:[A-Za-z]:\\)[^\r\n\"<>|]*"),
    ),
    (
        "unix_path",
        "Unixパス",
        "medium",
        re.compile(
            r"(?<![:/])/(?:[A-Za-z0-9._~+-]+/)+[A-Za-z0-9._~+-]*"
        ),
    ),
)
_CREDENTIAL_PATTERN = re.compile(
    r"(?i)\b([a-z_$][\w$-]*)\s*[:=]\s*([\"'])([^\"'\r\n]+)\2"
)
_CREDENTIAL_NAME_PARTS = (
    "apikey",
    "token",
    "password",
    "passwd",
    "secret",
    "credential",
)
_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
_PACKAGE_IMPORT_PATTERN = re.compile(
    r"^\s*(?:package|import)\s+(?:static\s+)?([\w$.*]+)\s*;",
    re.MULTILINE,
)
_CAMEL_BOUNDARY_PATTERN = re.compile(
    r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])"
)
_PACKAGE_DATA_DIR = Path(__file__).with_name("data")
_COMMON_WORDS_PATH = _PACKAGE_DATA_DIR / "java_common_words.txt"
_IDENTIFIER_SUFFIXES_PATH = _PACKAGE_DATA_DIR / "java_identifier_suffixes.txt"


def check_sensitive_patterns(text: str) -> tuple[LeakCandidate, ...]:
    """Find common sensitive patterns; credential literal contents stay hidden."""
    candidates: list[LeakCandidate] = []

    for category, _, risk, pattern in _PATTERN_SPECS:
        values: dict[str, list[tuple[str, int]]] = defaultdict(list)
        for line_number, line in enumerate(text.splitlines(), start=1):
            for match in pattern.finditer(line):
                value = _clean_match(match.group())
                if not value:
                    continue
                if category == "ipv4" and not _is_valid_ipv4(value):
                    continue
                values[value.casefold()].append((value, line_number))
        candidates.extend(
            _build_candidates(category, risk, values)
        )

    credential_matches: list[int] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for match in _CREDENTIAL_PATTERN.finditer(line):
            name = re.sub(r"[_-]", "", match.group(1).casefold())
            if any(part in name for part in _CREDENTIAL_NAME_PARTS):
                credential_matches.append(line_number)
    if credential_matches:
        candidates.append(
            LeakCandidate(
                category="credential",
                value="認証情報候補（値は非表示）",
                count=len(credential_matches),
                lines=tuple(sorted(set(credential_matches))),
                risk="high",
            )
        )

    return tuple(candidates)


def split_camel_case(identifier: str) -> tuple[str, ...]:
    """Split Java-style CamelCase and acronym boundaries into words."""
    separated = _CAMEL_BOUNDARY_PATTERN.sub(" ", identifier)
    return tuple(re.findall(r"[A-Za-z]+|[0-9]+", separated))


def analyze_package_imports(text: str) -> tuple[LeakCandidate, ...]:
    """Extract non-generic package and import segments with source line numbers."""
    occurrences = _collect_identifier_occurrences(text, package_only=True)
    return _build_identifier_candidates(occurrences, ignored_words=())


def find_identifier_candidates(
    text: str, ignored_words: Iterable[str] = ()
) -> tuple[LeakCandidate, ...]:
    """Find repeated CamelCase words and distinctive package/import segments."""
    occurrences = _collect_identifier_occurrences(text, package_only=False)
    return _build_identifier_candidates(occurrences, ignored_words)


def scan_for_leaks(
    text: str, ignored_words: Iterable[str] = ()
) -> LeakCheckResult:
    """Return structured pattern and Java identifier findings for text."""
    pattern_candidates = check_sensitive_patterns(text)
    identifier_candidates = find_identifier_candidates(text, ignored_words)
    pattern_checks = tuple(
        PatternCheck(
            category=category,
            label=label,
            count=(
                sum(
                    candidate.count
                    for candidate in pattern_candidates
                    if candidate.category == category
                )
            ),
        )
        for category, label, _, _ in _PATTERN_SPECS
    ) + (
        PatternCheck(
            category="credential",
            label="認証情報候補",
            count=sum(
                candidate.count
                for candidate in pattern_candidates
                if candidate.category == "credential"
            ),
        ),
    )
    return LeakCheckResult(
        pattern_candidates=pattern_candidates,
        identifier_candidates=identifier_candidates,
        pattern_checks=pattern_checks,
    )


def _collect_identifier_occurrences(
    text: str, package_only: bool
) -> dict[str, list[tuple[str, int, int, bool]]]:
    occurrences: dict[str, list[tuple[str, int, int, bool]]] = defaultdict(list)
    package_positions: set[tuple[int, int]] = set()

    for package_match in _PACKAGE_IMPORT_PATTERN.finditer(text):
        line_number = text.count("\n", 0, package_match.start()) + 1
        content = package_match.group(1)
        for segment_match in re.finditer(r"[\w$]+", content):
            start = package_match.start(1) + segment_match.start()
            package_positions.add((line_number, start))
            _add_identifier_terms(
                occurrences,
                segment_match.group(),
                line_number,
                start,
                is_package=True,
            )

    if package_only:
        return occurrences

    line_starts = [0]
    line_starts.extend(
        match.end() for match in re.finditer(r"\r\n|\r|\n", text)
    )
    for line_index, line in enumerate(text.splitlines()):
        line_number = line_index + 1
        line_start = line_starts[line_index]
        for match in _IDENTIFIER_PATTERN.finditer(line):
            identifier = match.group()
            start = line_start + match.start()
            is_package = (line_number, start) in package_positions
            if not is_package:
                _add_identifier_terms(
                    occurrences,
                    identifier,
                    line_number,
                    start,
                    is_package=False,
                )

    return occurrences


def _add_identifier_terms(
    occurrences: dict[str, list[tuple[str, int, int, bool]]],
    identifier: str,
    line_number: int,
    start: int,
    is_package: bool,
) -> None:
    words = split_camel_case(identifier)
    seen: set[str] = set()
    if is_package and any(character.isdigit() for character in identifier):
        normalized = identifier.casefold()
        occurrences[normalized].append((identifier, line_number, start, True))
        seen.add(normalized)
    for word in words:
        normalized = word.casefold()
        occurrences[normalized].append((word, line_number, start, is_package))
        seen.add(normalized)

    remaining_words = list(words)
    while (
        len(remaining_words) > 1
        and remaining_words[-1].casefold() in _load_identifier_suffixes()
    ):
        remaining_words.pop()
    if len(remaining_words) >= 2:
        compound = "".join(remaining_words)
        normalized = compound.casefold()
        if normalized not in seen:
            occurrences[normalized].append(
                (compound, line_number, start, is_package)
            )


def _build_identifier_candidates(
    occurrences: dict[str, list[tuple[str, int, int, bool]]],
    ignored_words: Iterable[str],
) -> tuple[LeakCandidate, ...]:
    common_words = _load_common_words()
    ignored = {word.casefold() for word in ignored_words}
    candidates: list[LeakCandidate] = []

    for normalized, matches in occurrences.items():
        if normalized in common_words or normalized in ignored:
            continue
        if not any(character.isalpha() for character in normalized):
            continue
        if len(normalized) < 3 and not any(is_package for _, _, _, is_package in matches):
            continue
        package_count = sum(is_package for _, _, _, is_package in matches)
        if len(matches) < 2 and package_count == 0:
            continue

        spellings = Counter(value for value, _, _, _ in matches)
        value = spellings.most_common(1)[0][0]
        lines = tuple(sorted({line for _, line, _, _ in matches}))
        risk = "medium" if package_count or len(matches) >= 3 else "low"
        candidates.append(
            LeakCandidate(
                category="identifier",
                value=value,
                count=len(matches),
                lines=lines,
                risk=risk,
            )
        )

    return tuple(
        sorted(
            candidates,
            key=lambda candidate: (
                candidate.risk != "medium",
                -candidate.count,
                candidate.value.casefold(),
            ),
        )
    )


def _build_candidates(
    category: str,
    risk: str,
    values: dict[str, list[tuple[str, int]]],
) -> list[LeakCandidate]:
    candidates: list[LeakCandidate] = []
    for matches in values.values():
        value_counts = Counter(value for value, _ in matches)
        value = value_counts.most_common(1)[0][0]
        candidates.append(
            LeakCandidate(
                category=category,
                value=value,
                count=len(matches),
                lines=tuple(sorted({line for _, line in matches})),
                risk=risk,
            )
        )
    return candidates


def _is_valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        return False
    return True


def _clean_match(value: str) -> str:
    return value.rstrip(".,;:!?)]}")


@lru_cache(maxsize=1)
def _load_common_words() -> frozenset[str]:
    words = _COMMON_WORDS_PATH.read_text(encoding="utf-8").splitlines()
    return frozenset(word.strip().casefold() for word in words if word.strip())


@lru_cache(maxsize=1)
def _load_identifier_suffixes() -> frozenset[str]:
    words = _IDENTIFIER_SUFFIXES_PATH.read_text(encoding="utf-8").splitlines()
    return frozenset(word.strip().casefold() for word in words if word.strip())
