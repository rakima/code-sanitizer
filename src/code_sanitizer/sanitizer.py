"""Text sanitization rules independent of the graphical interface."""

from dataclasses import dataclass, field
import hashlib
import re
from typing import Iterable

from .restoration import RestorationData, RestorationEntry


@dataclass(frozen=True)
class ReplacementRule:
    search: str
    replacement: str


@dataclass(frozen=True)
class MaskRule:
    search: str
    match_date_formats: bool = False


DATE_MASK_LABEL = "yyyy/mm/dd または yyyy年mm月dd日"
_DATE_PATTERNS = (
    re.compile(r"(?<![0-9])[0-9]{4}/[0-9]{1,2}/[0-9]{1,2}(?![0-9])"),
    re.compile(
        r"(?<![0-9])[0-9]{4}年[0-9]{1,2}月[0-9]{1,2}日(?![0-9])"
    ),
)


@dataclass(frozen=True)
class SanitizationResult:
    text: str
    replacement_count: int
    masked_line_count: int


@dataclass(frozen=True)
class RestorableSanitizationResult:
    text: str = field(repr=False)
    replacement_count: int
    masked_line_count: int
    restoration_data: RestorationData = field(repr=False)


def sanitize_text(
    text: str,
    replacement_rules: Iterable[ReplacementRule] = (),
    mask_rules: Iterable[MaskRule] = (),
) -> SanitizationResult:
    """Apply literal replacements and replace matching lines with ``[REDACTED]``."""
    replacements = tuple(rule for rule in replacement_rules if rule.search)
    masks = tuple(rule for rule in mask_rules if rule.search)
    output_lines: list[str] = []
    replacement_count = 0
    masked_line_count = 0

    for line in text.splitlines(keepends=True):
        content = line.rstrip("\r\n")
        line_ending = line[len(content) :]

        if any(_matches_mask_rule(content, rule) for rule in masks):
            output_lines.append(f"[REDACTED]{line_ending}")
            masked_line_count += 1
            continue

        for rule in replacements:
            replacement_count += content.count(rule.search)
            content = content.replace(rule.search, rule.replacement)

        output_lines.append(f"{content}{line_ending}")

    return SanitizationResult(
        text="".join(output_lines),
        replacement_count=replacement_count,
        masked_line_count=masked_line_count,
    )


def sanitize_text_for_restoration(
    text: str,
    replacement_rules: Iterable[ReplacementRule] = (),
    mask_rules: Iterable[MaskRule] = (),
) -> RestorableSanitizationResult:
    """Sanitize text with unique markers and local data needed for restoration."""
    replacements = tuple(rule for rule in replacement_rules if rule.search)
    masks = tuple(rule for rule in mask_rules if rule.search)
    entries: list[RestorationEntry] = []
    output_lines: list[str] = []
    used_tokens: set[str] = set()
    replacement_count = 0
    masked_line_count = 0

    def make_token(
        value: str,
        kind: str,
        source_start: int,
    ) -> str:
        sequence = len(entries) + 1
        token = f"[REDACTED_{sequence:04d}]"
        while token in text or token in used_tokens:
            sequence += 1
            token = f"[REDACTED_{sequence:04d}]"
        used_tokens.add(token)
        entries.append(
            RestorationEntry(
                token=token,
                value=value,
                kind=kind,
                source_start=source_start,
                source_end=source_start + len(value),
            )
        )
        return token

    source_offset = 0
    for line in text.splitlines(keepends=True):
        content = line.rstrip("\r\n")
        line_ending = line[len(content) :]

        if any(_matches_mask_rule(content, rule) for rule in masks):
            output_lines.append(
                f"{make_token(content, 'line', source_offset)}{line_ending}"
            )
            masked_line_count += 1
            source_offset += len(line)
            continue

        output_parts: list[str] = []
        position = 0
        while position < len(content):
            matches = [
                (found_at, rule_index, rule)
                for rule_index, rule in enumerate(replacements)
                if (found_at := content.find(rule.search, position)) >= 0
            ]
            if not matches:
                output_parts.append(content[position:])
                break

            found_at, _, rule = min(matches, key=lambda match: (match[0], match[1]))
            output_parts.append(content[position:found_at])
            output_parts.append(
                make_token(rule.search, "replacement", source_offset + found_at)
            )
            replacement_count += 1
            position = found_at + len(rule.search)

        output_lines.append(f"{''.join(output_parts)}{line_ending}")
        source_offset += len(line)

    restoration_data = RestorationData(
        source_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        entries=tuple(entries),
    )
    return RestorableSanitizationResult(
        text="".join(output_lines),
        replacement_count=replacement_count,
        masked_line_count=masked_line_count,
        restoration_data=restoration_data,
    )


def _matches_mask_rule(content: str, rule: MaskRule) -> bool:
    if rule.match_date_formats:
        return any(pattern.search(content) for pattern in _DATE_PATTERNS)
    return rule.search in content
