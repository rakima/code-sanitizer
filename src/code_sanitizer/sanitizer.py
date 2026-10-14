"""Text sanitization rules independent of the graphical interface."""

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class ReplacementRule:
    search: str
    replacement: str


@dataclass(frozen=True)
class MaskRule:
    search: str


@dataclass(frozen=True)
class SanitizationResult:
    text: str
    replacement_count: int
    masked_line_count: int


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

        if any(rule.search in content for rule in masks):
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
