from pathlib import Path

import pytest

from code_sanitizer.file_io import read_text_file, save_sanitized_file
from code_sanitizer.sanitizer import MaskRule, ReplacementRule, sanitize_text


def test_single_replacement() -> None:
    result = sanitize_text("package nkc;", [ReplacementRule("nkc", "company")])

    assert result.text == "package company;"
    assert result.replacement_count == 1
    assert result.masked_line_count == 0


def test_multiple_replacements() -> None:
    result = sanitize_text(
        "nkc gaia",
        [ReplacementRule("nkc", "company"), ReplacementRule("gaia", "product")],
    )

    assert result.text == "company product"
    assert result.replacement_count == 2


def test_replaces_all_occurrences() -> None:
    result = sanitize_text("nkc nkc", [ReplacementRule("nkc", "company")])

    assert result.text == "company company"
    assert result.replacement_count == 2


def test_replacement_is_case_sensitive() -> None:
    result = sanitize_text("NKC nkc", [ReplacementRule("nkc", "company")])

    assert result.text == "NKC company"
    assert result.replacement_count == 1


def test_replaces_japanese_text() -> None:
    result = sanitize_text(
        "顧客会社名",
        [ReplacementRule("顧客会社名", "ClientA")],
    )

    assert result.text == "ClientA"
    assert result.replacement_count == 1


def test_masks_a_matching_line() -> None:
    result = sanitize_text(
        'String companyName = "NKC株式会社";\nnext();',
        mask_rules=[MaskRule("NKC")],
    )

    assert result.text == "[REDACTED]\nnext();"
    assert result.masked_line_count == 1


def test_masks_multiple_lines_and_preserves_line_endings() -> None:
    result = sanitize_text(
        "NKC first\r\nkeep\nNKC second",
        mask_rules=[MaskRule("NKC")],
    )

    assert result.text == "[REDACTED]\r\nkeep\n[REDACTED]"
    assert result.masked_line_count == 2


def test_replacement_and_mask_rules_are_combined() -> None:
    result = sanitize_text(
        "nkc package\ncustomer record",
        replacement_rules=[ReplacementRule("nkc", "company")],
        mask_rules=[MaskRule("customer")],
    )

    assert result.text == "company package\n[REDACTED]"
    assert result.replacement_count == 1
    assert result.masked_line_count == 1


def test_no_matching_targets_leaves_text_unchanged() -> None:
    result = sanitize_text(
        "hello",
        replacement_rules=[ReplacementRule("missing", "replacement")],
        mask_rules=[MaskRule("private")],
    )

    assert result.text == "hello"
    assert result.replacement_count == 0
    assert result.masked_line_count == 0


def test_empty_file_stays_empty() -> None:
    result = sanitize_text("", [ReplacementRule("nkc", "company")], [MaskRule("NKC")])

    assert result.text == ""
    assert result.replacement_count == 0
    assert result.masked_line_count == 0


def test_empty_search_rules_are_ignored() -> None:
    result = sanitize_text(
        "unchanged",
        [ReplacementRule("", "replacement")],
        [MaskRule("")],
    )

    assert result.text == "unchanged"
    assert result.replacement_count == 0
    assert result.masked_line_count == 0


def test_file_io_uses_utf8_and_preserves_line_endings(tmp_path: Path) -> None:
    source = tmp_path / "source.txt"
    source.write_bytes("日本語\r\nline".encode("utf-8"))

    assert read_text_file(source) == "日本語\r\nline"

    destination = tmp_path / "result.txt"
    save_sanitized_file(source, destination, "置換後\r\nline")
    assert destination.read_bytes() == "置換後\r\nline".encode("utf-8")
    assert source.read_bytes() == "日本語\r\nline".encode("utf-8")


def test_file_io_rejects_saving_over_original(tmp_path: Path) -> None:
    source = tmp_path / "source.txt"
    source.write_text("original", encoding="utf-8")

    with pytest.raises(ValueError, match="cannot overwrite"):
        save_sanitized_file(source, source, "sanitized")

    assert source.read_text(encoding="utf-8") == "original"
