import hashlib

import pytest

from code_sanitizer.restoration import (
    RestorationData,
    load_restoration_data,
    parse_restoration_data,
    restore_text,
    serialize_restoration_data,
)
from code_sanitizer.sanitizer import (
    MaskRule,
    ReplacementRule,
    sanitize_text,
    sanitize_text_for_restoration,
)


def _restorable(original: str, *, masks=()):
    return sanitize_text_for_restoration(
        original,
        replacement_rules=(ReplacementRule("ABC株式会社", "CompanyA"),),
        mask_rules=masks,
    )


def test_restores_anonymized_code_unchanged() -> None:
    original = 'String companyName = "ABC株式会社";\n'
    sanitized = _restorable(original)

    result = restore_text(original, sanitized.text, sanitized.restoration_data)

    assert sanitized.text == 'String companyName = "[REDACTED_0001]";\n'
    assert result.text == original
    assert result.restored_count == 1
    assert result.fully_restored


def test_accepts_sanitized_baseline_and_reconstructs_original_source() -> None:
    original = 'String companyName = "ABC株式会社";\n'
    sanitized = _restorable(original)

    result = restore_text(
        sanitized.text,
        sanitized.text,
        sanitized.restoration_data,
    )

    assert result.text == original
    assert result.restored_count == 1
    assert result.source_reconstructed
    assert not result.source_mismatch


def test_accepts_sanitized_baseline_with_ai_edits() -> None:
    original = 'String companyName = "ABC株式会社";\n'
    sanitized = _restorable(original)
    edited = (
        "if (condition) {\n"
        f"    {sanitized.text}"
        "    execute(companyName);\n"
        "}\n"
    )

    result = restore_text(
        sanitized.text,
        edited,
        sanitized.restoration_data,
    )

    assert result.text == (
        "if (condition) {\n"
        '    String companyName = "ABC株式会社";\n'
        "    execute(companyName);\n"
        "}\n"
    )
    assert result.source_reconstructed
    assert result.fully_restored


def test_sanitized_baseline_missing_mapping_id_is_not_used() -> None:
    original = 'String companyName = "ABC株式会社";\n'
    sanitized = _restorable(original)
    invalid_baseline = sanitized.text.replace("[REDACTED_0001]", "removed")

    result = restore_text(
        invalid_baseline,
        sanitized.text,
        sanitized.restoration_data,
    )

    assert result.text == sanitized.text
    assert result.source_mismatch
    assert not result.source_reconstructed


def test_restores_token_inside_ai_modified_code() -> None:
    original = 'String companyName = "ABC株式会社";\n'
    sanitized = _restorable(original)
    edited = (
        "if (condition) {\n"
        '    String companyName = "[REDACTED_0001]";\n'
        "    execute(companyName);\n"
        "}\n"
    )

    result = restore_text(original, edited, sanitized.restoration_data)

    assert result.text == (
        "if (condition) {\n"
        '    String companyName = "ABC株式会社";\n'
        "    execute(companyName);\n"
        "}\n"
    )
    assert "execute(companyName);" in result.text
    assert result.fully_restored


def test_restores_when_lines_are_added_before_token() -> None:
    original = 'String name = "ABC株式会社";\n'
    sanitized = _restorable(original)
    edited = "// AI added this line\n" + sanitized.text

    result = restore_text(original, edited, sanitized.restoration_data)

    assert result.text == '// AI added this line\nString name = "ABC株式会社";\n'
    assert result.missing_tokens == ()


def test_restores_when_lines_before_token_are_deleted() -> None:
    original = (
        "first line\n"
        'String name = "ABC株式会社";\n'
        "last line\n"
    )
    sanitized = _restorable(original)
    edited = sanitized.text.replace("first line\n", "")

    result = restore_text(original, edited, sanitized.restoration_data)

    assert result.text == 'String name = "ABC株式会社";\nlast line\n'
    assert result.fully_restored


def test_restores_crlf_source_after_changes_to_earlier_lines() -> None:
    original = "first line\r\nString name = \"ABC株式会社\";\r\nlast line\r\n"
    sanitized = _restorable(original)
    edited = "// inserted\r\n" + sanitized.text.replace("first line\r\n", "")

    result = restore_text(original, edited, sanitized.restoration_data)

    assert result.text == '// inserted\r\nString name = "ABC株式会社";\r\nlast line\r\n'
    assert result.fully_restored


def test_deleted_token_is_reported_and_not_guessed() -> None:
    original = 'String name = "ABC株式会社";\n'
    sanitized = _restorable(original)
    edited = sanitized.text.replace("[REDACTED_0001]", "removed")

    result = restore_text(original, edited, sanitized.restoration_data)

    assert result.text == edited
    assert result.restored_count == 0
    assert result.unresolved_count == 1
    assert result.missing_tokens == ("[REDACTED_0001]",)
    assert not result.fully_restored


def test_changed_token_is_reported_as_missing_and_unknown() -> None:
    original = 'String name = "ABC株式会社";\n'
    sanitized = _restorable(original)
    edited = sanitized.text.replace("[REDACTED_0001]", "[REDACTED_9999]")

    result = restore_text(original, edited, sanitized.restoration_data)

    assert result.text == edited
    assert result.missing_tokens == ("[REDACTED_0001]",)
    assert result.unknown_tokens == ("[REDACTED_9999]",)
    assert result.unresolved_count == 2


def test_case_changed_token_is_not_restored() -> None:
    original = 'String name = "ABC株式会社";\n'
    sanitized = _restorable(original)
    edited = sanitized.text.replace("REDACTED", "redacted")

    result = restore_text(original, edited, sanitized.restoration_data)

    assert result.text == edited
    assert result.missing_tokens == ("[REDACTED_0001]",)
    assert result.unknown_tokens == ("[redacted_0001]",)


def test_duplicated_token_is_not_restored_at_any_occurrence() -> None:
    original = 'String name = "ABC株式会社";\n'
    sanitized = _restorable(original)
    edited = sanitized.text + sanitized.text

    result = restore_text(original, edited, sanitized.restoration_data)

    assert result.text == edited
    assert result.restored_count == 0
    assert result.duplicated_tokens == ("[REDACTED_0001]",)
    assert result.unresolved_count == 2


def test_unknown_added_token_is_not_restored() -> None:
    original = 'String name = "ABC株式会社";\n'
    sanitized = _restorable(original)
    edited = sanitized.text + "\n[REDACTED_9999]"

    result = restore_text(original, edited, sanitized.restoration_data)

    assert "[REDACTED_9999]" in result.text
    assert result.restored_count == 1
    assert result.unknown_tokens == ("[REDACTED_9999]",)
    assert result.unresolved_count == 1


def test_multiple_redactions_restore_independently() -> None:
    original = "ABC株式会社, ABC株式会社\n"
    sanitized = sanitize_text_for_restoration(
        original,
        replacement_rules=(ReplacementRule("ABC株式会社", "CompanyA"),),
    )

    assert sanitized.text == "[REDACTED_0001], [REDACTED_0002]\n"
    result = restore_text(original, sanitized.text, sanitized.restoration_data)
    assert result.text == original
    assert result.restored_count == 2


def test_japanese_symbols_and_comments_are_preserved() -> None:
    original = "// 顧客: ABC株式会社 #1\n"
    sanitized = _restorable(original)

    result = restore_text(original, sanitized.text, sanitized.restoration_data)

    assert sanitized.text == "// 顧客: [REDACTED_0001] #1\n"
    assert result.text == original


def test_ai_changes_outside_markers_are_preserved() -> None:
    original = 'String name = "ABC株式会社";\n'
    sanitized = _restorable(original)
    edited = sanitized.text.replace("String", "final String") + "runNewStep();\n"

    result = restore_text(original, edited, sanitized.restoration_data)

    assert result.text == 'final String name = "ABC株式会社";\nrunNewStep();\n'


def test_line_mask_restores_text_and_requires_human_review() -> None:
    original = 'String company = "ABC株式会社";\n'
    sanitized = _restorable(original, masks=(MaskRule("ABC株式会社"),))

    result = restore_text(original, sanitized.text, sanitized.restoration_data)

    assert sanitized.text == "[REDACTED_0001]\n"
    assert result.text == original
    assert result.restored_count == 1
    assert result.review_required == ("[REDACTED_0001]",)
    assert not result.fully_restored


def test_line_mask_with_ai_edits_keeps_marker_and_requires_review() -> None:
    original = 'String company = "ABC株式会社";\n'
    sanitized = _restorable(original, masks=(MaskRule("ABC株式会社"),))
    edited = "if (ready) {\n    " + sanitized.text.rstrip() + " // AI edited\n}\n"

    result = restore_text(original, edited, sanitized.restoration_data)

    assert sanitized.text == "[REDACTED_0001]\n"
    assert result.text == edited
    assert result.restored_count == 0
    assert result.unresolved_count == 1
    assert result.review_required == ("[REDACTED_0001]",)
    assert not result.fully_restored


def test_date_mask_is_recorded_as_a_restorable_line_mask() -> None:
    original = "updatedAt = '2024/01/02';\n"
    sanitized = sanitize_text_for_restoration(
        original,
        mask_rules=(
            MaskRule(
                "yyyy/mm/dd または yyyy年mm月dd日",
                match_date_formats=True,
            ),
        ),
    )

    assert sanitized.text == "[REDACTED_0001]\n"
    assert sanitized.masked_line_count == 1
    assert sanitized.restoration_data.entries[0].kind == "line"
    assert restore_text(
        original, sanitized.text, sanitized.restoration_data
    ).text == original


def test_wrong_original_source_refuses_to_restore_any_marker() -> None:
    original = 'String name = "ABC株式会社";\n'
    sanitized = _restorable(original)
    edited = sanitized.text

    result = restore_text("different original", edited, sanitized.restoration_data)

    assert result.text == edited
    assert result.restored_count == 0
    assert result.source_mismatch
    assert result.unresolved_count >= 1
    assert not result.fully_restored


def test_invalid_marker_is_reported_and_left_untouched() -> None:
    original = 'String name = "ABC株式会社";\n'
    sanitized = _restorable(original)
    edited = sanitized.text.replace("[REDACTED_0001]", "[REDACTED_bad]")

    result = restore_text(original, edited, sanitized.restoration_data)

    assert result.text == edited
    assert result.invalid_tokens == ("[REDACTED_bad]",)
    assert result.missing_tokens == ("[REDACTED_0001]",)


def test_legacy_redacted_marker_is_never_guessed() -> None:
    original = 'String name = "ABC株式会社";\n'
    sanitized = _restorable(original)

    result = restore_text(
        original, 'String name = "[REDACTED]";\n', sanitized.restoration_data
    )

    assert result.restored_count == 0
    assert result.missing_tokens == ("[REDACTED_0001]",)
    assert result.invalid_tokens == ("[REDACTED]",)


def test_malformed_marker_is_reported_and_left_untouched() -> None:
    original = 'String name = "ABC株式会社";\n'
    sanitized = _restorable(original)
    edited = sanitized.text.replace("[REDACTED_0001]", "[REDACTED_0001")

    result = restore_text(original, edited, sanitized.restoration_data)

    assert result.text == edited
    assert result.invalid_tokens == ("[REDACTED_0001",)


def test_restoration_data_round_trip_and_validation() -> None:
    sanitized = _restorable('String name = "ABC株式会社";\n')
    serialized = serialize_restoration_data(sanitized.restoration_data)

    assert parse_restoration_data(serialized) == sanitized.restoration_data
    assert "ABC株式会社" in serialized
    assert "ABC株式会社" not in repr(sanitized.restoration_data)
    assert "ABC株式会社" not in repr(sanitized.restoration_data.entries[0])

    duplicate_entry = sanitized.restoration_data.entries[0]
    duplicate_data = RestorationData(
        source_sha256=sanitized.restoration_data.source_sha256,
        entries=(duplicate_entry, duplicate_entry),
    )
    with pytest.raises(ValueError, match="重複"):
        serialize_restoration_data(duplicate_data)


def test_load_restoration_data_accepts_json_file(tmp_path) -> None:
    sanitized = _restorable('String companyName = "ABC株式会社";\n')
    path = tmp_path / "mapping.restoration.json"
    path.write_text(
        serialize_restoration_data(sanitized.restoration_data),
        encoding="utf-8",
    )

    assert load_restoration_data(path) == sanitized.restoration_data


def test_load_restoration_data_rejects_non_json_file(tmp_path) -> None:
    path = tmp_path / "mapping.java"
    path.write_text("not restoration metadata", encoding="utf-8")

    with pytest.raises(ValueError, match=r"\.json"):
        load_restoration_data(path)


def test_restoration_data_with_invalid_hash_is_rejected() -> None:
    contents = (
        '{"version": 1, "source_sha256": "bad", "entries": []}'
    )

    with pytest.raises(ValueError):
        parse_restoration_data(contents)


def test_tampered_restoration_value_does_not_restore() -> None:
    original = 'String name = "ABC株式会社";\n'
    sanitized = _restorable(original)
    original_entry = sanitized.restoration_data.entries[0]
    altered_entry = type(original_entry)(
        token=original_entry.token,
        value="wrong value",
        kind=original_entry.kind,
        source_start=original_entry.source_start,
        source_end=original_entry.source_end,
    )
    altered_data = type(sanitized.restoration_data)(
        source_sha256=sanitized.restoration_data.source_sha256,
        entries=(altered_entry,),
    )

    result = restore_text(original, sanitized.text, altered_data)

    assert result.text == sanitized.text
    assert result.restored_count == 0
    assert result.source_mismatch
    assert result.unresolved_count == 1


def test_existing_legacy_redaction_behavior_is_unchanged() -> None:
    original = 'String name = "ABC株式会社";\n'

    result = sanitize_text(
        original,
        replacement_rules=(ReplacementRule("ABC株式会社", "CompanyA"),),
        mask_rules=(MaskRule("name"),),
    )

    assert result.text == "[REDACTED]\n"


def test_marker_generation_skips_tokens_already_in_source() -> None:
    original = (
        '"[REDACTED_0001]"; String name = "ABC株式会社";\n'
    )
    result = _restorable(original)

    assert result.text.endswith('"[REDACTED_0002]";\n')
    assert result.restoration_data.entries[0].token == "[REDACTED_0002]"


def test_restoration_hash_is_of_original_utf8_source() -> None:
    original = "日本語\n"
    result = _restorable(original)

    assert result.restoration_data.source_sha256 == hashlib.sha256(
        original.encode("utf-8")
    ).hexdigest()


def test_no_matching_rules_produces_restorable_unchanged_text() -> None:
    original = "class Example {}\n"
    sanitized = sanitize_text_for_restoration(original)

    result = restore_text(original, sanitized.text, sanitized.restoration_data)

    assert sanitized.text == original
    assert result.text == original
    assert result.restored_count == 0
    assert result.fully_restored
