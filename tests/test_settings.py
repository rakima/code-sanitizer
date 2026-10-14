import json
from pathlib import Path

import pytest

from code_sanitizer.sanitizer import MaskRule, ReplacementRule
from code_sanitizer.settings import AppSettings, load_settings, save_settings


def test_load_missing_settings_returns_defaults(tmp_path: Path) -> None:
    assert load_settings(tmp_path / "missing.json") == AppSettings()


def test_settings_round_trip_rules_and_last_directory(tmp_path: Path) -> None:
    settings_path = tmp_path / "nested" / "settings.json"
    settings = AppSettings(
        replacement_rules=(
            ReplacementRule("Gaia", "Product"),
            ReplacementRule("gaia", "product"),
            ReplacementRule("秘密", ""),
        ),
        mask_rules=(MaskRule("顧客名"),),
        last_directory=r"C:\work\source",
    )

    save_settings(settings, settings_path)

    assert load_settings(settings_path) == settings
    assert not settings_path.with_name("settings.json.tmp").exists()


def test_saved_settings_are_utf8_json(tmp_path: Path) -> None:
    settings_path = tmp_path / "settings.json"
    save_settings(
        AppSettings(replacement_rules=(ReplacementRule("顧客名", "ClientA"),)),
        settings_path,
    )

    content = settings_path.read_text(encoding="utf-8")
    assert "顧客名" in content
    assert json.loads(content)["version"] == 1


@pytest.mark.parametrize(
    "contents",
    [
        "{not valid json",
        "[]",
        '{"version": 2, "replacement_rules": [], "mask_rules": []}',
        '{"version": 1, "replacement_rules": [{"search": "", "replacement": "x"}], "mask_rules": []}',
        '{"version": 1, "replacement_rules": [], "mask_rules": [{"search": ""}]}',
        '{"version": 1, "replacement_rules": [], "mask_rules": [], "last_directory": 5}',
    ],
)
def test_invalid_settings_raise_value_error(tmp_path: Path, contents: str) -> None:
    settings_path = tmp_path / "settings.json"
    settings_path.write_text(contents, encoding="utf-8")

    with pytest.raises(ValueError):
        load_settings(settings_path)


def test_settings_read_errors_are_not_silently_ignored(tmp_path: Path) -> None:
    settings_path = tmp_path / "settings.json"
    settings_path.mkdir()

    with pytest.raises(OSError):
        load_settings(settings_path)
