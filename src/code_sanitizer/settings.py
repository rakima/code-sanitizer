"""Local persistence for reusable sanitizer rules and the last file directory."""

from dataclasses import dataclass
import json
import os
from pathlib import Path
import sys
from typing import Any

from .sanitizer import MaskRule, ReplacementRule


@dataclass(frozen=True)
class AppSettings:
    replacement_rules: tuple[ReplacementRule, ...] = ()
    mask_rules: tuple[MaskRule, ...] = ()
    last_directory: str | None = None


def default_settings_path() -> Path:
    """Return the user's local application settings path for the current OS."""
    if os.name == "nt":
        base_directory = Path(
            os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")
        )
    elif sys.platform == "darwin":
        base_directory = Path.home() / "Library" / "Application Support"
    else:
        base_directory = Path(
            os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")
        )
    return base_directory / "code-sanitizer" / "settings.json"


def load_settings(path: str | Path | None = None) -> AppSettings:
    """Load saved settings, returning defaults when no settings file exists."""
    settings_path = Path(path) if path is not None else default_settings_path()
    try:
        contents = settings_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return AppSettings()

    try:
        data: Any = json.loads(contents)
    except json.JSONDecodeError as error:
        raise ValueError(f"設定ファイルのJSONを読み取れません: {error}") from error

    if not isinstance(data, dict) or data.get("version") != 1:
        raise ValueError("設定ファイルの形式またはバージョンが正しくありません。")

    replacement_rules = _read_replacement_rules(data.get("replacement_rules"))
    mask_rules = _read_mask_rules(data.get("mask_rules"))
    last_directory = data.get("last_directory")
    if last_directory is not None and not isinstance(last_directory, str):
        raise ValueError("設定ファイルのlast_directoryが正しくありません。")

    return AppSettings(
        replacement_rules=tuple(replacement_rules),
        mask_rules=tuple(mask_rules),
        last_directory=last_directory,
    )


def save_settings(
    settings: AppSettings, path: str | Path | None = None
) -> None:
    """Save settings as UTF-8 JSON using an atomic replacement."""
    settings_path = Path(path) if path is not None else default_settings_path()
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "version": 1,
        "replacement_rules": [
            {"search": rule.search, "replacement": rule.replacement}
            for rule in settings.replacement_rules
        ],
        "mask_rules": [{"search": rule.search} for rule in settings.mask_rules],
        "last_directory": settings.last_directory,
    }
    temporary_path = settings_path.with_name(f"{settings_path.name}.tmp")
    try:
        temporary_path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        temporary_path.replace(settings_path)
    except OSError:
        temporary_path.unlink(missing_ok=True)
        raise


def _read_replacement_rules(value: Any) -> list[ReplacementRule]:
    if not isinstance(value, list):
        raise ValueError("設定ファイルのreplacement_rulesが正しくありません。")

    rules: list[ReplacementRule] = []
    for item in value:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("search"), str)
            or not item["search"]
            or not isinstance(item.get("replacement"), str)
        ):
            raise ValueError("設定ファイルに正しくない置換ルールがあります。")
        rules.append(ReplacementRule(item["search"], item["replacement"]))
    return rules


def _read_mask_rules(value: Any) -> list[MaskRule]:
    if not isinstance(value, list):
        raise ValueError("設定ファイルのmask_rulesが正しくありません。")

    rules: list[MaskRule] = []
    for item in value:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("search"), str)
            or not item["search"]
        ):
            raise ValueError("設定ファイルに正しくない行マスクルールがあります。")
        rules.append(MaskRule(item["search"]))
    return rules
