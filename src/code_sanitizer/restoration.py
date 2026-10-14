"""Local restoration metadata and conservative placeholder restoration."""

from collections import Counter
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import re
from typing import Any


@dataclass(frozen=True)
class RestorationEntry:
    token: str
    value: str = field(repr=False)
    kind: str
    source_start: int
    source_end: int


@dataclass(frozen=True)
class RestorationData:
    source_sha256: str
    entries: tuple[RestorationEntry, ...] = field(repr=False)


@dataclass(frozen=True)
class RestorationResult:
    text: str = field(repr=False)
    restored_count: int
    unresolved_count: int
    missing_tokens: tuple[str, ...]
    invalid_tokens: tuple[str, ...]
    unknown_tokens: tuple[str, ...]
    duplicated_tokens: tuple[str, ...]
    review_required: tuple[str, ...]
    source_mismatch: bool

    @property
    def fully_restored(self) -> bool:
        return not (
            self.unresolved_count
            or self.review_required
            or self.source_mismatch
        )


_VALID_TOKEN = re.compile(r"\[REDACTED_\d{4,}\]", re.IGNORECASE)
_TOKEN_LIKE = re.compile(
    r"\[REDACTED[^\]\s\"'<>;,]*(?:\]|(?=$|[\s\"'<>;,]))",
    re.IGNORECASE,
)
_SHA256 = re.compile(r"[0-9a-f]{64}")


def serialize_restoration_data(data: RestorationData) -> str:
    """Serialize secret-bearing restoration data for an explicitly chosen file."""
    _validate_restoration_data(data)
    payload = {
        "version": 1,
        "source_sha256": data.source_sha256,
        "entries": [
            {
                "token": entry.token,
                "value": entry.value,
                "kind": entry.kind,
                "source_start": entry.source_start,
                "source_end": entry.source_end,
            }
            for entry in data.entries
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def parse_restoration_data(contents: str) -> RestorationData:
    """Parse and validate a restoration data JSON document."""
    try:
        payload: Any = json.loads(contents)
    except json.JSONDecodeError as error:
        raise ValueError(f"復元情報のJSONを読み取れません: {error}") from error

    if (
        not isinstance(payload, dict)
        or payload.get("version") != 1
        or not isinstance(payload.get("source_sha256"), str)
        or not isinstance(payload.get("entries"), list)
    ):
        raise ValueError("復元情報の形式またはバージョンが正しくありません。")

    entries: list[RestorationEntry] = []
    for item in payload["entries"]:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("token"), str)
            or not isinstance(item.get("value"), str)
            or not isinstance(item.get("kind"), str)
            or not isinstance(item.get("source_start"), int)
            or isinstance(item.get("source_start"), bool)
            or not isinstance(item.get("source_end"), int)
            or isinstance(item.get("source_end"), bool)
            or item.get("kind") not in {"replacement", "line"}
        ):
            raise ValueError("復元情報に不正な対応データがあります。")
        entries.append(
            RestorationEntry(
                token=item["token"],
                value=item["value"],
                kind=item["kind"],
                source_start=item["source_start"],
                source_end=item["source_end"],
            )
        )

    data = RestorationData(
        source_sha256=payload["source_sha256"],
        entries=tuple(entries),
    )
    _validate_restoration_data(data)
    return data


def load_restoration_data(path: str | Path) -> RestorationData:
    """Load restoration data locally from UTF-8 JSON."""
    return parse_restoration_data(
        Path(path).read_text(encoding="utf-8")
    )


def restore_text(
    original_text: str,
    edited_sanitized_text: str,
    restoration_data: RestorationData,
) -> RestorationResult:
    """Restore unique tokens, refusing missing, duplicate, unknown, or invalid IDs."""
    _validate_restoration_data(restoration_data)
    original_hash = hashlib.sha256(original_text.encode("utf-8")).hexdigest()
    token_matches = tuple(_TOKEN_LIKE.finditer(edited_sanitized_text))
    tokens = [match.group() for match in token_matches]
    token_counts = Counter(tokens)
    known_entries = {entry.token: entry for entry in restoration_data.entries}

    missing = tuple(
        sorted(token for token in known_entries if token_counts[token] == 0)
    )
    duplicated = tuple(
        sorted(token for token, count in token_counts.items() if count > 1)
    )
    unknown = tuple(
        sorted(
            token
            for token in token_counts
            if _VALID_TOKEN.fullmatch(token) and token not in known_entries
        )
    )
    invalid = tuple(
        sorted(token for token in token_counts if not _VALID_TOKEN.fullmatch(token))
    )

    if original_hash != restoration_data.source_sha256 or any(
        entry.source_start < 0
        or entry.source_end < entry.source_start
        or entry.source_end > len(original_text)
        or original_text[entry.source_start : entry.source_end] != entry.value
        for entry in restoration_data.entries
    ):
        return RestorationResult(
            text=edited_sanitized_text,
            restored_count=0,
            unresolved_count=(
                len(restoration_data.entries)
                + sum(token_counts[token] for token in duplicated)
                + sum(token_counts[token] for token in unknown)
                + sum(token_counts[token] for token in invalid)
            ),
            missing_tokens=missing,
            invalid_tokens=invalid,
            unknown_tokens=unknown,
            duplicated_tokens=duplicated,
            review_required=(),
            source_mismatch=True,
        )

    restorable = {
        entry.token: entry
        for entry in restoration_data.entries
        if token_counts[entry.token] == 1
        and (
            entry.kind == "replacement"
            or _is_standalone_line_token(edited_sanitized_text, entry.token)
        )
    }
    review_required = tuple(
        sorted(
            entry.token
            for entry in restoration_data.entries
            if entry.kind == "line" and token_counts[entry.token] == 1
        )
    )
    restored_text = _TOKEN_LIKE.sub(
        lambda match: (
            restorable[match.group()].value
            if match.group() in restorable
            else match.group()
        ),
        edited_sanitized_text,
    )
    unresolved_count = len(missing) + sum(
        count
        for token, count in token_counts.items()
        if token not in restorable
    )
    return RestorationResult(
        text=restored_text,
        restored_count=len(restorable),
        unresolved_count=unresolved_count,
        missing_tokens=missing,
        invalid_tokens=invalid,
        unknown_tokens=unknown,
        duplicated_tokens=duplicated,
        review_required=review_required,
        source_mismatch=False,
    )


def _validate_restoration_data(data: RestorationData) -> None:
    if (
        not isinstance(data.source_sha256, str)
        or not _SHA256.fullmatch(data.source_sha256)
    ):
        raise ValueError("復元情報の元ファイル識別値が正しくありません。")

    tokens: set[str] = set()
    for entry in data.entries:
        if (
            not isinstance(entry.token, str)
            or not _VALID_TOKEN.fullmatch(entry.token)
            or not isinstance(entry.value, str)
        ):
            raise ValueError("復元情報に不正なIDがあります。")
        if entry.token in tokens:
            raise ValueError("復元情報に重複したIDがあります。")
        if entry.kind not in {"replacement", "line"}:
            raise ValueError("復元情報に不正な匿名化種別があります。")
        if (
            entry.source_start < 0
            or entry.source_end < entry.source_start
        ):
            raise ValueError("復元情報に不正な元コード位置があります。")
        tokens.add(entry.token)


def _is_standalone_line_token(text: str, token: str) -> bool:
    line_pattern = re.compile(rf"(?m)^{re.escape(token)}(?=\r?$)")
    return line_pattern.search(text) is not None
