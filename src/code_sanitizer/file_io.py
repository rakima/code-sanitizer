"""UTF-8 text file input and output helpers."""

from pathlib import Path

from .restoration import (
    RestorationData,
    serialize_restoration_data,
)


def read_text_file(path: str | Path) -> str:
    """Read a text file as UTF-8 without changing its line endings."""
    with Path(path).open("r", encoding="utf-8", newline="") as source_file:
        return source_file.read()


def save_sanitized_file(
    source_path: str | Path,
    destination_path: str | Path,
    text: str,
) -> None:
    """Save output separately, refusing to overwrite the original file."""
    source = Path(source_path)
    destination = Path(destination_path)
    if source.resolve() == destination.resolve():
        raise ValueError("The sanitized file cannot overwrite the original file.")

    with destination.open("w", encoding="utf-8", newline="") as output_file:
        output_file.write(text)


def save_restorable_outputs(
    source_path: str | Path,
    sanitized_path: str | Path,
    restoration_path: str | Path,
    sanitized_text: str,
    restoration_data: RestorationData,
) -> None:
    """Write both restorable outputs without overwriting existing or source files."""
    source = Path(source_path).resolve()
    sanitized = Path(sanitized_path).resolve()
    restoration = Path(restoration_path).resolve()
    if sanitized in {source, restoration} or restoration == source:
        raise ValueError(
            "元ファイル、匿名化ファイル、復元情報には別々の保存先を指定してください。"
        )

    created_paths: list[Path] = []
    try:
        for path, contents in (
            (sanitized, sanitized_text),
            (restoration, serialize_restoration_data(restoration_data)),
        ):
            with path.open("x", encoding="utf-8", newline="") as output_file:
                created_paths.append(path)
                output_file.write(contents)
    except OSError:
        for path in created_paths:
            path.unlink(missing_ok=True)
        raise


def save_restored_file(
    destination_path: str | Path,
    text: str,
    protected_paths: tuple[str | Path, ...],
) -> None:
    """Save restored text without overwriting its source or restoration inputs."""
    destination = Path(destination_path).resolve()
    if destination in {Path(path).resolve() for path in protected_paths}:
        raise ValueError("入力ファイルや復元情報を上書きできません。")

    with destination.open("w", encoding="utf-8", newline="") as output_file:
        output_file.write(text)
