"""UTF-8 text file input and output helpers."""

from pathlib import Path


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
