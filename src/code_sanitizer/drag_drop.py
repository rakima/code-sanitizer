"""Helpers for interpreting native Tkinter drag-and-drop file lists."""

from tkinter import Tcl, TclError


def parse_dropped_files(interpreter: Tcl, data: str) -> tuple[str, ...]:
    """Parse the Tcl list used by Tk DND_FILES, including paths with spaces."""
    try:
        paths = tuple(str(path) for path in interpreter.splitlist(data))
    except TclError as error:
        raise ValueError("ドロップされたファイル名を読み取れません。") from error
    return tuple(path for path in paths if path)
