import tkinter

import pytest

from code_sanitizer.drag_drop import parse_dropped_files


@pytest.fixture
def interpreter():
    return tkinter.Tcl()


def test_parses_single_dropped_file(interpreter) -> None:
    assert parse_dropped_files(interpreter, "{C:/work/My Project/Main.java}") == (
        "C:/work/My Project/Main.java",
    )


def test_parses_multiple_dropped_files_with_spaces(interpreter) -> None:
    data = "{C:/work/Original Source.java} {C:/work/AI Result.java}"

    assert parse_dropped_files(interpreter, data) == (
        "C:/work/Original Source.java",
        "C:/work/AI Result.java",
    )


def test_parses_braced_and_unbraced_paths(interpreter) -> None:
    assert parse_dropped_files(
        interpreter, "{C:/work/Source File.java} C:/work/Plain.java"
    ) == ("C:/work/Source File.java", "C:/work/Plain.java")


def test_empty_drop_data_returns_no_paths(interpreter) -> None:
    assert parse_dropped_files(interpreter, "") == ()


def test_invalid_tcl_file_list_raises_a_clear_error(interpreter) -> None:
    with pytest.raises(ValueError, match="ドロップされたファイル名"):
        parse_dropped_files(interpreter, "{unterminated path")
