from code_sanitizer.leak_checker import (
    analyze_package_imports,
    check_sensitive_patterns,
    find_identifier_candidates,
    scan_for_leaks,
    split_camel_case,
)


def _candidate(candidates, category: str, value: str | None = None):
    return next(
        candidate
        for candidate in candidates
        if candidate.category == category
        and (value is None or candidate.value.casefold() == value.casefold())
    )


def test_detects_email() -> None:
    result = check_sensitive_patterns("contact alice@example.com")

    candidate = _candidate(result, "email")
    assert candidate.value == "alice@example.com"
    assert candidate.count == 1
    assert candidate.lines == (1,)


def test_detects_valid_ipv4_and_rejects_invalid_octets() -> None:
    result = check_sensitive_patterns("host 192.168.1.25 invalid 999.1.1.1")

    candidate = _candidate(result, "ipv4")
    assert candidate.value == "192.168.1.25"
    assert candidate.count == 1


def test_detects_url_without_trailing_punctuation() -> None:
    result = check_sensitive_patterns("endpoint https://service.example.com/api,")

    candidate = _candidate(result, "url")
    assert candidate.value == "https://service.example.com/api"


def test_detects_windows_absolute_path() -> None:
    result = check_sensitive_patterns(r"source C:\Users\Alice Smith\project\Main.java")

    candidate = _candidate(result, "windows_path")
    assert candidate.value == r"C:\Users\Alice Smith\project\Main.java"


def test_detects_unix_absolute_path() -> None:
    result = check_sensitive_patterns("source /home/alice/projects/app/Main.java")

    candidate = _candidate(result, "unix_path")
    assert candidate.value == "/home/alice/projects/app/Main.java"


def test_detects_credential_names_but_never_exposes_values() -> None:
    result = check_sensitive_patterns(
        'apiKey = "secret-key";\naccessToken: \'secret-token\'\npassword = "hidden"'
    )

    candidate = _candidate(result, "credential")
    assert candidate.count == 3
    assert candidate.lines == (1, 2, 3)
    assert "secret-key" not in candidate.value
    assert "secret-token" not in repr(result)
    assert "hidden" not in repr(result)


def test_detects_secret_suffix_and_multiple_credentials_on_one_line() -> None:
    result = check_sensitive_patterns(
        'clientSecret = "one"; secretKey = "two";'
    )

    candidate = _candidate(result, "credential")
    assert candidate.count == 2
    assert candidate.lines == (1,)


def test_splits_camel_case_and_acronyms() -> None:
    assert split_camel_case("AbstractGaiaComponentImpl") == (
        "Abstract",
        "Gaia",
        "Component",
        "Impl",
    )
    assert split_camel_case("APIKeyReader") == ("API", "Key", "Reader")


def test_repeated_identifier_compound_is_candidate() -> None:
    result = find_identifier_candidates(
        "class NumListEditorListener {}\n"
        "class NumListEditorModel {}\n"
        "class NdcExecSetting {}\n"
        "class NdcExecSettingFactory {}\n"
    )

    assert _candidate(result, "identifier", "NumList").count == 2
    assert _candidate(result, "identifier", "Ndc").count == 2


def test_repeated_java_identifier_words_are_candidates() -> None:
    source = (
        "class GaiaComponentSink {}\n"
        "class AbstractGaiaComponentImpl {}\n"
        "class GaiaCalendar {}\n"
        "class GaiaUtil {}\n"
    )

    candidate = _candidate(find_identifier_candidates(source), "identifier", "Gaia")
    assert candidate.count == 4
    assert candidate.lines == (1, 2, 3, 4)


def test_package_and_import_occurrences_are_counted_once_and_prioritized() -> None:
    source = (
        "package jp.co.gaia.client.tools.example;\n"
        "import jp.co.gaia.client.components.GaiaComponentModel;\n"
        "class GaiaComponentSink {}\n"
    )

    candidates = find_identifier_candidates(source)
    gaia = _candidate(candidates, "identifier", "gaia")
    client = _candidate(candidates, "identifier", "client")
    assert gaia.count == 4
    assert gaia.lines == (1, 2, 3)
    assert gaia.risk == "medium"
    assert client.count == 2
    assert client.lines == (1, 2)


def test_extracts_candidates_from_package_declarations() -> None:
    result = analyze_package_imports(
        "package jp.co.x1.gaia.client.tools.example;\n"
    )

    values = {candidate.value.casefold() for candidate in result}
    assert {"x1", "gaia", "client", "tools", "example"} <= values
    assert "jp" not in values
    assert "co" not in values


def test_extracts_candidates_from_imports() -> None:
    result = analyze_package_imports(
        "import jp.co.x1.gaia.components.GaiaComponentModel;\n"
    )

    values = {candidate.value.casefold() for candidate in result}
    assert {"x1", "gaia"} <= values
    assert "jp" not in values
    assert "component" not in values


def test_counts_repeated_words_and_case_variants_together() -> None:
    result = find_identifier_candidates(
        "class GaiaUtil {}\nclass gaiaClient {}\nclass GAIAService {}"
    )

    candidate = _candidate(result, "identifier", "gaia")
    assert candidate.count == 3
    assert candidate.lines == (1, 2, 3)


def test_ignored_words_are_case_insensitive() -> None:
    result = find_identifier_candidates(
        "class GaiaUtil {}\nclass GaiaCalendar {}", ignored_words={"GAIA"}
    )

    assert all(candidate.value.casefold() != "gaia" for candidate in result)


def test_excludes_common_java_words_and_package_qualifiers() -> None:
    result = find_identifier_candidates(
        "String Object List Map Calendar Button Panel Dialog Listener Model "
        "Controller Component Event Action Window Data Value Setting Util Impl "
        "Abstract java javax org com"
    )

    assert result == ()


def test_redacted_marker_does_not_become_a_candidate() -> None:
    result = scan_for_leaks(
        "[REDACTED]\nclass GaiaUtil {}\nclass GaiaCalendar {}"
    )

    assert _candidate(result.identifier_candidates, "identifier", "Gaia")
    assert all(
        candidate.value.casefold() != "redacted"
        for candidate in result.identifier_candidates
    )


def test_empty_file_reports_no_pattern_or_identifier_findings() -> None:
    result = scan_for_leaks("")

    assert result.pattern_candidates == ()
    assert result.identifier_candidates == ()
    assert all(check.count == 0 for check in result.pattern_checks)


def test_file_without_candidates_reports_pattern_categories_as_clear() -> None:
    result = scan_for_leaks("public class Main { String value = \"hello\"; }")

    assert result.pattern_candidates == ()
    assert result.identifier_candidates == ()
    assert {check.category for check in result.pattern_checks} == {
        "email",
        "ipv4",
        "url",
        "windows_path",
        "unix_path",
        "credential",
    }
    assert all(check.count == 0 for check in result.pattern_checks)


def test_handles_japanese_source_text() -> None:
    result = scan_for_leaks(
        "package jp.co.gaia.client;\n"
        "// 顧客名は匿名化済み\n"
        "class GaiaCalendar {}\n"
        "class GaiaUtil {}\n"
    )

    assert _candidate(result.identifier_candidates, "identifier", "gaia")
