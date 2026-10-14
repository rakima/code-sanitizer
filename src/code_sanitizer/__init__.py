"""Local code sanitization utilities."""

from .leak_checker import (
    LeakCandidate,
    LeakCheckResult,
    PatternCheck,
    analyze_package_imports,
    check_sensitive_patterns,
    find_identifier_candidates,
    scan_for_leaks,
    split_camel_case,
)
from .restoration import (
    RestorationData,
    RestorationEntry,
    RestorationResult,
    load_restoration_data,
    restore_text,
    serialize_restoration_data,
)
from .sanitizer import (
    MaskRule,
    ReplacementRule,
    RestorableSanitizationResult,
    SanitizationResult,
    sanitize_text,
    sanitize_text_for_restoration,
)

__all__ = [
    "LeakCandidate",
    "LeakCheckResult",
    "MaskRule",
    "PatternCheck",
    "ReplacementRule",
    "RestorableSanitizationResult",
    "RestorationData",
    "RestorationEntry",
    "RestorationResult",
    "SanitizationResult",
    "analyze_package_imports",
    "check_sensitive_patterns",
    "find_identifier_candidates",
    "load_restoration_data",
    "restore_text",
    "scan_for_leaks",
    "sanitize_text_for_restoration",
    "serialize_restoration_data",
    "split_camel_case",
    "sanitize_text",
]
