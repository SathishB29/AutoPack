"""Deterministic DLT line parsing helpers."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from datetime import timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

_PROFILE_CONFIG_FILE = "vendor_profiles.json"

_TIMESTAMP_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)

ProfilePatterns = dict[str, list[re.Pattern[str]]]
ProfileRegistry = dict[str, ProfilePatterns]
VendorRegistry = dict[str, tuple[str, ...]]


@dataclass(slots=True)
class ParsedDltLine:
    """Structured fields extracted from a single DLT text line."""

    raw_line: str
    message: str
    timestamp: datetime | None
    ecu: str | None
    app_id: str | None
    context_id: str | None


@dataclass(slots=True)
class ParsedDltRecord:
    """DLT record parsed from a file with deterministic line indexing."""

    line_number: int
    parsed: ParsedDltLine


@lru_cache(maxsize=1)
def _load_profile_registry() -> tuple[ProfileRegistry, VendorRegistry]:
    config_path = Path(__file__).with_name(_PROFILE_CONFIG_FILE)
    try:
        raw_text = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"Unable to read DLT profile config: {config_path}") from exc

    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in DLT profile config: {config_path}") from exc

    if not isinstance(payload, dict):
        raise ValueError("DLT profile config must be a JSON object")

    raw_profiles = payload.get("profiles")
    if not isinstance(raw_profiles, dict) or not raw_profiles:
        raise ValueError("DLT profile config must define non-empty 'profiles'")

    profiles: ProfileRegistry = {}
    for profile_name, raw_fields in raw_profiles.items():
        if not isinstance(profile_name, str) or not profile_name.strip():
            raise ValueError("DLT profile names must be non-empty strings")

        normalized_profile = profile_name.strip()
        profiles[normalized_profile] = _compile_profile_fields(
            profile_name=normalized_profile,
            raw_fields=raw_fields,
        )

    raw_vendor_map = payload.get("vendor_map")
    if not isinstance(raw_vendor_map, dict) or not raw_vendor_map:
        raise ValueError("DLT profile config must define non-empty 'vendor_map'")

    vendors: VendorRegistry = {}
    for vendor_name, raw_profile_order in raw_vendor_map.items():
        if not isinstance(vendor_name, str) or not vendor_name.strip():
            raise ValueError("DLT vendor names must be non-empty strings")

        if not isinstance(raw_profile_order, list) or not raw_profile_order:
            raise ValueError(f"Vendor '{vendor_name}' must map to a non-empty profile list")

        profile_order: list[str] = []
        for entry in raw_profile_order:
            if not isinstance(entry, str) or not entry.strip():
                raise ValueError(f"Vendor '{vendor_name}' contains an invalid profile name")

            normalized_profile = entry.strip()
            if normalized_profile not in profiles:
                raise ValueError(
                    f"Vendor '{vendor_name}' references unknown profile '{normalized_profile}'"
                )
            profile_order.append(normalized_profile)

        vendors[vendor_name.strip()] = tuple(profile_order)

    if "default" not in vendors:
        raise ValueError("DLT profile config must define a 'default' vendor mapping")

    return profiles, vendors


def _compile_profile_fields(profile_name: str, raw_fields: Any) -> ProfilePatterns:
    if not isinstance(raw_fields, dict):
        raise ValueError(f"Profile '{profile_name}' must map to a field object")

    compiled: ProfilePatterns = {}
    for field_name in ("ecu", "app", "context"):
        raw_patterns = raw_fields.get(field_name, [])
        if not isinstance(raw_patterns, list):
            raise ValueError(
                f"Profile '{profile_name}' field '{field_name}' must be a list of regex strings"
            )

        compiled_patterns: list[re.Pattern[str]] = []
        for pattern_index, pattern_text in enumerate(raw_patterns):
            if not isinstance(pattern_text, str) or not pattern_text.strip():
                raise ValueError(
                    "Invalid regex entry in profile "
                    f"'{profile_name}' field '{field_name}' at index {pattern_index}"
                )

            try:
                compiled_patterns.append(re.compile(pattern_text, re.IGNORECASE))
            except re.error as exc:
                raise ValueError(
                    "Failed to compile regex for profile "
                    f"'{profile_name}' field '{field_name}': {pattern_text}"
                ) from exc

        compiled[field_name] = compiled_patterns

    return compiled


def _derive_supported_profiles() -> tuple[str, ...]:
    profiles, _vendors = _load_profile_registry()
    return ("auto", *tuple(profiles.keys()))


def _derive_supported_vendors() -> tuple[str, ...]:
    _profiles, vendors = _load_profile_registry()
    return tuple(vendors.keys())


SUPPORTED_DLT_PROFILES: tuple[str, ...] = _derive_supported_profiles()
SUPPORTED_DLT_VENDORS: tuple[str, ...] = _derive_supported_vendors()


def parse_dlt_line(
    line: str,
    profile: str = "auto",
    vendor: str = "default",
) -> ParsedDltLine:
    """Parse structured DLT metadata from one line of text."""
    parsed, _resolved_profile = _parse_dlt_line_with_profile(
        line,
        profile=profile,
        vendor=vendor,
    )
    return parsed


def parse_dlt_file(
    path: Path,
    profile: str = "auto",
    vendor: str = "default",
) -> tuple[list[ParsedDltRecord], str, list[str]]:
    """Parse a DLT file using pydlt when available, with deterministic fallback."""
    profiles, vendors = _load_profile_registry()
    _validate_profile(profile, profiles)
    _validate_vendor(vendor, vendors)
    warnings: list[str] = []

    pydlt_records, pydlt_warnings = _parse_with_pydlt(
        path,
        profile=profile,
        vendor=vendor,
        profiles=profiles,
        vendors=vendors,
    )
    warnings.extend(pydlt_warnings)
    if pydlt_records:
        return pydlt_records, "pydlt", warnings

    fallback_records, profile_usage = _parse_text_fallback(
        path,
        profile=profile,
        vendor=vendor,
        profiles=profiles,
        vendors=vendors,
    )
    warnings.append(
        f"DLT parser backend for {path.name}: text-fallback ({len(fallback_records)} rows)"
    )
    warnings.append(
        "DLT profile selection "
        f"for {path.name} (vendor={vendor}, requested_profile={profile}): "
        f"{_format_profile_usage(profile_usage)}"
    )
    return fallback_records, "text-fallback", warnings


def _parse_dlt_line_with_profile(
    line: str,
    *,
    profile: str,
    vendor: str,
) -> tuple[ParsedDltLine, str]:
    profiles, vendors = _load_profile_registry()
    _validate_profile(profile, profiles)
    _validate_vendor(vendor, vendors)

    normalized = line.strip()
    ecu, app_id, context_id, resolved_profile = _extract_profiled_fields(
        normalized,
        profile=profile,
        vendor=vendor,
        profiles=profiles,
        vendors=vendors,
    )

    return ParsedDltLine(
        raw_line=normalized,
        message=normalized,
        timestamp=_extract_timestamp(normalized),
        ecu=ecu,
        app_id=app_id,
        context_id=context_id,
    ), resolved_profile


def _parse_with_pydlt(
    path: Path,
    *,
    profile: str,
    vendor: str,
    profiles: ProfileRegistry,
    vendors: VendorRegistry,
) -> tuple[list[ParsedDltRecord], list[str]]:
    warnings: list[str] = []

    try:
        import pydlt  # type: ignore[import-not-found]
    except Exception:
        return [], [f"pydlt not available; fallback parser used for {path.name}"]

    records: list[ParsedDltRecord] = []
    profile_usage: dict[str, int] = {}
    try:
        reader = pydlt.DltFileReader(str(path))
        for line_number, message_obj in enumerate(reader, start=1):
            text = str(message_obj).strip()
            if not text:
                continue

            ecu_text, app_text, context_text, resolved_profile = _extract_profiled_fields(
                text,
                profile=profile,
                vendor=vendor,
                profiles=profiles,
                vendors=vendors,
            )
            profile_usage[resolved_profile] = profile_usage.get(resolved_profile, 0) + 1

            records.append(
                ParsedDltRecord(
                    line_number=line_number,
                    parsed=ParsedDltLine(
                        raw_line=text,
                        message=text,
                        timestamp=_extract_timestamp(text),
                        ecu=_extract_ecu(message_obj, ecu_text),
                        app_id=_extract_app_id(message_obj, app_text),
                        context_id=_extract_context_id(message_obj, context_text),
                    ),
                )
            )
    except Exception as exc:
        warnings.append(f"pydlt parse failed for {path.name}: {exc}")
        return [], warnings

    warnings.append(f"DLT parser backend for {path.name}: pydlt ({len(records)} rows)")
    warnings.append(
        "DLT profile selection "
        f"for {path.name} (vendor={vendor}, requested_profile={profile}): "
        f"{_format_profile_usage(profile_usage)}"
    )
    return records, warnings


def _parse_text_fallback(
    path: Path,
    *,
    profile: str,
    vendor: str,
    profiles: ProfileRegistry,
    vendors: VendorRegistry,
) -> tuple[list[ParsedDltRecord], dict[str, int]]:
    records: list[ParsedDltRecord] = []
    profile_usage: dict[str, int] = {}
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, start=1):
            normalized = line.strip()
            if not normalized:
                continue

            parsed, resolved_profile = _parse_dlt_line_with_profile_cached(
                normalized,
                profile=profile,
                vendor=vendor,
                profiles=profiles,
                vendors=vendors,
            )
            profile_usage[resolved_profile] = profile_usage.get(resolved_profile, 0) + 1

            records.append(
                ParsedDltRecord(
                    line_number=line_number,
                    parsed=parsed,
                )
            )

    return records, profile_usage


def _parse_dlt_line_with_profile_cached(
    line: str,
    *,
    profile: str,
    vendor: str,
    profiles: ProfileRegistry,
    vendors: VendorRegistry,
) -> tuple[ParsedDltLine, str]:
    normalized = line.strip()
    ecu, app_id, context_id, resolved_profile = _extract_profiled_fields(
        normalized,
        profile=profile,
        vendor=vendor,
        profiles=profiles,
        vendors=vendors,
    )

    return (
        ParsedDltLine(
            raw_line=normalized,
            message=normalized,
            timestamp=_extract_timestamp(normalized),
            ecu=ecu,
            app_id=app_id,
            context_id=context_id,
        ),
        resolved_profile,
    )


def _extract_profiled_fields(
    text: str,
    *,
    profile: str,
    vendor: str,
    profiles: ProfileRegistry,
    vendors: VendorRegistry,
) -> tuple[str | None, str | None, str | None, str]:
    if profile != "auto":
        patterns = profiles[profile]
        return (
            _extract_first(text, patterns["ecu"]),
            _extract_first(text, patterns["app"]),
            _extract_first(text, patterns["context"]),
            profile,
        )

    candidate_order = vendors[vendor]
    best_profile = candidate_order[0]
    best_fields: tuple[str | None, str | None, str | None] = (None, None, None)
    best_score = -1

    for candidate in candidate_order:
        patterns = profiles[candidate]
        fields = (
            _extract_first(text, patterns["ecu"]),
            _extract_first(text, patterns["app"]),
            _extract_first(text, patterns["context"]),
        )
        score = sum(1 for value in fields if value is not None)
        if score > best_score:
            best_score = score
            best_profile = candidate
            best_fields = fields

    return (*best_fields, best_profile)


def _validate_profile(profile: str, profiles: ProfileRegistry) -> None:
    if profile == "auto":
        return

    if profile not in profiles:
        supported = ", ".join(("auto", *tuple(profiles.keys())))
        raise ValueError(f"Unsupported DLT profile: {profile}. Supported values: {supported}")


def _validate_vendor(vendor: str, vendors: VendorRegistry) -> None:
    if vendor not in vendors:
        supported = ", ".join(vendors.keys())
        raise ValueError(f"Unsupported DLT vendor: {vendor}. Supported values: {supported}")


def _format_profile_usage(profile_usage: dict[str, int]) -> str:
    if not profile_usage:
        return "none"

    return ", ".join(
        f"{profile_name}={count}" for profile_name, count in sorted(profile_usage.items())
    )


def _extract_timestamp(line: str) -> datetime | None:
    match = _TIMESTAMP_RE.search(line)
    if not match:
        return None

    raw = match.group(1).replace(" ", "T")
    if raw.endswith("Z"):
        raw = raw.replace("Z", "+00:00")
    elif len(raw) >= 5 and raw[-3] != ":" and (raw[-5] in {"+", "-"}):
        raw = raw[:-2] + ":" + raw[-2:]

    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def _extract_first(text: str, patterns: list[re.Pattern[str]]) -> str | None:
    for pattern in patterns:
        match = pattern.search(text)
        if match is None:
            continue

        value = match.group(1).strip()
        if value:
            return value

    return None


def _extract_ecu(message_obj: Any, text_value: str | None) -> str | None:
    return _coalesce_text(
        _try_get_attr(message_obj, "ecu_id"),
        _try_get_attr(_try_get_attr(message_obj, "str_header"), "ecu_id"),
        text_value,
    )


def _extract_app_id(message_obj: Any, text_value: str | None) -> str | None:
    return _coalesce_text(
        _try_get_attr(message_obj, "app_id"),
        _try_get_attr(message_obj, "apid"),
        _try_get_attr(_try_get_attr(message_obj, "std_header"), "apid"),
        text_value,
    )


def _extract_context_id(message_obj: Any, text_value: str | None) -> str | None:
    return _coalesce_text(
        _try_get_attr(message_obj, "context_id"),
        _try_get_attr(message_obj, "ctid"),
        _try_get_attr(_try_get_attr(message_obj, "std_header"), "ctid"),
        text_value,
    )


def _coalesce_text(*values: Any) -> str | None:
    for value in values:
        text = _to_text(value)
        if text is not None:
            return text
    return None


def _to_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text if text else None


def _try_get_attr(obj: Any, name: str) -> Any:
    if obj is None:
        return None
    return getattr(obj, name, None)
